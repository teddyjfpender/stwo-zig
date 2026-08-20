//! Shared serial proof-level A/B harness for typed opcode witness cutovers.
//!
//! The generated arm completes and independently verifies before the retired
//! authority arm starts. Acceptance requires exact statement, every interaction
//! claim, terminal transcript, draw count, and serialized proof byte—not merely
//! two successful verifications.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");
const committed = @import("committed_forgery_harness.zig");
const prover_engine = @import("stwo_prover_engine");
const prover_api = @import("stwo_prover_api");

const composition_work = prover_engine.air.composition_work;
const pcs_shell_work = prover_engine.pcs.shell_work_profile;
const work_pool = prover_engine.work_pool;

const orchestration = frontend.testing.prover_orchestration;
const prover = frontend.prover_mod;

pub const Evidence = struct {
    proof_bytes: usize,
    proof_sha256: [32]u8,
    transcript_digest: [32]u8,
    transcript_draws: u32,
    composition_authority_digest: ?composition_work.Digest = null,
    composition_receipt_digest: ?composition_work.Digest = null,
    pcs_shell_receipt_digest: ?pcs_shell_work.Digest = null,
};

pub fn compare(
    allocator: std.mem.Allocator,
    guest: *const committed.Guest,
    legacy_mutation: committed.Mutation,
) !Evidence {
    const generated = try runArm(allocator, guest, null, .{});
    defer generated.deinit(allocator);
    const legacy = try runArm(allocator, guest, legacy_mutation, .{});
    defer legacy.deinit(allocator);

    try expectEqualStatement(generated.statement, legacy.statement);
    try expectEqualClaim(generated.statement, generated.claim, legacy.claim);
    try std.testing.expectEqual(generated.channel_digest, legacy.channel_digest);
    try std.testing.expectEqual(generated.channel_draws, legacy.channel_draws);
    try std.testing.expectEqualSlices(u8, generated.proof_bytes, legacy.proof_bytes);

    var proof_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(generated.proof_bytes, &proof_sha256, .{});
    return .{
        .proof_bytes = generated.proof_bytes.len,
        .proof_sha256 = proof_sha256,
        .transcript_digest = generated.channel_digest,
        .transcript_draws = generated.channel_draws,
    };
}

/// Compares the predecessor against the production-bound Tree-1/Tree-2 epochs,
/// quotient scheduler, and PCS openings at every requested width. Each arm is
/// independently verified before exact statement, claims, transcript, and
/// proof bytes are compared, so completion order can never become protocol
/// order.
pub fn compareExecutionWidths(
    allocator: std.mem.Allocator,
    guest: *const committed.Guest,
    widths: []const usize,
) !Evidence {
    if (widths.len == 0) return error.EmptyExecutionWidthSet;
    const predecessor = try runArm(allocator, guest, null, .{});
    defer predecessor.deinit(allocator);
    var expected_composition_receipt: ?composition_work.Receipt = null;
    var expected_pcs_shell_receipt: ?pcs_shell_work.Receipt = null;

    for (widths) |width| {
        const audited = try runAuditedArm(allocator, guest, width);
        const planned = audited.arm;
        defer planned.deinit(allocator);
        try expectProofPoolAudit(audited.audit, width, true, false);
        try expectEqualStatement(predecessor.statement, planned.statement);
        try expectEqualClaim(
            predecessor.statement,
            predecessor.claim,
            planned.claim,
        );
        try std.testing.expectEqual(
            predecessor.channel_digest,
            planned.channel_digest,
        );
        try std.testing.expectEqual(
            predecessor.channel_draws,
            planned.channel_draws,
        );
        try std.testing.expectEqualSlices(
            u8,
            predecessor.proof_bytes,
            planned.proof_bytes,
        );
        try audited.composition_receipt.validate();
        if (expected_composition_receipt) |expected| {
            try std.testing.expect(std.meta.eql(
                expected,
                audited.composition_receipt,
            ));
        } else {
            expected_composition_receipt = audited.composition_receipt;
        }
        try audited.pcs_shell_receipt.validate();
        if (expected_pcs_shell_receipt) |expected| {
            try std.testing.expect(std.meta.eql(
                expected,
                audited.pcs_shell_receipt,
            ));
        } else {
            expected_pcs_shell_receipt = audited.pcs_shell_receipt;
        }
    }
    const composition_receipt = expected_composition_receipt orelse
        return error.MissingCompositionWorkReceipt;
    const pcs_shell_receipt = expected_pcs_shell_receipt orelse
        return error.MissingPcsShellWorkReceipt;

    var proof_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        predecessor.proof_bytes,
        &proof_sha256,
        .{},
    );
    return .{
        .proof_bytes = predecessor.proof_bytes.len,
        .proof_sha256 = proof_sha256,
        .transcript_digest = predecessor.channel_digest,
        .transcript_draws = predecessor.channel_draws,
        .composition_authority_digest = composition_receipt.authority_digest,
        .composition_receipt_digest = composition_receipt.receipt_digest,
        .pcs_shell_receipt_digest = pcs_shell_receipt.receipt_digest,
    };
}

/// Injects failure at the PCS opening boundary after Tree 1, Tree 2, and
/// quotient composition have completed. The same process must then complete
/// and verify another proof, establishing that the failed attempt released its
/// scoped binding, leases, queued tasks, commitment owners, and output slot.
pub fn expectExecutionFailureUnwindsAndRecovers(
    allocator: std.mem.Allocator,
    guest: *const committed.Guest,
    worker_count: usize,
) !void {
    var failed_audit = work_pool.TestProofPoolAudit.init(.{
        .fail_at_stage = .openings,
        .probe_nested_helper = worker_count > 1,
    });
    const failed_receipt = blk: {
        var binding = try work_pool.TestProofPoolAuditBinding.init(&failed_audit);
        defer binding.deinit();
        if (runArm(allocator, guest, null, executionOptions(worker_count))) |unexpected| {
            defer unexpected.deinit(allocator);
            return error.ExpectedProofPoolAuditInjectedFailure;
        } else |err| {
            try std.testing.expectEqual(error.ProofPoolAuditInjectedFailure, err);
        }
        break :blk failed_audit.snapshot();
    };
    try expectProofPoolAudit(failed_receipt, worker_count, false, true);

    const recovered = try runAuditedArm(allocator, guest, worker_count);
    defer recovered.arm.deinit(allocator);
    try expectProofPoolAudit(recovered.audit, worker_count, true, false);
}

const AuditedArm = struct {
    arm: *Snapshot,
    audit: work_pool.TestProofPoolAuditSnapshot,
    composition_receipt: composition_work.Receipt,
    pcs_shell_receipt: pcs_shell_work.Receipt,
};

fn runAuditedArm(
    allocator: std.mem.Allocator,
    guest: *const committed.Guest,
    worker_count: usize,
) !AuditedArm {
    var audit = work_pool.TestProofPoolAudit.init(.{
        .probe_nested_helper = worker_count > 1,
    });
    var binding = try work_pool.TestProofPoolAuditBinding.init(&audit);
    defer binding.deinit();
    var receipt_audit: composition_work.testing.ReceiptAudit = .{};
    var receipt_binding = try composition_work.testing.ReceiptAuditBinding.init(
        &receipt_audit,
    );
    defer receipt_binding.deinit();
    var shell_receipt_audit: pcs_shell_work.testing.ReceiptAudit = .{};
    var shell_receipt_binding = try pcs_shell_work.testing.ReceiptAuditBinding.init(
        &shell_receipt_audit,
    );
    defer shell_receipt_binding.deinit();
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "test",
        "riscv-real-proof-composition-receipt",
        .{ .capture_tasks = false, .capture_work = true },
    );
    defer recorder.deinit();
    const arm = try runArmWithRecorder(
        allocator,
        guest,
        null,
        executionOptions(worker_count),
        &recorder,
    );
    errdefer arm.deinit(allocator);

    const work = recorder.workCaptureRecorder() orelse unreachable;
    const composition_site = @intFromEnum(
        prover_api.work_profile.Site.air_composition_on_domain,
    );
    try std.testing.expectEqual(@as(u64, 1), work.planned_sites[composition_site]);
    try std.testing.expectEqual(@as(u64, 1), work.completed_sites[composition_site]);
    for ([_]prover_api.work_profile.Site{
        .oods_seed_to_point,
        .oods_mask_points,
        .oods_constraint_evaluation,
    }) |site| {
        const index = @intFromEnum(site);
        try std.testing.expectEqual(@as(u64, 1), work.planned_sites[index]);
        try std.testing.expectEqual(@as(u64, 1), work.completed_sites[index]);
    }
    const pcs_shell_site = @intFromEnum(
        prover_api.work_profile.Site.pcs_transcript_shell,
    );
    try std.testing.expectEqual(@as(u64, 1), work.planned_sites[pcs_shell_site]);
    try std.testing.expectEqual(@as(u64, 1), work.completed_sites[pcs_shell_site]);
    const receipt_snapshot = receipt_audit.snapshot();
    try std.testing.expectEqual(@as(usize, 1), receipt_snapshot.observation_count);
    const composition_receipt = receipt_snapshot.receipt orelse
        return error.MissingCompositionWorkReceipt;
    try composition_receipt.validate();
    const shell_receipt_snapshot = shell_receipt_audit.snapshot();
    try std.testing.expectEqual(
        @as(usize, 1),
        shell_receipt_snapshot.observation_count,
    );
    const pcs_shell_receipt = shell_receipt_snapshot.receipt orelse
        return error.MissingPcsShellWorkReceipt;
    try pcs_shell_receipt.validate();
    return .{
        .arm = arm,
        .audit = audit.snapshot(),
        .composition_receipt = composition_receipt,
        .pcs_shell_receipt = pcs_shell_receipt,
    };
}

fn executionOptions(worker_count: usize) orchestration.ExecutionOptions {
    return .{
        .cpu = .{
            .worker_count = worker_count,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        },
    };
}

fn expectProofPoolAudit(
    receipt: work_pool.TestProofPoolAuditSnapshot,
    worker_count: usize,
    expect_publication: bool,
    expect_injected_failure: bool,
) !void {
    const expected_pool_address = if (worker_count > 1) receipt.pool_address else 0;
    try std.testing.expectEqual(
        @as(usize, if (worker_count > 1) 1 else 0),
        receipt.pool_init_count,
    );
    try std.testing.expectEqual(receipt.pool_init_count, receipt.pool_deinit_count);
    try std.testing.expectEqual(receipt.pool_init_count, receipt.binding_init_count);
    try std.testing.expectEqual(receipt.binding_init_count, receipt.binding_deinit_count);
    if (worker_count > 1) try std.testing.expect(receipt.pool_address != 0);

    for (receipt.stage_observations, receipt.stage_pool_addresses) |observations, address| {
        try std.testing.expect(observations >= 1);
        try std.testing.expectEqual(expected_pool_address, address);
    }
    try std.testing.expectEqual(@as(usize, 0), receipt.stage_identity_mismatches);
    try std.testing.expect(receipt.global_resolution_count >= 1);
    try std.testing.expectEqual(@as(usize, 0), receipt.global_resolution_mismatches);

    try std.testing.expectEqual(receipt.lease_acquire_count, receipt.lease_release_count);
    try std.testing.expectEqual(@as(usize, 0), receipt.active_lease_count);
    try std.testing.expectEqual(@as(usize, 0), receipt.active_leased_workers);
    try std.testing.expect(receipt.max_leased_workers <= worker_count);
    try std.testing.expectEqual(receipt.structured_submitted, receipt.structured_completed);
    if (worker_count > 1) {
        try std.testing.expect(receipt.lease_acquire_count >= 1);
        try std.testing.expect(receipt.structured_submitted >= 1);
        try std.testing.expectEqual(@as(usize, 1), receipt.nested_helper_probe_count);
        try std.testing.expectEqual(@as(usize, 0), receipt.nested_helper_saw_pool_count);
        try std.testing.expectEqual(@as(usize, 1), receipt.nested_binding_denied_count);
    } else {
        try std.testing.expectEqual(@as(usize, 0), receipt.lease_acquire_count);
        try std.testing.expectEqual(@as(usize, 0), receipt.structured_submitted);
        try std.testing.expectEqual(@as(usize, 0), receipt.nested_helper_probe_count);
        try std.testing.expectEqual(@as(usize, 0), receipt.nested_helper_saw_pool_count);
        try std.testing.expectEqual(@as(usize, 0), receipt.nested_binding_denied_count);
    }

    try std.testing.expectEqual(
        @as(usize, @intFromBool(expect_publication)),
        receipt.publication_count,
    );
    try std.testing.expectEqual(
        @as(usize, @intFromBool(expect_injected_failure)),
        receipt.injected_failure_count,
    );
    try std.testing.expectEqual(@as(usize, 0), receipt.deinit_residual_leased_workers);
    try std.testing.expectEqual(@as(usize, 0), receipt.deinit_residual_reserved_slots);
    try std.testing.expectEqual(@as(usize, 0), receipt.deinit_residual_active_slots);
}

const Snapshot = struct {
    statement: prover.RiscVStatement,
    claim: prover.RiscVInteractionClaim,
    channel_digest: [32]u8,
    channel_draws: u32,
    proof_bytes: []u8,

    fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.proof_bytes);
        allocator.destroy(self);
    }
};

fn runArm(
    allocator: std.mem.Allocator,
    guest: *const committed.Guest,
    mutation: ?committed.Mutation,
    execution: orchestration.ExecutionOptions,
) !*Snapshot {
    return runArmWithRecorder(
        allocator,
        guest,
        mutation,
        execution,
        null,
    );
}

fn runArmWithRecorder(
    allocator: std.mem.Allocator,
    guest: *const committed.Guest,
    mutation: ?committed.Mutation,
    execution: orchestration.ExecutionOptions,
    recorder: ?*prover_api.stage_profile.Recorder,
) !*Snapshot {
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    var output = try orchestration.runRiscVWithEngineAndPublicDataUsingChannelAndExecution(
        riscv_cpu.CpuProverEngine,
        .prove,
        allocator,
        committed.PCS_CONFIG,
        &guest.run.execution_trace,
        &guest.run.state_chain_tracker,
        &guest.run.rw_memory,
        recorder,
        guest.public.data,
        &channel,
        mutation,
        null,
        execution,
    );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);

    var encoded: std.ArrayList(u8) = .{};
    defer encoded.deinit(allocator);
    try postcard.serializeProof(prover.Hasher, encoded.writer(allocator), output.proof);

    const snapshot = try allocator.create(Snapshot);
    errdefer allocator.destroy(snapshot);
    snapshot.* = .{
        .statement = output.statement,
        .claim = output.interaction_claim.*,
        .channel_digest = channel.digestBytes(),
        .channel_draws = channel.n_draws,
        .proof_bytes = try encoded.toOwnedSlice(allocator),
    };
    errdefer allocator.free(snapshot.proof_bytes);

    proof_moved = true;
    try riscv_cpu.verifyRiscV(
        allocator,
        committed.PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    );
    return snapshot;
}

fn expectEqualStatement(
    generated: prover.RiscVStatement,
    legacy: prover.RiscVStatement,
) !void {
    try std.testing.expectEqual(generated.n_components, legacy.n_components);
    try std.testing.expectEqualSlices(
        prover.FamilyComponentDesc,
        generated.component_descs[0..generated.n_components],
        legacy.component_descs[0..legacy.n_components],
    );
    try std.testing.expectEqual(generated.n_infra, legacy.n_infra);
    try std.testing.expectEqualSlices(
        prover.InfraComponentDesc,
        generated.infra_descs[0..generated.n_infra],
        legacy.infra_descs[0..legacy.n_infra],
    );
    try std.testing.expectEqual(generated.initial_pc, legacy.initial_pc);
    try std.testing.expectEqual(generated.final_pc, legacy.final_pc);
    try std.testing.expectEqual(generated.total_steps, legacy.total_steps);
    try expectEqualPublicData(generated.public_data, legacy.public_data);
}

fn expectEqualPublicData(
    generated: frontend.air.public_data.PublicData,
    legacy: frontend.air.public_data.PublicData,
) !void {
    try std.testing.expectEqual(generated.initial_pc, legacy.initial_pc);
    try std.testing.expectEqual(generated.final_pc, legacy.final_pc);
    try std.testing.expectEqual(generated.clock, legacy.clock);
    try std.testing.expectEqual(generated.initial_regs, legacy.initial_regs);
    try std.testing.expectEqual(generated.final_regs, legacy.final_regs);
    try std.testing.expectEqual(generated.reg_last_clock, legacy.reg_last_clock);
    try std.testing.expectEqual(generated.program_root, legacy.program_root);
    try std.testing.expectEqual(generated.initial_rw_root, legacy.initial_rw_root);
    try std.testing.expectEqual(generated.final_rw_root, legacy.final_rw_root);
    try std.testing.expectEqual(generated.completion, legacy.completion);
    try std.testing.expectEqual(generated.io_entries.input_start, legacy.io_entries.input_start);
    try std.testing.expectEqual(generated.io_entries.input_len, legacy.io_entries.input_len);
    try std.testing.expectEqual(generated.io_entries.output_len, legacy.io_entries.output_len);
    try std.testing.expectEqual(
        generated.io_entries.output_len_addr,
        legacy.io_entries.output_len_addr,
    );
    try std.testing.expectEqual(
        generated.io_entries.output_data_addr,
        legacy.io_entries.output_data_addr,
    );
    try std.testing.expectEqualSlices(
        u32,
        generated.io_entries.input_words,
        legacy.io_entries.input_words,
    );
    try std.testing.expectEqualSlices(
        frontend.air.public_data.OutputWord,
        generated.io_entries.output_words,
        legacy.io_entries.output_words,
    );
}

fn expectEqualClaim(
    statement: prover.RiscVStatement,
    generated: prover.RiscVInteractionClaim,
    legacy: prover.RiscVInteractionClaim,
) !void {
    try std.testing.expectEqual(generated.n_components, legacy.n_components);
    try std.testing.expectEqual(generated.n_infra, legacy.n_infra);
    try std.testing.expectEqual(generated.interaction_pow, legacy.interaction_pow);
    for (0..statement.n_components) |index| {
        const family = statement.component_descs[index].family;
        try std.testing.expectEqualSlices(
            @import("stwo_core").fields.qm31.QM31,
            try generated.opcodeClaims(family, index),
            try legacy.opcodeClaims(family, index),
        );
    }
    for (0..statement.n_infra) |index| {
        const kind = statement.infra_descs[index].kind;
        try std.testing.expectEqualSlices(
            @import("stwo_core").fields.qm31.QM31,
            try generated.infraClaims(kind, index),
            try legacy.infraClaims(kind, index),
        );
    }
}
