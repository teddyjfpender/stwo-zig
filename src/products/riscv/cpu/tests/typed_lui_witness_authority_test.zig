//! Serial proof-level acceptance for the generated typed LUI authority.
//!
//! The A arm uses production dispatch. The B arm clears every final LUI shard,
//! regenerates it with the retired handwritten oracle, discards the generated
//! lookup counters, and re-ingests from those rewritten cells. Exact statement,
//! interaction-claim, terminal transcript state, and postcard proof bytes are
//! required—not merely successful verification.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");
const committed = @import("committed_forgery_harness.zig");

const orchestration = frontend.testing.prover_orchestration;
const prover = frontend.prover_mod;

const BODY = [_]u32{
    0x0000_0337, // LUI x6, 0
    0x7fff_f3b7, // LUI x7, 0x7ffff
    0x8000_0437, // LUI x8, 0x80000
    0xffff_f4b7, // LUI x9, 0xfffff
};

test "typed LUI generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 6), try guest.familyRowCount(.lui));

    // Intentionally serial: each complete proof transaction is finished and
    // verified before the alternate authority begins.
    const generated = try runArm(allocator, &guest, null);
    defer generated.deinit(allocator);
    const legacy = try runArm(allocator, &guest, .legacy_lui_authority);
    defer legacy.deinit(allocator);

    try expectEqualStatement(generated.statement, legacy.statement);
    try expectEqualClaim(generated.statement, generated.claim, legacy.claim);
    try std.testing.expectEqual(generated.channel_digest, legacy.channel_digest);
    try std.testing.expectEqual(generated.channel_draws, legacy.channel_draws);
    try std.testing.expectEqualSlices(u8, generated.proof_bytes, legacy.proof_bytes);

    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(generated.proof_bytes, &proof_digest, .{});
    std.debug.print(
        "\n  typed LUI authority proof: bytes={d} sha256={s} transcript={s} draws={d}\n",
        .{
            generated.proof_bytes.len,
            &std.fmt.bytesToHex(proof_digest, .lower),
            &std.fmt.bytesToHex(generated.channel_digest, .lower),
            generated.channel_draws,
        },
    );
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
) !*Snapshot {
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    var output = try orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
        riscv_cpu.CpuProverEngine,
        .prove,
        allocator,
        committed.PCS_CONFIG,
        &guest.run.execution_trace,
        &guest.run.state_chain_tracker,
        &guest.run.rw_memory,
        null,
        guest.public.data,
        &channel,
        mutation,
        null,
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

    // Verification consumes the proof on both success and failure.
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
