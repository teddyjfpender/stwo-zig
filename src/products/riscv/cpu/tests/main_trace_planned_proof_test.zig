//! Exact production proof and lifecycle differential for one bounded pool.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");
const frontend = @import("stwo_riscv_frontend");
const prover_api = @import("stwo_prover_api");
const riscv_cpu = @import("stwo_riscv_cpu_integration");

const prover = frontend.prover_mod;

const exact_proof_work_sites = [_]prover_api.work_profile.Site{
    .oods_seed_to_point,
    .oods_mask_points,
    .oods_constraint_evaluation,
    .relation_challenges_and_interaction_traces,
    .quotient_sample_preparation,
    .quotient_row_execution,
    .air_composition_on_domain,
    .pcs_transcript_shell,
};

fn requireExactProofWorkSites(work: anytype) !void {
    for (exact_proof_work_sites) |site| {
        const index = @intFromEnum(site);
        try std.testing.expectEqual(@as(u64, 1), work.planned_sites[index]);
        try std.testing.expectEqual(@as(u64, 1), work.completed_sites[index]);
    }
}

const BODY = [_]u32{
    // x1 carries the fixture's halt/output base and must survive the body;
    // x4 is the aligned public-input address established by its prologue.
    0x0010_0313, // ADDI x6, x0, 1
    0x0020_0393, // ADDI x7, x0, 2
    0x0073_0433, // ADD  x8, x6, x7
    0x0082_2023, // SW   x8, 0(x4)
    0x0002_2483, // LW   x9, 0(x4)
    0x0094_0463, // BEQ  x8, x9, +8
    0x0630_0513, // skipped ADDI x10, x0, 99
    0x02a0_0493, // ADDI x9, x0, 42
};

test "one proof-scoped pool preserves exact N=1/2/4 proof identity" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();

    const evidence = try authority.compareExecutionWidths(
        allocator,
        &guest,
        &.{ 1, 2, 4 },
    );
    const composition_authority_digest = evidence.composition_authority_digest orelse
        return error.MissingCompositionWorkReceipt;
    const composition_receipt_digest = evidence.composition_receipt_digest orelse
        return error.MissingCompositionWorkReceipt;
    const pcs_shell_receipt_digest = evidence.pcs_shell_receipt_digest orelse
        return error.MissingPcsShellWorkReceipt;
    std.debug.print(
        "\n  proof-scoped execution: bytes={d} sha256={s} " ++
            "transcript={s} draws={d} composition-authority={s} " ++
            "composition-receipt={s} pcs-shell-receipt={s}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
            &std.fmt.bytesToHex(composition_authority_digest, .lower),
            &std.fmt.bytesToHex(composition_receipt_digest, .lower),
            &std.fmt.bytesToHex(pcs_shell_receipt_digest, .lower),
        },
    );
}

test "proof-scoped pool failure unwinds before a subsequent proof" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();

    try authority.expectExecutionFailureUnwindsAndRecovers(
        allocator,
        &guest,
        4,
    );
}

fn readDeterministicPhaseClock(context: *anyopaque) anyerror!u64 {
    const next: *u64 = @ptrCast(@alignCast(context));
    const sampled = next.*;
    next.* = try std.math.add(u64, sampled, 1);
    return sampled;
}

test "five-region phase meter covers one real independently verified proof" {
    const allocator = std.testing.allocator;
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "test",
        "riscv-v1-poseidon-witness",
        .{ .capture_work = true },
    );
    defer recorder.deinit();
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();

    // Exactly two clock reads per region make every duration one nanosecond.
    // This avoids a wall-clock assertion while proving that all five
    // production materialization boundaries execute and close before proof
    // publication.
    var next_tick: u64 = 0;
    var phase_meter = prover.proof_phase_meter.Meter.init(.{
        .context = &next_tick,
        .now_fn = readDeterministicPhaseClock,
    });
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    var output = try prover.proveRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter(
        riscv_cpu.CpuProverEngine,
        allocator,
        committed.PCS_CONFIG,
        &guest.run.execution_trace,
        &guest.run.state_chain_tracker,
        &guest.run.rw_memory,
        &recorder,
        guest.public.data,
        &channel,
        &phase_meter,
    );
    var proof_owned = true;
    defer if (proof_owned)
        output.deinit(allocator)
    else
        output.deinitAfterProofMoved(allocator);

    try phase_meter.requireComplete();
    try std.testing.expectEqual(prover.proof_phase_meter.REGION_COUNT, phase_meter.witness_ns);
    try std.testing.expectEqual(prover.proof_phase_meter.REGION_COUNT * 2, next_tick);
    const work = recorder.workCaptureRecorder() orelse unreachable;
    try requireExactProofWorkSites(work);
    const poseidon_site = @intFromEnum(
        prover_api.work_profile.Site.sparse_memory_and_guest_poseidon_witness,
    );
    try std.testing.expectEqual(@as(u64, 1), work.planned_sites[poseidon_site]);
    try std.testing.expectEqual(@as(u64, 1), work.completed_sites[poseidon_site]);
    const snapshot = try recorder.workSnapshot();
    try snapshot.validate();

    proof_owned = false;
    try riscv_cpu.verifyRiscV(
        allocator,
        committed.PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    );
}

test "profiled prepared Tree2 publishes exact interaction work" {
    const allocator = std.testing.allocator;
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "test",
        "riscv-prepared-tree2-interaction-work",
        .{ .capture_work = true },
    );
    defer recorder.deinit();
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();

    var channel = riscv_cpu.CpuProverEngine.Channel{};
    var output = try prover.proveRiscVWithEngineAndPublicDataUsingChannelAndExecution(
        riscv_cpu.CpuProverEngine,
        allocator,
        committed.PCS_CONFIG,
        &guest.run.execution_trace,
        &guest.run.state_chain_tracker,
        &guest.run.rw_memory,
        &recorder,
        guest.public.data,
        &channel,
        .{ .cpu = .{
            .worker_count = 4,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        } },
    );
    var proof_owned = true;
    defer if (proof_owned)
        output.deinit(allocator)
    else
        output.deinitAfterProofMoved(allocator);

    const work = recorder.workCaptureRecorder() orelse unreachable;
    try requireExactProofWorkSites(work);
    const snapshot = try recorder.workSnapshot();
    try snapshot.validate();
    std.debug.print("\n  prepared Tree2 work: adds={d} muls={d} invs={d}\n", .{
        work.counters.field_additions,
        work.counters.field_multiplications,
        work.counters.field_inversions,
    });
    // The whole-request snapshot may intentionally remain unavailable while
    // another producer marks its still-open P003 surface incomplete. The
    // completed-site ledger and live completed totals remain authoritative for
    // this producer. Its authenticated challenge receipt alone contributes 80
    // multiplications, while the prepared descriptors contribute all three
    // field-operation classes.
    try std.testing.expect(work.counters.field_additions > 0);
    try std.testing.expect(work.counters.field_multiplications >= 80);
    try std.testing.expect(work.counters.field_inversions > 0);

    proof_owned = false;
    try riscv_cpu.verifyRiscV(
        allocator,
        committed.PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    );
}
