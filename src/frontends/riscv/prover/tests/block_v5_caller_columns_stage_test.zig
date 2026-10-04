//! Complete caller reconstruction gates: physical commitments only, no STARK
//! proving, segment benchmark, driver execution or recursive proof generation.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../../runner/mod.zig");
const fixture = @import("../../runner/guest_precompile/test_elf.zig");
const Witness = @import("../block_v5_precompile_witness_v1.zig").Witness;
const Family = @import("../block_v5_precompile_family_proof_v1.zig");
const Stage = @import("../block_v5_caller_columns_stage_v1.zig");
const Pipeline = @import("../block_v5_caller_pipeline_v1.zig");
const Tables = @import("../../air/lookups/tables/mod.zig");
const Frame = @import("../../air/block/memory_event.zig").Frame;
const profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

test "staged full caller SHA and Keccak matrices selectors and signed counters recommit" {
    const diagnostic = fixture.buildEthereumSha(profile);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    try exercise(&elf, false);
}
test "staged full caller genuine signer secp private matrices and Keccak recommit" {
    const diagnostic = fixture.buildEthereumWithCompletionForProfile(.ecall, profile);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    try exercise(&elf, true);
}
fn exercise(elf: []const u8, signer: bool) !void {
    const a = std.testing.allocator;
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(16);
    defer segment.deinit();
    var witness = try Witness.initSegment(a, &segment);
    defer witness.deinit();
    try std.testing.expect(witness.statement.ethereum.counts.keccak_calls != 0);
    if (signer) {
        try std.testing.expect(witness.statement.ethereum.counts.signer_calls != 0);
        try std.testing.expect(witness.extension.secp_tape.recoveries.items.len != 0);
    } else try std.testing.expect(witness.statement.sha.call_count != 0);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const frame = Frame{ .clock_frame = segment.base.clock_frame, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = @intCast(segment.base.cycle_count) };
    var physical = try Family.ForBackend(Cpu).commitPhysicalFirstRound(a, &witness, witness.total_steps, config);
    defer physical.deinit(a);
    const descriptor = Stage.Descriptor{ .statement = witness.statement, .total_steps = witness.total_steps, .index = 0, .frame = frame, .config = config, .key_id = physical.key_id, .roots = physical.roots };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const limits = Stage.Limits{};
    const pin = try Stage.write(a, temporary.dir, "caller.columns", &witness, &descriptor, limits);
    var loaded = try Stage.ForBackend(Cpu).load(a, temporary.dir, "caller.columns", &descriptor, pin, limits);
    defer loaded.deinit(a);
    try std.testing.expectEqualDeep(descriptor.roots, loaded.first.roots);
    try std.testing.expectEqualDeep(witness.extension.shapes(), loaded.owner.witness.extension.shapes());
    try std.testing.expectEqualDeep(witness.sha_rows.geometry, loaded.owner.witness.sha_rows.geometry);
    const original_sha = witness.sha_rows.tuple();
    const restored_sha = loaded.owner.witness.sha_rows.tuple();
    inline for (@import("../../air/guest_precompile/sha256_memory_rows.zig").Airs, 0..) |_, i| {
        try std.testing.expectEqual(original_sha[i].len, restored_sha[i].len);
        for (original_sha[i], restored_sha[i]) |left, right| {
            for (left, right) |x, y| try std.testing.expectEqual(x.toU32(), y.toU32());
        }
    }
    // No invented recoveries are allocated to simulate a live construction
    // tape. Its real count is explicit independently admitted metadata.
    try std.testing.expectEqual(@as(usize, 0), loaded.owner.witness.extension.secp_tape.recoveries.items.len);
    try std.testing.expectEqual(witness.extension.signerCount(), loaded.owner.witness.extension.signerCount());
    var expected = try Tables.counter.Set.init(a);
    defer expected.deinit(a);
    try (@import("../../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = segment.extension.keccakf_calls.records(), .recovery = segment.extension.signer_recovery_calls.records() }).register(&expected);
    try @import("../../air/guest_precompile/sha256_lookup_registration.zig").register(a, &witness.sha_rows, &expected);
    for (expected.counters, loaded.owner.counters.counters) |left, right| {
        for (left.values, right.values) |x, y| try std.testing.expectEqual(x.toU32(), y.toU32());
    }
    var small = limits;
    small.max_reconstruction_bytes = 1;
    try std.testing.expectError(error.V5StagedCallerReconstructionLimit, Stage.ForBackend(Cpu).load(a, temporary.dir, "caller.columns", &descriptor, pin, small));
    var wrong_index = descriptor;
    wrong_index.index += 1;
    try std.testing.expectError(error.ChangedV5WitnessScope, Stage.ForBackend(Cpu).load(a, temporary.dir, "caller.columns", &wrong_index, pin, limits));
    var wrong_clock = descriptor;
    wrong_clock.frame.global_first_cycle += 1;
    try std.testing.expectError(error.ChangedV5WitnessScope, Stage.ForBackend(Cpu).load(a, temporary.dir, "caller.columns", &wrong_clock, pin, limits));
    var wrong_key = descriptor;
    wrong_key.key_id[0] ^= 1;
    try std.testing.expectError(error.ChangedV5StagedCallerDescriptor, Stage.ForBackend(Cpu).load(a, temporary.dir, "caller.columns", &wrong_key, pin, limits));
    var wrong_root = descriptor;
    wrong_root.roots[1][0] ^= 1;
    const rehashed = try Stage.write(a, temporary.dir, "wrong.columns", &witness, &wrong_root, limits);
    try std.testing.expectError(error.V5StagedCallerRootMismatch, Stage.ForBackend(Cpu).load(a, temporary.dir, "wrong.columns", &wrong_root, rehashed, limits));
    var wrong_pin = pin;
    wrong_pin.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5WitnessFile, Stage.ForBackend(Cpu).load(a, temporary.dir, "caller.columns", &descriptor, wrong_pin, limits));

    // Exercise actual first-pass integration: one already-owned arithmetic
    // witness supplies collection, byte census and streamed file publication.
    var combined = try Tables.counter.Set.init(a);
    defer combined.deinit(a);
    var staged_pin: Stage.Pin = undefined;
    var proposal = try Pipeline.ForBackend(Cpu).collectSegmentWithStaging(a, &segment, 0, frame, config, .{ .max_metadata_bytes = 1 << 20, .max_external_slots = 1024 }, &combined, .{ .dir = temporary.dir, .name = "collected.columns", .limits = limits, .pin_out = &staged_pin });
    defer proposal.deinit();
    try std.testing.expectEqualDeep(descriptor.roots, proposal.roots);
    try std.testing.expectEqualDeep(pin, staged_pin);
}
