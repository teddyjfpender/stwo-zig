//! Heavy gate: independently pinned strong native child enters a strong local outer proof.
//! This does not construct or publish the 49-row V3 wrapper.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("recursive_segment_v3_native_test_fixture.zig");
const pinned_ingress = @import("recursive_segment_v3_native_security_ingress.zig");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const outer_cohort = @import("recursive_segment_v2_outer_cohort.zig");

const recursion = frontend.recursion;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);

// Independently recorded for this ELF and local V2 projection, as in the
// pinned-native gate. These values are never derived from the proof under test.
const known_tree0 = [8]u32{
    2053578112, 2007969840, 1758814271, 1936034131,
    1603516961, 444025432,  32631551,   1362738667,
};
const known_key_id = [32]u8{
    0x0d, 0xe4, 0xa3, 0x90, 0x93, 0x1c, 0xa0, 0xa3,
    0x66, 0x39, 0x57, 0x5a, 0x0b, 0x76, 0x40, 0x38,
    0x0c, 0xfb, 0x4b, 0xa7, 0x1d, 0xc1, 0x34, 0x23,
    0xbc, 0xa4, 0x47, 0x36, 0xa1, 0x41, 0x61, 0xe9,
};

test "real q193 native child feeds freshly verified q193 local outer" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(false, .self_loop);
    var session = try frontend.runner.Poseidon2ExecutionSession.init(allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left = try session.startSegment(1);
    defer left.deinit();
    var right = try session.resumeSegment(left.base.continuation.?, 16);
    defer right.deinit();
    const source = try fixture.rightGlobal(allocator, &left.base, &right.base);
    const pinned_key = try pinned_ingress.PinnedKeyV1.admit(known_tree0, known_key_id);
    var timer = try std.time.Timer.start();
    var verified = try pinned_ingress.proveAndVerifyPinned(
        Engine,
        allocator,
        &source,
        recursion.poseidon2_channel.hashBytes("native-local-v3-session", 0x4e56_3250),
        pinned_key,
    );
    defer verified.deinit();
    const native_ns = timer.lap();

    var profile = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(recursion.protocol.PCS_CONFIG),
        &verified.native.capture.proof,
    );
    defer profile.deinit();
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    @memcpy(&tree_heights, profile.trace_tree_heights);
    const shape = try recursion.transcript_shape.derive(
        profile.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = profile.sampled_value_count,
            .queried_values_per_query = profile.queried_values_per_query,
            .claimed_sum_count = profile.claimed_sum_count,
            .interaction_pow_bits = profile.interaction_pow_bits,
            .pcs_pow_bits = profile.pcs_pow_bits,
        },
    );
    const schedule = recursion.air.verifier_schedule;
    var vm_plan = try schedule.Plan.initShape(allocator, try schedule.vmProgramSpec(0, 0), shape);
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, shape);
    defer recursion_plan.deinit();
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        recursion.poseidon2_channel.hashBytes("strong-v3-local-segment-vk", 0x4b56_3353),
        recursion.poseidon2_channel.hashBytes("strong-v3-local-parent-vk", 0x4b56_3350),
    );
    var prepared = try leaf_outer.PreparedNativeV2LeafOuter.init(
        allocator,
        allocator,
        &verified.native.capture,
        recursion.protocol.PCS_CONFIG,
        verified.native.interaction_pow,
        keys,
        recursion.air.universal_challenges.UniversalRelations.dummy(),
        .{ .vm = &vm_plan, .recursion = &recursion_plan },
    );
    verified.native.capture_owned = false;
    defer prepared.deinit();
    try pinned_ingress.admitPreparedNativeV2(&prepared, pinned_key);

    const strong_outer = recursion.segment_outer_transaction_v3.ForBackend(CpuBackend);
    const StrongKernel = strong_outer.EngineKernel(outer_cohort.Cohort);
    var strong = try StrongKernel.proveAndVerify(allocator, &prepared);
    defer strong.deinit(allocator);
    try strong.receipt.validate();
    try strong.artifact.validateEncoding();
    var cohort = try outer_cohort.Cohort.init(allocator, &prepared);
    defer cohort.deinit();
    try strong.field_snapshot.validateAgainst(cohort.manifest(), &strong.artifact);
    std.debug.print(
        "V3_STRONG_CHAIN native_ns={d} outer_transaction_ns={d} outer_prove_ns={d} outer_verify_ns={d} native_proof_bytes={d} outer_proof_bytes={d} wrapper_proof_created=false\n",
        .{ native_ns, strong.receipt.transaction_ns, strong.receipt.prover_ns, strong.receipt.fresh_verifier_ns, verified.native.proof_bytes.len, strong.artifact.proof_bytes.len },
    );
}
