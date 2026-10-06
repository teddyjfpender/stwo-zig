//! Heavy gate: independently pinned strong native child enters a strong local outer proof.
//! This does not construct or publish the 49-row V3 wrapper.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("recursive_segment_v3_native_test_fixture.zig");
const pinned_ingress = @import("recursive_segment_v3_native_security_ingress.zig");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const outer_cohort = @import("recursive_segment_v2_outer_cohort.zig");
const M31 = @import("stwo_core").fields.m31.M31;

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

    var cohort = try outer_cohort.Cohort.init(allocator, &prepared);
    defer cohort.deinit();
    try diagnoseDirect47(allocator, &prepared, &verified.native.global_metadata, &verified.native.link, &cohort);

    const strong_outer = recursion.segment_outer_transaction_v3.ForBackend(CpuBackend);
    const StrongKernel = strong_outer.EngineKernel(outer_cohort.Cohort);
    var strong = try StrongKernel.proveAndVerify(allocator, &prepared);
    defer strong.deinit(allocator);
    try strong.receipt.validate();
    try strong.artifact.validateEncoding();
    try strong.field_snapshot.validateAgainst(cohort.manifest(), &strong.artifact);
    std.debug.print(
        "V3_STRONG_CHAIN native_ns={d} outer_transaction_ns={d} outer_prepare_ns={d} outer_prove_ns={d} outer_serialize_ns={d} outer_destroy_ns={d} outer_verify_ns={d} native_proof_bytes={d} outer_proof_bytes={d} outer_producer_peak_bytes={d} wrapper_proof_created=false\n",
        .{ native_ns, strong.receipt.transaction_ns, strong.receipt.producer_prepare_ns, strong.receipt.prover_ns, strong.receipt.serialize_ns, strong.receipt.producer_destroy_ns, strong.receipt.fresh_verifier_ns, verified.native.proof_bytes.len, strong.artifact.proof_bytes.len, strong.receipt.producer_peak_bytes },
    );
}

fn diagnoseDirect47(
    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    metadata: *const recursion.segment_leaf_local_authority_v3.MetadataV3,
    link: *const recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3,
    cohort: *outer_cohort.Cohort,
) !void {
    const program_mod = recursion.ethereum_leaf_link_program_v3;
    const hash_mod = recursion.segment_leaf_wrapper_field_hash_witness_v3;
    const source_air = recursion.air.ethereum_leaf_link_source_v1;
    const arithmetic_air = recursion.air.ethereum_leaf_link_arithmetic_v1;
    const arithmetic_witness = recursion.air.ethereum_leaf_link_arithmetic_witness_v1;
    const direct_rows = recursion.segment_leaf_wrapper_cohort_direct_rows_v4;
    const candidate = recursion.segment_leaf_wrapper_cohort_candidate_v4;
    const call_buffer = recursion.segment_leaf_wrapper_cohort_calls_v3;
    const provider_mod = recursion.segment_leaf_wrapper_cohort_provider_v3;
    const plan_mod = recursion.segment_leaf_wrapper_roster_direct_v4;
    var native = try recursion.segment_leaf_wrapper_field_witness_v3.NativeV1.initFromPrepared(allocator, prepared);
    defer native.deinit();
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    var source = try recursion.segment_leaf_wrapper_source_projection_direct_v3.initFromNative(allocator, &program, prepared, metadata, link, &native);
    defer source.deinit();
    const metadata_words = try metadata.identityWords();
    const link_words = try link.identityWords();
    var metadata_hash = try hash_mod.HashV1.init(allocator, &metadata_words, recursion.segment_leaf_local_authority_v3.METADATA_ID_DOMAIN, source_air.METADATA_SCOPE, source_air.METADATA_DIGEST_KIND, recursion.ethereum_leaf_link_program_v1.METADATA_HASH_STEP_BASE, try metadata.identity());
    defer metadata_hash.deinit();
    var link_hash = try hash_mod.HashV1.init(allocator, &link_words, recursion.segment_leaf_local_verified_link_v3.IDENTITY_DOMAIN, source_air.LINK_SCOPE, source_air.LINK_DIGEST_KIND, recursion.ethereum_leaf_link_program_v1.LINK_HASH_STEP_BASE, link.identity);
    defer link_hash.deinit();
    var arithmetic = [_]arithmetic_air.Row{[_]M31{M31.zero()} ** arithmetic_air.LOGICAL_INPUT_COUNT} ** 16;
    arithmetic[0] = try arithmetic_witness.logicalRow(.entry_root, metadata.entry.continuation_root, false, 0, 0);
    arithmetic[1] = try arithmetic_witness.logicalRow(.exit_root, metadata.exit.continuation_root, false, 0, 0);
    arithmetic[2] = try arithmetic_witness.logicalRow(.completion, 0, metadata.completion != null, 0, 0);
    arithmetic[3] = try arithmetic_witness.logicalRow(.position, 0, false, metadata.global_cycle_start, metadata.local_cycle_count);
    const base_calls = try cohort.core.completePoseidonCalls();
    const plan = try plan_mod.Plan.build(allocator, cohort.manifest(), &program, .{
        .program_words = native.program.words.len,
        .base_poseidon_calls = base_calls.len,
    });
    const parts = [_][]const call_buffer.Call{
        base_calls, metadata_hash.calls, link_hash.calls, native.program_hash.calls,
    };
    var buffer = try call_buffer.Buffer.init(allocator, &parts);
    defer buffer.deinit();
    const writer = try provider_mod.Writer.initForDirectPlan(allocator, &plan, &buffer, &parts);
    var rows = try direct_rows.Rows.init(allocator, &plan, &program, &source, &arithmetic, &native, &metadata_hash, &link_hash);
    defer rows.deinit();
    const pp = try allocateDirectTree(allocator, &plan, 0);
    defer freeDirectTree(allocator, pp);
    const main = try allocateDirectTree(allocator, &plan, 1);
    defer freeDirectTree(allocator, main);
    const interaction = try allocateDirectTree(allocator, &plan, 2);
    defer freeDirectTree(allocator, interaction);
    try candidate.fillPreprocessed(allocator, cohort, &plan, &writer, &rows, pp);
    try candidate.fillMain(allocator, cohort, &plan, &writer, &rows, main);
    const relations = recursion.air.universal_challenges.UniversalRelations.dummy();
    const shared = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    const claims = try candidate.fillInteraction(allocator, cohort, &plan, &writer, &rows, &relations, &shared, main, interaction);
    const boundary = try cohort.publicWireBoundary(&relations);
    const residuals = try claims.residuals(&plan, &boundary);
    var nonzero_domains: usize = 0;
    for (residuals.domain_totals, 0..) |sum, domain| {
        if (sum.isZero()) continue;
        nonzero_domains += 1;
        const limbs = sum.toM31Array();
        std.debug.print("DIRECT47_RESIDUAL domain={d} limbs={d},{d},{d},{d}\n", .{ domain, limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() });
        for (claims.audits, 0..) |audit, row| {
            const contribution = audit.values[domain];
            if (contribution.isZero()) continue;
            const term = contribution.toM31Array();
            std.debug.print("DIRECT47_TERM domain={d} row={d} limbs={d},{d},{d},{d}\n", .{
                domain, row, term[0].toU32(), term[1].toU32(), term[2].toU32(), term[3].toU32(),
            });
        }
    }
    std.debug.print("DIRECT47_CANDIDATE claims=47 nonzero_domains={d} framework_zero={} proof_created=false\n", .{ nonzero_domains, residuals.framework_total.isZero() });
    if (nonzero_domains == 0) _ = try claims.verifyAllDomains(&plan, &boundary);
}

fn allocateDirectTree(allocator: std.mem.Allocator, plan: *const recursion.segment_leaf_wrapper_roster_direct_v4.Plan, tree: u8) ![][]M31 {
    const count = switch (tree) {
        0 => plan.total_preprocessed_columns,
        1 => plan.total_main_columns,
        2 => plan.total_interaction_columns,
        else => return error.InvalidDirectTree,
    };
    const columns = try allocator.alloc([]M31, count);
    var written: usize = 0;
    errdefer {
        for (columns[0..written]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const offset = switch (tree) {
            0 => item.preprocessed_offset,
            1 => item.main_offset,
            2 => item.interaction_offset,
            else => unreachable,
        };
        const n = switch (tree) {
            0 => item.geometry.preprocessed_columns,
            1 => item.geometry.main_columns,
            2 => item.geometry.interaction_columns,
            else => unreachable,
        };
        if (offset != written) return error.InvalidDirectTree;
        const rows = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (columns[offset..][0..n]) |*column| {
            column.* = try allocator.alloc(M31, rows);
            @memset(column.*, M31.zero());
            written += 1;
        }
    }
    return columns;
}

fn freeDirectTree(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
