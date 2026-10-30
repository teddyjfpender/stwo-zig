//! Admission-only tests with real executed native/caller statements. Root
//! nominations and ROM counts below are not a complete execution proof.
const std = @import("std");
const core = @import("stwo_core");
const Scope = @import("../block_v8_endpoint_mixed_scope_v1.zig");
const P = @import("../blake3_ethereum_sha_profile.zig");
const Schema = @import("../../air/lookups/tables/schema.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
test "mixed scope independently binds real caller inventory ELF roots frame and lookup bounds" {
    const a = std.testing.allocator;
    const Elf = @import("../../runner/guest_precompile/test_elf.zig");
    const source = Elf.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = Elf.withReleaseAbi(source.len, &source);
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(6);
    defer segment.deinit();
    var witness = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &segment);
    defer witness.deinit();
    const external = P.externalCount(&witness.statement);
    try std.testing.expect(external > 0 and external < 6);
    const hash = @import("../block_v7_real_window_capture_v1.zig").sha(&elf);
    var image = try @import("../block_v8_endpoint_local_program_v1.zig").Owned.init(a, &elf, hash, .rv32im_zkvm_ethereum_sha_v1, .{});
    defer image.deinit();
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment.base);
    defer io.deinit();
    io.data.program_root = image.root;
    io.data.initial_rw_root = null;
    io.data.final_rw_root = null;
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    const owner = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, external);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const counts = try a.alloc(u64, image.leaves.len / 4);
    defer a.free(counts);
    @memset(counts, 0);
    // Admission nomination only; the joint program bus must independently
    // reject this if these are not the actual executed per-PC multiplicities.
    counts[0] = 7;
    var demand = try LP.nativeDemand(&owner.statement, external);
    try @import("../block_v5_precompile_table_demand_v1.zig").add(a, &demand, &witness.statement, 6, config);
    demand[@intFromEnum(Schema.Kind.range_check_8_8)] += 4;
    var sizes: [6]u32 = undefined;
    inline for (0..6) |i| sizes[i] = Schema.logSize(@enumFromInt(i));
    const input = Scope.Input{
        .shape = &owner.statement,
        .caller_statement = &witness.statement,
        .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = 6 },
        .cohort_ordinal = 0,
        .endpoint_count = 1,
        .native_roots = @splat(@splat(3)),
        .caller_roots = @splat(@splat(3)),
        .program_plan = .{ .program_root = image.root, .leaves = image.leaves, .multiplicities = counts, .expected_fetches = 7, .log_size = @max(7, std.math.log2_int_ceil(usize, counts.len)) },
        .program_roots = @splat(@splat(5)),
        .lookup_plan = .{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand },
        .lookup_layout = try @import("../block_v7_lookup_compact_layout_v1.zig").Layout.init(@splat(.dense), sizes),
        .lookup_roots = @splat(@splat(7)),
    };
    const trusted = Scope.Trusted{ .elf = &elf, .elf_sha256 = hash, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
    const admitted = try Scope.Owned.init(a, trusted, input, .{});
    defer admitted.deinit();
    try std.testing.expectEqual(external, admitted.external);
    try std.testing.expectEqual(@as(usize, 4), admitted.entries.len);
    try std.testing.expectEqual(image.info.halt_flag, admitted.halt.halt_address);
    try std.testing.expectEqual(input.native_roots[2], admitted.source().endpoint_root);
    var changed = input;
    changed.caller_roots[0][0] ^= 1;
    try std.testing.expectError(error.EndpointMixedFixedRootMismatch, Scope.Owned.init(a, trusted, changed, .{}));
    changed = input;
    changed.lookup_plan.max_requests[0] += 1;
    try std.testing.expectError(error.UntrustedEndpointMixedLookup, Scope.Owned.init(a, trusted, changed, .{}));
    changed = input;
    changed.frame.cycle_count -= 1;
    try std.testing.expectError(error.InvalidEndpointMixedFrame, Scope.Owned.init(a, trusted, changed, .{}));
    changed = input;
    changed.endpoint_count = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidEndpointMixedCohort, Scope.Owned.init(a, trusted, changed, .{}));
    changed = input;
    changed.caller_roots[1][0] ^= 1;
    const rebound = try Scope.Owned.init(a, trusted, changed, .{});
    defer rebound.deinit();
    try std.testing.expect(!std.meta.eql(admitted.identity, rebound.identity));
    try std.testing.expect(!std.meta.eql(admitted.epoch.digest, rebound.epoch.digest));
}
