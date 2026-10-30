//! Genuine two-member original, with shared provider proof and independent
//! post-producer verification exactly once. Global RAM remains deliberately open.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Fixture = @import("block_v8_endpoint_group_fixture.zig");
const Original = @import("../block_v8_endpoint_group_proof_v1.zig");
const Statement = @import("../block_v8_endpoint_group_statement_v1.zig");
const Codec = @import("../block_v8_endpoint_group_codec_v1.zig");
const Scope = @import("../block_v8_endpoint_group_scope_v1.zig");
const Ledger = @import("../block_v8_endpoint_group_ledger_v1.zig");
test "group original two real native cohorts shares providers and freshly receives once" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 16 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const fixture = try Fixture.Owned.init(a, 2, config);
    var fixture_live = true;
    defer if (fixture_live) fixture.deinit();
    var timing: Original.Timings = .{};
    const proof = try Original.produceWithOptions(a, fixture.trusted, fixture.input(), fixture.fixed, fixture.stages(), .{}, .{ .program = &fixture.image.?, .timings = &timing });
    var proof_live = true;
    defer if (proof_live) proof.deinit();
    try std.testing.expectEqual(@as(usize, 16), proof.stark.commitment_scheme_proof.commitments.items.len);
    try std.testing.expectEqual(@as(u32, 2), proof.summary.cohorts);
    try std.testing.expectEqual(@as(u64, 8), proof.summary.cycles);
    try std.testing.expectEqual(.group_execution_global_ram_open, proof.summary.scope);
    try std.testing.expectEqual(@as(usize, 2), proof.endpoint_leases.len);
    for (proof.endpoint_leases) |lease| try std.testing.expect(lease != null);
    var input = fixture.input();
    input.members = proof.members;
    input.fixed_root = proof.fixed_root;
    input.range_main_root = proof.range_main_root;
    const public = try Statement.Owned.init(a, fixture.trusted, input);
    defer public.deinit();
    const bytes = try Codec.encode(a, proof, fixture.trusted, input, .{});
    defer a.free(bytes);
    // Prover-only domain batching must preserve every physical claim, opening,
    // transcript operation and complete canonical proof byte.
    const candidate = try Original.produceWithOptions(a, fixture.trusted, fixture.input(), fixture.fixed, fixture.stages(), .{}, .{ .program = &fixture.image.?, .batch_native_projections = true, .retain_endpoints = false });
    var candidate_live = true;
    defer if (candidate_live) candidate.deinit();
    var candidate_input = fixture.input();
    candidate_input.members = candidate.members;
    candidate_input.fixed_root = candidate.fixed_root;
    candidate_input.range_main_root = candidate.range_main_root;
    const candidate_bytes = try Codec.encode(a, candidate, fixture.trusted, candidate_input, .{});
    defer a.free(candidate_bytes);
    try std.testing.expectEqualSlices(u8, bytes, candidate_bytes);
    candidate.deinit();
    candidate_live = false;

    const expected = proof.summary;
    const expected_sources = try a.dupe(@TypeOf(expected.sources[0]), expected.sources);
    defer a.free(expected_sources);
    proof.deinit();
    proof_live = false;
    fixture.deinit();
    fixture_live = false;
    var received = try Codec.verifyBytes(a, bytes, public.trusted, public.input, .{});
    defer received.deinit();
    try std.testing.expectEqual(@as(u32, 2), received.summary.cohorts);
    try std.testing.expectEqualDeep(expected_sources, received.summary.sources);
    try std.testing.expectEqual(expected.initial_regs, received.summary.initial_regs);
    try std.testing.expectEqual(expected.final_regs, received.summary.final_regs);
    var decoded = try Codec.decode(a, bytes, public.trusted, public.input, .{});
    defer decoded.deinit();
    const admitted = try Scope.Owned.init(a, public.trusted, public.input, .{});
    defer admitted.deinit();
    const drawn = try admitted.epoch.draw(a);
    const proposed = try a.dupe(Ledger.MemberClaims, decoded.claims.members);
    defer a.free(proposed);
    const original0 = proposed[0].native;
    const original1 = proposed[1].native;
    const claim0 = try a.dupe(@TypeOf(original0[0]), original0);
    defer a.free(claim0);
    const claim1 = try a.dupe(@TypeOf(original1[0]), original1);
    defer a.free(claim1);
    const delta = core.fields.qm31.QM31.one();
    var index0: ?usize = null;
    var index1: ?usize = null;
    for (admitted.member[0].layout.slots, 0..) |slot, i| switch (slot.kind) {
        .lookup => |lookup| if (lookup.partition == .registers_state) {
            index0 = i;
            break;
        },
        else => {},
    };
    for (admitted.member[1].layout.slots, 0..) |slot, i| switch (slot.kind) {
        .lookup => |lookup| if (lookup.partition == .registers_state) {
            index1 = i;
            break;
        },
        else => {},
    };
    const first = index0 orelse return error.MissingStateProjection;
    const second = index1 orelse return error.MissingStateProjection;
    const aggregate = claim0[first].sum.add(claim1[second].sum);
    claim0[first].sum = claim0[first].sum.add(delta);
    claim1[second].sum = claim1[second].sum.sub(delta);
    try std.testing.expectEqualDeep(aggregate, claim0[first].sum.add(claim1[second].sum));
    proposed[0].native = claim0;
    proposed[1].native = claim1;
    var hostile = decoded.claims;
    hostile.members = proposed;
    try std.testing.expectError(error.UnclosedEndpointGroupMemberRegisters, Ledger.close(a, admitted, public.input, hostile, &drawn));
    try std.testing.expectError(error.OodsNotMatching, Original.verify(a, public.trusted, public.input, &decoded.stark, hostile, .{}));
    proposed[0].native = original0;
    proposed[1].native = original1;
    const ram_aggregate = proposed[0].endpoint[0].add(proposed[1].endpoint[0]);
    proposed[0].endpoint[0] = proposed[0].endpoint[0].add(delta);
    proposed[1].endpoint[0] = proposed[1].endpoint[0].sub(delta);
    try std.testing.expectEqualDeep(ram_aggregate, proposed[0].endpoint[0].add(proposed[1].endpoint[0]));
    try std.testing.expectError(error.UnclosedEndpointGroupMemberRam, Ledger.close(a, admitted, public.input, hostile, &drawn));
    std.debug.print("B8_GROUP_ORIGINAL members=2 originals=1 shared_range=1 shared_rom=1 shared_lookup=1 q=70 pow=26 bytes={d} core_ns={d} whole_ns={d} verified_once=true global_ram_open=true\n", .{ bytes.len, timing.core_ns, timing.whole_ns });
}
test "group endpoint lease explicit index preserves exact root geometry and owned lifetime" {
    const Retain = @import("../block_v8_endpoint_local_retained_v1.zig");
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 32 << 20);
    defer budget.destroy();
    const a = budget.allocator();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var scheme = try Retain.Scheme.init(a, config);
    var scheme_live = true;
    defer if (scheme_live) scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.always);
    var values: [16]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
    var columns: [23]E.pcs.ColumnEvaluation = undefined;
    for (&columns) |*column| column.* = .{ .log_size = 4, .values = &values };
    var channel = core.proof_suites.Blake3.Channel{};
    try scheme.commitBorrowedStreaming(a, columns[0..1], 4, &channel);
    try scheme.commitBorrowedStreaming(a, &columns, 4, &channel);
    const root = scheme.trees.items[1].root();
    try std.testing.expectError(error.InvalidEndpointRetention, Retain.Owned.acquireAt(a, &scheme, 0, root, 4, 8 << 20));
    try std.testing.expectError(error.InvalidEndpointRetention, Retain.Owned.acquireAt(a, &scheme, 7, root, 4, 8 << 20));
    try std.testing.expectError(error.InvalidEndpointRetention, Retain.Owned.acquire(a, &scheme, root, 4, 8 << 20));
    var wrong = root;
    wrong[0] ^= 1;
    try std.testing.expectError(error.InvalidEndpointRetention, Retain.Owned.acquireAt(a, &scheme, 1, wrong, 4, 8 << 20));
    try std.testing.expectError(error.EndpointRetentionResourceLimit, Retain.Owned.acquireAt(a, &scheme, 1, root, 4, 1));
    const lease = try Retain.Owned.acquireAt(a, &scheme, 1, root, 4, 8 << 20);
    defer lease.deinit();
    scheme.deinit(a);
    scheme_live = false;
    var retained = try lease.retainTree(root, config, 4);
    defer retained.deinit(a);
    try std.testing.expectEqual(root, retained.root());
    try std.testing.expectEqual(@as(usize, 23), retained.coefficients.?.len);
}
