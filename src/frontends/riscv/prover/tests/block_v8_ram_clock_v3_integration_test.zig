const std = @import("std");
const core = @import("stwo_core");
const Tracker = @import("../../runner/state_chain.zig").StateChainTracker;
const K = @import("../block_v8_ram_clock_v3_kernel.zig");
const Gap = @import("../block_v8_ram_clock_v3_component.zig");
const Infrastructure = @import("../block_v8_ram_clock_v3_infrastructure.zig").Component;
const Layout = @import("../block_v8_native_endpoint_layout_v3.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
test "direct RAM V3 collector eliminates RAM ghosts and preserves register ghosts" {
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.enableDirectRamClockV3(8000000);
    try tracker.recordMemTransition(0x100, 4000003, 0, 7);
    try tracker.recordMemTransition(0x100, 4000007, 7, 9);
    try tracker.recordRegTransition(1, 4000001, 0, 8);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_mem.items.len);
    try std.testing.expect(tracker.clock_updates_reg.items.len > 0);
    try std.testing.expectEqual(@as(u32, 0), tracker.accesses.items[0].clk_prev);
    try std.testing.expectEqual(@as(u32, 4000003), tracker.accesses.items[1].clk_prev);
    try std.testing.expectError(error.InvalidDirectRamClockTransition, tracker.requireDirectRamClock(0x100, 4000006, 4000003));
    try std.testing.expectError(error.InvalidDirectRamClockTransition, tracker.requireDirectRamClock(0x100, 8000003, 4000003));
    try std.testing.expectError(error.InvalidDirectRamClockTransition, tracker.requireDirectRamClock(0x100, 4000003, 4000007));
}
test "direct RAM V3 infrastructure rejects a canonical RAM filler even if its clock equations pass" {
    const component = Infrastructure{ .log_size = 4, .active_column = 1, .main_offset = 0 };
    var main: [10]Q = @splat(Q.zero());
    main[0] = Q.one();
    main[1] = Q.one();
    var checks: [4]Q = undefined;
    const out = try component.evaluate(Q, &main, Q.one(), &checks);
    for (out[0..3]) |check| try std.testing.expect(check.isZero());
    try std.testing.expect(out[3].eql(Q.one()));
    main[1] = Q.zero();
    _ = try component.evaluate(Q, &main, Q.one(), &checks);
    try std.testing.expect(checks[3].isZero());
}
test "direct RAM V3 gap range plane equals exactly three signed range16 requests" {
    const relation = @import("../block_v7_memory_relations_v1.zig").Relation(Q, 1){ .z = q(123), .powers = .{q(7)} };
    const aux = [3]Q{ q(2), q(3), q(2044) };
    const term = Gap.term(Q, relation, Q.one(), aux);
    var expected = Q.zero();
    for (aux) |value| expected = expected.sub(try Q.one().div(relation.combineSecure(.{value})));
    try std.testing.expect((try term.fraction()).eql(expected));
    try std.testing.expect((try Gap.term(Q, relation, Q.zero(), @splat(Q.zero())).fraction()).isZero());
    const row = [9]Q{ q(2), q(3), q(1), Q.zero(), Q.zero(), Q.zero(), q(3), Q.zero(), q(2047) };
    const equations = Gap.equations(Q, relation, Q.one(), row, @splat(Q.zero()), @splat(Q.zero()), Q.zero());
    for (equations[0..K.CONSTRAINT_COUNT]) |value| try std.testing.expect(value.isZero());
    _ = Layout.VERSION;
}
test "direct RAM V3 physical roster independently reconstructs bounded conditional lookup slots" {
    const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = .load_store, .log_size = 1, .n_rows = 1, .n_columns = 50 };
    shape.total_steps = 1;
    shape.public_data.clock = 1;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    var layout = try Layout.init(std.testing.allocator, &shape, 0);
    defer layout.deinit();
    try Layout.requireCoverage(std.testing.allocator, &shape, layout.slots);
    var observed: usize = 0;
    for (layout.slots) |slot| {
        try std.testing.expect(slot.degree <= 4);
        if (slot.kind == .lookup) {
            try std.testing.expect(slot.kind.lookup.direct_ram_clock_v3);
            for (slot.kind.lookup.entries[0..slot.kind.lookup.entry_count]) |index| if (index == 10 or index == 13) {
                observed += 1;
            };
        }
    }
    try std.testing.expectEqual(@as(usize, 2), observed);
    layout.slots[0].degree += 1;
    try std.testing.expectError(error.InvalidDirectRamClockCoverage, Layout.requireCoverage(std.testing.allocator, &shape, layout.slots));
}
test "direct RAM V3 long raw predecessor has explicit host authority while canonical R20 remains strict" {
    const a = std.testing.allocator;
    const code = [_]u32{ 0x001002b7, 0x10028293, 0x00800313, 0x0062a023, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .direct_ram_max_clock = 1 << 26 });
    defer session.deinit();
    var segment = try session.startSegment(code.len - 1);
    defer segment.deinit();
    var row = segment.execution_trace.rows.items[3];
    row.clk = 1000000;
    const clock = @import("../../access_clock.zig");
    row.rs1_prev_clk = Tracker.effectivePreviousClock(0, clock.encode(row.clk, .first));
    row.rs2_prev_clk = Tracker.effectivePreviousClock(0, clock.encode(row.clk, .second));
    row.mem_prev_clk = 0;
    try @import("../../runner/direct_ram_clock_v3.zig").validateTraceRow(row);
    if (@import("../../air/lang/typed_load_store_authority.zig").validateTraceRow(row)) |_| return error.CanonicalAuthorityAcceptedRawLongRamGap else |_| {}
    row.mem_prev_clk = clock.encode(row.clk, .third);
    try std.testing.expectError(error.InvalidDirectRamClockRow, @import("../../runner/direct_ram_clock_v3.zig").validateTraceRow(row));
    try std.testing.expect(@sizeOf(@import("../../runner/load_store_retirement.zig").Plan) <= @import("../../runner/load_store_retirement.zig").MAX_PLAN_BYTES);
}
test "wide native profile4 admits exact24-bit shards and preserves legacy16-bit admission" {
    const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
    const Profile = @import("../block_v8_native_endpoint_profile_v1.zig");
    const Wire = @import("../guest_precompile/proof_artifact_wire.zig");
    const Writer = @import("../bounded_artifact_writer_v1.zig").Writer;
    const a = std.testing.allocator;
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.native_shard_version = 1;
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = .load_store, .log_size = 17, .n_rows = 65537, .n_columns = 50 };
    shape.total_steps = 65537;
    shape.public_data.clock = 65537;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    try shape.validateBlake3ExecutionWithExternal(0);
    try Profile.requireShape(&shape, .direct_ram_clock_v3_wide);
    try std.testing.expectError(error.NativeClockGeometryProfileMismatch, Profile.requireShape(&shape, .direct_ram_clock_v3));
    try std.testing.expectError(error.UnsupportedEndpointNativeGeometry, @import("../block_v8_native_endpoint_layout_v1.zig").Layout.init(a, &shape, 0));
    var out = Writer.init(a, 1 << 20);
    defer out.deinit();
    try Wire.encodeBlake3Statement(&out, &shape, .{});
    var decoded = try Wire.decodeBlake3Statement(a, out.bytes.items, .{});
    defer decoded.deinit(a);
    try std.testing.expectEqual(@as(u32, 1), decoded.value.native_shard_version);
    try decoded.value.validateBlake3ExecutionWithExternal(0);
    shape.n_components = 2;
    shape.component_descs[0].log_size = 16;
    shape.component_descs[0].n_rows = 65536;
    shape.component_descs[1] = .{ .family = .load_store, .log_size = 1, .n_rows = 1, .n_columns = 50 };
    try std.testing.expectError(error.InvalidStatement, shape.validateBlake3ExecutionWithExternal(0));
    shape.native_shard_version = 0;
    try shape.validateBlake3ExecutionWithExternal(0);
    try std.testing.expectError(error.NativeClockGeometryProfileMismatch, Profile.requireShape(&shape, .direct_ram_clock_v3_wide));
}
