//! Admission and ownership tests, separate from expensive real-proof gates.
const std = @import("std");
const core = @import("stwo_core");
const adapter = @import("pcs_arithmetic_capture.zig");
const deep = @import("air/pcs_deep_circuit.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.circle.CirclePointQM31;
const Capture = struct {
    column_log_sizes: []const []const u32,
    sampled_points: []const []const []const P,
    sampled_values: []const Q,
    queried_values: []const M,
    deep_answers: []const Q,
    queries: struct { raw: []const usize },
    oods_seed: Q,
    deep_randomness: Q,
};
test "PCS arithmetic capture preserves ownership and rejects geometry encoding mutations" {
    const a = std.testing.allocator;
    const seed = Q.fromU32Unchecked(7, 11, 13, 17);
    const current = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    const step = core.poly.circle.canonic.CanonicCoset.new(3).step();
    const previous = current.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var pair = [_]P{ current, previous };
    const columns = [_][]const P{ &pair, &.{current} };
    var layouts = [_]deep.SamplePointLayout{ .current_previous, .current };
    const profile = deep.Profile{ .trees = &.{.{ .column_log_sizes = &.{ 4, 3 } }}, .sample_layouts = &layouts, .lifting_log_size = 4, .log_blowup_factor = 1, .query_count = 2 };
    var samples = [_]Q{ Q.one(), seed, Q.zero() };
    var values = [_]M{ M.one(), M.one(), M.zero(), M.zero() };
    var answers = [_]Q{ seed, seed };
    var queries = [_]usize{ 3, 3 };
    var capture = Capture{ .column_log_sizes = &.{&.{ 4, 3 }}, .sampled_points = &.{&columns}, .sampled_values = &samples, .queried_values = &values, .deep_answers = &answers, .queries = .{ .raw = &queries }, .oods_seed = seed, .deep_randomness = seed };
    try std.testing.checkAllAllocationFailures(a, allocate, .{ profile, &capture });
    var owned = try adapter.Owned.init(a, profile, &capture);
    defer owned.deinit();
    samples[0] = Q.zero();
    values[0] = M.zero();
    answers[0] = Q.zero();
    queries[0] = 4;
    try std.testing.expect(owned.inputs.sampled_values[0].eql(Q.one()));
    try std.testing.expect(owned.inputs.queried_values[0].eql(M.one()));
    try std.testing.expect(owned.inputs.answers[0].eql(seed));
    try std.testing.expectEqual(@as(u32, 3), owned.inputs.raw_queries[0].v);
    try std.testing.expectEqual(@as(u32, 3), owned.inputs.raw_queries[1].v);
    pair = .{ previous, current };
    try std.testing.expectError(error.InvalidPcsArithmeticCapture, adapter.Owned.init(a, profile, &capture));
    layouts[0] = .previous_current;
    try allocate(a, profile, &capture);
    queries[0] = 16;
    try std.testing.expectError(error.InvalidPcsArithmeticCapture, adapter.Owned.init(a, profile, &capture));
    queries[0] = 3;
    values[0].v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidPcsArithmeticCapture, adapter.Owned.init(a, profile, &capture));
    values[0] = M.zero();
    capture.deep_randomness.c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidPcsArithmeticCapture, adapter.Owned.init(a, profile, &capture));
    capture.deep_randomness = seed;
    capture.column_log_sizes = &.{&.{ 3, 4 }};
    try std.testing.expectError(error.InvalidPcsArithmeticCapture, adapter.Owned.init(a, profile, &capture));
}
fn allocate(a: std.mem.Allocator, profile: deep.Profile, capture: *const Capture) !void {
    var owned = try adapter.Owned.init(a, profile, capture);
    defer owned.deinit();
}
