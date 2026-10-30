const Owner = @import("integrations/riscv_cuda/hybrid_framework_interaction_v1.zig");
const API = @import("frontends/riscv/recursion/blake3_parent_interaction_executor_v1.zig");
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Q = @import("stwo_core").fields.qm31.QM31;
test "CUDA framework interaction lifecycle semantic" {
    _ = &Owner.Owner.open;
    _ = &Owner.Owner.deinit;
    _ = &force;
}
fn force(o: *Owner.Owner, a: std.mem.Allocator, p: *const API.Program, c: [3]usize, s: [2][]const []const M, v: API.Parameters, d: []const []M, claims: []Q) !void {
    const e = o.executor();
    try e.generate(e.context, a, p, c, s, v, d, claims);
}

test "interaction invocation rejects stale geometry and accepts only output claim shape" {
    const core = @import("stwo_core");
    const Tables = @import("frontends/riscv/air/lookups/tables/framework_export.zig");
    const Table = @import("frontends/riscv/air/lookups/tables/component.zig").LookupTableComponent;
    const Relations = @import("frontends/riscv/air/relation_challenges.zig").Relations;
    const Code = @import("backends/cuda/framework_interaction_codegen_v1.zig");
    const a = std.testing.allocator;
    const relations = Relations.dummy();
    const component = try Table.initProver(.range_check_8_8, 0, &.{ 1, 2 }, 0, 0, &relations, Q.zero());
    const counts = [3]usize{ 3, 1, 4 };
    var program = try Tables.exportProgram(a, &component, &counts);
    defer program.deinit();
    var parameters = try Tables.exportParameters(a, &component);
    defer parameters.deinit();
    // Invocation sizes are independent of the offline program's placement.
    parameters.values.trace_log_size = 1;
    const source = [_]M{ M.zero(), M.one() };
    const fixed = [_][]const M{ &source, &source, &source };
    const main = [_][]const M{&source};
    const sources = [2][]const []const M{ &fixed, &main };
    var destination: [4][2]M = undefined;
    var columns: [4][]M = undefined;
    for (&columns, &destination) |*c, *d| c.* = d;
    var claims: [1]Q = undefined;
    try API.validate(&program, counts, sources, parameters.values, &columns, &claims);
    try std.testing.expectError(error.InvalidFrameworkInteractionGeometry, API.validate(&program, counts, sources, parameters.values, columns[0..3], &claims));
    try std.testing.expectError(error.InvalidFrameworkInteractionGeometry, API.validate(&program, counts, sources, parameters.values, &columns, &.{}));
    try std.testing.expectError(error.InvalidFrameworkInteractionGeometry, API.validate(&program, counts, .{ fixed[0..2], &main }, parameters.values, &columns, &claims));
    var wrong = parameters.values;
    wrong.trace_log_size = 2;
    try std.testing.expectError(error.InvalidFrameworkInteractionGeometry, API.validate(&program, counts, sources, wrong, &columns, &claims));
    wrong = parameters.values;
    wrong.relation_values = &.{};
    if (API.validate(&program, counts, sources, wrong, &columns, &claims)) |_| return error.AcceptedWrongChallengeGeometry else |_| {}
    const id = try Code.identity(a, .{ .program = &program, .tree_column_counts = &counts });
    var ids: [3][32]u8 = undefined;
    inline for (std.meta.tags(Code.Scan), 0..) |kind, i| {
        ids[i] = try Code.scanIdentity(a, kind);
        try std.testing.expect(!std.mem.eql(u8, &id, &ids[i]));
    }
    for (ids, 0..) |x, i| for (ids[0..i]) |y| try std.testing.expect(!std.mem.eql(u8, &x, &y));
    // Resealing a different program cannot preserve executable identity.
    program.lookup_nodes[program.entries[0].numerator].op = .constant;
    program.lookup_nodes[program.entries[0].numerator].value = 1;
    program.identity = program.identityDigest();
    const altered = try Code.identity(a, .{ .program = &program, .tree_column_counts = &counts });
    try std.testing.expect(!std.mem.eql(u8, &id, &altered));
    _ = core;
}
