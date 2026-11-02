const std = @import("std");
const G = @import("../joined_codegen.zig");
const Fixtures = @import("../projection_fixture_support.zig");
const a = std.testing.allocator;
test "all source roles record native MAIN plus local binding plus global obligations" {
    for (Fixtures.descriptors()) |descriptor| {
        var artifact = try G.record(a, descriptor);
        defer artifact.deinit();
        try artifact.validate();
        const degrees = try artifact.program.degrees(a);
        defer a.free(degrees);
        for (artifact.program.roots) |root| try std.testing.expect(degrees[root] <= 3);
    }
}

test "joined executable binds source layout and parameter map without binding live values" {
    var artifact = try G.record(a, .{ .origin = .{ .core = .cpu }, .cpu_u8_pairs = true, .cpu_compact_decode = true });
    defer artifact.deinit();
    const identity = try artifact.identity();
    for (artifact.program.parameters) |*v| v.* = @TypeOf(v.*).zero();
    try std.testing.expectEqualSlices(u8, &identity, &(try artifact.identity()));
    const first_slot = artifact.parameter_slots[0];
    artifact.parameter_slots[0] = (first_slot + 1) % artifact.parameter_count;
    try std.testing.expect(!std.mem.eql(u8, &identity, &(try artifact.identity())));
    artifact.parameter_slots[0] = first_slot;
    artifact.descriptor.cpu_compact_decode = false;
    try std.testing.expectError(error.InvalidJoinedArtifact, artifact.validate());
}

test "INIT and TEARDOWN retain global RAM constraints without synthetic local GKR" {
    for ([_]G.Source.RoleId{ .initial, .terminal }) |role| {
        var artifact = try G.record(a, .{ .origin = .{ .core = role } });
        defer artifact.deinit();
        try artifact.validate();
        try std.testing.expectEqual(@as(usize, 16), artifact.interaction_width);
        try std.testing.expectEqual(@as(usize, 23), artifact.program.roots.len);
        for (artifact.program.inputs) |input| if (input.tree == 2) {
            try std.testing.expect(input.column < 16);
            try std.testing.expect(input.offset != 2);
        };
    }
}
