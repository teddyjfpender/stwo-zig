//! Nonproving recipe/transport rejection fixtures. No Fresh/Verified is forged.
const std = @import("std");
const Public = @import("../recursion/block_v5_requester_public_compensation_v1.zig");
const Scoped = @import("../recursion/block_v5_heterogeneous_scoped_plan_v1.zig");
const Bus = @import("../recursion/block_v5_requester_public_bus_v1.zig");
test "requester public: exact sorted scope lookup separates window coordinate and kind" {
    const requirements = [_]Scoped.Requirement{
        .{ .key = .{ .kind = .transition, .scope = 0, .coordinate = 0 }, .terms = &.{}, .disposition = .retain },
        .{ .key = .{ .kind = .public_auth, .scope = 0, .coordinate = 31 }, .terms = &.{}, .disposition = .retain },
        .{ .key = .{ .kind = .public_auth, .scope = 0, .coordinate = 32 }, .terms = &.{}, .disposition = .retain },
        .{ .key = .{ .kind = .public_auth, .scope = 1, .coordinate = 0 }, .terms = &.{}, .disposition = .retain },
    };
    for (requirements, 0..) |item, index| try std.testing.expectEqual(@as(u32, @intCast(index)), try Public.findRequirement(&requirements, item.key));
    try std.testing.expectError(error.MissingRequesterPublicScope, Public.findRequirement(&requirements, .{ .kind = .public_auth, .scope = 0, .coordinate = 0 }));
    try std.testing.expectError(error.MissingRequesterPublicScope, Public.findRequirement(&requirements, .{ .kind = .transition, .scope = 1, .coordinate = 0 }));
    try std.testing.expectError(error.MissingRequesterPublicScope, Public.findRequirement(&.{}, .{ .kind = .transition, .scope = 0, .coordinate = 0 }));
}
test "requester public: schedule has distinct authority and rejects unrelated child or seal selectors" {
    const wire = Bus.Wire{ .circuit = 3, .wire = 4, .uses = 2, .source = .{ .original = .{ .child = 0, .kind = .frame_cell, .coordinate = 5 } } };
    const actual = try Bus.scheduleDigest(&.{wire});
    const old = try @import("../recursion/block_v5_global_public_export_bus_v1.zig").scheduleDigest(&.{wire});
    try std.testing.expect(!std.meta.eql(actual, old));
    var changed = wire;
    changed.source.original.child = 2;
    try std.testing.expectError(error.InvalidRequesterPublicSchedule, Bus.scheduleDigest(&.{changed}));
    changed = wire;
    changed.source.original = .{ .child = 1, .kind = .frame_cell, .coordinate = 8 };
    try std.testing.expectError(error.InvalidRequesterPublicSchedule, Bus.scheduleDigest(&.{changed}));
    changed = wire;
    changed.source.original.kind = .native_span;
    try std.testing.expectError(error.InvalidRequesterPublicSchedule, Bus.scheduleDigest(&.{changed}));
    changed = wire;
    changed.negative = true;
    try std.testing.expect(!std.meta.eql(actual, try Bus.scheduleDigest(&.{changed})));
    try std.testing.expectError(error.InvalidGlobalPublicSchedule, Bus.scheduleDigest(&.{ wire, wire }));
}
test "requester public: resource rejection precedes unadmitted policy and source access" {
    const Receiver = @import("../recursion/block_v5_requester_public_receiver_v1.zig");
    var policy: Receiver.Policy = undefined;
    policy.max_proof_bytes = 0;
    try std.testing.expectError(error.RequesterPublicResourceLimit, Receiver.verify(std.testing.allocator, "proposal", policy));
    policy.max_proof_bytes = 1;
    try std.testing.expectError(error.RequesterPublicResourceLimit, Receiver.verify(std.testing.allocator, "proposal", policy));
    try std.testing.expectError(error.RequesterPublicResourceLimit, Receiver.verify(std.testing.allocator, "", policy));
    try std.testing.expectError(error.RequesterPublicResourceLimit, @import("../recursion/air/block_v5_requester_public_composition_v1.zig").prepare(std.testing.allocator, undefined, 0));
    try std.testing.expectError(error.RequesterPublicResourceLimit, @import("../recursion/block_v5_requester_public_preparation_v1.zig").prepare(std.testing.allocator, undefined, undefined, 0, .{}));
}
test "requester public: all-family recipe cannot supply requester public authority" {
    var catalog: @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig").Owner = undefined;
    catalog.scoped.recipe = .complete;
    try std.testing.expectError(error.UntrustedRequesterPublicRecipe, Public.init(std.testing.allocator, &catalog, undefined, undefined, .{}));
    try std.testing.expect(!Public.Owner.complete_block_authority);
    try std.testing.expect(!@import("../recursion/block_v5_requester_public_receiver_v1.zig").Fresh.complete_block_authority);
    try std.testing.expect(!@import("../recursion/block_v5_requester_public_source_v1.zig").Source.complete_block_authority);
}
