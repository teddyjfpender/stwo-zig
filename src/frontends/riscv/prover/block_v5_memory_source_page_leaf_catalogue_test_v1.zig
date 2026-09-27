//! No positive captures or manufactured keys. These pure coordinator checks
//! accompany actual durable admission/receiver retention in the body root.
const std = @import("std");
const Catalogue = @import("block_v5_memory_source_page_leaf_catalogue_v1.zig");
test "PAGE durable catalogue: bounded leases and backpressure conserve occupancy" {
    var occupancy = Catalogue.Occupancy{};
    var tickets: [4]u64 = undefined;
    for (&tickets) |*ticket| ticket.* = try occupancy.begin();
    try std.testing.expectEqual(@as(u32, 4), occupancy.count);
    try std.testing.expectError(error.PageLeafCatalogueBackpressure, occupancy.begin());
    try std.testing.expectEqual(@as(u64, 4), occupancy.serial);
    for (tickets, 0..) |ticket, index| try std.testing.expectEqual(@as(u64, @intCast(index + 1)), ticket);
    for (0..4) |_| occupancy.end();
    try std.testing.expectEqual(@as(u32, 0), occupancy.count);
    try std.testing.expectEqual(@as(u64, 5), try occupancy.begin());
    occupancy.end();
}
test "PAGE durable catalogue: ticket overflow is failure atomic" {
    var occupancy = Catalogue.Occupancy{ .serial = std.math.maxInt(u64) };
    try std.testing.expectError(error.Overflow, occupancy.begin());
    try std.testing.expectEqual(@as(u32, 0), occupancy.count);
    try std.testing.expectEqual(std.math.maxInt(u64), occupancy.serial);
}
test "PAGE durable catalogue: independent resource policy rejects inconsistent page limits" {
    var limits = Catalogue.Limits{};
    try limits.validate();
    limits.max_scope_bytes = 0;
    try std.testing.expectError(error.InvalidPageLeafCatalogueLimits, limits.validate());
    limits = .{};
    limits.recursive.max_capture_bytes = 0;
    try std.testing.expectError(error.InvalidPageLeafCatalogueLimits, limits.validate());
    limits = .{};
    limits.recursive.page.max_receiver_heap_bytes -= 1;
    try std.testing.expectError(error.InvalidPageLeafCatalogueLimits, limits.validate());
}
test "PAGE durable catalogue: lower-only child selection consumes no descriptor slots" {
    // A lower closed node needs its own genuine parent proof, not descendant
    // descriptor retention. Group does not touch this deliberately undefined
    // original owner when every ref has typed node absence of a leaf.
    var owner: Catalogue.Catalogue = undefined;
    const Ref = @import("../recursion/block_v5_memory_source_page_forest_plan_v1.zig").Ref;
    var group = try Catalogue.Group.acquire(&owner, &[_]Ref{ .{ .node = 0 }, .{ .node = 1 }, .{ .node = 2 }, .{ .node = 3 } });
    defer group.deinit();
    try std.testing.expectEqual(@as(usize, 0), group.count);
    try std.testing.expectError(error.PageLeafCatalogueBackpressure, Catalogue.Group.acquire(&owner, &[_]Ref{ .{ .node = 0 }, .{ .node = 1 }, .{ .node = 2 }, .{ .node = 3 }, .{ .node = 4 } }));
}

const Owned = @import("block_v5_memory_source_page_forest_policy_owner_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const PolicyFile = @import("block_v5_memory_source_page_policy_file_v1.zig");
fn invalidCatalogueAllocations(a: std.mem.Allocator, dir: std.fs.Dir, pin: PolicyFile.Pin) !void {
    const owner = Catalogue.Catalogue.create(a, dir, pin, undefined, .{}) catch |failure| {
        if (failure == error.OutOfMemory) return failure;
        try std.testing.expectEqual(error.UnknownField, failure);
        return;
    };
    owner.deinit();
    return error.InvalidPolicyUnexpectedlyAdmitted;
}
test "PAGE durable catalogue: control parent directory and invalid metadata failures release every allocation" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const proposal = "{\"unknown\":0}";
    try Files.publish(temp.dir, PolicyFile.FILE, proposal);
    const pin = PolicyFile.Pin{ .byte_len = proposal.len, .sha256 = Files.hash(proposal) };
    // Original Globals are intentionally unavailable: strict bounded metadata
    // rejection must happen before source reconstruction or any proof access.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, invalidCatalogueAllocations, .{ temp.dir, pin });
}
test "PAGE durable catalogue: exact original leaf node file census and typed empty roster" {
    const FilePin = Owned.FilePin;
    const leaves = [_]FilePin{ .{ .byte_len = 1, .sha256 = @splat(1) }, .{ .byte_len = 2, .sha256 = @splat(2) } };
    const nodes = [_]FilePin{.{ .byte_len = 3, .sha256 = @splat(3) }};
    try Owned.requireExisting(.{ .reconstruct = .{ .leaves = &leaves, .nodes = &nodes } }, 2, 1);
    try std.testing.expectError(error.IncompletePageForestPolicyFiles, Owned.requireExisting(.{ .reconstruct = .{ .leaves = leaves[0..1], .nodes = &nodes } }, 2, 1));
    try std.testing.expectError(error.IncompletePageForestPolicyFiles, Owned.requireExisting(.{ .reconstruct = .{ .leaves = &leaves, .nodes = &.{} } }, 2, 1));
    try Owned.requireExisting(.{ .reconstruct = .{ .leaves = &.{}, .nodes = &.{} } }, 0, 0);
    try std.testing.expectError(error.IncompletePageForestPolicyFiles, Owned.requireExisting(.{ .reconstruct = .{ .leaves = &leaves, .nodes = &nodes } }, 0, 0));
}
test "PAGE durable catalogue: independent limits reject before undefined source or file capability" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    var limits = Owned.Limits{};
    limits.max_live_bytes = 0;
    try std.testing.expectError(error.InvalidPageForestPolicyLimits, Owned.ForBackend(Cpu).build(std.testing.failing_allocator, undefined, undefined, undefined, undefined, limits, .publish));
    limits = .{};
    limits.max_metadata_bytes = 0;
    try std.testing.expectError(error.InvalidPageForestPolicyLimits, Owned.ForBackend(Cpu).build(std.testing.failing_allocator, undefined, undefined, undefined, undefined, limits, .{ .reconstruct = .{ .leaves = &.{}, .nodes = &.{} } }));
}
test "PAGE durable catalogue: durable names and closed summary grammar preserve exact old framing" {
    var leaf: [96]u8 = undefined;
    var node: [96]u8 = undefined;
    try std.testing.expectEqualStrings("source-page-recursive-leaf-17.b5pgp", try Owned.leafFilename(&leaf, 17));
    try std.testing.expectEqualStrings("source-page-recursive-node-5.b5pgf", try Owned.nodeFilename(&node, 5));
    const Original = @import("../recursion/block_v5_memory_source_page_forest_bus_v1.zig");
    const Compact = @import("../recursion/block_v5_memory_source_page_forest_summary_bus_v1.zig");
    const Protocol = @import("../recursion/block_v5_memory_source_page_forest_protocol_v1.zig");
    const CompactProtocol = @import("../recursion/block_v5_memory_source_page_forest_summary_protocol_v1.zig");
    try std.testing.expectEqual(Protocol.VERSION, CompactProtocol.VERSION);
    try std.testing.expect(std.meta.eql(Protocol.sourceAuthority(), CompactProtocol.sourceAuthority()));
    try std.testing.expect(std.meta.eql(try Original.scheduleDigest(&.{}), try Compact.scheduleDigest(&.{})));
    // There is no public supplier to read at a closed boundary. This rejects
    // without touching an undefined statement owner or original leaf policy.
    try std.testing.expectError(error.ClosedPageForestNodeHasNoPublicTerms, (Compact.Values{ .public = undefined }).at(undefined));
}
