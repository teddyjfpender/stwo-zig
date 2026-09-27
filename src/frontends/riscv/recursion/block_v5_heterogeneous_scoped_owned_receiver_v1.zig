//! Genuine fresh original leaf/parent verification with local immutable owner
//! policy. A cache/owner/file hash never substitutes its verifier capture.
const std = @import("std");
const Owner = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Source = @import("block_v5_heterogeneous_scoped_source_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const Fresh = @import("block_v5_heterogeneous_scoped_receiver_v1.zig").Fresh;
pub fn verify(a: std.mem.Allocator, bytes: []const u8, owner: *const Owner.Owner, index: u32) !Fresh {
    var lease = try owner.borrow();
    defer lease.deinit();
    const authority = try owner.node(index);
    var proof = try Parent.codec.decode(a, bytes, &authority);
    var equation = try Parent.verify(&proof, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, authority.expected_id);
    const source = try authority.source(a);
    return .{ .source = source, .equation = equation };
}
pub fn verifyLeaf(a: std.mem.Allocator, bytes: []const u8, owner: *const Owner.Owner, ordinal: u32) !Fresh {
    var lease = try owner.borrow();
    defer lease.deinit();
    const expected = try owner.source(.{ .leaf = ordinal });
    if (!owner.ready or ordinal >= owner.full.expected.len) return error.ScopedOwnerLifetime;
    // Exact physical policy is already independently owned/admitted. Call the
    // SAME original typed leaf verifier; avoid a global Coverage re-scan here.
    var leaf = switch (owner.full.expected[ordinal]) {
        .native_fused_v2 => return error.MissingGenuineNativeV3FusedAdapter,
        inline else => |policy| try policy.verify(a, bytes, owner.coverage.meta.physical[ordinal], owner.pins.recipe, owner.pins.source),
    };
    errdefer leaf.deinit();
    if (!std.meta.eql(leaf.child.seal, owner.full.children[ordinal].seal)) return error.UntrustedScopedPublicSource;
    const source = try Source.fromLeaf(a, &leaf.child, ordinal, owner.pins.routing);
    errdefer {
        var cleanup = source;
        cleanup.deinit();
    }
    if (!std.meta.eql(source.seal, expected.seal)) return error.UntrustedScopedPublicSource;
    leaf.child.deinit();
    return .{ .source = source, .equation = leaf.equation };
}
