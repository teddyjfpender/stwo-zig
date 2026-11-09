//! Bounded first wrapper: build the real P2 R6 source authority, then independently
//! commit its exact FIXED columns under Blake. Both cold costs are retained.
const std = @import("std");
const Suite = @import("profile.zig");
const R6 = @import("../../native_omul/authority.zig");
const Context = @import("../../context.zig").Context;
pub const Key = struct {
    inner: R6.Key,
    identity: [32]u8,
    fixed_root: Suite.H.Hash,
    fixed_tree: ?Suite.E.Scheme.CommittedTree,
    p2_source_setup_ns: u64,
    blake_fixed_setup_ns: u64,
    pub fn init(a: std.mem.Allocator, source: *const Context) !Key {
        var timer = try std.time.Timer.start();
        var inner = try R6.Key.init(a, source, Suite.fri_policy);
        errdefer inner.deinit();
        const p2_ns = timer.lap();
        // The real P2 root/identity stay intact; its tree is no longer needed by
        // this terminal prover. Raw FIXED and usage remain for witness creation.
        if (inner.base.fixed_tree) |*tree| tree.deinit(a);
        inner.base.fixed_tree = null;
        var scheme = try Suite.E.init(a, Suite.fri_policy.config());
        defer scheme.deinit(a);
        scheme.reuse_bounded_merkle_tail = true;
        scheme.setCompactPolynomialStorage(1);
        var channel = Suite.Channel.init();
        try scheme.commitBorrowedStreaming(a, inner.base.fixed.values, 64, &channel);
        const root = scheme.trees.items[0].root();
        try scheme.trees.items[0].share(a);
        const tree = scheme.trees.items[0].retainShared();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(Suite.DOMAIN);
        h.update(&Suite.MC.identity());
        h.update(&inner.base.identity);
        h.update(&root);
        return .{ .inner = inner, .identity = h.finalResult(), .fixed_root = root, .fixed_tree = tree, .p2_source_setup_ns = p2_ns, .blake_fixed_setup_ns = timer.lap() };
    }
    pub fn retireProverData(self: *Key) void {
        if (self.fixed_tree) |*tree| tree.deinit(self.inner.base.allocator);
        self.fixed_tree = null;
        @import("../../native_omul/verifier_key.zig").retireProverData(&self.inner);
    }
    pub fn deinit(self: *Key) void {
        if (self.fixed_tree) |*tree| tree.deinit(self.inner.base.allocator);
        self.inner.deinit();
        self.* = undefined;
    }
};
