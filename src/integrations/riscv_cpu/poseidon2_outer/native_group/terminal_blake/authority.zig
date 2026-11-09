//! Bounded first wrapper: build the real P2 R6 source authority, then independently
//! commit its exact FIXED columns under Blake. Both cold costs are retained.
const std = @import("std");
const Context = @import("../../context.zig").Context;
pub const Key = ForArithmetic(.r6).Key;
pub const R7 = ForArithmetic(.r7);
pub fn ForArithmetic(comptime kind: @import("arithmetic.zig").Kind) type {
    const Arith = @import("arithmetic.zig").For(kind);
    const Profile = @import("profile.zig").ForArithmetic(kind);
    return struct {
        pub const Key = struct {
            inner: Arith.SourceKey,
            identity: [32]u8,
            fixed_root: Profile.H.Hash,
            fixed_tree: ?Profile.E.Scheme.CommittedTree,
            p2_source_setup_ns: u64,
            blake_fixed_setup_ns: u64,
            pub fn init(a: std.mem.Allocator, source: *const Context) !@This() {
                var timer = try std.time.Timer.start();
                var inner = try Arith.SourceKey.init(a, source, Profile.fri_policy);
                errdefer inner.deinit();
                const p2_ns = timer.lap();
                // The real P2 root/identity stay intact; its tree is no longer needed by
                // this terminal prover. Raw FIXED and usage remain for witness creation.
                if (Arith.baseMut(&inner).fixed_tree) |*tree| tree.deinit(a);
                Arith.baseMut(&inner).fixed_tree = null;
                var scheme = try Profile.E.init(a, Profile.fri_policy.config());
                defer scheme.deinit(a);
                scheme.reuse_bounded_merkle_tail = true;
                scheme.setCompactPolynomialStorage(1);
                var channel = Profile.Channel.init();
                try scheme.commitBorrowedStreaming(a, Arith.baseMut(&inner).fixed.values, 64, &channel);
                const root = scheme.trees.items[0].root();
                try scheme.trees.items[0].share(a);
                const tree = scheme.trees.items[0].retainShared();
                var h = std.crypto.hash.sha2.Sha256.init(.{});
                h.update(Profile.DOMAIN);
                h.update(&Profile.MC.identity());
                h.update(&Arith.baseMut(&inner).identity);
                h.update(&root);
                return .{ .inner = inner, .identity = h.finalResult(), .fixed_root = root, .fixed_tree = tree, .p2_source_setup_ns = p2_ns, .blake_fixed_setup_ns = timer.lap() };
            }
            pub fn retireProverData(self: *@This()) void {
                if (self.fixed_tree) |*tree| tree.deinit(Arith.baseMut(&self.inner).allocator);
                self.fixed_tree = null;
                @import("../../native_omul/verifier_key.zig").retireProverData(Arith.coreMut(&self.inner));
            }
            pub fn deinit(self: *@This()) void {
                if (self.fixed_tree) |*tree| tree.deinit(Arith.baseMut(&self.inner).allocator);
                self.inner.deinit();
                self.* = undefined;
            }
        };
    };
}
