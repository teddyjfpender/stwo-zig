//! P2 FIXED authority rebuilt from receiver-owned source columns.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("worker_protocol.zig");
const W = P.W;
const R = @import("../roster.zig");
const Legacy = @import("../gkr_local/cpu_worker.zig");
pub const Key = struct {
    allocator: std.mem.Allocator,
    profile: P.Profile,
    source_root: [32]u8,
    identity: [32]u8,
    root: W.H.Hash,
    tree: W.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, profile: P.Profile) !Key {
        const columns = try setup.fixedColumns(a);
        defer a.free(columns);
        var scheme = try W.Prover.init(a, profile.config());
        defer scheme.deinit(a);
        scheme.setStorePolynomialsCoefficients();
        scheme.setCompactPolynomialStorage(1);
        var channel = W.Channel.init();
        try scheme.commit(a, columns, &channel);
        var tree = scheme.trees.pop().?;
        errdefer tree.deinit(a);
        try tree.share(a);
        const root = tree.root();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-p2v2/source-fixed-class/v1\x00");
        h.update(&profile.identity());
        h.update(&setup.materials.program.identity);
        h.update(&setup.key.root);
        h.update(&root);
        const geometry = try std.json.Stringify.valueAlloc(a, .{ .geometry = setup.materials.geometry, .bridges = setup.bridges }, .{});
        defer a.free(geometry);
        h.update(geometry);
        // Complete ordered source geometry, including the reduced local bindings.
        var plan = try @import("../gkr_local/cpu_components.zig").Plan.init(a, setup);
        defer plan.deinit();
        for (0..3) |index| {
            const logs = if (index < 2) try setup.logs(a, index) else try plan.interLogs(a);
            defer a.free(logs);
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, @intCast(logs.len), .little);
            h.update(&bytes);
            for (logs) |log| {
                std.mem.writeInt(u32, &bytes, log, .little);
                h.update(&bytes);
            }
        }
        return .{ .allocator = a, .profile = profile, .source_root = setup.key.root, .identity = h.finalResult(), .root = root, .tree = tree };
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn require(self: *const Key, setup: *const R.CpuSetup, profile: P.Profile) !void {
        if (profile != self.profile or !std.mem.eql(u8, &self.source_root, &setup.key.root) or !std.mem.eql(u8, &self.root, &self.tree.root())) return error.PoseidonNativeFixedAuthorityMismatch;
    }
    pub fn statement(self: *const Key, setup: *const R.CpuSetup, request: anytype, first: anytype) [32]u8 {
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        h.update("rv64-p2v2/source-worker-statement/v1\x00");
        h.update(&self.profile.identity());
        h.update(&self.identity);
        h.update(&self.root);
        h.update(&Legacy.cpuStatement(setup, request, first, self.profile.config()));
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    pub fn scope(self: *const Key) [32]u8 {
        return P.scopeRoot(self.profile, .fixed, self.root);
    }
    pub fn append(self: *const Key, a: std.mem.Allocator, scheme: *W.Scheme, ch: *W.Channel) !void {
        if (scheme.trees.items.len != 0 or !std.meta.eql(scheme.config, self.profile.config())) return error.PoseidonNativeFixedPhase;
        var tree = self.tree.retainShared();
        errdefer tree.deinit(self.allocator);
        try scheme.appendCommittedTree(a, tree, ch);
    }
};
