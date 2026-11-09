//! P2 FIXED authority rebuilt from receiver-owned source columns.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("pure_p2_worker_protocol.zig");
const W = P.W;
const R = @import("../word16_global_execution/services/roster.zig");
const Legacy = @import("../word16_global_execution/services/gkr_local/cpu_worker.zig");
pub const Key = struct {
    allocator: std.mem.Allocator,
    profile: P.Profile,
    op_only: bool = false,
    source_root: [32]u8,
    source_geometry: [32]u8,
    identity: [32]u8,
    root: W.H.Hash,
    tree: W.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, profile: P.Profile) !Key {
        if (setup.op_only or setup.bridges.tower != null) return error.UnqualifiedOpProtocol;
        return initMode(a, setup, profile, false);
    }
    pub fn initForOp(a: std.mem.Allocator, setup: *const R.CpuSetup, profile: P.Profile) !Key {
        if (!setup.op_only) return error.UnqualifiedOpSetup;
        return initMode(a, setup, profile, true);
    }
    fn initMode(a: std.mem.Allocator, setup: *const R.CpuSetup, profile: P.Profile, op_only: bool) !Key {
        if (profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        const columns = try setup.fixedColumns(a);
        defer a.free(columns);
        var scheme = try W.Prover.init(a, profile.config());
        defer scheme.deinit(a);
        scheme.setStorePolynomialsCoefficients();
        scheme.setCompactPolynomialStorage(1);
        var channel = W.Channel.init();
        try scheme.commitBorrowedStreaming(a, columns, 64, &channel);
        var tree = scheme.trees.pop().?;
        errdefer tree.deinit(a);
        try tree.share(a);
        const root = tree.root();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(if (op_only) "opstack-pure-p2/op-source-fixed-class/v1\x00" else "opstack-pure-p2/source-fixed-class/v1\x00");
        h.update(&profile.identity());
        h.update(&setup.materials.program.identity);
        h.update(&setup.key.root);
        h.update(&root);
        const source_geometry = try geometryIdentity(a, setup, &h);
        return .{ .allocator = a, .profile = profile, .op_only = op_only, .source_root = setup.key.root, .source_geometry = source_geometry, .identity = h.finalResult(), .root = root, .tree = tree };
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn require(self: *const Key, setup: *const R.CpuSetup, profile: P.Profile) !void {
        if (self.op_only or setup.op_only or setup.bridges.tower != null) return error.UnqualifiedOpProtocol;
        return self.requireMode(setup, profile);
    }
    pub fn requireForOp(self: *const Key, setup: *const R.CpuSetup, profile: P.Profile) !void {
        if (!self.op_only or !setup.op_only) return error.UnqualifiedOpSetup;
        return self.requireMode(setup, profile);
    }
    fn requireMode(self: *const Key, setup: *const R.CpuSetup, profile: P.Profile) !void {
        if (profile != self.profile or !std.mem.eql(u8, &self.source_root, &setup.key.root) or !std.mem.eql(u8, &self.root, &self.tree.root())) return error.PoseidonNativeFixedAuthorityMismatch;
        if (!std.mem.eql(u8, &self.source_geometry, &try geometryIdentity(self.allocator, setup, null))) return error.PoseidonNativeFixedGeometryMismatch;
    }
    pub fn statement(self: *const Key, setup: *const R.CpuSetup, request: anytype, first: anytype) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("opstack-pure-p2/source-worker-statement/v1\x00");
        h.update(&self.profile.identity());
        h.update(&self.identity);
        h.update(&self.root);
        h.update(&Legacy.cpuStatement(setup, request, first, self.profile.config()));
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    /// Request span belongs in the statement, never in immutable setup identity.
    pub fn statementForOp(self: *const Key, setup: *const R.CpuSetup, request: anytype, first: anytype, span: @import("../word16_global_execution/services/types.zig").OpTowerSpan) ![32]u8 {
        if (!self.op_only or !setup.op_only) return error.UnqualifiedOpSetup;
        try span.validate(setup.bridges);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("opstack-pure-p2/op-source-worker-statement/v1\x00");
        h.update(&self.statement(setup, request, first));
        var words: [12]u8 = undefined;
        std.mem.writeInt(u32, words[0..4], span.calls, .little);
        std.mem.writeInt(u32, words[4..8], span.first_id, .little);
        std.mem.writeInt(u32, words[8..12], setup.bridges.tower orelse 0, .little);
        h.update(&words);
        return h.finalResult();
    }
    pub fn scope(self: *const Key) W.H.Hash {
        return self.root;
    }
    pub fn append(self: *const Key, a: std.mem.Allocator, scheme: *W.Scheme, ch: *W.Channel) !void {
        if (scheme.trees.items.len != 0 or !std.meta.eql(scheme.config, self.profile.config())) return error.PoseidonNativeFixedPhase;
        var tree = self.tree.retainShared();
        errdefer tree.deinit(self.allocator);
        try scheme.appendCommittedTree(a, tree, ch);
    }
};

fn geometryIdentity(a: std.mem.Allocator, setup: *const R.CpuSetup, identity: ?*std.crypto.hash.sha2.Sha256) ![32]u8 {
    var geometry_hash = std.crypto.hash.sha2.Sha256.init(.{});
    geometry_hash.update("opstack-pure-p2/source-ordered-geometry/v1\x00");
    geometry_hash.update(&setup.materials.program.identity);
    geometry_hash.update(&setup.key.root);
    const geometry = try std.json.Stringify.valueAlloc(a, .{ .geometry = setup.materials.geometry, .bridges = setup.bridges }, .{});
    defer a.free(geometry);
    mixGeometry(&geometry_hash, identity, geometry);
    // Complete ordered source geometry, including the reduced local bindings.
    const Components = @import("../word16_global_execution/services/gkr_local/cpu_components.zig");
    var plan = if (setup.op_only) try Components.Plan.initForOp(a, setup) else try Components.Plan.init(a, setup);
    defer plan.deinit();
    for (0..3) |index| {
        const logs = if (index < 2) try setup.logs(a, index) else try plan.interLogs(a);
        defer a.free(logs);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(logs.len), .little);
        mixGeometry(&geometry_hash, identity, &bytes);
        for (logs) |log| {
            std.mem.writeInt(u32, &bytes, log, .little);
            mixGeometry(&geometry_hash, identity, &bytes);
        }
    }
    return geometry_hash.finalResult();
}
fn mixGeometry(hash: *std.crypto.hash.sha2.Sha256, identity: ?*std.crypto.hash.sha2.Sha256, bytes: []const u8) void {
    hash.update(bytes);
    if (identity) |other| other.update(bytes);
}
