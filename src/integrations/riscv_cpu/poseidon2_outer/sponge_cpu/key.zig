//! Independent CPU+frontier FIXED authority, separate from request identity.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Components = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const Frame = @import("frame.zig");
const L = @import("equations.zig").Layout;
pub const Key = struct {
    allocator: std.mem.Allocator,
    profile: Protocol.Profile,
    frontier_log: u32,
    identity: [32]u8,
    geometry: [32]u8,
    root: [36]u8,
    tree: W.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, profile: Protocol.Profile, log: u32) !Key {
        if (profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        var roster = try Frame.Roster.init(a, setup, 0, log, 1, 0);
        defer roster.deinit();
        const old = try setup.fixedColumns(a);
        defer a.free(old);
        const count = setup.columnCount(0);
        if (old.len != count) return error.SpongeCpuGeometry;
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, count + L.FIXED);
        defer a.free(columns);
        @memcpy(columns[0..count], old);
        const rows = @as(usize, 1) << @intCast(log);
        const data = try a.alloc(M, try std.math.mul(usize, rows, L.FIXED));
        defer a.free(data);
        for (0..rows) |logical| {
            const p = A.witness.physical(logical, log);
            data[p] = M.fromCanonical(@intCast(logical));
            data[rows + p] = M.fromCanonical(@intFromBool(logical == 0));
            data[2 * rows + p] = M.fromCanonical(@intFromBool(logical + 1 == rows));
        }
        for (columns[count..], 0..) |*v, c| v.* = .{ .log_size = log, .values = data[c * rows ..][0..rows] };
        var scheme = try W.Prover.init(a, profile.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        var channel = W.Channel.init();
        try scheme.commitBorrowedStreaming(a, columns, 64, &channel);
        var tree = scheme.trees.pop().?;
        errdefer tree.deinit(a);
        try tree.share(a);
        const root = tree.root();
        const geometry = try geometryIdentity(a, setup, log);
        return .{ .allocator = a, .profile = profile, .frontier_log = log, .geometry = geometry, .identity = identity(profile, geometry, root), .root = root, .tree = tree };
    }
    pub fn require(self: *const Key, setup: *const R.CpuSetup) !void {
        const derived = try geometryIdentity(self.allocator, setup, self.frontier_log);
        if (!std.mem.eql(u8, &derived, &self.geometry) or !std.mem.eql(u8, &self.root, &self.tree.root()) or !std.mem.eql(u8, &self.identity, &identity(self.profile, derived, self.root))) return error.SpongeCpuFixedAuthority;
    }
    pub fn statement(self: *const Key, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, span: T.OpTowerSpan, ordinal: u32) ![32]u8 {
        try self.require(setup);
        try span.validate(setup.bridges);
        try A.crypto.keccak_sponge.serialized.frontier.validatePublic(request.sponge.calls, self.frontier_log, request.base.epoch, ordinal);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(Frame.DOMAIN);
        h.update("/statement/v1");
        h.update(&self.identity);
        h.update(&@import("../../word16_global_execution/services/gkr_local/cpu_worker.zig").cpuStatement(setup, request, first, self.profile.config()));
        var words: [16]u8 = undefined;
        std.mem.writeInt(u32, words[0..4], span.calls, .little);
        std.mem.writeInt(u32, words[4..8], span.first_id, .little);
        std.mem.writeInt(u32, words[8..12], setup.bridges.tower orelse 0, .little);
        std.mem.writeInt(u32, words[12..16], ordinal, .little);
        h.update(&words);
        return h.finalResult();
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
        self.* = undefined;
    }
};
fn identity(profile: Protocol.Profile, geometry: [32]u8, root: [36]u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(Frame.DOMAIN);
    h.update("/key/v1");
    const p = profile.identity();
    h.update(&p);
    h.update(&geometry);
    h.update(&root);
    return h.finalResult();
}
fn geometryIdentity(a: std.mem.Allocator, setup: *const R.CpuSetup, log: u32) ![32]u8 {
    var roster = try Frame.Roster.init(a, setup, 0, log, 1, 0);
    defer roster.deinit();
    var plan = try Components.Plan.initForOp(a, setup);
    defer plan.deinit();
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(Frame.DOMAIN);
    h.update("/ordered-source-geometry/v1");
    h.update(&setup.materials.program.identity);
    h.update(&setup.key.root);
    const declaration = try std.json.Stringify.valueAlloc(a, .{ .geometry = setup.materials.geometry, .bridges = setup.bridges, .frontier_log = log }, .{});
    defer a.free(declaration);
    h.update(declaration);
    const semantic = try @import("semantic.zig").digest(a);
    h.update(&semantic);
    for (0..3) |tree| {
        const logs = if (tree < 2) try setup.logs(a, tree) else try plan.interLogs(a);
        defer a.free(logs);
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, @intCast(logs.len + L.widths()[tree]), .little);
        h.update(&word);
        for (logs) |value| {
            std.mem.writeInt(u32, &word, value, .little);
            h.update(&word);
        }
        for (0..L.widths()[tree]) |_| {
            std.mem.writeInt(u32, &word, log, .little);
            h.update(&word);
        }
    }
    return h.finalResult();
}
