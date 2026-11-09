//! Independently derived immutable fixed authority. Request counts/firstIDs and
//! boundary records stay in the statement, not immutable setup identity.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("authority.zig");
const Source = @import("source.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const M = core.fields.m31.M31;
pub const Key = struct {
    allocator: std.mem.Allocator,
    profile: Protocol.Profile,
    logs: [8]u32,
    detached: bool,
    identity: [32]u8,
    root: [36]u8,
    tree: ?W.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, profile: Protocol.Profile, g: R.Geometry) !Key {
        return initMode(a, profile, g, true);
    }
    /// Derive the same FIXED root from source, then release wide prover data.
    pub fn initDigest(a: std.mem.Allocator, profile: Protocol.Profile, g: R.Geometry) !Key {
        return initMode(a, profile, g, false);
    }
    fn initMode(a: std.mem.Allocator, profile: Protocol.Profile, g: R.Geometry, resident: bool) !Key {
        if (profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        const instances = try g.instances();
        var storage: [8][]M = undefined;
        var allocated: usize = 0;
        defer for (storage[0..allocated]) |v| a.free(v);
        var count: usize = 0;
        inline for (R.roles) |role| count += R.fixedWidth(role);
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, count);
        defer a.free(columns);
        var first: usize = 0;
        var logs: [8]u32 = undefined;
        inline for (R.roles, 0..) |role, i| {
            const rows = try instances[i].rows();
            storage[i] = try a.alloc(M, try std.math.mul(usize, rows, R.fixedWidth(role)));
            allocated += 1;
            logs[i] = instances[i].row_log;
            for (0..rows) |logical| {
                const fixed = Source.fixedRow(role, logical, logs[i]);
                const physical = A.witness.physical(logical, logs[i]);
                for (fixed, 0..) |v, c| storage[i][c * rows + physical] = v;
            }
            for (columns[first..][0..R.fixedWidth(role)], 0..) |*column, c| column.* = .{ .log_size = logs[i], .values = storage[i][c * rows ..][0..rows] };
            first += R.fixedWidth(role);
        }
        var scheme = try W.Prover.init(a, profile.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        var channel = W.Channel.init();
        try scheme.commitBorrowedStreaming(a, columns, 64, &channel);
        var tree = scheme.trees.pop().?;
        errdefer tree.deinit(a);
        if (resident) try tree.share(a);
        const root = tree.root();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(R.domain(g.detached));
        h.update("/fixed-authority");
        const profile_identity = profile.identity();
        h.update(&profile_identity);
        h.update(&root);
        const semantic_identity = if (g.detached) try @import("semantic.zig").digestFor(a, true) else try @import("semantic.zig").digestFor(a, false);
        h.update(&semantic_identity);
        for (instances) |instance| {
            var words: [16]u8 = undefined;
            std.mem.writeInt(u32, words[0..4], @intFromEnum(instance.role), .little);
            std.mem.writeInt(u32, words[4..8], instance.row_log, .little);
            std.mem.writeInt(u32, words[8..12], instance.queries(), .little);
            std.mem.writeInt(u32, words[12..16], @intCast(R.interactionWidth(instance.role)), .little);
            h.update(&words);
        }
        const out = Key{ .allocator = a, .profile = profile, .logs = logs, .detached = g.detached, .identity = h.finalResult(), .root = root, .tree = if (resident) tree else null };
        if (!resident) tree.deinit(a);
        return out;
    }
    pub fn retainFixedTree(self: *const Key) !W.Scheme.CommittedTree {
        const tree = self.tree orelse return error.SpongeDigestOnlyKeyCannotProve;
        return tree.retainShared();
    }
    pub fn retireProverData(self: *Key) void {
        if (self.tree) |*tree| tree.deinit(self.allocator);
        self.tree = null;
    }
    pub fn deinit(self: *Key) void {
        self.retireProverData();
        self.* = undefined;
    }
    pub fn require(self: *const Key, g: R.Geometry) !void {
        if (self.tree) |tree| if (!std.mem.eql(u8, &self.root, &tree.root())) return error.SpongeLocalFixedGeometry;
        if (g.detached != self.detached) return error.SpongeLocalFixedGeometry;
        for (try g.instances(), self.logs) |instance, log| if (instance.row_log != log) return error.SpongeLocalFixedGeometry;
    }
    pub fn statement(self: *const Key, g: R.Geometry, boundary: [32]u8) ![32]u8 {
        if (g.detached) return error.SpongeLocalScopeFlavor;
        return self.statementBody(g, boundary);
    }
    pub fn statementDetached(self: *const Key, g: R.Geometry) ![32]u8 {
        if (!g.detached) return error.SpongeLocalScopeFlavor;
        return self.statementBody(g, null);
    }
    fn statementBody(self: *const Key, g: R.Geometry, boundary: ?[32]u8) ![32]u8 {
        try self.require(g);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(R.domain(g.detached));
        h.update("/request");
        h.update(&self.identity);
        if (boundary) |b| h.update(&b);
        var counts: [12]u8 = undefined;
        std.mem.writeInt(u32, counts[0..4], g.calls, .little);
        std.mem.writeInt(u32, counts[4..8], g.permutations, .little);
        std.mem.writeInt(u32, counts[8..12], g.first_id, .little);
        h.update(&counts);
        return h.finalResult();
    }
};
