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
    identity: [32]u8,
    root: [36]u8,
    tree: W.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, profile: Protocol.Profile, g: R.Geometry) !Key {
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
        try tree.share(a);
        const root = tree.root();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(R.DOMAIN);
        h.update("/fixed-authority");
        h.update(&profile.identity());
        h.update(&root);
        h.update(&try @import("semantic.zig").digest(a));
        for (instances) |instance| {
            var words: [16]u8 = undefined;
            std.mem.writeInt(u32, words[0..4], @intFromEnum(instance.role), .little);
            std.mem.writeInt(u32, words[4..8], instance.row_log, .little);
            std.mem.writeInt(u32, words[8..12], instance.queries(), .little);
            std.mem.writeInt(u32, words[12..16], @intCast(R.interactionWidth(instance.role)), .little);
            h.update(&words);
        }
        return .{ .allocator = a, .profile = profile, .logs = logs, .identity = h.finalResult(), .root = root, .tree = tree };
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn require(self: *const Key, g: R.Geometry) !void {
        for (try g.instances(), self.logs) |instance, log| if (instance.row_log != log) return error.SpongeLocalFixedGeometry;
    }
    pub fn statement(self: *const Key, g: R.Geometry, boundary: [32]u8) ![32]u8 {
        try self.require(g);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(R.DOMAIN);
        h.update("/request");
        h.update(&self.identity);
        h.update(&boundary);
        var counts: [12]u8 = undefined;
        std.mem.writeInt(u32, counts[0..4], g.calls, .little);
        std.mem.writeInt(u32, counts[4..8], g.permutations, .little);
        std.mem.writeInt(u32, counts[8..12], g.first_id, .little);
        h.update(&counts);
        return h.finalResult();
    }
};
