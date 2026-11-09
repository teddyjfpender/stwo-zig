//! Independent source authority for the standalone experimental physical gate.
//! Public external Var values never come from the prover's MAIN or its claim.
const std = @import("std");
const Core = @import("stwo_core");
const A = @import("../authority.zig");
const Source = @import("authority.zig");
const R = @import("row.zig");
pub const M = A.M;
pub const Q = A.Q;
pub const O = A.O;
pub const FIXED_START = 0;
pub const MAIN_START = 0;
pub const INTER_START = 0;
pub const Binding = struct { id: u32, value: Q };
pub const External = struct { binding: Binding, count: i64 };
pub const Key = struct {
    allocator: std.mem.Allocator,
    source: Source.Source,
    external: []External,
    dot_log: u32,
    dot_rows: usize,
    auxiliary_log: u32,
    fixed: A.Columns,
    fixed_tree: A.E.Scheme.CommittedTree,
    fixed_root: A.H.Hash,
    identity: [32]u8,
    /// Request values bind separately from reusable source/setup identity.
    statement: [32]u8,
    profile: A.Profile = .op_target_b4_q72_p0_fold4_v1,
    pub fn deinit(self: *Key) void {
        self.fixed_tree.deinit(self.allocator);
        self.fixed.deinit();
        self.allocator.free(self.external);
        self.source.deinit();
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, calls: []const Source.Call, uses: []const u32, bindings: []const Binding, auxiliary_log: u32) !Key {
        var source = try Source.Source.compile(a, calls, uses);
        errdefer source.deinit();
        const log: u32 = @intCast(std.math.log2_int(usize, source.fixed.len));
        if (auxiliary_log <= log or auxiliary_log > log + 2 or auxiliary_log > 10) return error.InvalidNativeDotPhysicalGeometry;
        const net = try a.alloc(i64, uses.len);
        defer a.free(net);
        @memset(net, 0);
        for (source.fixed[0..source.raw_rows]) |fixed| {
            for (fixed[0..3]) |id| net[id.v] += 1;
            if (!fixed[R.LAST].isZero()) {
                for (0..2) |i| net[fixed[R.OUTPUT_IDS + i].v] -= fixed[R.OUTPUT_USES + i].v;
            }
        }
        var needed: usize = 0;
        for (net) |n| needed += @intFromBool(n != 0);
        if (bindings.len != needed) return error.NativeDotExternalCoverage;
        for (bindings, 0..) |binding, i| {
            if (binding.id >= net.len or net[binding.id] == 0) return error.NativeDotExternalCoverage;
            if (i != 0 and binding.id <= bindings[i - 1].id) return error.NativeDotExternalOrder;
        }
        const external = try a.alloc(External, bindings.len);
        errdefer a.free(external);
        for (external, bindings) |*out, binding| out.* = .{ .binding = binding, .count = net[binding.id] };
        // Fixed topology and public statements are independently constructed;
        // never read the supplied witness values while building this key.
        var fixed = try columns(a, 0, log, auxiliary_log);
        errdefer fixed.deinit();
        for (source.fixed, 0..) |row, i| for (row, 0..) |v, col| fixed.put(col, physical(i, log), v);
        const aux_rows = @as(usize, 1) << @intCast(auxiliary_log);
        for (0..aux_rows) |i| fixed.put(R.FIXED, physical(i, auxiliary_log), auxiliaryValue(i));
        const profile = A.Profile.op_target_b4_q72_p0_fold4_v1;
        var channel = A.MC.Channel.init();
        var scheme = try A.E.init(a, profile.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        try scheme.commit(a, fixed.values, &channel);
        const root = scheme.trees.items[0].root();
        try scheme.trees.items[0].share(a);
        var tree = scheme.trees.items[0].retainShared();
        errdefer tree.deinit(a);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("opstack/experimental-native-dot/physical-v1/independent-external-Var-debt");
        hash.update(&source.identity);
        hash.update(&profile.identity());
        hash.update(&root);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, auxiliary_log, .little);
        hash.update(&bytes);
        const identity = hash.finalResult();
        hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("opstack/experimental-native-dot/external-statement-v1");
        hash.update(&identity);
        for (external) |e| {
            std.mem.writeInt(u32, &bytes, e.binding.id, .little);
            hash.update(&bytes);
            for (e.binding.value.toM31Array()) |v| {
                std.mem.writeInt(u32, &bytes, v.v, .little);
                hash.update(&bytes);
            }
        }
        return .{ .allocator = a, .source = source, .external = external, .dot_log = log, .dot_rows = @as(usize, 1) << @intCast(log), .auxiliary_log = auxiliary_log, .fixed = fixed, .fixed_tree = tree, .fixed_root = root, .identity = identity, .statement = hash.finalResult() };
    }
    pub fn treeLogs(self: *const Key, a: std.mem.Allocator, tree: usize) ![]u32 {
        const w = widths(tree);
        const out = try a.alloc(u32, w);
        @memset(out, self.dot_log);
        if (tree < 2) out[out.len - 1] = self.auxiliary_log;
        return out;
    }
};
pub fn widths(tree: usize) usize {
    return switch (tree) {
        0 => R.FIXED + 1,
        1 => R.MAIN + 1,
        2 => R.INTER,
        else => unreachable,
    };
}
pub fn physical(row: usize, log: u32) usize {
    return Core.utils.bitReverseIndex(Core.utils.cosetIndexToCircleDomainIndex(row, log), log);
}
pub fn auxiliaryValue(i: usize) M {
    return M.fromCanonical(@intCast(17 * i + 3));
}
pub fn columns(a: std.mem.Allocator, tree: usize, dot_log: u32, auxiliary_log: u32) !A.Columns {
    const out = try a.alloc(A.Col, widths(tree));
    var made: usize = 0;
    errdefer {
        for (out[0..made]) |column| a.free(column.values);
        a.free(out);
    }
    for (out, 0..) |*column, i| {
        const log = if (tree < 2 and i + 1 == out.len) auxiliary_log else dot_log;
        const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
        @memset(values, M.zero());
        column.* = .{ .log_size = log, .values = values };
        made += 1;
    }
    return .{ .allocator = a, .values = out };
}
