//! Owned mixed-height physical columns, reconstructed from the immutable DAG.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_residue;
const S = G.spec;
const N = @import("native.zig");
const C = @import("component.zig");
const P = @import("projection.zig");
const Q = N.Q;
const M = N.M;
const physical = A.memory.closed_ram.trace.physical;
pub const ORDER = [_]N.Role{ .frontier, .square, .multiply, .hint, .table };
pub fn width(tree: usize) usize {
    var total: usize = 0;
    inline for (ORDER) |r| total += switch (tree) {
        0 => C.fixedWidth(r),
        1 => C.mainWidth(r),
        2 => C.interactionWidth(r),
        else => unreachable,
    };
    return total;
}
pub fn logs(comptime tree: usize) [width(tree)]u32 {
    var out: [width(tree)]u32 = undefined;
    var offset: usize = 0;
    inline for (ORDER) |r| {
        const n = switch (tree) {
            0 => C.fixedWidth(r),
            1 => C.mainWidth(r),
            2 => C.interactionWidth(r),
            else => unreachable,
        };
        @memset(out[offset..][0..n], C.logSize(r));
        offset += n;
    }
    return out;
}
pub fn offsets(comptime role: N.Role) [3]usize {
    var out: [3]usize = .{ 0, 0, 0 };
    inline for (ORDER) |r| {
        if (r == role) return out;
        out[0] += C.fixedWidth(r);
        out[1] += C.mainWidth(r);
        out[2] += C.interactionWidth(r);
    }
    unreachable;
}
pub const Part = struct {
    allocator: std.mem.Allocator,
    role: N.Role,
    log: u32,
    fixed: []M,
    main: []M,
    inter: []M,
    pub fn init(comptime role: N.Role, a: std.mem.Allocator, w: *const G.fixture.Model) !@This() {
        const log = C.logSize(role);
        const rows = @as(usize, 1) << @intCast(log);
        const f = try a.alloc(M, C.fixedWidth(role) * rows);
        errdefer a.free(f);
        const m = try a.alloc(M, C.mainWidth(role) * rows);
        errdefer a.free(m);
        const inter = try a.alloc(M, C.interactionWidth(role) * rows);
        errdefer a.free(inter);
        @memset(f, M.zero());
        @memset(m, M.zero());
        @memset(inter, M.zero());
        for (0..rows) |logical| {
            const p = physical(logical, log);
            const v = w.view(role, logical);
            for (0..C.fixedWidth(role)) |c| f[c * rows + p] = v.fixed(c).toM31Array()[0];
            for (0..C.mainWidth(role)) |c| m[c * rows + p] = v.main(c).toM31Array()[0];
        }
        return .{ .allocator = a, .role = role, .log = log, .fixed = f, .main = m, .inter = inter };
    }
    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.main);
        self.allocator.free(self.inter);
        self.* = undefined;
    }
    pub fn columns(self: *const @This(), tree: usize, out: []engine.pcs.ColumnEvaluation) void {
        const data = switch (tree) {
            0 => self.fixed,
            1 => self.main,
            2 => self.inter,
            else => unreachable,
        };
        const rows = @as(usize, 1) << @intCast(self.log);
        std.debug.assert(data.len == out.len * rows);
        for (out, 0..) |*v, i| v.* = .{ .log_size = self.log, .values = data[i * rows ..][0..rows] };
    }
    pub fn installBinding(self: *@This(), w: *const G.fixture.Model, data: *const P.Data, index: usize) !void {
        if (data.instance.role != self.role or index >= C.bindingCountForRuntime(self.role)) return error.DenseSsaTraceShape;
        const columns_ = try P.witness(self.allocator, w, data);
        defer self.allocator.free(columns_);
        const rows = @as(usize, 1) << @intCast(self.log);
        @memcpy(self.inter[index * 16 * rows ..][0 .. 16 * rows], columns_);
    }
    pub const View = struct {
        part: *const Part,
        logical: usize,
        pub fn main(v: *const @This(), c: usize) Q {
            const rows = @as(usize, 1) << @intCast(v.part.log);
            return Q.fromBase(v.part.main[c * rows + physical(v.logical, v.part.log)]);
        }
        pub fn fixed(v: *const @This(), c: usize) Q {
            const rows = @as(usize, 1) << @intCast(v.part.log);
            return Q.fromBase(v.part.fixed[c * rows + physical(v.logical, v.part.log)]);
        }
    };
};
