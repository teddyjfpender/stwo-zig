//! Owned mixed-height physical columns, reconstructed from the immutable DAG.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = A.crypto.bn254_pairing_mac12;
const S = G.source;
const N = @import("native.zig");
const C = @import("component.zig");
const P = @import("projection.zig");
const Q = N.Q;
const M = N.M;
const physical = A.memory.closed_ram.trace.physical;
const Work = engine.lookups.row_work;
pub const PHYSICAL_ROW_TILE: usize = 32;
pub const MAX_LIVE_ROW_PAYLOAD_BYTES = Work.MAX_SHARDS * @sizeOf(G.fixture.Materialized);
pub const ORDER = [_]N.Role{ .frontier, .arithmetic, .hints, .table };
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
    bound_model: ?*G.fixture.Model = null,
    pub fn init(comptime role: N.Role, a: std.mem.Allocator, w: *G.fixture.Model) !@This() {
        const log = comptime C.logSize(role);
        const rows = comptime @as(usize, 1) << @intCast(log);
        if (w.columns[@intFromEnum(role)] != null) return error.PairingFixtureDuplicateColumns;
        const f = try a.alloc(M, C.fixedWidth(role) * rows);
        errdefer a.free(f);
        const m = try a.alloc(M, C.mainWidth(role) * rows);
        errdefer a.free(m);
        const inter = try a.alloc(M, C.interactionWidth(role) * rows);
        errdefer a.free(inter);
        @memset(inter, M.zero());
        // Table histograms depend on the completed arithmetic/hint matrices.
        // No helper may perform this coordinator-owned state transition.
        if (role == .table and !w.table_ready) try w.recount();
        const Context = struct {
            model: *G.fixture.Model,
            fixed: []M,
            main: []M,
            errors: [Work.MAX_SHARDS]?anyerror = @splat(null),
            pub fn runRange(context: *@This(), index: usize, start: usize, end: usize) void {
                context.fill(start * PHYSICAL_ROW_TILE, @min(end * PHYSICAL_ROW_TILE, rows)) catch |err| {
                    context.errors[index] = err;
                };
            }
            fn fill(context: *@This(), start: usize, end: usize) !void {
                for (start..end) |p| {
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, log), log);
                    const row = try context.model.materialize(role, logical);
                    for (0..C.fixedWidth(role)) |col| context.fixed[col * rows + p] = row.fixed(col).toM31Array()[0];
                    for (0..C.mainWidth(role)) |col| context.main[col * rows + p] = M.fromCanonical(row.main_values[col]);
                }
            }
        };
        var context = Context{ .model = w, .fixed = f, .main = m };
        const shards = Work.forEachRange(rows / PHYSICAL_ROW_TILE, &context, .{ .min_rows_per_shard = 16 });
        for (context.errors[0..shards]) |maybe| if (maybe) |err| return err;
        // Every FIXED/MAIN entry, including padding, is initialized before the
        // borrowed source view can become visible to a GKR reader.
        try w.installColumns(role, m);
        return .{ .allocator = a, .role = role, .log = log, .fixed = f, .main = m, .inter = inter, .bound_model = w };
    }
    /// Original logical-row traversal remains an independent test oracle.
    pub fn initScalarReferenceForTesting(comptime role: N.Role, a: std.mem.Allocator, w: *G.fixture.Model) !@This() {
        if (!@import("builtin").is_test) @compileError("test-only scalar column reference");
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
            const row = try w.materialize(role, logical);
            for (0..C.fixedWidth(role)) |col| f[col * rows + p] = row.fixed(col).toM31Array()[0];
            for (0..C.mainWidth(role)) |col| m[col * rows + p] = row.main(col).toM31Array()[0];
        }
        try w.installColumns(role, m);
        return .{ .allocator = a, .role = role, .log = log, .fixed = f, .main = m, .inter = inter, .bound_model = w };
    }
    /// Receiver authority needs only immutable FIXED, never MAIN/advice rows.
    pub fn initFixed(comptime role: N.Role, a: std.mem.Allocator, w: *const G.fixture.Model) !@This() {
        const log = C.logSize(role);
        const rows = @as(usize, 1) << @intCast(log);
        const f = try a.alloc(M, C.fixedWidth(role) * rows);
        errdefer a.free(f);
        const main = try a.alloc(M, 0);
        errdefer a.free(main);
        const inter = try a.alloc(M, 0);
        errdefer a.free(inter);
        for (0..rows) |row| {
            for (0..C.fixedWidth(role)) |col| f[col * rows + physical(row, log)] = w.fixed(role, row, col).toM31Array()[0];
        }
        return .{ .allocator = a, .role = role, .log = log, .fixed = f, .main = main, .inter = inter };
    }
    pub fn deinit(self: *@This()) void {
        if (self.bound_model) |model| {
            const slot = &model.columns[@intFromEnum(self.role)];
            if (slot.*) |borrowed| if (borrowed.ptr == self.main.ptr and borrowed.len == self.main.len) {
                slot.* = null;
            };
            if (self.role == .arithmetic or self.role == .hints) model.table_ready = false;
        }
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
        if (data.instance.role != self.role or index >= C.bindingCountForRuntime(self.role)) return error.PairingMac12SsaTraceShape;
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
