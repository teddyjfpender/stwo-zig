//! Concrete CPU service bridges and separately sized unchanged RCB truth rosters.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const B = S.word16_bridge;
const Mat = @import("../../word16_execution/setup.zig");
const Src = @import("../../word16_execution/sources.zig");
const Key = @import("../keccak/shared/key.zig").Key;
const append = @import("../keccak/roster.zig").append;
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;
pub const CpuSetup = struct {
    materials: Mat.Materials,
    bridge_logs: [2]u32,
    bridge_fixed: [2][]M,
    key: Key,
    pub fn initProgram(a: std.mem.Allocator, program: A.program.setup.Program, g: Mat.Geometry, bridge_logs: [2]u32) !CpuSetup {
        var m = try Mat.Materials.init(a, program, g);
        errdefer m.deinit();
        const add = try B.source.fixed(a, .add, bridge_logs[0]);
        errdefer a.free(add);
        const double = try B.source.fixed(a, .double, bridge_logs[1]);
        errdefer a.free(double);
        var self = CpuSetup{ .materials = m, .bridge_logs = bridge_logs, .bridge_fixed = .{ add, double }, .key = undefined };
        const cols = try self.fixedColumns(a);
        defer a.free(cols);
        self.key = try Key.seal(a, cols);
        return self;
    }
    pub fn deinit(self: *CpuSetup) void {
        self.key.deinit();
        for (self.bridge_fixed) |f| self.materials.allocator.free(f);
        self.materials.deinit();
    }
    pub fn total(self: *const CpuSetup, tree: usize) usize {
        var n: usize = 0;
        for (self.materials.shapes()) |s| n += s.widths[tree];
        return n;
    }
    pub fn fixedColumns(self: *const CpuSetup, a: std.mem.Allocator) ![]Col {
        const old = try self.materials.fixedColumns(a);
        defer a.free(old);
        const out = try a.alloc(Col, old.len + 2 * B.layout.FIXED);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (self.bridge_fixed, self.bridge_logs) |f, log| append(out, &at, f, log);
        return out;
    }
    pub fn logs(self: *const CpuSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const old = try self.materials.logs(a, tree);
        defer a.free(old);
        const width = B.layout.widths(.bridge)[tree];
        const out = try a.alloc(u32, old.len + 2 * width);
        @memcpy(out[0..old.len], old);
        for (self.bridge_logs, 0..) |log, i| @memset(out[old.len + i * width ..][0..width], log);
        return out;
    }
};
pub const CpuSource = struct {
    core: Src.Source,
    bridges: [2]B.source.Source,
    pub fn deinit(self: *CpuSource) void {
        for (&self.bridges) |*b| b.deinit();
        self.core.deinit();
    }
    pub fn mergeRanges(self: *CpuSource) !void {
        const base = &self.core;
        if (base.range16.interaction.len != 0 or base.range8.interaction.len != 0 or base.range16.main.len != 65536 or base.range8.main.len != 256) return error.InvalidSecpRangePhase;
        for (&self.bridges) |*b| {
            inline for (.{ base.counts16, base.counts8 }, .{ b.counts16, b.counts8 }, .{ base.range16.main, base.range8.main }, [_]u32{ 16, 8 }) |counts, extra, main, log| {
                var mass: u64 = 0;
                for (counts, extra, 0..) |*c, x, row| {
                    c.* = try std.math.add(u64, c.*, x);
                    mass = try std.math.add(u64, mass, c.*);
                    if (mass >= core.fields.m31.Modulus) return error.SecpRangeMassExceeded;
                    main[A.witness.physical(row, log)] = M.fromCanonical(@intCast(c.*));
                }
            }
        }
    }
    pub fn releaseMain(self: *CpuSource) !void {
        try self.core.releaseMain();
        for (&self.bridges) |*b| b.releaseMain();
    }
    pub fn columns(self: *const CpuSource, a: std.mem.Allocator, tree: usize) ![]Col {
        const old = try self.core.columns(a, tree);
        defer a.free(old);
        const width = B.layout.widths(.bridge)[tree];
        const out = try a.alloc(Col, old.len + 2 * width);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (self.bridges) |b| append(out, &at, if (tree == 1) b.main else b.interaction, b.log_size);
        return out;
    }
};
pub const TruthSetup = struct {
    allocator: std.mem.Allocator,
    kind: S.program.Kind,
    logs: [2]u32,
    product_fixed: []M,
    linear_fixed: []M,
    bytes: A.range.provider.Trace,
    key: Key,
    pub fn init(a: std.mem.Allocator, kind: S.program.Kind, logs: [2]u32) !TruthSetup {
        const p = S.program.get(kind);
        _ = try S.layout.admitRoster(&.{ .{ .kind = .product, .program = p, .calls = 0, .first_id = 1, .log = logs[0] }, .{ .kind = .linear, .program = p, .calls = 0, .first_id = 1, .log = logs[1] } }, &.{});
        const pf = try S.trace.fixedColumns(a, .product, p, logs[0]);
        errdefer a.free(pf);
        const lf = try S.trace.fixedColumns(a, .linear, p, logs[1]);
        errdefer a.free(lf);
        var bytes = try A.range.provider.Trace.init(a, &@as([256]u64, @splat(0)));
        errdefer bytes.deinit();
        var self = TruthSetup{ .allocator = a, .kind = kind, .logs = logs, .product_fixed = pf, .linear_fixed = lf, .bytes = bytes, .key = undefined };
        const cols = try self.fixedColumns(a);
        defer a.free(cols);
        self.key = try Key.seal(a, cols);
        return self;
    }
    pub fn deinit(self: *TruthSetup) void {
        self.key.deinit();
        self.allocator.free(self.product_fixed);
        self.allocator.free(self.linear_fixed);
        self.bytes.deinit();
    }
    pub fn widths(tree: usize) [3]usize {
        return .{ if (tree == 0) S.layout.FIXED else if (tree == 1) S.layout.main(.product) else S.layout.interaction(.product), if (tree == 0) S.layout.FIXED else if (tree == 1) S.layout.main(.linear) else S.layout.interaction(.linear), ([_]usize{ 3, 1, 8 })[tree] };
    }
    pub fn fixedColumns(self: *const TruthSetup, a: std.mem.Allocator) ![]Col {
        const w = widths(0);
        const out = try a.alloc(Col, w[0] + w[1] + w[2]);
        var at: usize = 0;
        append(out, &at, self.product_fixed, self.logs[0]);
        append(out, &at, self.linear_fixed, self.logs[1]);
        append(out, &at, self.bytes.fixed, 8);
        return out;
    }
    pub fn columnLogs(self: *const TruthSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const w = widths(tree);
        const out = try a.alloc(u32, w[0] + w[1] + w[2]);
        var at: usize = 0;
        for (w, [_]u32{ self.logs[0], self.logs[1], 8 }) |width, log| {
            @memset(out[at..][0..width], log);
            at += width;
        }
        return out;
    }
};
pub const TruthSource = struct {
    batch: S.batch.Batch,
    bytes: A.range.provider.Trace,
    pub fn init(a: std.mem.Allocator, setup: *const TruthSetup, calls: []const B.types.Call, first: u32) !TruthSource {
        const p = S.program.get(setup.kind);
        const inputs = try a.alloc(S.trace.Input, calls.len);
        defer a.free(inputs);
        for (calls, inputs) |call, *input| {
            input.* = .{ .coordinates = @splat(0) };
            for (0..p.inputs) |coord| {
                var bytes: [32]u8 = undefined;
                for (0..4) |lane| std.mem.writeInt(u64, bytes[8 * lane ..][0..8], call.before[4 * coord + lane], .little);
                input.coordinates[coord] = std.mem.readInt(u256, &bytes, .little);
            }
        }
        var batch = try S.batch.Batch.initWithLogs(a, p, inputs, first, setup.logs[0], setup.logs[1]);
        errdefer batch.deinit();
        a.free(batch.product.fixed);
        batch.product.fixed = setup.product_fixed;
        batch.product.owns_fixed = false;
        a.free(batch.linear.fixed);
        batch.linear.fixed = setup.linear_fixed;
        batch.linear.owns_fixed = false;
        var counts: [256]u64 = undefined;
        for (&counts, batch.product.byte_counts, batch.linear.byte_counts) |*v, x, y| v.* = try std.math.add(u64, x, y);
        return .{ .batch = batch, .bytes = try A.range.provider.Trace.init(a, &counts) };
    }
    pub fn deinit(self: *TruthSource) void {
        self.bytes.deinit();
        self.batch.deinit();
    }
    pub fn releaseMain(self: *TruthSource) !void {
        try self.batch.product.releaseMain();
        try self.batch.linear.releaseMain();
    }
    pub fn columns(self: *const TruthSource, a: std.mem.Allocator, tree: usize) ![]Col {
        const w = TruthSetup.widths(tree);
        const out = try a.alloc(Col, w[0] + w[1] + w[2]);
        var at: usize = 0;
        append(out, &at, if (tree == 1) self.batch.product.main else self.batch.product.interaction, self.batch.product.log_size);
        append(out, &at, if (tree == 1) self.batch.linear.main else self.batch.linear.interaction, self.batch.linear.log_size);
        append(out, &at, if (tree == 1) self.bytes.main else self.bytes.interaction, 8);
        return out;
    }
};
