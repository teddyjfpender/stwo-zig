//! Concrete CPU+bridge and pure K truth rosters. Arithmetic remains in existing
//! frontend authorities; this module only owns material/column lifetimes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const B = K.word16_bridge;
const Mat = @import("../../../word16_execution/setup.zig");
const S = @import("../../../word16_execution/sources.zig");
const V1 = @import("../roster.zig");
const Key = @import("key.zig").Key;
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;
pub const CpuSetup = struct {
    materials: Mat.Materials,
    bridge_log: u32,
    bridge_fixed: []M,
    key: Key,
    pub fn initProgram(a: std.mem.Allocator, program: A.program.setup.Program, g: Mat.Geometry, blog: u32) !CpuSetup {
        var m = try Mat.Materials.init(a, program, g);
        errdefer m.deinit();
        return seal(a, m, blog);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, authority: *const @import("../../../rv64_full.zig").ProgramAuthority, g: Mat.Geometry, blog: u32) !CpuSetup {
        var m = try Mat.Materials.initWithAuthority(a, authority, g);
        errdefer m.deinit();
        return seal(a, m, blog);
    }
    fn seal(a: std.mem.Allocator, m: Mat.Materials, blog: u32) !CpuSetup {
        const fixed = try B.source.fixed(a, blog);
        errdefer a.free(fixed);
        var self = CpuSetup{ .materials = m, .bridge_log = blog, .bridge_fixed = fixed, .key = undefined };
        const cols = try self.fixedColumns(a);
        defer a.free(cols);
        self.key = try Key.seal(a, cols);
        return self;
    }
    pub fn deinit(self: *CpuSetup) void {
        const a = self.materials.allocator;
        self.key.deinit();
        a.free(self.bridge_fixed);
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
        const out = try a.alloc(Col, old.len + B.layout.FIXED);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        V1.append(out, &at, self.bridge_fixed, self.bridge_log);
        return out;
    }
    pub fn logs(self: *const CpuSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const old = try self.materials.logs(a, tree);
        defer a.free(old);
        const width = ([_]usize{ B.layout.FIXED, B.layout.MAIN, B.layout.INTERACTION })[tree];
        const out = try a.alloc(u32, old.len + width);
        @memcpy(out[0..old.len], old);
        @memset(out[old.len..], self.bridge_log);
        return out;
    }
};
pub const CpuSource = struct {
    core: S.Source,
    bridge: B.source.Source,
    pub fn deinit(self: *CpuSource) void {
        self.bridge.deinit();
        self.core.deinit();
    }
    pub fn mergeRanges(self: *CpuSource) !void {
        const base = &self.core;
        if (base.range16.interaction.len != 0 or base.range8.interaction.len != 0 or base.range16.main.len != 65536 or base.range8.main.len != 256) return error.InvalidSharedTruthRangePhase;
        inline for (.{ base.counts16, base.counts8 }, .{ self.bridge.counts16, self.bridge.counts8 }, .{ base.range16.main, base.range8.main }, [_]u32{ 16, 8 }) |counts, extra, main, log| {
            var mass: u64 = 0;
            for (counts, extra, 0..) |*c, x, row| {
                c.* = try std.math.add(u64, c.*, x);
                mass = try std.math.add(u64, mass, c.*);
                if (mass >= core.fields.m31.Modulus) return error.SharedTruthRangeMassExceeded;
                main[A.witness.physical(row, log)] = M.fromCanonical(@intCast(c.*));
            }
        }
    }
    pub fn releaseMain(self: *CpuSource) !void {
        try self.core.releaseMain();
        self.bridge.releaseMain();
    }
    pub fn columns(self: *const CpuSource, a: std.mem.Allocator, tree: usize) ![]Col {
        const old = try self.core.columns(a, tree);
        defer a.free(old);
        const width = if (tree == 1) B.layout.MAIN else B.layout.INTERACTION;
        const out = try a.alloc(Col, old.len + width);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        V1.append(out, &at, if (tree == 1) self.bridge.main else self.bridge.interaction, self.bridge.log_size);
        return out;
    }
};
pub const TruthSetup = struct {
    allocator: std.mem.Allocator,
    log: u32,
    fixed: []M,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    key: Key,
    pub const WIDTHS = [3]usize{ K.layout.FIXED + 14, K.layout.MAIN + 2, K.layout.INTERACTION + 8 };
    pub fn init(a: std.mem.Allocator, log: u32) !TruthSetup {
        if (log > 21) return error.SharedTruthGeometryBudget;
        try K.layout.validateGeometry(0, 1, log);
        const fixed = try K.trace.fixedColumnsForLog(a, log);
        errdefer a.free(fixed);
        var chi = try K.tables.Trace.init(a, .chi, &(@as([8192]u64, @splat(0))));
        errdefer chi.deinit();
        var xor = try K.tables.Trace.init(a, .xor5, &(@as([1024]u64, @splat(0))));
        errdefer xor.deinit();
        var self = TruthSetup{ .allocator = a, .log = log, .fixed = fixed, .chi = chi, .xor5 = xor, .key = undefined };
        const cols = try self.fixedColumns(a);
        defer a.free(cols);
        self.key = try Key.seal(a, cols);
        return self;
    }
    pub fn deinit(self: *TruthSetup) void {
        self.key.deinit();
        self.allocator.free(self.fixed);
        self.chi.deinit();
        self.xor5.deinit();
    }
    pub fn fixedColumns(self: *const TruthSetup, a: std.mem.Allocator) ![]Col {
        const out = try a.alloc(Col, WIDTHS[0]);
        var at: usize = 0;
        V1.append(out, &at, self.fixed, self.log);
        V1.append(out, &at, self.chi.fixed, 13);
        V1.append(out, &at, self.xor5.fixed, 10);
        return out;
    }
    pub fn logs(self: *const TruthSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const out = try a.alloc(u32, WIDTHS[tree]);
        const widths = if (tree == 0) [3]usize{ K.layout.FIXED, 7, 7 } else if (tree == 1) [3]usize{ K.layout.MAIN, 1, 1 } else [3]usize{ K.layout.INTERACTION, 4, 4 };
        var at: usize = 0;
        for (widths, [3]u32{ self.log, 13, 10 }) |w, l| {
            @memset(out[at..][0..w], l);
            at += w;
        }
        return out;
    }
};
pub const TruthSource = struct {
    permutation: K.trace.Trace,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    pub fn init(a: std.mem.Allocator, inputs: []const K.trace.State, log: u32) !TruthSource {
        var p = try K.trace.Trace.initWithLog(a, inputs, 1, log);
        errdefer p.deinit();
        const counts = try K.interaction.Counts.fromTrace(&p);
        var c = try K.tables.Trace.init(a, .chi, &counts.chi);
        errdefer c.deinit();
        return .{ .permutation = p, .chi = c, .xor5 = try K.tables.Trace.init(a, .xor5, &counts.xor5) };
    }
    pub fn deinit(self: *TruthSource) void {
        self.xor5.deinit();
        self.chi.deinit();
        self.permutation.deinit();
    }
    pub fn releaseMain(self: *TruthSource) !void {
        try self.permutation.releaseMain();
        try self.chi.releaseMain();
        try self.xor5.releaseMain();
    }
    pub fn columns(self: *const TruthSource, a: std.mem.Allocator, tree: usize) ![]Col {
        const out = try a.alloc(Col, TruthSetup.WIDTHS[tree]);
        var at: usize = 0;
        V1.append(out, &at, if (tree == 1) self.permutation.main else self.permutation.interaction, self.permutation.log_size);
        V1.append(out, &at, if (tree == 1) self.chi.main else self.chi.interaction, 13);
        V1.append(out, &at, if (tree == 1) self.xor5.main else self.xor5.interaction, 10);
        return out;
    }
};
