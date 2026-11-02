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
    /// Lookup interpretation of the unchanged MAIN witness. `triple_v2` is the
    /// compact truth (existing bundles); `throughput_v1` commits the RV32
    /// throughput tables (2^21 chi, 2^16 xor5) and 608 interaction columns.
    policy: Policy = .triple_v2,
    pub const Policy = K.equations.BatchPolicy;
    pub const WIDTHS = widthsFor(.triple_v2);
    pub fn widthsFor(policy: Policy) [3]usize {
        return .{ K.layout.FIXED + 14, K.layout.MAIN + 2, policy.interactionCount() + 8 };
    }
    pub fn widths(self: *const TruthSetup) [3]usize {
        return widthsFor(self.policy);
    }
    pub fn init(a: std.mem.Allocator, log: u32) !TruthSetup {
        return initWithSuite(a, log, Key.Suite.production());
    }
    pub fn initWithSuite(a: std.mem.Allocator, log: u32, suite: Key.Suite) !TruthSetup {
        return initPolicy(a, log, suite, .triple_v2);
    }
    pub fn initPolicy(a: std.mem.Allocator, log: u32, suite: Key.Suite, policy: Policy) !TruthSetup {
        try suite.validate();
        if (policy == .quartet_v3) return error.UnsupportedSharedTruthPolicy;
        if (log > 21) return error.SharedTruthGeometryBudget;
        try K.layout.validateGeometryFor(policy.geometry(), 0, 1, log);
        const fixed = try K.trace.fixedColumnsForLogGeometry(a, log, policy.geometry());
        errdefer a.free(fixed);
        const zeros = try a.alloc(u64, @as(usize, 1) << @intCast(policy.tableLog(.chi)));
        defer a.free(zeros);
        @memset(zeros, 0);
        var chi = try K.tables.Trace.initPolicy(a, .chi, policy, zeros);
        errdefer chi.deinit();
        var xor = try K.tables.Trace.initPolicy(a, .xor5, policy, zeros[0 .. @as(usize, 1) << @intCast(policy.tableLog(.xor5))]);
        errdefer xor.deinit();
        var self = TruthSetup{ .allocator = a, .log = log, .fixed = fixed, .chi = chi, .xor5 = xor, .key = undefined, .policy = policy };
        const cols = try self.fixedColumns(a);
        defer a.free(cols);
        self.key = try Key.sealWithSuite(a, cols, suite);
        return self;
    }
    pub fn deinit(self: *TruthSetup) void {
        self.key.deinit();
        self.allocator.free(self.fixed);
        self.chi.deinit();
        self.xor5.deinit();
    }
    pub fn fixedColumns(self: *const TruthSetup, a: std.mem.Allocator) ![]Col {
        const out = try a.alloc(Col, self.widths()[0]);
        var at: usize = 0;
        V1.append(out, &at, self.fixed, self.log);
        V1.append(out, &at, self.chi.fixed, self.policy.tableLog(.chi));
        V1.append(out, &at, self.xor5.fixed, self.policy.tableLog(.xor5));
        return out;
    }
    pub fn logs(self: *const TruthSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const out = try a.alloc(u32, self.widths()[tree]);
        const parts = if (tree == 0) [3]usize{ K.layout.FIXED, 7, 7 } else if (tree == 1) [3]usize{ K.layout.MAIN, 1, 1 } else [3]usize{ self.policy.interactionCount(), 4, 4 };
        var at: usize = 0;
        for (parts, [3]u32{ self.log, self.policy.tableLog(.chi), self.policy.tableLog(.xor5) }) |w, l| {
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
        return initSpan(a, inputs, 1, log);
    }
    pub fn initSpan(a: std.mem.Allocator, inputs: []const K.trace.State, first_id: u32, log: u32) !TruthSource {
        return initSpanPolicy(a, inputs, first_id, log, .triple_v2);
    }
    pub fn initSpanPolicy(a: std.mem.Allocator, inputs: []const K.trace.State, first_id: u32, log: u32, lookup: TruthSetup.Policy) !TruthSource {
        if (lookup == .quartet_v3) return error.UnsupportedSharedTruthPolicy;
        var p = try K.trace.Trace.initWithLogGeometry(a, inputs, first_id, log, lookup.geometry());
        errdefer p.deinit();
        if (lookup.throughputTables()) {
            var counts = try K.throughput_counts.Counts.fromTrace(a, &p);
            defer counts.deinit();
            var c = try K.tables.Trace.initPolicy(a, .chi, lookup, counts.chi);
            errdefer c.deinit();
            return .{ .permutation = p, .chi = c, .xor5 = try K.tables.Trace.initPolicy(a, .xor5, lookup, counts.xor5) };
        }
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
    pub fn policy(self: *const TruthSource) TruthSetup.Policy {
        return self.chi.policy;
    }
    pub fn columns(self: *const TruthSource, a: std.mem.Allocator, tree: usize) ![]Col {
        const p = self.policy();
        const out = try a.alloc(Col, TruthSetup.widthsFor(p)[tree]);
        var at: usize = 0;
        V1.append(out, &at, if (tree == 1) self.permutation.main else self.permutation.interaction, self.permutation.log_size);
        V1.append(out, &at, if (tree == 1) self.chi.main else self.chi.interaction, p.tableLog(.chi));
        V1.append(out, &at, if (tree == 1) self.xor5.main else self.xor5.interaction, p.tableLog(.xor5));
        return out;
    }
};
