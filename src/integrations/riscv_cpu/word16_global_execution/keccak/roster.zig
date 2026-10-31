//! Concrete service roster appended to the immutable17-role CPU/RAM roster.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const B = K.word16_bridge;
const Old = @import("../../word16_execution/setup.zig");
const Sources = @import("../../word16_execution/sources.zig");
const P = @import("../protocol.zig");
const M = core.fields.m31.M31;
const Q = P.Q;
const Col = engine.pcs.ColumnEvaluation;
pub const Geo = struct { klog: u32, blog: u32 };
pub const WIDTHS = [3]usize{ K.layout.FIXED + 14 + B.layout.FIXED, K.layout.MAIN + 2 + B.layout.MAIN, K.layout.INTERACTION + 8 + B.layout.INTERACTION };
const logs = [_]u32{ 0, 13, 10, 0 };
pub fn append(out: []Col, at: *usize, data: []const M, log: u32) void {
    const n = @as(usize, 1) << @intCast(log);
    for (0..data.len / n) |c| {
        out[at.*] = .{ .log_size = log, .values = data[c * n ..][0..n] };
        at.* += 1;
    }
}
pub const Setup = struct {
    base: Old.Setup,
    geo: Geo,
    kfixed: []M,
    bfixed: []M,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    fixed_root: [32]u8,
    fixed_tree: @FieldType(Old.Setup, "fixed_tree"),
    pub fn init(a: std.mem.Allocator, authority: *const @import("../../rv64_full.zig").ProgramAuthority, g: Old.Geometry, geo: Geo) !Setup {
        try K.layout.validateGeometry(0, 1, geo.klog);
        _ = try B.types.validateGeometry(0, 1, geo.blog);
        var base = try Old.Setup.initWithAuthority(a, authority, g);
        errdefer base.deinit();
        return seal(a, base, geo);
    }
    pub fn initProgram(a: std.mem.Allocator, program: A.program.setup.Program, g: Old.Geometry, geo: Geo) !Setup {
        try K.layout.validateGeometry(0, 1, geo.klog);
        _ = try B.types.validateGeometry(0, 1, geo.blog);
        var base = try Old.Setup.init(a, program, g);
        errdefer base.deinit();
        return seal(a, base, geo);
    }
    fn seal(a: std.mem.Allocator, base: Old.Setup, geo: Geo) !Setup {
        const kf = try K.trace.fixedColumnsForLog(a, geo.klog);
        errdefer a.free(kf);
        const bf = try B.source.fixed(a, geo.blog);
        errdefer a.free(bf);
        var chi = try K.tables.Trace.init(a, .chi, &(@as([8192]u64, @splat(0))));
        errdefer chi.deinit();
        var xor = try K.tables.Trace.init(a, .xor5, &(@as([1024]u64, @splat(0))));
        errdefer xor.deinit();
        var self: Setup = .{ .base = base, .geo = geo, .kfixed = kf, .bfixed = bf, .chi = chi, .xor5 = xor, .fixed_root = undefined, .fixed_tree = undefined };
        const cols = try self.fixedColumns(a);
        defer a.free(cols);
        var scheme = try P.T.Scheme.init(a, P.T.P.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var ch = P.T.P.Channel{};
        try scheme.commitBorrowedStreaming(a, cols, 8, &ch);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        try scheme.trees.items[0].share(a);
        self.fixed_tree = scheme.trees.pop().?;
        self.fixed_root = roots.items[0];
        return self;
    }
    pub fn deinit(self: *Setup) void {
        const a = self.base.materials.allocator;
        self.fixed_tree.deinit(a);
        a.free(self.kfixed);
        a.free(self.bfixed);
        self.chi.deinit();
        self.xor5.deinit();
        self.base.deinit();
        self.* = undefined;
    }
    pub fn totals(self: *const Setup, tree: usize) usize {
        const shapes = self.base.materials.shapes();
        var n: usize = 0;
        for (shapes) |s| n += s.widths[tree];
        return n;
    }
    pub fn fixedColumns(self: *const Setup, a: std.mem.Allocator) ![]Col {
        const old = try self.base.materials.fixedColumns(a);
        defer a.free(old);
        const out = try a.alloc(Col, old.len + WIDTHS[0]);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        append(out, &at, self.kfixed, self.geo.klog);
        append(out, &at, self.chi.fixed, 13);
        append(out, &at, self.xor5.fixed, 10);
        append(out, &at, self.bfixed, self.geo.blog);
        return out;
    }
    pub fn columnLogs(self: *const Setup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const old = try self.base.materials.logs(a, tree);
        defer a.free(old);
        const out = try a.alloc(u32, old.len + WIDTHS[tree]);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        const widths = if (tree == 0) [4]usize{ K.layout.FIXED, 7, 7, B.layout.FIXED } else if (tree == 1) [4]usize{ K.layout.MAIN, 1, 1, B.layout.MAIN } else [4]usize{ K.layout.INTERACTION, 4, 4, B.layout.INTERACTION };
        for (widths, [4]u32{ self.geo.klog, 13, 10, self.geo.blog }) |w, l| {
            @memset(out[at..][0..w], l);
            at += w;
        }
        return out;
    }
    pub fn appendFixed(self: *const Setup, a: std.mem.Allocator, s: *P.T.Scheme, ch: *P.T.P.Channel) !void {
        if (s.trees.items.len != 0) return error.InvalidServiceFixedPhase;
        var tree = self.fixed_tree.retainShared();
        errdefer tree.deinit(self.base.materials.allocator);
        try s.appendCommittedTree(a, tree, ch);
    }
};
pub const Claims = struct {
    permutation: Q,
    chi: Q,
    xor5: Q,
    bridge: B.types.Claims,
    pub fn values(self: @This()) [8]Q {
        return .{ self.permutation, self.chi, self.xor5, self.bridge.ram, self.bridge.owner, self.bridge.io, self.bridge.range16, self.bridge.range8 };
    }
};
pub const Source = struct {
    permutation: K.trace.Trace,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    bridge: B.source.Source,
    pub fn init(a: std.mem.Allocator, calls: []const B.types.Call, geo: Geo) !Source {
        try K.layout.validateGeometry(calls.len, 1, geo.klog);
        _ = try B.types.validateGeometry(calls.len, 1, geo.blog);
        const inputs = try a.alloc(K.trace.State, calls.len);
        defer a.free(inputs);
        for (calls, inputs) |c, *i| i.* = c.before;
        var perm = try K.trace.Trace.initWithLog(a, inputs, 1, geo.klog);
        errdefer perm.deinit();
        const counts = try K.interaction.Counts.fromTrace(&perm);
        var chi = try K.tables.Trace.init(a, .chi, &counts.chi);
        errdefer chi.deinit();
        var xor = try K.tables.Trace.init(a, .xor5, &counts.xor5);
        errdefer xor.deinit();
        return .{ .permutation = perm, .chi = chi, .xor5 = xor, .bridge = try B.source.Source.init(a, calls, 1, geo.blog) };
    }
    pub fn deinit(self: *Source) void {
        self.bridge.deinit();
        self.xor5.deinit();
        self.chi.deinit();
        self.permutation.deinit();
    }
    pub fn releaseMain(self: *Source) !void {
        try self.permutation.releaseMain();
        try self.chi.releaseMain();
        try self.xor5.releaseMain();
        self.bridge.releaseMain();
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, base: *const Sources.Source, tree: usize) ![]Col {
        const old = try base.columns(a, tree);
        defer a.free(old);
        const out = try a.alloc(Col, old.len + WIDTHS[tree]);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        append(out, &at, if (tree == 1) self.permutation.main else self.permutation.interaction, self.permutation.log_size);
        append(out, &at, if (tree == 1) self.chi.main else self.chi.interaction, 13);
        append(out, &at, if (tree == 1) self.xor5.main else self.xor5.interaction, 10);
        append(out, &at, if (tree == 1) self.bridge.main else self.bridge.interaction, self.bridge.log_size);
        return out;
    }
    pub fn generate(self: *Source, ch: K.equations.Challenges, base: P.Old.Draw, dict16: []const Q, dict8: []const Q) !Claims {
        return .{ .permutation = try K.interaction.generate(&self.permutation, ch), .chi = try self.chi.generateInteraction(ch), .xor5 = try self.xor5.generateInteraction(ch), .bridge = try self.bridge.generate(.{ .io = ch.io, .ram = base.memory.ram, .owner = base.cpu.owner, .range16 = base.memory.range16, .range8 = base.memory.range8 }, dict16, dict8) };
    }
    pub fn mergeRanges(self: *const Source, base: *Sources.Source) !void {
        if (base.range16.interaction.len != 0 or base.range8.interaction.len != 0 or base.range16.main.len != 65536 or base.range8.main.len != 256) return error.InvalidServiceRangePhase;
        inline for (.{ base.counts16, base.counts8 }, .{ self.bridge.counts16, self.bridge.counts8 }, .{ base.range16.main, base.range8.main }, [_]u32{ 16, 8 }) |counts, extra, main, l| {
            var mass: u64 = 0;
            for (counts, extra, 0..) |*c, x, row| {
                c.* = try std.math.add(u64, c.*, x);
                mass = try std.math.add(u64, mass, c.*);
                if (mass >= core.fields.m31.Modulus) return error.ServiceRangeMassBound;
                main[A.witness.physical(row, l)] = M.fromCanonical(@intCast(c.*));
            }
        }
    }
};
pub const Components = struct {
    k: K.component.Component,
    chi: K.component.Component,
    xor5: K.component.Component,
    bridge: B.component.Component,
    pub fn init(setup: *const Setup, calls: u32, ch: K.equations.Challenges, base: P.Old.Draw, claims: Claims) Components {
        var at: [3]usize = .{ setup.totals(0), setup.totals(1), setup.totals(2) };
        const k: K.component.Component = .{ .kind = .permutation, .log_size = setup.geo.klog, .calls = calls, .offsets = .{ .fixed = at[0], .main = at[1], .interaction = at[2] }, .challenges = ch, .claim = claims.permutation };
        at[0] += K.layout.FIXED;
        at[1] += K.layout.MAIN;
        at[2] += K.layout.INTERACTION;
        const chi: K.component.Component = .{ .kind = .chi, .log_size = 13, .offsets = .{ .fixed = at[0], .main = at[1], .interaction = at[2] }, .challenges = ch, .claim = claims.chi };
        at[0] += 7;
        at[1] += 1;
        at[2] += 4;
        const xor: K.component.Component = .{ .kind = .xor5, .log_size = 10, .offsets = .{ .fixed = at[0], .main = at[1], .interaction = at[2] }, .challenges = ch, .claim = claims.xor5 };
        at[0] += 7;
        at[1] += 1;
        at[2] += 4;
        return .{ .k = k, .chi = chi, .xor5 = xor, .bridge = .{ .kind = .bridge, .log_size = setup.geo.blog, .rows = calls, .first_id = 1, .offsets = at, .claims = claims.bridge, .challenges = .{ .ram = base.memory.ram, .owner = base.cpu.owner, .io = ch.io, .range16 = base.memory.range16, .range8 = base.memory.range8 } } };
    }
    pub fn proverHandles(self: *const Components) ![4]engine.air.component_prover.ComponentProver {
        return .{ self.k.asProverComponent(), self.chi.asProverComponent(), self.xor5.asProverComponent(), try self.bridge.asProverComponent().withCompositionGeometryOverrideV1(.{ .composition_log_split = 2, .max_constraint_log_degree_bound_delta = 1 }) };
    }
    pub fn verifierHandles(self: *const Components) ![4]core.air.components.Component {
        return .{ self.k.asVerifierComponent(), self.chi.asVerifierComponent(), self.xor5.asVerifierComponent(), try self.bridge.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .composition_log_split = 2, .max_constraint_log_degree_bound_delta = 1 }) };
    }
};
