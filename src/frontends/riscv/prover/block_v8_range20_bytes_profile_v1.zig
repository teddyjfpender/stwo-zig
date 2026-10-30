//! Explicit seven-plane lookup profile. Only range20 encoding changes;
//! native table tuple identities and all other canonical providers persist.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const K = @import("block_v8_range20_bytes_kernel_v1.zig");
const A = @import("block_v7_lookup_compact_algebra_v1.zig");
const L = @import("block_v7_lookup_compact_layout_v1.zig");
const Trace = @import("block_v7_lookup_compact_trace_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Counters = @import("../air/lookups/tables/counter.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations;
const Mapped = @import("block_v7_memory_joint_component_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
pub const Claims = K.Claims;
pub const Layout = struct {
    // Part is a shared physical storage descriptor, not legacy layout authority.
    parts: [6]L.Part,
    columns: [3]u32,
    digest: [32]u8,
    pub fn init(modes: [6]A.Mode, logs: [6]u32) !Layout {
        var out = Layout{ .parts = undefined, .columns = @splat(0), .digest = undefined };
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ K.TAG, K.VERSION, 7, 4, 8 });
        for (&out.parts, modes, logs, 0..) |*part, mode, log, i| {
            if (log < 4 or log > A.Schema.logSize(@enumFromInt(i))) return error.InvalidRange20Profile;
            if (i == 1) {
                if (mode != .sparse) return error.InvalidRange20Profile;
                part.* = .{ .kind = .range_check_20, .mode = .sparse, .log = log, .offset = out.columns, .width = .{ 1, 4, 8 }, .claim_count = 2 };
            } else {
                if (i == 4 and mode != .dense) return error.InvalidRange20Profile;
                part.* = try L.part(@enumFromInt(i), mode, log, out.columns);
            }
            ch.mixU32s(&.{ @intCast(i), @intFromEnum(mode), log });
            ch.mixU32s(&part.width);
            for (&out.columns, part.width) |*n, w| n.* = try std.math.add(u32, n.*, w);
        }
        out.digest = ch.digestBytes();
        return out;
    }
    pub fn validate(self: Layout) !void {
        var modes: [6]A.Mode = undefined;
        var logs: [6]u32 = undefined;
        for (self.parts, &modes, &logs) |p, *m, *l| {
            m.* = p.mode;
            l.* = p.log;
        }
        if (!std.meta.eql(self, try init(modes, logs))) return error.InvalidRange20Profile;
    }
};
pub const Stage = struct {
    a: std.mem.Allocator,
    layout: Layout,
    matrices: [6]T.Matrix,
    pub fn create(a: std.mem.Allocator, counters: *const Counters.Set, queries: u32) !Stage {
        var bytes = try Counters.Counter.init(a, .range_check_8_8);
        defer bytes.deinit(a);
        @memcpy(bytes.values, counters.counters[4].values);
        var modes: [6]A.Mode = undefined;
        var logs: [6]u32 = undefined;
        for (&counters.counters, &modes, &logs, 0..) |*counter, *mode, *log, i| {
            const n = try Trace.distinct(counter);
            mode.* = if (i == 1) .sparse else if (i == 4) .dense else try L.choose(counter.kind, n, 1, queries);
            log.* = if (mode.* == .dense) A.Schema.logSize(counter.kind) else @max(@as(u32, 4), std.math.log2_int_ceil(usize, @max(1, n)));
        }
        const layout = try Layout.init(modes, logs);
        var matrices: [6]T.Matrix = undefined;
        var ready: [6]bool = @splat(false);
        errdefer for (matrices, ready) |m, r| if (r) {
            var owned = m;
            owned.deinit();
        };
        matrices[1] = try T.Matrix.init(a, logs[1], 5, 1 << 30);
        ready[1] = true;
        var next: usize = 0;
        for (0..matrices[1].size()) |row| matrices[1].set(0, row, R.M.one());
        for (counters.counters[1].values, 0..) |m, v| if (!m.isZero()) {
            const w = try K.Spec.witness(@intCast(v), m);
            for (w, 0..) |x, j| matrices[1].set(1 + j, next, x);
            next += 1;
        };
        // Queries cover padded rows too. Zero multiplicity padding has valid
        // zero limbs and byte slack15, so no witness-selected activity exists.
        for (0..matrices[1].size()) |row| {
            try bytes.registerBase(R.M.one().neg(), &.{ matrices[1].get(2, row), matrices[1].get(3, row) });
            try bytes.registerBase(R.M.one().neg(), &.{ matrices[1].get(4, row), R.M.fromCanonical(15).sub(matrices[1].get(4, row)) });
        }
        for (layout.parts, 0..) |part, i| {
            if (i == 1) continue;
            const counter = if (i == 4) &bytes else &counters.counters[i];
            var f = try Trace.fixed(a, part, 1 << 30);
            defer f.deinit();
            var m = try Trace.main(a, part, counter, 1 << 30);
            defer m.deinit();
            matrices[i] = try T.Matrix.init(a, part.log, part.width[0] + part.width[1], 1 << 30);
            ready[i] = true;
            for (f.columns, 0..) |c, j| @memcpy(@constCast(matrices[i].columns[j].values), c.values);
            for (m.columns, 0..) |c, j| @memcpy(@constCast(matrices[i].columns[part.width[0] + j].values), c.values);
        }
        return .{ .a = a, .layout = layout, .matrices = matrices };
    }
    pub fn deinit(self: *Stage) void {
        for (&self.matrices) |*m| m.deinit();
    }
    pub fn fixed(a: std.mem.Allocator, layout: Layout) ![6]T.Matrix {
        try layout.validate();
        var out: [6]T.Matrix = undefined;
        var ready: usize = 0;
        errdefer for (out[0..ready]) |m| {
            var own = m;
            own.deinit();
        };
        for (layout.parts, 0..) |part, i| {
            if (i == 1) {
                out[i] = try T.Matrix.init(a, part.log, 1, 1 << 30);
                for (0..out[i].size()) |r| out[i].set(0, r, R.M.one());
            } else out[i] = try Trace.fixed(a, part, 1 << 30);
            ready += 1;
        }
        return out;
    }
};
fn Context(comptime i: usize, comptime mode: A.Mode) type {
    return struct {
        relation: R.Relation(R.Q, A.Schema.arity(@enumFromInt(i))),
        pub fn termsAt(self: @This(), matrix: T.Matrix, row: usize) ![1]R.Term(R.Q) {
            const Spec = A.For(@enumFromInt(i), mode);
            return .{Spec.term(R.Q, self.relation, matrix.row(Spec.FIXED_COUNT, 0, row), matrix.row(Spec.MAIN_COUNT, Spec.FIXED_COUNT, row))};
        }
    };
}
const Context20 = struct {
    range20: R.Relation(R.Q, 1),
    bytes: R.Relation(R.Q, 2),
    pub fn termsAt(self: @This(), m: T.Matrix, row: usize) ![2]R.Term(R.Q) {
        return K.Spec.terms(R.Q, self.range20, self.bytes, m.row(1, 0, row), m.row(4, 1, row));
    }
};
pub const Generated = struct {
    a: std.mem.Allocator,
    range20: T.Generated(2),
    other: [6]?T.Generated(1),
    columns: []Column,
    claims: Claims,
    pub fn create(a: std.mem.Allocator, stage: *const Stage, shared: Shared) !Generated {
        var range20 = try T.interactions(2, a, stage.matrices[1], Context20{ .range20 = .from(shared.native.range_check_20), .bytes = .from(shared.native.range_check_8_8) }, 1 << 30);
        errdefer range20.deinit();
        var other: [6]?T.Generated(1) = @splat(null);
        errdefer for (&other) |*g| if (g.*) |*v| v.deinit();
        var claims = Claims{ .native = undefined, .range20_bytes = range20.sums[1] };
        claims.native[1] = range20.sums[0];
        inline for (0..6) |i| if (i != 1) {
            inline for (.{ A.Mode.dense, A.Mode.sparse }) |mode| if (stage.layout.parts[i].mode == mode) {
                other[i] = try T.interactions(1, a, stage.matrices[i], Context(i, mode){ .relation = .from(@field(shared.native, @tagName(@as(A.Schema.Kind, @enumFromInt(i))))) }, 1 << 30);
                claims.native[i] = other[i].?.sums[0];
            };
        };
        const columns = try a.alloc(Column, 28);
        var at: usize = 0;
        for (0..6) |i| {
            const src = if (i == 1) range20.matrix.columns else other[i].?.matrix.columns;
            @memcpy(columns[at..][0..src.len], src);
            at += src.len;
        }
        return .{ .a = a, .range20 = range20, .other = other, .columns = columns, .claims = claims };
    }
    pub fn deinit(self: *Generated) void {
        self.range20.deinit();
        for (&self.other) |*g| if (g.*) |*v| v.deinit();
        self.a.free(self.columns);
    }
};
pub const Owner = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    provers: [6]engine.air.component_prover.ComponentProver,
    verifiers: [6]core.air.components.Component,
    pub fn create(a: std.mem.Allocator, layout: Layout, shared: Shared, claims: Claims) !*Owner {
        try layout.validate();
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.a = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const t = self.arena.allocator();
        const C20 = Mapped.ForPlacement(K.Spec, L.Part);
        const c20 = try t.create(C20);
        c20.* = try C20.init(.{ .range20 = .from(shared.native.range_check_20), .bytes = .from(shared.native.range_check_8_8), .sums = .{ claims.native[1], claims.range20_bytes } }, layout.parts[1]);
        self.provers[1] = c20.asProverComponent();
        self.verifiers[1] = c20.asVerifierComponent();
        inline for (0..6) |i| if (i != 1) {
            inline for (.{ A.Mode.dense, A.Mode.sparse }) |mode| if (layout.parts[i].mode == mode) {
                const Spec = A.For(@enumFromInt(i), mode);
                const C = Mapped.ForPlacement(Spec, L.Part);
                const c = try t.create(C);
                c.* = try C.init(.{ .relation = .from(@field(shared.native, @tagName(@as(A.Schema.Kind, @enumFromInt(i))))), .sums = .{claims.native[i]} }, layout.parts[i]);
                self.provers[i] = c.asProverComponent();
                self.verifiers[i] = c.asVerifierComponent();
            };
        };
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        self.arena.deinit();
        a.destroy(self);
    }
};
