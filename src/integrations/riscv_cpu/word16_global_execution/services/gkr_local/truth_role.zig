//! Concrete wide classic truth AIR. Original arithmetic/rational authority,
//! explicit eight-coordinate interaction layout, no legacy four-column casts.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const O = core.fields.om31.OM31;
const Air = core.air.components.ForField(O);
const Point = core.circle.CirclePoint(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Frame = @import("truth_frame.zig");
const Local = @import("truth_classic.zig");
const TF = @import("truth_fractions.zig");
const Globals = @import("truth_global.zig");
pub const Kind = Frame.Role;
/// Claim-free physical metadata, shared by actual component methods and
/// receiver/device preflight. No zero claims or uninitialized challenges.
pub const Shape = struct {
    kind: Kind,
    log_size: u32,
    keccak_policy: K.equations.BatchPolicy = .triple_v2,
    byte_policy: S.layout.BytePolicy = .local,
    pub fn instance(self: *const @This()) Frame.Instance {
        return .{ .role = self.kind, .row_log = self.log_size, .queries = @intCast(switch (self.kind) {
            .keccak => self.keccak_policy.lookups(),
            .product, .linear => S.layout.byteCountFor(self.secpKind(), self.byte_policy),
            else => 1,
        }), .keccak_policy = self.keccak_policy, .byte_policy = self.byte_policy };
    }
    pub fn localWidth(self: *const @This()) usize {
        return Local.columns(self.instance());
    }
    pub fn firstColumn(self: *const @This()) usize {
        return switch (self.kind) {
            .keccak => K.layout.FIRST,
            .product, .linear => S.layout.FIRST,
            .chi, .xor5 => 6,
            .bytes => 1,
        };
    }
    pub fn widths(self: *const @This()) [3]usize {
        return switch (self.kind) {
            .keccak => .{ K.layout.FIXED, K.layout.MAIN, self.localWidth() + 8 * (self.keccak_policy.ioLookups() + 1) },
            .chi, .xor5 => .{ 7, 1, self.localWidth() },
            .product, .linear => .{ S.layout.FIXED, S.layout.main(self.secpKind()), self.localWidth() + 32 },
            .bytes => .{ 3, 1, self.localWidth() },
        };
    }
    pub fn secpKind(self: *const @This()) S.layout.Kind {
        return if (self.kind == .product) .product else .linear;
    }
    pub fn nConstraints(self: *const @This()) usize {
        return Local.residualCount(self.instance()) + switch (self.kind) {
            .keccak => K.layout.DIRECT + self.keccak_policy.ioLookups() + 2,
            .product, .linear => S.layout.direct(self.secpKind()) + 5,
            else => 0,
        };
    }
    pub fn shifts(self: *const @This(), tree: usize, col: usize) []const i32 {
        if (tree == 1) switch (self.kind) {
            .keccak => {
                if (col < K.layout.STATE) return &.{ 0, -2, -1, 1, 2 };
                if (col >= K.layout.ACTIVE_A) return &.{ 0, -1 };
            },
            .product, .linear => if (col == 0 or col == S.layout.base(self.secpKind())) return &.{ 0, -1 },
            else => {},
        };
        if (tree == 2 and ((col >= self.localWidth() - 8 and col < self.localWidth()) or col >= self.widths()[2] - 8)) return &.{ 0, -1 };
        return &.{0};
    }
    pub fn globalQueries(self: *const @This()) usize {
        return switch (self.kind) {
            .keccak, .product, .linear => (self.widths()[2] - self.localWidth()) / E.extensionDegree(O) - 1,
            else => 0,
        };
    }
    pub fn maxSamples(self: *const @This()) usize {
        var maximum: usize = 0;
        for (self.widths(), 0..) |width, tree| for (0..width) |column| {
            maximum = @max(maximum, self.shifts(tree, column).len);
        };
        return maximum;
    }
    pub fn maxDegree(self: *const @This()) u8 {
        return if (self.kind == .keccak) 5 else 3;
    }
};
pub const Component = struct {
    kind: Kind,
    log_size: u32,
    offsets: [3]usize = .{ 0, 0, 0 },
    calls: u32 = 0,
    first_id: u32 = 1,
    program: ?*const S.program.Program = null,
    keccak_policy: K.equations.BatchPolicy = .triple_v2,
    byte_policy: S.layout.BytePolicy = .local,
    local: TF.ChallengesFor(O),
    shared: @import("manifest.zig").Shared,
    claim: O,
    global_claim: O = O.zero(),
    split: u32 = 1,
    pub fn shape(self: *const @This()) Shape {
        return .{ .kind = self.kind, .log_size = self.log_size, .byte_policy = self.byte_policy, .keccak_policy = self.keccak_policy };
    }
    pub fn instance(self: *const @This()) Frame.Instance {
        const descriptor = self.shape();
        return descriptor.instance();
    }
    pub fn localWidth(self: *const @This()) usize {
        const descriptor = self.shape();
        return descriptor.localWidth();
    }
    pub fn firstColumn(self: *const @This()) usize {
        const descriptor = self.shape();
        return descriptor.firstColumn();
    }
    pub fn widths(self: *const @This()) [3]usize {
        const descriptor = self.shape();
        return descriptor.widths();
    }
    pub fn secpKind(self: *const @This()) S.layout.Kind {
        const descriptor = self.shape();
        return descriptor.secpKind();
    }
    pub fn validate(self: *const @This()) !void {
        switch (self.kind) {
            .keccak => {
                try K.layout.validateGeometryFor(self.keccak_policy.geometry(), self.calls, self.first_id, self.log_size);
            },
            .chi => if (self.log_size != self.keccak_policy.tableLog(.chi)) return error.InvalidWideTruthGeometry,
            .xor5 => if (self.log_size != self.keccak_policy.tableLog(.xor5)) return error.InvalidWideTruthGeometry,
            .product, .linear => {
                try S.layout.validate(self.secpKind(), self.program orelse return error.MissingWideTruthProgram, self.calls, self.first_id, self.log_size);
            },
            .bytes => if (self.log_size != 8) return error.InvalidWideTruthGeometry,
        }
    }
    pub fn nConstraints(self: *const @This()) usize {
        const descriptor = self.shape();
        return descriptor.nConstraints();
    }
    pub fn compositionLogSplit(self: *const @This()) u32 {
        return self.split;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + self.compositionLogSplit();
    }
    pub fn constraintDegreeBound(self: *const @This(), i: usize) !u8 {
        if (i >= self.nConstraints()) return error.InvalidConstraintIndex;
        return self.shape().maxDegree();
    }
    pub fn shifts(self: *const @This(), tree: usize, col: usize) []const i32 {
        const descriptor = self.shape();
        return descriptor.shifts(tree, col);
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        try self.validate();
        const trees = try a.alloc([]u32, 3);
        errdefer a.free(trees);
        var done: usize = 0;
        errdefer for (trees[0..done]) |v| a.free(v);
        for (trees, self.widths()) |*tree, width| {
            tree.* = try a.alloc(u32, width);
            @memset(tree.*, self.log_size);
            done += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.widths()[0]);
        for (out, 0..) |*v, c| v.* = self.offsets[0] + c;
        return out;
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        try self.validate();
        _ = try A.geometry.localPointFor(O, point, global_log, self.log_size);
        const trees = try a.alloc([][]Point, 3);
        errdefer a.free(trees);
        var done: usize = 0;
        errdefer for (trees[0..done]) |tree| {
            for (tree) |col| a.free(col);
            a.free(tree);
        };
        const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step;
        const lift = Point{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) };
        for (trees, self.widths(), 0..) |*tree, width, t| {
            tree.* = try a.alloc([]Point, width);
            var assigned: usize = 0;
            errdefer {
                for (tree.*[0..assigned]) |v| a.free(v);
                a.free(tree.*);
            }
            for (tree.*, 0..) |*col, c| {
                const shifts_ = self.shifts(t, c);
                col.* = try a.alloc(Point, shifts_.len);
                for (col.*, shifts_) |*v, shift| v.* = point.add(lift.mulSigned(shift));
                assigned += 1;
            }
            done += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    /// Large packed row buffers have a single explicit owner. Domain workers
    /// allocate these on their admitted allocator, never on1MiB helper stacks.
    pub fn Workspace(comptime F: type) type {
        return struct {
            fixed: [K.layout.FIXED]F,
            main: [K.layout.MAIN]F,
            current: [5336]F,
            previous: [5336]F,
            shifted: [4][K.layout.STATE]F,
            header: [3]F,
        };
    }
    /// Point/circuit callers retain their existing wrapper. The constraint
    /// body and emission order are shared with heap-workspace domain callers.
    pub fn emitFor(self: *const @This(), comptime F: type, samples: anytype, sink: *E.SinkFor(F)) !void {
        var workspace: Workspace(F) = undefined;
        return self.emitForWithWorkspace(F, samples, sink, &workspace);
    }
    pub fn emitForWithWorkspace(self: *const @This(), comptime F: type, samples: anytype, sink: *E.SinkFor(F), workspace: *Workspace(F)) !void {
        const width = self.widths();
        const fixed = &workspace.fixed;
        const main = &workspace.main;
        const current = &workspace.current;
        const previous = &workspace.previous;
        for (fixed[0..width[0]], 0..) |*v, c| v.* = try samples.get(0, c, 0);
        for (main[0..width[1]], 0..) |*v, c| v.* = try samples.get(1, c, 0);
        for (current[0..width[2]], 0..) |*v, c| {
            v.* = try samples.get(2, c, 0);
            previous[c] = F.zero();
            if (self.shifts(2, c).len > 1) previous[c] = try samples.get(2, c, -1);
        }
        const first = fixed[self.firstColumn()];
        const last = try samples.last();
        var local = Local.SinkFor(F){ .challenges = &self.local, .current = current[0..self.localWidth()], .out = sink, .width = Local.packing(self.kind) };
        switch (self.kind) {
            .keccak => {
                const shifted = &workspace.shifted;
                const offsets_ = [_]i32{ -2, -1, 1, 2 };
                for (shifted, offsets_) |*state, shift| {
                    for (state, 0..) |*v, c| v.* = try samples.get(1, c, shift);
                }
                const header = &workspace.header;
                for (header, 0..) |*v, c| v.* = try samples.get(1, K.layout.ACTIVE_A + c, -1);
                const row = K.equations.RowFor(F){ .fixed = fixed[0..K.layout.FIXED], .main = main[0..K.layout.MAIN], .previous_header = header, .state_minus_two = &shifted[0], .state_minus_one = &shifted[1], .state_plus_one = &shifted[2], .state_plus_two = &shifted[3] };
                if (self.keccak_policy.geometry() == .pair27) K.equations.emitDirectR27For(F, row, .{ .calls = self.calls, .first_id = self.first_id }, sink) else K.equations.emitDirectFor(F, row, .{ .calls = self.calls, .first_id = self.first_id }, sink, true);
                TF.keccakForPolicy(F, self.keccak_policy, row, &local);
                try local.finish(self.instance(), previous[0..self.localWidth()], first, last, self.claim);
                try Globals.keccakForPolicy(F, self.keccak_policy, row, current[self.localWidth()..width[2]], previous[self.localWidth()..width[2]], first, last, self.global_claim, self.shared.kio, sink);
            },
            .product, .linear => {
                const row = S.equations.RowFor(F){ .fixed = fixed[0..S.layout.FIXED], .main = main[0..width[1]], .previous_active = try samples.get(1, 0, -1), .previous_id = try samples.get(1, S.layout.base(self.secpKind()), -1) };
                S.equations.emitMainFor(F, self.secpKind(), row, self.local.polynomial, .{ .calls = self.calls, .first_id = self.first_id }, sink);
                TF.secpFor(F, self.secpKind(), self.byte_policy, row.main, &local);
                try local.finish(self.instance(), previous[0..self.localWidth()], first, last, self.claim);
                try Globals.secpFor(F, self.secpKind(), self.program.?, row, current[self.localWidth()..width[2]], previous[self.localWidth()..width[2]], first, last, self.global_claim, self.shared.wire, sink);
            },
            .chi, .xor5 => {
                TF.keccakTableFor(F, if (self.kind == .chi) .chi else .xor5, fixed[0..6].*, main[0], &local);
                try local.finish(self.instance(), previous[0..self.localWidth()], first, last, self.claim);
            },
            .bytes => {
                TF.byteTableFor(F, fixed[0], main[0], &local);
                try local.finish(self.instance(), previous[0..self.localWidth()], first, last, self.claim);
            },
        }
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc, global_log: u32) !void {
        try self.validate();
        const Sampler = struct {
            owner: *const Component,
            masks: *const Air.MaskValues,
            last_anchor: O,
            pub fn last(s: @This()) !O {
                return s.last_anchor;
            }
            pub fn get(s: @This(), tree: usize, col: usize, shift: i32) !O {
                const shifts_ = s.owner.shifts(tree, col);
                const at = std.mem.indexOfScalar(i32, shifts_, shift) orelse return error.InvalidWideTruthMask;
                return E.lane.sample(O, E.lane.NativeMasksForField(O){ .values = s.masks }, tree, s.owner.offsets[tree] + col, at, shifts_.len);
            }
        };
        var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.log_size) };
        const local = try A.geometry.localPointFor(O, point, global_log, self.log_size);
        const step = core.poly.circle.canonic.CanonicCoset.new(self.log_size).coset().step;
        const last = try @import("../../../logup_gkr/mle_point.zig").evalIsFirstFor(O, core.poly.circle.canonic.CanonicCoset.new(self.log_size).coset(), local.add(.{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) }));
        try self.emitFor(O, Sampler{ .owner = self, .masks = mask, .last_anchor = last }, &sink);
        if (sink.count != self.nConstraints()) return error.WideTruthConstraintCount;
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
        return @import("truth_role_domain.zig").evaluate(self, trace, acc);
    }
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator).asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) P.ComponentProver {
        return core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator).asProverComponent(self);
    }
};
