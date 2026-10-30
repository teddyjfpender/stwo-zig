//! Original caller RAM projection without integer-copy or WORD sidecar rows.
//! This component reads only admitted caller/state columns. Keccak output is
//! the actual +27 opening. It must share one original STARK with those caller
//! arithmetic equations; alone it confers no execution authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = core.air.components;
const CP = engine.air.component_prover;
const DA = engine.air.accumulation.DomainEvaluationAccumulator;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const Canonic = core.poly.circle.canonic.CanonicCoset;
const logup = @import("../air/logup.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Source = @import("block_v8_caller_ram_projection_v1.zig");
const Sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const Keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const Signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
const KeccakTrace = @import("../air/guest_precompile/keccakf_trace.zig");
const KeccakWitness = @import("../air/guest_precompile/keccakf_witness.zig");
const AccessBridge = @import("block_execution_external_access_bridge_v2.zig");
const MAX_CALLER = @max(Sha.PHYSICAL_MAIN_COLUMN_COUNT, @max(Keccak.Layout.main_columns, Signer.Layout.main_columns));
pub const Component = struct {
    descriptor: Source.Descriptor,
    fixed_logs: []const u32,
    main_logs: []const u32,
    interaction_logs: []const u32,
    interaction_offset: usize,
    root_owner: bool,
    /// All state ranges requiring current/+27 openings, derived from the exact
    /// admitted descriptor inventory, never selected by proof-carried masks.
    keccak_state_offsets: []const usize,
    relation: R.Relation(Q, 7),
    claim: Q,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, CP.ComponentProver, CP.Trace, DA);
    pub fn init(self: Self) !Self {
        try @import("block_execution_external_trace_v2.zig").requireRwDescriptors(&.{self.descriptor}, 1);
        const d = self.descriptor;
        if (d.log_size < 1 or d.log_size > 24 or d.main_offset > self.main_logs.len or d.mainWidth() > self.main_logs.len - d.main_offset or
            self.interaction_offset > self.interaction_logs.len or 4 > self.interaction_logs.len - self.interaction_offset) return error.InvalidCallerRamGeometry;
        for (self.main_logs[d.main_offset..][0..d.mainWidth()]) |log| if (log != d.log_size) return error.InvalidCallerRamGeometry;
        for (self.interaction_logs[self.interaction_offset..][0..4]) |log| if (log != d.log_size) return error.InvalidCallerRamGeometry;
        if (d.kind == .sha and (d.fixed_offset >= self.fixed_logs.len or self.fixed_logs[d.fixed_offset] != d.log_size)) return error.InvalidCallerRamGeometry;
        for (self.keccak_state_offsets) |offset| if (offset > self.main_logs.len or KeccakWitness.state_cell_count > self.main_logs.len - offset) return error.InvalidCallerRamGeometry;
        for (self.claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidCallerRamClaim;
        return self;
    }
    pub fn asProverComponent(self: *const Self) CP.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) C.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return 4;
    }
    pub fn compositionLogSplit(_: *const Self) u32 {
        return 2;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.descriptor.log_size + 2;
    }
    pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
        if (index >= 4) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
        const f = try a.dupe(u32, if (self.root_owner) self.fixed_logs else &.{});
        errdefer a.free(f);
        const m = try a.dupe(u32, if (self.root_owner) self.main_logs else &.{});
        errdefer a.free(m);
        const interaction = try a.dupe(u32, &([_]u32{self.descriptor.log_size} ** 4));
        errdefer a.free(interaction);
        return .initOwned(try a.dupe([]u32, &.{ f, m, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        if (!self.root_owner) return a.alloc(usize, 0);
        const out = try a.alloc(usize, self.fixed_logs.len);
        for (out, 0..) |*value, index| value.* = index;
        return out;
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
        if (max_log < self.descriptor.log_size) return error.InvalidCallerRamMask;
        const f = try pointColumns(a, if (self.root_owner) self.fixed_logs.len else 0, &.{point});
        errdefer freePoints(a, f);
        const m = try pointColumns(a, if (self.root_owner) self.main_logs.len else 0, &.{point});
        errdefer freePoints(a, m);
        if (self.root_owner) {
            const output_point = point.add(logup.liftPoint(Canonic.new(max_log).coset_value.step).mulSigned(27));
            for (self.keccak_state_offsets) |offset| for (m[offset..][0..KeccakWitness.state_cell_count]) |*column| {
                a.free(column.*);
                column.* = try a.dupe(Point, &.{ point, output_point });
            };
        }
        const interaction = try pointColumns(a, 4, &.{ point, logup.prevRowPoint(max_log, point) });
        errdefer freePoints(a, interaction);
        return .initOwned(try a.dupe([][]Point, &.{ f, m, interaction }));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3 or mask.items[1].len != self.main_logs.len or mask.items[2].len < self.interaction_offset + 4) return error.InvalidCallerRamMask;
        const Samples = struct {
            mask: *const C.MaskValues,
            pub fn at(self_: @This(), tree: usize, column: usize, ordinal: usize) !Q {
                if (tree >= self_.mask.items.len or column >= self_.mask.items[tree].len or ordinal >= self_.mask.items[tree][column].len) return error.InvalidCallerRamMask;
                return self_.mask.items[tree][column][ordinal];
            }
        };
        const projected = try fromSamples(self.descriptor, self.relation, Samples{ .mask = mask });
        var current: [4]Q = undefined;
        var previous: [4]Q = undefined;
        for (&current, &previous, 0..) |*now, *before, index| {
            now.* = try (Samples{ .mask = mask }).at(2, self.interaction_offset + index, 0);
            before.* = try (Samples{ .mask = mask }).at(2, self.interaction_offset + index, 1);
        }
        const normalized = try self.claim.divM31(M.fromU64(@as(usize, 1) << @intCast(self.descriptor.log_size)));
        const inverse = try core.constraints.cosetVanishing(Q, Canonic.new(self.descriptor.log_size).coset(), point.repeatedDouble(max_log - self.descriptor.log_size)).inv();
        for (Source.equations(Q, projected, current, previous, normalized)) |equation| accumulator.accumulate(equation.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const CP.Trace, accumulator: *DA) !void {
        if (source.polys.items.len != 3) return error.InvalidCallerRamTrees;
        const d = self.descriptor;
        const caller_count: usize = switch (d.kind) {
            .sha => Sha.PHYSICAL_MAIN_COLUMN_COUNT,
            .keccak => Keccak.Layout.main_columns,
            .signer => Signer.Layout.main_columns,
        };
        const keccak_columns = if (d.kind == .keccak) try AccessBridge.keccakRamColumns(d.slot) else [_]usize{0} ** 4;
        const selected_count = if (d.kind == .keccak) keccak_columns.len else caller_count;
        const fixed_count: usize = @intFromBool(d.kind == .sha);
        const state_count: usize = if (d.kind == .keccak) 32 else 0;
        const caller_offset = d.main_offset + if (d.kind == .keccak) KeccakTrace.Layout.caller else @as(usize, 0);
        const state_offset = d.main_offset + KeccakTrace.Layout.state + (if (d.kind == .keccak) (d.slot - 1) * 32 else @as(usize, 0));
        const count = fixed_count + selected_count + state_count + 4;
        const a = accumulator.allocator;
        const polys = try a.alloc(CP.Poly, count);
        defer a.free(polys);
        if (fixed_count != 0) polys[0] = source.polys.items[0][d.fixed_offset];
        for (0..selected_count) |index| polys[fixed_count + index] = source.polys.items[1][caller_offset + if (d.kind == .keccak) keccak_columns[index] else index];
        for (0..state_count) |index| polys[fixed_count + selected_count + index] = source.polys.items[1][state_offset + index];
        for (0..4) |index| polys[count - 4 + index] = source.polys.items[2][self.interaction_offset + index];
        const eval_log = d.log_size + 2;
        const domain = Canonic.new(eval_log).circleDomain();
        const support = @import("../recursion/air/universal_typed_component_contract.zig");
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, d.log_size, eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        const values = try a.alloc([]const M, count);
        defer a.free(values);
        var twiddles: ?engine.poly.twiddles.TwiddleTree([]M) = if (owned_count != 0) try engine.poly.twiddles.precomputeM31(a, domain.half_coset) else null;
        defer if (twiddles) |*tree| engine.poly.twiddles.deinitM31(a, tree);
        const transform: ?engine.poly.twiddles.TwiddleTree([]const M) = if (twiddles) |tree| .init(tree.root_coset, tree.twiddles, tree.itwiddles) else null;
        for (polys, values) |poly, *value| value.* = try support.evaluationValues(a, poly, d.log_size, eval_log, domain.size(), transform, owned, &initialized);
        if (initialized != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, transform.?);
        var inverse: [4]M = undefined;
        for (&inverse, 0..) |*out, index| out.* = try core.constraints.cosetVanishing(M, Canonic.new(d.log_size).coset(), domain.at(core.utils.bitReverseIndex(index, 2))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = 4 }});
        defer a.free(output);
        var result = output[0];
        const normalized = try self.claim.divM31(M.fromU64(@as(usize, 1) << @intCast(d.log_size)));
        for (0..domain.size()) |row| {
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, d.log_size, eval_log);
            var caller: [MAX_CALLER]Q = @splat(Q.zero());
            for (values[fixed_count..][0..selected_count], 0..) |column, index| caller[if (d.kind == .keccak) keccak_columns[index] else index] = Q.fromBase(column[row]);
            const projected = if (d.kind == .sha) try Source.sha(Q, caller[0..caller_count], Q.fromBase(values[0][row]), d.slot, self.relation) else if (d.kind == .signer) try Source.signer(Q, caller[0..caller_count], d.slot, self.relation) else blk: {
                const output_row = core.utils.offsetBitReversedCircleDomainIndex(row, d.log_size, eval_log, 27);
                var input_bits: [32]Q = undefined;
                var output_bits: [32]Q = undefined;
                for (&input_bits, &output_bits, 0..) |*before, *after, index| {
                    const column = values[fixed_count + selected_count + index];
                    before.* = Q.fromBase(column[row]);
                    after.* = Q.fromBase(column[output_row]);
                }
                break :blk try Source.keccak(Q, caller[0..caller_count], input_bits, output_bits, d.slot, self.relation);
            };
            var current: [4]Q = undefined;
            var previous: [4]Q = undefined;
            for (&current, &previous, 0..) |*now, *before, index| {
                now.* = Q.fromBase(values[count - 4 + index][row]);
                before.* = Q.fromBase(values[count - 4 + index][prior]);
            }
            for (Source.equations(Q, projected, current, previous, normalized), 0..) |equation, index| result.accumulate(row, result.random_coeff_powers[3 - index].mul(equation).mulM31(inverse[row >> @as(std.math.Log2Int(usize), @intCast(d.log_size))]));
        }
    }
};
/// Exact selected-word extraction at arbitrary OODS points or committed rows.
pub fn AuthenticatedAccessFor(comptime S: type) type {
    return struct { pair: @import("block_execution_access_bridge_v2.zig").Pair(S), instruction_cycle: S };
}
pub const AuthenticatedAccess = AuthenticatedAccessFor(Q);
pub fn accessFromSamples(descriptor: Source.Descriptor, samples: anytype) !AuthenticatedAccess {
    return accessFromSamplesAs(Q, descriptor, samples);
}
/// Domain inputs are M31; keep their linear byte/clock extraction in M31.
/// OODS callers continue to instantiate the exact same formula over QM31.
pub fn accessFromSamplesAs(comptime S: type, descriptor: Source.Descriptor, samples: anytype) !AuthenticatedAccessFor(S) {
    try @import("block_execution_external_trace_v2.zig").requireRwDescriptors(&.{descriptor}, 1);
    if (descriptor.kind == .sha) {
        var caller: [Sha.PHYSICAL_MAIN_COLUMN_COUNT]S = undefined;
        for (&caller, 0..) |*value, index| value.* = try samples.at(1, descriptor.main_offset + index, 0);
        return .{ .pair = try @import("block_execution_external_access_bridge_v2.zig").shaPair(S, &caller, try samples.at(0, descriptor.fixed_offset, 0), descriptor.slot), .instruction_cycle = caller[Sha.Layout.clock] };
    }
    if (descriptor.kind == .signer) {
        var caller: [Signer.Layout.main_columns]S = undefined;
        for (&caller, 0..) |*value, index| value.* = try samples.at(1, descriptor.main_offset + index, 0);
        return .{ .pair = try @import("block_execution_external_access_bridge_v2.zig").signerPair(S, &caller, descriptor.slot), .instruction_cycle = caller[Signer.Layout.execution_clock] };
    }
    var caller: [Keccak.Layout.main_columns]S = @splat(S.zero());
    for (try AccessBridge.keccakRamColumns(descriptor.slot)) |index| caller[index] = try samples.at(1, descriptor.main_offset + KeccakTrace.Layout.caller + index, 0);
    var input: [32]S = undefined;
    var output: [32]S = undefined;
    const offset = descriptor.main_offset + KeccakTrace.Layout.state + (descriptor.slot - 1) * 32;
    for (&input, &output, 0..) |*before, *after, index| {
        before.* = try samples.at(1, offset + index, 0);
        after.* = try samples.at(1, offset + index, 1);
    }
    return .{ .pair = try @import("block_execution_external_access_bridge_v2.zig").keccakPairFromWordBits(S, &caller, input, output, descriptor.slot), .instruction_cycle = caller[Keccak.Layout.execution_clock] };
}
/// The RAM relation and first-halt guard consume the very same authenticated
/// tuple extractor, including Keccak's actual +27 output and instruction clock.
pub fn fromSamples(descriptor: Source.Descriptor, relation: R.Relation(Q, 7), samples: anytype) !Source.Point(Q) {
    return Source.fromPair(Q, (try accessFromSamples(descriptor, samples)).pair, relation);
}

fn pointColumns(a: std.mem.Allocator, count: usize, points: []const Point) ![][]Point {
    const out = try a.alloc([]Point, count);
    var ready: usize = 0;
    errdefer {
        for (out[0..ready]) |value| a.free(value);
        a.free(out);
    }
    for (out) |*column| {
        column.* = try a.dupe(Point, points);
        ready += 1;
    }
    return out;
}
fn freePoints(a: std.mem.Allocator, points: [][]Point) void {
    for (points) |column| a.free(column);
    a.free(points);
}
