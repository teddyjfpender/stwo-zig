//! Membership metadata reuses authentic caller source and byte-witness fields.
//! No copied address, clock, before, after, word-bit or fixed activity columns.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Protocol = @import("block_v5_caller_readonly_protocol_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Bridge = @import("block_execution_access_bridge_v2.zig");
const Pair = Bridge.Pair(Q);
const canonic = core.poly.circle.canonic;
pub const META_COUNT = Protocol.METADATA_COLUMNS;
pub const INTER_COUNT = Protocol.INTERACTION_COLUMNS;
pub const COUNT = Protocol.EQUATIONS;
pub const Metadata = [META_COUNT]Q;
/// One exact membership/access algebra for the original QM31 evaluator and
/// symbolic verifier. Column order and all149 residuals are unchanged.
pub fn Algebra(comptime F: type) type {
    return struct {
        fn scalar(v: u32) F {
            return F.fromBase(M.fromCanonical(v));
        }
        fn bits(row: []const F) F {
            var sum = F.zero();
            var power = F.one();
            for (row) |value| {
                sum = sum.add(value.mul(power));
                power = power.add(power);
            }
            return sum;
        }
        fn bytes16(v: []const F) F {
            return v[0].add(v[1].mul(scalar(256)));
        }
        pub fn sourceTuple(pair: @import("block_execution_access_bridge_v2.zig").Pair(F), witness: [Integer.COLUMN_COUNT]F) [11]F {
            const w = @import("block_execution_integer_algebra_v1.zig").Algebra(F).Witness.fromColumns(witness);
            return .{ F.one(), bytes16(w.byte_address[0..2]), bytes16(w.byte_address[2..4]), bytes16(w.global_clock[0..2]), bytes16(w.global_clock[2..4]), bytes16(w.global_clock[4..6]), bytes16(w.global_clock[6..8]), bytes16(pair.before[0..2]), bytes16(pair.before[2..4]), bytes16(pair.after[0..2]), bytes16(pair.after[2..4]) };
        }
        fn wordIndex(witness: [Integer.COLUMN_COUNT]F) F {
            const w = @import("block_execution_integer_algebra_v1.zig").Algebra(F).Witness.fromColumns(witness);
            return w.byte_address[0].add(w.byte_address[1].mul(scalar(256))).add(w.byte_address[2].mul(scalar(65536)))
                .add(w.byte_address[3].mul(scalar(16777216))).mul(scalar(536870912)); // inverse 4 in M31
        }
        fn combine(elements: anytype, tuple: anytype) F {
            var sum = F.zero();
            for (tuple, elements.alpha_powers) |value, power| sum = sum.add(value.mul(power));
            return sum.sub(elements.z);
        }
        pub fn denominators(pair: @import("block_execution_access_bridge_v2.zig").Pair(F), witness: [Integer.COLUMN_COUNT]F, metadata: [META_COUNT]F, challenges: anytype) [3]F {
            const tuple = @This().sourceTuple(pair, witness);
            return .{ combine(challenges.word.transition, tuple), combine(challenges.classification, metadata[0..5].*), combine(challenges.read, tuple[1..3].* ++ metadata[3..5].*) };
        }
        pub fn numerators(pair: @import("block_execution_access_bridge_v2.zig").Pair(F), metadata: [META_COUNT]F) [4]F {
            const ro = pair.active.mul(metadata[2]);
            return .{ pair.active.sub(ro), pair.active, ro, ro };
        }
        pub fn equations(pair: @import("block_execution_access_bridge_v2.zig").Pair(F), witness: [Integer.COLUMN_COUNT]F, metadata: [META_COUNT]F, current: [INTER_COUNT]F, previous: [INTER_COUNT]F, shifts: [4]F, challenges: anytype) [COUNT]F {
            @setEvalBranchQuota(30000);
            var result: [COUNT]F = undefined;
            var at: usize = 0;
            for (metadata[5..]) |bit| {
                result[at] = bit.mul(bit.sub(F.one()));
                at += 1;
            }
            const w = @import("block_execution_integer_algebra_v1.zig").Algebra(F).Witness.fromColumns(witness);
            result[at] = pair.active.mul(w.byte_address[0].sub(bits(metadata[65..71]).mul(scalar(4))));
            at += 1;
            const ro = metadata[2];
            result[at] = ro.mul(ro.sub(F.one()));
            at += 1;
            const word = wordIndex(witness);
            result[at] = pair.active.mul(word.sub(metadata[0]).sub(bits(metadata[5..35])));
            at += 1;
            result[at] = pair.active.mul(metadata[1].sub(word).sub(F.one()).sub(bits(metadata[35..65])));
            at += 1;
            const tuple = @This().sourceTuple(pair, witness);
            inline for (0..2) |i| {
                result[at] = pair.active.mul(ro).mul(tuple[7 + i].sub(metadata[3 + i]));
                at += 1;
                result[at] = pair.active.mul(ro).mul(tuple[9 + i].sub(metadata[3 + i]));
                at += 1;
            }
            for (metadata) |value| {
                result[at] = F.one().sub(pair.active).mul(value);
                at += 1;
            }
            const d = @This().denominators(pair, witness, metadata, challenges);
            const n = @This().numerators(pair, metadata);
            inline for (0..4) |i| {
                const delta = F.fromPartialEvals(current[4 * i ..][0..4].*).sub(F.fromPartialEvals(previous[4 * i ..][0..4].*)).add(shifts[i]);
                result[at] = if (i < 3) delta.mul(d[i]).sub(n[i]) else delta.sub(n[i]);
                at += 1;
            }
            std.debug.assert(at == result.len);
            return result;
        }
    };
}
pub const sourceTuple = Algebra(Q).sourceTuple;
pub const denominators = Algebra(Q).denominators;
pub const numerators = Algebra(Q).numerators;
pub const equations = Algebra(Q).equations;

pub fn witnessRow(event: @import("../air/block/memory_transition.zig").Transition, interval: Plan.Interval) ![META_COUNT]M {
    const full = try @import("block_v5_readonly_input_component_v1.zig").witnessRow(event, interval);
    var result: [META_COUNT]M = undefined;
    @memcpy(result[0..65], full[38..103]);
    for (0..6) |bit| result[65 + bit] = M.fromCanonical(((event.address / 4) >> @intCast(bit)) & 1);
    return result;
}
pub const Component = struct {
    source: @import("block_execution_sidecar_stark_v2.zig").Component,
    metadata_offset: usize,
    prefix_offset: usize,
    claim: Protocol.Claim,
    challenges: *const Protocol.Challenges,
    split: u32,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, engine.air.component_prover.ComponentProver, engine.air.component_prover.Trace, engine.air.accumulation.DomainEvaluationAccumulator);
    pub fn init(self: Self) !Self {
        _ = try self.source.init();
        const descriptor = self.source.external_source orelse return error.MissingCallerReadonlySource;
        if (self.source.register_custody_mode != 1 or (descriptor.kind == .sha and descriptor.slot < 2) or
            (descriptor.kind != .sha and descriptor.slot == 0) or self.split < 2 or self.split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT)
            return error.InvalidCallerReadonlySourceGeometry;
        const witness = self.source.witness_logs orelse return error.MissingCallerReadonlyLogs;
        const interactions = self.source.interaction_logs orelse return error.MissingCallerReadonlyLogs;
        if (self.metadata_offset > witness.len or META_COUNT > witness.len - self.metadata_offset or
            self.prefix_offset > interactions.len or INTER_COUNT > interactions.len - self.prefix_offset) return error.InvalidCallerReadonlyLogs;
        for (witness[self.metadata_offset..][0..META_COUNT]) |log| if (log != descriptor.log_size) return error.InvalidCallerReadonlyLogs;
        for (interactions[self.prefix_offset..][0..INTER_COUNT]) |log| if (log != descriptor.log_size) return error.InvalidCallerReadonlyLogs;
        return self;
    }
    pub fn asProverComponent(self: *const Self) engine.air.component_prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return COUNT;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.source.log_size + 2;
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.split;
    }
    pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
        if (index >= COUNT) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
        return a.alloc(usize, 0);
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        const fixed = try a.alloc(u32, 0);
        errdefer a.free(fixed);
        const main = try a.alloc(u32, 0);
        errdefer a.free(main);
        const witness = try a.alloc(u32, META_COUNT);
        errdefer a.free(witness);
        @memset(witness, self.source.log_size);
        const interactions = try a.alloc(u32, INTER_COUNT);
        errdefer a.free(interactions);
        @memset(interactions, self.source.log_size);
        return .initOwned(try a.dupe([]u32, &.{ fixed, main, witness, interactions }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: core.circle.CirclePointQM31, max_log: u32) !core.air.components.MaskPoints {
        if (max_log < self.source.log_size) return error.InvalidCallerReadonlyMask;
        const prior = @import("../air/logup.zig").prevRowPoint(max_log, point);
        const fixed = try emptyMasks(a, 0);
        errdefer a.free(fixed);
        const main = try emptyMasks(a, 0);
        errdefer a.free(main);
        const witness = try emptyMasks(a, META_COUNT);
        errdefer {
            for (witness) |column| a.free(column);
            a.free(witness);
        }
        for (witness) |*column| try replace(a, column, &.{point});
        const interactions = try emptyMasks(a, INTER_COUNT);
        errdefer {
            for (interactions) |column| a.free(column);
            a.free(interactions);
        }
        for (interactions) |*column| try replace(a, column, &.{ point, prior });
        return .initOwned(try a.dupe([][]core.circle.CirclePointQM31, &.{ fixed, main, witness, interactions }));
    }
    /// Domain-only full view. These source samples are already declared by the
    /// existing ALL-RW access components; they are not new columns/openings.
    pub fn sourceMaskPoints(self: *const Self, a: std.mem.Allocator, point: core.circle.CirclePointQM31, max_log: u32) !core.air.components.MaskPoints {
        if (max_log < self.source.log_size) return error.InvalidCallerReadonlyMask;
        const prior = @import("../air/logup.zig").prevRowPoint(max_log, point);
        const lens = [_]usize{ self.source.fixed_logs.len, self.source.main_logs.len, self.source.witness_logs.?.len, self.source.interaction_logs.?.len };
        const trees = try a.alloc([][]core.circle.CirclePointQM31, 4);
        var initialized: usize = 0;
        errdefer {
            for (trees[0..initialized]) |tree| {
                for (tree) |column| a.free(column);
                a.free(tree);
            }
            a.free(trees);
        }
        for (lens, trees) |len, *tree| {
            tree.* = try emptyMasks(a, len);
            initialized += 1;
        }
        const d = self.source.external_source.?;
        if (d.kind == .sha) try replace(a, &trees[0][d.fixed_offset], &.{point});
        const keccak = @import("../air/guest_precompile/keccakf_trace.zig");
        const caller_width: usize = switch (d.kind) {
            .sha => @import("../air/guest_precompile/sha256_memory_caller.zig").PHYSICAL_MAIN_COLUMN_COUNT,
            .signer => @import("../air/guest_precompile/secp256k1_recovery_caller.zig").Layout.main_columns,
            .keccak => @import("../air/guest_precompile/keccakf_caller.zig").Layout.main_columns,
        };
        const caller_offset = d.main_offset + (if (d.kind == .keccak) keccak.Layout.caller else @as(usize, 0));
        for (trees[1][caller_offset..][0..caller_width]) |*column| try replace(a, column, &.{point});
        if (d.kind == .keccak) {
            const output = point.add(@import("../air/logup.zig").liftPoint(canonic.CanonicCoset.new(d.log_size).coset_value.step).mulSigned(27));
            for (trees[1][d.main_offset + keccak.Layout.state + (d.slot - 1) * 32 ..][0..32]) |*column| try replace(a, column, &.{ point, output });
        }
        for (trees[2][self.source.witness_offset..][0..Integer.COLUMN_COUNT]) |*column| try replace(a, column, &.{point});
        for (trees[2][self.metadata_offset..][0..META_COUNT]) |*column| try replace(a, column, &.{point});
        for (trees[3][self.prefix_offset..][0..INTER_COUNT]) |*column| try replace(a, column, &.{ point, prior });
        return .initOwned(trees);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: core.circle.CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (max_log < self.source.log_size) return error.InvalidCallerReadonlyMask;
        const residuals = try self.evaluateMask(mask);
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.source.log_size).coset(), point.repeatedDouble(max_log - self.source.log_size)).inv();
        for (residuals) |residual| accumulator.accumulate(residual.mul(inverse));
    }
    pub fn evaluateMask(self: *const Self, mask: *const core.air.components.MaskValues) ![COUNT]Q {
        if (mask.items.len < 4) return error.InvalidCallerReadonlyMask;
        const pair = try sourcePair(self.source.external_source.?, mask);
        var witness: [Integer.COLUMN_COUNT]Q = undefined;
        var metadata: Metadata = undefined;
        var current: [INTER_COUNT]Q = undefined;
        var previous: [INTER_COUNT]Q = undefined;
        for (&witness, 0..) |*value, i| value.* = try cell(mask, 2, self.source.witness_offset + i, 0);
        for (&metadata, 0..) |*value, i| value.* = try cell(mask, 2, self.metadata_offset + i, 0);
        for (&current, &previous, 0..) |*value, *before, i| {
            value.* = try cell(mask, 3, self.prefix_offset + i, 0);
            before.* = try cell(mask, 3, self.prefix_offset + i, 1);
        }
        var shifts: [4]Q = undefined;
        const size = M.fromCanonical(@as(u32, 1) << @intCast(self.source.log_size));
        if (self.claim.readonly_count > size.toU32()) return error.InvalidCallerReadonlyClaim;
        for ([_]Q{ self.claim.mutable_sum, self.claim.classification_sum, self.claim.read_sum, Q.fromBase(M.fromCanonical(@intCast(self.claim.readonly_count))) }, &shifts) |sum, *out| out.* = try sum.divM31(size);
        return equations(pair, witness, metadata, current, previous, shifts, self.challenges);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const engine.air.component_prover.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator) !void {
        return @import("block_v5_caller_readonly_domain_v1.zig").evaluate(self, source, accumulator);
    }
};
fn emptyMasks(a: std.mem.Allocator, len: usize) ![][]core.circle.CirclePointQM31 {
    const result = try a.alloc([]core.circle.CirclePointQM31, len);
    var n: usize = 0;
    errdefer {
        for (result[0..n]) |column| a.free(column);
        a.free(result);
    }
    for (result) |*column| {
        column.* = try a.alloc(core.circle.CirclePointQM31, 0);
        n += 1;
    }
    return result;
}
fn replace(a: std.mem.Allocator, column: *[]core.circle.CirclePointQM31, points: []const core.circle.CirclePointQM31) !void {
    const next = try a.dupe(core.circle.CirclePointQM31, points);
    a.free(column.*);
    column.* = next;
}
fn cell(mask: *const core.air.components.MaskValues, tree: usize, column: usize, sample: usize) !Q {
    if (tree >= mask.items.len or column >= mask.items[tree].len or sample >= mask.items[tree][column].len) return error.InvalidCallerReadonlyMask;
    return mask.items[tree][column][sample];
}
pub fn sourcePair(d: @import("block_execution_external_trace_v2.zig").Descriptor, mask: *const core.air.components.MaskValues) !Pair {
    if (d.slot >= d.count() or (d.kind == .sha and d.slot < 2) or (d.kind != .sha and d.slot == 0)) return error.InvalidCallerReadonlySourceGeometry;
    const Source = @import("block_execution_external_access_bridge_v2.zig");
    switch (d.kind) {
        .sha => {
            var row: [@import("../air/guest_precompile/sha256_memory_caller.zig").PHYSICAL_MAIN_COLUMN_COUNT]Q = undefined;
            for (&row, 0..) |*v, i| v.* = try cell(mask, 1, d.main_offset + i, 0);
            return Source.shaPair(Q, &row, try cell(mask, 0, d.fixed_offset, 0), d.slot);
        },
        .signer => {
            var row: [@import("../air/guest_precompile/secp256k1_recovery_caller.zig").Layout.main_columns]Q = undefined;
            for (&row, 0..) |*v, i| v.* = try cell(mask, 1, d.main_offset + i, 0);
            return Source.signerPair(Q, &row, d.slot);
        },
        .keccak => {
            const Trace = @import("../air/guest_precompile/keccakf_trace.zig");
            var row: [@import("../air/guest_precompile/keccakf_caller.zig").Layout.main_columns]Q = undefined;
            for (&row, 0..) |*v, i| v.* = try cell(mask, 1, d.main_offset + Trace.Layout.caller + i, 0);
            var before: [32]Q = undefined;
            var after: [32]Q = undefined;
            for (&before, &after, 0..) |*v, *w, i| {
                v.* = try cell(mask, 1, d.main_offset + Trace.Layout.state + (d.slot - 1) * 32 + i, 0);
                w.* = try cell(mask, 1, d.main_offset + Trace.Layout.state + (d.slot - 1) * 32 + i, 1);
            }
            return Source.keccakPairFromWordBits(Q, &row, before, after, d.slot);
        },
    }
}
