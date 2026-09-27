//! Stwo adapter for one opcode access slot. It declares the complete replayed
//! native fixed/main root geometry, then proves byte, carry, transition and
//! universal-range identities against the *same* opcode main openings.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const prover_component = engine.air.component_prover;
const domain_accumulation = engine.air.accumulation;
const support = @import("../air/memory_commitment/hash_component_prepared_support.zig");
const logup = @import("../air/logup.zig");
const opcode = @import("../runner/trace.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const range = @import("block_execution_byte_range_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const external = @import("block_execution_external_trace_v2.zig");
const external_bridge = @import("block_execution_external_access_bridge_v2.zig");
const keccak_trace = @import("../air/guest_precompile/keccakf_trace.zig");
const keccak_witness = @import("../air/guest_precompile/keccakf_witness.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
pub const eval = @import("block_execution_sidecar_stark_eval_v2.zig");
const v5_eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const universal_elements = @import("../recursion/air/universal_challenges.zig").Elements;
const quotient_cache = @import("block_v5_quotient_column_cache_v1.zig");

pub const Component = struct {
    /// Prover-only immutable main evaluations shared across access slots.
    /// Null on every verifier; never included in geometry or transcript.
    quotient_cache: ?*quotient_cache.Cache = null,
    family: opcode.OpcodeFamily,
    slot: usize,
    external_source: ?external.Descriptor = null,
    log_size: u32,
    base_clock: u64,
    /// Exact native root column-log roster. The enclosing verifier must pin
    /// both roots to its freshly verified typed native execution proof.
    fixed_logs: []const u32,
    main_logs: []const u32,
    witness_logs: ?[]const u32 = null,
    interaction_logs: ?[]const u32 = null,
    root_owner: bool = true,
    main_open_mask: ?[]const bool = null,
    fixed_open_mask: ?[]const bool = null,
    shared_keccak_state_offset: ?usize = null,
    main_offset: usize,
    witness_offset: usize = 0,
    interaction_offset: usize = 0,
    transition_claim: Q,
    transition_count: u64 = 0,
    range_claims: range.Claims,
    challenges: *const bus.Challenges,
    /// Opt-in v5 interaction over the same opened native opcode columns.
    /// Absent for every existing v2 proof and transcript.
    v5_universal: ?struct { claim: Q, elements: *const universal_elements } = null,

    /// Explicit packed transition ABI. Null preserves byte-v2 proof bytes.
    v5_packed: ?struct { elements: *const @import("block_v5_word_memory_protocol_v1.zig").Challenges } = null,
    register_custody_mode: u32 = 0,

    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, prover_component.ComponentProver, prover_component.Trace, domain_accumulation.DomainEvaluationAccumulator);
    pub fn init(self: Self) !Self {
        if (self.v5_packed != null and self.v5_universal == null) return error.InvalidPackedExecutionSidecar;
        if (self.register_custody_mode > 1 or (self.register_custody_mode == 1 and self.v5_packed == null)) return error.MixedV5OpcodeMemoryScope;
        const main_count = if (self.external_source) |descriptor| descriptor.mainWidth() else opcode.nColumnsForFamily(self.family);
        if (self.log_size == 0 or self.log_size + 2 >= circle.M31_CIRCLE_LOG_ORDER or
            self.main_offset + main_count > self.main_logs.len or
            self.slot >= (if (self.external_source) |descriptor| descriptor.count() else @import("block_execution_access_bridge_v2.zig").MAX_PAIRS))
            return error.InvalidExecutionSidecarGeometry;
        if (self.external_source) |descriptor| {
            if (descriptor.main_offset != self.main_offset or descriptor.slot != self.slot or descriptor.log_size != self.log_size or
                (descriptor.kind == .sha and descriptor.fixed_offset >= self.fixed_logs.len)) return error.InvalidExecutionSidecarGeometry;
        }
        for (self.main_logs[self.main_offset..][0..main_count]) |log_size|
            if (log_size != self.log_size) return error.InvalidExecutionSidecarGeometry;
        if (self.witness_logs) |logs| if (self.witness_offset + integer.COLUMN_COUNT > logs.len) return error.InvalidExecutionSidecarGeometry;
        if (self.interaction_logs) |logs| if (self.interaction_offset + interactionCount(&self) > logs.len) return error.InvalidExecutionSidecarGeometry;
        return self;
    }
    pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Self) usize {
        return if (self.v5_universal != null) v5_eval.CONSTRAINT_COUNT else eval.CONSTRAINT_COUNT;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Self) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 5;
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
        const fixed = try a.dupe(u32, if (self.root_owner) self.fixed_logs else &.{});
        errdefer a.free(fixed);
        const main = try a.dupe(u32, if (self.root_owner) self.main_logs else &.{});
        errdefer a.free(main);
        const witness = try filled(a, integer.COLUMN_COUNT, self.log_size);
        errdefer a.free(witness);
        const interaction = try filled(a, interactionCount(self), self.log_size);
        errdefer a.free(interaction);
        return components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, witness, interaction }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: circle.CirclePointQM31, max_log: u32) !components.MaskPoints {
        if (max_log < self.log_size) return error.InvalidExecutionSidecarMask;
        const previous = logup.prevRowPoint(max_log, point);
        // The replayed native trees contain other components at larger log
        // sizes. This quotient only opens the typed opcode columns it uses;
        // asking the PCS to lift every native column to this slot's domain is
        // invalid when an unrelated component has a larger trace.
        const fixed = try pointColumns(a, if (self.root_owner) self.fixed_logs.len else 0, &.{});
        errdefer freePoints(a, fixed);
        const main = try pointColumns(a, if (self.root_owner) self.main_logs.len else 0, &.{});
        errdefer freePoints(a, main);
        if (self.root_owner) {
            if (self.fixed_open_mask) |open_mask| {
                if (open_mask.len != fixed.len) return error.InvalidExecutionSidecarMask;
                for (fixed, open_mask) |*column, open| if (open) {
                    a.free(column.*);
                    column.* = try a.dupe(circle.CirclePointQM31, &.{point});
                };
            }
            if (self.main_open_mask) |open_mask| {
                if (open_mask.len != main.len) return error.InvalidExecutionSidecarMask;
                for (main, open_mask) |*column, open| if (open) {
                    a.free(column.*);
                    column.* = try a.dupe(circle.CirclePointQM31, &.{point});
                };
            } else for (main[self.main_offset..][0..(if (self.external_source) |descriptor| descriptor.mainWidth() else opcode.nColumnsForFamily(self.family))]) |*column| {
                a.free(column.*);
                column.* = try a.dupe(circle.CirclePointQM31, &.{point});
            }
            if (self.shared_keccak_state_offset) |state_offset| {
                if (state_offset + keccak_witness.state_cell_count > main.len) return error.InvalidExecutionSidecarMask;
                const output_point = point.add(logup.liftPoint(canonic.CanonicCoset.new(self.log_size).coset_value.step).mulSigned(27));
                for (main[state_offset..][0..keccak_witness.state_cell_count]) |*column| {
                    a.free(column.*);
                    column.* = try a.dupe(circle.CirclePointQM31, &.{ point, output_point });
                }
            }
        }
        const witness = try pointColumns(a, integer.COLUMN_COUNT, &.{point});
        errdefer freePoints(a, witness);
        const interaction = try pointColumns(a, interactionCount(self), &.{ point, previous });
        errdefer freePoints(a, interaction);
        return components.MaskPoints.initOwned(try a.dupe([][]circle.CirclePointQM31, &.{ fixed, main, witness, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        if (self.external_source) |descriptor| if (descriptor.kind == .sha) return a.dupe(usize, &.{descriptor.fixed_offset});
        // This component has no fixed-column identities. The native fixed
        // commitment is pinned by the verified execution proof; requesting
        // its unrelated high-log preprocessed openings would exceed this
        // sidecar's quotient domain.
        return a.alloc(usize, 0);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: circle.CirclePointQM31, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        const main_count = if (self.external_source) |descriptor| descriptor.mainWidth() else opcode.nColumnsForFamily(self.family);
        if (mask.items.len < 4 or max_log < self.log_size or
            mask.items[1].len < self.main_offset + main_count or
            mask.items[2].len < self.witness_offset + integer.COLUMN_COUNT or
            mask.items[3].len < self.interaction_offset + interactionCount(self))
            return error.InvalidExecutionSidecarMask;
        var witness: [integer.COLUMN_COUNT]Q = undefined;
        for (&witness, 0..) |*value, i| value.* = try pointAt(mask.items[2][self.witness_offset + i], 0);
        var interaction: [v5_eval.INTERACTION_COUNT]Q = undefined;
        var previous: [v5_eval.INTERACTION_COUNT]Q = undefined;
        for (0..interactionCount(self)) |i| {
            interaction[i] = try pointAt(mask.items[3][self.interaction_offset + i], 0);
            previous[i] = try pointAt(mask.items[3][self.interaction_offset + i], 1);
        }
        var residuals: [v5_eval.CONSTRAINT_COUNT]Q = undefined;
        if (self.v5_universal != null) {
            const pair = if (self.external_source) |descriptor|
                try externalPairAtPoint(descriptor, mask)
            else blk: {
                var main: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
                for (main[0..main_count], 0..) |*value, i| value.* = try pointAt(mask.items[1][self.main_offset + i], 0);
                const pairs = try @import("block_execution_access_bridge_v2.zig").fromCommittedMain(Q, self.family, main[0..main_count]);
                if (self.slot >= pairs.len) return error.InvalidExecutionSidecarSlot;
                break :blk try @import("block_execution_access_bridge_v2.zig").rwPairForMode(Q, self.family, self.slot, pairs.items[self.slot], self.register_custody_mode);
            };
            const current = try v5_eval.evaluatePair(self, pair, witness, interaction, previous);
            @memcpy(residuals[0..current.len], &current);
        } else {
            var old_interaction: [eval.INTERACTION_COUNT]Q = undefined;
            var old_previous: [eval.INTERACTION_COUNT]Q = undefined;
            @memcpy(&old_interaction, interaction[0..eval.INTERACTION_COUNT]);
            @memcpy(&old_previous, previous[0..eval.INTERACTION_COUNT]);
            const current = if (self.external_source) |descriptor|
                try eval.evaluatePair(self, try externalPairAtPoint(descriptor, mask), witness, old_interaction, old_previous)
            else blk: {
                var main: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
                for (main[0..main_count], 0..) |*value, i| value.* = try pointAt(mask.items[1][self.main_offset + i], 0);
                break :blk try eval.evaluateRow(self, main[0..main_count], witness, old_interaction, old_previous);
            };
            @memcpy(residuals[0..current.len], &current);
        }
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.log_size).coset(), point.repeatedDouble(max_log - self.log_size)).inv();
        for (residuals[0..self.nConstraints()]) |residual| accumulator.accumulate(residual.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const prover_component.Trace, accumulator: *domain_accumulation.DomainEvaluationAccumulator) !void {
        if (self.external_source != null) return evaluateExternalOnDomain(self, source, accumulator);
        const a = accumulator.allocator;
        if (source.polys.items.len != 4) return error.InvalidExecutionSidecarTrees;
        const trees = source.polys.items;
        const main_count = opcode.nColumnsForFamily(self.family);
        if (trees[1].len < self.main_offset + main_count or trees[2].len < self.witness_offset + integer.COLUMN_COUNT or trees[3].len < self.interaction_offset + interactionCount(self))
            return error.InvalidExecutionSidecarColumns;
        const eval_log = self.log_size + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        const count = main_count + integer.COLUMN_COUNT + interactionCount(self);
        const polys = try a.alloc(prover_component.Poly, count);
        defer a.free(polys);
        for (0..main_count) |i| polys[i] = trees[1][self.main_offset + i];
        for (0..integer.COLUMN_COUNT) |i| polys[main_count + i] = trees[2][self.witness_offset + i];
        for (0..interactionCount(self)) |i| polys[main_count + integer.COLUMN_COUNT + i] = trees[3][self.interaction_offset + i];
        var owned_count: usize = 0;
        const packed_support = @import("../recursion/air/universal_typed_component_contract.zig");
        for (polys) |poly| owned_count += @intFromBool(if (self.v5_packed != null)
            try packed_support.sourceNeedsExtension(poly, self.log_size, eval_log)
        else
            try support.sourceNeedsExtension(poly, self.log_size, eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        const values = try a.alloc([]const M, count);
        defer a.free(values);
        var twiddles: ?engine.poly.twiddles.TwiddleTree([]M) = if (owned.len != 0) try engine.poly.twiddles.precomputeM31(a, domain.half_coset) else null;
        defer if (twiddles) |*transform| engine.poly.twiddles.deinitM31(a, transform);
        const transform: ?engine.poly.twiddles.TwiddleTree([]const M) = if (twiddles) |t| .init(t.root_coset, t.twiddles, t.itwiddles) else null;
        // Packed v5 leases immutable native trees whose coefficients may be
        // released. Recover from the entire authenticated LDE, check its full
        // degree, and reuse the already-required quotient buffer.
        for (polys, values, 0..) |poly, *out, index| {
            if (index < main_count) if (self.quotient_cache) |cache| {
                if (try cache.get(if (self.v5_packed != null) .packed_word else .retained, poly, self.log_size, eval_log, transform)) |shared| {
                    out.* = shared;
                    continue;
                }
            };
            out.* = if (self.v5_packed != null)
                try packed_support.evaluationValues(a, poly, self.log_size, eval_log, eval_size, transform, owned, &initialized)
            else
                try support.evaluationValues(a, poly, eval_log, eval_size, owned, &initialized);
        }
        if (initialized != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, transform.?);
        var inverses: [4]M = undefined;
        const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
        for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, 2))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
        defer a.free(output);
        var result = output[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        for (0..eval_size) |row| {
            const prev_row = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
            var main: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            for (0..main_count) |i| main[i] = Q.fromBase(values[i][row]);
            var witness: [integer.COLUMN_COUNT]Q = undefined;
            for (0..integer.COLUMN_COUNT) |i| witness[i] = Q.fromBase(values[main_count + i][row]);
            var interaction: [v5_eval.INTERACTION_COUNT]Q = undefined;
            var previous: [v5_eval.INTERACTION_COUNT]Q = undefined;
            for (0..interactionCount(self)) |i| {
                interaction[i] = Q.fromBase(values[main_count + integer.COLUMN_COUNT + i][row]);
                previous[i] = Q.fromBase(values[main_count + integer.COLUMN_COUNT + i][prev_row]);
            }
            var residuals: [v5_eval.CONSTRAINT_COUNT]Q = undefined;
            if (self.v5_universal != null) {
                const pairs = try @import("block_execution_access_bridge_v2.zig").fromCommittedMain(Q, self.family, main[0..main_count]);
                if (self.slot >= pairs.len) return error.InvalidExecutionSidecarSlot;
                const pair = try @import("block_execution_access_bridge_v2.zig").rwPairForMode(Q, self.family, self.slot, pairs.items[self.slot], self.register_custody_mode);
                const current = try v5_eval.evaluatePair(self, pair, witness, interaction, previous);
                @memcpy(residuals[0..current.len], &current);
            } else {
                var old_interaction: [eval.INTERACTION_COUNT]Q = undefined;
                var old_previous: [eval.INTERACTION_COUNT]Q = undefined;
                @memcpy(&old_interaction, interaction[0..eval.INTERACTION_COUNT]);
                @memcpy(&old_previous, previous[0..eval.INTERACTION_COUNT]);
                const current = try eval.evaluateRow(self, main[0..main_count], witness, old_interaction, old_previous);
                @memcpy(residuals[0..current.len], &current);
            }
            var folded = Q.zero();
            const powers = result.random_coeff_powers;
            for (residuals[0..self.nConstraints()], 0..) |residual, index| folded = folded.add(powers[powers.len - 1 - index].mul(residual));
            result.accumulate(row, folded.mulM31(inverses[row >> shift]));
        }
    }
};

fn interactionCount(component: *const Component) usize {
    return if (component.v5_universal != null) v5_eval.INTERACTION_COUNT else eval.INTERACTION_COUNT;
}

fn filled(a: std.mem.Allocator, count: usize, value: u32) ![]u32 {
    const result = try a.alloc(u32, count);
    @memset(result, value);
    return result;
}
fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingExecutionSidecarPoint;
    return values[index];
}
fn pointColumns(a: std.mem.Allocator, count: usize, points: []const circle.CirclePointQM31) ![][]circle.CirclePointQM31 {
    const result = try a.alloc([]circle.CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| a.free(column);
        a.free(result);
    }
    for (result) |*column| {
        column.* = try a.dupe(circle.CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}
fn freePoints(a: std.mem.Allocator, columns: [][]circle.CirclePointQM31) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}

fn externalPairAtPoint(descriptor: external.Descriptor, mask: *const components.MaskValues) !@import("block_execution_access_bridge_v2.zig").Pair(Q) {
    const Samples = struct {
        mask: *const components.MaskValues,
        pub fn at(self: @This(), tree: usize, column: usize, ordinal: usize) !Q {
            if (tree >= self.mask.items.len or column >= self.mask.items[tree].len) return error.InvalidExternalAccessMask;
            return pointAt(self.mask.items[tree][column], ordinal);
        }
    };
    return @import("block_v5_caller_fused_algebra_v1.zig").externalPair(Q, descriptor, Samples{ .mask = mask });
}

fn evaluateExternalOnDomain(self: *const Component, source: *const prover_component.Trace, accumulator: *domain_accumulation.DomainEvaluationAccumulator) !void {
    return @import("block_execution_external_domain_v2.zig").evaluate(self, source, accumulator);
}

test "block-v2 sidecar adapter declares same-root opcode main and own witnesses" {
    const a = std.testing.allocator;
    const family: opcode.OpcodeFamily = .base_alu_imm;
    const main_logs = try filled(a, opcode.nColumnsForFamily(family), 1);
    defer a.free(main_logs);
    const sealed = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(81), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(a, sealed);
    const adapter = try (Component{
        .family = family,
        .slot = 0,
        .log_size = 1,
        .base_clock = 0,
        .fixed_logs = &.{},
        .main_logs = main_logs,
        .main_offset = 0,
        .transition_claim = Q.zero(),
        .range_claims = @splat(Q.zero()),
        .challenges = &challenges,
    }).init();
    try std.testing.expectEqual(@as(usize, 65), adapter.nConstraints());
    var bounds = try adapter.traceLogDegreeBounds(a);
    defer bounds.deinitDeep(a);
    try std.testing.expectEqual(@as(usize, 4), bounds.items.len);
    try std.testing.expectEqual(main_logs.len, bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, integer.COLUMN_COUNT), bounds.items[2].len);
    const zeros: [opcode.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
    const residuals = try eval.evaluateRow(&adapter, zeros[0..opcode.nColumnsForFamily(family)], @splat(Q.zero()), @splat(Q.zero()), @splat(Q.zero()));
    for (residuals) |residual| try std.testing.expect(residual.isZero());
}
