//! Real-domain specialization of the unchanged original RAM equations.
//! Direct constraints stay in M31; only LogUp and random-power folding use QM31.
const core = @import("stwo_core");
const m31 = core.fields.m31;
const M = m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const V = m31.PackedM31;
const Ram = @import("block_v7_ram_component_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Halt = @import("block_v7_halt_algebra_v1.zig");
const Old = @import("block_v5_word_memory_protocol_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
/// Algebra adapter, not a different field or a trusted value conversion.
pub const Base = struct {
    value: V,
    pub inline fn zero() Base {
        return .{ .value = @splat(0) };
    }
    pub inline fn one() Base {
        return .{ .value = @splat(1) };
    }
    pub inline fn fromBase(value: M) Base {
        return .{ .value = m31.splatPacked(value) };
    }
    // The shared original word equations call this only for literal M31
    // constants. Externally supplied halt constants are checked by init().
    pub inline fn splat(value: Q) Base {
        return fromBase(value.tryIntoM31() catch unreachable);
    }
    pub inline fn add(a: Base, b: Base) Base {
        return .{ .value = m31.addPacked(a.value, b.value) };
    }
    pub inline fn sub(a: Base, b: Base) Base {
        return .{ .value = m31.subPacked(a.value, b.value) };
    }
    pub inline fn mul(a: Base, b: Base) Base {
        return .{ .value = m31.mulPacked(a.value, b.value) };
    }
    pub inline fn neg(a: Base) Base {
        return zero().sub(a);
    }
};
pub fn lift(comptime n: usize, values: [n]V) [n]P {
    var out: [n]P = undefined;
    for (&out, values) |*v, x| v.* = P.fromBase(x);
    return out;
}
fn wrap(comptime n: usize, values: [n]V) [n]Base {
    var out: [n]Base = undefined;
    for (&out, values) |*v, x| v.* = .{ .value = x };
    return out;
}
pub const Result = struct { direct: [Ram.DIRECT_COUNT]Base, interaction: [Ram.PLANES]P };
pub const Prepared = struct {
    domain: Ram.Spec.Domain,
    factor_range_pairs: bool,
    range_a: P,
    range_z: P,
    range_a2: P,
    range_az: P,
    range_z2: P,
    prior: [9]Base,
    first: [11]Base,
    last: [11]Base,
    halt: Halt.Constants(Base),
    incoming: P,
    normalized: [Ram.PLANES]P,
    pub fn init(domain: Ram.Spec.Domain) !Prepared {
        return initWithRangeFactoring(domain, false);
    }
    pub fn initWithRangeFactoring(domain: Ram.Spec.Domain, enabled: bool) !Prepared {
        var out: Prepared = undefined;
        out.domain = domain;
        out.factor_range_pairs = enabled;
        // Use the actual secure coefficient, including zero/nonunit cases.
        out.range_a = domain.packed_challenges.range16.powers[0];
        out.range_z = domain.packed_challenges.range16.z;
        out.range_a2 = out.range_a.mul(out.range_a);
        out.range_az = out.range_a.mul(out.range_z);
        out.range_z2 = out.range_z.mul(out.range_z);
        const prior = if (domain.claim.preceding) |p| Old.endpointTuple(p) else @as([9]M, @splat(M.zero()));
        for (&out.prior, prior) |*v, x| v.* = Base.fromBase(x);
        for (&out.first, Old.transitionTuple(domain.claim.first)) |*v, x| v.* = Base.fromBase(x);
        for (&out.last, Old.transitionTuple(domain.claim.last)) |*v, x| v.* = Base.fromBase(x);
        for (&out.halt.address, domain.halt.address) |*v, x| v.* = Base.fromBase(x.tryIntoM31() catch return error.InvalidV7BaseHaltConstant);
        for (&out.halt.clocks, domain.halt.clocks) |*row, values| {
            for (row, values) |*v, x| v.* = Base.fromBase(x.tryIntoM31() catch return error.InvalidV7BaseHaltConstant);
        }
        out.incoming = P.splat(domain.incoming);
        for (&out.normalized, domain.normalized) |*v, x| v.* = P.splat(x);
        return out;
    }
    pub fn evaluate(self: *const Prepared, fixed: [24]V, row: [88]V, previous: [88]V, current: [116]V, before: [116]V) Result {
        const base_fixed = Trace.fixedPoint(Base, wrap(24, fixed), self.domain.claim);
        const secure_fixed = Trace.fixedPoint(P, lift(24, fixed), self.domain.claim);
        return .{
            .direct = Ram.directEquations(Base, self.prior, self.first, self.last, self.halt, base_fixed, wrap(88, row), wrap(88, previous)),
            .interaction = if (self.factor_range_pairs) self.factoredInteractions(base_fixed, secure_fixed, row, previous, current, before) else R.interactionConstraints(P, Ram.PLANES, Ram.terms(P, self.domain.packed_challenges, self.incoming, secure_fixed, lift(88, row), lift(88, previous)), lift(116, current), lift(116, before), self.normalized),
        };
    }
    fn delta(self: *const Prepared, current: [116]V, before: [116]V, index: usize) P {
        return P.fromPartialEvals(lift(4, current[4 * index ..][0..4].*)).sub(P.fromPartialEvals(lift(4, before[4 * index ..][0..4].*))).add(self.normalized[index]);
    }
    fn factoredInteractions(self: *const Prepared, fixed: @import("../air/block/word_memory_lanes_v1.zig").Algebra(Base).Fixed, secure_fixed: @import("../air/block/word_memory_lanes_v1.zig").Algebra(P).Fixed, row: [88]V, previous: [88]V, current: [116]V, before: [116]V) [Ram.PLANES]P {
        var out: [Ram.PLANES]P = undefined;
        for (Ram.primaryTerms(P, self.domain.packed_challenges, self.incoming, secure_fixed, lift(88, row), lift(88, previous)), 0..) |term, i| out[i] = term.residual(self.delta(current, before, i));
        var count = Base.zero();
        const base_row = wrap(88, row);
        for (Ram.rangePairs(Base, fixed, base_row), 0..) |pair, i| {
            // d0*d1 = A²*x0*x1 - A*z*(x0+x1) + z².
            // Original weights are negative requests, so subtracting their
            // numerator adds A*(w0*x1+w1*x0)-z*(w0+w1).
            const product = pair.left.mul(pair.right);
            const sum = pair.left.add(pair.right);
            const weighted = pair.left_weight.mul(pair.right).add(pair.right_weight.mul(pair.left));
            const weights = pair.left_weight.add(pair.right_weight);
            const denominator = self.range_a2.mulBase(product.value).sub(self.range_az.mulBase(sum.value)).add(self.range_z2);
            const numerator = self.range_a.mulBase(weighted.value).sub(self.range_z.mulBase(weights.value));
            out[3 + i] = self.delta(current, before, 3 + i).mul(denominator).add(numerator);
            count = count.add(weights);
        }
        const rows = Ram.rows(Base, base_row);
        const initial = Ram.access(Base, fixed, rows, 0).gate().add(Ram.access(Base, fixed, rows, 1).gate());
        out[27] = self.delta(current, before, 27).sub(P.fromBase(initial.value));
        out[28] = self.delta(current, before, 28).sub(P.fromBase(count.value));
        return out;
    }
    pub fn fold(self: *const Prepared, fixed: [24]V, row: [88]V, previous: [88]V, current: [116]V, before: [116]V, powers: *const [161]P) P {
        const result = self.evaluate(fixed, row, previous, current, before);
        var sum = P.zero();
        for (result.direct, powers[0..Ram.DIRECT_COUNT]) |equation, power| sum = sum.add(power.mulBase(equation.value));
        for (result.interaction, powers[Ram.DIRECT_COUNT..]) |equation, power| sum = sum.add(equation.mul(power));
        return sum;
    }
};
