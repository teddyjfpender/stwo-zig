//! Original public interval/read suppliers, not a scalar verified-sum surrogate.
//! Zero-counter poles retain original skip semantics through constrained gating.
const std = @import("std");
const core = @import("stwo_core");
const Plan = @import("../../prover/block_v5_readonly_input_plan_v1.zig");
const Protocol = @import("../../prover/block_v5_readonly_input_protocol_v1.zig");
const r = @import("composition_graph_recorder.zig");
pub const S = r.Scalar;
pub const Element = struct {
    z: S,
    alpha_powers: []const S,
    fn combine(self: Element, tuple: anytype) !S {
        if (tuple.len != self.alpha_powers.len) return error.InvalidReadonlyPublicProviders;
        var result = S.zero();
        for (tuple, self.alpha_powers) |value, power| result = result.add(power.mul(S.fromBase(value)));
        return result.sub(self.z);
    }
};
pub fn record(builder: *r.Builder, intervals: []const Plan.Interval, counters: []const S, enabled: []const S, classification: Element, read: Element, classification_sum: S, read_sum: S, readonly_count: S, events: u32) !void {
    if (events == 0 or events >= core.fields.m31.Modulus) return error.InvalidReadonlyPublicProviders;
    return recordDynamic(builder, intervals, counters, enabled, classification, read, classification_sum, read_sum, readonly_count, S.fromBase(core.fields.m31.M31.fromCanonical(events)));
}
pub fn recordDynamic(builder: *r.Builder, intervals: []const Plan.Interval, counters: []const S, enabled: []const S, classification: Element, read: Element, classification_sum: S, read_sum: S, readonly_count: S, events: S) !void {
    if (intervals.len == 0 or intervals.len != counters.len or intervals.len != enabled.len) return error.InvalidReadonlyPublicProviders;
    var mass = S.zero();
    var readonly_mass = S.zero();
    var classification_total = S.zero();
    var read_total = S.zero();
    for (intervals, counters, enabled) |interval, counter, active| {
        const inactive = S.one().sub(active);
        try builder.constrainZero(active.mul(inactive));
        try builder.constrainZero(counter.mul(inactive));
        // Counter+inactive is always nonzero in a valid public census. This
        // also constrains active iff counter is nonzero without zero inversion.
        try builder.constrainZero(counter.mul(counter.add(inactive).inverse()).sub(active));
        const denominator = try classification.combine(Protocol.intervalTuple(interval));
        const inverse = denominator.mul(active).add(inactive).inverse();
        classification_total = classification_total.add(counter.mul(inverse));
        mass = mass.add(counter);
        if (interval.readonly) {
            const input_denominator = try read.combine(Protocol.inputTuple(interval.lower * 4, interval.value));
            read_total = read_total.add(counter.mul(input_denominator.mul(active).add(inactive).inverse()));
            readonly_mass = readonly_mass.add(counter);
        }
    }
    try builder.constrainZero(mass.sub(events));
    try builder.constrainZero(readonly_mass.sub(readonly_count));
    try builder.constrainZero(classification_total.sub(classification_sum));
    try builder.constrainZero(read_total.sub(read_sum));
}
