//! Exact real-domain terminal kernel plus BOTH nonterminal state-delta planes.
//! Random-power ordering remains original direct+29 interactions+2 deltas.
const core = @import("stwo_core");
const Base = @import("block_v7_ram_packed_base_v1.zig");
const Window = @import("block_v7_window_ram_component_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const P = core.fields.packed_qm31.PackedQM31;
const V = core.fields.m31.PackedM31;
pub const Prepared = struct {
    original: Base.Prepared,
    delta: R.Relation(P, 5),
    normalized: [2]P,
    pub fn initWithRangeFactoring(domain: Window.Spec.Domain, enabled: bool) !Prepared {
        return .{ .original = try Base.Prepared.initWithRangeFactoring(domain.original, enabled), .delta = domain.packed_delta, .normalized = .{ P.splat(domain.normalized[0]), P.splat(domain.normalized[1]) } };
    }
    pub fn fold(self: *const Prepared, fixed: [24]V, row: [88]V, previous: [88]V, current: [124]V, before: [124]V, powers: *const [163]P) P {
        var result = self.original.fold(fixed, row, previous, current[0..116].*, before[0..116].*, powers[0..161]);
        const state_delta = Window.deltaEquations(P, Trace.fixedPoint(P, Base.lift(24, fixed), self.original.domain.claim), Base.lift(88, row), Base.lift(8, current[116..124].*), Base.lift(8, before[116..124].*), self.delta, self.normalized);
        for (state_delta, powers[161..163]) |equation, power| result = result.add(equation.mul(power));
        return result;
    }
};
