//! The original G/XOR recursion-wire boundary, on the already committed
//! 192-byte capture main. Framing is proved by PAGE semantic arithmetic;
//! this component supplies all 32 inputs and consumes all 16 outputs.
//! No digest, default-frame, or source authority follows from this component.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Topology = @import("../recursion/air/blake3_compression_plan.zig");
pub const FIXED_COUNT: usize = 6;
pub const MAIN_COUNT: usize = 192;
pub const WIRE_COUNT: usize = 48;
pub const PAIRS: usize = WIRE_COUNT / 2;
pub const INTERACTION_COUNT: usize = 4 * PAIRS;
pub const CONSTRAINT_COUNT: usize = MAIN_COUNT + PAIRS;
pub const DEGREE: u32 = 3;
pub const EXPANSION_BITS: u32 = 2;
pub fn requestMass() u64 {
    var total: u64 = 16;
    for (Topology.canonical().uses[0..32]) |uses| total += uses;
    return total;
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Challenge = struct { z: S, powers: [6]S };
        pub const Term = struct { numerator: S, denominator: S };
        fn scalar(value: u32) S {
            if (S == core.fields.packed_qm31.PackedQM31) return S.fromBase(@splat(M.fromCanonical(value).v));
            return S.fromBase(M.fromCanonical(value));
        }
        pub fn terms(fixed: [FIXED_COUNT]S, main: [MAIN_COUNT]S, challenge: Self.Challenge) [WIRE_COUNT]Self.Term {
            const plan = Topology.canonical();
            var out: [WIRE_COUNT]Self.Term = undefined;
            for (&out, 0..) |*term, i| {
                const input = i < 32;
                const wire = if (input) @as(u32, @intCast(i)) else plan.output[i - 32];
                const values = [_]S{ fixed[1], scalar(wire) } ++ main[4 * i ..][0..4].*;
                var denominator = challenge.z.neg();
                for (values, challenge.powers) |value, power| denominator = denominator.add(value.mul(power));
                term.* = .{ .numerator = if (input) fixed[0].mul(scalar(plan.uses[i])) else fixed[0].neg(), .denominator = denominator };
            }
            return out;
        }
        pub fn constraints(fixed: [FIXED_COUNT]S, main: [MAIN_COUNT]S, current: [INTERACTION_COUNT]S, previous: [INTERACTION_COUNT]S, normalized: [PAIRS]S, challenge: Self.Challenge) [CONSTRAINT_COUNT]S {
            var out: [CONSTRAINT_COUNT]S = undefined;
            for (main, 0..) |value, i| out[i] = S.one().sub(fixed[0]).mul(value);
            const requests = terms(fixed, main, challenge);
            for (0..PAIRS) |i| {
                const left = requests[2 * i];
                const right = requests[2 * i + 1];
                const delta = S.fromPartialEvals(current[4 * i ..][0..4].*).sub(S.fromPartialEvals(previous[4 * i ..][0..4].*)).add(normalized[i]);
                out[MAIN_COUNT + i] = delta.mul(left.denominator).mul(right.denominator).sub(left.numerator.mul(right.denominator)).sub(right.numerator.mul(left.denominator));
            }
            return out;
        }
    };
}
pub fn degree(index: usize) !u8 {
    if (index >= CONSTRAINT_COUNT) return error.InvalidSourceBlakeCaptureConstraint;
    return if (index < MAIN_COUNT) 2 else 3;
}
comptime {
    if (@import("block_v5_memory_source_packed_blake_columns_v1.zig").CAPTURE_MAIN_COUNT != MAIN_COUNT or
        @import("block_v5_memory_source_packed_blake_columns_v1.zig").CAPTURE_FIXED_COUNT != FIXED_COUNT)
        @compileError("original packed BLAKE capture ABI drift");
}
