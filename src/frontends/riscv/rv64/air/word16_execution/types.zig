//! Arithmetic-lane constants only; no machine or prover factory.
const E = @import("../evaluation.zig");
const M = @import("stwo_core").fields.m31.M31;
pub const Q = E.Q;
pub const Boundary = @import("../word16_cpu/public.zig").Public;
pub const OwnerChallengesFor = @import("../memory/load_store_v2/types.zig").OwnerChallengesFor;
pub const OwnerChallenges = OwnerChallengesFor(Q);
pub fn InputsFor(comptime C: type) type {
    E.assertConstLane(C);
    return struct { steps: E.CountFor(C), initial_pc: [4]E.CountFor(C), final_pc: [4]E.CountFor(C), epoch: E.CountFor(C) };
}
pub const Inputs = InputsFor(Q);
pub fn validateInputs(public: Inputs, log: u32) !void {
    if (log < 5 or log > 22 or public.steps == 0 or public.steps >= @as(u32, 1) << @intCast(log) or public.epoch == 0 or public.epoch > 65535) return error.InvalidExecutionInputs;
    for (public.initial_pc ++ public.final_pc) |limb| if (limb > 65535) return error.InvalidExecutionInputs;
    if (public.initial_pc[0] & 3 != 0 or public.final_pc[0] & 3 != 0) return error.InvalidExecutionInputs;
}
pub fn inputs(boundary: Boundary, epoch: u16, log: u32) !Inputs {
    try boundary.validate(log);
    if (epoch == 0) return error.InvalidExecutionEpoch;
    var result = Inputs{ .steps = boundary.steps, .initial_pc = undefined, .final_pc = undefined, .epoch = epoch };
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        result.initial_pc[i] = @as(u16, @truncate(boundary.initial_pc >> shift));
        result.final_pc[i] = @as(u16, @truncate(boundary.final_pc >> shift));
    }
    try validateInputs(result, log);
    return result;
}
fn RelationFor(comptime C: type, comptime N: usize) type {
    return struct {
        offset: C,
        coefficients: [N]C,
        pub fn denominatorFor(self: @This(), comptime F: type, tuple: [N]F) E.SecureFor(F) {
            return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
        }
    };
}
pub fn FunctionChallengesFor(comptime C: type) type {
    return RelationFor(C, 13);
}
pub const FunctionChallenges = FunctionChallengesFor(Q);
pub fn RomChallengesFor(comptime C: type) type {
    return RelationFor(C, 30);
}
pub const RomChallenges = RomChallengesFor(Q);
fn RangeFor(comptime C: type) type {
    return struct {
        offset: C,
        coefficient: C,
        pub fn denominatorFor(self: @This(), comptime F: type, value: F) E.SecureFor(F) {
            return E.splatFor(F, self.offset).sub(E.mulBaseFor(F, E.splatFor(F, self.coefficient), value));
        }
    };
}
pub fn ChallengesFor(comptime C: type) type {
    E.assertConstLane(C);
    return struct { register: RelationFor(C, 6), function: FunctionChallengesFor(C), rom: RomChallengesFor(C), owner: OwnerChallengesFor(C), range16: RangeFor(C), range8: RangeFor(C) };
}
pub const Challenges = ChallengesFor(Q);
pub fn literal(comptime F: type, value: u32) F {
    return if (F == M) M.fromCanonical(value) else E.qFor(F, value);
}
