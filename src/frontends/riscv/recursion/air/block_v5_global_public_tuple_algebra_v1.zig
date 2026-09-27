//! Actual terminal/register public tuple arithmetic over raw byte inputs.
//! Decoding is deterministic PUBLIC admission, not a proved private decoder.
//! The caller must route every byte and each challenge from its true producer.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const VERSION: u32 = 1;
pub fn Word(comptime S: type) type {
    return [4]S;
}
pub fn Data(comptime S: type) type {
    return struct {
        initial_pc: Word(S),
        final_pc: Word(S),
        clock: Word(S),
        initial: [32]Word(S),
        final: [32]Word(S),
        clocks: [32]Word(S),
        completion_address: Word(S),
        decoded: [4]Word(S),
        first_cycle: [8]S,
        last_cycle: [8]S,
    };
}
pub fn Results(comptime S: type) type {
    return struct { native_compensation: S, register_compensation: S, program_boundary: S };
}
pub fn base(comptime S: type, value: u32) S {
    return S.fromBase(M.fromCanonical(value));
}
pub fn reconstruct(comptime S: type, bytes: Word(S)) S {
    var result = S.zero();
    for (bytes, 0..) |byte, part| result = result.add(byte.mul(base(S, @as(u32, 1) << @as(u5, @intCast(8 * part)))));
    return result;
}
fn inverse(comptime S: type, value: S) !S {
    if (S == core.fields.qm31.QM31) return value.inv();
    return value.inverse();
}
/// relations.combine is the original arity/order/z/alpha polynomial. There is
/// no relation-tag substitution and no M31 truncation of register word bytes.
pub fn evaluate(comptime S: type, data: Data(S), relations: anytype, local_zero: bool, terminal_fetch: bool) !Results(S) {
    const state = try relations.getExact(.registers_state);
    const memory = try relations.getExact(.memory_access);
    const program = try relations.getExact(.program_access);
    var result = Results(S){ .native_compensation = (try inverse(S, try state.combine(&.{ reconstruct(S, data.initial_pc), S.one() }))).sub((try inverse(S, try state.combine(&.{ reconstruct(S, data.final_pc), reconstruct(S, data.clock).add(S.one()) })))), .register_compensation = S.zero(), .program_boundary = S.zero() };
    for (@as(usize, if (local_zero) 1 else 0)..32) |index| {
        const initial_tuple = .{ S.zero(), base(S, @intCast(index)), S.zero() } ++ data.initial[index];
        const final_tuple = .{ S.zero(), base(S, @intCast(index)), reconstruct(S, data.clocks[index]) } ++ data.final[index];
        result.register_compensation = result.register_compensation.add((try inverse(S, try memory.combine(&initial_tuple)))).sub((try inverse(S, try memory.combine(&final_tuple))));
    }
    if (terminal_fetch) {
        var tuple: [5]S = undefined;
        tuple[0] = reconstruct(S, data.completion_address);
        for (data.decoded, tuple[1..]) |word, *value| value.* = reconstruct(S, word);
        result.program_boundary = (try inverse(S, try program.combine(&tuple))).neg();
    }
    return result;
}
/// Each byte remains an original public input. The carry is derived inside the
/// graph, then proved binary; no public/prover-selected carry is trusted. This
/// handles the full u64 wrap and rejects overflow instead of reducing modulo M31.
pub fn nextCycle(comptime S: type, sink: anytype, last: [8]S, next: [8]S) !void {
    const inverse_256 = try inverse(S, base(S, 256));
    var carry = S.one();
    for (last, next) |before, after| {
        carry = before.add(carry).sub(after).mul(inverse_256);
        try sink.zero(carry.mul(carry.sub(S.one())), error.UntrustedGlobalPublicCycleBoundary);
    }
    try sink.zero(carry, error.UntrustedGlobalPublicCycleBoundary);
}
pub fn initialCycle(comptime S: type, sink: anytype, first: [8]S) !void {
    for (first, 0..) |byte, part| try sink.zero(byte.sub(if (part == 0) S.one() else S.zero()), error.UntrustedGlobalPublicCycleBoundary);
}
pub fn registerContinuity(comptime S: type, sink: anytype, before: [32]Word(S), after: [32]Word(S)) !void {
    for (before, after) |left, right| for (left, right) |a, b| try sink.zero(a.sub(b), error.UntrustedGlobalPublicRegisterBoundary);
}
pub fn localZero(comptime S: type, sink: anytype, data: Data(S)) !void {
    for (data.initial[0] ++ data.final[0] ++ data.clocks[0]) |byte| try sink.zero(byte, error.UntrustedX0LocalPublicBoundary);
}
