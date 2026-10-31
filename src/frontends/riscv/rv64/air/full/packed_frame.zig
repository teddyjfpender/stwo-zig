//! Packed control framing. ROM membership authenticates canonical24/24/16
//! words; adjacency remains UNMASKED through padding to the public endpoint.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../evaluation.zig");
const L = E.L;
const Q = E.Q;
const P = @import("../program/packed_control.zig");
const rom = @import("../program/setup.zig");
const Frame = @import("frame.zig");
pub const ACTIVE = 0;
pub const SELECTORS = 1;
pub const ENTRY = SELECTORS + L.fixed.OPCODES;
pub const NEXT_PC = ENTRY + P.COUNT;
pub const WIDTH = NEXT_PC + 3;
pub const Advice = [WIDTH]Q;
pub fn entryView(advice: []const Q) *const P.Tuple {
    return entryViewFor(Q, advice);
}
pub fn entryViewFor(comptime F: type, advice: []const F) *const [P.COUNT]F {
    return advice[ENTRY..][0..P.COUNT];
}
pub fn entry(advice: []const Q) P.Tuple {
    return entryFor(Q, advice);
}
pub fn entryFor(comptime F: type, advice: []const F) [P.COUNT]F {
    return entryViewFor(F, advice).*;
}
pub fn inflate(advice: []const Q, geometry: Frame.Geometry) E.Fixed {
    return inflateFor(Q, advice, geometry);
}
pub fn inflateFor(comptime V: type, advice: []const V, geometry: [Frame.FIXED]V) E.FixedFor(V) {
    const tuple = entryViewFor(V, advice);
    const selectors = advice[SELECTORS..][0..L.fixed.OPCODES].*;
    var fixed = P.inflateFixedFor(V, tuple, &selectors);
    fixed[L.fixed.active] = advice[ACTIVE];
    fixed[L.fixed.first] = geometry[1];
    fixed[L.fixed.last] = geometry[2];
    for (0..4) |slot| fixed[L.fixed.tick_start + slot] = geometry[0].mul(E.qFor(V, 4)).add(E.qFor(V, @intCast(slot + 1))).mul(fixed[L.fixed.slot_start + slot]);
    return fixed;
}
pub fn evaluate(advice: []const Q, previous: []const Q, geometry: Frame.Geometry, public: Frame.Public, log_size: u32, out: *E.Sink) void {
    return evaluateFor(Q, advice, previous, geometry, public, log_size, out);
}
pub fn evaluateFor(comptime V: type, advice: []const V, previous: []const V, geometry: [Frame.FIXED]V, public: Frame.Public, log_size: u32, out: *E.SinkFor(V)) void {
    const one = V.one();
    const active = advice[ACTIVE];
    const prior = previous[ACTIVE];
    const index = geometry[0];
    const first = geometry[1];
    const last = geometry[2];
    const nonfirst = one.sub(first);
    E.booleanFor(V, out, active);
    out.emit(first.mul(active.sub(one)));
    out.emit(nonfirst.mul(one.sub(prior)).mul(active));
    out.emit(nonfirst.mul(prior.sub(active)).mul(index.sub(E.qFor(V, public.steps))));
    out.emit(last.mul(active).mul(E.qFor(V, public.steps).sub(E.qFor(V, @as(u32, 1) << @intCast(log_size)))));
    const tuple = entryViewFor(V, advice);
    out.emit(tuple[P.field.valid].sub(active));
    const selectors = advice[SELECTORS..][0..L.fixed.OPCODES].*;
    P.evaluateSelectorsFor(V, tuple, &selectors, out);
    for (0..P.COUNT) |i| {
        if (i >= P.field.pc and i < P.field.pc + 3) continue;
        out.emit(one.sub(active).mul(tuple[i]));
    }
    const initial = P.packFor(V, public.initial_pc);
    const final = P.packFor(V, public.final_pc);
    for (0..3) |i| {
        const pc = tuple[P.field.pc + i];
        const next = advice[NEXT_PC + i];
        out.emit(first.mul(pc.sub(initial[i])));
        out.emit(nonfirst.mul(pc.sub(previous[NEXT_PC + i])));
        out.emit(one.sub(active).mul(next.sub(pc)));
        out.emit(last.mul(next.sub(final[i])));
    }
}
pub fn fillFromRowBase(out: []M, row: *const rom.Row, next_pc: u64, active: bool) void {
    @memset(out[0..WIDTH], M.zero());
    out[ACTIVE] = M.fromCanonical(@intFromBool(active));
    if (active) {
        out[SELECTORS + row[rom.field.opcode].v] = M.one();
        const tuple = P.fromRowBase(row);
        @memcpy(out[ENTRY..][0..P.COUNT], &tuple);
    } else {
        const pc = P.packBase(next_pc);
        @memcpy(out[ENTRY + P.field.pc ..][0..3], &pc);
    }
    const next = P.packBase(next_pc);
    @memcpy(out[NEXT_PC..][0..3], &next);
}
