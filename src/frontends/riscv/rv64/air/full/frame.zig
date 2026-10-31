//! Full-execution control frame. Only index/first/last are preprocessing;
//! decode advice is authenticated against the immutable compact program ROM.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../evaluation.zig");
const L = E.L;
const Q = E.Q;
const compact = @import("../program/compact.zig");
const rom = @import("../program/setup.zig");
pub const ACTIVE = 0;
pub const SELECTORS = ACTIVE + 1;
pub const ENTRY = SELECTORS + L.fixed.OPCODES;
pub const NEXT_PC = ENTRY + compact.COUNT;
pub const WIDTH = NEXT_PC + 8;
pub const FIXED = 3;
pub const KECCAK_COUNT = WIDTH;
pub const SERVICE_FLAGS = WIDTH + 1;
pub const SECP_COUNTERS = WIDTH + 4;
pub fn width(profile: @import("../../execution_profile.zig").Profile) usize {
    return switch (profile) {
        .rv64im => WIDTH,
        .keccak_service_v1 => WIDTH + 1,
        .ethereum_services_v1, .ethereum_services_v2 => WIDTH + 6,
    };
}
pub const Advice = [WIDTH]Q;
pub const Geometry = [FIXED]Q; // index, first, last
pub const Public = struct {
    steps: u32,
    initial_pc: u64,
    final_pc: u64,
    pub fn validate(self: Public, log_size: u32) !void {
        if (log_size < 5 or log_size > 22 or self.steps == 0 or self.steps > (@as(u32, 1) << @intCast(log_size))) return error.InvalidRv64FullGeometry;
    }
};
/// Boundary publics as a component lane stores them: native integers for the
/// QM31 family, lane wires (steps, little-endian PC bytes) for an external lane.
pub fn PublicFor(comptime Lane: type) type {
    if (E.isExternalLane(Lane)) return struct { steps: Lane, initial_pc: [8]Lane, final_pc: [8]Lane };
    return Public;
}
pub inline fn stepsFor(comptime F: type, public: PublicFor(E.ConstFor(F))) F {
    if (comptime E.isExternalLane(F)) return public.steps;
    return E.qFor(F, public.steps);
}
pub inline fn pcByteFor(comptime F: type, public: PublicFor(E.ConstFor(F)), comptime final: bool, index: usize) F {
    if (comptime E.isExternalLane(F)) return (if (final) public.final_pc else public.initial_pc)[index];
    const pc = if (final) public.final_pc else public.initial_pc;
    return E.qFor(F, @intCast((pc >> @as(u6, @intCast(8 * index))) & 255));
}
pub fn needsPrevious(column: usize) bool {
    return column == ACTIVE or (column >= NEXT_PC and column < NEXT_PC + 8);
}
pub fn entry(advice: *const Advice) compact.Tuple {
    return entryFor(Q, advice);
}
pub fn entryFor(comptime F: type, advice: *const [WIDTH]F) [compact.COUNT]F {
    return advice[ENTRY..][0..compact.COUNT].*;
}
pub fn inflate(advice: *const Advice, geometry: Geometry) E.Fixed {
    return inflateFor(Q, advice, geometry);
}
pub fn inflateFor(comptime F: type, advice: *const [WIDTH]F, geometry: [FIXED]F) E.FixedFor(F) {
    const tuple = entryFor(F, advice);
    const selectors = advice[SELECTORS..][0..L.fixed.OPCODES].*;
    var fixed = compact.inflateFixedFor(F, &tuple, &selectors);
    fixed[L.fixed.active] = advice[ACTIVE];
    fixed[L.fixed.first] = geometry[1];
    fixed[L.fixed.last] = geometry[2];
    @memcpy(fixed[L.fixed.next_pc..][0..8], advice[NEXT_PC..][0..8]);
    for (0..4) |slot| fixed[L.fixed.tick_start + slot] = geometry[0].mul(E.qFor(F, 4)).add(E.qFor(F, @intCast(slot + 1))).mul(fixed[L.fixed.slot_start + slot]);
    return fixed;
}
pub fn evaluate(advice: *const Advice, previous: *const Advice, geometry: Geometry, public: Public, log_size: u32, out: *E.Sink) void {
    return evaluateFor(Q, advice, previous, geometry, public, log_size, out);
}
pub fn evaluateFor(comptime F: type, advice: *const [WIDTH]F, previous: *const [WIDTH]F, geometry: [FIXED]F, public: PublicFor(E.ConstFor(F)), log_size: u32, out: *E.SinkFor(F)) void {
    const one = F.one();
    const active = advice[ACTIVE];
    const prior = previous[ACTIVE];
    const index = geometry[0];
    const first = geometry[1];
    const last = geometry[2];
    const nonfirst = one.sub(first);
    E.booleanFor(F, out, active);
    out.emit(first.mul(active.sub(one)));
    out.emit(nonfirst.mul(one.sub(prior)).mul(active));
    out.emit(nonfirst.mul(prior.sub(active)).mul(index.sub(stepsFor(F, public))));
    out.emit(last.mul(active).mul(stepsFor(F, public).sub(E.qFor(F, @as(u32, 1) << @intCast(log_size)))));
    const tuple = entryFor(F, advice);
    const expanded = compact.expandFor(F, &tuple);
    out.emit(expanded[rom.field.valid].sub(active));
    const selectors = advice[SELECTORS..][0..L.fixed.OPCODES].*;
    compact.evaluateSelectorsFor(F, &tuple, &selectors, out);
    // No disabled decode advice can create state events or arithmetic enables.
    for (compact.fields, 0..) |source, c| {
        if (source >= rom.field.pc and source < rom.field.pc + 8) continue;
        out.emit(one.sub(active).mul(tuple[c]));
    }
    for (0..8) |i| {
        const pc = expanded[rom.field.pc + i];
        const next = advice[NEXT_PC + i];
        const initial_byte = pcByteFor(F, public, false, i);
        const final_byte = pcByteFor(F, public, true, i);
        out.emit(first.mul(pc.sub(initial_byte)));
        out.emit(nonfirst.mul(pc.sub(previous[NEXT_PC + i])));
        out.emit(one.sub(active).mul(next.sub(pc)));
        out.emit(last.mul(next.sub(final_byte)));
    }
}
pub fn fixedColumns(a: std.mem.Allocator, log_size: u32) ![]M {
    try (Public{ .steps = 1, .initial_pc = 0, .final_pc = 0 }).validate(log_size);
    const size = @as(usize, 1) << @intCast(log_size);
    const values = try a.alloc(M, FIXED * size);
    @memset(values, M.zero());
    for (0..size) |i| {
        const row = @import("../witness.zig").physical(i, log_size);
        values[row] = M.fromCanonical(@intCast(i));
        values[size + row] = M.fromCanonical(@intFromBool(i == 0));
        values[2 * size + row] = M.fromCanonical(@intFromBool(i + 1 == size));
    }
    return values;
}
/// Capture supplies exact independently decoded ROM rows; projection does not
/// consult a public PC schedule and never executes the instruction here.
pub fn fromRow(row: *const rom.Row, next_pc: u64, active: bool) Advice {
    const base = fromRowBase(row, next_pc, active);
    var advice: Advice = undefined;
    for (&advice, base) |*value, source| value.* = Q.fromBase(source);
    return advice;
}
/// Native witness values remain M31 until polynomial evaluation requires QM31.
pub fn fromRowBase(row: *const rom.Row, next_pc: u64, active: bool) [WIDTH]M {
    var advice: [WIDTH]M = @splat(M.zero());
    advice[ACTIVE] = M.fromCanonical(@intFromBool(active));
    if (active) {
        advice[SELECTORS + row[rom.field.opcode].v] = M.one();
        for (compact.fields, 0..) |source, c| advice[ENTRY + c] = row[source];
    } else {
        for (compact.fields, 0..) |source, c| {
            if (source >= rom.field.pc and source < rom.field.pc + 8) advice[ENTRY + c] = M.fromCanonical(@intCast((next_pc >> @as(u6, @intCast(8 * (source - rom.field.pc)))) & 255));
        }
    }
    for (0..8) |i| advice[NEXT_PC + i] = M.fromCanonical(@intCast((next_pc >> @as(u6, @intCast(i * 8))) & 255));
    return advice;
}

test "full control frame proves exact active prefix and PC adjacency" {
    const public = Public{ .steps = 5, .initial_pc = 0x1000, .final_pc = 0x1014 };
    var previous: Advice = @splat(Q.zero());
    var output: [256]Q = undefined;
    for (0..32) |i| {
        const pc: u64 = if (i < 5) 0x1000 + 4 * i else 0x1014;
        const next: u64 = if (i < 5) pc + 4 else pc;
        const row = rom.deriveRow(pc, 0x00108093); // addi x1,x1,1
        const advice = fromRow(&row, next, i < 5);
        const geometry: Geometry = .{ E.q(@intCast(i)), E.q(@intFromBool(i == 0)), E.q(@intFromBool(i == 31)) };
        var sink = E.Sink{ .values = &output };
        evaluate(&advice, &previous, geometry, public, 5, &sink);
        for (output[0..sink.count]) |residual| try std.testing.expect(residual.isZero());
        if (i == 2) {
            var forged = advice;
            forged[NEXT_PC] = forged[NEXT_PC].add(Q.one());
            var next_advice = advice;
            const next_row = rom.deriveRow(pc + 4, 0x00108093);
            next_advice = fromRow(&next_row, pc + 8, true);
            sink.count = 0;
            evaluate(&next_advice, &forged, .{ E.q(3), Q.zero(), Q.zero() }, public, 5, &sink);
            var rejected = false;
            for (output[0..sink.count]) |residual| rejected = rejected or !residual.isZero();
            try std.testing.expect(rejected);
        }
        previous = advice;
    }
    const row = rom.deriveRow(0x1004, 0x00108093);
    const advice = fromRow(&row, 0x1008, true);
    const disabled: Advice = @splat(Q.zero());
    var sink = E.Sink{ .values = &output };
    evaluate(&advice, &disabled, .{ E.q(1), Q.zero(), Q.zero() }, public, 5, &sink);
    var rejected = false;
    for (output[0..sink.count]) |residual| rejected = rejected or !residual.isZero();
    try std.testing.expect(rejected);
}

// Versioned compact control wrappers; legacy entry points above stay byte-exact.
const Control = @import("../control_policy.zig").Policy;
const packed_frame = @import("packed_frame.zig");
pub fn bodyWidth(control: Control) usize {
    return if (control == .bytes_v1) WIDTH else packed_frame.WIDTH;
}
pub fn widthWithControl(profile: @import("../../execution_profile.zig").Profile, control: Control) usize {
    return bodyWidth(control) + width(profile) - WIDTH;
}
pub fn nextPcStart(control: Control) usize {
    return if (control == .bytes_v1) NEXT_PC else packed_frame.NEXT_PC;
}
pub fn nextPcLen(control: Control) usize {
    return if (control == .bytes_v1) 8 else 3;
}
pub fn keccakCount(control: Control) usize {
    return bodyWidth(control);
}
pub fn serviceFlags(control: Control) usize {
    return bodyWidth(control) + 1;
}
pub fn secpCounters(control: Control) usize {
    return bodyWidth(control) + 4;
}
pub fn needsPreviousWithControl(column: usize, control: Control) bool {
    return column == ACTIVE or (column >= nextPcStart(control) and column < nextPcStart(control) + nextPcLen(control));
}
pub fn inflateWithControl(advice: []const Q, geometry: Geometry, control: Control) E.Fixed {
    return inflateWithControlFor(Q, advice, geometry, control);
}
pub fn inflateWithControlFor(comptime F: type, advice: []const F, geometry: [FIXED]F, control: Control) E.FixedFor(F) {
    return if (control == .bytes_v1) inflateFor(F, advice[0..WIDTH], geometry) else packed_frame.inflateFor(F, advice, geometry);
}
pub fn evaluateWithControl(advice: []const Q, previous: []const Q, geometry: Geometry, public: Public, log_size: u32, control: Control, out: *E.Sink) void {
    return evaluateWithControlFor(Q, advice, previous, geometry, public, log_size, control, out);
}
pub fn evaluateWithControlFor(comptime F: type, advice: []const F, previous: []const F, geometry: [FIXED]F, public: PublicFor(E.ConstFor(F)), log_size: u32, control: Control, out: *E.SinkFor(F)) void {
    if (control == .bytes_v1) evaluateFor(F, advice[0..WIDTH], previous[0..WIDTH], geometry, public, log_size, out) else packed_frame.evaluateFor(F, advice, previous, geometry, public, log_size, out);
}
pub fn executionDenominatorWithControl(ch: @import("../program/provider.zig").Challenges, advice: []const Q, control: Control) Q {
    return executionDenominatorWithControlFor(Q, ch, advice, control);
}
pub fn executionDenominatorWithControlFor(comptime F: type, ch: @import("../program/provider.zig").ChallengesFor(E.ConstFor(F)), advice: []const F, control: Control) E.SecureFor(F) {
    return if (control == .bytes_v1) compact.executionDenominatorFor(F, ch, &entryFor(F, advice[0..WIDTH])) else @import("../program/packed_control.zig").executionDenominatorFor(F, ch, packed_frame.entryViewFor(F, advice));
}
pub fn fillFromRowBaseWithControl(out: []M, row: *const rom.Row, next_pc: u64, active: bool, control: Control) void {
    if (control == .bytes_v1) @memcpy(out[0..WIDTH], &fromRowBase(row, next_pc, active)) else packed_frame.fillFromRowBase(out, row, next_pc, active);
}
