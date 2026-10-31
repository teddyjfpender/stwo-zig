//! One degree-four authority for authenticated lane I/O, RAM and service calls.
const Eval = @import("../../../evaluation.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const modular = @import("../equations.zig");
const P = @import("../program.zig");
pub const PacketFormat = @import("../../../../execution_profile.zig").SecpPacketFormat;
const ram = @import("../../../relations.zig");
pub const CallChallenges = struct {
    offset: Q,
    coefficients: [11]Q,
    pub fn draw(channel: anytype) CallChallenges {
        // This family cannot cancel against any structurally similar bus.
        channel.mixU32s(&.{ 0x5343414c, 1, 11 });
        var result: CallChallenges = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*v| v.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: CallChallenges, tuple: *const [11]Q) Q {
        var d = self.offset;
        for (tuple, self.coefficients) |v, c| d = d.sub(v.mul(c));
        return d;
    }
};
pub const Challenges = struct { wire: modular.Wire, call: CallChallenges, ram: ram.Challenges, bytes: Q };
pub const Public = struct { calls: u32, first_id: u32 };
pub const Row = RowFor(Q);
pub fn RowFor(comptime F: type) type {
    return struct {
        packet_format: PacketFormat = .big_endian_bytes_v1,
        previous_header: *const [2]F = &@as([2]F, @splat(F.zero())),
        fixed: *const [L.FIXED]F,
        main: *const [L.MAIN]F,
        previous_main: *const [L.PREVIOUS_MAIN]F,
    };
}
pub const Event = EventFor(Q);
pub fn EventFor(comptime F: type) type {
    return struct { coefficient: F, denominator: Eval.SecureFor(F) };
}
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
fn reconstruct(bytes: []const Q) Q {
    return reconstructFor(Q, bytes);
}
fn reconstructFor(comptime F: type, bytes: []const F) F {
    var result = F.zero();
    var factor: u32 = 1;
    for (bytes) |byte| {
        result = result.add(byte.mul(Eval.qFor(F, factor)));
        factor *= 256;
    }
    return result;
}
pub fn callTuple(program: *const P.Program, row: Row) [11]Q {
    return callTupleFor(Q, program, row);
}
pub fn callTupleFor(comptime F: type, program: *const P.Program, row: RowFor(F)) [11]F {
    var tuple: [11]F = undefined;
    tuple[0] = Eval.qFor(F, @intFromEnum(program.kind));
    tuple[1] = row.main[L.CALL_ID];
    tuple[2] = row.main[L.TICK];
    @memcpy(tuple[3..], row.main[L.POINTER..][0..8]);
    return tuple;
}
pub fn wireTuple(program: *const P.Program, row: Row, after: bool) [35]Q {
    return wireTupleFor(Q, program, row, after);
}
pub fn wireTupleFor(comptime F: type, program: *const P.Program, row: RowFor(F), after: bool) [35]F {
    var tuple: [35]F = undefined;
    tuple[0] = Eval.qFor(F, @intFromEnum(program.kind));
    tuple[1] = row.main[L.CALL_ID];
    tuple[2] = row.fixed[if (after) L.OUTPUT_WIRE else L.COORD];
    // The immutable service profile selects a fixed byte permutation to LE.
    for (tuple[3..], 0..) |*v, i| v.* = row.main[@as(usize, if (after) L.AFTER else L.BEFORE) + (if (row.packet_format == .big_endian_bytes_v1) 31 - i else i)];
    return tuple;
}
pub fn ramTuple(row: Row, after: bool, lane: usize) ram.Tuple {
    return ramTupleFor(Q, row, after, lane);
}
pub fn ramTupleFor(comptime F: type, row: RowFor(F), after: bool, lane: usize) [20]F {
    var tuple: [20]F = @splat(F.zero());
    tuple[0] = F.one();
    @memcpy(tuple[1..9], row.main[L.ADDRESS..][0..8]);
    tuple[1] = tuple[1].add(Eval.qFor(F, @intCast(8 * lane)));
    tuple[9] = row.main[if (after) L.TICK else L.PREVIOUS + lane];
    @memcpy(tuple[10..18], row.main[@as(usize, if (after) L.AFTER else L.BEFORE) + 8 * lane ..][0..8]);
    tuple[18] = F.one();
    tuple[19] = row.main[L.WRITABLE + lane];
    return tuple;
}
pub fn event(program: *const P.Program, row: Row, ch: Challenges, index: usize) Event {
    return eventFor(Q, program, row, ch, index);
}
pub fn eventFor(comptime F: type, program: *const P.Program, row: RowFor(F), ch: Challenges, index: usize) EventFor(F) {
    const S = Eval.SecureFor(F);
    if (index >= L.EVENTS) return .{ .coefficient = F.zero(), .denominator = S.one() };
    if (index < L.RANGE_COUNT) return .{ .coefficient = F.one(), .denominator = Eval.splatFor(F, ch.bytes).sub(Eval.liftFor(F, row.main[L.RANGE_COLUMNS[index]])) };
    const active = row.main[L.ACTIVE];
    const local = index - L.RANGE_COUNT;
    if (local == 0) return .{ .coefficient = active, .denominator = Eval.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &wireTupleFor(F, program, row, false), true) };
    if (local == 1) return .{ .coefficient = active.mul(row.fixed[L.IS_OUTPUT]).neg(), .denominator = Eval.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &wireTupleFor(F, program, row, true), true) };
    if (local < 10) return .{ .coefficient = if (local % 2 == 0) active else active.neg(), .denominator = Eval.denominatorFor(F, ch.ram.offset, &ch.ram.coefficients, &ramTupleFor(F, row, local % 2 != 0, (local - 2) / 2), false) };
    return .{ .coefficient = active.mul(row.fixed[L.GROUP_FIRST]).neg(), .denominator = Eval.denominatorFor(F, ch.call.offset, &ch.call.coefficients, &callTupleFor(F, program, row), true) };
}
pub fn emit(program: *const P.Program, row: Row, interaction: *const [L.BATCHES]Q, previous_final: Q, claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    emitGeneric(Q, program, row, interaction, previous_final, claim, ch, public, sink);
}
pub fn emitGeneric(comptime F: type, program: *const P.Program, row: RowFor(F), interaction: *const [L.BATCHES]Eval.SecureFor(F), previous_final: Eval.SecureFor(F), claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    const main = row.main;
    const active = main[L.ACTIVE];
    const id = main[L.CALL_ID];
    const previous_active = row.previous_header[0];
    const previous_id = row.previous_header[1];
    const group_first = row.fixed[L.GROUP_FIRST];
    const continuation = F.one().sub(group_first);
    const first_id = Eval.qFor(F, public.first_id);
    const last_id = Eval.qFor(F, public.first_id + public.calls - 1);
    sink.emit(active.mul(active.sub(F.one())));
    sink.emit(F.one().sub(row.fixed[L.COMPLETE_GROUP]).mul(active));
    sink.emit(row.fixed[L.FIRST].mul(active.sub(Eval.qFor(F, @intFromBool(public.calls != 0)))));
    sink.emit(continuation.mul(active.sub(previous_active)));
    sink.emit(continuation.mul(id.sub(previous_id)));
    sink.emit(group_first.sub(row.fixed[L.FIRST]).mul(F.one().sub(previous_active)).mul(active));
    sink.emit(group_first.sub(row.fixed[L.FIRST]).mul(previous_active.sub(active)).mul(previous_id.sub(last_id)));
    sink.emit(active.mul(id.sub(first_id).sub(row.fixed[L.CALL_INDEX])));
    sink.emit(F.one().sub(active).mul(id));
    for (main[L.CARRY..][0..7]) |v| sink.emit(v.mul(v.sub(F.one())));
    var pointer_low = F.zero();
    for (main[L.ALIGNED..][0..3], 0..) |v, i| {
        sink.emit(v.mul(v.sub(F.one())));
        pointer_low = pointer_low.add(v.mul(Eval.qFor(F, @as(u32, 32) << @as(u5, @intCast(i)))));
    }
    sink.emit(main[L.POINTER].sub(pointer_low));
    for (0..8) |i| {
        const incoming = if (i == 0) row.fixed[L.COORD].mul(Eval.qFor(F, 32)) else main[L.CARRY + i - 1];
        const outgoing = if (i == 7) F.zero() else main[L.CARRY + i];
        sink.emit(active.mul(main[L.POINTER + i].add(incoming).sub(main[L.ADDRESS + i]).sub(outgoing.mul(Eval.qFor(F, 256)))));
    }
    sink.emit(main[L.TICK].sub(reconstructFor(F, main[L.TICK_BYTES..][0..3])));
    for (0..4) |lane| {
        sink.emit(main[L.PREVIOUS + lane].sub(reconstructFor(F, main[L.PREVIOUS_BYTES + 3 * lane ..][0..3])));
        sink.emit(active.mul(main[L.TICK].sub(main[L.PREVIOUS + lane]).sub(F.one()).sub(reconstructFor(F, main[L.GAP + 3 * lane ..][0..3]))));
        const writable = main[L.WRITABLE + lane];
        sink.emit(writable.mul(writable.sub(F.one())));
        sink.emit(active.mul(row.fixed[L.IS_OUTPUT]).mul(writable.sub(F.one())));
    }
    for (0..32) |i| sink.emit(active.mul(F.one().sub(row.fixed[L.IS_OUTPUT])).mul(main[L.AFTER + i].sub(main[L.BEFORE + i])));
    const repeated_arguments = active.mul(F.one().sub(group_first));
    for (0..L.PREVIOUS_MAIN) |i| sink.emit(repeated_arguments.mul(main[i].sub(row.previous_main[i])));
    const padding = F.one().sub(active);
    for (main[0..L.ACTIVE]) |v| sink.emit(padding.mul(v));
    const S = Eval.SecureFor(F);
    for (0..L.BATCHES) |batch| {
        const a = eventFor(F, program, row, ch, 3 * batch);
        const b = eventFor(F, program, row, ch, 3 * batch + 1);
        const c = eventFor(F, program, row, ch, 3 * batch + 2);
        const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) Eval.mulBaseFor(F, Eval.splatFor(F, claim), row.fixed[L.FIRST]) else S.zero());
        const numerator = Eval.mulBaseFor(F, b.denominator.mul(c.denominator), a.coefficient).add(Eval.mulBaseFor(F, a.denominator.mul(c.denominator), b.coefficient)).add(Eval.mulBaseFor(F, a.denominator.mul(b.denominator), c.coefficient));
        sink.emit(delta.mul(a.denominator).mul(b.denominator).mul(c.denominator).sub(numerator));
    }
}
