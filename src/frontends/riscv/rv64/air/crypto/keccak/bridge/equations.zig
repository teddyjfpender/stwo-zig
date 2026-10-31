//! One degree-four authority for authenticated lane I/O, RAM and service calls.
const core = @import("stwo_core");
const V = @import("../../../evaluation.zig");
pub const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const keccak = @import("../equations.zig");
const ram = @import("../../../relations.zig");
pub const CallChallenges = struct {
    offset: Q,
    coefficients: [10]Q,
    pub fn draw(channel: anytype) CallChallenges {
        // This family cannot cancel against any structurally similar bus.
        channel.mixU32s(&.{ 0x4b43414c, 1, 10 });
        var result: CallChallenges = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*v| v.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: CallChallenges, tuple: *const [10]Q) Q {
        return self.denominatorFor(Q, tuple);
    }
    pub fn denominatorFor(self: CallChallenges, comptime F: type, tuple: *const [10]F) V.SecureFor(F) {
        return V.denominatorFor(F, self.offset, &self.coefficients, tuple, true);
    }
};
pub const Challenges = struct { io: keccak.Io, call: CallChallenges, ram: ram.Challenges, bytes: Q };
pub const Public = struct { calls: u32, first_id: u32 };
pub const Row = RowFor(Q);
pub fn RowFor(comptime F: type) type {
    return struct {
        const zero_header: [2]F = @splat(F.zero());
        previous_header: *const [2]F = &zero_header,
        fixed: *const [L.FIXED]F,
        main: *const [L.MAIN]F,
        previous_main: *const [L.PREVIOUS_MAIN]F,
    };
}
pub const Event = EventFor(Q);
pub fn EventFor(comptime F: type) type {
    return struct { coefficient: F, denominator: V.SecureFor(F) };
}
fn reconstructFor(comptime F: type, bytes: []const F) F {
    var result = F.zero();
    var factor: u32 = 1;
    for (bytes) |byte| {
        result = result.add(byte.mul(V.qFor(F, factor)));
        factor *= 256;
    }
    return result;
}
pub fn callTuple(row: Row) [10]Q {
    return callTupleFor(Q, row);
}
pub fn callTupleFor(comptime F: type, row: RowFor(F)) [10]F {
    var tuple: [10]F = undefined;
    tuple[0] = row.main[L.CALL_ID];
    tuple[1] = row.main[L.TICK];
    @memcpy(tuple[2..], row.main[L.POINTER..][0..8]);
    return tuple;
}
pub fn ioTuple(row: Row, after: bool) [11]Q {
    return ioTupleFor(Q, row, after);
}
pub fn ioTupleFor(comptime F: type, row: RowFor(F), after: bool) [11]F {
    var tuple: [11]F = undefined;
    tuple[0] = row.main[L.CALL_ID];
    tuple[1] = V.qFor(F, @intFromBool(after));
    tuple[2] = row.fixed[L.LANE];
    @memcpy(tuple[3..], row.main[if (after) L.AFTER else L.BEFORE..][0..8]);
    return tuple;
}
pub fn ramTuple(row: Row, after: bool) ram.Tuple {
    return ramTupleFor(Q, row, after);
}
pub fn ramTupleFor(comptime F: type, row: RowFor(F), after: bool) [ram.ARITY]F {
    var tuple: [ram.ARITY]F = @splat(F.zero());
    tuple[0] = F.one();
    @memcpy(tuple[1..9], row.main[L.ADDRESS..][0..8]);
    tuple[9] = row.main[if (after) L.TICK else L.PREVIOUS];
    @memcpy(tuple[10..18], row.main[if (after) L.AFTER else L.BEFORE..][0..8]);
    tuple[18] = F.one();
    tuple[19] = F.one();
    return tuple;
}
pub fn event(row: Row, ch: Challenges, index: usize) Event {
    return eventFor(Q, row, ch, index);
}
pub fn eventFor(comptime F: type, row: RowFor(F), ch: Challenges, index: usize) EventFor(F) {
    if (index < L.RANGE_COUNT) return .{ .coefficient = F.one(), .denominator = V.splatFor(F, ch.bytes).sub(V.liftFor(F, row.main[L.RANGE_COLUMNS[index]])) };
    const active = row.main[L.ACTIVE];
    return switch (index - L.RANGE_COUNT) {
        0 => .{ .coefficient = active.neg(), .denominator = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTupleFor(F, row, false), true) },
        1 => .{ .coefficient = active.neg(), .denominator = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTupleFor(F, row, true), true) },
        2 => .{ .coefficient = active, .denominator = ch.ram.denominatorFor(F, ramTupleFor(F, row, false)) },
        3 => .{ .coefficient = active.neg(), .denominator = ch.ram.denominatorFor(F, ramTupleFor(F, row, true)) },
        4 => .{ .coefficient = active.mul(row.fixed[L.GROUP_FIRST]).neg(), .denominator = ch.call.denominatorFor(F, &callTupleFor(F, row)) },
        else => unreachable,
    };
}
pub fn emit(row: Row, interaction: *const [L.BATCHES]Q, previous_final: Q, claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    return emitFor(Q, row, interaction, previous_final, claim, ch, public, sink);
}
pub fn emitFor(comptime F: type, row: RowFor(F), interaction: *const [L.BATCHES]V.SecureFor(F), previous_final: V.SecureFor(F), claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    const main = row.main;
    const active = main[L.ACTIVE];
    const id = main[L.CALL_ID];
    const previous_active = row.previous_header[0];
    const previous_id = row.previous_header[1];
    const group_first = row.fixed[L.GROUP_FIRST];
    const continuation = F.one().sub(group_first);
    const first_id = V.qFor(F, public.first_id);
    const last_id = V.qFor(F, public.first_id + public.calls - 1);
    sink.emit(active.mul(active.sub(F.one())));
    sink.emit(F.one().sub(row.fixed[L.COMPLETE_GROUP]).mul(active));
    sink.emit(row.fixed[L.FIRST].mul(active.sub(V.qFor(F, @intFromBool(public.calls != 0)))));
    sink.emit(continuation.mul(active.sub(previous_active)));
    sink.emit(continuation.mul(id.sub(previous_id)));
    sink.emit(group_first.sub(row.fixed[L.FIRST]).mul(F.one().sub(previous_active)).mul(active));
    sink.emit(group_first.sub(row.fixed[L.FIRST]).mul(previous_active.sub(active)).mul(previous_id.sub(last_id)));
    sink.emit(active.mul(id.sub(first_id).sub(row.fixed[L.CALL_INDEX])));
    sink.emit(F.one().sub(active).mul(id));
    for (main[L.CARRY..][0..7]) |v| sink.emit(v.mul(v.sub(F.one())));
    var pointer_low = F.zero();
    for (main[L.ALIGNED..][0..5], 0..) |v, i| {
        sink.emit(v.mul(v.sub(F.one())));
        pointer_low = pointer_low.add(v.mul(V.qFor(F, @as(u32, 8) << @as(u5, @intCast(i)))));
    }
    sink.emit(main[L.POINTER].sub(pointer_low));
    for (0..8) |i| {
        const incoming = if (i == 0) row.fixed[L.LANE].mul(V.qFor(F, 8)) else main[L.CARRY + i - 1];
        const outgoing = if (i == 7) F.zero() else main[L.CARRY + i];
        sink.emit(active.mul(main[L.POINTER + i].add(incoming).sub(main[L.ADDRESS + i]).sub(outgoing.mul(V.qFor(F, 256)))));
    }
    sink.emit(main[L.TICK].sub(reconstructFor(F, main[L.TICK_BYTES..][0..3])));
    sink.emit(main[L.PREVIOUS].sub(reconstructFor(F, main[L.PREVIOUS_BYTES..][0..3])));
    sink.emit(active.mul(main[L.TICK].sub(main[L.PREVIOUS]).sub(F.one()).sub(reconstructFor(F, main[L.GAP..][0..3]))));
    const repeated_arguments = active.mul(F.one().sub(group_first));
    for (0..L.PREVIOUS_MAIN) |i| sink.emit(repeated_arguments.mul(main[i].sub(row.previous_main[i])));
    const padding = F.one().sub(active);
    for (main[0..L.ACTIVE]) |v| sink.emit(padding.mul(v));
    for (0..L.BATCHES) |batch| {
        const a = eventFor(F, row, ch, 3 * batch);
        const b = eventFor(F, row, ch, 3 * batch + 1);
        const c = eventFor(F, row, ch, 3 * batch + 2);
        const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) V.mulBaseFor(F, V.splatFor(F, claim), row.fixed[L.FIRST]) else V.SecureFor(F).zero());
        const numerator = V.mulBaseFor(F, b.denominator, a.coefficient).mul(c.denominator).add(V.mulBaseFor(F, a.denominator, b.coefficient).mul(c.denominator)).add(V.mulBaseFor(F, a.denominator, c.coefficient).mul(b.denominator));
        sink.emit(delta.mul(a.denominator).mul(b.denominator).mul(c.denominator).sub(numerator));
    }
}
