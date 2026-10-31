//! One QM31 authority for the concrete paired permutation and its stitched LogUp.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
pub const BatchPolicy = @import("batch_policy.zig").Policy;
const L = @import("layout.zig");
const V = @import("../../evaluation.zig");
const tuples = @import("../../../../air/guest_precompile/keccakf_lookup_tuples.zig");
pub const Lookup = @import("../../providers/tables.zig").Challenges;
pub const Io = struct {
    offset: Q,
    coefficients: [L.IO_ARITY]Q,
    pub fn draw(channel: anytype) Io {
        var result: Io = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: Io, tuple: *const [L.IO_ARITY]Q) Q {
        var result = self.offset;
        for (tuple, self.coefficients) |value, coefficient| result = result.sub(value.mul(coefficient));
        return result;
    }
};
pub const Challenges = struct {
    chi: Lookup,
    xor5: Lookup,
    io: Io,
    pub fn draw(channel: anytype) Challenges {
        return .{ .chi = Lookup.draw(channel), .xor5 = Lookup.draw(channel), .io = Io.draw(channel) };
    }
};
pub const Public = struct { calls: u32, first_id: u32 };
const zero_header: [3]Q = @splat(Q.zero());
pub const Row = RowFor(Q);
pub fn RowFor(comptime F: type) type {
    return struct {
        const zeros: [3]F = @splat(F.zero());

        previous_header: *const [3]F = &zeros,
        fixed: *const [L.FIXED]F,
        main: *const [L.MAIN]F,
        state_minus_two: *const [L.STATE]F,
        state_minus_one: *const [L.STATE]F,
        state_plus_one: *const [L.STATE]F,
        state_plus_two: *const [L.STATE]F,
    };
}
pub fn lookupDenominator(row: Row, ch: Challenges, event: usize) Q {
    return lookupDenominatorFor(Q, row, ch, event);
}
pub fn lookupDenominatorFor(comptime F: type, row: RowFor(F), ch: Challenges, event: usize) V.SecureFor(F) {
    if (event < L.STATE) return V.denominatorFor(F, ch.chi.offset, &ch.chi.coefficients, &tuples.chi(F, row.main[0..L.STATE], row.main[L.STATE..L.ACTIVE_A], row.state_plus_one, row.fixed[2..26], event), true);
    return V.denominatorFor(F, ch.xor5.offset, &ch.xor5.coefficients, &tuples.xor5(F, row.main[0..L.STATE], row.main[L.STATE..L.ACTIVE_A], event - L.STATE), true);
}
pub fn ioTuple(row: Row, lane: usize) [L.IO_ARITY]Q {
    return ioTupleFor(Q, row, lane);
}
pub fn ioTupleFor(comptime F: type, row: RowFor(F), lane: usize) [L.IO_ARITY]F {
    var tuple: [L.IO_ARITY]F = undefined;
    tuple[0] = row.main[L.BASE_ID].add(row.fixed[1]).add(row.fixed[28]);
    tuple[1] = row.fixed[27].add(row.fixed[28]);
    tuple[2] = V.qFor(F, @intCast(lane));
    for (0..8) |byte| {
        var value = F.zero();
        for (0..8) |bit| value = value.add(row.main[64 * lane + 8 * byte + bit].mul(V.qFor(F, @as(u32, 1) << @as(u5, @intCast(bit)))));
        tuple[3 + byte] = value;
    }
    return tuple;
}
pub fn roundActive(row: Row) Q {
    return roundActiveFor(Q, row);
}
pub fn roundActiveFor(comptime F: type, row: RowFor(F)) F {
    var result = F.zero();
    for (row.fixed[2..26]) |s| result = result.add(s);
    return result.mul(row.main[L.ACTIVE_A]);
}
pub fn ioActive(row: Row) Q {
    return ioActiveFor(Q, row);
}
pub fn ioActiveFor(comptime F: type, row: RowFor(F)) F {
    return row.main[L.ACTIVE_A].mul(row.fixed[0].add(row.fixed[27])).add(row.main[L.ACTIVE_B].mul(row.fixed[1].add(row.fixed[28])));
}
/// Triple batching gives degree four. Cross-column stitching needs only the
/// final secure column at the predecessor point and one transcript-bound claim.
pub fn emit(row: Row, interaction: []const Q, previous_final: Q, claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    return emitFor(Q, row, interaction, previous_final, claim, ch, public, sink);
}
pub fn emitFor(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    return emitForBatch(F, 3, row, interaction, previous_final, claim, ch, public, sink);
}
pub fn emitForPolicy(comptime F: type, policy: BatchPolicy, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    switch (policy) {
        .triple_v2 => emitForBatch(F, 3, row, interaction, previous_final, claim, ch, public, sink),
        .quartet_v3 => emitForBatch(F, 4, row, interaction, previous_final, claim, ch, public, sink),
    }
}
pub fn emitForBatch(comptime F: type, comptime width: usize, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    const active = row.main[L.ACTIVE_A];
    const second = row.main[L.ACTIVE_B];
    const id = row.main[L.BASE_ID];
    const previous_active = row.previous_header[0];
    const previous_second = row.previous_header[1];
    const previous_id = row.previous_header[2];
    const phase_first = row.fixed[0];
    const continuation = F.one().sub(phase_first);
    const first_id = V.qFor(F, public.first_id);
    const last_id = V.qFor(F, public.first_id + public.calls - 1);
    sink.emit(active.mul(active.sub(F.one())));
    sink.emit(second.mul(second.sub(F.one())));
    sink.emit(second.mul(F.one().sub(active)));
    sink.emit(F.one().sub(row.fixed[L.COMPLETE_SLOT]).mul(active));
    sink.emit(row.fixed[L.FIRST].mul(active.sub(V.qFor(F, @intFromBool(public.calls != 0)))));
    sink.emit(continuation.mul(active.sub(previous_active)));
    sink.emit(continuation.mul(second.sub(previous_second)));
    sink.emit(continuation.mul(id.sub(previous_id)));
    sink.emit(phase_first.sub(row.fixed[L.FIRST]).mul(F.one().sub(previous_active)).mul(active));
    sink.emit(phase_first.mul(active).mul(previous_active.sub(previous_second)));
    sink.emit(phase_first.sub(row.fixed[L.FIRST]).mul(previous_active.sub(active)).mul(previous_id.add(previous_second).sub(last_id)));
    sink.emit(active.mul(id.sub(first_id).sub(row.fixed[L.SLOT_INDEX].mul(V.qFor(F, 2)))));
    sink.emit(F.one().sub(active).mul(id));
    const boundary = row.fixed[0].add(row.fixed[1]).add(row.fixed[27]).add(row.fixed[28]);
    for (0..L.STATE) |i| {
        const v = row.main[i];
        sink.emit(boundary.mul(active).mul(v.mul(F.one().sub(v))));
        const input = v.sub(row.state_minus_two[i]).sub(row.state_minus_one[i].mul(V.qFor(F, 8)));
        const output = v.sub(row.state_plus_one[i]).sub(row.state_plus_two[i].mul(V.qFor(F, 8)));
        sink.emit(row.fixed[2].mul(input).add(row.fixed[26].mul(output)));
    }
    const parity_zero = boundary.add(row.fixed[26]);
    for (row.main[L.STATE..L.ACTIVE_A]) |v| sink.emit(parity_zero.mul(v));
    const padding = F.one().sub(active);
    for (row.main[0..L.ACTIVE_A]) |v| sink.emit(padding.mul(v));
    if (comptime width == 3) {
        const coefficient = roundActiveFor(F, row).neg();
        for (0..L.LOOKUPS / 3) |batch| {
            const d0 = lookupDenominatorFor(F, row, ch, 3 * batch);
            const d1 = lookupDenominatorFor(F, row, ch, 3 * batch + 1);
            const d2 = lookupDenominatorFor(F, row, ch, 3 * batch + 2);
            const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) V.mulBaseFor(F, V.splatFor(F, claim), row.fixed[L.FIRST]) else V.SecureFor(F).zero());
            const numerator = V.mulBaseFor(F, d0.mul(d1).add(d0.mul(d2)).add(d1.mul(d2)), coefficient);
            sink.emit(delta.mul(d0).mul(d1).mul(d2).sub(numerator));
        }
        for (0..L.IO_BATCHES) |local| {
            const batch = L.LOOKUPS / 3 + local;
            var denominators: [3]V.SecureFor(F) = @splat(V.SecureFor(F).one());
            var coefficients: [3]F = @splat(F.zero());
            for (0..3) |i| if (3 * local + i < L.IO_LANES) {
                denominators[i] = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTupleFor(F, row, 3 * local + i), true);
                coefficients[i] = ioActiveFor(F, row);
            };
            const numerator = V.mulBaseFor(F, denominators[1], coefficients[0]).mul(denominators[2])
                .add(V.mulBaseFor(F, denominators[0], coefficients[1]).mul(denominators[2]))
                .add(V.mulBaseFor(F, denominators[0], coefficients[2]).mul(denominators[1]));
            sink.emit(interaction[batch].sub(interaction[batch - 1]).mul(denominators[0]).mul(denominators[1]).mul(denominators[2]).sub(numerator));
        }
    } else {
        const coefficient = roundActiveFor(F, row).neg();
        for (0..L.LOOKUPS / 4) |batch| {
            var d: [4]V.SecureFor(F) = undefined;
            for (&d, 0..) |*value, i| value.* = lookupDenominatorFor(F, row, ch, 4 * batch + i);
            const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) V.mulBaseFor(F, V.splatFor(F, claim), row.fixed[L.FIRST]) else V.SecureFor(F).zero());
            sink.emit(clearQuartetFor(F, true, d, @splat(coefficient), delta));
        }
        for (0..(L.IO_LANES + 3) / 4) |local| {
            const batch = L.LOOKUPS / 4 + local;
            var d: [4]V.SecureFor(F) = @splat(V.SecureFor(F).one());
            var c: [4]F = @splat(F.zero());
            for (0..4) |i| if (4 * local + i < L.IO_LANES) {
                d[i] = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTupleFor(F, row, 4 * local + i), true);
                c[i] = ioActiveFor(F, row);
            };
            sink.emit(clearQuartetFor(F, false, d, c, interaction[batch].sub(interaction[batch - 1])));
        }
    }
}

/// One quartet polynomial, including distinct IO weights and dummy entries.
/// Factoring changes neither the numerator nor the order of emitted residuals.
pub fn clearQuartetFor(comptime F: type, comptime same_coefficient: bool, d: [4]V.SecureFor(F), c: [4]F, delta: V.SecureFor(F)) V.SecureFor(F) {
    const p01 = d[0].mul(d[1]);
    const p23 = d[2].mul(d[3]);
    const numerator = if (same_coefficient)
        V.mulBaseFor(F, p01.mul(d[2].add(d[3])).add(p23.mul(d[0].add(d[1]))), c[0])
    else
        p23.mul(V.mulBaseFor(F, d[1], c[0]).add(V.mulBaseFor(F, d[0], c[1]))).add(p01.mul(V.mulBaseFor(F, d[3], c[2]).add(V.mulBaseFor(F, d[2], c[3]))));
    return delta.mul(p01).mul(p23).sub(numerator);
}
