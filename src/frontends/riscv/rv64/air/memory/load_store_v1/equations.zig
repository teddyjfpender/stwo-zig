//! One arithmetic-lane authority for Word16 LS domain/OODS. Width/sign facts
//! come from the same immutable decode-derived specification as the legacy AIR.
const E = @import("../../evaluation.zig");
const R = @import("../closed_ram/equations.zig");
const Specs = @import("../../memory_constraints.zig");
const S = @import("../../providers/scalar_range.zig");
const Add = @import("../../word16_v1/word_add.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
pub const CONSTRAINTS = 280;
pub fn ownerTuple(comptime F: type, m: []const F) [21]F {
    var result: [21]F = undefined;
    result[0] = m[3];
    result[1] = m[L.opcode];
    @memcpy(result[2..18], m[L.a..][0..16]);
    result[18] = m[9];
    result[19] = m[12];
    result[20] = m[13];
    return result;
}
pub fn selectionTuple(comptime F: type, m: []const F) [5]F {
    var parity = F.zero();
    for ([_]usize{ 1, 3, 5, 7 }) |offset| parity = parity.add(m[L.offsets + offset]);
    return .{ m[L.selected_limb], parity, m[L.selected_byte], m[L.selected_sign], m[L.limb_sign] };
}
pub fn emitFor(comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    emitLocalFor(F, f, m, pm, rows, out);
    const one = F.one();
    const active = m[0];
    R.transitionRamFor(F, m[0..28], i, pi, f[1], f[2], claims.ram, ch.ram, out);
    S.single(F, ch.owner.denominatorFor(F, ownerTuple(F, m)), active, E.secureFor(F, i, L.OWNER), E.secureFor(F, i, L.OWNER + 4), E.secureFor(F, pi, L.OWNER + 4), f[1], f[2], claims.owner, out);
    R.rangesFor(F, m, i, pi, &L.U16, L.RANGE16, f[1], f[2], claims.range16, ch.range16, out);
    R.rangesFor(F, m, i, pi, &L.U8, L.RANGE8, f[1], f[2], claims.range8, ch.range8, out);
    S.single(F, ch.selection.denominatorFor(F, selectionTuple(F, m)), one, E.secureFor(F, i, L.SELECTION), E.secureFor(F, i, L.SELECTION + 4), E.secureFor(F, pi, L.SELECTION + 4), f[1], f[2], claims.selection, out);
}

/// Shared local RAM/LS arithmetic; lookup encodings are separate authorities.
/// The original emitFor preserves its exact residual order through this seam.
pub fn emitLocalFor(comptime F: type, f: []const F, m: []const F, pm: []const F, rows: u32, out: *E.SinkFor(F)) void {
    @setEvalBranchQuota(1000000);
    const one = F.one();
    const active = m[0];
    R.transitionLocalFor(F, f, m[0..28], pm[0..28], rows, out);
    for (m[28..]) |value| out.emit(one.sub(active).mul(value));
    var flag_sum = F.zero();
    var load = F.zero();
    var store = F.zero();
    var opcode = F.zero();
    inline for (Specs.load_specs ++ Specs.store_specs, 0..) |spec, index| {
        const flag = m[L.flags + index];
        E.booleanFor(F, out, flag);
        flag_sum = flag_sum.add(flag);
        if (index < Specs.load_specs.len) load = load.add(flag) else store = store.add(flag);
        opcode = opcode.add(flag.mul(E.qFor(F, @intFromEnum(spec.opcode))));
    }
    out.emit(flag_sum.sub(active));
    out.emit(m[L.opcode].sub(opcode));
    out.emit(m[1].sub(store));
    var offset_sum = F.zero();
    var offset_value = F.zero();
    for (0..8) |offset| {
        const flag = m[L.offsets + offset];
        E.booleanFor(F, out, flag);
        offset_sum = offset_sum.add(flag);
        offset_value = offset_value.add(flag.mul(E.qFor(F, @intCast(offset))));
    }
    out.emit(offset_sum.sub(active));
    for (m[L.address_carries..][0..4]) |carry| E.booleanFor(F, out, carry);
    for (0..4) |c| out.emit(active.mul(Add.limbResidualFor(F, m[L.a + c], m[L.immediate + c], if (c == 0) F.zero() else m[L.address_carries + c - 1], m[L.effective + c], m[L.address_carries + c])));
    // Natural alignment only. The word address is a multiple of eight; the
    // bounded quotient prevents modular inverse-of-eight address compensation.
    out.emit(m[L.effective].sub(m[4]).sub(offset_value));
    for (1..4) |c| out.emit(m[L.effective + c].sub(m[4 + c]));
    out.emit(m[4].sub(m[L.quotient].mul(E.qFor(F, 8))));
    out.emit(m[L.b].sub(m[L.b_low]).sub(m[L.b_high].mul(E.qFor(F, 256))));
    inline for (Specs.load_specs ++ Specs.store_specs, 0..) |spec, index| {
        const flag = m[L.flags + index];
        var selected = F.zero();
        for (0..8) |offset| {
            if (offset % spec.width != 0 or offset + spec.width > 8) {
                out.emit(flag.mul(m[L.offsets + offset]));
            } else {
                const top = offset / 2 + (if (spec.width == 1) 0 else spec.width / 2 - 1);
                selected = selected.add(m[L.offsets + offset].mul(m[14 + top]));
            }
        }
        out.emit(flag.mul(m[L.selected_limb].sub(selected)));
    }
    inline for (Specs.load_specs, 0..) |spec, index| {
        const flag = m[L.flags + index];
        const sign = if (!spec.signed) F.zero() else m[if (spec.width == 1) L.selected_sign else L.limb_sign];
        for (0..4) |c| {
            var wanted = F.zero();
            if (spec.width == 1 and c == 0) {
                wanted = m[L.selected_byte].add(sign.mul(E.qFor(F, 65280)));
            } else if (c < spec.width / 2) {
                for (0..8) |offset| if (offset % spec.width == 0 and offset + spec.width <= 8) {
                    wanted = wanted.add(m[L.offsets + offset].mul(m[14 + offset / 2 + c]));
                };
            } else wanted = sign.mul(E.qFor(F, 65535));
            out.emit(flag.mul(m[L.c + c].sub(wanted)));
        }
    }
    for (0..4) |c| out.emit(store.mul(m[L.c + c]));
    for (0..4) |c| out.emit(load.mul(m[L.b + c]));
    inline for (Specs.store_specs, 0..) |spec, index| {
        const flag = m[L.flags + Specs.load_specs.len + index];
        for (0..4) |c| {
            var wanted = m[14 + c];
            for (0..8) |offset| {
                if (offset % spec.width != 0 or offset + spec.width > 8) continue;
                if (spec.width == 1) {
                    if (offset / 2 == c) wanted = wanted.add(m[L.offsets + offset].mul(m[L.b_low].sub(m[L.selected_byte])).mul(E.qFor(F, if (offset % 2 == 0) 1 else 256)));
                } else if (c >= offset / 2 and c < offset / 2 + spec.width / 2) {
                    wanted = wanted.add(m[L.offsets + offset].mul(m[L.b + c - offset / 2].sub(m[14 + c])));
                }
            }
            out.emit(flag.mul(m[18 + c].sub(wanted)));
        }
    }
}
