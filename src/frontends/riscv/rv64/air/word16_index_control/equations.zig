//! Concrete index frame plus the SAME qualified register/range/function math.
//! No machine factory or runtime representation policy selects this component.
const E = @import("../evaluation.zig");
const Shared = @import("../word16_cpu/equations.zig");
const Lookup = @import("../word16_cpu/lookup.zig");
const State = @import("../word16_cpu/public.zig");
const Old = @import("../word16_cpu/layout.zig");
const Authority = @import("authority.zig");
pub const MAIN = 40;
pub const INTERACTION = 56;
pub const CONSTRAINTS = 49;
pub const current_id = 0;
pub const next_id = 1;
pub const active = Old.main.active - 6;
pub const Public = struct { state: State.Public, initial_id: u32, final_id: u32 };
pub fn resolve(authority: *const Authority.Authority, state: State.Public, log: u32) !Public {
    try state.validate(log);
    return .{ .state = state, .initial_id = try authority.executableId(state.initial_pc), .final_id = try authority.idForPc(state.final_pc) };
}
pub const RomChallenges = struct {
    offset: E.Q,
    coefficients: [17]E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, fields: [17]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &fields, true);
    }
};
pub const MapChallenges = struct {
    offset: E.Q,
    coefficients: [5]E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, fields: [5]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &fields, true);
    }
};
/// Transient view only: no 46-column source matrix is constructed or copied.
pub fn logical(comptime F: type, main: []const F) [46]F {
    var result: [46]F = @splat(F.zero());
    @memcpy(result[8..], main[2..MAIN]);
    return result;
}
pub fn tuple(comptime F: type, main: []const F) [17]F {
    var result: [17]F = undefined;
    result[0] = F.one();
    result[1] = main[0];
    result[2] = main[1];
    @memcpy(result[3..10], main[2..9]);
    result[10] = main[38];
    result[11] = main[39];
    for (0..4) |i| result[12 + i] = main[38].mul(main[Old.main.b - 6 + i]);
    result[16] = main[39].mul(main[Old.main.c - 6]);
    return result;
}
pub fn emitFor(comptime F: type, fixed: []const F, main: []const F, previous_main: []const F, current: []const F, previous: []const F, public: Public, claims: State.Claims, data_ch: Lookup.Challenges, rom_ch: RomChallenges, sink: *E.SinkFor(F)) void {
    const view = logical(F, main);
    const prior = logical(F, previous_main);
    Shared.emitActivityFor(F, fixed, &view, &prior, public.state.steps, sink);
    const first = fixed[1];
    const last = fixed[2];
    sink.emit(first.mul(main[current_id].sub(E.qFor(F, public.initial_id))));
    sink.emit(F.one().sub(first).mul(main[current_id].sub(previous_main[next_id])));
    sink.emit(F.one().sub(main[active]).mul(main[next_id].sub(main[current_id])));
    sink.emit(last.mul(main[next_id].sub(E.qFor(F, public.final_id))));
    Shared.emitDataFor(F, .alu_binary_v2, fixed, &view, sink);
    Shared.emitRegisterFor(F, fixed, &view, current, previous, claims.register, data_ch.register, sink);
    Shared.emitFunctionFor(F, fixed, &view, current, previous, claims.function, data_ch.function, sink);
    Lookup.single(F, rom_ch.denominatorFor(F, tuple(F, main)), main[active], E.secureFor(F, current, Old.inter.rom_inverse), E.secureFor(F, current, Old.inter.rom_sum), E.secureFor(F, previous, Old.inter.rom_sum), first, last, claims.rom, sink);
    Shared.emitRangesFor(F, fixed, &view, current, previous, claims.range16, claims.range8, data_ch.range16, data_ch.range8, sink);
}
pub fn mapTuple(comptime F: type, fixed: []const F) [5]F {
    return .{ fixed[1], fixed[Authority.RAW_PC], fixed[Authority.RAW_PC + 1], fixed[Authority.RAW_PC + 2], fixed[Authority.RAW_PC + 3] };
}
pub fn emitRomFor(comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, claims: [2]E.Q, ch: RomChallenges, map: MapChallenges, sink: *E.SinkFor(F)) void {
    Lookup.single(F, ch.denominatorFor(F, fixed[0..17].*), main[0].neg(), E.secureFor(F, current, 0), E.secureFor(F, current, 4), E.secureFor(F, previous, 4), fixed[Authority.FIRST], fixed[Authority.LAST], claims[0], sink);
    sink.emit(main[0].mul(F.one().sub(fixed[0])));
    // ALL map rows are true, including nonfetchable words and canonical padded
    // copies of the first address. No decode-valid mask applies to this family.
    Lookup.single(F, map.denominatorFor(F, mapTuple(F, fixed)), main[1].neg(), E.secureFor(F, current, 8), E.secureFor(F, current, 12), E.secureFor(F, previous, 12), fixed[Authority.FIRST], fixed[Authority.LAST], claims[1], sink);
}
