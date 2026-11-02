//! Private RAM CellTable: canonical values feed chunk hashes; local clocks and
//! rights feed the CPU/K state relation. The receiver never accepts a host RAM
//! rational target. Chunk headers and immutable-policy permits close separately.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const state = @import("../relations.zig");
const values = @import("values.zig");
const internal = @import("internal_relations.zig");
const rational = @import("policy_air.zig");
const words = @import("message_air.zig");
const prefix = @import("prefix.zig");
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const BEFORE = 0;
pub const AFTER = 8;
pub const CLOCK = 16;
pub const BASE = 19;
pub const BEFORE_ID = 27;
pub const AFTER_ID = 28;
pub const CHANGED = 29;
pub const READ = 30;
pub const WRITE = 31;
pub const TOUCHED = 32;
pub const CLOCK_INVERSE = 33;
pub const ACTIVE = 34;
pub const MAIN = 35;
pub const FIXED = 7;
pub const FIRST = 0;
pub const LAST = 1;
pub const INDEX = 2;
pub const CELL = 3;
pub const GROUP_FIRST = 4;
pub const OFFSET_LOW = 5;
pub const OFFSET_HIGH = 6;
pub const BYTE_SUMS = 7;
pub const PAYLOAD_SUMS = 3;
pub const HEADER_SUM = 10;
pub const PERMIT_SUM = 11;
pub const STATE_SUM = 12;
pub const SUMS = 13;
pub const INTERACTION = 4 * SUMS;
pub const CONSTRAINTS = 54;
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const Fixed = [FIXED]Q;
pub fn ClaimsFor(comptime C: type) type {
    return [SUMS]C;
}
pub const Claims = ClaimsFor(Q);
pub const Term = rational.Term;
pub const PolicyMode = enum { chunk, word };
/// Cell challenges over constant lane C (QM31 natively, external wires otherwise).
pub fn ChallengesFor(comptime C: type) type {
    return struct { ram: internal.PreparedFor(C), state: state.ChallengesFor(C), bytes: C };
}
pub const Challenges = ChallengesFor(Q);
pub const Shape = struct {
    geometry: values.Geometry,
    chunks: u32,
    log_size: u32,
    policy_mode: PolicyMode,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn activeRows(self: Shape) u32 {
        return self.chunks * @as(u32, @intCast(self.geometry.cells()));
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 24 or @as(u64, self.chunks) * self.geometry.cells() > self.size()) return error.InvalidPrivateRamCellShape;
    }
    pub fn fixedAt(self: Shape, i: usize) [FIXED]M {
        return .{ M.fromCanonical(@intFromBool(i == 0)), M.fromCanonical(@intFromBool(i + 1 == self.size())), M.fromCanonical(@intCast(i)), M.fromCanonical(@intCast(i % self.geometry.cells())), M.fromCanonical(@intFromBool(i % self.geometry.cells() == 0)), M.fromCanonical(@intCast((8 * (i % self.geometry.cells())) & 255)), M.fromCanonical(@intCast((8 * (i % self.geometry.cells())) >> 8)) };
    }
};
pub fn clock(main: *const SecureRow) Q {
    return clockFor(Q, main);
}
pub fn clockFor(comptime F: type, main: *const [MAIN]F) F {
    return main[CLOCK].add(E.qFor(F, 256).mul(main[CLOCK + 1])).add(E.qFor(F, 65536).mul(main[CLOCK + 2]));
}
/// Base addresses are independently authenticated/aligned by LeafHeader. The
/// immutable offset schedule has low byte<=248 and high byte<=15, so adding it
/// to an aligned chunk base cannot overflow byte one in either geometry.
pub fn address(fixed: *const Fixed, main: *const SecureRow) [8]Q {
    return addressFor(Q, fixed, main);
}
pub fn addressFor(comptime F: type, fixed: *const [FIXED]F, main: *const [MAIN]F) [8]F {
    var result = main[BASE..][0..8].*;
    result[0] = fixed[OFFSET_LOW];
    result[1] = result[1].add(fixed[OFFSET_HIGH]);
    return result;
}
pub fn header(ram: *const internal.Prepared, base: [8]Q, before_id: Q, after_id: Q, changed: Q) Q {
    return headerFor(Q, ram, base, before_id, after_id, changed);
}
pub fn headerFor(comptime F: type, ram: *const internal.PreparedFor(F), base: [8]F, before_id: F, after_id: F, changed: F) F {
    var fields: [11]F = undefined;
    @memcpy(fields[0..8], &base);
    fields[8] = before_id;
    fields[9] = after_id;
    fields[10] = changed;
    return ram.combine(.header, &fields);
}
pub fn byteTerm(main: *const SecureRow, alpha: Q, slot: usize) Term {
    return byteTermFor(Q, main, alpha, slot);
}
pub fn byteTermFor(comptime F: type, main: *const [MAIN]F, alpha: F, slot: usize) rational.TermFor(F) {
    return if (slot < 19) .{ .denominator = alpha.sub(main[slot]), .numerator = main[ACTIVE] } else .{ .denominator = F.one(), .numerator = F.zero() };
}
pub fn payloadTerm(fixed: *const Fixed, main: *const SecureRow, ram: *const internal.Prepared, slot: usize) Term {
    return payloadTermFor(Q, fixed, main, ram, slot);
}
pub fn payloadTermFor(comptime F: type, fixed: *const [FIXED]F, main: *const [MAIN]F, ram: *const internal.PreparedFor(F), slot: usize) rational.TermFor(F) {
    if (slot >= 8) return .{ .denominator = F.one(), .numerator = F.zero() };
    const after = slot >= 4;
    const limbs = words.wordValuesFor(F, if (after) main[AFTER..][0..8] else main[BEFORE..][0..8]);
    return .{ .denominator = ram.payload(main[if (after) AFTER_ID else BEFORE_ID], E.qFor(F, 4).mul(fixed[CELL]).add(E.qFor(F, @intCast(slot % 4))), limbs[slot % 4]), .numerator = if (after) main[ACTIVE].mul(main[CHANGED]).neg() else main[ACTIVE].neg() };
}
pub fn headerTerm(fixed: *const Fixed, main: *const SecureRow, ram: *const internal.Prepared) Term {
    return headerTermFor(Q, fixed, main, ram);
}
pub fn headerTermFor(comptime F: type, fixed: *const [FIXED]F, main: *const [MAIN]F, ram: *const internal.PreparedFor(F)) rational.TermFor(F) {
    return .{ .denominator = headerFor(F, ram, main[BASE..][0..8].*, main[BEFORE_ID], main[AFTER_ID], main[CHANGED]), .numerator = main[ACTIVE].mul(fixed[GROUP_FIRST]) };
}
pub fn stateTerm(fixed: *const Fixed, main: *const SecureRow, challenges: state.Challenges, slot: usize) Term {
    return stateTermFor(Q, fixed, main, challenges, slot);
}
pub fn stateTermFor(comptime F: type, fixed: *const [FIXED]F, main: *const [MAIN]F, challenges: state.ChallengesFor(F), slot: usize) rational.TermFor(F) {
    if (slot >= 2) return .{ .denominator = F.one(), .numerator = F.zero() };
    var tuple: [state.ARITY]F = @splat(F.zero());
    tuple[0] = F.one();
    @memcpy(tuple[1..9], &addressFor(F, fixed, main));
    tuple[9] = if (slot == 0) F.zero() else clockFor(F, main);
    @memcpy(tuple[10..18], main[if (slot == 0) BEFORE else AFTER..][0..8]);
    tuple[18] = main[READ];
    tuple[19] = main[WRITE];
    const weight = main[ACTIVE].mul(main[TOUCHED]);
    return .{ .denominator = challenges.denominatorFor(F, tuple), .numerator = if (slot == 0) weight.neg() else weight };
}
pub fn permitTerm(shape: Shape, fixed: *const Fixed, main: *const SecureRow, ram: *const internal.Prepared) Term {
    return permitTermFor(Q, shape, fixed, main, ram);
}
pub fn permitTermFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, ram: *const internal.PreparedFor(F)) rational.TermFor(F) {
    var fields: [11]F = undefined;
    @memcpy(fields[0..8], main[BASE..][0..8]);
    if (shape.policy_mode == .word) {
        fields[0] = fixed[OFFSET_LOW];
        fields[1] = fields[1].add(fixed[OFFSET_HIGH]);
    }
    fields[8] = E.qFor(F, if (shape.policy_mode == .word) 3 else shape.geometry.logBytes());
    fields[9] = main[READ];
    fields[10] = main[WRITE];
    return .{ .denominator = ram.combine(.permit, &fields), .numerator = main[ACTIVE].mul(if (shape.policy_mode == .word) main[TOUCHED] else fixed[GROUP_FIRST]) };
}
pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    return evaluateFor(Q, shape, fixed, main, previous, interaction, previous_interaction, claims, challenges, prefix.rows(shape.activeRows(), @intCast(shape.size())), out);
}
/// Same residuals over any secure lane; `rows` carries the active-row publics.
pub fn evaluateFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous: *const [MAIN]F, interaction: []const F, previous_interaction: []const F, claims: ClaimsFor(F), challenges: *const ChallengesFor(F), rows: prefix.RowsFor(F), out: *E.SinkFor(F)) void {
    const active = main[ACTIVE];
    const touched = main[TOUCHED];
    prefix.evaluateFor(F, active, previous[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], rows, out);
    for (main[CHANGED .. TOUCHED + 1]) |bit| out.emit(bit.mul(bit.sub(F.one())));
    out.emit(touched.mul(F.one().sub(main[READ])).mul(F.one().sub(main[WRITE])));
    out.emit(clockFor(F, main).mul(main[CLOCK_INVERSE]).sub(touched));
    out.emit(F.one().sub(touched).mul(clockFor(F, main)));
    const hold = active.mul(F.one().sub(fixed[GROUP_FIRST]));
    for (BASE..CHANGED + 1) |i| out.emit(hold.mul(main[i].sub(previous[i])));
    for (READ..WRITE + 1) |i| out.emit(if (shape.policy_mode == .chunk) hold.mul(main[i].sub(previous[i])) else F.zero());
    for (0..8) |i| {
        const delta = main[AFTER + i].sub(main[BEFORE + i]);
        out.emit(F.one().sub(touched).mul(delta));
        out.emit(F.one().sub(main[CHANGED]).mul(delta));
    }
    for (0..SUMS) |group| {
        var denominators: [3]F = undefined;
        var numerators: [3]F = undefined;
        for (0..3) |slot| {
            const term = if (group < BYTE_SUMS) byteTermFor(F, main, challenges.bytes, 3 * group + slot) else if (group < HEADER_SUM) payloadTermFor(F, fixed, main, &challenges.ram, 3 * (group - BYTE_SUMS) + slot) else if (group == HEADER_SUM) (if (slot == 0) headerTermFor(F, fixed, main, &challenges.ram) else rational.TermFor(F){ .denominator = F.one(), .numerator = F.zero() }) else if (group == PERMIT_SUM) (if (slot == 0) permitTermFor(F, shape, fixed, main, &challenges.ram) else rational.TermFor(F){ .denominator = F.one(), .numerator = F.zero() }) else stateTermFor(F, fixed, main, challenges.state, slot);
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        out.emit(rational.tripleFor(F, rational.secureFor(F, interaction, group), rational.secureFor(F, previous_interaction, group), fixed[FIRST], claims[group], denominators, numerators));
    }
}

pub const Native = struct {
    base: u64,
    before_id: u32,
    after_id: u32,
    changed: bool,
    before: u64,
    after: u64,
    terminal_clock: u32,
    readable: bool,
    writable: bool,
};
pub fn fill(geometry: values.Geometry, native: Native) !Row {
    return fillWithInverse(geometry, native, null);
}
pub fn restore(geometry: values.Geometry, native: Native, inverse: M) !Row {
    return fillWithInverse(geometry, native, inverse);
}
fn fillWithInverse(geometry: values.Geometry, native: Native, cached_inverse: ?M) !Row {
    const touched = native.terminal_clock != 0;
    if ((native.base & (geometry.bytes() - 1)) != 0 or native.terminal_clock >= 1 << 24 or native.before_id >= core.fields.m31.Modulus or native.after_id >= core.fields.m31.Modulus or
        ((!touched or !native.changed) and native.before != native.after) or (touched and !native.readable and !native.writable)) return error.InvalidPrivateRamCell;
    var row: Row = @splat(M.zero());
    for (0..8) |i| {
        row[BEFORE + i] = M.fromCanonical(@intCast((native.before >> @intCast(8 * i)) & 255));
        row[AFTER + i] = M.fromCanonical(@intCast((native.after >> @intCast(8 * i)) & 255));
        row[BASE + i] = M.fromCanonical(@intCast((native.base >> @intCast(8 * i)) & 255));
    }
    for (0..3) |i| row[CLOCK + i] = M.fromCanonical((native.terminal_clock >> @intCast(8 * i)) & 255);
    row[BEFORE_ID] = M.fromCanonical(native.before_id);
    row[AFTER_ID] = M.fromCanonical(native.after_id);
    row[CHANGED] = M.fromCanonical(@intFromBool(native.changed));
    row[READ] = M.fromCanonical(@intFromBool(native.readable));
    row[WRITE] = M.fromCanonical(@intFromBool(native.writable));
    row[TOUCHED] = M.fromCanonical(@intFromBool(touched));
    if (touched) row[CLOCK_INVERSE] = if (cached_inverse) |inverse| inverse else try M.fromCanonical(native.terminal_clock).inv();
    row[ACTIVE] = M.one();
    return row;
}
