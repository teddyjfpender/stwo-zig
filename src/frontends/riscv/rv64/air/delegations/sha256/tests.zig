//! Constraint-level authority tests for the SHA-256 truth AIR.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const N = @import("native.zig");
const Eq = @import("equations.zig");
const T = @import("trace.zig");
const Candidate = @import("../../../ethereum_services/candidate_services.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;

const IV = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

/// Mutable QM31 view, so adversarial tests can place non-Boolean/non-canonical values.
const View = struct {
    fixed_values: [L.FIXED]Q,
    main_values: []Q,
    previous_active: Q,
    inter: [L.INTERACTION]Q = @splat(Q.zero()),
    previous_inter: [L.INTERACTION]Q = @splat(Q.zero()),
    pub fn fixed(self: *const View, c: usize) Q {
        return self.fixed_values[c];
    }
    pub fn main(self: *const View, c: usize) Q {
        return self.main_values[c];
    }
    pub fn previousActive(self: *const View) Q {
        return self.previous_active;
    }
    pub fn interaction(self: *const View, c: usize) Q {
        return self.inter[c];
    }
    pub fn previousInteraction(self: *const View, c: usize) Q {
        return self.previous_inter[c];
    }
};
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
const Case = struct {
    main: [L.MAIN]Q,
    view: View,
    fn init(self: *Case, input: N.Input, row_index: u32, active: bool, previous: bool) void {
        var row: N.Row = undefined;
        _ = N.fill(&row, input);
        row[L.ACTIVE] = @intFromBool(active);
        for (&self.main, row) |*dst, v| dst.* = q(v);
        self.view = .{ .fixed_values = .{ q(row_index), q(@intFromBool(row_index == 0)), q(0) }, .main_values = &self.main, .previous_active = q(@intFromBool(previous)) };
    }
    /// Index of the first nonzero MAIN residual (activity uses calls = 1000).
    fn firstFailure(self: *Case) ?usize {
        self.view.main_values = &self.main;
        var values: [L.CONSTRAINTS - L.BATCHES]Q = undefined;
        var sink = E.Sink{ .values = &values };
        Eq.emitMain(Q, &self.view, .{ .calls = 1000, .first_id = 1 }, &sink);
        std.debug.assert(sink.count == values.len);
        for (values, 0..) |v, i| if (!v.isZero()) return i;
        return null;
    }
};
fn randomInput(rng: std.Random) N.Input {
    var input: N.Input = undefined;
    for (&input.state) |*w| w.* = rng.int(u32);
    rng.bytes(&input.block);
    return input;
}
fn sha256Message(message: []const u8) [32]u8 {
    var state = IV;
    var padded: [256]u8 = @splat(0);
    std.debug.assert(message.len <= 128);
    @memcpy(padded[0..message.len], message);
    padded[message.len] = 0x80;
    const blocks = (message.len + 9 + 63) / 64;
    std.mem.writeInt(u64, padded[64 * blocks - 8 ..][0..8], 8 * @as(u64, message.len), .big);
    for (0..blocks) |b| {
        var row: N.Row = undefined;
        state = N.fill(&row, .{ .state = state, .block = padded[64 * b ..][0..64].* });
    }
    var out: [32]u8 = undefined;
    for (0..8) |i| std.mem.writeInt(u32, out[4 * i ..][0..4], state[i], .big);
    return out;
}

test "FIPS 180-4 one- and two-block known answers through the witness" {
    const vectors = [_]struct { message: []const u8, digest: []const u8 }{
        .{ .message = "abc", .digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        .{ .message = "", .digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        .{ .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", .digest = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        .{ .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", .digest = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
    };
    for (vectors) |vector| {
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, vector.digest);
        try std.testing.expectEqualSlices(u8, &expected, &sha256Message(vector.message));
    }
}

test "witness and AIR agree with an independent compression on random and extreme blocks" {
    var prng = std.Random.DefaultPrng.init(0x5a256);
    const rng = prng.random();
    var case: Case = undefined;
    for (0..48) |i| {
        var input = randomInput(rng);
        // Extreme carries: all-ones state and block, all-zero, and mixed.
        if (i == 0) {
            input.state = @splat(0xffffffff);
            input.block = @splat(0xff);
        } else if (i == 1) {
            input.state = @splat(0);
            input.block = @splat(0);
        } else if (i == 2) input.state = IV;
        var expected = input.state;
        Candidate.sha256Compress(&expected, &input.block);
        var row: N.Row = undefined;
        try std.testing.expectEqual(expected, N.fill(&row, input));
        try std.testing.expectEqual(expected, N.compress(input.state, &input.block));
        case.init(input, 0, true, false);
        try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
        // Native wire bytes agree with the AIR's linear byte forms.
        for (0..4) |wire| {
            const tuple = Eq.tuple(Q, &case.view, .{ .calls = 1, .first_id = 7 }, @intCast(wire));
            const bytes = N.wireBytes(input, expected, @intCast(wire));
            try std.testing.expect(tuple[0].eql(q(L.PROGRAM_KIND)) and tuple[1].eql(q(7)) and tuple[2].eql(q(@intCast(wire))));
            for (bytes, tuple[3..]) |b, t| try std.testing.expect(t.eql(q(b)));
        }
    }
}

test "adversarial rows: wrong output, wrong message, non-canonical bit, carry forgery" {
    var prng = std.Random.DefaultPrng.init(0xadb256);
    const rng = prng.random();
    var case: Case = undefined;
    for (0..8) |_| {
        const input = randomInput(rng);
        // Wrong output byte (field-consistent with nothing).
        case.init(input, 0, true, false);
        case.main[L.OUT + rng.uintLessThan(usize, 32)] = case.main[L.OUT].add(q(1));
        try std.testing.expect(case.firstFailure() != null);
        // Wrong message bit: flip one W_0..15 bit, keep everything else.
        case.init(input, 0, true, false);
        const bit = L.w(rng.uintLessThan(usize, 16), rng.uintLessThan(usize, 32));
        case.main[bit] = Q.one().sub(case.main[bit]);
        try std.testing.expect(case.firstFailure() != null);
        // Non-canonical bit: a value 2 in place of a 1 bit and the lower bit
        // cleared keeps the weighted half equal but fails Booleanity.
        case.init(input, 0, true, false);
        var found = false;
        for (1..32) |i| {
            const hi = L.e(10, i);
            const lo = L.e(10, i - 1);
            if (!case.main[hi].isZero() and case.main[lo].isZero()) {
                // 2 * 2^(i-1) == 2^i: the weighted half of E_6 is unchanged.
                case.main[hi] = Q.zero();
                case.main[lo] = q(2);
                found = true;
                break;
            }
        }
        if (found) try std.testing.expect(case.firstFailure() != null);
        // Carry forgery: change a round carry by one and move 2^16 into the
        // low half sum; Booleanity of the carry bits or the half equation fails.
        case.init(input, 0, true, false);
        const c = L.roundCarry(5, .e, false, 0);
        case.main[c] = Q.one().sub(case.main[c]);
        try std.testing.expect(case.firstFailure() != null);
        // Feed-forward carry forgery alone.
        case.init(input, 0, true, false);
        case.main[L.finalCarry(3, false)] = Q.one().sub(case.main[L.finalCarry(3, false)]);
        try std.testing.expect(case.firstFailure() != null);
    }
}

test "every single-cell perturbation of an honest row violates some MAIN residual" {
    var prng = std.Random.DefaultPrng.init(0xce11);
    const rng = prng.random();
    var case: Case = undefined;
    const input = randomInput(rng);
    // OUT bytes are the only non-Boolean MAIN cells. A +1 perturbation of any
    // single cell must be caught locally (OUT range comes from Wire35).
    for (0..L.MAIN) |c| {
        case.init(input, 0, true, false);
        case.main[c] = case.main[c].add(q(1));
        try std.testing.expect(case.firstFailure() != null);
    }
}

test "activity prefix: exactly rows 0..calls-1 may be active" {
    var case: Case = undefined;
    const input = N.PADDING;
    // Row 0 must be active.
    case.init(input, 0, false, false);
    try std.testing.expect(case.firstFailure() != null);
    // 0 -> 1 transitions after row 0 are forbidden.
    case.init(input, 5, true, false);
    try std.testing.expect(case.firstFailure() != null);
    // A 1 -> 0 transition only at row == calls (1000 in the helper).
    case.init(input, 999, false, true);
    try std.testing.expect(case.firstFailure() != null);
    case.init(input, 1000, false, true);
    try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
    // The last row is never active.
    case.init(input, 4, true, true);
    case.view.fixed_values[L.LAST] = q(1);
    try std.testing.expect(case.firstFailure() != null);
}

test "interaction claim equals the native Wire35 sum and satisfies both batch residuals" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x1a7e);
    const rng = prng.random();
    var inputs: [5]N.Input = undefined;
    for (&inputs) |*input| input.* = randomInput(rng);
    var source = try T.Source.init(a, &inputs, 11, 5);
    defer source.deinit();
    var wire: Eq.Wire = undefined;
    wire.offset = q(0x1234567).add(Q.fromPartialEvals(.{ q(1), q(2), q(3), q(4) }));
    for (&wire.coefficients, 0..) |*c, i| c.* = Q.fromPartialEvals(.{ q(@intCast(i + 9)), q(@intCast(3 * i + 1)), q(77), q(@intCast(i * i + 5)) });
    const claim = try source.generateInteraction(wire);
    var expected = Q.zero();
    for (inputs, 0..) |input, r| {
        const out = N.compress(input.state, &input.block);
        for (0..4) |id| {
            const d = wire.denominator(&T.externalTuple(11 + @as(u32, @intCast(r)), @intCast(id), N.wireBytes(input, out, @intCast(id))));
            const inv = try d.inv();
            expected = if (id == 3) expected.add(inv) else expected.sub(inv);
        }
    }
    try std.testing.expect(claim.eql(expected));
    const n = source.size();
    const R = @import("../../memory/closed_ram/mod.zig");
    var rows: [32]N.Row = undefined;
    for (&rows, 0..) |*row, r| {
        _ = N.fill(row, if (r < inputs.len) inputs[r] else N.PADDING);
        row[L.ACTIVE] = @intFromBool(r < inputs.len);
    }
    var main: [L.MAIN]Q = undefined;
    for (0..n) |r| {
        const p = R.trace.physical(r, 5);
        const prev = (r + n - 1) % n;
        const pp = R.trace.physical(prev, 5);
        for (&main, rows[r]) |*dst, v| dst.* = q(v);
        var view = View{ .fixed_values = .{ q(@intCast(r)), q(@intFromBool(r == 0)), q(@intFromBool(r == n - 1)) }, .main_values = &main, .previous_active = q(rows[prev][L.ACTIVE]) };
        for (0..L.INTERACTION) |c| {
            view.inter[c] = Q.fromBase(source.interaction[c * n + p]);
            view.previous_inter[c] = Q.fromBase(source.interaction[c * n + pp]);
        }
        // Coordinates are stored as four base columns per secure value.
        var values: [L.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &values };
        Eq.emit(Q, &view, .{ .calls = 5, .first_id = 11 }, claim, wire, &sink);
        for (values) |v| try std.testing.expect(v.isZero());
    }
}
