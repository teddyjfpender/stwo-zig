const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const support = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
const routing = @import("recursive_common_ethereum_incremental_leaf_role_input_routing_v4.zig");
const arithmetic = support.arithmetic;
const M31 = support.M31;
const QM31 = support.QM31;
const raw = support.segment_v2;
const CLOCK_START = support.STATEMENT_WORD_COUNT;
const AUX_START = CLOCK_START + support.CLOCK_LIMB_COUNT;
const INPUT_COUNT = AUX_START + support.CLOCK_AUX_INPUT_COUNT;

const Fixture = struct {
    circuit: arithmetic.Circuit,
    inputs: []QM31,
    statement: [support.STATEMENT_WORD_COUNT]u32 = @splat(0),
    native: [raw.FIXED_CANONICAL_WORDS]M31 = @splat(M31.zero()),

    fn init() !Fixture {
        const allocator = std.testing.allocator;
        var builder = arithmetic.Builder.initDefault(allocator);
        defer builder.deinit();
        var values: [INPUT_COUNT]arithmetic.Value = undefined;
        for (&values, 0..) |*value, index| value.* = try builder.input(@intCast(index));
        try support.constrainRawClocks(&builder, values[0..CLOCK_START], values[CLOCK_START..AUX_START], values[AUX_START..]);
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        const inputs = try allocator.alloc(QM31, INPUT_COUNT);
        @memset(inputs, QM31.zero());
        return .{ .circuit = circuit, .inputs = inputs };
    }

    fn deinit(self: *Fixture) void {
        self.circuit.deinit();
        std.testing.allocator.free(self.inputs);
    }

    fn cycles(self: *Fixture, first: u64, count: u64) void {
        for ([_]usize{ support.span.canonical_layout.first_cycle_start, support.span.canonical_layout.executed_cycle_count_start }, [_]u64{ first, count }) |start, value| {
            for (0..4) |limb| self.statement[start + limb] = @intCast((value >> @as(u6, @intCast(limb * 16))) & 65535);
        }
    }

    fn clock(self: *Fixture, boundary: support.Boundary, register: usize, value: u32) void {
        const start = (if (boundary == .entry) raw.fixed_layout.entry_register_clocks else raw.fixed_layout.exit_register_clocks) + register * 2;
        self.native[start] = M31.fromCanonical(value & 65535);
        self.native[start + 1] = M31.fromCanonical(value >> 16);
    }

    fn refresh(self: *Fixture) !void {
        for (self.statement, self.inputs[0..CLOCK_START]) |word, *input| input.* = QM31.fromBase(M31.fromCanonical(word));
        for (self.native[raw.fixed_layout.entry_register_clocks..raw.fixed_layout.completion], self.inputs[CLOCK_START..AUX_START]) |word, *input| input.* = QM31.fromBase(word);
        for (self.inputs[AUX_START..], 0..) |*input, index| input.* = try support.clockAuxValue(try support.clockAuxSourceAt(index), &self.statement, &self.native);
    }

    fn expect(self: *Fixture, accepted: bool) !void {
        var evaluation = try self.circuit.evaluate(std.testing.allocator, self.inputs);
        defer evaluation.deinit();
        try std.testing.expectEqual(accepted, try self.circuit.outputsAreZero(evaluation.values));
    }
};

test "Ethereum raw boundary clock accepts zero and native access bounds" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_][2]u64{ .{ 0, 1 }, .{ 1, 1 }, .{ 7, 9 }, .{ (1 << 24) - 1, 1 } }) |range| {
        @memset(&fixture.native, M31.zero());
        fixture.cycles(range[0], range[1]);
        // Literal zero remains valid even at cycle0, including untouched registers.
        try fixture.refresh();
        try fixture.expect(true);
        const first: u32 = @intCast(range[0]);
        const end: u32 = @intCast(range[0] + range[1]);
        for (0..32) |reg| {
            const entry: u32 = @intCast(frontend.access_clock.maximum(first));
            const exit: u32 = @intCast(frontend.access_clock.maximum(end));
            try std.testing.expect(frontend.access_clock.isWithinExecution(entry, first, true));
            try std.testing.expect(frontend.access_clock.isWithinExecution(exit, end, true));
            fixture.clock(.entry, reg, entry);
            fixture.clock(.exit, reg, exit);
        }
        try fixture.refresh();
        try fixture.expect(true);
    }
}

test "Ethereum raw boundary clock rejects aliases reserved residues and reverse time" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.cycles(3, 2);
    const cases = [_][2]u32{
        .{ core.fields.m31.Modulus, core.fields.m31.Modulus }, // Cancels as field zero.
        .{ 4, 4 }, // Reserved nonzero residue0.
        .{ 13, 13 }, // First valid subclock outside entry cycle3.
        .{ 0, 21 }, // First valid subclock outside exit cycle5.
        .{ 11, 10 }, // Both fit their bounds, but time goes backwards.
        .{ 0, 1 << 26 }, // High-limb truncation cannot hide the first excess bit.
    };
    for (cases) |pair| {
        fixture.clock(.entry, 3, pair[0]);
        fixture.clock(.exit, 3, pair[1]);
        try fixture.refresh();
        try fixture.expect(false);
    }
    fixture.cycles(0, 1);
    fixture.clock(.entry, 3, 1);
    fixture.clock(.exit, 3, 1);
    try fixture.refresh();
    try fixture.expect(false);
}

test "Ethereum raw boundary clock binds full u64 span and exact native limit" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_][2]u64{
        .{ 0, 0 },                       .{ 1 << 24, 1 },                 .{ (1 << 24) - 1, 2 },
        .{ 0, (1 << 24) + 1 },           .{ 1 << 32, 1 },                 .{ 0, 1 << 32 },
        .{ core.fields.m31.Modulus, 1 }, .{ 0, core.fields.m31.Modulus },
    }) |range| {
        fixture.cycles(range[0], range[1]);
        try fixture.refresh();
        try fixture.expect(false);
    }
    fixture.cycles(0, 1 << 24);
    try fixture.refresh();
    try fixture.expect(true);
    // Runtime rejects overflow rather than generating a wrapped end witness.
    fixture.cycles(std.math.maxInt(u64), 1);
    try std.testing.expectError(error.Overflow, support.clockAuxValue(.{ .cycle_bit = .{ .kind = .end, .bit = 0 } }, &fixture.statement, &fixture.native));
    // AIR independently rejects upper limbs even with stale low-bit witnesses.
    fixture.inputs[support.span.canonical_layout.first_cycle_start + 3] = QM31.one();
    try fixture.expect(false);
}

test "Ethereum raw boundary clock binds every raw limb and auxiliary bits" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.cycles(1, 2);
    for (0..32) |reg| {
        fixture.clock(.entry, reg, 3);
        fixture.clock(.exit, reg, 11);
    }
    try fixture.refresh();
    try fixture.expect(true);
    // Every raw limb, not a second reconstructed clock vector, joins the bits.
    for (CLOCK_START..AUX_START) |index| {
        const saved = fixture.inputs[index];
        fixture.inputs[index] = saved.add(QM31.one());
        try fixture.expect(false);
        fixture.inputs[index] = saved;
    }
    // Both ends of every clock's bit decomposition and every cycle bit are
    // linked. A non-boolean witness must fail even if its source is private.
    for (0..64) |clock_index| for ([_]usize{ 0, 25 }) |bit| {
        const index = AUX_START + clock_index * support.CLOCK_BIT_COUNT + bit;
        const saved = fixture.inputs[index];
        fixture.inputs[index] = QM31.one().sub(saved);
        try fixture.expect(false);
        fixture.inputs[index] = saved;
    };
    for (AUX_START + 64 * support.CLOCK_BIT_COUNT..INPUT_COUNT) |index| {
        const saved = fixture.inputs[index];
        fixture.inputs[index] = QM31.one().sub(saved);
        try fixture.expect(false);
        fixture.inputs[index] = saved;
    }
    fixture.inputs[AUX_START] = QM31.fromBase(M31.fromCanonical(2));
    try fixture.expect(false);
    try std.testing.expectError(error.InvalidPublicSumClockSourceV4, support.clockAuxSourceAt(support.CLOCK_AUX_INPUT_COUNT));
    try std.testing.expectError(error.InvalidPublicSumClockSourceV4, support.clockAuxValue(.{ .register_bit = .{ .boundary = .entry, .register = 0, .bit = 26 } }, &fixture.statement, &fixture.native));
    try std.testing.expectError(error.InvalidPublicSumClockSourceV4, support.clockAuxValue(.{ .cycle_bit = .{ .kind = .first, .bit = 25 } }, &fixture.statement, &fixture.native));
}

test "Ethereum raw boundary clock preserves private routing and canonical claim tail" {
    const allocator = std.testing.allocator;
    var built = try support.build(allocator, 2);
    defer built.deinit(allocator);
    try std.testing.expectEqual(try support.inputCount(2), built.bindings.len);
    const tail_start = built.bindings.len - support.CHALLENGE_WORD_COUNT - support.CANONICAL_CLAIM_WORD_COUNT;
    const aux_start = tail_start - support.CLOCK_AUX_INPUT_COUNT;
    for (built.bindings[aux_start..tail_start], 0..) |binding, index|
        try std.testing.expectEqualDeep(support.InputSourceV4{ .clock_aux = try support.clockAuxSourceAt(index) }, binding);
    for (built.bindings[tail_start..][0..support.CHALLENGE_WORD_COUNT]) |binding|
        try std.testing.expect(std.meta.activeTag(binding) == .relation_challenge_word);
    for (built.bindings[tail_start + support.CHALLENGE_WORD_COUNT ..], 0..) |binding, index|
        try std.testing.expectEqualDeep(support.InputSourceV4{ .canonical_claim_word = .{ .item = @intCast(index / 4), .limb = @intCast(index % 4) } }, binding);

    const values = [_]QM31{QM31.zero()} ** support.CLOCK_AUX_INPUT_COUNT;
    const uses = [_]u32{1} ** support.CLOCK_AUX_INPUT_COUNT;
    const view = .{ .bindings = built.bindings[aux_start..tail_start], .values = &values, .use_counts = &uses };
    var prepared = try routing.Prepared.init(allocator, view);
    defer prepared.deinit();
    try prepared.validate(view);
    try std.testing.expectEqual(support.CLOCK_AUX_INPUT_COUNT, prepared.rows.len);
    try std.testing.expectEqual(@as(usize, 0), prepared.claims.len);
    for (prepared.rows) |row| {
        // Same row16 circuit input, with no fake claim source or publication.
        try std.testing.expect(row[3].isZero());
        try std.testing.expect(row[4].isZero());
        try std.testing.expectEqual(@as(u32, 42), row[8].toU32());
    }
}
