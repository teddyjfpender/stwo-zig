const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const subject = @import("recursive_common_ethereum_incremental_leaf_global_binding_v1.zig");
const support = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
const arithmetic = frontend.recursion.arithmetic_circuit;
const projection = frontend.recursion.segment_leaf_local_projection_v3;
const layout = frontend.recursion.span_statement.canonical_layout;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const GLOBAL = subject.WORD_COUNT;
const AUX = GLOBAL + subject.WORD_COUNT;
const CLOCK = AUX + subject.AUX_COUNT;
const CLOCK_AUX = CLOCK + support.CLOCK_LIMB_COUNT;
const COUNT = CLOCK_AUX + support.CLOCK_AUX_INPUT_COUNT;
const Fixture = struct {
    circuit: arithmetic.Circuit,
    inputs: []QM31,
    global: [subject.WORD_COUNT]u32 = @splat(0),
    local: [subject.WORD_COUNT]u32 = @splat(0),
    fn init() !Fixture {
        var builder = arithmetic.Builder.initDefault(std.testing.allocator);
        defer builder.deinit();
        var values: [COUNT]arithmetic.Value = undefined;
        for (&values, 0..) |*value, index| value.* = try builder.input(@intCast(index));
        try subject.constrain(&builder, values[0..GLOBAL], values[GLOBAL..AUX], values[AUX..CLOCK]);
        try support.constrainRawClocks(&builder, values[0..GLOBAL], values[CLOCK..CLOCK_AUX], values[CLOCK_AUX..]);
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        const inputs = try std.testing.allocator.alloc(QM31, COUNT);
        @memset(inputs, QM31.zero());
        return .{ .circuit = circuit, .inputs = inputs };
    }
    fn deinit(self: *Fixture) void {
        self.circuit.deinit();
        std.testing.allocator.free(self.inputs);
    }
    fn range(self: *Fixture, first: u64, count: u64, total: u64) void {
        self.global[layout.first_segment_start] = 1;
        for ([_]usize{ layout.first_cycle_start, layout.executed_cycle_count_start, layout.total_cycles_start }, [_]u64{ first, count, total }) |start, value| for (0..4) |limb| {
            self.global[start + limb] = @intCast((value >> @as(u6, @intCast(limb * 16))) & 65535);
        };
    }
    fn refresh(self: *Fixture) !void {
        for (&self.local, 0..) |*word, index| word.* = switch (try projection.canonicalWordSourceV1(index)) {
            .global_word => |source| self.global[source],
            .local_cycle_count_limb => |limb| self.global[layout.executed_cycle_count_start + @as(usize, limb)],
            .zero => 0,
        };
        for (self.local, self.inputs[0..GLOBAL]) |word, *input| input.* = base(word);
        for (self.global, self.inputs[GLOBAL..AUX]) |word, *input| input.* = base(word);
        for (self.inputs[AUX..CLOCK], 0..) |*input, index| input.* = try subject.auxValue(try subject.sourceAt(index), &self.global);
        const raw = [_]M31{M31.zero()} ** support.segment_v2.FIXED_CANONICAL_WORDS;
        @memset(self.inputs[CLOCK..CLOCK_AUX], QM31.zero());
        for (self.inputs[CLOCK_AUX..], 0..) |*input, index| input.* = try support.clockAuxValue(try support.clockAuxSourceAt(index), &self.local, &raw);
    }
    fn expect(self: *Fixture, accepted: bool) !void {
        var evaluation = try self.circuit.evaluate(std.testing.allocator, self.inputs);
        defer evaluation.deinit();
        try std.testing.expectEqual(accepted, try self.circuit.outputsAreZero(evaluation.values));
    }
};
fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

test "Ethereum global projection accepts full u64 positions with unchanged local clocks" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_][3]u64{ .{ 0, 1, 1 }, .{ 65535, 2, 131072 }, .{ (1 << 32) - 1, 0x10003, 1 << 48 }, .{ (1 << 48) - 1, 1 << 24, std.math.maxInt(u64) }, .{ std.math.maxInt(u64) - 1, 1, std.math.maxInt(u64) } }) |range| {
        fixture.range(range[0], range[1], range[2]);
        try fixture.refresh();
        try fixture.expect(true);
    }
    try std.testing.expectError(error.InvalidGlobalProjectionInput, subject.sourceAt(subject.AUX_COUNT));
}

test "Ethereum global projection binds every word endpoint and auxiliary witness" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.range((1 << 32) - 1, 0x10003, 1 << 48);
    try fixture.refresh();
    try fixture.expect(true);
    // Includes program/namespace, CPU boundaries, continuation roots and all
    // projected integer words: either side changing alone breaks this graph.
    for (fixture.inputs[0..CLOCK]) |*input| {
        const saved = input.*;
        input.* = input.add(QM31.one());
        try fixture.expect(false);
        input.* = saved;
    }
    const saved = fixture.inputs[AUX];
    fixture.inputs[AUX] = QM31.fromM31Array(.{ M31.zero(), M31.one(), M31.zero(), M31.zero() });
    try fixture.expect(false);
    fixture.inputs[AUX] = saved;
}

test "Ethereum global projection rejects overflow reversal aliases and shifted initial leaf" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.range(std.math.maxInt(u64), 1, std.math.maxInt(u64));
    try std.testing.expectError(error.Overflow, fixture.refresh());
    fixture.range(10, 2, 11);
    try std.testing.expectError(error.Overflow, fixture.refresh());
    fixture.range(0, 1, 2);
    fixture.global[layout.first_segment_start] = 0;
    try fixture.refresh();
    try fixture.expect(true);
    fixture.range(1, 1, 2);
    fixture.global[layout.first_segment_start] = 0;
    try fixture.refresh();
    try fixture.expect(false);
    fixture.range(0, (1 << 24) + 1, 1 << 25);
    try fixture.refresh();
    try fixture.expect(false);
    fixture.range(0, 1, 2);
    try fixture.refresh();
    // A canonical M31 representative cannot serve as a noncanonical u16.
    fixture.inputs[GLOBAL + layout.first_cycle_start] = base(65536);
    try fixture.expect(false);
    fixture.global[layout.first_cycle_start] = 65536;
    try std.testing.expectError(error.InvalidGlobalProjectionInput, fixture.refresh());
}

test "Ethereum global projection full program preserves canonical tail and exact local fanout" {
    const allocator = std.testing.allocator;
    const elf = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig").programElf();
    const admission = try support.program_admission.ProgramAdmissionV1.createFromElf(allocator, &elf);
    defer admission.deinit();
    var local = try support.buildWithProgram(allocator, 2, admission);
    defer local.deinit(allocator);
    var global = try support.buildWithGlobalProgram(allocator, 2, admission);
    defer global.deinit(allocator);
    try std.testing.expectEqual(local.bindings.len + subject.WORD_COUNT + subject.AUX_COUNT, global.bindings.len);
    const tail = support.CHALLENGE_WORD_COUNT + support.CANONICAL_CLAIM_WORD_COUNT;
    try std.testing.expectEqualDeep(local.bindings[local.bindings.len - tail ..], global.bindings[global.bindings.len - tail ..]);
    const routing = @import("recursive_common_ethereum_incremental_leaf_statement_routing_v4.zig");
    const local_plan = try routing.Plan.init(local.bindings, local.circuit.useCounts()[0..local.bindings.len], @splat(1));
    const global_plan = try routing.Plan.init(global.bindings, global.circuit.useCounts()[0..global.bindings.len], @splat(2));
    try std.testing.expect(local_plan.local_publication);
    try std.testing.expect(!global_plan.local_publication);
    var first_global: ?usize = null;
    var globals: usize = 0;
    var auxiliaries: usize = 0;
    for (global.bindings, 0..) |binding, index| switch (binding) {
        .global_statement_word => |word| {
            try std.testing.expectEqual(globals, word);
            try std.testing.expect(global.circuit.useCounts()[index] > 0);
            if (first_global == null) first_global = index;
            globals += 1;
        },
        .global_aux => {
            try std.testing.expect(global.circuit.useCounts()[index] > 0);
            auxiliaries += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(subject.WORD_COUNT, globals);
    try std.testing.expectEqual(subject.AUX_COUNT, auxiliaries);
    // Same global graph's local source schedule loses exactly its former
    // publication consumer, independent of added arithmetic wire fanout.
    var diagnostic_plan = global_plan;
    diagnostic_plan.local_publication = true;
    for (0..subject.WORD_COUNT) |word| {
        const row: frontend.recursion.air.statement_input_witness.Row = .{ .row_mask = 1, .segment_mask = 1, .binary_mask = 0, .derived_parent_mask = 0, .verifier_id = 0, .statement_scope = 0, .word_index = @intCast(word) };
        try std.testing.expectEqual(global_plan.extraUses(row) + 1, diagnostic_plan.extraUses(row));
    }
    const index = first_global.?;
    const saved = global.bindings[index];
    global.bindings[index] = global.bindings[index + 1];
    try std.testing.expectError(error.InvalidEthereumStatementRouting, routing.Plan.init(global.bindings, global.circuit.useCounts()[0..global.bindings.len], @splat(2)));
    global.bindings[index] = saved;
}
