//! Eight canonical G calls share typed SSA values within one compression round.
//! Arithmetic comes from the existing packed G author; no equations are copied.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const g_arithmetic = @import("blake3_g_packed.zig");
const topology = @import("blake3_compression_plan.zig");
const partition = @import("blake3_compression_partition.zig");
const INTERNAL_COLUMN_COUNT = g_arithmetic.COLUMN_COUNT - 24;
pub const COLUMN_COUNT = 128 + 8 * INTERNAL_COLUMN_COUNT;
pub const CONSTRAINT_COUNT = 8 * g_arithmetic.CONSTRAINT_COUNT;
pub const EVENT_COUNT = 64 + 8 * (g_arithmetic.EVENT_COUNT - 12);
pub const Word = g_arithmetic.Typed.Word;
pub const Row = [COLUMN_COUNT]core.fields.m31.M31;
pub const Ports = struct { input: [32]Word, output: [16]Word };
pub const Definition = struct {
    arena: lang.ir.Arena,
    ports: Ports,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
};
pub fn build(a: std.mem.Allocator) !Definition {
    var ops = g_arithmetic.Typed{ .arena = lang.ir.Arena.init(a) };
    errdefer ops.arena.deinit();
    const ports = try populate(&ops);
    try lang.validate.validate(&ops.arena);
    if (ops.columns != COLUMN_COUNT or ops.arena.constraintsView().len != CONSTRAINT_COUNT or ops.arena.effectsView().len != EVENT_COUNT) return error.InvalidBlake3RoundGeometry;
    return .{ .arena = ops.arena, .ports = ports };
}
pub fn populate(ops: *g_arithmetic.Typed) !Ports {
    const group = (try partition.build(8)).groups[0];
    const graph = topology.canonical();
    var wires: [topology.WIRE_COUNT]Word = undefined;
    var ports: Ports = undefined;
    for (&ports.input, group.inputs[0..32]) |*word, wire| {
        word.* = try ops.word(true);
        wires[wire] = word.*;
    }
    for (graph.g[0..8]) |call| {
        var input: [6]Word = undefined;
        for (&input, call.input) |*word, wire| word.* = wires[wire];
        const output = try core.crypto.blake3_compression.g(g_arithmetic.Typed, ops, input);
        for (call.output, output) |wire, word| wires[wire] = word;
    }
    for (&ports.output, group.outputs[0..16]) |*word, wire| word.* = wires[wire];
    return ports;
}
pub fn witness(input: [32]u32) !struct { row: Row, output: [16]u32 } {
    const group = (try partition.build(8)).groups[0];
    const graph = topology.canonical();
    var wires: [topology.WIRE_COUNT]u32 = undefined;
    var row: Row = undefined;
    for (input, group.inputs[0..32], 0..) |word, wire, i| {
        wires[wire] = word;
        for (0..4) |byte| row[4 * i + byte] = core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(byte * 8))) & 255);
    }
    var next: usize = 128;
    for (graph.g[0..8]) |call| {
        var words: [6]u32 = undefined;
        for (&words, call.input) |*word, wire| word.* = wires[wire];
        const prepared = try @import("blake3_g_packed_witness.zig").withOutput(words);
        @memcpy(row[next..][0..INTERNAL_COLUMN_COUNT], prepared.row[24..]);
        next += INTERNAL_COLUMN_COUNT;
        for (call.output, prepared.output) |wire, word| wires[wire] = word;
    }
    var output: [16]u32 = undefined;
    for (&output, group.outputs[0..16]) |*word, wire| word.* = wires[wire];
    std.debug.assert(next == COLUMN_COUNT);
    return .{ .row = row, .output = output };
}
