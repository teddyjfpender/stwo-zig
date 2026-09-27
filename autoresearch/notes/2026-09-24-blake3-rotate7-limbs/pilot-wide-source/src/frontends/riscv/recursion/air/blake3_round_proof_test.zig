const std = @import("std");
const core = @import("stwo_core");
const round = @import("blake3_round_call.zig");
const arithmetic = @import("blake3_round_packed.zig");
const topology = @import("blake3_compression_plan.zig");
const partition = @import("blake3_compression_partition.zig");
const f = @import("blake3_proof_fixture.zig");
const M = core.fields.m31.M31;
test "BLAKE3 round compression committed proof binds inputs outputs and fixed schedule" {
    try prove({}, void);
}
pub fn prove(protocol: anytype, comptime Observer: type) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const graph = topology.canonical();
    const plan = try partition.build(8);
    const cv = core.crypto.blake3_compression.IV;
    var block: [16]u32 = undefined;
    for (&block, 0..) |*word, i| word.* = @as(u32, @intCast(i)) *% 0x89abcdef;
    const counter: u64 = 0x123456789abcdef0;
    const length: u32 = 63;
    const flags: u32 = 11;
    const initial = cv ++ core.crypto.blake3_compression.IV[0..4].* ++ [4]u32{ @truncate(counter), @truncate(counter >> 32), length, flags } ++ block;
    const output = try core.crypto.blake3_compression.compress(cv, block, counter, length, flags);
    var wires: [topology.WIRE_COUNT]u32 = undefined;
    wires[0..32].* = initial;
    var rounds: [7]round.Row = undefined;
    var fixed: [7]round.Row = undefined;
    var reads: [32]u32 = @splat(0);
    for (plan.groups[0..7], &rounds, &fixed) |group, *row, *trusted| {
        var input: [32]u32 = undefined;
        for (&input, group.inputs) |*word, wire| {
            word.* = wires[wire];
            if (wire < 32) reads[wire] += 1;
        }
        const schedule = round.Schedule{ .circuit = 19, .input = group.inputs, .output = group.outputs, .uses = group.output_uses };
        row.* = try round.logicalRow(schedule, input);
        trusted.* = try round.fixedRow(schedule);
        const witness = try arithmetic.witness(input);
        for (group.outputs, witness.output) |wire, word| wires[wire] = word;
    }
    var xors: [16]f.xor.Row = undefined;
    var trusted_xors: [16]f.xor.Row = undefined;
    for (graph.xor, &xors, &trusted_xors, output) |call, *row, *trusted, expected| {
        const input = [2]u32{ wires[call.input[0]], wires[call.input[1]] };
        try std.testing.expectEqual(expected, input[0] ^ input[1]);
        for (call.input) |wire| if (wire < 32) {
            reads[wire] += 1;
        };
        const schedule = f.xor.Schedule{ .circuit = 19, .input = call.input, .output = call.output, .uses = 1 };
        row.* = try f.xor.logicalRow(schedule, input);
        trusted.* = try f.xor.fixedRow(schedule);
    }
    var boundaries: [48]f.boundary.Row = undefined;
    for (initial, reads, 0..) |word, count, i| boundaries[i] = try f.boundary.logicalRow(19, @intCast(i), M.fromCanonical(count), word);
    for (output, graph.output, 0..) |word, wire, i| boundaries[32 + i] = try f.boundary.logicalRow(19, wire, M.one().neg(), word);
    const Airs = .{ round, f.xor, f.boundary };
    const F = @import("blake3_component_roster.zig").ForAirs(Airs);
    const logs = [3]u32{ 3, 4, 6 };
    const rows = .{ try f.padded(round, a, &rounds, logs[0]), try f.padded(f.xor, a, &xors, logs[1]), try f.padded(f.boundary, a, &boundaries, logs[2]) };
    var pp: std.ArrayList(f.Column) = .empty;
    inline for (Airs, .{ &fixed, &trusted_xors, &boundaries }, logs) |Air, values, log| try f.project(Air, a, values, log, 0, &pp);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &pp);
    const wrong = try a.dupe(f.Column, pp.items);
    const changed = try a.dupe(M, wrong[0].values);
    changed[0] = changed[0].add(M.one());
    wrong[0].values = changed;
    const gate = @import("blake3_proof_gate_test_support.zig");
    if (comptime @TypeOf(protocol) == void) {
        try gate.runFor(F, a, rows, logs, pp.items, wrong);
    } else {
        const parameters: [3][0]M = @splat(.{});
        try gate.ForBackend(f.Cpu).runForParametersProtocol(F, a, rows, logs, pp.items, wrong, parameters, protocol, Observer);
    }
}
