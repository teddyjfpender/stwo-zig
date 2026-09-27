const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const component = @import("blake3_round_call.zig");
const arithmetic = @import("blake3_round_packed.zig");
const topology = @import("blake3_compression_plan.zig");
const partition = @import("blake3_compression_partition.zig");
const support = @import("test_support.zig");
const M = core.fields.m31.M31;
const Evaluation = struct { valid: bool, output: [16]u32 };
fn evaluate(d: *const component.Definition, row: *const component.Row, expected: *const component.Row) !Evaluation {
    const a = std.testing.allocator;
    const values = try support.evaluateArena(a, &d.arena, row);
    defer a.free(values);
    const admitted = try support.evaluateArena(a, &d.arena, expected);
    defer a.free(admitted);
    var result = Evaluation{ .valid = true, .output = @splat(0) };
    for (d.arena.constraintsView()) |constraint| result.valid = result.valid and values[lang.types.idIndex(constraint.root)].isZero();
    for (d.arena.effectsView(), 0..) |event, i| {
        const tuple = d.arena.effectValues(@enumFromInt(i)).?;
        var words: [6]u32 = undefined;
        for (tuple, 0..) |id, j| words[j] = values[lang.types.idIndex(id)].toU32();
        const schema = event.binding.?.schema;
        if (schema == lang.relation.id(.range_check_8_8)) {
            result.valid = result.valid and words[0] < 256 and words[1] < 256;
        } else if (schema == lang.relation.id(.bitwise)) {
            result.valid = result.valid and words[0] < 256 and words[1] < 256 and words[2] < 256 and words[3] == 2 and words[0] ^ words[1] == words[2];
        } else if (schema == lang.relation.id(.recursion_wire)) {
            // External caller ledger is independent of a mutated local row.
            for (tuple) |id| result.valid = result.valid and values[lang.types.idIndex(id)].eql(admitted[lang.types.idIndex(id)]);
        } else return error.UnexpectedRoundRelation;
        const weight = lang.types.idIndex(event.liveness.?);
        result.valid = result.valid and values[weight].eql(admitted[weight]);
    }
    for (d.ports.output, &result.output) |word, *out| for (word, 0..) |id, byte| {
        out.* |= values[lang.types.idIndex(id)].toU32() << @as(u5, @intCast(byte * 8));
    };
    return result;
}
fn schedule(group: partition.Group) component.Schedule {
    return .{ .circuit = 19, .input = group.inputs, .output = group.outputs, .uses = group.output_uses };
}
test "typed BLAKE3 round preserves all seven canonical compression groups" {
    const a = std.testing.allocator;
    var definition = try component.build(a);
    defer definition.deinit();
    var degree = try lang.degree.analyze(a, &definition.arena);
    defer degree.deinit();
    try std.testing.expectEqual(@as(u32, 2), degree.maximumConstraintDegree());
    const digest = try lang.digest.computeIdentity(&definition.arena);
    std.debug.print("BLAKE3_ROUND_TYPED main={d} fixed={d} constraints={d} events={d} digest={x}\n", .{ component.PHYSICAL_MAIN_COLUMN_COUNT, component.PREPROCESSED_COLUMN_COUNT, component.DIRECT_CONSTRAINT_COUNT, component.RELATION_EVENT_COUNT, digest.bytes });
    var random = std.Random.DefaultPrng.init(0x912fabcd);
    const graph = topology.canonical();
    const plan = try partition.build(8);
    for (0..8) |_| {
        var cv: [8]u32 = undefined;
        var block: [16]u32 = undefined;
        for (&cv) |*word| word.* = random.random().int(u32);
        for (&block) |*word| word.* = random.random().int(u32);
        const counter = random.random().int(u64);
        const len = random.random().uintLessThan(u32, 65);
        const flags = random.random().int(u32);
        var wires: [topology.WIRE_COUNT]u32 = undefined;
        wires[0..32].* = cv ++ core.crypto.blake3_compression.IV[0..4].* ++ [4]u32{ @truncate(counter), @truncate(counter >> 32), len, flags } ++ block;
        const trace = try core.crypto.blake3_compression.trace(cv, block, counter, len, flags);
        for (plan.groups[0..plan.count]) |group| {
            var input: [32]u32 = undefined;
            for (&input, group.inputs) |*word, wire| word.* = wires[wire];
            const witness = try arithmetic.witness(input);
            const row = try component.logicalRow(schedule(group), input);
            const result = try evaluate(&definition, &row, &row);
            try std.testing.expect(result.valid);
            try std.testing.expectEqualDeep(witness.output, result.output);
            for (graph.g[group.first..][0..group.count], trace.calls[group.first..][0..group.count]) |call, native| for (call.output, native.output) |wire, word| {
                wires[wire] = word;
            };
            for (group.outputs, witness.output) |wire, word| try std.testing.expectEqual(wires[wire], word);
        }
    }
}
test "typed BLAKE3 round rejects all coordinate and caller-binding mutations" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var input: [32]u32 = undefined;
    for (&input, 0..) |*word, i| word.* = @as(u32, @intCast(i)) *% 0x89abcdef;
    const group = (try partition.build(8)).groups[0];
    const row = try component.logicalRow(schedule(group), input);
    for (0..component.LOGICAL_INPUT_COUNT) |i| {
        var changed = row;
        changed[i] = changed[i].add(M.one());
        try std.testing.expect(!(try evaluate(&definition, &changed, &row)).valid);
    }
    var bad = schedule(group);
    bad.circuit = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidBlake3RoundSchedule, component.fixedRow(bad));
    const fixed = try component.fixedRow(schedule(group));
    try std.testing.expectEqualSlices(M, row[component.PHYSICAL_MAIN_COLUMN_COUNT..], fixed[component.PHYSICAL_MAIN_COLUMN_COUNT..]);
}
