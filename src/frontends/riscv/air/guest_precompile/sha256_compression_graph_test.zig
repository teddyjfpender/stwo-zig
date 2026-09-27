//! Exact typed equations and shared-table/word-wire closure, not yet a STARK.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/mod.zig");
const support = @import("../../recursion/air/test_support.zig");
const tables = @import("../lookups/tables/schema.zig");
const graph = @import("sha256_compression_graph.zig");
const sha = @import("sha256_compression.zig");
const calls = @import("sha256_packed_call.zig");
const source = @import("sha256_packed_source.zig");
const program = @import("sha256_word_program.zig");
const M = core.fields.m31.M31;
pub const Counter = std.AutoHashMap([6]u32, i64);
pub fn add(counter: *Counter, tuple: [6]u32, weight: i64) !void {
    const item = try counter.getOrPut(tuple);
    if (!item.found_existing) item.value_ptr.* = 0;
    item.value_ptr.* += weight;
}
fn wireTuple(call: u32, wire: u32, value: u32) [6]u32 {
    return .{ call, wire, value & 255, (value >> 8) & 255, (value >> 16) & 255, value >> 24 };
}
pub fn emit(definition: anytype, row: []const M, counter: *Counter) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, row);
    defer std.testing.allocator.free(values);
    for (definition.arena.constraintsView()) |c| if (!values[lang.types.idIndex(c.root)].isZero()) return error.InvalidShaEquation;
    for (definition.arena.effectsView(), 0..) |event, i| {
        const ids = definition.arena.effectValues(@enumFromInt(i)).?;
        var tuple: [6]u32 = @splat(0);
        var fields: [6]M = undefined;
        for (ids, 0..) |id, j| {
            fields[j] = values[lang.types.idIndex(id)];
            tuple[j] = fields[j].toU32();
        }
        const schema = event.binding.?.schema;
        if (schema == lang.relation.id(.recursion_wire)) {
            const weight: i64 = @intCast(values[lang.types.idIndex(event.liveness.?)].toU32());
            try add(counter, tuple, if (event.binding.?.role == .emit) weight else -weight);
        } else if (schema == lang.relation.id(.range_check_8_8)) {
            _ = tables.indexBase(.range_check_8_8, fields[0..ids.len]) catch return error.InvalidShaLookup;
        } else if (schema == lang.relation.id(.bitwise)) {
            _ = tables.indexBase(.bitwise, fields[0..ids.len]) catch return error.InvalidShaLookup;
        } else return error.UnexpectedShaRelation;
    }
}
fn operation(comptime kind: program.Kind, definition: anytype, op: graph.Operation(kind), g: *const graph.Graph, call: u32, values: *[graph.wire_count]u32, counter: *Counter) !void {
    const Air = calls.ForKind(kind);
    var input: [program.inputCount(kind)]u32 = undefined;
    for (op.input, 0..) |id, i| input[i] = values[id];
    const row = try Air.row(call, op, &g.uses, input);
    try emit(definition, &row, counter);
    const output: [program.outputCount(kind)]u32 = switch (kind) {
        .round => blk: {
            const r = sha.round(input[0..8].*, input[8], input[9]);
            break :blk .{ r[0], r[4] };
        },
        .schedule => .{sha.sigmaSmall1(input[0]) +% input[1] +% sha.sigmaSmall0(input[2]) +% input[3]},
        .feed_forward => .{input[0] +% input[1]},
    };
    for (op.output, output) |id, value| values[id] = value;
}
const Fault = enum { none, constant, caller_input, namespace, output };
fn check(initial: sha.State, block: [64]u8, fault: Fault) !void {
    const a = std.testing.allocator;
    const g = graph.build();
    var rd = try calls.ForKind(.round).build(a);
    defer rd.deinit();
    var sd = try calls.ForKind(.schedule).build(a);
    defer sd.deinit();
    var fd = try calls.ForKind(.feed_forward).build(a);
    defer fd.deinit();
    var input_def = try source.build(a);
    defer input_def.deinit();
    var counter = Counter.init(a);
    defer counter.deinit();
    var values: [graph.wire_count]u32 = undefined;
    const inputs = graph.sources(initial, block);
    @memcpy(values[0..graph.source_count], &inputs);
    for (inputs[0..24], 0..) |value, i| try add(&counter, wireTuple(17, @intCast(graph.input_boundary_offset + i), value), 1);
    for (inputs, 0..) |value, i| {
        const changed = if ((fault == .constant and i == 24) or (fault == .caller_input and i == 0)) value +% 1 else value;
        const row = try source.row(17, @intCast(i), changed, &g.uses);
        try emit(&input_def, &row, &counter);
    }
    for (g.expansion) |op| try operation(.schedule, &sd, op, &g, 17, &values, &counter);
    for (g.rounds, 0..) |op, i| try operation(.round, &rd, op, &g, if (fault == .namespace and i == 32) 18 else 17, &values, &counter);
    for (g.feed_forward) |op| try operation(.feed_forward, &fd, op, &g, 17, &values, &counter);
    const reference_trace = sha.witness(initial, block);
    for (g.expansion, 16..) |op, i| try std.testing.expectEqual(reference_trace.schedule[i], values[op.output[0]]);
    for (g.rounds, 0..) |op, i| {
        try std.testing.expectEqual(reference_trace.states[i + 1][0], values[op.output[0]]);
        try std.testing.expectEqual(reference_trace.states[i + 1][4], values[op.output[1]]);
    }
    const expected = sha.compress(initial, block);
    for (g.output, expected, 0..) |wire, value, i| {
        try std.testing.expectEqual(value, values[wire]);
        try add(&counter, wireTuple(17, wire, if (fault == .output and i == 0) value +% 1 else value), -1);
    }
    var iterator = counter.valueIterator();
    while (iterator.next()) |count| if (count.* != 0) return error.UnclosedShaGraph;
}
test "SHA graph closes complete typed compression and rejects broken boundaries" {
    var rng = std.Random.DefaultPrng.init(0x5348414752415048);
    for (0..4) |i| {
        var block: [64]u8 = undefined;
        var initial: sha.State = undefined;
        rng.random().bytes(&block);
        for (&initial) |*word| word.* = if (i == 0) 0xffffffff else rng.random().int(u32);
        try check(initial, block, .none);
        if (i == 0) {
            try std.testing.expectError(error.InvalidShaEquation, check(initial, block, .constant));
            try std.testing.expectError(error.UnclosedShaGraph, check(initial, block, .caller_input));
            try std.testing.expectError(error.UnclosedShaGraph, check(initial, block, .namespace));
            try std.testing.expectError(error.UnclosedShaGraph, check(initial, block, .output));
        }
    }
}
test "SHA graph is acyclic and all sources and operations have live consumers" {
    const g = graph.build();
    for (g.uses) |count| try std.testing.expect(count > 0);
    for (g.expansion) |op| for (op.input) |id| {
        try std.testing.expect(id < op.output[0]);
    };
    for (g.rounds) |op| for (op.input) |id| {
        try std.testing.expect(id < op.output[0]);
    };
    for (g.feed_forward) |op| for (op.input) |id| {
        try std.testing.expect(id < op.output[0]);
    };
    inline for (.{ program.Kind.round, .schedule, .feed_forward }) |kind| {
        const Air = calls.ForKind(kind);
        var d = try Air.build(std.testing.allocator);
        defer d.deinit();
        const id = try lang.digest.computeIdentity(&d.arena);
        std.debug.print("SHA_CALL kind={s} main={d} fixed={d} digest={s}\n", .{ @tagName(kind), Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.PREPROCESSED_COLUMN_COUNT, std.fmt.bytesToHex(id.bytes, .lower) });
    }
    var d = try source.build(std.testing.allocator);
    defer d.deinit();
    const id = try lang.digest.computeIdentity(&d.arena);
    std.debug.print("SHA_SOURCE digest={s}\n", .{std.fmt.bytesToHex(id.bytes, .lower)});
}
