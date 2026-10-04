const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../lang/mod.zig");
const air = @import("../sha256_memory_caller.zig");
const record = @import("../sha256_memory_record.zig");
const sha = @import("../sha256_compression.zig");
const support = @import("../../../recursion/air/test_support.zig");
const tables = @import("../../lookups/tables/schema.zig");
const M = core.fields.m31.M31;
fn fixture(reverse: bool) record.Record {
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(i * 73 + 9);
    const state: sha.State = .{ 0, 0xffffffff, 0x80000000, 1, 123, 0xabcd, 0x12345678, 0xeeeeeeee };
    return .{ .execution_clock = 17, .pc = 1024, .state_register = 3, .block_register = 9, .state_ptr = if (reverse) 8192 else 4096, .block_ptr = if (reverse) 4096 else 8192, .pointer_previous_clocks = .{ 1, 2 }, .memory_previous_clocks = @splat(3), .state = state, .block = block, .output = sha.compress(state, block) };
}
fn evaluate(d: *const air.Definition, row: *const air.Row) !void {
    const values = try support.evaluateArena(std.testing.allocator, &d.arena, row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |c| if (!values[lang.types.idIndex(c.root)].isZero()) return error.InvalidShaCallerConstraint;
    for (d.arena.effectsView(), 0..) |event, i| {
        const ids = d.arena.effectValues(@enumFromInt(i)).?;
        var fields: [7]M = undefined;
        for (ids, 0..) |id, j| fields[j] = values[lang.types.idIndex(id)];
        if (values[lang.types.idIndex(event.liveness.?)].isZero()) continue;
        inline for (.{ tables.Kind.range_check_8_8, tables.Kind.range_check_8_8_4, tables.Kind.range_check_20 }) |kind| {
            if (event.binding.?.schema == lang.relation.id(switch (kind) {
                .range_check_8_8 => .range_check_8_8,
                .range_check_8_8_4 => .range_check_8_8_4,
                .range_check_20 => .range_check_20,
                else => unreachable,
            })) {
                _ = tables.indexBase(kind, fields[0..ids.len]) catch return error.InvalidShaCallerLookup;
            }
        }
    }
}
test "SHA memory caller binds disjoint pointers and exact bounded access clocks" {
    var d = try air.build(std.testing.allocator);
    defer d.deinit();
    const identity = try lang.digest.computeIdentity(&d.arena);
    std.debug.print("SHA_MEMORY_CALLER constraints={d} events={d} digest={s}\n", .{ d.arena.constraintsView().len, d.arena.effectsView().len, std.fmt.bytesToHex(identity.bytes, .lower) });
    try std.testing.expectEqual(air.DIRECT_CONSTRAINT_COUNT, d.arena.constraintsView().len);
    try std.testing.expectEqual(air.RELATION_EVENT_COUNT, d.arena.effectsView().len);
    for ([_]bool{ false, true }) |reverse| {
        const input = fixture(reverse);
        const row = try air.row(input);
        try evaluate(&d, &row);
        for ([_]usize{ air.Layout.register_clock, air.Layout.memory_clock, air.Layout.pointer_words, air.Layout.addresses + 13, air.Layout.gaps + 11, air.Layout.register_gap, air.Layout.register_difference_inverse }) |column| {
            var wrong = row;
            wrong[column] = wrong[column].add(M.one());
            try std.testing.expectError(error.InvalidShaCallerConstraint, evaluate(&d, &wrong));
        }
        var alias = input;
        alias.block_ptr = alias.state_ptr;
        try std.testing.expectError(error.OverlappingShaSpans, air.row(alias));
        var wrong = input;
        wrong.output[0] ^= 1;
        try std.testing.expectError(error.InvalidShaOutput, air.row(wrong));
        var late = input;
        late.memory_previous_clocks[0] = 100;
        try std.testing.expectError(error.InvalidShaPreviousClock, air.row(late));
    }
    const padding: air.Row = @splat(M.zero());
    try evaluate(&d, &padding);
}

fn closed(caller_row: *const air.Row, input: record.Record) !void {
    const helpers = @import("sha256_compression_graph_test.zig");
    const provider = @import("../sha256_compression_rows.zig");
    const source = @import("../sha256_packed_source.zig");
    const a = std.testing.allocator;
    var d = try air.build(a);
    defer d.deinit();
    try evaluate(&d, caller_row);
    var wires = helpers.Counter.init(a);
    defer wires.deinit();
    const values = try support.evaluateArena(a, &d.arena, caller_row);
    defer a.free(values);
    var memory_event: usize = 0;
    for (d.arena.effectsView(), 0..) |event, i| {
        const ids = d.arena.effectValues(@enumFromInt(i)).?;
        var tuple: [7]u32 = @splat(0);
        for (ids, 0..) |id, j| tuple[j] = values[lang.types.idIndex(id)].toU32();
        if (event.binding.?.schema == lang.relation.id(.recursion_wire)) {
            try helpers.add(&wires, tuple[0..6].*, if (event.binding.?.role == .emit) 1 else -1);
        } else if (event.binding.?.schema == lang.relation.id(.memory_access)) {
            const after = memory_event % 2 == 1;
            const index = memory_event / 2;
            const word: u32 = if (index < 2) (if (index == 0) input.state_ptr else input.block_ptr) else (if (after) input.after(index - 2) else input.before(index - 2));
            const address: u32 = if (index < 2) (if (index == 0) input.state_register else input.block_register) else input.address(index - 2);
            const previous = if (index < 2) input.pointer_previous_clocks[index] else input.memory_previous_clocks[index - 2];
            const current = @import("../../../access_clock.zig").encode(input.execution_clock, if (index < 2) .first else .second);
            const expected = [7]u32{ @intFromBool(index >= 2), address, if (after) current else previous, word & 255, (word >> 8) & 255, (word >> 16) & 255, word >> 24 };
            if (!std.mem.eql(u32, &expected, &tuple)) return error.ShaMemoryClaimMismatch;
            memory_event += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 52), memory_event);
    var rows = try provider.prepare(a, &.{.{ .execution_clock = input.execution_clock, .state = input.state, .block = input.block }});
    defer rows.deinit();
    const tuple = rows.tuple();
    inline for (.{ source, provider.Schedule, provider.Round, provider.FeedForward }, 0..) |Air, i| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const count = [_]usize{ 88, 48, 64, 8 };
        for (tuple[i][0..count[i]]) |r| try helpers.emit(&definition, &r, &wires);
    }
    var it = wires.valueIterator();
    while (it.next()) |value| if (value.* != 0) return error.UnclosedShaMemoryCall;
}
test "SHA memory caller closes the complete compression graph and exact memory tuples" {
    const input = fixture(false);
    const row = try air.row(input);
    try closed(&row, input);
    var wrong = row;
    wrong[air.Layout.output] = wrong[air.Layout.output].add(M.one());
    try std.testing.expectError(error.ShaMemoryClaimMismatch, closed(&wrong, input));
    wrong = row;
    wrong[air.Layout.before + 32] = wrong[air.Layout.before + 32].add(M.one());
    try std.testing.expectError(error.ShaMemoryClaimMismatch, closed(&wrong, input));
    // Change the witness and external output claim together: only the actual
    // compression graph can reject this forged result.
    var forged = input;
    forged.output[0] ^= 1;
    wrong = row;
    wrong[air.Layout.output] = M.fromCanonical(forged.output[0] & 255);
    try std.testing.expectError(error.UnclosedShaMemoryCall, closed(&wrong, forged));
}

test "SHA memory caller uses the full address range and rejects malformed closed access groups" {
    var high = fixture(true);
    high.state_ptr = record.address_limit - 32;
    high.block_ptr = record.address_limit - 128;
    const row = try air.row(high);
    try closed(&row, high);
    var d = try air.build(std.testing.allocator);
    defer d.deinit();
    for (d.arena.effects.items, 0..) |event, i| {
        if (event.kind == .component_call and event.binding.?.schema == lang.relation.id(.memory_access) and event.binding.?.role == .emit) {
            d.arena.effects.items[i].binding.?.role = .consume;
            try std.testing.expectError(error.InvalidEffect, lang.validate.validate(&d.arena));
            d.arena.effects.items[i] = event;
            try d.validate();
            const saved = d.arena.effects.items[i + 1];
            d.arena.effects.items[i + 1].liveness = null;
            try std.testing.expectError(error.InvalidEffect, lang.validate.validate(&d.arena));
            d.arena.effects.items[i + 1] = saved;
            try d.validate();
            break;
        }
    }
}

test "SHA memory caller compiles and exports exact base and secure machine expressions" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    std.debug.print("SHA_CALLER_COMPILER arena_nodes={d}\n", .{definition.arena.nodeCount()});
    try @import("../../../recursion/air/tests/framework_polynomial_export_v1_test.zig").exercise(air, &definition);
    const runtime = @import("../../../recursion/air/relation_interaction.zig");
    try std.testing.expectError(error.InvalidInputGeometry, runtime.Runtime(air.LOGICAL_INPUT_COUNT, air.RELATION_EVENT_COUNT, air.LOOKUP_BATCH_SIZE).authenticate(&definition.arena, air.SEMANTIC_DIGEST, definition.events));
}

test "SHA memory caller program PC admission follows derived addresses and rejects invalid policies" {
    const runtime = @import("../../../recursion/air/relation_interaction.zig");
    const Bound = runtime.RuntimeWithMachineInputs(air.LOGICAL_INPUT_COUNT, air.RELATION_EVENT_COUNT, air.LOOKUP_BATCH_SIZE, air.PHYSICAL_MAIN_COLUMN_COUNT, &.{}, air.PROGRAM_BOUND_PC_INPUTS);
    const WrongType = runtime.RuntimeWithMachineInputs(air.LOGICAL_INPUT_COUNT, air.RELATION_EVENT_COUNT, air.LOOKUP_BATCH_SIZE, air.PHYSICAL_MAIN_COLUMN_COUNT, &.{}, &.{air.Layout.clock});
    const Duplicate = runtime.RuntimeWithMachineInputs(air.LOGICAL_INPUT_COUNT, air.RELATION_EVENT_COUNT, air.LOOKUP_BATCH_SIZE, air.PHYSICAL_MAIN_COLUMN_COUNT, &.{}, &.{ air.Layout.pc, air.Layout.pc });
    var d = try air.build(std.testing.allocator);
    defer d.deinit();
    _ = try Bound.authenticate(&d.arena, air.SEMANTIC_DIGEST, d.events);
    try std.testing.expectError(error.InvalidInputGeometry, WrongType.authenticate(&d.arena, air.SEMANTIC_DIGEST, d.events));
    try std.testing.expectError(error.InvalidInputGeometry, Duplicate.authenticate(&d.arena, air.SEMANTIC_DIGEST, d.events));
    var tested = false;
    for (d.arena.effects.items, 0..) |effect, i| {
        if (effect.kind != .state_produce) continue;
        // The produced PC is a derived next-PC expression, not the declared
        // input itself. Its lookup must still use the program request's gate.
        d.arena.effects.items[i].liveness = null;
        try std.testing.expectError(error.InvalidEffect, Bound.authenticate(&d.arena, air.SEMANTIC_DIGEST, d.events));
        d.arena.effects.items[i] = effect;
        tested = true;
        break;
    }
    try std.testing.expect(tested);
    try d.validate();
}
