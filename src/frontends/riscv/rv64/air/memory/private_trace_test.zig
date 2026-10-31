const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const T = @import("private_trace.zig");
const I = @import("private_interaction.zig");
const values = @import("values.zig");
const policy = @import("policy.zig");
const B = @import("batch.zig");
const Byte = @import("../range/provider.zig");
const PR = @import("policy_provider.zig");
const CA = @import("chunk_air.zig");
const Cell = @import("cell_air.zig");
const Leaf = @import("leaf_air.zig");
const Node = @import("node_air.zig");
const Side = @import("side_air.zig");
const Permit = @import("permit_air.zig");
const state = @import("../relations.zig");
const Q = E.Q;
const M = core.fields.m31.M31;
const physical = @import("../witness.zig").physical;
fn auditLocal(trace: *const T.Trace, inter: *const I.Interaction, ch: *const I.Challenges) !void {
    for (T.TABLES) |table| {
        const size = @as(usize, 1) << @intCast(T.tableLog(trace.shapes, table));
        const main_data = T.mainData(trace, table);
        const interaction = inter.tables[@intFromEnum(table)];
        const claims = inter.claims.slice(table);
        for (0..size) |i| {
            const at = physical(i, T.tableLog(trace.shapes, table));
            const prior = physical((i + size - 1) % size, T.tableLog(trace.shapes, table));
            var main: [111]Q = undefined;
            var previous: [111]Q = undefined;
            var fixed: [8]Q = undefined;
            var f: [8]M = undefined;
            var current: [52]Q = undefined;
            var old: [52]Q = undefined;
            for (0..T.mainWidth(table)) |j| {
                main[j] = Q.fromBase(main_data[j * size + at]);
                previous[j] = Q.fromBase(main_data[j * size + prior]);
            }
            T.fixedAt(trace.shapes, table, i, f[0..T.fixedWidth(table)]);
            for (fixed[0..T.fixedWidth(table)], f[0..T.fixedWidth(table)]) |*value, m| value.* = Q.fromBase(m);
            for (0..T.sumCount(table) * 4) |j| {
                current[j] = Q.fromBase(interaction[j * size + at]);
                old[j] = Q.fromBase(interaction[j * size + prior]);
            }
            var residuals: [63]Q = undefined;
            var sink = E.Sink{ .values = &residuals };
            switch (table) {
                .chunk => CA.evaluate(trace.shapes.chunk, fixed[0..CA.FIXED], main[0..CA.MAIN], previous[0..CA.MAIN], current[0..CA.INTERACTION], old[0..CA.INTERACTION], claims[0..CA.SUMS].*, &.{ .ram = ch.ram, .io = ch.permutations.poseidon2_io }, &sink),
                .common_cells, .edge_cells => Cell.evaluate(if (table == .common_cells) trace.shapes.common_cells else trace.shapes.edge_cells, fixed[0..Cell.FIXED], main[0..Cell.MAIN], previous[0..Cell.MAIN], current[0..Cell.INTERACTION], old[0..Cell.INTERACTION], claims[0..Cell.SUMS].*, &.{ .ram = ch.ram, .state = ch.state, .bytes = ch.bytes }, &sink),
                .leaf => Leaf.evaluate(trace.shapes.leaf, fixed[0..Leaf.FIXED], main[0..Leaf.MAIN], previous[0..Leaf.MAIN], current[0..Leaf.INTERACTION], old[0..Leaf.INTERACTION], claims[0..Leaf.SUMS].*, &.{ .ram = ch.ram, .bytes = ch.bytes }, &sink),
                .node => Node.evaluate(trace.shapes.node, fixed[0..Node.FIXED], main[0..Node.MAIN], previous[0..Node.MAIN], current[0..Node.INTERACTION], old[0..Node.INTERACTION], claims[0..Node.SUMS].*, &.{ .ram = ch.ram, .io = ch.permutations.poseidon2_io, .bytes = ch.bytes }, &sink),
                .side => Side.evaluate(trace.shapes.side, fixed[0..Side.FIXED], main[0..Side.MAIN], previous[0..Side.MAIN], current[0..Side.INTERACTION], old[0..Side.INTERACTION], claims[0..Side.SUMS].*, &.{ .ram = ch.ram, .bytes = ch.bytes }, &sink),
                .common_permits, .edge_permits => Permit.evaluate(if (table == .common_permits) trace.shapes.common_permits else trace.shapes.edge_permits, fixed[0..Permit.FIXED], main[0..Permit.MAIN], previous[0..Permit.MAIN], current[0..Permit.INTERACTION], old[0..Permit.INTERACTION], claims[0..Permit.SUMS].*, &.{ .bytes = ch.bytes, .policy = ch.policy, .permit = ch.ram.permitChallenge() }, &sink),
            }
            for (residuals[0..sink.count], 0..) |value, constraint| if (!value.isZero()) {
                std.debug.print("RAM local residual table={s} row={d} constraint={d}\n", .{ @tagName(table), i, constraint });
                return error.InvalidPrivateRamLocal;
            };
        }
    }
}
test "RV64 private RAM tables: actual shared frontier policy certificates canonical cells and all typed claims close" {
    const a = std.testing.allocator;
    var cache = try values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var mappings = try policy.Policy.init(a, &.{ .{ .first = 0x1000, .last = 0x11ff, .flags = 3 }, .{ .first = 0x2000, .last = 0x2007, .flags = 1 }, .{ .first = 0x20f8, .last = 0x20ff, .flags = 3 } });
    defer mappings.deinit();
    const before: [2][64]u64 = @splat(@splat(0));
    var after = before;
    after[0][0] = 17;
    after[1][31] = 29;
    var clocks: [2][64]u32 = @splat(@splat(0));
    clocks[0][0] = 4;
    clocks[1][0] = 8;
    clocks[1][31] = 12;
    var rights: [2][64]u2 = .{ @splat(3), @splat(0) };
    rights[1][0] = 1;
    rights[1][31] = 3;
    var openings: [2]B.Opening = undefined;
    for (&openings, 0..) |*opening, i| opening.* = .{ .index = if (i == 0) 8 else 16, .before = &before[i], .after = &after[i], .terminal_clocks = &clocks[i], .rights = &rights[i] };
    var trace = try T.Trace.init(a, &cache, &mappings, &openings);
    defer trace.deinit();
    try std.testing.expectEqual(@as(u32, 1), trace.shapes.common_cells.chunks);
    try std.testing.expectEqual(@as(u32, 1), trace.shapes.edge_cells.chunks);
    var bytes = try Byte.Trace.init(a, &trace.byte_counts);
    defer bytes.deinit();
    var rom = try PR.Trace.init(a, &mappings, trace.policy_counts);
    defer rom.deinit();
    var channel = @import("../protocol.zig").Channel{};
    channel.mixU32s(&.{0x5250524d});
    const ch = try I.Challenges.draw(a, &channel);
    var inter = try I.Interaction.init(a, &trace, &ch);
    defer inter.deinit();
    const byte_claim = try bytes.generateInteraction(ch.bytes);
    const policy_claim = try rom.generateInteraction(.{ .policy = ch.policy });
    const debt = try I.close(trace.witness.before, trace.witness.after, .chunk512, &inter.claims, inter.provider.claims, byte_claim, policy_claim, &ch);
    var expected = Q.zero();
    for (openings) |opening| for (opening.before, opening.after, opening.terminal_clocks, opening.rights, 0..) |initial, final, clock, flags, i| if (clock != 0) {
        const addr = (opening.index << 9) + i * 8;
        expected = expected.sub(try ch.state.denominator(state.boundaryTuple(1, addr, 0, initial, flags & 1 != 0, flags & 2 != 0)).inv()).add(try ch.state.denominator(state.boundaryTuple(1, addr, clock, final, flags & 1 != 0, flags & 2 != 0)).inv());
    };
    try std.testing.expectEqualDeep(expected, debt);
    try auditLocal(&trace, &inter, &ch);
    var query_mass: u64 = 0;
    for (trace.byte_counts) |count| query_mass += count;
    try std.testing.expect(query_mass <= try I.boundByteMass(trace.shapes));
    try std.testing.expect(try I.boundInternalMass(trace.shapes) < core.fields.m31.Modulus);
    var noncanonical = inter.claims;
    noncanonical.tables[@intFromEnum(T.Table.chunk)][CA.SUMS] = Q.one();
    try std.testing.expectError(error.NoncanonicalPrivateRamClaimTail, I.close(trace.witness.before, trace.witness.after, .chunk512, &noncanonical, inter.provider.claims, byte_claim, policy_claim, &ch));
    var forged_root = trace.witness.after;
    forged_root[8] ^= 1;
    try std.testing.expectError(error.UnbalancedPrivateRamGraph, I.close(trace.witness.before, forged_root, .chunk512, &inter.claims, inter.provider.claims, byte_claim, policy_claim, &ch));
}

fn ownedFailure(allocator: std.mem.Allocator, cache: *const values.Cache, mappings: *const policy.Policy, openings: []const B.Opening) !void {
    var captured = try @import("openings.zig").Owned.copy(allocator, .chunk512, openings);
    defer captured.deinit();
    const words = captured.words.ptr;
    var trace = T.Trace.initOwned(allocator, cache, mappings, &captured) catch |err| {
        try std.testing.expect(captured.words.ptr == words and captured.chunks.len == openings.len);
        return err;
    };
    defer trace.deinit();
    try std.testing.expectEqual(@as(usize, 0), captured.words.len);
}
test "RV64 private RAM ownership: every constructor allocation failure leaves captured owner and sparse cache intact" {
    const a = std.testing.allocator;
    var cache = try values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    const initial = cache.root();
    var mappings = try policy.Policy.init(a, &.{.{ .first = 0x1000, .last = 0x11ff, .flags = 3 }});
    defer mappings.deinit();
    const before: [64]u64 = @splat(0);
    var after = before;
    after[0] = 17;
    var clocks: [64]u32 = @splat(0);
    clocks[0] = 4;
    const rights: [64]u2 = @splat(3);
    const openings = [_]B.Opening{.{ .index = 8, .before = &before, .after = &after, .terminal_clocks = &clocks, .rights = &rights }};
    try std.testing.checkAllAllocationFailures(a, ownedFailure, .{ &cache, &mappings, &openings });
    try std.testing.expect(values.equal(initial, cache.root()));
    try std.testing.expectEqual(@as(usize, 0), cache.count());
}

fn borrowedFailure(a: std.mem.Allocator, cache: *const values.Cache, mappings: *const policy.Policy, openings: []const B.Opening, buffers: T.MainBuffers) !void {
    var captured = try @import("openings.zig").Owned.copy(a, .chunk512, openings);
    defer captured.deinit();
    var prepared = try T.Preparation.init(a, .chunk512, mappings, captured.chunks);
    defer prepared.deinit();
    const words = captured.words.ptr;
    var trace = T.Trace.initPreparedBorrowedOwned(a, cache, &prepared, &captured, buffers) catch |err| {
        try std.testing.expect(prepared.available);
        try std.testing.expectEqual(openings.len, captured.chunks.len);
        try std.testing.expect(captured.words.ptr == words);
        for (buffers.policy_tail) |value| try std.testing.expectEqualDeep(M.fromCanonical(173), value);
        for (buffers.byte_tail) |value| try std.testing.expectEqualDeep(M.fromCanonical(173), value);
        return err;
    };
    defer trace.deinit();
    try std.testing.expect(!prepared.available);
    try std.testing.expectEqual(@as(usize, 0), captured.chunks.len);
    for (buffers.policy_tail) |value| try std.testing.expectEqualDeep(M.fromCanonical(173), value);
    for (buffers.byte_tail) |value| try std.testing.expectEqualDeep(M.fromCanonical(173), value);
}

test "RV64 borrowed RAM main: exact owned parity, untouched shared tails, all failures retain owners, release before interactions" {
    const a = std.testing.allocator;
    var cache = try values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var mappings = try policy.Policy.init(a, &.{ .{ .first = 0x1000, .last = 0x11ff, .flags = 3 }, .{ .first = 0x2000, .last = 0x2007, .flags = 3 } });
    defer mappings.deinit();
    const before: [2][64]u64 = @splat(@splat(0));
    var after = before;
    after[0][0] = 17;
    after[1][0] = 29;
    var clocks: [2][64]u32 = @splat(@splat(0));
    clocks[0][0] = 4;
    clocks[1][0] = 8;
    var rights: [2][64]u2 = .{ @splat(3), @splat(0) };
    rights[1][0] = 3;
    var openings: [2]B.Opening = undefined;
    for (&openings, 0..) |*opening, i| opening.* = .{ .index = if (i == 0) 8 else 16, .before = &before[i], .after = &after[i], .terminal_clocks = &clocks[i], .rights = &rights[i] };
    var reference = try T.Trace.init(a, &cache, &mappings, &openings);
    defer reference.deinit();
    var arena: ?[]M = try a.alloc(M, reference.main_backing.len);
    defer if (arena) |data| a.free(data);
    @memset(arena.?, M.fromCanonical(173));
    var cursor: usize = 0;
    var buffers: T.MainBuffers = undefined;
    for (T.TABLES) |table| {
        const len = T.mainData(&reference, table).len;
        buffers.callers[@intFromEnum(table)] = arena.?[cursor..][0..len];
        cursor += len;
    }
    buffers.provider = arena.?[cursor..][0..reference.provider.len];
    cursor += reference.provider.len;
    buffers.policy_tail = arena.?[cursor..][0..reference.policy_tail.len];
    cursor += reference.policy_tail.len;
    buffers.byte_tail = arena.?[cursor..][0..256];
    try std.testing.checkAllAllocationFailures(a, borrowedFailure, .{ &cache, &mappings, &openings, buffers });
    var owned = try @import("openings.zig").Owned.copy(a, .chunk512, &openings);
    defer owned.deinit();
    var prepared = try T.Preparation.init(a, .chunk512, &mappings, owned.chunks);
    defer prepared.deinit();
    var alias = buffers;
    alias.callers[1] = alias.callers[0];
    try std.testing.expectError(error.InvalidPrivateRamMainBuffers, T.Trace.initPreparedBorrowedOwned(a, &cache, &prepared, &owned, alias));
    try std.testing.expect(prepared.available and owned.chunks.len == 2);
    alias = buffers;
    alias.provider = arena.?[0..buffers.provider.len];
    try std.testing.expectError(error.AliasedPrivateRamMainBuffers, T.Trace.initPreparedBorrowedOwned(a, &cache, &prepared, &owned, alias));
    try std.testing.expect(prepared.available and owned.chunks.len == 2);
    // Prepared geometry cannot silently outlive a changed native witness.
    const final_words = @constCast(owned.chunks[0].after);
    final_words[0] = 0;
    try std.testing.expectError(error.PrivateRamPreparationChanged, T.Trace.initPreparedBorrowedOwned(a, &cache, &prepared, &owned, buffers));
    try std.testing.expect(prepared.available and owned.chunks.len == 2);
    final_words[0] = 17;
    var trace = try T.Trace.initPreparedBorrowedOwned(a, &cache, &prepared, &owned, buffers);
    defer trace.deinit();
    for (T.TABLES) |table| try std.testing.expectEqualSlices(M, T.mainData(&reference, table), T.mainData(&trace, table));
    try std.testing.expectEqualSlices(M, reference.provider, trace.provider);
    try std.testing.expectEqualDeep(reference.byte_counts, trace.byte_counts);
    try std.testing.expectEqualSlices(u64, reference.policy_counts, trace.policy_counts);
    try std.testing.expectError(error.PrivateRamBorrowedMain, trace.detachMain(a, buffers.policy_tail));
    try trace.releaseBorrowedMain();
    try std.testing.expectError(error.InvalidPrivateRamTracePhase, trace.releaseBorrowedMain());
    a.free(arena.?);
    arena = null;
    var channel = @import("../protocol.zig").Channel{};
    const ch = try I.Challenges.draw(a, &channel);
    var expected = try I.Interaction.init(a, &reference, &ch);
    defer expected.deinit();
    var actual = try I.Interaction.initMetadata(a, &trace, &ch);
    defer actual.deinit();
    try std.testing.expectEqualDeep(expected.claims, actual.claims);
    for (expected.tables, actual.tables) |first, second| try std.testing.expectEqualSlices(M, first, second);
    try std.testing.expectEqualSlices(M, expected.provider.columns, actual.provider.columns);
}
