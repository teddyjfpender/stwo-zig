//! Original native PAGE equations, profiles and byte schedules as mathematical
//! oracles. No received key, successful capture, proof MAIN or admission token.
const std = @import("std");
const core = @import("stwo_core");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Fixture = @import("block_v5_page_fixed_roster_fixture_v1.zig");
const Sources = @import("../recursion/air/block_v5_recursive_parent_fixed_sources_v1.zig");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Roots = @import("../recursion/air/blake3_root_sources.zig");
const Private = @import("../recursion/air/blake3_private_word.zig");
const Pcs = @import("../recursion/block_v5_native_recursive_fixed_pcs_v1.zig");
const Assembly = @import("../recursion/block_v5_recursive_parent_fixed_assembly_v1.zig");
const Roster = @import("../recursion/block_v5_recursive_parent_fixed_roster_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
fn BusFor(comptime kind: Semantic.Kind) type {
    return @import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
}
fn less(comptime Wire: type) fn (void, Wire, Wire) bool {
    return struct {
        fn compare(_: void, left: Wire, right: Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
    }.compare;
}
/// Independent pre-extraction live routing oracle. No live value validation is
/// omitted in production; this fixture supplies no live acceptance authority.
fn originalSchedule(comptime kind: Semantic.Kind, a: std.mem.Allocator, fixture: *const Fixture.ForKind(kind)) ![]BusFor(kind).Wire {
    const Bus = BusFor(kind);
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    for (0..8) |tree| for (0..8) |coordinate| {
        try wires.append(a, .{ .circuit = Roots.CIRCUIT, .wire = @intCast(tree * 8 + coordinate), .uses = 1, .source = .first_root, .coordinate = @intCast(tree * 8 + coordinate) });
    };
    for (fixture.transcript.fixed.root_reads) |receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
        for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) {
            try wires.append(a, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = .word, .coordinate = receipt.source.first_wire + @as(u32, @intCast(coordinate)) });
        };
    };
    for (fixture.transcript.fixed.payload_reads) |receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
        for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) {
            const wire = receipt.source.first_wire + @as(u32, @intCast(coordinate));
            const field = wire >= fixture.layout.word_count;
            try wires.append(a, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = wire, .uses = uses, .source = if (field) .felt_word else .word, .coordinate = if (field) wire - fixture.layout.word_count else wire });
        };
    };
    const counts = try a.alloc(u32, fixture.composition.circuit.nodes.len);
    defer a.free(counts);
    const uses = try Lower.computeUseCountsInto(fixture.composition.circuit.graph(), counts);
    for (fixture.composition.sources, 0..) |source, node| if (source == .public_input and uses[node] != 0) {
        try wires.append(a, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = .public_input, .coordinate = source.public_input });
    };
    std.mem.sort(Bus.Wire, wires.items, {}, less(Bus.Wire));
    var output: usize = 0;
    for (wires.items) |wire| {
        if (output != 0 and wires.items[output - 1].circuit == wire.circuit and wires.items[output - 1].wire == wire.wire) {
            const prior = &wires.items[output - 1];
            if (prior.source != wire.source or prior.coordinate != wire.coordinate) return error.InvalidTestOriginalPageSchedule;
            prior.uses = try std.math.add(u32, prior.uses, wire.uses);
        } else {
            wires.items[output] = wire;
            output += 1;
        }
    }
    wires.items.len = output;
    return wires.toOwnedSlice(a);
}
fn publicSchedule(comptime kind: Semantic.Kind, a: std.mem.Allocator, fixture: *const Fixture.ForKind(kind)) ![]BusFor(kind).Wire {
    return BusFor(kind).collectFixedSchedule(a, &fixture.transcript, &fixture.composition, fixture.layout.word_count, @import("../recursion/air/block_v5_memory_source_page_composition_v1.zig").claimCount(kind), 8, 1, 1 << 20);
}
fn parity(comptime kind: Semantic.Kind) !void {
    @setEvalBranchQuota(20_000);
    const a = std.testing.allocator;
    var fixture = try Fixture.ForKind(kind).init(a);
    defer fixture.deinit();
    const public = try publicSchedule(kind, a, &fixture);
    defer a.free(public);
    const original = try originalSchedule(kind, a, &fixture);
    defer a.free(original);
    try std.testing.expectEqualDeep(original, public);
    try std.testing.expectEqual(try BusFor(kind).scheduleDigest(original), try BusFor(kind).scheduleDigest(public));
    var roots_count: usize = 0;
    var equations: usize = 0;
    for (public) |wire| {
        if (wire.source == .first_root) {
            try std.testing.expectEqual(@as(u32, 1), wire.uses);
            try std.testing.expectEqual(@as(u32, @intCast(roots_count)), wire.coordinate);
            roots_count += 1;
        }
        if (wire.source == .public_input) equations += 1;
    }
    try std.testing.expectEqual(@as(usize, 64), roots_count);
    try std.testing.expect(equations != 0);
    const actual = try Sources.Owned.compileNativePage(a, fixture.profile, &fixture.composition, &fixture.deep, &fixture.fri, &fixture.transcript);
    defer actual.deinit();
    try std.testing.expectEqual(@as(usize, 0), (try actual.roots.metadata(2)).len);
    inline for (.{ 12, 11, 10, 2, 9 }) |slot| try std.testing.expectEqual(@as(usize, 0), (try actual.claims.metadata(slot)).len);
    // Original commitments8/9 and each FRI root/nonce have the same private
    // word AIR/multiplicity. Initial0..7 appear only in the public schedule.
    const words = try actual.roots.metadata(9);
    try std.testing.expectEqual(8 * (2 + fixture.profile.widths.len) + 2, words.len);
    var cursor: usize = 0;
    var root_index: usize = 8;
    for (fixture.transcript.fixed.root_reads) |receipt| if (receipt.source.circuit == Roots.CIRCUIT) {
        try std.testing.expectEqualDeep(try Roots.caller(root_index), receipt.source);
        for (receipt.uses, 0..) |reads, coordinate| {
            const row = try Private.logicalRow(receipt.source.circuit, receipt.source.first_wire + @as(u32, @intCast(coordinate)), reads + 1, 0);
            try std.testing.expectEqualDeep(Storage.compactFixed(Private, row), words[cursor]);
            cursor += 1;
        }
        root_index += 1;
    };
    var nonce: [2]u32 = @splat(0);
    for (fixture.transcript.fixed.payload_reads) |receipt| if (receipt.source.circuit == 4_100_001) {
        for (&nonce, receipt.uses) |*count, uses| count.* += uses;
    };
    for (nonce, 0..) |uses, coordinate| try std.testing.expectEqualDeep(Storage.compactFixed(Private, try Private.logicalRow(4_100_001, @intCast(2 + coordinate), uses, 0)), words[cursor + coordinate]);
    try std.testing.expect((try actual.challenges.metadata(12)).len != 0);
    try std.testing.expect((try actual.samples.metadata(11)).len != 0);
    try std.testing.expect((try actual.terminal.metadata(10)).len != 0);
    const pcs = try Pcs.ForCommitments(10).Owned.compile(a, fixture.profile, &fixture.deep, &fixture.fri, &fixture.transcript);
    defer pcs.deinit();
    var arithmetic = try Assembly.Arithmetic.init(a, .{ fixture.composition.circuit.graph(), fixture.deep.graph(), fixture.fri.graph() });
    defer arithmetic.deinit();
    const selectors = try Assembly.selectorsForGraphs(a, &fixture.deep, &fixture.fri);
    const fixed = try Roster.compileOriginalRoster(a, actual, null, pcs.openings, pcs.ports, &fixture.transcript, &pcs.paths, &arithmetic, selectors, &fixture.deep);
    defer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
    const logs = try @import("../recursion/blake3_parent_fixed_key_v1.zig").rowLogs(fixed);
    inline for (0..Storage.Airs.len) |i| {
        try std.testing.expect(logs[i] >= 1);
        try std.testing.expect(fixed[i].len <= @as(usize, 1) << @intCast(logs[i]));
    }
    const hash = fixture.transcript.fixed.hash_metadata.?;
    var g_count: usize = 0;
    inline for (@import("../recursion/air/blake3_g_partition.zig").SHARDS) |slot| g_count += fixed[slot].len;
    try std.testing.expectEqual(hash.g_rows.len + pcs.paths.metadata.g_rows.len, g_count);
    try std.testing.expectEqual(hash.xor_rows.len + pcs.paths.metadata.xor_rows.len, fixed[1].len);
    try std.testing.expectEqual(arithmetic.fused.fixed[1].len, fixed[3].len);
    try std.testing.expectEqual(arithmetic.fused.fixed[2].len, fixed[4].len);
    try std.testing.expectEqual(arithmetic.fused.fixed[3].len, fixed[5].len);
    try std.testing.expect(fixed[18].len + fixed[19].len != 0);
}
test "PAGE fixed roster: original raw public private ten-tree and exact append parity" {
    try parity(.raw);
}
test "PAGE fixed roster: original fold public private ten-tree and exact append parity" {
    try parity(.fold);
}
fn mutated(comptime kind: Semantic.Kind) !void {
    const a = std.testing.allocator;
    var fixture = try Fixture.ForKind(kind).init(a);
    defer fixture.deinit();
    const Bus = BusFor(kind);
    const public_count = @import("../recursion/air/block_v5_memory_source_page_composition_v1.zig").claimCount(kind);
    try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, Bus.collectFixedSchedule(a, &fixture.transcript, &fixture.composition, fixture.layout.word_count, public_count, 8, 0, 1 << 20));
    try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, Bus.collectFixedSchedule(a, &fixture.transcript, &fixture.composition, fixture.layout.word_count, public_count, 7, 1, 1 << 20));
    try std.testing.expectError(error.FusedRecursiveResourceLimit, Bus.collectFixedSchedule(a, &fixture.transcript, &fixture.composition, fixture.layout.word_count, public_count, 8, 1, 63));
    var touched = false;
    for (fixture.composition.sources) |*source| if (source.* == .public_input) {
        const retained = source.*;
        source.* = .{ .public_input = @intCast(public_count) };
        try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, publicSchedule(kind, a, &fixture));
        source.* = retained;
        touched = true;
        break;
    };
    try std.testing.expect(touched);
    // Routing proposal mutation never supplies an admitted owner. The native
    // profile independently rejects a mismatched graph/config/column route.
    const retained = fixture.deep.profile_digest;
    fixture.deep.profile_digest[0] ^= 1;
    try std.testing.expectError(error.ProfileIdentityMismatch, Sources.Owned.compileNativePage(a, fixture.profile, &fixture.composition, &fixture.deep, &fixture.fri, &fixture.transcript));
    fixture.deep.profile_digest = retained;
    const wires = try publicSchedule(kind, a, &fixture);
    defer a.free(wires);
    const id = try Bus.scheduleDigest(wires);
    wires[0].coordinate += 1;
    try std.testing.expect(!std.meta.eql(id, try Bus.scheduleDigest(wires)));
}
test "PAGE fixed roster: typed root count public source profile and schedule mutations" {
    try mutated(.raw);
    try mutated(.fold);
}
fn publicAllocation(a: std.mem.Allocator, fixture: *const Fixture.ForKind(.fold)) !void {
    const wires = try publicSchedule(.fold, a, fixture);
    defer a.free(wires);
}
fn privateAllocation(a: std.mem.Allocator, fixture: *const Fixture.ForKind(.fold)) !void {
    const sources = try Sources.Owned.compileNativePage(a, fixture.profile, &fixture.composition, &fixture.deep, &fixture.fri, &fixture.transcript);
    defer sources.deinit();
}
test "PAGE fixed roster: exact source and schedule allocation rollback" {
    const a = std.testing.allocator;
    var fixture = try Fixture.ForKind(.fold).init(a);
    defer fixture.deinit();
    // Original immutable compiler work is done once. Exhaustive failures
    // exercise only the newly connected supplier ports and their cleanup.
    try std.testing.checkAllAllocationFailures(a, publicAllocation, .{&fixture});
    try std.testing.checkAllAllocationFailures(a, privateAllocation, .{&fixture});
}
test "PAGE fixed roster: source control retains original allocator through final teardown" {
    const a = std.testing.allocator;
    var fixture = try Fixture.ForKind(.fold).init(a);
    defer fixture.deinit();
    const budget = try Budget.create(a, 128 << 20);
    const sources = Sources.Owned.compileNativePage(budget.allocator(), fixture.profile, &fixture.composition, &fixture.deep, &fixture.fri, &fixture.transcript) catch |failure| {
        budget.destroy();
        return failure;
    };
    budget.destroy();
    defer sources.deinit();
    try sources.roots.finish();
    try sources.samples.finish();
}
