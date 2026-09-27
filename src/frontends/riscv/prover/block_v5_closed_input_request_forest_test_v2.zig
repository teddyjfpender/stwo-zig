//! No positive proof admission from fixtures. Actual shipped boundary AIR,
//! interaction rows, exact coordinates, lifecycle and topology only.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const B = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Closure = @import("../recursion/air/block_v5_closed_public_supply_v1.zig");
const Session = @import("../recursion/block_v5_public_supply_session_v2.zig");
const Boundary = @import("../recursion/air/blake3_boundary.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Direct = @import("../recursion/air/blake3_direct_cohort_columns_v1.zig").ForAir(Boundary);
const committed = @import("../recursion/air/framework_interaction.zig").committedRow;
const Values = struct {
    coordinates: *[4]M,
    guards: *usize,
    pub fn validate(self: @This()) !void {
        self.guards.* += 1;
    }
    pub fn at(self: @This(), wire: B.Wire) ![4]M {
        if (wire.coordinate != 0 or wire.child != 0 or wire.kind != .output_slot or wire.part != null) return error.InvalidFixtureCoordinate;
        return self.coordinates.*;
    }
};
fn fixtureWires() [2]B.Wire {
    return .{
        .{ .circuit = 400, .wire = 0, .uses = 3, .kind = .output_slot, .coordinate = 0 },
        .{ .circuit = 400, .wire = 1, .uses = 7, .negative = true, .kind = .output_slot, .coordinate = 0 },
    };
}
test "closed input forest: bounded synchronous lookup guards entry and exit only" {
    var coordinates: [4]M = .{ M.one(), M.fromCanonical(2), M.fromCanonical(3), M.fromCanonical(4) };
    var guards: usize = 0;
    const wires = fixtureWires();
    var session = try Session.ForValues(Values).begin(.{ .coordinates = &coordinates, .guards = &guards }, &wires, .{});
    for (0..100) |_| try std.testing.expectEqualDeep(coordinates, try session.at(1));
    try std.testing.expectEqual(@as(usize, 1), guards);
    _ = try session.finish();
    try std.testing.expectEqual(@as(usize, 2), guards);
    try std.testing.expectError(error.InvalidPublicSupplySession, session.at(0));
    try std.testing.expectError(error.InvalidPublicSupplySession, session.finish());
}
test "closed input forest: admission session detects value or schedule mutation" {
    var coordinates: [4]M = @splat(M.one());
    var guards: usize = 0;
    var wires = fixtureWires();
    var session = try Session.ForValues(Values).begin(.{ .coordinates = &coordinates, .guards = &guards }, &wires, .{});
    coordinates[2] = M.fromCanonical(2);
    try std.testing.expectError(error.MutatedPublicSupplySession, session.finish());
    var changed = try Session.ForValues(Values).begin(.{ .coordinates = &coordinates, .guards = &guards }, &wires, .{});
    wires[0].uses += 1;
    try std.testing.expectError(error.MutatedPublicSupplySession, changed.finish());
    try std.testing.expectError(error.ClosedPublicSupplyResourceLimit, Session.ForValues(Values).begin(.{ .coordinates = &coordinates, .guards = &guards }, &wires, .{ .max_local_wires = 1 }));
}
fn satisfied(a: std.mem.Allocator, definition: anytype, row: Boundary.Row) !bool {
    const evaluated = try @import("../recursion/air/test_support.zig").evaluateArena(a, &definition.arena, &row);
    defer a.free(evaluated);
    const lang = @import("../air/lang/mod.zig");
    for (definition.arena.constraintsView()) |constraint| if (!evaluated[lang.types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
test "closed input forest: all four coordinates are constrained by original boundary AIR" {
    const a = std.testing.allocator;
    var definition = try Boundary.build(a);
    defer definition.deinit();
    const original = try Closure.row(fixtureWires()[0], .{ M.fromCanonical(300), M.one(), M.zero(), M.fromCanonical(999) });
    try std.testing.expect(try satisfied(a, &definition, original));
    for (0..4) |coordinate| {
        var mutated = original;
        mutated[coordinate] = mutated[coordinate].add(M.one());
        try std.testing.expect(!try satisfied(a, &definition, mutated));
        mutated = original;
        mutated[8 + coordinate] = mutated[8 + coordinate].add(M.one());
        try std.testing.expect(!try satisfied(a, &definition, mutated));
    }
    var wire = fixtureWires()[0];
    wire.uses = 0;
    try std.testing.expectError(error.InvalidClosedPublicSupply, Closure.row(wire, original[0..4].*));
    wire.uses = 1;
    wire.circuit = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidBlake3Boundary, Closure.row(wire, original[0..4].*));
}
fn interactionCase(a: std.mem.Allocator) !void {
    const Binding = @import("../recursion/air/universal_relation_binding.zig").Binding(Boundary);
    const Framework = @import("../recursion/air/framework_interaction.zig").Runtime(Binding.Runtime);
    var definition = try Boundary.build(a);
    defer definition.deinit();
    const plan = try Binding.authenticate(&definition);
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354346, 5 });
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relation = try relations.getExact(.recursion_wire);
    const wires = fixtureWires();
    const coordinates: [4]M = .{ M.fromCanonical(300), M.one(), M.zero(), M.fromCanonical(999) };
    var rows: [4]Boundary.Row = @splat(@splat(M.zero()));
    var expected = Q.zero();
    for (wires, rows[0..2]) |wire, *row| {
        row.* = try Closure.row(wire, coordinates);
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ coordinates));
        const numerator = M.fromCanonical(wire.uses);
        const term = Q.fromBase(numerator).mul(try denominator.inv());
        expected = if (wire.negative) expected.sub(term) else expected.add(term);
    }
    var trace = try Framework.generatePrepared(a, &plan, &rows, 2, &relations);
    defer trace.deinit(a);
    try std.testing.expectEqualDeep(expected, trace.claimed_sum);
    // The inherited public supply is eliminated by actual AIR, not by deleting
    // an open interaction claim. The opposite old consumer closes to zero.
    try std.testing.expect(trace.claimed_sum.add(expected.neg()).isZero());
    rows[1][7] = rows[1][7].add(M.one());
    var changed = try Framework.generatePrepared(a, &plan, &rows, 2, &relations);
    defer changed.deinit(a);
    try std.testing.expect(!changed.claimed_sum.eql(expected));
}
test "closed input forest: genuine interaction claim preserves both original signs and multiplicities" {
    try interactionCase(std.testing.allocator);
}
test "closed input forest: interaction construction allocation failures clean up" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, interactionCase, .{});
}
fn storageCase(a: std.mem.Allocator) !void {
    var parent: Storage.Prepared = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 13 };
    inline for (0..Storage.Airs.len) |i| parent.fixed[i] = &.{};
    defer parent.deinit();
    var old = try Direct.init(a, 1);
    defer old.deinit();
    const original = try Boundary.logicalRow(333, 10, M.one(), 0xab010203);
    try old.append(original);
    const owned = try old.take();
    parent.main[2] = owned.main;
    parent.fixed[2] = owned.fixed;
    var coordinates: [4]M = @splat(M.fromCanonical(17));
    var guards: usize = 0;
    const wires = fixtureWires();
    _ = try Closure.append(a, &parent, &wires, Values{ .coordinates = &coordinates, .guards = &guards }, .{});
    try std.testing.expectEqual(@as(usize, 3), parent.fixed[2].len);
    try std.testing.expectEqual(@as(usize, 13), parent.input_count);
    const log = parent.main[2][0].log_size;
    const expected = [_]Boundary.Row{ original, try Closure.row(wires[0], coordinates), try Closure.row(wires[1], coordinates) };
    for (expected, 0..) |row, logical| {
        try std.testing.expectEqualDeep(Storage.compactFixed(Boundary, row), parent.fixed[2][logical]);
        for (parent.main[2], row[0..4]) |column, value| try std.testing.expect(value.eql(column.values[committed(logical, log)]));
    }
}
test "closed input forest: closure appends exact committed rows without losing original boundary" {
    try storageCase(std.testing.allocator);
}
test "closed input forest: appended closure rolls back every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, storageCase, .{});
}
test "closed input forest: version5 node prefix preserves canonical config and separate domain" {
    const Layout = @import("../recursion/block_v5_input_request_forest_public_v1.zig");
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    const Bus = @import("../recursion/block_v5_closed_input_request_forest_bus_v2.zig");
    // Framing proposal only. Undefined metadata never enters positive admission.
    var spec: Layout.Spec = undefined;
    spec.geometry.profile = .csp_q70_pow26;
    spec.geometry.config = Base.CSP_CONFIG;
    spec.expected_id = @splat(0x55);
    var policy: Layout.Policy = undefined;
    policy.index = 0;
    policy.specs = (&spec)[0..1];
    const prefix = try Bus.nodePrefix(policy);
    try std.testing.expectEqual(@as(u32, 15), prefix.len);
    try std.testing.expectEqualSlices(u32, &.{ 0x42354d50, 5, 2, 26, 1, 70, 0 }, prefix.words[0..7]);
    _ = try Bus.scheduleDigest(&.{});
    try std.testing.expectError(error.ClosedInputRequestNodeHasNoPublicTerms, Bus.scheduleDigest(&fixtureWires()));
    try std.testing.expectError(error.InvalidScopedPublicSchedule, B.scheduleDigest(&.{}));
    try std.testing.expectEqual(@as(u32, 5), @import("../recursion/block_v5_closed_input_request_forest_protocol_v2.zig").VERSION);
}
test "closed input forest: foreign allocator and resource rejection preserve old row custody" {
    const a = std.testing.allocator;
    var parent: Storage.Prepared = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |i| parent.fixed[i] = &.{};
    defer parent.deinit();
    var direct = try Direct.init(a, 1);
    defer direct.deinit();
    try direct.append(try Boundary.logicalRow(500, 1, M.one(), 10));
    const taken = try direct.take();
    parent.main[2] = taken.main;
    parent.fixed[2] = taken.fixed;
    const original_main = parent.main[2].ptr;
    const original_fixed = parent.fixed[2].ptr;
    var coordinates: [4]M = @splat(M.one());
    var guards: usize = 0;
    const values = Values{ .coordinates = &coordinates, .guards = &guards };
    const wires = fixtureWires();
    var foreign = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidClosedPublicSupplyAllocator, Closure.append(foreign.allocator(), &parent, &wires, values, .{}));
    try std.testing.expectError(error.ClosedPublicSupplyResourceLimit, Closure.append(a, &parent, &wires, values, .{ .max_local_wires = 1 }));
    try std.testing.expect(parent.main[2].ptr == original_main and parent.fixed[2].ptr == original_fixed);
    try std.testing.expectEqual(@as(usize, 1), parent.fixed[2].len);
}
test "closed input forest: zero external terms stay bounded across minimum topology sizes" {
    const Plan = @import("../recursion/block_v5_input_request_forest_plan_v1.zig");
    const a = std.testing.allocator;
    for ([_]usize{ 1, 4, 5, 17, 65, 257 }) |count| {
        const ranges = try a.alloc(Plan.Range, count);
        defer a.free(ranges);
        for (ranges, 0..) |*range, index| range.* = .{ .first = @intCast(index), .count = 1, .leaves = 1 };
        var plan = try Plan.derive(a, ranges, @intCast(count), .{});
        defer plan.deinit();
        for (plan.nodes) |node| {
            try std.testing.expect(node.child_count <= 4);
            // Version5 exports no recursive-wire schedule at any height.
            // A carrier adds one genuine provider, independent of descendant count.
            try std.testing.expect(node.child_count + @as(u32, @intFromBool(node.kind == .carrier)) <= 5);
        }
        try std.testing.expectEqual(@as(usize, (count - 1 + 2) / 3 + 1), plan.nodes.len);
    }
}
