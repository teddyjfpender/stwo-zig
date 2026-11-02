const std = @import("std");
const E = @import("../evaluation.zig");
const R = @import("../rows.zig");
const S = @import("../statement.zig");
const W = @import("../witness.zig");
const T = @import("../trace.zig");
const C = @import("../component.zig");
const P = @import("../protocol.zig");
const relation = @import("../relations.zig");
const L = E.L;
const a = std.testing.allocator;
const program = [_]u32{0x001080b3}; // ADD x1,x1,x1: all three aliases
fn statement() S.Statement {
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x87654321ffffffff;
    var final = initial;
    final[1] +%= final[1];
    return .{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x100001004, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 1 };
}

test "rv64 AIR: projected rows are exact linear substitutions and aliases have distinct clocks" {
    var witness = try W.Witness.build(a, statement());
    defer witness.deinit();
    var trace = try T.Trace.init(a, statement(), witness.metadata, witness.rows);
    defer trace.deinit();
    const physical = W.physical(0, trace.log_size);
    const main = trace.mainAt(physical);
    for (main, witness.rows[0]) |actual, expected| try std.testing.expect(actual.eql(E.Q.fromBase(expected)));
    const fixed = trace.fixedAt(physical);
    const original = try R.fixedRow(statement(), witness.metadata, 0, trace.domainSize());
    for (fixed, original) |actual, expected| try std.testing.expect(actual.eql(E.Q.fromBase(expected)));
    try std.testing.expect(main[L.previousClock(0)].isZero());
    try std.testing.expect(main[L.previousClock(1)].eql(E.q(1)));
    try std.testing.expect(main[L.previousClock(2)].eql(E.q(2)));
    try std.testing.expectEqual(@as(u16, 3), witness.metadata.register_clocks[1]);
}

test "rv64 AIR: inverse prefix first-row and terminal closure constraints reject mutation" {
    var witness = try W.Witness.build(a, statement());
    defer witness.deinit();
    var trace = try T.Trace.init(a, statement(), witness.metadata, witness.rows);
    defer trace.deinit();
    var channel = P.Channel{};
    const challenges = relation.Challenges.draw(&channel);
    const target = try relation.expected(statement(), witness.metadata, challenges);
    try std.testing.expect(target.eql(try trace.generateInteraction(challenges)));
    const component = try C.Component.init(trace.log_size, trace.projection, challenges, target);
    const output = try a.alloc(E.Q, component.constraint_count);
    defer a.free(output);
    for (0..trace.domainSize()) |logical| {
        const physical = W.physical(logical, trace.log_size);
        const prior = W.physical((logical + trace.domainSize() - 1) % trace.domainSize(), trace.log_size);
        const fixed = trace.fixedAt(physical);
        const main = trace.mainAt(physical);
        var current: [L.INTERACTION]E.Q = undefined;
        var previous: [L.INTERACTION]E.Q = undefined;
        for (&current, &previous, 0..) |*cur, *prev, c| {
            cur.* = E.Q.fromBase(trace.interaction[c * trace.domainSize() + physical]);
            prev.* = E.Q.fromBase(trace.interaction[c * trace.domainSize() + prior]);
        }
        component.evaluate(&fixed, &main, &current, &previous, output);
        for (output) |value| try std.testing.expect(value.isZero());
        for ([_]usize{ L.bit(.a, 0), L.bit(.b, 0), L.bit(.result, 63), L.bit(.previous_rd, 40), L.carry(.alu, 0), L.previousClock(1) + 1, L.gap(1) + 1, L.readable }) |c| {
            var mutated = main;
            mutated[c] = mutated[c].add(E.Q.one());
            component.evaluate(&fixed, &mutated, &current, &previous, output);
            var rejected = false;
            for (output) |value| rejected = rejected or !value.isZero();
            try std.testing.expect(rejected);
        }
        for ([_]usize{ 0, 4, 24, 32, 35 }) |c| {
            var mutated = current;
            mutated[c] = mutated[c].add(E.Q.one());
            component.evaluate(&fixed, &main, &mutated, &previous, output);
            var rejected = false;
            for (output) |value| rejected = rejected or !value.isZero();
            try std.testing.expect(rejected);
        }
    }
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var witness = try W.Witness.build(allocator, statement());
    defer witness.deinit();
    var trace = try T.Trace.init(allocator, statement(), witness.metadata, witness.rows);
    defer trace.deinit();
    var channel = P.Channel{};
    _ = try trace.generateInteraction(relation.Challenges.draw(&channel));
    trace.releaseColumns();
}
test "rv64 AIR: every witness projection trace and interaction allocation failure releases ownership" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
