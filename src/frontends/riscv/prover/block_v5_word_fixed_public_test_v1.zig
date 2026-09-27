//! Structural routing oracles only. No capture, Fresh, native admission,
//! private values, PCS commitment or accepted proof is fabricated.
const std = @import("std");
const core = @import("stwo_core");
const Word = @import("../recursion/block_v5_word_recursive_fixed_v1.zig");
const Transcript = @import("../recursion/block_v5_word_recursive_fixed_transcript_v1.zig");
const Equation = @import("../recursion/air/block_v5_word_recursive_shape_composition_v1.zig");
const Schedule = @import("../recursion/air/block_v5_word_public_schedule_v1.zig");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const Plan = @import("../recursion/air/blake3_transcript_plan.zig").Plan;
fn BusFor(comptime family: Schedule.Family) type {
    return if (family == .ram_lanes) @import("../recursion/block_v5_ram_lanes_recursive_public_bus_v1.zig") else @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig");
}
fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 3) };
}
/// Independent pre-extraction live routing oracle, without its verified-value
/// comparisons. Those exact comparisons remain in original live preparation.
fn original(comptime family: Schedule.Family, a: std.mem.Allocator, plan: *const Plan, composition: *const Equation.ForFamily(family).Compiled) ![]BusFor(family).Wire {
    const Bus = BusFor(family);
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    for (0..2) |root| for (0..8) |coordinate| try wires.append(a, .{ .circuit = @import("../recursion/air/blake3_root_sources.zig").CIRCUIT, .wire = @intCast(root * 8 + coordinate), .uses = 3, .source = if (root == 0) .fixed_root else .main_root, .coordinate = @intCast(coordinate) });
    for (plan.fixed.root_reads) |receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
        const source: Bus.Source = if (receipt.source.first_wire == 0) .sealed else if (family == .ram_lanes) .pin_identity else .plan;
        for (receipt.uses, 0..) |uses, coordinate| try wires.append(a, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = source, .coordinate = @intCast(coordinate) });
    };
    for (plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
        for (receipt.uses, 0..) |uses, coordinate| {
            const source: Bus.Source = if (family == .ram_lanes) .claim_words else switch (receipt.source.first_wire) {
                16 => .shard_header,
                22 => .request_count_words,
                24 => .claim_count_words,
                26...29 => .sum_words,
                else => unreachable,
            };
            try wires.append(a, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = source, .coordinate = if (family == .ram_lanes) receipt.source.first_wire - 16 + @as(u32, @intCast(coordinate)) else if (source == .sum_words) receipt.source.first_wire - 26 else @intCast(coordinate) });
        }
    };
    const counts = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(counts);
    const uses = try Lower.computeUseCountsInto(composition.circuit.graph(), counts);
    for (composition.sources, 0..) |source, node| if (source == .public_input) {
        if (family == .ram_lanes and uses[node] == 0) continue;
        try wires.append(a, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = if (family == .ram_lanes) .equation else if (source.public_input == 0) .sum else .count, .coordinate = if (family == .ram_lanes) source.public_input else 0 });
    };
    return wires.toOwnedSlice(a);
}
fn parity(comptime family: Schedule.Family) !void {
    const a = std.testing.allocator;
    const Bus = BusFor(family);
    const Shape = Word.ForFamily(family).Shape;
    const shape = try Shape.init(a, if (family == .ram_lanes) 6 else 16, try config(), .{});
    defer shape.deinit();
    var composition = try Equation.ForFamily(family).compile(a, shape);
    defer composition.deinit();
    var plan = try Transcript.ForFamily(family).recordForShape(a, shape, 1, .{});
    defer plan.deinit();
    const actual = try Schedule.For(family, Bus).collect(a, &plan, &composition, 3);
    defer a.free(actual);
    const expected = try original(family, a, &plan, &composition);
    defer a.free(expected);
    try std.testing.expectEqualDeep(expected, actual);
    try std.testing.expectEqual(try Bus.scheduleDigest(expected), try Bus.scheduleDigest(actual));
    for (actual[0..16], 0..) |wire, index| {
        try std.testing.expectEqual(index, wire.wire);
        try std.testing.expectEqual(@as(u32, 3), wire.uses);
        try std.testing.expectEqual(if (index < 8) Bus.Source.fixed_root else Bus.Source.main_root, wire.source);
    }
    var equations: usize = 0;
    for (actual) |wire| if (wire.circuit == 1500) {
        equations += 1;
        try std.testing.expect(wire.uses != 0);
    };
    try std.testing.expect(equations != 0);
}
test "word fixed public: original RAM external root statement and 61-input routing parity" {
    try parity(.ram_lanes);
}
test "word fixed public: original range16 shard count sum and root routing parity" {
    try parity(.range16);
}
fn rejected(comptime family: Schedule.Family) !void {
    const a = std.testing.allocator;
    const Bus = BusFor(family);
    const invalid = if (family == .ram_lanes) error.InvalidRamPublicSchedule else error.InvalidRangePublicSchedule;
    const Shape = Word.ForFamily(family).Shape;
    const shape = try Shape.init(a, if (family == .ram_lanes) 5 else 16, try config(), .{});
    defer shape.deinit();
    var composition = try Equation.ForFamily(family).compile(a, shape);
    defer composition.deinit();
    var plan = try Transcript.ForFamily(family).recordForShape(a, shape, 1, .{});
    defer plan.deinit();
    try std.testing.expectError(invalid, Schedule.For(family, Bus).collect(a, &plan, &composition, 0));
    // Mutate borrowed routing copies only; immutable original Plan custody is
    // retained, and these structural proposals cannot mint an admitted owner.
    const roots = try a.dupe(@TypeOf(plan.fixed.root_reads[0]), plan.fixed.root_reads);
    defer a.free(roots);
    const payloads = try a.dupe(@TypeOf(plan.fixed.payload_reads[0]), plan.fixed.payload_reads);
    defer a.free(payloads);
    var proposal = plan;
    proposal.fixed.root_reads = roots;
    proposal.fixed.payload_reads = payloads;
    for (roots) |*receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
        const old = receipt.source;
        receipt.source.first_wire = 7;
        try std.testing.expectError(invalid, Schedule.For(family, Bus).collect(a, &proposal, &composition, 3));
        receipt.source = old;
        break;
    };
    for (payloads) |*receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
        const old = receipt.source;
        receipt.source.first_wire = std.math.maxInt(u32);
        try std.testing.expectError(invalid, Schedule.For(family, Bus).collect(a, &proposal, &composition, 3));
        receipt.source = old;
        break;
    };
    for (composition.sources) |*source| if (source.* == .public_input) {
        const old = source.*;
        source.* = .{ .public_input = std.math.maxInt(u32) };
        try std.testing.expectError(invalid, Schedule.For(family, Bus).collect(a, &plan, &composition, 3));
        source.* = old;
        break;
    };
    try plan.validate();
    try composition.validateAgainst(shape);
}
test "word fixed public: native receipt span and graph ordinal mutations reject without integer overflow" {
    try rejected(.ram_lanes);
    try rejected(.range16);
}
fn allocation(a: std.mem.Allocator, plan: *const Plan, composition: *const Equation.ForFamily(.ram_lanes).Compiled) !void {
    const wires = try Schedule.For(.ram_lanes, BusFor(.ram_lanes)).collect(a, plan, composition, 3);
    defer a.free(wires);
}
test "word fixed public: all routing allocation failures release original source ownership" {
    const a = std.testing.allocator;
    const Shape = Word.ForFamily(.ram_lanes).Shape;
    const shape = try Shape.init(a, 5, try config(), .{});
    defer shape.deinit();
    var composition = try Equation.ForFamily(.ram_lanes).compile(a, shape);
    defer composition.deinit();
    var plan = try Transcript.ForFamily(.ram_lanes).recordForShape(a, shape, 1, .{});
    defer plan.deinit();
    try std.testing.checkAllAllocationFailures(a, allocation, .{ &plan, &composition });
    try plan.validate();
    try composition.validateAgainst(shape);
}
