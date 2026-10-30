const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const A = @import("../air/block_v8_window_closure_algebra_v1.zig");
const G = @import("../air/composition_graph_recorder.zig");
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
fn word(value: u32) [4]Q {
    var bytes: [4]Q = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = q(@intCast((value >> @intCast(8 * index)) & 255));
    return bytes;
}
fn element(comptime n: usize, seed: u32) @import("../../air/relation_challenges.zig").RelationElements(n) {
    return .init(Q.fromU32Unchecked(seed, 2, 3, 4), q(seed + 7));
}
test "native boundary closure exactly matches existing register and state arithmetic" {
    var initial: [32]u32 = @splat(0);
    var final: [32]u32 = @splat(0);
    var last: [32]u32 = @splat(0);
    for (1..32) |index| {
        initial[index] = 0xf0000000 + @as(u32, @intCast(index));
        final[index] = 0x80000000 + @as(u32, @intCast(index));
        last[index] = @intCast(index + 3);
    }
    const data = .{ .initial_pc = @as(u32, 4096), .final_pc = @as(u32, 4112), .clock = @as(u32, 40), .initial_regs = initial, .final_regs = final, .reg_last_clock = last };
    const relations = .{ .registers_state = element(2, 11), .memory_access = element(7, 13) };
    var boundary = A.Boundary(Q){ .initial_pc = q(data.initial_pc), .final_pc = q(data.final_pc), .final_clock_plus_one = q(data.clock + 1), .initial_register_bytes = undefined, .final_register_bytes = undefined, .register_last_clock = undefined };
    for (0..32) |index| {
        boundary.initial_register_bytes[index] = word(initial[index]);
        boundary.final_register_bytes[index] = word(final[index]);
        boundary.register_last_clock[index] = q(last[index]);
    }
    const got = try A.native(Q, &.{}, &.{}, boundary, .{ .z = relations.registers_state.z, .powers = relations.registers_state.alpha_powers }, .{ .z = relations.memory_access.z, .powers = relations.memory_access.alpha_powers });
    const Public = @import("../../air/public_logup_arithmetic.zig");
    try std.testing.expectEqualDeep(try Public.registersStateSumFor(Q, &data, &relations), got.state);
    try std.testing.expectEqualDeep(try Public.registerMemoryAccessSumFor(Q, &data, &relations), got.registers);
}
test "six memory closure equations compile to a graph and detect individual forged planes" {
    const a = std.testing.allocator;
    var values: [67]Q = @splat(Q.zero());
    // Two physical RAM components, then interval/range providers and an
    // independently bound expected snapshot delta. Claims stay separate.
    for (0..2) |component| for (0..31) |plane| {
        values[component * 31 + plane] = Q.fromU32Unchecked(@intCast(plane + 1), @intCast(component + 2), 3, 4);
    };
    // Link has no external provider; make its two component claims cancel.
    values[32] = values[1].neg();
    values[62] = values[2].add(values[33]).neg();
    var ranges = Q.zero();
    for (0..2) |component| for (3..27) |plane| {
        ranges = ranges.add(values[component * 31 + plane]);
    };
    values[64] = ranges.neg();
    values[63] = values[27].add(values[58]);
    values[65] = values[28].add(values[59]);
    values[66] = values[29].add(values[30]).add(values[60]).add(values[61]);
    var b = G.Builder.init(a);
    defer b.deinit();
    var inputs: [67]G.Scalar = undefined;
    for (&inputs) |*value| value.* = (try b.input()).value;
    try b.activate();
    defer if (b.active) b.deactivate();
    const symbolic = try A.memory(G.Scalar, &.{ inputs[0..31].*, inputs[31..62].* }, inputs[62..64].*, inputs[64..66].*, inputs[66]);
    for (symbolic.constraints) |constraint| try b.constrainZero(constraint);
    b.deactivate();
    var circuit = try b.finish();
    defer circuit.deinit();
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    defer a.free(evaluated);
    try circuit.evaluateInto(&values, evaluated);
    for (circuit.outputs) |output| try std.testing.expect(evaluated[output].isZero());
    // All six distinct relation/counter/state closure equations are active.
    for ([_]usize{ 1, 2, 3, 27, 28, 29 }) |plane| {
        var forged = values;
        forged[plane] = forged[plane].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&forged, evaluated));
    }
}

test "global source closure includes every provider byte request and exact count" {
    const Source = A.SourceExports(Q);
    const first = Source{ .program = q(3), .transition = q(5), .fetches = q(3), .events = q(5), .tables = @splat(q(7)), .byte_requests = q(2) };
    var second = Source{ .program = q(13), .transition = q(17), .fetches = q(7), .events = q(11), .tables = @splat(q(19)), .byte_requests = q(23) };
    const byte_pair = @intFromEnum(@import("../../air/lookups/tables/schema.zig").Kind.range_check_8_8);
    var providers: [6]Q = @splat(q(26).neg());
    providers[byte_pair] = providers[byte_pair].sub(q(25));
    const honest = A.global(Q, &.{ first, second }, q(16).neg(), q(22).neg(), providers, q(10), q(16));
    for (honest) |equation| try std.testing.expect(equation.isZero());
    second.byte_requests = second.byte_requests.add(Q.one());
    const forged = A.global(Q, &.{ first, second }, q(16).neg(), q(22).neg(), providers, q(10), q(16));
    try std.testing.expect(forged[2 + byte_pair].eql(Q.one()));
    for (forged, 0..) |equation, index| if (index != 2 + byte_pair) try std.testing.expect(equation.isZero());
}
