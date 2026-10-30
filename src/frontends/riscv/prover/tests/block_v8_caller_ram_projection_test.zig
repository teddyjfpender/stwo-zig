//! Algebra/descriptor tests only; no original/recursive proof qualification.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const C = @import("../block_v8_caller_ram_projection_v1.zig");
const Joined = @import("../block_v8_window_endpoint_local_closure_v1.zig");
const R = @import("../block_v7_memory_relations_v1.zig");
const Access = @import("../block_execution_access_bridge_v2.zig");
const K = @import("../block_v8_ram_endpoint_kernel_v1.zig");
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
fn relation() R.Relation(Q, 7) {
    return .{ .z = Q.fromU32Unchecked(3, 5, 7, 11), .powers = .{ q(1), q(13), q(169), q(2197), q(28561), q(371293), q(4826809) } };
}
fn bytes(value: u32) [4]Q {
    var out: [4]Q = undefined;
    for (&out, 0..) |*byte, index| byte.* = q((value >> @as(u5, @intCast(8 * index))) & 255);
    return out;
}
fn pair(address: u32, previous_clock: u32, clock: u32, before: u32, after: u32) Access.Pair(Q) {
    return .{ .active = Q.one(), .space = Q.one(), .source_address = q(address), .address_unit = .byte_address, .local_clock = q(clock), .consume_clock = q(previous_clock), .before = bytes(before), .after = bytes(after), .pair_residuals = @splat(Q.zero()), .access_ordinal = null };
}
test "caller RAM projection preserves actual nonzero Keccak state words and native signs" {
    const Keccak = @import("../../air/guest_precompile/keccakf_caller.zig");
    const Witness = @import("../../air/guest_precompile/keccakf_witness.zig");
    const Relations = @import("../guest_precompile/ethereum_transcript.zig").Relations;
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try Relations.draw(std.testing.allocator, &channel);
    const native = R.Relation(Q, 7).from(relations.base.memory_access);
    var caller: [Keccak.Layout.main_columns]Q = @splat(Q.zero());
    caller[Keccak.Layout.enabler] = Q.one();
    caller[Keccak.Layout.execution_clock] = q(10);
    caller[Keccak.Layout.pointer_double_word_index] = q(0x12345);
    for (0..Keccak.word_count) |word| caller[Keccak.Layout.previousClock(word)] = q(3);
    var input: [Witness.state_cell_count]Q = undefined;
    var output: [Witness.state_cell_count]Q = undefined;
    for (&input, &output, 0..) |*before, *after, index| {
        before.* = q(@intFromBool(index % 3 == 0));
        after.* = q(@intFromBool(index % 5 == 0));
    }
    const events = Keccak.coreEvents(Q, &caller, &input, &output, &relations.keccak);
    for (1..Keccak.word_count + 1) |slot| {
        const offset = (slot - 1) * 32;
        const point = try C.keccak(Q, &caller, input[offset..][0..32].*, output[offset..][0..32].*, slot, native);
        const consumed = events[6 + 3 * (slot - 1)];
        const emitted = events[7 + 3 * (slot - 1)];
        try std.testing.expect(point.term.left.eql(consumed.d1));
        try std.testing.expect(point.term.right.eql(emitted.d1));
        try std.testing.expect(point.term.wl.eql(consumed.n1));
        try std.testing.expect(point.term.wr.eql(emitted.n1));
        const zero_bits: [32]Q = @splat(Q.zero());
        const zero_point = try C.keccak(Q, &caller, zero_bits, zero_bits, slot, native);
        try std.testing.expect(!point.term.left.eql(zero_point.term.left));
        try std.testing.expect(!point.term.right.eql(zero_point.term.right));
    }
    try std.testing.expectError(error.InvalidCallerEndpointSlot, C.keccak(Q, &caller, input[0..32].*, output[0..32].*, 0, native));
}
test "caller projection preserves pair constraints and rejects mismatched address units" {
    var access = pair(64, 2, 6, 7, 8);
    access.pair_residuals[0] = Q.one();
    const point = try C.fromPair(Q, access, relation());
    const result = C.equations(Q, point, @splat(Q.zero()), @splat(Q.zero()), Q.zero());
    try std.testing.expect(result[0].eql(Q.one()));
    access.address_unit = .word_index;
    try std.testing.expectError(error.UnsupportedCallerEndpointAddressUnit, C.fromPair(Q, access, relation()));
    access.address_unit = .byte_address;
    access.consume_clock = null;
    try std.testing.expectError(error.MissingCallerEndpointClock, C.fromPair(Q, access, relation()));
}
test "two precompile calls interleaved with native RAM close one window not sequential source phases" {
    const address = 64;
    const first_native = try C.fromPair(Q, pair(address, 0, 2, 1, 2), relation());
    const first_caller = try C.fromPair(Q, pair(address, 2, 6, 2, 3), relation());
    const second_caller = try C.fromPair(Q, pair(address, 6, 10, 3, 4), relation());
    const last_native = try C.fromPair(Q, pair(address, 10, 14, 4, 5), relation());
    const native_sum = (try first_native.term.fraction()).add(try last_native.term.fraction());
    const row = try K.construct(.{ .address = address, .initial = 1, .final = 5, .last_clock = 14 }, null, .{ .source_ordinal = 7, .max_local_clock = 15 });
    const supplier = (try relation().combineSecure(K.localTuple(Q, row, false)).inv()).sub(try relation().combineSecure(K.localTuple(Q, row, true)).inv());
    const identity: [32]u8 = @splat(17);
    var callers = [_]Joined.Caller{
        .{ .index = 0, .window_identity = identity, .ram = try first_caller.term.fraction(), .state = Q.zero(), .registers = Q.zero(), .internal_residual = Q.zero() },
        .{ .index = 1, .window_identity = identity, .ram = try second_caller.term.fraction(), .state = Q.zero(), .registers = Q.zero(), .internal_residual = Q.zero() },
    };
    const native = Joined.Native{ .ram = native_sum, .ram_clock = Q.zero(), .state_residual = Q.zero(), .register_residual = Q.zero() };
    try Joined.close(identity, 2, native, &callers, supplier);
    try std.testing.expect(!native_sum.add(supplier).isZero());
    try std.testing.expectError(error.InvalidEndpointWindowRoster, Joined.close(identity, 2, native, &callers[0..1].*, supplier));
    callers[0].internal_residual = Q.one();
    callers[1].internal_residual = Q.one().neg();
    try std.testing.expect(callers[0].internal_residual.add(callers[1].internal_residual).isZero());
    try std.testing.expectError(error.UnclosedEndpointCallerArithmetic, Joined.close(identity, 2, native, &callers, supplier));
    callers[0].internal_residual = Q.zero();
    callers[1].internal_residual = Q.zero();
    callers[1].window_identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedEndpointWindowCaller, Joined.close(identity, 2, native, &callers, supplier));
}
test "caller endpoint plan reconstructs the exact active inventory" {
    const a = std.testing.allocator;
    const Profile = @import("../blake3_ethereum_sha_profile.zig");
    const Geometry = @import("../../air/guest_precompile/ethereum_statement.zig");
    var shapes: Geometry.SecpShapes = undefined;
    inline for (@typeInfo(Geometry.SecpShapes).@"struct".fields) |field| @field(shapes, field.name) = .{ .log_size = 1, .n_rows = 1 };
    shapes.byte = .{ .log_size = 8, .n_rows = 256 };
    const statement: Profile.admission.Statement = try @import("../block_v5_precompile_witness_v1.zig").canonicalStatement(a, 1, 1, 2, shapes);
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 4 };
    var plan = try C.Plan.derive(a, &statement, 4, frame);
    defer plan.deinit();
    try plan.require(&statement, 4, frame);
    try std.testing.expectEqual(try @import("../block_execution_external_trace_v2.zig").expectedEventCountForMode(&statement, 1), plan.logical_ram_accesses);
    const saved = plan.descriptors[0];
    plan.descriptors[0].slot = 0;
    try std.testing.expectError(error.UntrustedCallerEndpointPlan, plan.require(&statement, 4, frame));
    plan.descriptors[0] = saved;
    plan.logical_ram_accesses += 1;
    try std.testing.expectError(error.UntrustedCallerEndpointPlan, plan.require(&statement, 4, frame));
}
