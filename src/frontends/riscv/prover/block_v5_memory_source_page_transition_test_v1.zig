//! Bounded nonproving tests of metadata, census, original accumulator equations
//! and ownership. Scalar fixtures never enter the genuine verify proof path.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const Receiver = @import("block_v5_memory_source_page_transition_receiver_v1.zig");
const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(true);
const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Engine = Memory.ForBackend(Cpu);
const Lane = @import("block_v5_ram_lanes_receiver_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Page = @import("block_v5_memory_source_page_join_owner_v1.zig");

fn memoryPins() Lane.Pins {
    // Independent metadata fixture, never admitted as a real proof policy.
    var result = std.mem.zeroes(Lane.Pins);
    result.first_round = &.{};
    result.pins = &.{};
    result.range_roots = &.{};
    result.expected_total_events = 17;
    result.expected_seal_digest = @splat(3);
    result.seal.memory_plan_digest = @splat(4);
    result.source.initial.initial_rw_root = @splat(5);
    result.source.expected_final_rw_root = @splat(6);
    result.source.initial.first_touches.records = 2;
    result.source.endpoints.records = 2;
    return result;
}
fn proposal(pins: Lane.Pins, sealed: Seal.Sealed) Page.Open {
    return .{ .transition_sum = Q.zero(), .events = pins.expected_total_events, .first_touches = 2, .endpoints = 2, .range_requests = 0, .memory_instances = 0, .range_shards = 0, .raw_pages = 0, .fold_pages = 0, .base_seal = sealed.digest, .page_seal = @splat(7), .epoch = @splat(8), .source_identity = @splat(9), .memory_plan = pins.seal.memory_plan_digest, .initial_root = pins.source.initial.initial_rw_root, .final_root = pins.source.expected_final_rw_root };
}
test "source PAGE transition: independently pinned memory roots layout limits and exact roster reject changes" {
    const pins = memoryPins();
    try Receiver.testing.requireMemory(pins, pins);
    var changed = pins;
    changed.source.initial.layout.input_base += 4;
    try std.testing.expectError(error.UntrustedSourcePageTransitionMemory, Receiver.testing.requireMemory(pins, changed));
    changed = pins;
    changed.source.expected_final_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageTransitionMemory, Receiver.testing.requireMemory(pins, changed));
    changed = pins;
    changed.limits.plan.max_instances += 1;
    try std.testing.expectError(error.UntrustedSourcePageTransitionMemory, Receiver.testing.requireMemory(pins, changed));
    changed = pins;
    changed.expected_total_events += 1;
    try std.testing.expectError(error.UntrustedSourcePageTransitionMemory, Receiver.testing.requireMemory(pins, changed));
    const roots = [_][2][32]u8{.{ @splat(10), @splat(11) }};
    changed = pins;
    changed.range_roots = &roots;
    try std.testing.expectError(error.UntrustedSourcePageTransitionMemory, Receiver.testing.requireMemory(pins, changed));
    var expected = changed;
    var other = roots;
    other[0][0][0] ^= 1;
    changed.range_roots = &other;
    try std.testing.expectError(error.UntrustedSourcePageTransitionMemory, Receiver.testing.requireMemory(expected, changed));
    expected.range_roots = &roots;
    try Receiver.testing.requireMemory(expected, expected);
}
test "source PAGE transition: source proposals cannot change independently expected census plans or roots" {
    const pins = memoryPins();
    var sealed: Seal.Sealed = undefined;
    sealed.digest = pins.expected_seal_digest;
    const original = proposal(pins, sealed);
    try Receiver.testing.requireSourceIdentity(original, pins, sealed);
    inline for (.{ "events", "first_touches", "endpoints", "memory_instances", "range_shards" }) |field| {
        var changed = original;
        @field(changed, field) += 1;
        try std.testing.expectError(error.UntrustedSourcePageTransitionSource, Receiver.testing.requireSourceIdentity(changed, pins, sealed));
    }
    inline for (.{ "base_seal", "memory_plan", "initial_root", "final_root" }) |field| {
        var changed = original;
        @field(changed, field)[0] ^= 1;
        try std.testing.expectError(error.UntrustedSourcePageTransitionSource, Receiver.testing.requireSourceIdentity(changed, pins, sealed));
    }
}
test "source PAGE transition: genuine caller shape census includes ALL RW and ordinary overflow rejects" {
    const a = std.testing.allocator;
    const Protocol = @import("block_v5_precompile_protocol_v1.zig");
    var empty = try @import("guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, &.{}, &.{}, &.{}, &.{}, 4, Protocol.circuit_profile);
    defer empty.deinit();
    const statement = try @import("block_v5_precompile_witness_v1.zig").canonicalStatement(a, 3, 0, 1, empty.shapes());
    const extensions = [_]Memory.ExtensionPin{.{ .public = .{ .execution_index = 0, .statement = &statement, .total_steps = 4, .expected_key_id = @splat(12) }, .witness_root = @splat(13) }};
    var pins: Memory.Pins = undefined;
    pins.ordinary_events = &.{ 7, 11 };
    pins.extensions = &extensions;
    const External = @import("block_execution_external_trace_v2.zig");
    inline for (.{ @as(u32, 0), @as(u32, 1) }) |mode| {
        const caller = try External.expectedEventCountForMode(&statement, mode);
        try std.testing.expectEqual(18 + caller, try Receiver.testing.exactEventCensus(pins, mode));
    }
    try std.testing.expectEqual(@as(u64, 5), (try Receiver.testing.exactEventCensus(pins, 0)) - (try Receiver.testing.exactEventCensus(pins, 1)));
    try std.testing.expectError(error.InvalidV5RegisterCustodyMode, Receiver.testing.exactEventCensus(pins, 2));
    pins.extensions = &.{};
    pins.ordinary_events = &.{};
    try std.testing.expectEqual(@as(u64, 0), try Receiver.testing.exactEventCensus(pins, 1));
    pins.ordinary_events = &.{ std.math.maxInt(u64), 1 };
    try std.testing.expectError(error.Overflow, Receiver.testing.exactEventCensus(pins, 1));
}
test "source PAGE transition: original hook accumulator rejects missing duplicate census and wrong transition sign" {
    // Exercise only the original private accumulator's order/count/equations.
    // No fixture here is accepted by Receiver.verify as a fresh proof receipt.
    var engine: Engine = undefined;
    engine.owned = false;
    try std.testing.expectError(error.InvalidV5MemoryNativeHookOrder, engine.onFusedNative(0, undefined, undefined, null));
    try std.testing.expectError(error.InvalidV5MemoryCallerHookOrder, engine.onFusedPrecompile(0, undefined, undefined, undefined));
    try std.testing.expectError(error.IncompleteV5MemoryHooks, engine.finish());
    engine.owned = true;
    engine.next_native = 0;
    engine.pins.executions = &.{undefined};
    try std.testing.expectError(error.InvalidV5MemoryNativeHookOrder, engine.onFusedNative(1, undefined, undefined, null));
    try std.testing.expectError(error.IncompleteV5MemoryHooks, engine.finish());
    engine.next_native = 1;
    engine.next_extension = 0;
    engine.pins.extensions = &.{};
    const part = [_]Memory.ExecutionBytes{.{ .index = 0, .event_count = 3, .request_count = 0, .max_requests = 0, .sum = Q.zero() }};
    engine.byte_parts = @constCast(&part);
    engine.fresh_memory.event_count = 4;
    try std.testing.expectError(error.UnclosedV5PackedTransitionBus, engine.finish());
    engine.fresh_memory.event_count = 3;
    engine.transition_sum = Q.one();
    engine.fresh_memory.transition_sum = Q.one();
    try std.testing.expectError(error.UnclosedV5PackedTransitionBus, engine.finish());
    // Genuine success is reserved for the original fresh hook path; directly
    // test the unchanged zero equation rather than manufacture an OpenPartition.
    var sink = @import("block_v5_global_join_algebra_v1.zig").ScalarSink{};
    try @import("block_v5_global_join_algebra_v1.zig").Algebra(Q).transition(&sink, Q.one(), Q.one().neg());
}
test "source PAGE transition: resource limits reject before undefined original proof authorities" {
    try std.testing.expectError(error.SourcePageTransitionResourceLimit, Receiver.verify(std.testing.allocator, undefined, undefined, undefined, undefined, .{ .max_live_bytes = 0 }));
    try std.testing.expectError(error.SourcePageTransitionResourceLimit, Receiver.verify(std.testing.allocator, undefined, undefined, undefined, undefined, .{ .max_executions = 0 }));
    try std.testing.expect(!Receiver.Open.complete_block_authority);
}
fn storageCase(a: std.mem.Allocator) !void {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const owner = try Budget.create(a, 4096);
    errdefer owner.destroy();
    const parts = try owner.allocator().alloc(Memory.ExecutionBytes, 2);
    // Disposal-only object: source/program authority is deliberately absent.
    var result: Receiver.Open = undefined;
    result.allocation_owner = owner;
    result.bytes = parts;
    result.deinit();
}
test "source PAGE transition: retained output allocation lease tears down on every allocation failure" {
    try storageCase(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, storageCase, .{});
}
