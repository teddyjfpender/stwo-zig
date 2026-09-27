const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const public = @import("blake3_segment_public.zig");
const native_trace = @import("blake3_execution_trace.zig");
const native_proof = @import("block_v5_native_execution_proof_v3.zig");
const sidecar = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const slots_mod = @import("block_execution_sidecar_batch_v2.zig");
const opcode_trace = @import("block_execution_sidecar_trace_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const seals = @import("block_v5_source_seal_v1.zig");
const catalog_mod = @import("block_v5_native_template_catalog_v1.zig");
const fixture_mod = @import("block_v5_word_memory_join_fixture_v1.zig");
const join_mod = @import("block_v5_word_memory_join_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
const Capture = struct {
    proof: ?sidecar.Proof = null,
    calls: u32 = 0,
    fn take(ctx: *anyopaque, index: u32) anyerror!sidecar.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0) return error.InvalidJoinOpcodeCapture;
        const result = self.proof orelse return error.InvalidJoinOpcodeCapture;
        self.proof = null;
        self.calls += 1;
        return result;
    }
    fn deinit(self: *Capture, a: std.mem.Allocator) void {
        if (self.proof) |*owned| owned.deinit(a);
    }
};

test "block-v5 packed joint fresh native sorted range source register transition closure" {
    try exercise(false);
}
test "block-v5 packed joint rejects re-sealed valid sorted clock against native access" {
    try exercise(true);
}
fn exercise(wrong_global_clock: bool) !void {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(1);
    defer segment.deinit();
    var io = try public.Owned.init(a, &segment);
    defer io.deinit();
    io.data.program_root = .{ .bytes = @splat(3) };
    const owner = try native_trace.Owner.init(a, &segment.execution_trace, io.data, &segment.state_chain_tracker);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.global_first_cycle, .cycle_count = @intCast(segment.cycle_count) };
    const slots = try slots_mod.slotsFromStatement(a, &owner.statement, frame);
    defer a.free(slots);
    const traces = try a.alloc(opcode_trace.Trace, slots.len);
    defer a.free(traces);
    const inputs = try a.alloc(sidecar.Input, slots.len);
    defer a.free(inputs);
    var initialized: usize = 0;
    defer for (traces[0..initialized]) |*trace| trace.deinit();
    var events: [2]Transition = undefined;
    var event_count: usize = 0;
    for (slots, inputs, 0..) |slot, *input, index| {
        var offset: usize = 0;
        var found: ?usize = null;
        for (owner.statement.component_descs[0..owner.statement.n_components], 0..) |desc, component| {
            if (offset == slot.main_offset and desc.family == slot.family) {
                found = component;
                break;
            }
            offset += desc.n_columns;
        }
        traces[index] = try opcode_trace.Trace.init(a, slot.family, &owner.opcode_columns.components[found orelse return error.MissingJointOpcodeComponent], slot.slot, slot.log_size, slot.frame);
        initialized += 1;
        input.* = .{ .descriptor = slot, .trace = &traces[index] };
        for (0..traces[index].domainSize()) |logical| {
            const row = try traces[index].row(logical);
            if (!row.active) continue;
            if (event_count >= events.len) return error.UnexpectedJointAccessCensus;
            events[event_count] = try bus.decodeTransitionTuple(row.tuple);
            event_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), event_count);
    if (events[0].address > events[1].address) std.mem.swap(Transition, &events[0], &events[1]);
    // A candidate may carry independently re-sealed sorted data and a valid
    // endpoint table. It still must match the actual native access clock.
    if (wrong_global_clock) events[0].clock ^= @as(u64, 1) << 32;
    var memory_fixture = try fixture_mod.Fixture.init(a, events, io.data.initial_regs, io.data.final_regs, config);
    defer memory_fixture.deinit();
    const pin = try @import("block_v5_native_public_admission_v1.zig").Admission.init(.{
        .job_id = @splat(1),
        .source_image_digest = @splat(2),
        .program_root = @splat(3),
        .program_plan_digest = @splat(4),
        .memory_plan_digest = memory_fixture.first.plan_digest,
        .initial_source_plan_digest = try memory_fixture.endpoint_pins.initial.digest(),
        .rw_endpoint_plan_digest = try memory_fixture.endpoint_pins.digest(),
        .execution_index = 0,
        .first_cycle = segment.global_first_cycle,
        .last_cycle = segment.global_first_cycle + segment.cycle_count - 1,
    }, &io.data);
    const Native = native_proof.ForBackend(Cpu);
    var native_first = try Native.commitFirstRound(a, owner, pin, config, .rv32im_zkvm_v1, 0);
    defer native_first.deinit(a);
    const records = [_]catalog_mod.Record{.{ .index = 0, .template_id = native_first.template_id, .geometry_digest = native_first.template.geometry_digest, .fixed_root = native_first.template.fixed_root }};
    const catalog = catalog_mod.Admission{ .records = &records };
    var counter = try @import("../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const Sidecar = sidecar.ForPackedBackend(Cpu);
    var opcode_first = try Sidecar.commitFirstRound(a, owner.preprocessed.items, owner.main.items, inputs, slots, &counter, 0, native_first.template_id, config);
    defer opcode_first.deinit(a);
    var counts: [seals.family_count]u32 = @splat(0);
    inline for ([_]seals.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range }) |family| counts[@intFromEnum(family) - 1] = 1;
    const pins = seals.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_catalog_digest = try catalog.digest(), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = memory_fixture.first.plan_digest, .initial_source_plan_digest = try memory_fixture.endpoint_pins.initial.digest(), .rw_endpoint_plan_digest = try memory_fixture.endpoint_pins.digest(), .expected_final_rw_root = memory_fixture.endpoint_pins.expected_final_rw_root, .register_endpoint_plan_digest = try memory_fixture.register_pins.digest(), .config = config, .counts = counts };
    const entries = [_]seals.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        native_first.entry(),
        sidecar.packedEntry(native_first.instance_id, native_first.roots, opcode_first.roots[2], 0, slots),
        .{ .family = .program_request, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        memory_fixture.first.memoryEntry(0),
        memory_fixture.first.rangeEntry(0),
    };
    const sealed = try seals.seal(pins, &entries);
    var capture = fixture_mod.Capture{};
    defer capture.deinit(a);
    try memory_fixture.prove(&capture, pins, &entries, sealed);
    const native_received = try Native.proveWithCatalog(a, &native_first, sealed, pins, &entries, catalog);
    const native_receipt = try Native.verifyOwnedWithCatalog(a, native_received, &owner.statement, pin, native_first.template, native_first.template_id, .rv32im_zkvm_v1, 0, sealed, pins, &entries, catalog);
    var opcode_capture = Capture{ .proof = try Sidecar.prove(a, &opcode_first, inputs, slots, sealed, pins, &entries, catalog, &native_receipt, 0, opcode_first.roots[2]) };
    defer opcode_capture.deinit(a);
    const instance_pins = [_]@import("block_v5_program_native_batch_receiver_v3.zig").InstancePin{.{ .shape = &owner.statement, .admission = pin, .template = native_first.template, .template_id = native_first.template_id, .profile = .rv32im_zkvm_v1 }};
    const Join = join_mod.ForBackend(Cpu);
    var joined = try Join.init(a, .{ .memory = @import("block_v5_sorted_memory_v1.zig").Pins.fromWord(memory_fixture.pins(pins, &entries, sealed)), .catalog = catalog, .executions = &instance_pins, .opcode_witness_roots = &.{opcode_first.roots[2]}, .ordinary_events = &.{2}, .extensions = &.{} }, &.{}, memory_fixture.files(), @import("block_v5_sorted_memory_v1.zig").Loader.fromWord(capture.loader()), .{ .context = &opcode_capture, .take_opcode = Capture.take }, sealed);
    defer joined.deinit();
    try std.testing.expectError(error.IncompleteV5MemoryHooks, joined.finish());
    try joined.onNative(a, 0, instance_pins[0], &native_receipt);
    try std.testing.expectEqual(@as(u32, 1), opcode_capture.calls);
    try std.testing.expectError(error.InvalidV5MemoryNativeHookOrder, joined.onNative(a, 0, instance_pins[0], &native_receipt));
    if (wrong_global_clock) {
        try std.testing.expectError(error.UnclosedV5PackedTransitionBus, joined.finish());
        return;
    }
    var closed = try joined.finish();
    defer closed.deinit(a);
    try std.testing.expect(closed.memory.register_endpoints_verified);
    try std.testing.expectEqual(@as(u64, 2), closed.memory.event_count);
    try std.testing.expectEqual(@as(u64, 28), closed.bytes[0].request_count);
    try std.testing.expectEqual(@as(u64, 28), closed.bytes[0].max_requests);
    try std.testing.expect(!closed.ordinary_memory_opposite.isZero());
    try std.testing.expect(closed.external_memory_opposite.isZero());
}
