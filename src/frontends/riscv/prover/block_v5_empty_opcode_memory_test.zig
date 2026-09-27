//! Real caller-only leaf: native-v3 + empty family3 + family11/13 + memory.
//! ROM, native table and recursive obligations remain explicitly unproved.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const native = @import("block_v5_native_execution_proof_v3.zig");
const profile = @import("blake3_ethereum_sha_profile.zig");
const family = @import("block_v5_precompile_family_proof_v1.zig");
const caller = @import("block_v5_precompile_protocol_v1.zig");
const external = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const source = @import("block_execution_external_trace_v2.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const empty = @import("block_v5_empty_opcode_memory_v1.zig");
const memory_fixture = @import("block_v5_caller_memory_fixture_v1.zig");
const join_mod = @import("block_v5_word_memory_join_v1.zig");
const Programs = @import("block_v5_program_native_batch_receiver_v3.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
const Capture = struct {
    proof: ?external.Proof,
    opcode_calls: u32 = 0,
    fn ordinary(ctx: *anyopaque, _: u32) anyerror!@import("block_v5_opcode_memory_sidecar_proof_v1.zig").Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        self.opcode_calls += 1;
        return error.UnexpectedEmptyOpcodeStarkLoad;
    }
    fn take(ctx: *anyopaque, index: u32) anyerror!external.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0) return error.InvalidEmptyCallerCapture;
        const result = self.proof orelse return error.InvalidEmptyCallerCapture;
        self.proof = null;
        return result;
    }
    fn deinit(self: *Capture, a: std.mem.Allocator) void {
        if (self.proof) |*owned| owned.deinit(a);
    }
};
test "block-v5 empty opcode fresh SHA Keccak leaf closes packed caller memory" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const elf_mod = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = elf_mod.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = elf_mod.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var setup = try session.startSegment(3);
    defer setup.deinit();
    var segment = try session.resumeSegment(setup.base.continuation.?, 4);
    defer segment.deinit();
    var extension = try @import("block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &segment);
    defer extension.deinit();
    try std.testing.expectEqual(@as(u32, 3), profile.externalCount(&extension.statement));
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const fixed = try profile.preprocessed(a, &extension.statement);
    defer {
        for (fixed) |column| a.free(column.values);
        a.free(fixed);
    }
    var main = try profile.mainWitness(a, &extension);
    defer main.deinit(a);
    const fixed_logs = try caller.columnLogs(a, &extension.statement, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try caller.columnLogs(a, &extension.statement, .main);
    defer a.free(main_logs);
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = @intCast(segment.base.cycle_count) };
    const slots = try source.descriptorsFromStatement(a, &extension.statement, fixed_logs, main_logs, frame);
    defer a.free(slots);
    const traces = try a.alloc(source.Trace, slots.len);
    defer a.free(traces);
    var initialized: usize = 0;
    defer for (traces[0..initialized]) |*trace| trace.deinit();
    const inputs = try a.alloc(external.Input, slots.len);
    defer a.free(inputs);
    var events: std.ArrayList(Transition) = .empty;
    defer events.deinit(a);
    for (slots, traces, inputs) |slot, *trace, *input| {
        trace.* = try source.Trace.init(a, slot, fixed, main.columns);
        initialized += 1;
        input.* = .{ .descriptor = slot, .trace = trace };
        for (0..trace.domainSize()) |logical| {
            const row = try trace.row(logical);
            if (row.active) try events.append(a, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
        }
    }
    try std.testing.expectEqual(@as(usize, 103), events.items.len);
    var io = try @import("blake3_segment_public.zig").Owned.init(a, &segment.base);
    defer io.deinit();
    io.data.program_root = .{ .bytes = @splat(3) };
    var memory = try memory_fixture.Fixture.init(a, events.items, io.data.initial_regs, io.data.final_regs, segment.base.rw_memory.layout, config);
    defer memory.deinit();
    const pin = try @import("block_v5_native_public_admission_v1.zig").Admission.init(.{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = memory.first.plan_digest, .initial_source_plan_digest = try memory.endpoint_pins.initial.digest(), .rw_endpoint_plan_digest = try memory.endpoint_pins.digest(), .execution_index = 0, .first_cycle = segment.base.global_first_cycle, .last_cycle = segment.base.global_first_cycle + segment.base.cycle_count - 1 }, &io.data);
    const owner = try @import("blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, profile.externalCount(&extension.statement));
    defer owner.deinit();
    try owner.sealNativeOnly();
    const Native = native.ForBackend(Cpu);
    var native_first = try Native.commitFirstRound(a, owner, pin, config, .rv32im_zkvm_ethereum_sha_v1, 0);
    defer native_first.deinit(a);
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = native_first.template_id, .geometry_digest = native_first.template.geometry_digest, .fixed_root = native_first.template.fixed_root }};
    const catalog = Catalog.Admission{ .records = &records };
    const Family = family.ForBackend(Cpu);
    var first = try Family.commitFirstRound(a, &extension, extension.total_steps, config, 0, native_first.instance_id);
    defer first.deinit(a);
    var counter = try @import("../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const External = external.ForPackedBackend(Cpu);
    var external_first = try External.commitFirstRound(a, fixed, main.columns, inputs, slots, &counter, 0, first.key_id, config);
    defer external_first.deinit(a);
    const empty_entry = try empty.firstRoundEntry(a, &owner.statement, frame, native_first.entry(), 0);
    try std.testing.expectError(error.InvalidV5EmptyOpcodeAdmission, empty.firstRoundEntry(a, &owner.statement, frame, native_first.entry(), 1));
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range, .precompile, .execution_external_sidecar }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_catalog_digest = try catalog.digest(), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = memory.first.plan_digest, .initial_source_plan_digest = try memory.endpoint_pins.initial.digest(), .expected_final_rw_root = memory.endpoint_pins.expected_final_rw_root, .rw_endpoint_plan_digest = try memory.endpoint_pins.digest(), .register_endpoint_plan_digest = try memory.register_pins.digest(), .config = config, .counts = counts };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        native_first.entry(),
        empty_entry,
        .{ .family = .program_request, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        memory.first.memoryEntry(0),
        memory.first.rangeEntry(0),
        first.entry(),
        external.packedEntry(native_first.instance_id, first.instance_id, first.key_id, first.roots, external_first.roots[2], 0, slots),
    };
    const sealed = try seal.seal(pins, &entries);
    var capture = memory_fixture.Capture{};
    defer capture.deinit(a);
    memory.prove(&capture, pins, &entries, sealed) catch |err| {
        std.debug.print("EMPTY_JOIN_MEMORY_FAILURE sorted_produced={} range_produced={} error={s}\n", .{ capture.sorted != null, capture.range != null, @errorName(err) });
        return err;
    };
    std.debug.print("EMPTY_JOIN_STAGE memory_proved\n", .{});
    const native_received = try Native.proveWithCatalog(a, &native_first, sealed, pins, &entries, catalog);
    std.debug.print("EMPTY_JOIN_STAGE native_proved\n", .{});
    const fresh_native = try Native.verifyOwnedWithCatalog(a, native_received, &owner.statement, pin, native_first.template, native_first.template_id, .rv32im_zkvm_ethereum_sha_v1, 0, sealed, pins, &entries, catalog);
    std.debug.print("EMPTY_JOIN_STAGE native_verified\n", .{});
    const caller_received = try Family.prove(a, &first, sealed, pins, &entries, &pool);
    std.debug.print("EMPTY_JOIN_STAGE caller_proved\n", .{});
    const fresh_caller = try Family.verifyOwned(a, caller_received, &extension.statement, extension.total_steps, first.key_id, native_first.instance_id, 0, sealed, pins, &entries);
    std.debug.print("EMPTY_JOIN_STAGE caller_verified\n", .{});
    var external_capture = Capture{ .proof = try External.prove(a, &external_first, inputs, slots, sealed, pins, &entries, &fresh_caller.binding, 0, external_first.roots[2]) };
    defer external_capture.deinit(a);
    const instances = [_]Programs.InstancePin{.{ .shape = &owner.statement, .admission = pin, .template = native_first.template, .template_id = native_first.template_id, .profile = .rv32im_zkvm_ethereum_sha_v1 }};
    const extension_pin = Programs.ExtensionPin{ .execution_index = 0, .statement = &extension.statement, .total_steps = extension.total_steps, .expected_key_id = first.key_id };
    var join_pins = join_mod.Pins{ .memory = @import("block_v5_sorted_memory_v1.zig").Pins.fromWord(memory.pins(pins, &entries, sealed)), .catalog = catalog, .executions = &instances, .opcode_witness_roots = &.{empty.witnessRoot()}, .ordinary_events = &.{0}, .extensions = &.{.{ .public = extension_pin, .witness_root = external_first.roots[2] }} };
    const loader = join_mod.Loader{ .context = &external_capture, .take_opcode = Capture.ordinary, .take_external = Capture.take };
    const Join = join_mod.ForBackend(Cpu);
    var changed = entries;
    changed[2].roots[0][0] ^= 1;
    const wrong_seal = try seal.seal(pins, &changed);
    join_pins.memory = @import("block_v5_sorted_memory_v1.zig").Pins.fromWord(memory.pins(pins, &changed, wrong_seal));
    try std.testing.expectError(error.UntrustedV5EmptyOpcodeEntry, Join.init(a, join_pins, &.{}, memory.files(), @import("block_v5_sorted_memory_v1.zig").Loader.fromWord(capture.loader()), loader, wrong_seal));
    try std.testing.expect(capture.sorted != null);
    changed = entries;
    changed[2].index = 1;
    try std.testing.expectError(error.InvalidBlockV5FirstRoundOrder, seal.seal(pins, &changed));
    join_pins.memory = @import("block_v5_sorted_memory_v1.zig").Pins.fromWord(memory.pins(pins, &entries, sealed));
    var joined = try Join.init(a, join_pins, &.{}, memory.files(), @import("block_v5_sorted_memory_v1.zig").Loader.fromWord(capture.loader()), loader, sealed);
    std.debug.print("EMPTY_JOIN_STAGE memory_verified\n", .{});
    defer joined.deinit();
    try joined.onNative(a, 0, instances[0], &fresh_native);
    try std.testing.expectError(error.InvalidV5MemoryNativeHookOrder, joined.onNative(a, 0, instances[0], &fresh_native));
    try joined.onPrecompile(a, 0, extension_pin, &fresh_caller);
    std.debug.print("EMPTY_JOIN_STAGE sidecar_verified\n", .{});
    var closed = try joined.finish();
    defer closed.deinit(a);
    try std.testing.expectEqual(@as(u32, 0), external_capture.opcode_calls);
    try std.testing.expectEqual(@as(u64, 103), closed.memory.event_count);
    try std.testing.expectEqual(@as(u64, 1442), closed.bytes[0].request_count);
    try std.testing.expect(closed.ordinary_memory_opposite.isZero());
    try std.testing.expect(!closed.external_memory_opposite.isZero());
}
