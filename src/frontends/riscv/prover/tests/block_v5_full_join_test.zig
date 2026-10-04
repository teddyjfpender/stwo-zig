const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const public = @import("../blake3_segment_public.zig");
const native_trace = @import("../blake3_execution_trace.zig");
const native_proof = @import("../block_v5_native_execution_proof_v3.zig");
const sidecar = @import("../block_v5_opcode_memory_sidecar_proof_v1.zig");
const slots_mod = @import("../block_execution_sidecar_batch_v2.zig");
const opcode_trace = @import("../block_execution_sidecar_trace_v2.zig");
const bus = @import("../block_memory_relation_v2.zig");
const seals = @import("../block_v5_source_seal_v1.zig");
const catalog_mod = @import("../block_v5_native_template_catalog_v1.zig");
const fixture_mod = @import("../block_v5_word_memory_join_fixture_v1.zig");
const Global = @import("../block_v5_global_receiver_v1.zig");
const Transition = @import("../../air/block/memory_transition.zig").Transition;
const Programs = @import("../block_v5_program_native_batch_receiver_v3.zig");
const Request = @import("../block_v5_program_request_proof_v1.zig");
const Table = @import("../block_v5_program_table_proof_v1.zig");
const Projection = @import("../block_v5_native_lookup_request_proof_v1.zig");
const ProjectionSource = @import("../block_v5_native_lookup_request_source_v1.zig");
const Provider = @import("../block_v5_native_lookup_proof_v1.zig");
const Planning = @import("../block_v5_native_lookup_plan_v1.zig");
const TableJoin = @import("../block_v5_native_table_join_v1.zig");
const transport = @import("../block_v5_full_join_capture_v1.zig");
const Security = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;

test "block-v5 genuine native ROM group tables packed memory closes joined residual" {
    try run(.globals, .diagnostic_q8_pow0);
}
test "block-v5 complete ordinary bundle verifies global joins and exact recursion" {
    try run(.complete, .diagnostic_q8_pow0);
}
test "block-v5 complete ordinary detached bundle verifies fresh globals and pinned files" {
    try run(.detached, .diagnostic_q8_pow0);
}
test "block-v5 canonical security whole ordinary detached bundle" {
    try run(.detached, .csp_q70_pow26);
}
fn run(comptime mode: enum { globals, complete, detached }, comptime security: Security) !void {
    const complete = mode != .globals;
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(1);
    defer segment.deinit();
    var io = try public.Owned.init(a, &segment);
    defer io.deinit();
    var rom = try @import("../../air/program/blake3_commitment.zig").buildDeclared(a, @as(@import("../../air/program/commitment.zig").DeclaredDecodeAuthority, .base), .{segment.execution_trace.rows.items}, segment.rw_memory.program_words, @import("../commitment_program_witness.zig").completionFetch(io.data.completion));
    defer rom.deinit();
    const multiplicities = try a.alloc(u64, rom.rows.len);
    defer a.free(multiplicities);
    var fetch_count: u64 = 0;
    for (rom.rows, multiplicities) |row, *count| {
        count.* = row.multiplicity;
        fetch_count += row.multiplicity;
    }
    const table_plan = @import("../block_v5_program_table_v1.zig").Plan{ .program_root = rom.root, .leaves = rom.leaves, .multiplicities = multiplicities, .expected_fetches = fetch_count, .log_size = 7 };
    io.data.program_root = rom.root;
    const owner = try native_trace.Owner.init(a, &segment.execution_trace, io.data, &segment.state_chain_tracker);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = security.config();
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.global_first_cycle, .cycle_count = @intCast(segment.cycle_count) };
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
    var memory_fixture = try fixture_mod.Fixture.init(a, events, io.data.initial_regs, io.data.final_regs, config);
    defer memory_fixture.deinit();
    const pin = try @import("../block_v5_native_public_admission_v1.zig").Admission.init(.{
        .job_id = @splat(1),
        .source_image_digest = @splat(2),
        .program_root = rom.root.bytes,
        .program_plan_digest = try table_plan.digest(),
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
    var counter = try @import("../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const Sidecar = sidecar.ForPackedBackend(Cpu);
    var opcode_first = try Sidecar.commitFirstRound(a, owner.preprocessed.items, owner.main.items, inputs, slots, &counter, 0, native_first.template_id, config);
    defer opcode_first.deinit(a);
    const request_slots = try Request.slotsFromStatement(a, &owner.statement);
    defer a.free(request_slots);
    var request_first = try Request.ForBackend(Cpu).borrowFirstRound(a, &native_first.scheme, owner.main.items, request_slots, native_first.template_id, 0);
    defer request_first.deinit(a);
    const projection_slots = try ProjectionSource.slotsFromShape(a, &owner.statement, 0);
    defer a.free(projection_slots);
    var projection_first = try Projection.ForBackend(Cpu).borrowFirstRound(a, &native_first.scheme, owner.main.items, projection_slots, native_first.template_id, native_first.instance_id, 0);
    defer projection_first.deinit(a);
    var table_first = try Table.ForBackend(Cpu).commitFirstRound(a, table_plan, config);
    defer table_first.deinit(a);
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
    defer counters.deinit(a);
    counters.mergeFrom(&owner.opcode_columns.lookup_counters.?);
    for (counters.get(.range_check_8_8).values, counter.values) |*value, byte_count| value.* = value.add(byte_count);
    var lookup_plan = Planning.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = try Planning.nativeDemand(&owner.statement, 0) };
    try Planning.addDemand(&lookup_plan.max_requests, try Planning.sidecarMemoryDemand(2));
    var provider_first = try Provider.ForBackend(Cpu).commitFirstRound(a, &counters, lookup_plan, config);
    defer provider_first.deinit(a);
    var counts: [seals.family_count]u32 = @splat(0);
    inline for ([_]seals.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range, .native_lookup }) |family| counts[@intFromEnum(family) - 1] = 1;
    const pins = seals.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_catalog_digest = try catalog.digest(), .program_root = rom.root.bytes, .program_plan_digest = try table_plan.digest(), .memory_plan_digest = memory_fixture.first.plan_digest, .initial_source_plan_digest = try memory_fixture.endpoint_pins.initial.digest(), .rw_endpoint_plan_digest = try memory_fixture.endpoint_pins.digest(), .expected_final_rw_root = memory_fixture.endpoint_pins.expected_final_rw_root, .register_endpoint_plan_digest = try memory_fixture.register_pins.digest(), .config = config, .counts = counts };
    const entries = [_]seals.Entry{
        .{ .family = .program, .index = 0, .instance_id = try Table.instanceId(table_plan), .roots = table_first.roots },
        native_first.entry(),
        sidecar.packedEntry(native_first.instance_id, native_first.roots, opcode_first.roots[2], 0, slots),
        .{ .family = .program_request, .index = 0, .instance_id = Request.nativeV5InstanceId(native_first.template_id, native_first.instance_id, 0, request_slots), .roots = native_first.roots },
        memory_fixture.first.memoryEntry(0),
        memory_fixture.first.rangeEntry(0),
        try provider_first.entry(lookup_plan),
    };
    const sealed = try seals.seal(pins, &entries);
    var capture = fixture_mod.Capture{};
    defer capture.deinit(a);
    try memory_fixture.prove(&capture, pins, &entries, sealed);
    var proofs = transport.Capture{};
    defer proofs.deinit(a);
    proofs.request = try Request.ForBackend(Cpu).prove(a, &request_first, owner.main.items, request_slots, sealed.programSeal(), native_first.template_id, 0, native_first.roots);
    proofs.projection = try Projection.ForBackend(Cpu).prove(a, &projection_first, owner.main.items, projection_slots, sealed, native_first.template_id, native_first.instance_id, 0, native_first.roots);
    proofs.table = try Table.ForBackend(Cpu).prove(a, &table_first, table_plan, sealed.programSeal());
    proofs.provider = try Provider.ForBackend(Cpu).prove(a, &provider_first, &counters, lookup_plan, sealed, pins, &entries);
    const native_received = try Native.proveWithCatalog(a, &native_first, sealed, pins, &entries, catalog);
    proofs.native = try @import("../block_v5_native_codec_fixture_v3.zig").reopen(a, &native_received, .{ .shape = &owner.statement, .external_retirements = 0, .template_id = native_first.template_id, .instance_id = native_first.instance_id, .config = config });
    var native_capture = try Native.verifyCaptureOwnedWithCatalog(a, native_received, &owner.statement, pin, native_first.template, native_first.template_id, .rv32im_zkvm_v1, 0, sealed, pins, &entries, catalog);
    defer native_capture.deinit();
    const producer_receipt = native_capture.receipt;
    proofs.opcode = try Sidecar.prove(a, &opcode_first, inputs, slots, sealed, pins, &entries, catalog, &producer_receipt, 0, opcode_first.roots[2]);
    const instance_pins = [_]Programs.InstancePin{.{ .shape = &owner.statement, .admission = pin, .template = native_first.template, .template_id = native_first.template_id, .profile = .rv32im_zkvm_v1 }};
    const memory_pins = @import("../block_v5_word_memory_join_v1.zig").Pins{ .memory = @import("../block_v5_sorted_memory_v1.zig").Pins.fromWord(memory_fixture.pins(pins, &entries, sealed)), .catalog = catalog, .executions = &instance_pins, .opcode_witness_roots = &.{opcode_first.roots[2]}, .ordinary_events = &.{2}, .extensions = &.{} };
    const record = @import("../block_v5_native_lookup_batch_v1.zig").Record{ .plan = lookup_plan, .roots = provider_first.roots };
    const table_pins = TableJoin.Pins{ .seal = pins, .roster = &entries, .catalog = catalog, .executions = &instance_pins, .ordinary_events = &.{2}, .extensions = &.{}, .providers = &.{record} };
    var changed_record = record;
    changed_record.plan.max_requests[0] += 1;
    var changed_pins = table_pins;
    changed_pins.providers = &.{changed_record};
    try std.testing.expectError(error.UntrustedBlockV5LookupDemand, TableJoin.ForBackend(Cpu).init(a, changed_pins, sealed, proofs.tableLoader()));
    const global_pins = Global.Pins{ .expected_seal_digest = sealed.digest, .program = table_plan, .memory = memory_pins, .tables = table_pins };
    var wrong_seal = global_pins;
    wrong_seal.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5GlobalPins, wrong_seal.validate());
    const global_inputs = Global.Inputs{
        .public_input = &.{},
        .endpoint_sources = memory_fixture.files(),
        .memory = @import("../block_v5_sorted_memory_v1.zig").Loader.fromWord(capture.loader()),
        .execution_memory = proofs.memoryLoader(),
        .tables = proofs.tableLoader(),
        .programs = proofs.programLoader(),
    };
    const closed = if (complete) blk: {
        var recursive = try @import("../block_v5_complete_recursion_fixture_v1.zig").Fixture.init(a, instance_pins[0], &native_capture, sealed, pins, &entries, catalog);
        defer recursive.deinit();
        var weaker_leaf = recursive.leaf_pins;
        weaker_leaf[0].key.config.fri_config.n_queries = 1;
        var rejected = recursive.pins();
        rejected.leaves = &weaker_leaf;
        try std.testing.expectError(error.V5CompleteRecursiveSecurityMismatch, Global.ForBackend(Cpu).verifyComplete(a, global_pins, global_inputs, rejected, recursive.loader()));
        rejected = recursive.pins();
        rejected.outer.key.config.fri_config.n_queries = 1;
        try std.testing.expectError(error.V5CompleteRecursiveSecurityMismatch, Global.ForBackend(Cpu).verifyComplete(a, global_pins, global_inputs, rejected, recursive.loader()));
        rejected = recursive.pins();
        rejected.outer.key.context.child_config.fri_config.n_queries = 1;
        try std.testing.expectError(error.V5CompleteRecursiveSecurityMismatch, Global.ForBackend(Cpu).verifyComplete(a, global_pins, global_inputs, rejected, recursive.loader()));
        var weaker_parent = recursive.pins().outer;
        weaker_parent.key.config.fri_config.n_queries = 1;
        rejected = recursive.pins();
        rejected.parents = &.{weaker_parent};
        try std.testing.expectError(error.V5CompleteRecursiveSecurityMismatch, Global.ForBackend(Cpu).verifyComplete(a, global_pins, global_inputs, rejected, recursive.loader()));
        rejected = recursive.pins();
        rejected.outer.expected_id[0] ^= 1;
        try std.testing.expectError(error.UntrustedV5CompleteRecursiveKey, Global.ForBackend(Cpu).verifyComplete(a, global_pins, global_inputs, rejected, recursive.loader()));
        try std.testing.expect(proofs.native != null and proofs.request != null and proofs.provider != null and proofs.opcode != null);
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        var received = if (mode == .detached)
            try Global.ForBackend(Cpu).verifyCompleteDetached(a, global_pins, global_inputs, recursive.pins(), try recursive.writeDetached(temp.dir))
        else
            try Global.ForBackend(Cpu).verifyComplete(a, global_pins, global_inputs, recursive.pins(), recursive.loader());
        defer received.deinit();
        try std.testing.expectEqual(@as(u32, 1), received.recursive.execution_count);
        try std.testing.expectEqualDeep(received.globals.span, received.recursive.span);
        try std.testing.expect(received.globals.exact_recursive_forest == .verified);
        break :blk received.globals;
    } else try Global.ForBackend(Cpu).verifyGlobals(a, global_pins, global_inputs);
    try std.testing.expectEqual(@as(u64, 2), closed.memory_events);
    try std.testing.expectEqual(@as(u64, 28), closed.byte_requests);
    try std.testing.expectEqual(@as(u32, 1), closed.lookup_groups);
    try std.testing.expectEqual(fetch_count, closed.program_fetches);
    try std.testing.expect(closed.exact_recursive_forest == (if (complete) .verified else .pending));
    try std.testing.expect(proofs.native == null and proofs.request == null and proofs.table == null and proofs.projection == null and proofs.provider == null and proofs.opcode == null);
    std.debug.print("BLOCK_V5_FULL_JOIN native3=true rom=true grouped_tables=true packed_memory=true pc_clock=true globals_closed=true recursive={s} complete={} detached={} queries={d} pow_bits={d}\n", .{ if (complete) "verified" else "pending", complete, mode == .detached, config.fri_config.n_queries, config.pow_bits });
}
