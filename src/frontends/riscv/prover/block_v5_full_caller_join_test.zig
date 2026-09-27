//! Fresh complete caller-only block: actual ROM, six table groups, packed
//! memory, caller state and exact native recursive forest share one B5SS.
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
const Table = @import("block_v5_program_table_proof_v1.zig");
const ExtensionProgram = @import("block_v5_program_extension_proof_v1.zig");
const ExtensionSlots = @import("block_v5_program_extension_slots_v1.zig");
const EmptyProgram = @import("block_v5_empty_program_request_v1.zig");
const EmptyTables = @import("block_v5_empty_native_tables_v1.zig");
const CallerTables = @import("block_v5_precompile_lookup_proof_v1.zig");
const CallerState = @import("block_v5_precompile_state_request_proof_v1.zig");
const Provider = @import("block_v5_native_lookup_proof_v1.zig");
const Planning = @import("block_v5_native_lookup_plan_v1.zig");
const TableJoin = @import("block_v5_native_table_join_v1.zig");
const Global = @import("block_v5_global_receiver_v1.zig");
const ProofCapture = @import("block_v5_full_join_capture_v1.zig").Capture;
test "block-v5 complete caller SHA Keccak bundle fresh verifies every global bus and exact recursion" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
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
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &source_digest, .{});
    const tapes = &segment.extension;
    var rom = try @import("../air/program/blake3_commitment.zig").buildDeclared(a, @import("../air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_sha_v1 }, .{ segment.base.execution_trace.rows.items, tapes.keccakf_execution_rows.rows(), tapes.signer_recovery_execution_rows.rows(), tapes.sha_calls.records() }, segment.base.rw_memory.program_words, @import("commitment_program_witness.zig").completionFetch(io.data.completion));
    defer rom.deinit();
    const multiplicities = try a.alloc(u64, rom.rows.len);
    defer a.free(multiplicities);
    var fetches: u64 = 0;
    for (rom.rows, multiplicities) |row, *count| {
        count.* = row.multiplicity;
        fetches = try std.math.add(u64, fetches, count.*);
    }
    const plan = @import("block_v5_program_table_v1.zig").Plan{ .program_root = rom.root, .leaves = rom.leaves, .multiplicities = multiplicities, .expected_fetches = fetches, .log_size = 7 };
    io.data.program_root = rom.root;
    var memory = try memory_fixture.Fixture.init(a, events.items, io.data.initial_regs, io.data.final_regs, segment.base.rw_memory.layout, config);
    defer memory.deinit();
    const pin = try @import("block_v5_native_public_admission_v1.zig").Admission.init(.{ .job_id = @splat(1), .source_image_digest = source_digest, .program_root = rom.root.bytes, .program_plan_digest = try plan.digest(), .memory_plan_digest = memory.first.plan_digest, .initial_source_plan_digest = try memory.endpoint_pins.initial.digest(), .rw_endpoint_plan_digest = try memory.endpoint_pins.digest(), .execution_index = 0, .first_cycle = segment.base.global_first_cycle, .last_cycle = segment.base.global_first_cycle + segment.base.cycle_count - 1 }, &io.data);
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
    try EmptyTables.validateShape(a, &owner.statement, profile.externalCount(&extension.statement));
    const extension_slots = try ExtensionSlots.fromProfile(a, &extension.statement, fixed_logs, main_logs, 0, 0);
    defer a.free(extension_slots);
    var program_first = try ExtensionProgram.ForBackend(Cpu).commitFirstRound(a, fixed, main.columns, extension_slots, first.instance_id, native_first.instance_id, 0, config);
    defer program_first.deinit(a);
    try std.testing.expectEqualDeep(first.roots, program_first.roots);
    var state_first = try CallerState.ForBackend(Cpu).borrowFirstRound(a, &first);
    defer state_first.deinit(a);
    var table_first = try Table.ForBackend(Cpu).commitFirstRound(a, plan, config);
    defer table_first.deinit(a);
    var counters = try @import("../air/lookups/tables/counter.zig").Set.init(a);
    defer counters.deinit(a);
    counters.mergeFrom(&owner.opcode_columns.lookup_counters.?);
    try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{
        .keccak = tapes.keccakf_calls.records(),
        .recovery = tapes.signer_recovery_calls.records(),
    }).register(&counters);
    try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &extension.sha_rows, &counters);
    for (counters.get(.range_check_8_8).values, counter.values) |*value, byte_count| value.* = value.add(byte_count);
    var lookup_plan = Planning.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = try Planning.nativeDemand(&owner.statement, profile.externalCount(&extension.statement)) };
    try Planning.addDemand(&lookup_plan.max_requests, try Planning.sidecarMemoryDemand(103));
    try @import("block_v5_precompile_table_demand_v1.zig").add(a, &lookup_plan.max_requests, &extension.statement, extension.total_steps, config);
    var provider_first = try Provider.ForBackend(Cpu).commitFirstRound(a, &counters, lookup_plan, config);
    defer provider_first.deinit(a);
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range, .precompile, .program_extension_request, .execution_external_sidecar, .native_lookup }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = source_digest, .native_template_catalog_digest = try catalog.digest(), .program_root = rom.root.bytes, .program_plan_digest = try plan.digest(), .memory_plan_digest = memory.first.plan_digest, .initial_source_plan_digest = try memory.endpoint_pins.initial.digest(), .expected_final_rw_root = memory.endpoint_pins.expected_final_rw_root, .rw_endpoint_plan_digest = try memory.endpoint_pins.digest(), .register_endpoint_plan_digest = try memory.register_pins.digest(), .config = config, .counts = counts };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = try Table.instanceId(plan), .roots = table_first.roots },
        native_first.entry(),
        empty_entry,
        try EmptyProgram.entry(native_first.template_id, native_first.entry()),
        memory.first.memoryEntry(0),
        memory.first.rangeEntry(0),
        first.entry(),
        .{ .family = .program_extension_request, .index = 0, .instance_id = ExtensionProgram.instanceId(first.instance_id, native_first.instance_id, 0, extension_slots), .roots = first.roots },
        external.packedEntry(native_first.instance_id, first.instance_id, first.key_id, first.roots, external_first.roots[2], 0, slots),
        try provider_first.entry(lookup_plan),
    };
    var missing_requests = pins;
    missing_requests.counts[@intFromEnum(seal.Family.program_extension_request) - 1] = 0;
    try std.testing.expectError(error.IncompleteBlockV5PrecompileFamilies, missing_requests.validateComplete());
    const sealed = try seal.seal(pins, &entries);
    const binding = first.binding(sealed);
    var caller_tables_first = try CallerTables.ForBackend(Cpu).borrowFirstRound(a, &first, binding);
    defer caller_tables_first.deinit(a);
    var memory_capture = memory_fixture.Capture{};
    defer memory_capture.deinit(a);
    try memory.prove(&memory_capture, pins, &entries, sealed);
    var proofs = ProofCapture{};
    defer proofs.deinit(a);
    proofs.table = try Table.ForBackend(Cpu).prove(a, &table_first, plan, sealed.programSeal());
    proofs.provider = try Provider.ForBackend(Cpu).prove(a, &provider_first, &counters, lookup_plan, sealed, pins, &entries);
    proofs.caller_program = try ExtensionProgram.ForBackend(Cpu).prove(a, &program_first, fixed, main.columns, extension_slots, sealed.programSeal(), first.instance_id, native_first.instance_id, 0, first.roots);
    proofs.caller_state = try CallerState.ForBackend(Cpu).prove(a, &state_first, &extension, binding, sealed, pins, &entries, extension.total_steps);
    proofs.caller_tables = try CallerTables.ForBackend(Cpu).prove(a, &caller_tables_first, &extension, binding, sealed, pins, &entries);
    proofs.external = try External.prove(a, &external_first, inputs, slots, sealed, pins, &entries, &binding, 0, external_first.roots[2]);
    proofs.caller = try Family.prove(a, &first, sealed, pins, &entries, &pool);
    const native_received = try Native.proveWithCatalog(a, &native_first, sealed, pins, &entries, catalog);
    proofs.native = try @import("block_v5_native_codec_fixture_v3.zig").reopen(a, &native_received, .{ .shape = &owner.statement, .external_retirements = 3, .template_id = native_first.template_id, .instance_id = native_first.instance_id, .config = config });
    var native_capture = try Native.verifyCaptureOwnedWithCatalog(a, native_received, &owner.statement, pin, native_first.template, native_first.template_id, .rv32im_zkvm_ethereum_sha_v1, 0, sealed, pins, &entries, catalog);
    defer native_capture.deinit();
    const instances = [_]Programs.InstancePin{.{ .shape = &owner.statement, .admission = pin, .template = native_first.template, .template_id = native_first.template_id, .profile = .rv32im_zkvm_ethereum_sha_v1 }};
    const extension_pin = Programs.ExtensionPin{ .execution_index = 0, .statement = &extension.statement, .total_steps = extension.total_steps, .expected_key_id = first.key_id };
    const memory_pins = join_mod.Pins{ .memory = @import("block_v5_sorted_memory_v1.zig").Pins.fromWord(memory.pins(pins, &entries, sealed)), .catalog = catalog, .executions = &instances, .opcode_witness_roots = &.{empty.witnessRoot()}, .ordinary_events = &.{0}, .extensions = &.{.{ .public = extension_pin, .witness_root = external_first.roots[2] }} };
    const record = @import("block_v5_native_lookup_batch_v1.zig").Record{ .plan = lookup_plan, .roots = provider_first.roots };
    const table_pins = TableJoin.Pins{ .seal = pins, .roster = &entries, .catalog = catalog, .executions = &instances, .ordinary_events = &.{0}, .extensions = &.{extension_pin}, .providers = &.{record} };
    var changed_record = record;
    changed_record.plan.max_requests[4] -= 1;
    var wrong_tables = table_pins;
    wrong_tables.providers = &.{changed_record};
    try std.testing.expectError(error.UntrustedBlockV5LookupDemand, TableJoin.ForBackend(Cpu).init(a, wrong_tables, sealed, proofs.tableLoader()));
    const global_pins = Global.Pins{ .expected_seal_digest = sealed.digest, .program = plan, .memory = memory_pins, .tables = table_pins };
    var wrong_seal = global_pins;
    wrong_seal.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5GlobalPins, wrong_seal.validate());
    var missing_tables = proofs.tableLoader();
    missing_tables.take_caller_tables = null;
    try std.testing.expectError(error.UntrustedV5TableJoinPins, TableJoin.ForBackend(Cpu).init(a, table_pins, sealed, missing_tables));
    try std.testing.expect(proofs.provider != null and proofs.caller != null and proofs.caller_program != null);
    const global_inputs = Global.Inputs{ .public_input = &.{}, .endpoint_sources = memory.files(), .memory = @import("block_v5_sorted_memory_v1.zig").Loader.fromWord(memory_capture.loader()), .execution_memory = proofs.memoryLoader(), .tables = proofs.tableLoader(), .programs = proofs.programLoader() };
    var recursive = try @import("block_v5_complete_recursion_fixture_v1.zig").Fixture.init(a, instances[0], &native_capture, sealed, pins, &entries, catalog);
    defer recursive.deinit();
    var complete = try Global.ForBackend(Cpu).verifyComplete(a, global_pins, global_inputs, recursive.pins(), recursive.loader());
    defer complete.deinit();
    try std.testing.expectEqual(@as(u64, 103), complete.globals.memory_events);
    try std.testing.expectEqual(@as(u64, 1442), complete.globals.byte_requests);
    try std.testing.expectEqual(fetches, complete.globals.program_fetches);
    try std.testing.expectEqual(@as(u32, 1), complete.globals.lookup_groups);
    try std.testing.expect(complete.globals.exact_recursive_forest == .verified);
    try std.testing.expectEqualDeep(complete.globals.span, complete.recursive.span);
    try std.testing.expectEqual(@as(u32, 0), proofs.request_loads);
    try std.testing.expectEqual(@as(u32, 0), proofs.projection_loads);
    try std.testing.expectEqual(@as(u32, 0), proofs.opcode_loads);
    inline for (.{ "native", "caller", "caller_program", "caller_state", "caller_tables", "external", "provider", "table" }) |field|
        try std.testing.expect(@field(proofs, field) == null);
    std.debug.print("BLOCK_V5_FULL_CALLER sha=2 keccak=1 signer=0 memory_events=103 byte_requests=1442 rom_fetches={d} pc_clock=true six_table_groups=true authenticated_empty_native=true complete=true\n", .{fetches});
}
