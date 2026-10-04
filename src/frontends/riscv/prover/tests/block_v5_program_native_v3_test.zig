//! Actual lightweight native-v3/global-ROM/table projection gate.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const Native = @import("../block_v5_native_execution_proof_v3.zig");
const Request = @import("../block_v5_program_request_proof_v1.zig");
const Table = @import("../block_v5_program_table_proof_v1.zig");
const Public = @import("../block_v5_native_public_admission_v1.zig");
const Providers = @import("../block_v5_native_lookup_proof_v1.zig");
const Planning = @import("../block_v5_native_lookup_plan_v1.zig");
const Groups = @import("../block_v5_native_lookup_request_receiver_v1.zig");
const Projection = @import("../block_v5_native_lookup_request_proof_v1.zig");
const ProjectionSource = @import("../block_v5_native_lookup_request_source_v1.zig");
const Receiver = @import("../block_v5_program_native_batch_receiver_v3.zig");
const Catalog = @import("../block_v5_native_template_catalog_v1.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");

const Store = struct {
    native: ?Native.Proof = null,
    group_native: ?Native.Proof = null,
    projection: ?Projection.Proof = null,
    provider: ?Providers.Proof = null,
    request: ?Request.Proof = null,
    table: ?Table.Proof = null,
    fn deinit(self: *Store, a: std.mem.Allocator) void {
        if (self.native) |*proof| proof.deinit(a);
        if (self.group_native) |*proof| proof.deinit(a);
        if (self.projection) |*proof| proof.deinit(a);
        if (self.provider) |*proof| proof.deinit(a);
        if (self.request) |*proof| proof.deinit(a);
        if (self.table) |*proof| proof.deinit(a);
    }
    fn takeNative(context: *anyopaque, index: u32) anyerror!Native.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0) return error.InvalidV5FixtureIndex;
        const proof = self.native orelse return error.MissingV5FixtureProof;
        self.native = null;
        return proof;
    }
    fn takeRequest(context: *anyopaque, index: u32) anyerror!Request.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0) return error.InvalidV5FixtureIndex;
        const proof = self.request orelse return error.MissingV5FixtureProof;
        self.request = null;
        return proof;
    }
    fn takeTable(context: *anyopaque) anyerror!Table.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        const proof = self.table orelse return error.MissingV5FixtureProof;
        self.table = null;
        return proof;
    }
    fn takeGroupNative(context: *anyopaque, index: u32) anyerror!Native.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0) return error.InvalidV5FixtureIndex;
        const proof = self.group_native orelse return error.MissingV5FixtureProof;
        self.group_native = null;
        return proof;
    }
    fn takeProjection(context: *anyopaque, index: u32) anyerror!Projection.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0) return error.InvalidV5FixtureIndex;
        const proof = self.projection orelse return error.MissingV5FixtureProof;
        self.projection = null;
        return proof;
    }
    fn takeProvider(context: *anyopaque, index: u32) anyerror!Providers.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0) return error.InvalidV5FixtureIndex;
        const proof = self.provider orelse return error.MissingV5FixtureProof;
        self.provider = null;
        return proof;
    }
    fn groupLoader(self: *Store) Groups.Loader {
        return .{ .context = self, .take_native = takeGroupNative, .take_projection = takeProjection, .take_provider = takeProvider };
    }
    fn loader(self: *Store) Receiver.Loader {
        return .{ .context = self, .take_native = takeNative, .take_request = takeRequest, .take_table = takeTable };
    }
};

test "block-v5 lightweight v3 closes ROM six native tables and perleaf PC clock at shared roots" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x002081b3, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(3);
    defer segment.deinit();
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment);
    defer io.deinit();
    var rom = try @import("../../air/program/blake3_commitment.zig").buildDeclared(a, @as(@import("../../air/program/commitment.zig").DeclaredDecodeAuthority, .base), .{segment.execution_trace.rows.items}, segment.rw_memory.program_words, @import("../commitment_program_witness.zig").completionFetch(io.data.completion));
    defer rom.deinit();
    var fetches: u64 = 0;
    const multiplicities = try a.alloc(u64, rom.rows.len);
    defer a.free(multiplicities);
    for (rom.rows, multiplicities) |row, *multiplicity| {
        multiplicity.* = row.multiplicity;
        fetches = try std.math.add(u64, fetches, row.multiplicity);
    }
    const table_plan = @import("../block_v5_program_table_v1.zig").Plan{
        .program_root = rom.root,
        .leaves = rom.leaves,
        .multiplicities = multiplicities,
        .expected_fetches = fetches,
        .log_size = 7,
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var counts: [Seal.family_count]u32 = @splat(0);
    inline for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .native_lookup }) |family| counts[@intFromEnum(family) - 1] = 1;
    var pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_catalog_digest = @splat(12), .program_root = rom.root.bytes, .program_plan_digest = try table_plan.digest(), .memory_plan_digest = @splat(3), .initial_source_plan_digest = @splat(4), .config = config, .counts = counts };
    io.data.program_root = rom.root;
    const pin = try Public.Admission.init(.{
        .job_id = pins.job_id,
        .source_image_digest = pins.source_image_digest,
        .program_root = pins.program_root,
        .program_plan_digest = pins.program_plan_digest,
        .memory_plan_digest = pins.memory_plan_digest,
        .initial_source_plan_digest = pins.initial_source_plan_digest,
        .rw_endpoint_plan_digest = pins.rw_endpoint_plan_digest,
        .execution_index = 0,
        .first_cycle = segment.global_first_cycle,
        .last_cycle = segment.global_first_cycle + segment.cycle_count - 1,
    }, &io.data);
    const owner = try @import("../blake3_execution_trace.zig").Owner.init(a, &segment.execution_trace, io.data, &segment.state_chain_tracker);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const NativeApi = Native.ForBackend(Cpu);
    const RequestApi = Request.ForBackend(Cpu);
    var first = try NativeApi.commitFirstRound(a, owner, pin, config, .rv32im_zkvm_v1, 0);
    defer first.deinit(a);
    const slots = try Request.slotsFromStatement(a, &owner.statement);
    defer a.free(slots);
    var request_first = try RequestApi.borrowFirstRound(a, &first.scheme, owner.main.items, slots, first.template_id, 0);
    defer request_first.deinit(a);
    try std.testing.expectEqual(owner.preprocessed.items.len, request_first.fixed_logs.len);
    try std.testing.expectEqual(owner.main.items.len, request_first.main_logs.len);
    for (owner.preprocessed.items, request_first.fixed_logs) |column, log|
        try std.testing.expectEqual(column.log_size, log);
    for (owner.main.items, request_first.main_logs) |column, log|
        try std.testing.expectEqual(column.log_size, log);
    for (first.scheme.trees.items, request_first.scheme.trees.items) |native_tree, request_tree|
        try std.testing.expect(native_tree.shared_owner != null and
            native_tree.shared_owner == request_tree.shared_owner);
    const projection_slots = try ProjectionSource.slotsFromShape(a, &owner.statement, 0);
    defer a.free(projection_slots);
    var projection_first = try Projection.ForBackend(Cpu).borrowFirstRound(a, &first.scheme, owner.main.items, projection_slots, first.template_id, first.instance_id, 0);
    defer projection_first.deinit(a);
    var table_first = try Table.ForBackend(Cpu).commitFirstRound(a, table_plan, config);
    defer table_first.deinit(a);
    var census_first = try @import("../block_v5_program_first_round_v1.zig").ForBackend(Cpu).init(a, rom.root, rom.leaves, 1);
    defer census_first.deinit();
    const canonical_fetches = try a.alloc(@import("../block_v5_program_census_v1.zig").Fetch, rom.rows.len);
    defer a.free(canonical_fetches);
    for (rom.rows, canonical_fetches) |row, *fetch| fetch.* = .{ .address = row.addr, .multiplicity = row.multiplicity };
    try census_first.addLightweight(canonical_fetches, &owner.statement, first.template_id, first.instance_id, first.roots, request_first.roots);
    try census_first.addLightweightExtension(0, canonical_fetches, &.{}, 0, null);
    try std.testing.expectEqualSlices(u64, multiplicities, (try census_first.census.tablePlan(1, fetches, 7)).multiplicities);
    const table_entry = Seal.Entry{ .family = .program, .index = 0, .instance_id = try Table.instanceId(table_plan), .roots = table_first.roots };
    const lookup_plan = Planning.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = try Planning.nativeDemand(&owner.statement, 0) };
    var provider_first = try Providers.ForBackend(Cpu).commitFirstRound(a, &owner.opcode_columns.lookup_counters.?, lookup_plan, config);
    defer provider_first.deinit(a);
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = first.template_id, .geometry_digest = first.template.geometry_digest, .fixed_root = first.roots[0] }};
    const catalog = Catalog.Admission{ .records = &records };
    pins.native_template_catalog_digest = try catalog.digest();
    const roster = [_]Seal.Entry{
        table_entry,                                                                                                 first.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(5), .roots = .{ @splat(6), @splat(7) } }, .{ .family = .program_request, .index = 0, .instance_id = Request.nativeV5InstanceId(first.template_id, first.instance_id, 0, slots), .roots = first.roots },
        .{ .family = .memory, .index = 0, .instance_id = @splat(8), .roots = .{ @splat(9), @splat(10) } },           try provider_first.entry(lookup_plan),
    };
    const sealed = try Seal.seal(pins, &roster);
    var store = Store{};
    defer store.deinit(a);
    std.debug.print("V5_PROGRAM_STAGE request_prove\n", .{});
    store.request = try RequestApi.prove(a, &request_first, owner.main.items, slots, sealed.programSeal(), first.template_id, 0, first.roots);
    std.debug.print("V5_PROGRAM_STAGE request_proved\n", .{});
    var wrong_count = try cloneRequest(a, store.request.?);
    wrong_count.claims[0].fetch_count += 1;
    try std.testing.expectError(error.InvalidProgramRequestCensus, RequestApi.verifyOwned(a, wrong_count, sealed.programSeal(), 0, first.template_id, slots, request_first.fixed_logs, request_first.main_logs, first.roots, first.roots, config));
    // Request proof destroyed its lease; the original native trees remain
    // alive and unchanged, and subsequently produce a fresh verified proof.
    var surviving_roots = try first.scheme.roots(a);
    defer surviving_roots.deinit(a);
    try std.testing.expectEqualDeep(first.roots, surviving_roots.items[0..2].*);
    store.projection = try Projection.ForBackend(Cpu).prove(a, &projection_first, owner.main.items, projection_slots, sealed, first.template_id, first.instance_id, 0, first.roots);
    std.debug.print("V5_PROGRAM_STAGE native_v3_prove\n", .{});
    store.native = try NativeApi.proveWithCatalog(a, &first, sealed, pins, &roster, catalog);
    std.debug.print("V5_PROGRAM_STAGE table_prove\n", .{});
    store.table = try Table.ForBackend(Cpu).prove(a, &table_first, table_plan, sealed.programSeal());
    store.provider = try Providers.ForBackend(Cpu).prove(a, &provider_first, &owner.opcode_columns.lookup_counters.?, lookup_plan, sealed, pins, &roster);
    const wire_expected = @import("../block_v5_native_codec_v3.zig").Expected{
        .shape = &owner.statement,
        .external_retirements = 0,
        .template_id = first.template_id,
        .instance_id = first.instance_id,
        .config = config,
    };
    store.group_native = try @import("../block_v5_native_codec_fixture_v3.zig").reopen(a, &store.native.?, wire_expected);
    const instance = Receiver.InstancePin{ .shape = &owner.statement, .admission = pin, .template = first.template, .template_id = first.template_id, .profile = .rv32im_zkvm_v1 };
    var changed = roster;
    changed[3].instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5NativeProgramRequest, Receiver.ForBackend(Cpu).verify(a, pins, &changed, try Seal.seal(pins, &changed), catalog, table_plan, &.{instance}, store.loader()));
    std.debug.print("V5_PROGRAM_STAGE fresh_verify\n", .{});
    const verified = try Receiver.ForBackend(Cpu).verify(a, pins, &roster, sealed, catalog, table_plan, &.{instance}, store.loader());
    try std.testing.expectEqual(fetches, verified.fetch_count);
    try std.testing.expectEqualDeep(sealed.digest, verified.seal_digest);
    try std.testing.expect(store.native == null and store.request == null and store.table == null);
    const group_instance = Groups.Instance{ .shape = &owner.statement, .admission = pin, .template = first.template, .template_id = first.template_id, .profile = .rv32im_zkvm_v1 };
    const provider_record = @import("../block_v5_native_lookup_batch_v1.zig").Record{ .plan = lookup_plan, .roots = provider_first.roots };
    const group_pins = Groups.Pins{ .seal = pins, .expected_seal_digest = sealed.digest, .roster = &roster, .catalog = catalog, .instances = &.{group_instance}, .providers = &.{provider_record} };
    var changed_record = provider_record;
    changed_record.plan.max_requests[0] += 1;
    var wrong_groups = group_pins;
    wrong_groups.providers = &.{changed_record};
    try std.testing.expectError(error.UntrustedBlockV5LookupDemand, Groups.verify(Cpu, a, wrong_groups, store.groupLoader()));
    const closed = try Groups.verify(Cpu, a, group_pins, store.groupLoader());
    try std.testing.expectEqual(@as(u32, 1), closed.group_count);
    try std.testing.expect(closed.provider_sum.add(closed.native_table_sum).isZero());
    try std.testing.expect(store.group_native == null and store.projection == null and store.provider == null);
    std.debug.print("BLOCK_V5_V3_ROM_TABLE native3=true shared_prefix=true rom_fetches={d} native_tables_closed=true per_leaf_pc_clock_closed=true complete=false\n", .{fetches});
}

fn cloneRequest(a: std.mem.Allocator, proof: Request.Proof) !Request.Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    return .{ .stark = stark, .claims = try a.dupe(Request.Claim, proof.claims) };
}
