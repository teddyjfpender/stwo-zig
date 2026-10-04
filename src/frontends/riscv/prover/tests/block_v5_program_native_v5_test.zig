//! Actual native-v5/global-ROM gate, with no native hash custody columns.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const Native = @import("../block_v5_native_execution_proof_v1.zig");
const Request = @import("../block_v5_program_request_proof_v1.zig");
const Table = @import("../block_v5_program_table_proof_v1.zig");
const First = @import("../block_v5_program_first_round_v1.zig");
const Receiver = @import("../block_v5_program_native_batch_receiver_v1.zig");
const Catalog = @import("../block_v5_native_template_catalog_v1.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const NativePlan = @import("../blake3_commitment_plan.zig");

const Store = struct {
    native: ?Native.Proof = null,
    request: ?Request.Proof = null,
    table: ?Table.Proof = null,
    fn deinit(self: *Store, a: std.mem.Allocator) void {
        if (self.native) |*proof| proof.deinit(a);
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
    fn loader(self: *Store) Receiver.Loader {
        return .{ .context = self, .take_native = takeNative, .take_request = takeRequest, .take_table = takeTable };
    }
};

test "block-v5 real native shared prefix freshly verifies after program request and ROM closure" {
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
    // Interim public roots only: allocate no RW or program custody schedules,
    // BLAKE3 circuit rows, hash witnesses, or per-leaf Merkle paths.
    const image = @import("../../recursion/air/blake3_memory_snapshot.zig");
    var entry = try image.fromSnapshot(a, &segment.rw_memory, .entry, .ordinary_boundary);
    defer entry.deinit();
    var exit = try image.fromSnapshot(a, &segment.rw_memory, .exit, .ordinary_boundary);
    defer exit.deinit();
    const Word = @import("../../recursion/air/blake3_program_word.zig");
    var programs: std.ArrayList(Word.Statement) = .empty;
    defer programs.deinit(a);
    var fetches: u64 = 0;
    for (rom.rows) |row| if (row.multiplicity != 0) {
        try programs.append(a, .{ .namespace = 100 + @as(u32, @intCast(programs.items.len)) * Word.CIRCUIT_COUNT, .address = row.addr, .multiplicity = row.multiplicity, .root = rom.root });
        fetches = try std.math.add(u64, fetches, row.multiplicity);
    };
    var native_plan = try NativePlan.Plan.initSparse(a, .{ rom.root, entry.root, exit.root }, &.{}, programs.items, rom.leaves);
    defer native_plan.deinit();
    io.data.program_root = rom.root;
    io.data.initial_rw_root = entry.root;
    io.data.final_rw_root = exit.root;
    const pin = try NativePlan.Admission.init(&native_plan, try native_plan.identity());
    const owner = try @import("../blake3_execution_trace.zig").Owner.init(a, &segment.execution_trace, io.data, &segment.state_chain_tracker);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
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
    var collector = try First.ForBackend(Cpu).init(a, rom.root, rom.leaves, 1);
    defer collector.deinit();
    try collector.add(&native_plan, &owner.statement, first.template_id, first.instance_id, first.roots, request_first.roots);
    try collector.addExtension(0, &native_plan, &.{}, 0, null);
    const table_entry = try collector.finish(fetches, config);
    const table_plan = try collector.census.smallestTablePlan(1, fetches);
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = first.template_id, .geometry_digest = first.template.geometry_digest, .fixed_root = first.roots[0] }};
    const catalog = Catalog.Admission{ .records = &records };
    var counts: [Seal.family_count]u32 = @splat(0);
    inline for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |family| counts[@intFromEnum(family) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_catalog_digest = try catalog.digest(), .program_root = rom.root.bytes, .program_plan_digest = try table_plan.digest(), .memory_plan_digest = @splat(3), .initial_source_plan_digest = @splat(4), .config = config, .counts = counts };
    const roster = [_]Seal.Entry{
        table_entry,                                                                                                 first.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(5), .roots = .{ @splat(6), @splat(7) } }, collector.requestEntries()[0],
        .{ .family = .memory, .index = 0, .instance_id = @splat(8), .roots = .{ @splat(9), @splat(10) } },
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
    std.debug.print("V5_PROGRAM_STAGE native_prove\n", .{});
    store.native = try NativeApi.proveWithCatalog(a, &first, sealed, pins, &roster, catalog);
    std.debug.print("V5_PROGRAM_STAGE table_prove\n", .{});
    store.table = try collector.proveTable(sealed.programSeal());
    const instance = Receiver.InstancePin{ .shape = &owner.statement, .admission = pin, .template = first.template, .template_id = first.template_id, .profile = .rv32im_zkvm_v1 };
    var changed = roster;
    changed[3].instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5NativeProgramRequest, Receiver.ForBackend(Cpu).verify(a, pins, &changed, try Seal.seal(pins, &changed), catalog, table_plan, &.{instance}, store.loader()));
    std.debug.print("V5_PROGRAM_STAGE fresh_verify\n", .{});
    const verified = try Receiver.ForBackend(Cpu).verify(a, pins, &roster, sealed, catalog, table_plan, &.{instance}, store.loader());
    try std.testing.expectEqual(fetches, verified.fetch_count);
    try std.testing.expectEqualDeep(sealed.digest, verified.seal_digest);
    try std.testing.expect(store.native == null and store.request == null and store.table == null);
    std.debug.print("BLOCK_V5_NATIVE_PROGRAM shared_prefix=true native_and_request_fresh=true fetches={d} native_fixed_columns={d} native_main_columns={d} complete=false\n", .{ fetches, owner.preprocessed.items.len, owner.main.items.len });
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
