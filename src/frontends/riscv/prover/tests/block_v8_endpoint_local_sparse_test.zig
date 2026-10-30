//! Genuine typed execution -> local original -> late narrow bridge -> global
//! window RAM. This qualifies a bundle of originals, NOT a recursive root or
//! skipped-prefix/block publication. Native wide producers are destroyed before
//! the bridge, retaining only endpoint rows and their exact PCS lease.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Driver = @import("../block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const Collect = @import("../block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("../block_v8_endpoint_range_provider_v1.zig");
const Source = @import("../block_v8_endpoint_local_scope_v1.zig");
const Proof = @import("../block_v8_endpoint_local_proof_v1.zig");
const Statement = @import("../block_v8_endpoint_local_statement_v1.zig");
const Metadata = @import("../block_v8_endpoint_local_statement_wire_v1.zig");
const Codec = @import("../block_v8_endpoint_local_codec_v1.zig");
const BridgeScope = @import("../block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("../block_v8_endpoint_global_bridge_proof_v1.zig");
const Memory = @import("../block_v7_window_memory_joint_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Counters = @import("../../air/lookups/tables/counter.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
const Sparse = @import("../block_v8_sparse_rom_v1.zig");
const SparseProvider = @import("../block_v8_sparse_rom_provider_v1.zig");
const Artifact = struct {
    a: std.mem.Allocator,
    proof_bytes: []u8,
    metadata_bytes: []u8,
    summary: @import("../block_v8_endpoint_local_ledger_v1.zig").Summary,
    fn deinit(self: *@This()) void {
        self.a.free(self.proof_bytes);
        self.a.free(self.metadata_bytes);
        self.a.destroy(self);
    }
};
const Consumer = struct {
    pub const Result = *Artifact;
    pub fn discardStagedResult(result: Result) void {
        result.deinit();
    }
    pub fn consumeStagedWindow(f: Driver.StagedWindowFixture) !Result {
        const a = f.allocator;
        const resident = f.resident_natives orelse return error.ExpectedResidentLocalFixture;
        if (resident.len != 1 or f.callers.len != 0) return error.ExpectedSingleLocalNative;
        const native = resident[0];
        const events = try @import("../block_v8_endpoint_execution_v1.zig").extractEvents(a, native.owner, native.pin().frame, 1 << 20);
        defer a.free(events);
        var endpoints = try Collect.collectGlobal(a, .{ .frame = native.pin().frame, .cohort_ordinal = 0, .cohort_count = 1 }, events, .{});
        defer endpoints.deinit();
        var ranges = try Range.Owned.init(a, endpoints.matrix, @intCast(endpoints.endpoints.len), .{});
        defer ranges.deinit();
        var counters = try Counters.Set.init(a);
        defer counters.deinit(a);
        counters.mergeFrom(&native.owner.opcode_columns.lookup_counters.?);
        var demand = try LP.nativeDemand(&native.owner.statement, 0);
        try ranges.appendToLookup(counters.get(.range_check_8_8), &demand);
        const lookup_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        var lookup = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, f.trusted.config, null, .{});
        defer lookup.deinit();
        const trusted = Source.Trusted{ .elf = f.trusted.elf, .elf_sha256 = f.trusted.elf_sha256, .profile = f.trusted.profile, .config = f.trusted.config, .cohort_count = 1 };
        var image = try @import("../block_v8_endpoint_local_program_v1.zig").Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, .{});
        defer image.deinit();
        var support: std.ArrayList(Sparse.Entry) = .empty;
        defer support.deinit(a);
        // Test-only old staged driver supplies a census, never authority.
        // Every selected tuple is freshly reconstructed from the pinned ELF.
        for (f.program_plan.multiplicities, 0..) |count, i| if (count != 0) try support.append(a, .{ .pc = f.program_plan.leaves[4 * i].index, .count = count });
        var sparse = try Sparse.Owned.fromImage(a, .{ .elf = trusted.elf, .elf_sha256 = trusted.elf_sha256, .profile = trusted.profile, .program_root = image.root, .expected_fetches = f.program_plan.expected_fetches }, support.items, &image, .{});
        defer sparse.deinit();
        var first = try SparseProvider.ForBackend(Cpu).commit(a, &sparse, trusted.config);
        defer first.deinit(a);
        var input = Source.Input{ .rom_flavor = .sparse_elf, .sparse_support = sparse.entries, .shape = &native.owner.statement, .frame = native.pin().frame, .cohort_ordinal = 0, .endpoint_count = @intCast(endpoints.endpoints.len), .native_roots = @splat(@splat(0)), .program_plan = .{ .program_root = image.root, .leaves = &.{}, .multiplicities = &.{}, .expected_fetches = sparse.trusted.expected_fetches, .log_size = sparse.log_size }, .program_roots = first.roots, .lookup_plan = lookup_plan, .lookup_layout = lookup.layout, .lookup_roots = lookup.roots };
        const proof = try Proof.produceWithOptions(a, trusted, input, native.owner.preprocessed.items, .{ .native_main = native.owner.main.items, .endpoints = &endpoints, .endpoint_range = &ranges, .program = &first, .program_allocator = a, .lookup = &lookup }, .{}, .{ .program = &image, .retain_endpoint = false });
        defer proof.deinit();
        input.native_roots = proof.native_roots;
        const proof_bytes = try Codec.encode(a, proof, trusted, input, .{});
        errdefer a.free(proof_bytes);
        const metadata_bytes = try Metadata.encode(a, trusted, input, .{});
        errdefer a.free(metadata_bytes);
        const result = try a.create(Artifact);
        result.* = .{ .a = a, .proof_bytes = proof_bytes, .metadata_bytes = metadata_bytes, .summary = proof.summary };
        return result;
    }
};

fn qualifySparse(config: core.pcs.PcsConfig) !void {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = Guest.elf();
    const pins = Capture.Pins{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    const span = Capture.Window{ .skip_cycles = 9, .cycles = 4 };
    var captured = try Capture.capture(a, &elf, &.{}, pins, span, .{});
    defer captured.deinit();
    const external = Window.Trusted{ .elf_sha256 = pins.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    const result = try Driver.run(budget, directory.dir, .{ .elf = &elf, .elf_sha256 = pins.elf, .cycles = span.cycles, .config = config, .state = .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = external } }, .{ .segment_cycles = 4, .active_callers = true, .sparse_window_initialization = true, .resident_original_stages = true }, &pool, Consumer);
    const artifact = result.value;
    defer artifact.deinit();
    // All native/endpoint/provider owners are destroyed before byte reception.
    const trusted = Source.Trusted{ .elf = &elf, .elf_sha256 = pins.elf, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
    const metadata = try Metadata.decode(a, artifact.metadata_bytes, trusted, .{});
    defer metadata.deinit();
    try std.testing.expectEqual(.sparse_elf, metadata.input.rom_flavor);
    try std.testing.expectEqual(@as(usize, 0), metadata.input.program_plan.multiplicities.len);
    try std.testing.expectEqual(@as(usize, 0), metadata.input.program_plan.leaves.len);
    const summary = try Codec.verifyBytes(a, artifact.proof_bytes, trusted, metadata.input, .{});
    try std.testing.expectEqualDeep(artifact.summary, summary);
    try std.testing.expect(std.mem.startsWith(u8, artifact.proof_bytes, Codec.SPARSE_MAGIC));
    var legacy = metadata.input;
    legacy.rom_flavor = .legacy_complete;
    legacy.sparse_support = &.{};
    try std.testing.expectError(error.UntrustedEndpointEnvelope, Codec.decode(a, artifact.proof_bytes, trusted, legacy, .{}));
    var wrong = metadata.input;
    wrong.program_plan.log_size += 1;
    if (Codec.verifyBytes(a, artifact.proof_bytes, trusted, wrong, .{})) |_| return error.AcceptedSparseGeometryChange else |err| if (err == error.OutOfMemory) return err;
    const changed = try a.dupe(Sparse.Entry, metadata.input.sparse_support);
    defer a.free(changed);
    changed[0].count += 1;
    wrong = metadata.input;
    wrong.sparse_support = changed;
    if (Codec.verifyBytes(a, artifact.proof_bytes, trusted, wrong, .{})) |_| return error.AcceptedSparseCensusChange else |err| if (err == error.OutOfMemory) return err;
    if (std.posix.getenv("STWO_SPARSE_LOCAL_OUTPUT")) |base| {
        const profile = if (config.fri_config.n_queries == 70) "csp_q70_pow26" else "diagnostic_q8_pow0";
        const path = try std.fs.path.join(a, &.{ base, profile });
        defer a.free(path);
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "local.proof", .data = artifact.proof_bytes });
        try dir.writeFile(.{ .sub_path = "local.json", .data = artifact.metadata_bytes });
        try dir.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
    }
    std.debug.print("SPARSE_LOCAL_FRESH_BYTE_VERIFIED queries={d} proofBytes={d} metadataBytes={d} selectedPCs={d} log={d}\n", .{ config.fri_config.n_queries, artifact.proof_bytes.len, artifact.metadata_bytes.len, metadata.input.sparse_support.len, metadata.input.program_plan.log_size });
}
test "diagnostic sparse genuine local original closes ROM lookup endpoint and fresh byte verifies" {
    try qualifySparse(@import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config());
}
test "canonical sparse genuine local original closes ROM lookup endpoint and fresh byte verifies" {
    try qualifySparse(@import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config());
}
