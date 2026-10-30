//! Genuine V3 local original after all private producers are destroyed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Scope = @import("../block_v8_endpoint_local_scope_v1.zig");
const Proof = @import("../block_v8_endpoint_local_proof_v1.zig");
const Codec = @import("../block_v8_endpoint_local_codec_v1.zig");
const Metadata = @import("../block_v8_endpoint_local_statement_wire_v1.zig");
const Prepare = @import("../block_v8_endpoint_execution_v1.zig");
const Native = @import("../blake3_execution_trace.zig");
const Program = @import("../block_v8_endpoint_local_program_v1.zig");
const ROM = @import("../block_v7_program_provider_v1.zig").ForBackend(Cpu);
const Collect = @import("../block_v8_ram_endpoint_collector_v1.zig");
test "canonical DirectRAM V3 local original closes endpoint range ROM tables then fresh byte-only receiver" {
    _ = try qualify(false, false);
}
test "canonical DirectRAM V3 wide profile4 binds new geometry and fresh byte-only receiver" {
    const original = try qualify(true, false);
    const batched = try qualify(true, true);
    try std.testing.expectEqualSlices(u8, &original, &batched);
}
fn qualify(comptime wide: bool, comptime batch: bool) ![32]u8 {
    return qualifyWithObserver(wide, batch, struct {});
}
pub fn qualifyWithObserver(comptime wide: bool, comptime batch: bool, comptime Observer: type) ![32]u8 {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 8 << 30);
    defer budget.destroy();
    defer if (comptime @hasDecl(Observer, "discard")) Observer.discard();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const code = [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x001002b7, 0x10028293, 0x0082a023, 0x0002a483, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    const trusted = Scope.Trusted{ .elf = &elf, .elf_sha256 = @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .profile = .rv32im_zkvm_v1, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(), .cohort_count = 1 };
    var proof_bytes: []u8 = undefined;
    var metadata_bytes: []u8 = undefined;
    {
        var image = try Program.Owned.init(a, &elf, trusted.elf_sha256, trusted.profile, .{});
        defer image.deinit();
        var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .direct_ram_max_clock = 31, .direct_ram_wide = wide });
        defer session.deinit();
        var segment = try session.startSegment(code.len - 1);
        defer segment.deinit();
        var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment);
        defer io.deinit();
        io.data.program_root = image.root;
        io.data.io_entries.input_len = 0;
        io.data.io_entries.input_words = &.{};
        io.data.io_entries.output_len = 0;
        io.data.io_entries.output_words = &.{};
        const native = try Native.Owner.initWithExternal(a, &segment.execution_trace, io.data, &segment.state_chain_tracker, 0);
        defer native.deinit();
        try native.sealNativeOnly();
        try std.testing.expectEqual(if (wide) .direct_ram_clock_v3_wide else .direct_ram_clock_v3, native.native_profile);
        const frame = Collect.Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = @intCast(segment.cycle_count) };
        const events = try Prepare.extractEvents(a, native, frame, 64);
        defer a.free(events);
        var endpoints = try Collect.collectGlobal(a, .{ .frame = frame, .cohort_ordinal = 0, .cohort_count = 1 }, events, .{});
        defer endpoints.deinit();
        var providers = try Prepare.LookupPreparation.init(a, native, &endpoints, trusted.config, .{}, .{});
        defer providers.deinit();
        const multiplicities = try a.alloc(u64, image.leaves.len / 4);
        defer a.free(multiplicities);
        @memset(multiplicities, 0);
        for (segment.execution_trace.rows.items) |row| multiplicities[(row.pc - image.info.memory_layout.program_base) / 4] += 1;
        multiplicities[(segment.exit_cpu.pc - image.info.memory_layout.program_base) / 4] += 1;
        const plan = @import("../block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = multiplicities, .expected_fetches = segment.cycle_count + 1, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) };
        var program = try ROM.commit(a, plan, trusted.config);
        defer program.deinit(a);
        var input = Scope.Input{ .native_profile = if (wide) .direct_ram_clock_v3_wide else .direct_ram_clock_v3, .shape = &native.statement, .frame = frame, .cohort_ordinal = 0, .endpoint_count = @intCast(endpoints.endpoints.len), .native_roots = @splat(@splat(0)), .program_plan = plan, .program_roots = program.roots, .lookup_plan = providers.plan, .lookup_layout = providers.lookup.layout, .lookup_roots = providers.lookup.roots };
        const proof = try Proof.produceWithOptions(a, trusted, input, native.preprocessed.items, .{ .native_main = native.main.items, .endpoints = &endpoints, .endpoint_range = &providers.ranges, .program = &program, .program_allocator = a, .lookup = &providers.lookup }, .{}, .{ .batch_native_projections = batch, .native_batch_options = .{ .max_batch_slots = 32, .max_interaction_workspace_bytes = 8 << 30 } });
        defer proof.deinit();
        input.native_roots = proof.native_roots;
        try std.testing.expectEqual(@as(u64, 2), proof.summary.logical_ram_accesses);
        proof_bytes = try Codec.encode(a, proof, trusted, input, .{});
        errdefer a.free(proof_bytes);
        metadata_bytes = try Metadata.encode(a, trusted, input, .{});
    }
    defer a.free(proof_bytes);
    defer a.free(metadata_bytes);
    // The only remaining source material is public ELF + serialized bytes.
    const admitted = try Metadata.decode(a, metadata_bytes, trusted, .{});
    defer admitted.deinit();
    try std.testing.expectEqual(if (wide) .direct_ram_clock_v3_wide else .direct_ram_clock_v3, admitted.input.native_profile);
    const fresh = try Codec.verifyBytes(a, proof_bytes, admitted.trusted, admitted.input, .{});
    try std.testing.expectEqual(@as(u64, 2), fresh.logical_ram_accesses);
    try std.testing.expectEqual(.local_execution_global_ram_open, fresh.scope);
    var wrong_profile = admitted.input;
    wrong_profile.native_profile = .endpoint_v2;
    try std.testing.expectError(error.UntrustedEndpointEnvelope, Codec.decode(a, proof_bytes, trusted, wrong_profile, .{}));
    const public_dispatch = try @import("../block_v8_endpoint_source_wire_dispatch_v1.zig").verifyBytes(a, metadata_bytes, proof_bytes, trusted, .{});
    try std.testing.expectEqual(fresh.cycles, public_dispatch.cycles);
    std.debug.print("DirectRAM V3 canonical local wide={} batch={} q70/26 fresh-byte receiver: {d} proof bytes, {d} cycles, {d} RAM accesses\n", .{ wide, batch, proof_bytes.len, fresh.cycles, fresh.logical_ram_accesses });
    if (comptime @hasDecl(Observer, "observe")) try Observer.observe(a, admitted, proof_bytes);
    return @import("../block_v5_initial_sources_v1.zig").sha256(proof_bytes);
}
test "direct RAM V3 migration preserves saved V2 metadata bytes and fresh original acceptance" {
    const directory_path = std.posix.getenv("STWO_B8_V3_LEGACY_DIR") orelse return error.SkipZigTest;
    const a = std.testing.allocator;
    var directory = try std.fs.cwd().openDir(directory_path, .{});
    defer directory.close();
    const elf = try std.fs.cwd().readFileAlloc(a, "vectors/reports/block-v7-real-window-corpus-20261029/source/guest.elf", 32 << 20);
    defer a.free(elf);
    var pin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pin, "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688");
    const trusted = Scope.Trusted{ .elf = elf, .elf_sha256 = pin, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(), .cohort_count = 8 };
    const metadata_bytes = try directory.readFileAlloc(a, "local-0.json", 16 << 20);
    defer a.free(metadata_bytes);
    const proof_bytes = try directory.readFileAlloc(a, "local-0.proof", 128 << 20);
    defer a.free(proof_bytes);
    const admitted = try Metadata.decode(a, metadata_bytes, trusted, .{});
    defer admitted.deinit();
    try std.testing.expectEqual(.endpoint_v2, admitted.input.native_profile);
    const reencoded = try Metadata.encode(a, admitted.trusted, admitted.input, .{});
    defer a.free(reencoded);
    try std.testing.expectEqualSlices(u8, metadata_bytes, reencoded);
    _ = try Codec.verifyBytes(a, proof_bytes, trusted, admitted.input, .{});
    std.debug.print("Saved V2 metadata exact-byte parity + fresh q70 original receiving preserved ({d} proof bytes)\n", .{proof_bytes.len});
}
