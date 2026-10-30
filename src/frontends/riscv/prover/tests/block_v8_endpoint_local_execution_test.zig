const std = @import("std");
const engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const code = [_]u32{
    0x001000b7, // lui x1,0x100
    0x20008093, // addi x1,x1,0x200
    0x0000a103, // lw x2,0(x1)
    0x00110113, // addi x2,x2,1
    0x0020a023, // sw x2,0(x1)
    0xff5ff06f, // jal x0,-12
};
const elf = blk: {
    var bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, value| std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
test "continuous clean local producer proves two real cohorts and closes one shared global window" {
    try qualify(false);
}
test "continuous clean local compact producer proves two real cohorts and closes one shared global window" {
    try qualify(true);
}
test "parallel clean local compact producer closes fresh file-only bundle" {
    try qualifyWithObserver(true, struct {
        pub const parallel_local_proofs: u32 = 2;
    });
}
fn qualify(comptime compact: bool) !void {
    return qualifyWithObserver(compact, struct {});
}
pub fn qualifyWithObserver(comptime compact: bool, comptime Observer: type) !void {
    const Run = if (compact) @import("../block_v8_endpoint_local_compact_execution_v1.zig") else @import("../block_v8_endpoint_local_execution_v1.zig");
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    defer if (comptime @hasDecl(Observer, "discard")) Observer.discard();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    const pins = Capture.Pins{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    const span = Capture.Window{ .skip_cycles = 2, .cycles = 8 };
    var captured = try Capture.capture(a, &elf, &.{}, pins, span, .{});
    defer captured.deinit();
    var output = std.testing.tmpDir(.{ .iterate = true });
    defer output.cleanup();
    const result = try Run.run(budget, &pool, output.dir, .{ .elf = &elf, .elf_sha256 = pins.elf, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(), .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted_window = .{ .elf_sha256 = pins.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span } }, .{ .program_flavor = if (comptime @hasDecl(Observer, "program_flavor")) Observer.program_flavor else .legacy_complete, .cohort_cycles = 4, .memory_rows_per_shard = 4, .parallel_local_proofs = if (comptime @hasDecl(Observer, "parallel_local_proofs")) Observer.parallel_local_proofs else 1, .proof_workers = 4 });
    // Run.run owns its binding; bind the pool after it returns for observers.
    var observer_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer observer_binding.deinit();
    var result_live = true;
    defer if (result_live) result.deinit();
    try std.testing.expectEqual(.declared_window_originals_closed, result.verified.scope);
    try std.testing.expectEqual(if (compact) .compact_endpoint else .legacy_window, result.verified.global_argument);
    try std.testing.expectEqual(@as(u32, 2), result.verified.cohorts);
    try std.testing.expectEqual(@as(u64, 8), result.verified.cycles);
    try std.testing.expectEqual(@as(u64, 4), result.stats.logical_ram_events);
    try std.testing.expectEqual(@as(u64, 2), result.stats.endpoint_events);
    try std.testing.expectEqual(@as(u32, 1), result.stats.bridge_batches);
    try std.testing.expectEqual(@as(usize, 6), result.bridges[0].stark.commitment_scheme_proof.commitments.items.len);
    try std.testing.expect(result.stats.retained_endpoint_peak_bytes > 0);
    for ([_][]const u8{ "local-0.proof", "local-0.json", "local-1.proof", "local-1.json", "bridge-0.proof", "global-memory.proof", "global-public.json" }) |name| try std.testing.expect((try output.dir.statFile(name)).size > 0);
    const external = @import("../block_v8_endpoint_local_bundle_v1.zig").External{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = .{ .elf_sha256 = pins.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span }, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config() };
    if (comptime @hasDecl(Observer, "observeTrain")) try Observer.observeTrain(a, output.dir, external, result);
    if (comptime compact and @hasDecl(Observer, "observeCompactGlobal")) {
        const Source = @import("../block_v8_endpoint_local_scope_v1.zig");
        const Metadata = @import("../block_v8_endpoint_local_statement_wire_v1.zig");
        const Codec = @import("../block_v8_endpoint_local_codec_v1.zig");
        const BridgeScope = @import("../block_v8_endpoint_global_bridge_scope_v1.zig");
        const Window = @import("../block_v7_real_window_policy_v2.zig");
        const Compact = @import("../block_v8_compact_ram_proof_v1.zig");
        var policy_window = try Window.Owned.deriveCohortsForAddresses(a, &elf, captured.incoming, captured.outgoing, external.trusted, result.cohort_policy, result.selected_initial_addresses, .{});
        defer policy_window.deinit();
        const policy = Compact.Policy{ .window = &policy_window, .config = external.config, .event_count = @intCast(result.verified.endpoint_events) };
        const sources = try a.alloc(BridgeScope.Source, result.verified.cohorts);
        defer a.free(sources);
        const provider = Run.FileProvider{ .directory = output.dir, .bridges = result.bridges, .source_count = result.verified.cohorts, .metadata_bytes = 16 << 20, .proof_bytes = 128 << 20 };
        for (sources, 0..) |*source, i| {
            var bytes = try provider.loadLocal(a, @intCast(i));
            defer bytes.deinit();
            const statement = try Metadata.decode(a, bytes.metadata, Source.Trusted{ .elf = &elf, .elf_sha256 = pins.elf, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = result.verified.cohorts }, .{});
            defer statement.deinit();
            const verified = try Codec.verifyBytes(a, bytes.proof, statement.trusted, statement.input, .{});
            source.* = .{ .local_identity = verified.source.local_identity, .local_epoch = verified.source.local_epoch, .endpoint_root = verified.source.endpoint_root, .endpoint_count = verified.source.endpoint_count, .policy = verified.source.policy };
        }
        var scope = try BridgeScope.Owned.init(a, try policy.digest(), external.config, sources, try policy.entry(result.global_memory.roots));
        defer scope.deinit();
        try Observer.observeCompactGlobal(a, policy, scope.epoch, scope.entries, &result.global_memory);
    }
    const expected_summary = result.verified;
    const event_nomination: u32 = @intCast(result.verified.endpoint_events);
    result.deinit();
    result_live = false;
    // Strict durable receiving after EVERY producer result and typed original
    // object is gone. The receiver has only files plus external pins/states.
    const Directory = @import("../block_v8_endpoint_local_directory_v1.zig");
    const verify_files = if (compact) Directory.verifyDirectoryCompact else Directory.verifyDirectory;
    const received = try verify_files(a, output.dir, external, .{ .endpoint_events_nomination = event_nomination }, .{});
    try std.testing.expectEqualDeep(expected_summary, received);
    const bridge_bytes = try output.dir.readFileAlloc(a, "bridge-0.proof", 128 << 20);
    defer a.free(bridge_bytes);
    bridge_bytes[0] ^= 1;
    try output.dir.writeFile(.{ .sub_path = "bridge-0.proof", .data = bridge_bytes });
    try std.testing.expectError(error.UntrustedEndpointTransport, verify_files(a, output.dir, external, .{ .endpoint_events_nomination = event_nomination }, .{}));
    bridge_bytes[0] ^= 1;
    try output.dir.writeFile(.{ .sub_path = "bridge-0.proof", .data = bridge_bytes });
    std.debug.print("B8_CLEAN_LOCAL_TRAIN queries=70 pow=26 cohorts=2 cycles=8 logical_events=4 endpoints=2 shared_global_providers=1 compact={any} freshly_verified=true\n", .{compact});
}

test "sparse clean local compact sequential producer closes fresh file-only bundle" {
    try qualifyWithObserver(true, struct {
        pub const program_flavor = @import("../block_v8_endpoint_local_scope_v1.zig").RomFlavor.sparse_elf;
    });
}
test "sparse clean local compact parallel producer closes fresh file-only bundle" {
    try qualifyWithObserver(true, struct {
        pub const parallel_local_proofs: u32 = 2;
        pub const program_flavor = @import("../block_v8_endpoint_local_scope_v1.zig").RomFlavor.sparse_elf;
    });
}
