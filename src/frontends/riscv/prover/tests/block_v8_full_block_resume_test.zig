//! Cached completion is never a receipt: fresh metadata/key reconstruction and
//! parent verification precede reuse. This test never produces a new proof.
const std = @import("std");
const E = @import("stwo_prover_engine");
const C = @import("../block_v7_real_window_capture_v1.zig");
const Pipeline = @import("../block_v8_full_block_pipeline_v1.zig");
const Fixture = @import("block_v8_terminal_mixed_fixture.zig");
const Wire = @import("../../recursion/block_v8_window_root_wire_v1.zig");
const ClaimsWire = @import("../block_v7_union_claim_wire_v1.zig");
const Receiver = @import("../../recursion/block_v8_endpoint_mixed_join_receiver_v1.zig");
const evidence = "vectors/reports/riscv-cpu-architecture-20261029/full-mixed-driver-qualification-v1";
fn seed(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    var source = try std.fs.cwd().openDir(evidence, .{});
    defer source.close();
    for ([_][]const u8{ "root.proof", "node-0.public", "report.json", "catalog.json" }) |name| {
        const bytes = try source.readFileAlloc(a, name, 64 << 20);
        defer a.free(bytes);
        try dir.writeFile(.{ .sub_path = name, .data = bytes });
        if (std.mem.eql(u8, name, "root.proof")) try dir.writeFile(.{ .sub_path = "node-0.proof", .data = bytes });
    }
}
fn noNewProving(dir: std.fs.Dir) !void {
    try std.testing.expectError(error.FileNotFound, dir.access("window-0", .{}));
    try std.testing.expectError(error.FileNotFound, dir.access("node-0.recursion.json", .{}));
}
fn qualifyResume(comptime immutable: bool) !void {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const pins = C.Pins{ .elf = C.sha(&Fixture.elf), .input = C.sha(&.{}) };
    const manifest_bytes = try std.fs.cwd().readFileAlloc(a, "vectors/reports/riscv-cpu-architecture-20261029/terminal-mixed-root-qualification-v1/public-metadata.bin", 16 << 20);
    defer a.free(manifest_bytes);
    var snapshot_arena = std.heap.ArenaAllocator.init(a);
    defer snapshot_arena.deinit();
    const SnapshotManifest = struct { external: Receiver.External, input: Receiver.Input, main_root: [32]u8 };
    var snapshot_cursor = @import("../guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = manifest_bytes };
    var snapshot_items: usize = 1 << 20;
    const saved = try ClaimsWire.decode(SnapshotManifest, snapshot_arena.allocator(), &snapshot_cursor, &snapshot_items);
    try snapshot_cursor.requireDone();
    try std.testing.expectEqualSlices(u8, &Fixture.elf, saved.external.elf);
    const jobs = [_]Pipeline.Job{.{ .kind = .mixed, .request = .{ .elf = &Fixture.elf, .elf_sha256 = pins.elf, .config = config, .incoming = saved.external.incoming, .outgoing = saved.external.outgoing, .trusted_window = .{ .elf_sha256 = pins.elf, .incoming_sha256 = saved.external.incoming.identity(), .outgoing_sha256 = saved.external.outgoing.identity(), .window = .{ .skip_cycles = 0, .cycles = 9 } } } }};
    const input = Pipeline.Input{ .elf = &Fixture.elf, .private_input = &.{}, .trusted = .{ .elf_sha256 = pins.elf, .input_sha256 = pins.input, .total_cycles = 9, .expected_output = Fixture.expectedOutput(), .config = config }, .jobs = &jobs };
    var positive = std.testing.tmpDir(.{ .iterate = true });
    defer positive.cleanup();
    try seed(a, positive.dir);
    const old = try positive.dir.readFileAlloc(a, "root.proof", 64 << 20);
    defer a.free(old);
    try std.testing.expectEqualStrings("d8ffa95771396e877bf7b296891d75f9a7b7bee186a8a2947e5834dc5726f475", &std.fmt.bytesToHex(C.sha(old), .lower));
    try std.testing.expectError(error.NonemptyFullBlockOutput, Pipeline.run(budget, &pool, positive.dir, input, .{}));
    const result = try Pipeline.run(budget, &pool, positive.dir, input, .{ .resume_saved = true, .immutable_admission_cache = immutable });
    try std.testing.expect(result.proof_verified);
    if (immutable) {
        try std.testing.expectEqual(@as(usize, 1), result.admission_cache.?.independent_derivations);
        try std.testing.expectEqual(@as(usize, 0), result.admission_cache.?.temporary_fold_derivations);
    } else try std.testing.expect(result.admission_cache == null);
    try std.testing.expectEqual(@as(u32, 1), result.resumed_windows);
    try std.testing.expectEqual(@as(u32, 0), result.resumed_original_bundles);
    try std.testing.expectEqual(@as(u64, 0), result.originals_ns);
    try std.testing.expectEqual(@as(u64, 0), result.window_roots_ns);
    try std.testing.expectEqual(@as(u64, 0), result.folds_ns);
    try std.testing.expect(!result.fresh_complete_run);
    try std.testing.expectEqualStrings("resume invocation; previously completed proving excluded", result.timing_scope);
    const fresh = try positive.dir.readFileAlloc(a, "root.proof", 64 << 20);
    defer a.free(fresh);
    try std.testing.expectEqualSlices(u8, old, fresh);
    const archived = try positive.dir.readFileAlloc(a, "previous-final-0/root.proof", 64 << 20);
    defer a.free(archived);
    try std.testing.expectEqualSlices(u8, old, archived);
    try noNewProving(positive.dir);

    var bad_main = std.testing.tmpDir(.{ .iterate = true });
    defer bad_main.cleanup();
    try seed(a, bad_main.dir);
    const metadata = try bad_main.dir.readFileAlloc(a, "node-0.public", 16 << 20);
    defer a.free(metadata);
    var parsed = try Wire.decodeMixedLeafOwned(a, metadata, .{});
    defer parsed.deinit();
    parsed.value.main_root[0] ^= 1;
    const tampered = try Wire.encodeMixedLeaf(a, parsed.value);
    defer a.free(tampered);
    try bad_main.dir.writeFile(.{ .sub_path = "node-0.public", .data = tampered });
    try std.testing.expectError(error.UntrustedB8WindowRootCapture, Pipeline.run(budget, &pool, bad_main.dir, input, .{ .resume_saved = true, .immutable_admission_cache = immutable }));
    try noNewProving(bad_main.dir);

    var bad_claim = std.testing.tmpDir(.{ .iterate = true });
    defer bad_claim.cleanup();
    try seed(a, bad_claim.dir);
    var original = try Wire.decodeMixedLeafOwned(a, metadata, .{});
    defer original.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var cursor = @import("../guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = original.value.input.physical_claims };
    var remaining: usize = 1 << 20;
    const claims = try ClaimsWire.decode(Receiver.Claims, arena.allocator(), &cursor, &remaining);
    try cursor.requireDone();
    try std.testing.expect(claims.mixed.caller_ram.len >= 2);
    const ram = @constCast(claims.mixed.caller_ram);
    const Q = @import("stwo_core").fields.qm31.QM31;
    ram[0] = ram[0].add(Q.one());
    ram[1] = ram[1].sub(Q.one());
    var writer = @import("../bounded_artifact_writer_v1.zig").Writer.init(a, 16 << 20);
    defer writer.deinit();
    remaining = 1 << 20;
    try ClaimsWire.encode(Receiver.Claims, &writer, claims, &remaining);
    original.value.input.physical_claims = writer.bytes.items;
    const changed_claims = try Wire.encodeMixedLeaf(a, original.value);
    defer a.free(changed_claims);
    try bad_claim.dir.writeFile(.{ .sub_path = "node-0.public", .data = changed_claims });
    if (Pipeline.run(budget, &pool, bad_claim.dir, input, .{ .resume_saved = true, .immutable_admission_cache = immutable })) |_| return error.AcceptedChangedSavedClaims else |err| {
        std.debug.print("B8_RESUME_CLAIM_NEGATIVE error={s}\n", .{@errorName(err)});
        try std.testing.expect(err == error.UntrustedBlake3ParentKey or err == error.InvalidBlake3ParentClaims or err == error.UntrustedBlake3ParentPublicInputs);
    }
    try noNewProving(bad_claim.dir);

    var missing = std.testing.tmpDir(.{ .iterate = true });
    defer missing.cleanup();
    try seed(a, missing.dir);
    try missing.dir.deleteFile("node-0.proof");
    try std.testing.expectError(error.IncompleteSavedWindowRoot, Pipeline.run(budget, &pool, missing.dir, input, .{ .resume_saved = true, .immutable_admission_cache = immutable }));
    try noNewProving(missing.dir);
    std.debug.print("B8_RESUME_QUALIFIED immutable_cache={any} source_execution_count=0 cached_windows=1 original_proofs=0 parent_proofs=0 root_bytes_identical=true fresh_final_verify=true malicious_main_claim_missing_rejected=true\n", .{immutable});
}

test "resume saved complete mixed root revalidates cached leaf and rejects tampering without proving" {
    try qualifyResume(false);
}
test "immutable cache full driver saved mixed candidate and thin tree routing reject tampering" {
    try qualifyResume(true);
}
