//! Saved ORIGINAL files only; no historical parent body/capture is consumed.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Capture = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Thin = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
const Saved = @import("saved_metadata.zig");
const Join = @import("window_join.zig");

test "RISC direct original saved metadata from durable native and mixed originals" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_SAVED_METADATA_Q70")) return error.SkipZigTest;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try native(a);
    try mixed(a);
    std.debug.print("RISC_ORIGINAL_SAVED_METADATA native_initial_middle_terminal=true mixed_sha_keccak=true authority_parity=true original_verifications=0 parent_proofs_read=0 parent_derivations=0 proofs_generated=0 full_block=false\n", .{});
}

fn native(a: std.mem.Allocator) !void {
    const elf = @import("../riscv_recursion/qualification_v1.zig").tinyElf();
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const trusted = Full.Trusted{ .elf_sha256 = Capture.sha(&elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = output, .config = config };
    var boundary = try Full.Owned.derive(a, &elf, &.{}, trusted, .{});
    defer boundary.deinit();
    var directory = try std.fs.cwd().openDir("campaign/qualification/new-full-block-depth2-driver-q70-v1", .{});
    defer directory.close();
    for ([_]u64{ 0, 4, 6 }, [_]u32{ 4, 2, 1 }, 0..) |skip, cycles, i| {
        var capture = try Capture.capture(a, &elf, &.{}, .{ .elf = trusted.elf_sha256, .input = trusted.input_sha256 }, .{ .skip_cycles = skip, .cycles = cycles }, .{});
        defer capture.deinit();
        capture.releaseExecution();
        const external = Upper.External{ .elf = &elf, .incoming = capture.incoming, .outgoing = capture.outgoing, .trusted = .{ .elf_sha256 = trusted.elf_sha256, .incoming_sha256 = capture.incoming.identity(), .outgoing_sha256 = capture.outgoing.identity(), .window = .{ .skip_cycles = skip, .cycles = cycles } }, .config = config, .boundary = try boundary.windowOptions(skip, cycles) };
        var name: [64]u8 = undefined;
        const public = try directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "node-{d}.public", .{i}), 16 << 20);
        defer a.free(public);
        var expected_leaf = try Thin.decodeNativeLeafOwned(a, public, .{});
        defer expected_leaf.deinit();
        var expected = try Join.Authority.derive(a, .{ .native = .{ .external = external, .input = expected_leaf.value } });
        defer expected.deinit();
        var originals = try directory.openDir(try std.fmt.bufPrint(&name, "window-{d}", .{i}), .{});
        defer originals.close();
        var saved = try Saved.Owned.fromDirectory(a, .native, originals, external);
        defer saved.deinit();
        try std.testing.expectEqualDeep(@as([32]u8, @splat(0)), saved.metadata.native.input.main_root);
        var actual = try Join.Authority.derive(a, saved.metadata);
        defer actual.deinit();
        try std.testing.expectEqualDeep(expected.seal, actual.seal);
        try std.testing.expectEqualDeep(try expected.statement.digest(), try actual.statement.digest());
        var wire = try Thin.decodeNativeLeafOwned(a, saved.public_bytes, .{});
        defer wire.deinit();
        try std.testing.expectEqualDeep(@as([32]u8, @splat(0)), wire.value.main_root);
        try std.testing.expectEqualSlices(u8, saved.metadata.native.input.physical_claims, wire.value.physical_claims);
    }
}

fn digest(text: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}
fn pinned(a: std.mem.Allocator, directory: std.fs.Dir, name: []const u8, pin: []const u8) ![]u8 {
    const bytes = try directory.readFileAlloc(a, name, 32 << 20);
    errdefer a.free(bytes);
    if (!std.meta.eql(Capture.sha(bytes), try digest(pin))) return error.UntrustedSavedOriginalFixture;
    return bytes;
}
fn mixed(a: std.mem.Allocator) !void {
    const M = @import("../../../frontends/riscv/recursion/block_v8_endpoint_mixed_recursive_v1.zig");
    const Metadata = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_statement_wire_v1.zig");
    const Codec = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_codec_v1.zig");
    var directory = try std.fs.cwd().openDir("vectors/reports/riscv-cpu-architecture-20261029/mixed-durable-compact-bundle-q70/sha_keccak", .{});
    defer directory.close();
    const elf = try pinned(a, directory, "guest.elf", "d079709f439e8b303eebc08766e858495e0288d8a6c12c06bc5fbfae67cb7aa4");
    defer a.free(elf);
    const incoming_id = try digest("f33cbcd3ad14cff75b236addc55e2b2f8ab356c2048726979649a429666f0a73");
    const outgoing_id = try digest("c3849abe8c8dd7cdd49d5e8cf75c55932e327c7e491b03da061e808a7ffe0322");
    const in_bytes = try directory.readFileAlloc(a, "incoming.b7win", 32 << 20);
    defer a.free(in_bytes);
    const out_bytes = try directory.readFileAlloc(a, "outgoing.b7win", 32 << 20);
    defer a.free(out_bytes);
    var incoming = try Capture.Snapshot.decode(a, in_bytes, incoming_id, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, out_bytes, outgoing_id, .{});
    defer outgoing.deinit(a);
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const external = Upper.External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = Capture.sha(elf), .incoming_sha256 = incoming_id, .outgoing_sha256 = outgoing_id, .window = .{ .skip_cycles = 0, .cycles = 6 } }, .config = config };
    // Separate direct statement/codec extraction is an independent reference
    // for the factory's mixed source. Its raw decoder and statement die here.
    const expected = blk: {
        const metadata = try directory.readFileAlloc(a, "local-0.json", 16 << 20);
        defer a.free(metadata);
        const trusted = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_scope_v1.zig").Trusted{ .elf = elf, .elf_sha256 = Capture.sha(elf), .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
        const statement = try Metadata.decode(a, metadata, trusted, .{});
        defer statement.deinit();
        const raw = try directory.readFileAlloc(a, "local-0.proof", 128 << 20);
        defer a.free(raw);
        var decoded = try Codec.decode(a, raw, trusted, statement.input, .{});
        defer decoded.deinit();
        break :blk try M.Profile.Owned.derive(a, statement, decoded.claims, .{});
    };
    defer expected.deinit();
    var saved = try Saved.Owned.fromDirectory(a, .mixed, directory, external);
    defer saved.deinit();
    try std.testing.expectEqual(@as(usize, 0), saved.metadata.mixed.input.root.len);
    var actual = try Join.Authority.derive(a, saved.metadata);
    defer actual.deinit();
    try std.testing.expectEqualDeep(expected.seal, actual.admission.sources[0].mixed.seal);
    try std.testing.expectEqual(@as(usize, 3), actual.sources.len);
    try std.testing.expectEqual(@as(u64, 1), actual.statement.span.first_cycle);
    try std.testing.expectEqual(@as(u64, 6), actual.statement.span.cycles);
    try std.testing.expectEqualDeep(incoming_id, actual.statement.span.incoming_snapshot_id);
    try std.testing.expectEqualDeep(outgoing_id, actual.statement.span.outgoing_snapshot_id);
    try std.testing.expectEqualDeep(incoming.cpu, actual.statement.span.initial_cpu);
    try std.testing.expectEqualDeep(outgoing.cpu, actual.statement.span.final_cpu);
    try std.testing.expect(actual.statement.span.initial_policy_id == null and actual.statement.span.terminal_policy_id == null);
    var wire = try Thin.decodeMixedLeafOwned(a, saved.public_bytes, .{});
    defer wire.deinit();
    try std.testing.expectEqual(@as(usize, 0), wire.value.input.root.len);
    try std.testing.expectEqualDeep(@as([32]u8, @splat(0)), wire.value.main_root);
}
