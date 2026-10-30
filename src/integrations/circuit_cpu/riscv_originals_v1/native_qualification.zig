//! Initial/middle/terminal direct-original gates using durable originals.
//! The historical NativeParent proof bodies are deliberately never loaded.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const b = @import("stwo_circuit_frontend").builder;
const Q = core.fields.qm31.QM31;
const Capture = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
const Wire = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
const Admission = @import("admission.zig");
const Join = @import("window_join.zig");
const Material = @import("material.zig");
const Window = @import("window_registry.zig");
const Registry = @import("../riscv_recursion/registry_v1.zig");
const Fold = @import("../riscv_recursion/circuit_fold_v1.zig");
const FoldWire = @import("../riscv_recursion/fold_wire_v1.zig");

test "RISC direct original native initial middle terminal and depth two q70" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_NATIVE_Q70")) return error.SkipZigTest;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    const elf = @import("../riscv_recursion/qualification_v1.zig").tinyElf();
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var expected: [43]u8 = @splat(0);
    expected[32] = 1;
    const trusted = Full.Trusted{ .elf_sha256 = Capture.sha(&elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = expected, .config = config };
    var boundary = try Full.Owned.derive(a, &elf, &.{}, trusted, .{});
    defer boundary.deinit();
    var directory = try std.fs.cwd().openDir("campaign/qualification/new-full-block-depth2-driver-q70-v1", .{});
    defer directory.close();
    var captures: [3]Capture.Captured = undefined;
    var initialized: usize = 0;
    defer for (captures[0..initialized]) |*capture| capture.deinit();
    var metadata: [3]Admission.Metadata = undefined;
    for (&captures, &metadata, [_]u64{ 0, 4, 6 }, [_]u32{ 4, 2, 1 }, 0..) |*capture, *destination, skip, cycles, index| {
        capture.* = try Capture.capture(a, &elf, &.{}, .{ .elf = trusted.elf_sha256, .input = trusted.input_sha256 }, .{ .skip_cycles = skip, .cycles = cycles }, .{});
        initialized += 1;
        capture.releaseExecution();
        var name: [64]u8 = undefined;
        const public = try directory.readFileAlloc(t, try std.fmt.bufPrint(&name, "node-{d}.public", .{index}), 16 << 20);
        destination.* = .{ .native = .{
            .input = try Wire.decodeNativeLeafLeaky(t, public, .{}),
            .external = .{ .elf = &elf, .incoming = capture.incoming, .outgoing = capture.outgoing, .trusted = .{ .elf_sha256 = trusted.elf_sha256, .incoming_sha256 = capture.incoming.identity(), .outgoing_sha256 = capture.outgoing.identity(), .window = .{ .skip_cycles = skip, .cycles = cycles } }, .config = config, .boundary = try boundary.windowOptions(skip, cycles) },
        } };
        var originals_dir = try directory.openDir(try std.fmt.bufPrint(&name, "window-{d}", .{index}), .{});
        defer originals_dir.close();
        var originals: [3][]const u8 = undefined;
        for (&originals, [_][]const u8{ "local-0.proof", "bridge-0.proof", "global-memory.proof" }) |*raw, path| raw.* = try originals_dir.readFileAlloc(t, path, 128 << 20);
        var authority = try Join.Authority.derive(a, destination.*);
        defer authority.deinit();
        var materials: [3]Material.Owned = undefined;
        var count: usize = 0;
        defer for (materials[0..count]) |*material| material.deinit();
        for (&materials, authority.sources, originals) |*material, *source, raw| {
            material.* = try Material.Owned.fromBytes(a, source, raw, .{});
            count += 1;
        }
        var ctx = try b.Context(Q).init(a, Join.OUTPUTS);
        defer ctx.deinit();
        _ = try Join.build(Q, &ctx, &authority, &materials);
        try Registry.finalizeStrict(Q, &ctx);
        try std.testing.expect(try ctx.isCircuitValid());
        std.debug.print("RISC_ORIGINAL_NATIVE_JOIN index={d} cycles={d} initial={any} terminal={any} variables={d}\n", .{ index, cycles, authority.statement.span.initial_policy_id != null, authority.statement.span.terminal_policy_id != null, ctx.circuit.n_vars });
    }
    if (!std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_NATIVE_FOLD_Q70")) return;
    const air = try std.fs.cwd().readFileAlloc(t, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 1 << 20);
    const projection = try std.fs.cwd().readFileAlloc(t, "vectors/circuit/official/compiled_air_constraints_v1.bin", 1 << 20);
    const backend = try Registry.BackendAuthority.load(a, air, projection);
    defer backend.deinit();
    const output_path = std.posix.getenv("STWO_RISCV_ORIGINALS_NATIVE_OUTPUT") orelse "campaign/qualification/new-direct-original-native-fold-q70-v1";
    try std.fs.cwd().makePath(output_path);
    var output = try std.fs.cwd().openDir(output_path, .{});
    defer output.close();
    var artifacts: [3]Window.Artifact = undefined;
    var count: usize = 0;
    defer for (artifacts[0..count]) |*artifact| artifact.deinit();
    var leaves: [3]Fold.Metadata = undefined;
    for (&artifacts, &leaves, metadata, 0..) |*artifact, *leaf, source_metadata, index| {
        var name: [64]u8 = undefined;
        var originals_dir = try directory.openDir(try std.fmt.bufPrint(&name, "window-{d}", .{index}), .{});
        defer originals_dir.close();
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        var originals: [3][]const u8 = undefined;
        for (&originals, [_][]const u8{ "local-0.proof", "bridge-0.proof", "global-memory.proof" }) |*raw, path| raw.* = try originals_dir.readFileAlloc(scratch.allocator(), path, 128 << 20);
        artifact.* = try Window.produce(a, source_metadata, &originals, backend, .{});
        count += 1;
        try output.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "window-{d}.proof", .{index}), .data = artifact.bytes });
        const times = try std.json.Stringify.valueAlloc(scratch.allocator(), artifact.times, .{ .whitespace = .indent_2 });
        try output.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "window-{d}.times.json", .{index}), .data = times });
        try Window.verifyBytes(a, source_metadata, artifact.bytes, backend, .{});
        leaf.* = .{ .originals = source_metadata };
    }
    const first_pair = [_]Fold.Metadata{ leaves[0], leaves[1] };
    const first_metadata = Fold.Metadata{ .pair = &first_pair };
    var first = try Fold.produce(a, first_metadata, .{ artifacts[0].bytes, artifacts[1].bytes }, backend, .{});
    var first_live = true;
    defer if (first_live) first.deinit();
    try output.writeFile(.{ .sub_path = "fold-0.proof", .data = first.bytes });
    const final_pair = [_]Fold.Metadata{ first_metadata, leaves[2] };
    const final_metadata = Fold.Metadata{ .pair = &final_pair };
    var root = try Fold.produce(a, final_metadata, .{ first.bytes, artifacts[2].bytes }, backend, .{});
    defer root.deinit();
    try output.writeFile(.{ .sub_path = "root.proof", .data = root.bytes });
    // Receiving reconstructs all expected keys from external metadata after
    // producer artifacts have been destroyed. Only the root bytes remain.
    first.deinit();
    first_live = false;
    for (artifacts[0..count]) |*artifact| artifact.deinit();
    count = 0;
    const records = [_]FoldWire.Record{ .{ .kind = 3, .a = 0 }, .{ .kind = 3, .a = 1 }, .{ .kind = 3, .a = 2 }, .{ .kind = 2, .a = 0, .b = 1 }, .{ .kind = 2, .a = 3, .b = 2 } };
    const public_wire = try FoldWire.encode(t, .{ .records = &records, .root = 4, .sources = 3 });
    try output.writeFile(.{ .sub_path = "root.catalog", .data = public_wire });
    const sources = [_]FoldWire.SourceMetadata{ .{ .originals = metadata[0] }, .{ .originals = metadata[1] }, .{ .originals = metadata[2] } };
    var fresh = try std.time.Timer.start();
    try FoldWire.verifyFullSourceBytes(a, public_wire, root.bytes, .{ .sources = &sources, .elf = &elf, .private_input = &.{}, .trusted = trusted, .canonical_circuit_air = air, .canonical_circuit_projection = projection }, .{});
    const verification_ns = fresh.read();
    try std.testing.expectEqual(@as(u32, 2), root.certificate.fold.depth);
    try std.testing.expectEqual(@as(u32, 3), root.certificate.fold.leaves);
    try std.testing.expectEqual(@as(u32, 7), root.certificate.span().cycles);
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(root.bytes, &sha, .{});
    const report = try std.json.Stringify.valueAlloc(t, .{
        .schema = "stwo-riscv-direct-original-depth2-q70-v1",
        .cycles = 7,
        .q = 70,
        .pow_bits = 26,
        .leaves = 3,
        .folds = 2,
        .native_parent_proofs = 0,
        .root_bytes = root.bytes.len,
        .root_sha256 = std.fmt.bytesToHex(sha, .lower),
        .fresh_wire_full_verification_ns = verification_ns,
        .charged_peak_bytes = budget.snapshot().peak_live_bytes,
        .scope = "initial middle terminal seven-cycle fixture; not retained Ethereum block",
    }, .{ .whitespace = .indent_2 });
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
    std.debug.print("RISC_ORIGINAL_NATIVE_ROOT q=70 pow=26 cycles=7 leaves=3 folds=2 bytes={d} peak_bytes={d}\n", .{ root.bytes.len, budget.snapshot().peak_live_bytes });
}
