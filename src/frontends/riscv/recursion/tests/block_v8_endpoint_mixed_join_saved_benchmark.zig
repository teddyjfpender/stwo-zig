//! Retained Mixed + bridge + compact originals -> ONE recursively closed root.
//! This runner does not execute the VM or produce new child proofs.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Saved = @import("../block_v8_endpoint_mixed_join_saved_v1.zig");
const Receiver = @import("../block_v8_endpoint_mixed_join_receiver_v1.zig");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
fn env(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingSavedMixedJoinInput;
}
fn num(comptime T: type, name: [:0]const u8) !T {
    return std.fmt.parseInt(T, try env(name), 10);
}
fn digest(name: [:0]const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    const encoded = try env(name);
    if (encoded.len != 64) return error.InvalidSavedMixedDigest;
    _ = try std.fmt.hexToBytes(&out, encoded);
    return out;
}
test "saved Mixed three original bodies to ONE closed root benchmark" {
    if (std.posix.getenv("STWO_B8_JOIN_SOURCE_DIR") == null) return error.SkipZigTest;
    var whole = try std.time.Timer.start();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_JOIN_ELF"), 32 << 20);
    defer a.free(elf);
    if (!std.meta.eql(Capture.sha(elf), try digest("STWO_B8_JOIN_ELF_SHA256"))) return error.UntrustedSavedMixedJoinElf;
    const inbytes = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_JOIN_INCOMING"), 256 << 20);
    defer a.free(inbytes);
    const outbytes = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_JOIN_OUTGOING"), 256 << 20);
    defer a.free(outbytes);
    var incoming = try Capture.Snapshot.decode(a, inbytes, try digest("STWO_B8_JOIN_INCOMING_SHA256"), .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outbytes, try digest("STWO_B8_JOIN_OUTGOING_SHA256"), .{});
    defer outgoing.deinit(a);
    const FullBoundary = @import("../../prover/block_v8_full_boundary_policy_v1.zig");
    var full_boundary: ?FullBoundary.Owned = null;
    defer if (full_boundary) |*value| value.deinit();
    if (std.posix.getenv("STWO_B8_JOIN_FULL_INPUT")) |input_path| {
        const input_bytes = try std.fs.cwd().readFileAlloc(a, input_path, 64 << 20);
        defer a.free(input_bytes);
        var expected_output: [43]u8 = undefined;
        const encoded_output = try env("STWO_B8_JOIN_EXPECTED_OUTPUT");
        if (encoded_output.len != 86) return error.InvalidSavedMixedExpectedOutput;
        _ = try std.fmt.hexToBytes(&expected_output, encoded_output);
        full_boundary = try FullBoundary.Owned.derive(a, elf, input_bytes, .{
            .elf_sha256 = Capture.sha(elf),
            .input_sha256 = try digest("STWO_B8_JOIN_FULL_INPUT_SHA256"),
            .total_cycles = try num(u64, "STWO_B8_JOIN_TOTAL_CYCLES"),
            .expected_output = expected_output,
            .config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(),
        }, .{});
    }
    var external = Saved.External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = Capture.sha(elf), .incoming_sha256 = incoming.identity(), .outgoing_sha256 = outgoing.identity(), .window = .{ .skip_cycles = try num(u64, "STWO_B8_JOIN_SKIP"), .cycles = try num(u32, "STWO_B8_JOIN_CYCLES") } }, .config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config() };
    if (full_boundary) |*value| external.boundary = try value.windowOptions(external.trusted.window.skip_cycles, external.trusted.window.cycles);
    var input_dir = try std.fs.cwd().openDir(try env("STWO_B8_JOIN_SOURCE_DIR"), .{});
    defer input_dir.close();
    var output = try std.fs.cwd().openDir(try env("STWO_B8_JOIN_OUTPUT"), .{});
    defer output.close();
    if (output.access("root.proof", .{})) |_| return error.RefuseOverwriteSavedMixedJoinRoot else |err| if (err != error.FileNotFound) return err;
    const source_workers: u8 = if (std.posix.getenv("STWO_B8_JOIN_SOURCE_WORKERS")) |s| try std.fmt.parseInt(u8, s, 10) else 2;
    var saved = try Saved.produce(a, input_dir, external, .{ .source_workers = source_workers });
    var live = true;
    defer if (live) saved.deinit();
    try output.writeFile(.{ .sub_path = "root.proof", .data = saved.root.bytes });
    try output.writeFile(.{ .sub_path = "physical-claims.bin", .data = saved.claims });
    try output.writeFile(.{ .sub_path = "local-0.json", .data = saved.metadata });
    const cohort_policy = saved.data.cohort_policy;
    const selected = try a.dupe(u32, saved.data.selected_initial_addresses);
    defer a.free(selected);
    const roots = saved.data.memory_roots;
    const source_preparation = saved.stats;
    const saved_inputs_to_root_ns = saved.whole_ns;
    const parent_stats = saved.root.stats;
    const parent_whole_ns = saved.root.whole_ns;
    const root_len = saved.root.bytes.len;
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(saved.root.bytes, &sha, .{});
    saved.deinit();
    live = false;
    // Strict fresh file receiver, after captures, profiles, keys, all decoded
    // child proofs AND the parent producer artifact have been destroyed.
    const root_bytes = try output.readFileAlloc(a, "root.proof", 16 << 20);
    defer a.free(root_bytes);
    const claims = try output.readFileAlloc(a, "physical-claims.bin", 16 << 20);
    defer a.free(claims);
    const metadata = try output.readFileAlloc(a, "local-0.json", 128 << 20);
    defer a.free(metadata);
    var timer = try std.time.Timer.start();
    var verified = try Receiver.verify(a, external, .{ .global_g_repartition = parent_stats.global_g_repartition, .root = root_bytes, .physical_claims = claims, .mixed_metadata = metadata, .global_roots = roots, .cohort_policy = cohort_policy, .selected_addresses = selected });
    defer verified.deinit();
    const fresh_receiver_ns = timer.read();
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-saved-mixed-single-dag-root-benchmark-v1", .scope = "declared mixed window recursively closed; not full Ethereum block", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .workers = @as(u32, 8), .window = external.trusted.window, .cohorts = cohort_policy.cohort_count, .mixed_originals = @as(u32, 1), .bridge_originals = @as(u32, 1), .compact_originals = @as(u32, 1), .source_captures = @as(u32, 3), .intermediate_recursive_proofs = @as(u32, 0), .source_reproof_count = @as(u32, 0), .source_execution_count = @as(u32, 0), .snapshot_delta_public_ports = @as(u32, 0), .source_preparation = source_preparation, .parent = parent_stats, .parent_whole_ns = parent_whole_ns, .saved_inputs_to_root_ns = saved_inputs_to_root_ns, .fresh_receiver_ns = fresh_receiver_ns, .whole_ns = whole.read(), .root_bytes = root_len, .root_sha256 = std.fmt.bytesToHex(sha, .lower), .charged_peak_bytes = budget.snapshot().peak_live_bytes, .fresh_verified = true, .file_only_receiver = true }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
    std.debug.print("B8_SAVED_MIXED_SINGLE_ROOT verified=true cohorts={d} cycles={d} root_bytes={d} core_ns={d} fresh_receiver_ns={d} peak_bytes={d}\n", .{ cohort_policy.cohort_count, external.trusted.window.cycles, root_len, parent_stats.proof_ns, fresh_receiver_ns, budget.snapshot().peak_live_bytes });
}
