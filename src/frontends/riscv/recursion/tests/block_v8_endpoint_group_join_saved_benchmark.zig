//! Retained Group + bridge + compact originals -> ONE recursively closed root.
//! This runner does not execute the VM or produce new child proofs.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Saved = @import("../block_v8_endpoint_group_join_saved_v1.zig");
const Receiver = @import("../block_v8_endpoint_group_join_receiver_v1.zig");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
fn env(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingSavedGroupJoinInput;
}
fn num(comptime T: type, name: [:0]const u8) !T {
    return std.fmt.parseInt(T, try env(name), 10);
}
fn digest(name: [:0]const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, try env(name));
    return out;
}
test "saved Group three original bodies to ONE closed root benchmark" {
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
    if (!std.meta.eql(Capture.sha(elf), try digest("STWO_B8_JOIN_ELF_SHA256"))) return error.UntrustedSavedGroupJoinElf;
    const inbytes = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_JOIN_INCOMING"), 256 << 20);
    defer a.free(inbytes);
    const outbytes = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_JOIN_OUTGOING"), 256 << 20);
    defer a.free(outbytes);
    var incoming = try Capture.Snapshot.decode(a, inbytes, try digest("STWO_B8_JOIN_INCOMING_SHA256"), .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outbytes, try digest("STWO_B8_JOIN_OUTGOING_SHA256"), .{});
    defer outgoing.deinit(a);
    const external = Saved.External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = Capture.sha(elf), .incoming_sha256 = incoming.identity(), .outgoing_sha256 = outgoing.identity(), .window = .{ .skip_cycles = try num(u64, "STWO_B8_JOIN_SKIP"), .cycles = try num(u32, "STWO_B8_JOIN_CYCLES") } }, .config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config() };
    var input_dir = try std.fs.cwd().openDir(try env("STWO_B8_JOIN_SOURCE_DIR"), .{});
    defer input_dir.close();
    var output = try std.fs.cwd().openDir(try env("STWO_B8_JOIN_OUTPUT"), .{});
    defer output.close();
    if (output.access("root.proof", .{})) |_| return error.RefuseOverwriteSavedGroupJoinRoot else |err| if (err != error.FileNotFound) return err;
    const source_workers: u8 = if (std.posix.getenv("STWO_B8_JOIN_SOURCE_WORKERS")) |s| try std.fmt.parseInt(u8, s, 10) else 2;
    var saved = try Saved.produce(a, input_dir, external, .{ .source_workers = source_workers });
    var live = true;
    defer if (live) saved.deinit();
    try output.writeFile(.{ .sub_path = "root.proof", .data = saved.root.bytes });
    try output.writeFile(.{ .sub_path = "physical-claims.bin", .data = saved.claims });
    try output.writeFile(.{ .sub_path = "group-0.json", .data = saved.metadata });
    const cohort_policy = saved.data.cohort_policy;
    const selected = try a.dupe(u32, saved.data.selected_initial_addresses);
    defer a.free(selected);
    const roots = saved.data.memory_roots;
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
    const metadata = try output.readFileAlloc(a, "group-0.json", 128 << 20);
    defer a.free(metadata);
    var timer = try std.time.Timer.start();
    var verified = try Receiver.verify(a, external, .{ .root = root_bytes, .physical_claims = claims, .group_metadata = metadata, .global_roots = roots, .cohort_policy = cohort_policy, .selected_addresses = selected });
    defer verified.deinit();
    const fresh_receiver_ns = timer.read();
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-saved-group-single-dag-root-benchmark-v1", .scope = "declared nonterminal native window recursively closed; not full Ethereum block", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .workers = @as(u32, 8), .window = external.trusted.window, .cohorts = cohort_policy.cohort_count, .group_originals = @as(u32, 1), .bridge_originals = @as(u32, 1), .compact_originals = @as(u32, 1), .source_captures = @as(u32, 3), .intermediate_recursive_proofs = @as(u32, 0), .source_reproof_count = @as(u32, 0), .source_execution_count = @as(u32, 0), .snapshot_delta_public_ports = @as(u32, 0), .parent = parent_stats, .parent_whole_ns = parent_whole_ns, .fresh_receiver_ns = fresh_receiver_ns, .whole_ns = whole.read(), .root_bytes = root_len, .root_sha256 = std.fmt.bytesToHex(sha, .lower), .charged_peak_bytes = budget.snapshot().peak_live_bytes, .fresh_verified = true, .file_only_receiver = true }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
    std.debug.print("B8_SAVED_GROUP_SINGLE_ROOT verified=true cohorts={d} cycles={d} root_bytes={d} core_ns={d} fresh_receiver_ns={d} peak_bytes={d}\n", .{ cohort_policy.cohort_count, external.trusted.window.cycles, root_len, parent_stats.proof_ns, fresh_receiver_ns, budget.snapshot().peak_live_bytes });
}
