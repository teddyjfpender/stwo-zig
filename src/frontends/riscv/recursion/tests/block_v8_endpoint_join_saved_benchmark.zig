//! Saved compact originals -> ONE closed root. No VM execution/source proving.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Window = @import("../../prover/block_v7_real_window_policy_v2.zig");
const Directory = @import("../../prover/block_v8_endpoint_local_directory_v1.zig");
const Transport = @import("../../prover/block_v8_endpoint_local_transport_v1.zig");
const Metadata = @import("../../prover/block_v8_endpoint_local_statement_wire_v1.zig");
const Codec = @import("../../prover/block_v8_endpoint_local_codec_v1.zig");
const Scope = @import("../../prover/block_v8_endpoint_local_scope_v1.zig");
const BridgeScope = @import("../../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const L = @import("../block_v8_endpoint_recursive_adapter_v1.zig").For(.local_open);
const B = @import("../block_v8_endpoint_bridge_recursive_v1.zig");
const G = @import("../block_v8_compact_ram_recursive_v1.zig");
const Source = @import("../block_v8_endpoint_join_source_v1.zig");
const Pipeline = @import("../block_v8_endpoint_join_pipeline_v1.zig");
const Receiver = @import("../block_v8_endpoint_join_many_receiver_v1.zig");
fn env(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingSavedJoinInput;
}
fn num(comptime T: type, name: [:0]const u8) !T {
    return std.fmt.parseInt(T, try env(name), 10);
}
fn digest(name: [:0]const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, try env(name));
    return out;
}
fn json(a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = path, .data = bytes });
}
fn cells(columns: []const []const u32) !u64 {
    var total: u64 = 0;
    for (columns) |tree| for (tree) |log| {
        if (log > 30) return error.InvalidSavedJoinShape;
        total = try std.math.add(u64, total, @as(u64, 1) << @intCast(log));
    };
    return total;
}
const SourceCensus = struct { kind: Source.Kind, trace_trees: usize, original_raw_cells: u64, original_lde_cells: u64, physical_claims: usize, constraints: usize };
fn census(source: Source.Source) !SourceCensus {
    return switch (source) {
        inline else => |p, k| .{ .kind = k, .trace_trees = p.shape.columns.len - 1, .original_raw_cells = (try cells(p.shape.columns)) >> @intCast(p.shape.config.fri_config.log_blowup_factor), .original_lde_cells = try cells(p.shape.columns), .physical_claims = switch (k) {
            .local => p.claims.native.len + 11 + 2 + 1 + 6,
            .mixed => p.claims.native.len + 11 + 2 + 1 + 6 + p.claims.caller_ram.len,
            .bridge => p.claims.len,
            .global => 10,
        }, .constraints = p.constraint_count },
    };
}

test "saved compact endpoint originals to one closed root benchmark" {
    if (std.posix.getenv("STWO_B8_JOIN_SOURCE_DIR") == null) return error.SkipZigTest;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
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
    if (!std.meta.eql(Capture.sha(elf), try digest("STWO_B8_JOIN_ELF_SHA256"))) return error.UntrustedSavedJoinElf;
    const inbytes = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_JOIN_INCOMING"), 256 << 20);
    defer a.free(inbytes);
    const outbytes = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_JOIN_OUTGOING"), 256 << 20);
    defer a.free(outbytes);
    var incoming = try Capture.Snapshot.decode(a, inbytes, try digest("STWO_B8_JOIN_INCOMING_SHA256"), .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outbytes, try digest("STWO_B8_JOIN_OUTGOING_SHA256"), .{});
    defer outgoing.deinit(a);
    const config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var full_boundary = try @import("../../prover/block_v8_full_boundary_policy_v1.zig").fromEnvironment(a, elf, Capture.sha(elf), config);
    defer if (full_boundary) |*full| full.deinit();
    const selected_boundary = if (full_boundary) |*full| try full.windowOptions(try num(u64, "STWO_B8_JOIN_SKIP"), try num(u32, "STWO_B8_JOIN_CYCLES")) else @import("../../prover/block_v8_execution_boundary_ports_v1.zig").Options{};
    const external = Receiver.External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = Capture.sha(elf), .incoming_sha256 = incoming.identity(), .outgoing_sha256 = outgoing.identity(), .window = .{ .skip_cycles = try num(u64, "STWO_B8_JOIN_SKIP"), .cycles = try num(u32, "STWO_B8_JOIN_CYCLES") } }, .config = config, .boundary = selected_boundary };
    var input_dir = try std.fs.cwd().openDir(try env("STWO_B8_JOIN_SOURCE_DIR"), .{});
    defer input_dir.close();
    var output = try std.fs.cwd().openDir(try env("STWO_B8_JOIN_OUTPUT"), .{});
    defer output.close();
    if (output.access("root.proof", .{})) |_| return error.RefuseOverwriteSavedJoinRoot else |err| if (err != error.FileNotFound) return err;
    const global_json = try input_dir.readFileAlloc(a, "global-public.json", 128 << 20);
    defer a.free(global_json);
    var parsed = try std.json.parseFromSlice(Directory.Data(true), a, global_json, .{});
    defer parsed.deinit();
    const data = parsed.value;
    const n = data.cohort_count;
    if (n == 0 or n > 62 or data.bridge_batches != 1 or n != data.cohort_policy.cohort_count or !std.meta.eql(data.window, external.trusted.window) or !std.meta.eql(data.config, config)) return error.InvalidSavedJoinRoster;
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, elf, incoming, outgoing, external.trusted, data.cohort_policy, data.selected_initial_addresses, external.boundary, .{});
    defer window.deinit();
    const extra = Receiver.boundaryBytes(&window);
    const loading_ns = phase.lap();
    const metas = try a.alloc([]const u8, n);
    defer a.free(metas);
    var meta_count: usize = 0;
    defer for (metas[0..meta_count]) |bytes| a.free(bytes);
    const sources = try a.alloc(Source.Source, n + 2);
    defer a.free(sources);
    var source_count: usize = 0;
    defer for (sources[0..source_count]) |source| Source.deinitProfile(source);
    const local_captures = try a.alloc(L.Original.VerifiedCapture, n);
    defer a.free(local_captures);
    var cap_count: usize = 0;
    var captures_live = true;
    defer if (captures_live) for (local_captures[0..cap_count]) |*c| c.deinit();
    const caps = try a.alloc(Source.Capture, n + 2);
    defer a.free(caps);
    const pins = try a.alloc(BridgeScope.Source, n);
    defer a.free(pins);
    const proposed = try a.alloc(L.Ledger.Claims, n);
    defer a.free(proposed);
    var events: u32 = 0;
    var original_verify_ns: u64 = 0;
    var profile_ns: u64 = 0;
    const provider = Directory.Provider{ .directory = input_dir, .config = config, .cohorts = n, .local_metadata_bytes = 16 << 20, .local_proof_bytes = 128 << 20, .transport = .{} };
    for (0..n) |i| {
        var lease = try provider.loadLocal(a, @intCast(i));
        defer lease.deinit();
        metas[i] = try a.dupe(u8, lease.metadata);
        meta_count += 1;
        const trusted = Scope.Trusted{ .elf = elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = n, .terminal_cycle = if (external.boundary.terminal != null) external.trusted.window.cycles else null, .boundary_policy_id = if (external.boundary.terminal) |last| last.policy_id else @splat(0) };
        const metadata = try Metadata.decode(a, lease.metadata, trusted, .{});
        defer metadata.deinit();
        var decoded = try Codec.decode(a, lease.proof, trusted, metadata.input, .{});
        defer decoded.deinit();
        phase.reset();
        local_captures[i] = try L.Original.verifyAndCapture(a, trusted, metadata.input, &decoded.stark, decoded.claims, .{});
        cap_count += 1;
        original_verify_ns += phase.lap();
        sources[i] = .{ .local = try L.Profile.Owned.derive(a, metadata, decoded.claims, .{}) };
        source_count += 1;
        profile_ns += phase.lap();
        caps[i] = .{ .local = &local_captures[i] };
        proposed[i] = sources[i].local.claims;
        const source = sources[i].local.scope.source();
        pins[i] = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
        events = try std.math.add(u32, events, source.endpoint_count);
        std.debug.print("B8_SAVED_JOIN_CAPTURE local={d}/{d} original_verify_ns={d} profile_ns={d}\n", .{ i + 1, n, original_verify_ns, profile_ns });
    }
    const policy = G.Original.Policy{ .window = &window, .config = config, .event_count = events };
    const bridge_metadata = try B.Statement.Owned.init(a, .{ .config = config, .block_statement = try policy.digest() }, .{ .sources = pins, .global_memory = try policy.entry(data.memory_roots), .batch_first = 0, .batch_count = n });
    defer bridge_metadata.deinit();
    if (!std.meta.eql(bridge_metadata.scope.epoch.digest, data.global_epoch)) return error.UntrustedSavedJoinGlobalEpoch;
    var bridge = try provider.loadBridge(a, 0);
    var bridge_live = true;
    defer if (bridge_live) bridge.deinit();
    phase.reset();
    var bridge_capture = try B.Original.verifyConditionalAndCapture(a, bridge_metadata.scope, &bridge.proof.stark, bridge.proof.claims, .{});
    var bridge_cap_live = true;
    defer if (bridge_cap_live) bridge_capture.deinit();
    original_verify_ns += phase.lap();
    sources[n] = .{ .bridge = try B.Profile.Owned.derive(a, bridge_metadata, bridge.proof.claims, .{}) };
    source_count += 1;
    profile_ns += phase.lap();
    caps[n] = .{ .bridge = &bridge_capture };
    const global_bytes = try input_dir.readFileAlloc(a, "global-memory.proof", 128 << 20);
    defer a.free(global_bytes);
    var decoded_global = try Transport.compact(a, global_bytes, events, policy.boundaryLog(), config, .{});
    var decoded_global_live = true;
    defer if (decoded_global_live) decoded_global.deinit();
    const global_view = G.Original.Proof{ .a = decoded_global.arena.allocator(), .budget = decoded_global.budget, .event_count = events, .roots = data.memory_roots, .claims = decoded_global.claims, .stark = decoded_global.stark };
    const global_metadata = try G.Statement.Owned.init(a, .{ .config = config, .policy = policy }, .{ .epoch = bridge_metadata.scope.epoch, .entries = bridge_metadata.scope.entries, .roots = data.memory_roots });
    defer global_metadata.deinit();
    phase.reset();
    var global_capture = try G.Original.verifyAndCaptureConditional(a, policy, bridge_metadata.scope.epoch, bridge_metadata.scope.entries, &global_view, .{});
    var global_cap_live = true;
    defer if (global_cap_live) global_capture.deinit();
    original_verify_ns += phase.lap();
    sources[n + 1] = .{ .global = try G.Profile.Owned.derive(a, global_metadata, decoded_global.claims, .{}) };
    source_count += 1;
    profile_ns += phase.lap();
    caps[n + 1] = .{ .global = &global_capture };
    const censuses = try a.alloc(SourceCensus, sources.len);
    defer a.free(censuses);
    for (sources, censuses) |source, *c| c.* = try census(source);
    try json(a, output, "source-report.json", .{ .schema = "stwo-b8-saved-compact-source-census-v1", .sources = censuses, .snapshot_delta_public_ports = @as(u32, 0), .original_captures = sources.len });
    var writer = @import("../../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
    defer writer.deinit();
    var remaining: usize = 1 << 20;
    try @import("../../prover/block_v7_union_claim_wire_v1.zig").encode(Receiver.Claims, &writer, .{ .locals = proposed, .bridge = bridge.proof.claims, .global = decoded_global.claims }, &remaining);
    try output.writeFile(.{ .sub_path = "physical-claims.bin", .data = writer.bytes.items });
    bridge.deinit();
    bridge_live = false;
    decoded_global.deinit();
    decoded_global_live = false;
    const global_g_repartition = std.posix.getenv("STWO_B8_JOIN_GLOBAL_G") != null;
    if (std.posix.getenv("STWO_B8_JOIN_CENSUS_ONLY") != null) {
        var diagnostic = try @import("../block_v8_endpoint_join_roster_v1.zig").Owned.deriveWithOptions(a, sources, &extra, .{ .global_g_repartition = global_g_repartition });
        defer diagnostic.deinit();
        const memory = try diagnostic.memoryCensus();
        try json(a, output, "memory-census.json", memory);
        std.debug.print("B8_JOIN_MEMORY_CENSUS predicted_joined_retained_bytes={d} main_bytes={d} aggregate_fixed_bytes={d} cold_children_fixed_bytes={d}\n", .{ memory.predicted_joined_retained_bytes, memory.predicted_joined_main_bytes, memory.aggregate_fixed_bytes, memory.cold_children_fixed_bytes });
        return;
    }
    const source_workers: u8 = if (std.posix.getenv("STWO_B8_JOIN_SOURCE_WORKERS")) |text| try std.fmt.parseInt(u8, text, 10) else 2;
    var root = try Pipeline.produceWithOptions(a, sources, caps, &extra, .csp_q70_pow26, .{ .source_workers = source_workers, .global_g_repartition = global_g_repartition });
    defer root.deinit();
    try output.writeFile(.{ .sub_path = "root.proof", .data = root.bytes });
    for (local_captures[0..cap_count]) |*c| c.deinit();
    captures_live = false;
    bridge_capture.deinit();
    bridge_cap_live = false;
    global_capture.deinit();
    global_cap_live = false;
    for (sources[0..source_count]) |source| Source.deinitProfile(source);
    source_count = 0;
    phase.reset();
    var received = try Receiver.verify(a, external, .{ .root = root.bytes, .physical_claims = writer.bytes.items, .local_metadata = metas, .global_roots = data.memory_roots, .cohort_policy = data.cohort_policy, .selected_addresses = data.selected_initial_addresses, .global_g_repartition = global_g_repartition });
    defer received.deinit();
    const fresh_receiver_ns = phase.lap();
    var root_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(root.bytes, &root_sha, .{});
    try json(a, output, "report.json", .{ .schema = "stwo-b8-saved-compact-single-dag-root-benchmark-v1", .scope = "declared nonterminal native window recursively closed; no source reproof or execution; not a full Ethereum block", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .workers = @as(u32, 8), .backing_allocator = "std.heap.smp_allocator", .global_g_repartition = global_g_repartition, .window = external.trusted.window, .cohorts = n, .loading_ns = loading_ns, .original_verify_ns = original_verify_ns, .original_profile_ns = profile_ns, .parent = root.stats, .parent_whole_ns = root.whole_ns, .fresh_receiver_ns = fresh_receiver_ns, .whole_ns = whole.read(), .root_bytes = root.bytes.len, .root_sha256 = std.fmt.bytesToHex(root_sha, .lower), .charged_peak_bytes = budget.snapshot().peak_live_bytes, .source_captures = sources.len, .source_execution_count = @as(u32, 0), .source_reproof_count = @as(u32, 0), .snapshot_delta_public_ports = @as(u32, 0), .fresh_verified = true });
    std.debug.print("B8_SAVED_COMPACT_SINGLE_ROOT verified=true cohorts={d} cycles={d} root_bytes={d} parent_proof_ns={d} fresh_receiver_ns={d} peak_bytes={d}\n", .{ n, external.trusted.window.cycles, root.bytes.len, root.proof_ns, fresh_receiver_ns, budget.snapshot().peak_live_bytes });
}
