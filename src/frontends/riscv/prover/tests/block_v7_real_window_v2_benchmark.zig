//! Explicit corpus gate; runtime input pins are selected outside the proof.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Run = @import("../block_v7_real_window_execution_v2.zig");
const Q = core.fields.qm31.QM31;
const Consumer = struct {
    pub const Result = struct { proof_count: usize, proof_bytes: usize, selection_bytes: usize, artifact_write_ns: u64, metadata_write_ns: u64 = 0 };
    pub fn consume(fixture: Run.Fixture) !Result {
        if (fixture.original.scope != .declared_window) return error.InvalidWindowProofScope;
        var timer = try std.time.Timer.start();
        const path = std.posix.getenv("STWO_REAL_WINDOW_V2_OUTPUT") orelse return error.MissingBenchmarkOutput;
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        var proofs: std.ArrayList(*const core.proof_suites.Blake3.Proof) = .empty;
        defer proofs.deinit(fixture.allocator);
        for (fixture.input.natives) |item| try proofs.append(fixture.allocator, &item.proof.stark);
        for (fixture.input.active_callers) |item| try proofs.append(fixture.allocator, &item.proof.stark);
        try proofs.appendSlice(fixture.allocator, &.{ &fixture.input.program.stark, &fixture.input.lookup.compact.proof.stark, &fixture.input.memory.window_joint.stark });
        var bytes: usize = 0;
        for (proofs.items, 0..) |proof, i| {
            var wire = std.Io.Writer.Allocating.init(fixture.allocator);
            defer wire.deinit();
            try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &wire.writer, proof.*);
            var name: [64]u8 = undefined;
            try dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "original-{d}.postcard", .{i}), .data = wire.written() });
            bytes = try std.math.add(usize, bytes, wire.written().len);
        }
        var selection_bytes: usize = 0;
        if (fixture.trusted.window.?.selection) |selected| {
            const selection = try std.json.Stringify.valueAlloc(fixture.allocator, .{
                .schema = "stwo-window-initialization-selection-v1",
                .authority = "Address selection only; values must be independently reconstructed from the externally pinned complete incoming snapshot and ELF.",
                .incoming_sha256 = std.fmt.bytesToHex(fixture.trusted.window.?.boundary.incoming_sha256, .lower),
                .addresses = selected.addresses,
            }, .{ .whitespace = .indent_2 });
            defer fixture.allocator.free(selection);
            try dir.writeFile(.{ .sub_path = "initialization-selection.json", .data = selection });
            selection_bytes = selection.len;
        }
        return .{ .proof_count = proofs.items.len, .proof_bytes = bytes, .selection_bytes = selection_bytes, .artifact_write_ns = timer.read() };
    }
};
const UnionProducer = @import("../block_v7_window_union_producer_v1.zig");
const UnionProof = @import("../block_v7_multi_union_proof_v1.zig").ForMode(true);
const UnionCodec = @import("../block_v7_multi_union_codec_v1.zig").ForMode(true);
const UnionConsumer = struct {
    pub const Result = *UnionProducer.Artifact;
    pub fn limits(memory: @import("../block_v7_window_memory_joint_v1.zig").Limits) UnionProof.Limits {
        return .{ .max_retained_pcs_bytes = 24 << 30, .max_windows = 8, .receiver = .{ .window_memory = memory } };
    }
    pub fn consumeStagedWindow(f: @import("../block_v7_streaming_execution_mode_v1.zig").ForMode(true).StagedWindowFixture) !Result {
        return UnionProducer.produce(f, .{
            .limits = limits(f.memory.limits),
            .proving = .{
                .recorder = f.recorder,
                .consume_memory_producer = true,
                .compact_storage_admission = true,
                .native_main_cache_bytes = try std.math.mul(usize, try number(usize, "STWO_REAL_WINDOW_V2_NATIVE_MAIN_CACHE_MIB", 256), 1 << 20),
                .deep_group_budget = try Engine.pcs.DeepGroupBudget.parseMiB(try number(u32, "STWO_REAL_WINDOW_V2_DEEP_GROUP_MIB", 1)),
            },
        });
    }
    pub fn discardStagedResult(value: Result) void {
        value.deinit();
    }
};
fn finishUnion(artifact: *UnionProducer.Artifact, output: std.fs.Dir) !Consumer.Result {
    var artifact_live = true;
    defer if (artifact_live) artifact.deinit();
    const a = artifact.allocator;
    const Metadata = @import("../block_v7_multi_union_statement_wire_v1.zig").ForMode(true);
    const memory = @import("block_v7_real_window_benchmark_resources.zig").memory(.resident);
    const wire_limits = UnionCodec.Limits{ .scope = UnionConsumer.limits(memory), .verification_bytes = 24 << 30 };
    var timer = try std.time.Timer.start();
    const metadata = try Metadata.encode(a, artifact.statement, .{});
    defer a.free(metadata);
    try output.writeFile(.{ .sub_path = "union-public.json", .data = metadata });
    const metadata_ns = timer.lap();
    const wire = try UnionCodec.encode(a, artifact.proof.view(), artifact.statement.input, wire_limits);
    defer a.free(wire);
    try output.writeFile(.{ .sub_path = "union.proof", .data = wire });
    const write_ns = timer.lap();
    // Preserve candidate bytes before any later loader failure. Qualification
    // is published only after independent verification, never file presence.
    const detached = try Metadata.decode(a, metadata, artifact.statement.trusted, .{});
    defer detached.deinit();
    const metadata_decode_ns = timer.lap();
    const stats = artifact.stats;
    artifact.deinit();
    artifact_live = false;
    const verified = try UnionCodec.verifyBytes(a, wire, detached.trusted, detached.input, wire_limits);
    if (verified.scope != .declared_window) return error.InvalidWindowProofScope;
    const verification_ns = timer.read();
    const detail = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-window-union-verification-v1",
        .scope = "one independently verified original shared STARK; no recursive root",
        .producer_proof_destroyed = true,
        .producer_metadata_destroyed = true,
        .metadata_transport_ns = metadata_ns + metadata_decode_ns,
        .metadata_decode_ns = metadata_decode_ns,
        .metadata_bytes = metadata.len,
        .metadata_sha256 = std.fmt.bytesToHex(Capture.sha(metadata), .lower),
        .verification_ns = verification_ns,
        .proof_bytes = wire.len,
        .proof_sha256 = std.fmt.bytesToHex(Capture.sha(wire), .lower),
        .verified = verified,
        .producer = stats,
    }, .{ .whitespace = .indent_2 });
    defer a.free(detail);
    try output.writeFile(.{ .sub_path = "union-verification.json", .data = detail });
    return .{ .proof_count = 1, .proof_bytes = wire.len, .selection_bytes = 0, .artifact_write_ns = write_ns, .metadata_write_ns = metadata_ns };
}
fn number(comptime T: type, key: [:0]const u8, fallback: T) !T {
    return if (std.posix.getenv(key)) |text| try std.fmt.parseInt(T, text, 10) else fallback;
}
fn nativeLayout() !@import("../block_v7_native_source_v1.zig").LayoutMode {
    const text = std.posix.getenv("STWO_REAL_WINDOW_V2_NATIVE_LAYOUT") orelse "canonical";
    if (std.mem.eql(u8, text, "canonical")) return .canonical_v1;
    if (std.mem.eql(u8, text, "degree-bounded-q2")) return .degree_bounded_q2_v1;
    return error.InvalidBenchmarkNativeLayout;
}
fn digest(key: [:0]const u8) !Capture.Digest {
    const text = std.posix.getenv(key) orelse return error.MissingBenchmarkPin;
    var out: Capture.Digest = undefined;
    if ((try std.fmt.hexToBytes(&out, text)).len != 32) return error.InvalidBenchmarkPin;
    return out;
}
fn saveProfile(a: std.mem.Allocator, dir: std.fs.Dir, recorder: *Engine.stage_profile.Recorder) !void {
    var profile = try recorder.snapshot(a);
    defer profile.deinit(a);
    const bytes = try std.json.Stringify.valueAlloc(a, profile, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = "native-stage-profile.json", .data = bytes });
}
const ReloadInput = struct {
    allocator: std.mem.Allocator,
    output: std.fs.Dir,
    elf: []const u8,
    elf_pin: Capture.Digest,
    incoming: Capture.Snapshot,
    outgoing: Capture.Snapshot,
    incoming_pin: Capture.Digest,
    outgoing_pin: Capture.Digest,
    window: Capture.Window,
    workers: usize,
    loading_ns: u64,
    whole: *std.time.Timer,
    budget: *Engine.host_budget_allocator.SharedHostBudget,
};
fn reloadSaved(f: ReloadInput) !void {
    const a = f.allocator;
    const Metadata = @import("../block_v7_multi_union_statement_wire_v1.zig").ForMode(true);
    const Loader = @import("../block_v7_window_union_loader_v1.zig");
    var timer = try std.time.Timer.start();
    var source = try std.fs.cwd().openDir(std.posix.getenv("STWO_REAL_WINDOW_V2_UNION_SOURCE") orelse return error.MissingUnionArtifactSource, .{});
    defer source.close();
    const metadata = try source.readFileAlloc(a, "union-public.json", 16 << 20);
    defer a.free(metadata);
    const proof = try source.readFileAlloc(a, "union.proof", 128 << 20);
    defer a.free(proof);
    const artifact_loading_ns = timer.lap();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const selected_layout = try nativeLayout();
    const wire_limits = UnionCodec.Limits{ .scope = UnionConsumer.limits(@import("block_v7_real_window_benchmark_resources.zig").memory(.resident)), .verification_bytes = 24 << 30 };
    const verified = try Loader.verify(a, proof, metadata, .{ .elf = f.elf, .incoming = f.incoming, .outgoing = f.outgoing, .trusted = .{ .elf_sha256 = f.elf_pin, .incoming_sha256 = f.incoming_pin, .outgoing_sha256 = f.outgoing_pin, .window = f.window }, .config = config }, .{ .wire = wire_limits });
    const verification_ns = timer.read();
    const parsing = try Engine.host_budget_allocator.SharedHostBudget.create(a, 128 << 20);
    defer parsing.destroy();
    const parsed = try std.json.parseFromSlice(Metadata.Data, parsing.allocator(), metadata, .{});
    defer parsed.deinit();
    for (parsed.value.natives) |native| if (native.layout_mode != selected_layout) return error.UnexpectedUnionNativeLayout;
    const report = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-real-window-shared-union-reload-v1",
        .scope = "fresh_verification_only_of_saved_shared_original",
        .verified = verified,
        .canonical_security = true,
        .complete_recursive_root = false,
        .query_count = 70,
        .pow_bits = 26,
        .ethereum_block = false,
        .skipped_prefix_proved = false,
        .window = f.window,
        .elf_sha256 = std.fmt.bytesToHex(f.elf_pin, .lower),
        .incoming_sha256 = std.fmt.bytesToHex(f.incoming_pin, .lower),
        .outgoing_sha256 = std.fmt.bytesToHex(f.outgoing_pin, .lower),
        .worker_count = f.workers,
        .native_layout_mode = @tagName(selected_layout),
        .sparse_window_initialization = parsed.value.selected_initial_addresses.len != 0,
        .source_loading_ns = f.loading_ns,
        .artifact_loading_ns = artifact_loading_ns,
        .verification_ns = verification_ns,
        .whole_request_ns = f.whole.read(),
        .charged_peak_bytes = f.budget.snapshot().peak_live_bytes,
        .proof_bytes = proof.len,
        .proof_sha256 = std.fmt.bytesToHex(Capture.sha(proof), .lower),
        .metadata_bytes = metadata.len,
        .metadata_sha256 = std.fmt.bytesToHex(Capture.sha(metadata), .lower),
        .producer_objects_present = false,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try f.output.writeFile(.{ .sub_path = "report.json", .data = report });
}
test "retained Ethereum new v7 window benchmark with independently admitted snapshots" {
    try runWithExecutor(null);
}
pub fn runWithExecutor(executor: ?*const Engine.pcs.QuotientExecutor) !void {
    return runSelected(.original, executor);
}
pub fn runUnion() !void {
    return runSelected(.shared, null);
}
pub fn runUnionRoot() !void {
    return runSelected(.shared_root, null);
}
pub fn runReload() !void {
    return runSelected(.reload, null);
}
const Mode = enum { original, shared, shared_root, reload };
fn runSelected(comptime mode: Mode, executor: ?*const Engine.pcs.QuotientExecutor) !void {
    const union_proof = mode == .shared or mode == .shared_root;
    const elf_path = std.posix.getenv("STWO_REAL_WINDOW_V2_ELF") orelse return error.SkipZigTest;
    var whole = try std.time.Timer.start();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, if (mode == .shared_root) 48 << 30 else 32 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(a, elf_path, 32 << 20);
    defer a.free(elf);
    const elf_pin = try digest("STWO_REAL_WINDOW_V2_ELF_SHA256");
    if (!std.meta.eql(Capture.sha(elf), elf_pin)) return error.UntrustedRealWindowSource;
    const incoming_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_REAL_WINDOW_V2_INCOMING") orelse return error.MissingBenchmarkSnapshot, 64 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_REAL_WINDOW_V2_OUTGOING") orelse return error.MissingBenchmarkSnapshot, 64 << 20);
    defer a.free(outgoing_bytes);
    const incoming_pin = try digest("STWO_REAL_WINDOW_V2_INCOMING_SHA256");
    const outgoing_pin = try digest("STWO_REAL_WINDOW_V2_OUTGOING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const loading_ns = whole.read();
    const workers = try number(usize, "STWO_REAL_WINDOW_V2_WORKERS", 4);
    if (workers == 0 or workers > Engine.work_pool.MAX_WORKERS) return error.InvalidBenchmarkWorkers;
    var recorder = Engine.stage_profile.Recorder.initWithOptions(a, "cpu", "retained-ethereum-window-native", .{ .capture_tasks = false });
    defer recorder.deinit();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const span: Capture.Window = .{ .skip_cycles = try number(u64, "STWO_REAL_WINDOW_V2_SKIP", 1), .cycles = try number(u32, "STWO_REAL_WINDOW_V2_CYCLES", 32768) };
    const output_path = std.posix.getenv("STWO_REAL_WINDOW_V2_OUTPUT") orelse return error.MissingBenchmarkOutput;
    var output = try std.fs.cwd().openDir(output_path, .{});
    defer output.close();
    if (mode == .reload) return reloadSaved(.{ .allocator = a, .output = output, .elf = elf, .elf_pin = elf_pin, .incoming = incoming, .outgoing = outgoing, .incoming_pin = incoming_pin, .outgoing_pin = outgoing_pin, .window = span, .workers = workers, .loading_ns = loading_ns, .whole = &whole, .budget = budget });
    errdefer saveProfile(a, output, &recorder) catch {};
    try output.makeDir("checkpoints");
    var checkpoint = try output.openDir("checkpoints", .{ .iterate = true });
    defer checkpoint.close();
    const segment_cycles = try number(u32, "STWO_REAL_WINDOW_V2_SEGMENT", 16384);
    const deep_group_mib = try number(u32, "STWO_REAL_WINDOW_V2_DEEP_GROUP_MIB", 1);
    const deep_group_budget = try Engine.pcs.DeepGroupBudget.parseMiB(deep_group_mib);
    const native_cache_mib = try number(usize, "STWO_REAL_WINDOW_V2_NATIVE_MAIN_CACHE_MIB", 256);
    const native_cache_bytes = try std.math.mul(usize, native_cache_mib, 1 << 20);
    if (native_cache_bytes > @import("../block_v7_shared_quotient_cache_v1.zig").MAX_RETAINED_BYTES) return error.InvalidBenchmarkNativeCache;
    const resident_memory = (try number(u1, "STWO_REAL_WINDOW_V2_RESIDENT_MEMORY", 0)) == 1;
    const resident_original_stages = (try number(u1, "STWO_REAL_WINDOW_V2_RESIDENT_ORIGINAL_STAGES", 0)) == 1;
    if (resident_original_stages and mode != .shared_root) return error.UnsupportedResidentOriginalBenchmarkMode;
    const memory_storage: @import("../block_v7_input_storage_v1.zig").Policy = if (resident_memory) .resident else .{ .coefficients = .{} };
    const result = try Run.run(budget, checkpoint, .{ .elf = elf, .elf_sha256 = elf_pin, .cycles = span.cycles, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG, .state = .{ .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = span } } }, .{ .quotient_executor = executor, .resident_original_stages = resident_original_stages, .segment_cycles = segment_cycles, .ram_component_planning = if (mode == .shared_root) @import("../block_v7_ram_component_planner_v1.zig").Policy{ .target_components = try number(u32, "STWO_REAL_WINDOW_V2_RAM_TARGET_COMPONENTS", 4) } else null, .native_layout_mode = try nativeLayout(), .sparse_window_initialization = (try number(u1, "STWO_REAL_WINDOW_V2_SPARSE_INITIALIZATION", 0)) == 1, .native_prove = .{ .fused_projection_rows = (try number(u1, "STWO_REAL_WINDOW_V2_FUSED_PROJECTION_ROWS", 0)) == 1, .recorder = &recorder, .native_main_cache_bytes = native_cache_bytes, .deep_group_budget = deep_group_budget }, .max_events = 1 << 24, .memory = @import("block_v7_real_window_benchmark_resources.zig").memory(memory_storage) }, &pool, if (union_proof) UnionConsumer else Consumer);
    const artifacts = if (mode == .shared_root) try @import("block_v7_union_root_benchmark.zig").finish(result.value, output) else if (union_proof) try finishUnion(result.value, output) else result.value;
    try saveProfile(a, output, &recorder);
    const report = try std.json.Stringify.valueAlloc(a, .{
        .schema = if (mode == .shared_root) "stwo-real-window-shared-union-root-v1" else if (union_proof) "stwo-real-window-shared-union-v1" else "stwo-real-window-new-v7-originals-v2",
        .scope = if (mode == .shared_root) "declared_nonterminal_window_to_shared_recursive_root" else if (union_proof) "declared_nonterminal_window_to_shared_original_stark" else "explicit externally admitted incoming and outgoing complete machine states; skipped prefix is not proved; original proofs independently verified; no recursive root from this gate",
        .complete_global_closure = true,
        .verified = true,
        .complete_recursive_root = mode == .shared_root,
        .canonical_security = true,
        .query_count = 70,
        .pow_bits = 26,
        .ethereum_block = false,
        .skipped_prefix_proved = false,
        .union_proof = union_proof,
        .ram_target_components = if (mode == .shared_root) try number(u32, "STWO_REAL_WINDOW_V2_RAM_TARGET_COMPONENTS", 4) else @as(u32, 0),
        .window = span,
        .segment_cycles = segment_cycles,
        .worker_count = workers,
        .native_main_cache_mib = native_cache_mib,
        .deep_group_mib = deep_group_mib,
        .resident_memory = resident_memory,
        .resident_original_stages = resident_original_stages,
        .native_layout_mode = @tagName(result.stats.native_layout_mode),
        .fused_projection_rows = (try number(u1, "STWO_REAL_WINDOW_V2_FUSED_PROJECTION_ROWS", 0)) == 1,
        .sparse_window_initialization = result.stats.initial_selected_addresses != 0,
        .native_stage_profile = "native-stage-profile.json",
        .stage_accounting = "native_proof_ns includes ordered native_segment roots; their children are inclusive nested stages and must not be added to parents. Native interaction generation outside core recorder remains in segment residual. Other families currently have aggregate original-proof times.",
        .elf_sha256 = std.fmt.bytesToHex(elf_pin, .lower),
        .incoming_sha256 = std.fmt.bytesToHex(incoming_pin, .lower),
        .outgoing_sha256 = std.fmt.bytesToHex(outgoing_pin, .lower),
        .source_loading_ns = loading_ns,
        .whole_request_ns = whole.read(),
        .charged_peak_including_detached_verification = budget.snapshot().peak_live_bytes,
        .stats = result.stats,
        .artifacts = artifacts,
        .logical_input_bytes = elf.len + incoming_bytes.len + outgoing_bytes.len,
        .physical_disk_bytes = @as(?u64, null),
        .host_budget_bytes = @as(u64, if (mode == .shared_root) 48 << 30 else 32 << 30),
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
    std.debug.print("V7_REAL_WINDOW_NEW cycles={d} proofs={d} whole_ns={d} peak={d} scope=declared_window verified=true\n", .{ span.cycles, artifacts.proof_count, result.stats.whole_ns, result.stats.charged_peak_bytes });
}
