//! New proof production from an explicitly pinned saved canonical original.
//! This is NOT a source-proving measurement or the verification-only reload.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Loader = @import("../block_v7_window_union_loader_v1.zig");
const Codec = @import("../block_v7_multi_union_codec_v1.zig").ForMode(true);
const Multi = @import("../block_v7_multi_union_proof_v1.zig").ForMode(true);
const Profile = @import("../../recursion/block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Pipeline = @import("../../recursion/block_v8_union_closed_pipeline_v1.zig");
fn variable(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingSavedUnionBenchmarkInput;
}
fn number(comptime T: type, name: [:0]const u8) !T {
    return std.fmt.parseInt(T, try variable(name), 10);
}
fn digest(name: [:0]const u8) ![32]u8 {
    const value = try variable(name);
    if (value.len != 64) return error.InvalidSavedUnionDigest;
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, value);
    return result;
}
fn read(a: std.mem.Allocator, path: [:0]const u8, maximum: usize, pin: [:0]const u8) ![]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(a, try variable(path), maximum);
    errdefer a.free(bytes);
    if (!std.meta.eql(Capture.sha(bytes), try digest(pin))) return error.UntrustedSavedUnionArtifact;
    return bytes;
}
test "retained Ethereum V8 saved original to in-proof closed root benchmark" {
    if (std.posix.getenv("STWO_V8_SAVED_ELF") == null) return error.SkipZigTest;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try read(a, "STWO_V8_SAVED_ELF", 32 << 20, "STWO_V8_SAVED_ELF_SHA256");
    defer a.free(elf);
    const elf_pin = Capture.sha(elf);
    const incoming_bytes = try std.fs.cwd().readFileAlloc(a, try variable("STWO_V8_SAVED_INCOMING"), 64 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try std.fs.cwd().readFileAlloc(a, try variable("STWO_V8_SAVED_OUTGOING"), 64 << 20);
    defer a.free(outgoing_bytes);
    const incoming_pin = try digest("STWO_V8_SAVED_INCOMING_SHA256");
    const outgoing_pin = try digest("STWO_V8_SAVED_OUTGOING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const source_loading_ns = phase.lap();
    const proof_bytes = try read(a, "STWO_V8_SAVED_SOURCE_PROOF", 128 << 20, "STWO_V8_SAVED_SOURCE_PROOF_SHA256");
    var proof_bytes_live = true;
    defer if (proof_bytes_live) a.free(proof_bytes);
    const proof_size = proof_bytes.len;
    const proof_pin = Capture.sha(proof_bytes);
    const metadata = try read(a, "STWO_V8_SAVED_METADATA", 16 << 20, "STWO_V8_SAVED_METADATA_SHA256");
    defer a.free(metadata);
    const artifact_loading_ns = phase.lap();
    const workers = try number(usize, "STWO_V8_SAVED_WORKERS");
    if (workers == 0 or workers > Engine.work_pool.MAX_WORKERS) return error.InvalidSavedUnionWorkers;
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var output = try std.fs.cwd().openDir(try variable("STWO_V8_SAVED_OUTPUT"), .{});
    defer output.close();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const external = Loader.External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = .{ .skip_cycles = try number(u64, "STWO_V8_SAVED_SKIP"), .cycles = try number(u32, "STWO_V8_SAVED_CYCLES") } }, .config = config };
    const original_limits = Multi.Limits{ .max_retained_pcs_bytes = 24 << 30, .max_windows = 8, .receiver = .{ .window_memory = @import("block_v7_real_window_benchmark_resources.zig").memory(.resident) } };
    const wire_limits = Codec.Limits{ .scope = original_limits, .decode_bytes = 1 << 30, .verification_bytes = 24 << 30 };
    const metadata_owner = try Loader.admitMetadata(a, metadata, external, .{ .wire = wire_limits });
    var metadata_live = true;
    defer if (metadata_live) metadata_owner.deinit();
    if (metadata_owner.input.callers.len != 0) return error.UnsupportedClosedUnionCaller;
    const native_count = metadata_owner.input.natives.len;
    const memory_components = metadata_owner.input.memory_geometry.len;
    const events = metadata_owner.input.memory_geometry[0].total_events;
    const changes = metadata_owner.trusted.window.?.changes.len;
    const metadata_admission_ns = phase.lap();
    var decoded = try Codec.decode(a, proof_bytes, metadata_owner.trusted, metadata_owner.input, wire_limits);
    var decoded_live = true;
    defer if (decoded_live) decoded.deinit();
    a.free(proof_bytes);
    proof_bytes_live = false;
    const original_decoding_ns = phase.lap();
    var capture = try Multi.verifyViewAndCapture(a, metadata_owner.trusted, metadata_owner.input, &decoded.proof, original_limits);
    var capture_live = true;
    defer if (capture_live) capture.deinit();
    decoded.deinit();
    decoded_live = false;
    const original_verification_ns = phase.lap();
    const profile = try Profile.Owned.derive(a, metadata_owner, &capture.claims, .{ .original = original_limits });
    var profile_live = true;
    defer if (profile_live) profile.deinit();
    const profile_admission_ns = phase.lap();
    const limits = Pipeline.Limits{ .fixed = .{ .max_bytes = 16 << 30 }, .preparation = .{ .max_bytes = 16 << 30 } };
    var root = try Pipeline.produce(a, profile, &capture, limits);
    defer root.deinit();
    const recursive_production_ns = phase.lap();
    profile.deinit();
    profile_live = false;
    capture.deinit();
    capture_live = false;
    metadata_owner.deinit();
    metadata_live = false;
    const producer_release_ns = phase.lap();
    try output.writeFile(.{ .sub_path = "root.proof", .data = root.bytes });
    try output.writeFile(.{ .sub_path = "union.claims", .data = root.claims });
    const artifact_write_ns = phase.lap();
    const fresh_metadata = try Loader.admitMetadata(a, metadata, external, .{ .wire = wire_limits });
    defer fresh_metadata.deinit();
    const fresh_metadata_admission_ns = phase.lap();
    var verified = try Pipeline.verify(a, root.bytes, root.claims, fresh_metadata, original_limits, limits);
    defer verified.deinit();
    const fresh_recursive_verification_ns = phase.lap();
    const report = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-v8-saved-original-closed-root-v1",
        .scope = "saved_canonical_original_to_in_proof_closed_declared_window_root",
        .verified = true,
        .canonical_security = true,
        .query_count = 70,
        .pow_bits = 26,
        .closure_in_proof = true,
        .host_global_closure_used_by_root_receiver = false,
        .source_original_fresh_verified = true,
        .source_proving_performed = false,
        .source_stark_count = 1,
        .recursive_stark_count = 1,
        .ethereum_block = false,
        .skipped_prefix_proved = false,
        .terminal = false,
        .original_proof_objects_destroyed = true,
        .original_capture_destroyed = true,
        .producer_parent_rows_destroyed = true,
        .fresh_metadata_independently_reconstructed = true,
        .window = external.trusted.window,
        .worker_count = workers,
        .native_segments = native_count,
        .callers = 0,
        .ram_components = memory_components,
        .logical_ram_events = events,
        .snapshot_changes = changes,
        .source_loading_ns = source_loading_ns,
        .artifact_loading_ns = artifact_loading_ns,
        .metadata_admission_ns = metadata_admission_ns,
        .original_decoding_ns = original_decoding_ns,
        .original_verification_ns = original_verification_ns,
        .profile_admission_ns = profile_admission_ns,
        .recursive_production_ns = recursive_production_ns,
        .recursive = root.stats,
        .producer_release_ns = producer_release_ns,
        .artifact_write_ns = artifact_write_ns,
        .fresh_metadata_admission_ns = fresh_metadata_admission_ns,
        .fresh_recursive_verification_ns = fresh_recursive_verification_ns,
        .whole_request_ns = whole.read(),
        .charged_peak_bytes = budget.snapshot().peak_live_bytes,
        .elf_sha256 = std.fmt.bytesToHex(elf_pin, .lower),
        .incoming_sha256 = std.fmt.bytesToHex(incoming_pin, .lower),
        .outgoing_sha256 = std.fmt.bytesToHex(outgoing_pin, .lower),
        .source_proof_bytes = proof_size,
        .source_proof_sha256 = std.fmt.bytesToHex(proof_pin, .lower),
        .metadata_bytes = metadata.len,
        .metadata_sha256 = std.fmt.bytesToHex(Capture.sha(metadata), .lower),
        .root_bytes = root.bytes.len,
        .root_sha256 = std.fmt.bytesToHex(Capture.sha(root.bytes), .lower),
        .claims_bytes = root.claims.len,
        .claims_sha256 = std.fmt.bytesToHex(Capture.sha(root.claims), .lower),
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
    std.debug.print("V8_SAVED_ORIGINAL_CLOSED_ROOT verified=true whole_ns={d} recursive_proof_ns={d} peak_bytes={d}\n", .{ whole.read(), root.stats.proof_ns, budget.snapshot().peak_live_bytes });
}
