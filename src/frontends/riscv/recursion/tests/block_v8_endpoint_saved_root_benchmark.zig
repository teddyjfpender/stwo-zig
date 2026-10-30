//! Explicitly pinned saved NEW B8 endpoint original -> one closed recursive
//! root. Source proving never runs here. Original capture happens exactly once;
//! the original envelope, decoded proof, capture and producer metadata are all
//! destroyed before independently admitted metadata verifies the new root.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Loader = @import("../../prover/block_v8_endpoint_whole_loader_v1.zig");
const Codec = @import("../../prover/block_v8_endpoint_whole_codec_v1.zig");
const Whole = @import("../../prover/block_v8_endpoint_whole_proof_v1.zig");
const Profile = @import("../block_v8_endpoint_original_profile_v1.zig");
const Pipeline = @import("../block_v8_endpoint_pipeline_v1.zig");
const SourceReport = @import("../block_v8_endpoint_root_source_report_v1.zig");
fn variable(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingSavedEndpointBenchmarkInput;
}
fn number(comptime T: type, name: [:0]const u8) !T {
    return std.fmt.parseInt(T, try variable(name), 10);
}
fn optionalNumber(comptime T: type, name: [:0]const u8, default: T) !T {
    return if (std.posix.getenv(name)) |text| try std.fmt.parseInt(T, text, 10) else default;
}
fn digest(name: [:0]const u8) ![32]u8 {
    const value = try variable(name);
    if (value.len != 64) return error.InvalidSavedEndpointDigest;
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, value);
    return result;
}
fn read(a: std.mem.Allocator, path: [:0]const u8, maximum: usize, pin: [:0]const u8) ![]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(a, try variable(path), maximum);
    errdefer a.free(bytes);
    if (!std.meta.eql(Capture.sha(bytes), try digest(pin))) return error.UntrustedSavedEndpointArtifact;
    return bytes;
}
fn json(a: std.mem.Allocator, output: std.fs.Dir, path: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try output.writeFile(.{ .sub_path = path, .data = bytes });
}
fn requireFresh(output: std.fs.Dir) !void {
    const existing = output.openFile("root.proof", .{}) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    existing.close();
    return error.SavedEndpointOutputAlreadyContainsRoot;
}
test "saved new B8 endpoint original to closed recursive root benchmark" {
    if (std.posix.getenv("STWO_B8_ENDPOINT_SAVED_ELF") == null) return error.SkipZigTest;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, try optionalNumber(usize, "STWO_B8_ENDPOINT_SAVED_BUDGET_BYTES", 48 << 30));
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try read(a, "STWO_B8_ENDPOINT_SAVED_ELF", 32 << 20, "STWO_B8_ENDPOINT_SAVED_ELF_SHA256");
    defer a.free(elf);
    const elf_pin = Capture.sha(elf);
    const incoming_bytes = try std.fs.cwd().readFileAlloc(a, try variable("STWO_B8_ENDPOINT_SAVED_INCOMING"), 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try std.fs.cwd().readFileAlloc(a, try variable("STWO_B8_ENDPOINT_SAVED_OUTGOING"), 256 << 20);
    defer a.free(outgoing_bytes);
    const incoming_pin = try digest("STWO_B8_ENDPOINT_SAVED_INCOMING_SHA256");
    const outgoing_pin = try digest("STWO_B8_ENDPOINT_SAVED_OUTGOING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const source_loading_ns = phase.lap();
    const proof_bytes = try read(a, "STWO_B8_ENDPOINT_SAVED_SOURCE_PROOF", 128 << 20, "STWO_B8_ENDPOINT_SAVED_SOURCE_PROOF_SHA256");
    var proof_bytes_live = true;
    defer if (proof_bytes_live) a.free(proof_bytes);
    const proof_size = proof_bytes.len;
    const proof_pin = Capture.sha(proof_bytes);
    const metadata = try read(a, "STWO_B8_ENDPOINT_SAVED_METADATA", 16 << 20, "STWO_B8_ENDPOINT_SAVED_METADATA_SHA256");
    defer a.free(metadata);
    const artifact_loading_ns = phase.lap();
    const workers = try number(usize, "STWO_B8_ENDPOINT_SAVED_WORKERS");
    if (workers == 0 or workers > Engine.work_pool.MAX_WORKERS) return error.InvalidSavedEndpointWorkers;
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var output = try std.fs.cwd().openDir(try variable("STWO_B8_ENDPOINT_SAVED_OUTPUT"), .{});
    defer output.close();
    try requireFresh(output);
    const config = @import("../blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const external = Loader.External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = .{ .skip_cycles = try number(u64, "STWO_B8_ENDPOINT_SAVED_SKIP"), .cycles = try number(u32, "STWO_B8_ENDPOINT_SAVED_CYCLES") } }, .config = config };
    const original_limits = (@import("../../prover/block_v8_endpoint_execution_v1.zig").Options{}).proof;
    const wire_limits = Codec.Limits{ .original = original_limits, .decode_bytes = 1 << 30, .verification_bytes = 24 << 30 };
    const metadata_owner = try Loader.admitMetadata(a, metadata, external, .{});
    var metadata_live = true;
    defer if (metadata_live) metadata_owner.deinit();
    const metadata_admission_ns = phase.lap();
    var decoded = try Codec.decode(a, proof_bytes, metadata_owner.trusted, metadata_owner.input, wire_limits);
    var decoded_live = true;
    defer if (decoded_live) decoded.deinit();
    a.free(proof_bytes);
    proof_bytes_live = false;
    const original_decoding_ns = phase.lap();
    var capture = try Whole.verifyAndCapture(a, metadata_owner.trusted, metadata_owner.input, &decoded.stark, decoded.claims, original_limits);
    var capture_live = true;
    defer if (capture_live) capture.deinit();
    const original_verification_ns = phase.lap();
    const original_profile_limits = Profile.Limits{ .original = original_limits };
    // Whole capture deliberately owns no physical claims. Independent profile
    // admission clones them before the decoded original is destroyed.
    const profile = try Profile.Owned.derive(a, metadata_owner, decoded.claims, original_profile_limits);
    var profile_live = true;
    defer if (profile_live) profile.deinit();
    const profile_admission_ns = phase.lap();
    const source = try SourceReport.derive(profile);
    const source_manifest = SourceReport.manifest();
    try json(a, output, "source-report.json", source);
    try json(a, output, "source-exact-manifest.json", source_manifest);
    const source_report_ns = phase.lap();
    decoded.deinit();
    decoded_live = false;
    const original_objects_release_ns = phase.lap();
    std.debug.print("B8_ENDPOINT_SAVED_ROOT_SOURCE cycles={d} endpoints={d} logical_ram={d} raw_cells={d} lde_cells={d} public_ports={d} snapshot_delta_byte_ports={d} source_capture_count=1\n", .{ external.trusted.window.cycles, source.endpoint_count, source.logical_ram_accesses, source.total_raw_cells, source.total_extended_cells, source.total_public_operands, source.snapshot_delta_public_byte_ports });
    const parent_budget = try optionalNumber(usize, "STWO_B8_ENDPOINT_SAVED_PARENT_BUDGET_BYTES", 24 << 30);
    const public_wires = try optionalNumber(usize, "STWO_B8_ENDPOINT_SAVED_MAX_PUBLIC_WIRES", 1 << 24);
    const limits = Pipeline.Limits{ .fixed = .{ .max_bytes = parent_budget, .max_public_wires = public_wires }, .preparation = .{ .max_bytes = parent_budget, .max_public_wires = public_wires } };
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
    try output.writeFile(.{ .sub_path = "physical-claims.bin", .data = root.claims });
    try output.writeFile(.{ .sub_path = "public-metadata.json", .data = metadata });
    const artifact_write_ns = phase.lap();
    const fresh_metadata = try Loader.admitMetadata(a, metadata, external, .{});
    defer fresh_metadata.deinit();
    const fresh_metadata_admission_ns = phase.lap();
    var verified = try Pipeline.verify(a, root.bytes, root.claims, fresh_metadata, original_profile_limits, limits);
    defer verified.deinit();
    const fresh_recursive_verification_ns = phase.lap();
    try json(a, output, "report.json", .{
        .schema = "stwo-b8-endpoint-saved-original-closed-root-v1",
        .scope = "saved_canonical_new_endpoint_original_to_closed_declared_nonterminal_window_root",
        .prototype_snapshot_delta_boundary = true,
        .compact_late_global_bridge = false,
        .verified = true,
        .query_count = config.fri_config.n_queries,
        .pow_bits = config.pow_bits,
        .layout_version = @import("../../prover/block_v8_native_endpoint_layout_v1.zig").VERSION,
        .closure_in_proof = true,
        .host_global_closure_used_by_root_receiver = false,
        .source_original_fresh_verified = true,
        .source_capture_count = 1,
        .source_proving_performed = false,
        .source_stark_count = 1,
        .recursive_stark_count = 1,
        .ethereum_block = false,
        .skipped_prefix_proved = false,
        .terminal = false,
        .original_envelope_destroyed = true,
        .original_proof_objects_destroyed = true,
        .original_capture_destroyed = true,
        .producer_parent_rows_destroyed = true,
        .fresh_metadata_independently_reconstructed = true,
        .window = external.trusted.window,
        .worker_count = workers,
        .source_geometry = source,
        .embedded_frontend_source_digest = source_manifest.digest,
        .source_loading_ns = source_loading_ns,
        .artifact_loading_ns = artifact_loading_ns,
        .metadata_admission_ns = metadata_admission_ns,
        .original_decoding_ns = original_decoding_ns,
        .original_verification_ns = original_verification_ns,
        .profile_admission_ns = profile_admission_ns,
        .source_report_ns = source_report_ns,
        .original_objects_release_ns = original_objects_release_ns,
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
    });
    std.debug.print("B8_ENDPOINT_SAVED_ORIGINAL_CLOSED_ROOT verified=true whole_ns={d} recursive_proof_ns={d} peak_bytes={d}\n", .{ whole.read(), root.stats.proof_ns, budget.snapshot().peak_live_bytes });
}
