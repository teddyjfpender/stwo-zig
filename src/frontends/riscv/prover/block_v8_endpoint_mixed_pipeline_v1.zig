//! Real mixed execution -> durable original/bridge/global-memory bundle.
//! The wide witness is built and proved once. Only its exact endpoint tree
//! and narrow endpoint rows survive into the late memory argument. A fresh
//! directory receiver closes every original after all producers are gone.
//! This module does not label an original bundle a recursive or block proof.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("block_v8_endpoint_mixed_execution_v1.zig");
const Original = @import("block_v8_endpoint_mixed_proof_v1.zig");
const Codec = @import("block_v8_endpoint_mixed_codec_v1.zig");
const Metadata = @import("block_v8_endpoint_mixed_statement_wire_v1.zig");
const Bundle = @import("block_v8_endpoint_local_bundle_v1.zig");
const Directory = @import("block_v8_endpoint_local_directory_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
const Bridge = @import("block_v8_endpoint_global_bridge_proof_v1.zig");
const BridgeScope = @import("block_v8_endpoint_global_bridge_scope_v1.zig");
pub const production_active = false;
pub const Options = struct {
    source: Source.Options = .{},
    original: Original.Limits = .{},
    original_options: Original.Options = .{},
    metadata: Metadata.Limits = .{},
    codec: Codec.Limits = .{},
    compact: Compact.Limits = .{},
    bridge: Bridge.Limits = .{},
    initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
    receiver: Directory.For(true).Limits = .{},
    artifact_bytes: usize = 128 << 20,
};
pub const Stats = struct {
    preparation_ns: u64 = 0,
    original_ns: u64 = 0,
    source_publication_ns: u64 = 0,
    wide_release_ns: u64 = 0,
    memory_preparation_ns: u64 = 0,
    bridge_ns: u64 = 0,
    narrow_release_ns: u64 = 0,
    global_memory_ns: u64 = 0,
    global_publication_ns: u64 = 0,
    fresh_verification_ns: u64 = 0,
    whole_ns: u64 = 0,
    preparation: Source.Stats = .{},
    original: Original.Timings = .{},
};
pub const Result = struct { verified: Bundle.Summary, stats: Stats };

/// Empty output directories are required: interrupted attempts are evidence,
/// never a pool of silently reusable proofs from a different request.
pub fn produceDirectory(a: std.mem.Allocator, request: Source.Request, directory: std.fs.Dir, options: Options) !Result {
    var iterator = directory.iterate();
    if (try iterator.next() != null) return error.NonemptyMixedPipelineDirectory;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var stats: Stats = .{};
    const source = try Source.Owned.init(a, request, options.source);
    var source_live = true;
    defer if (source_live) source.deinit();
    stats.preparation = source.stats;
    stats.preparation_ns = phase.lap();
    var proof_options = options.original_options;
    proof_options.retain_endpoint = true;
    proof_options.program = &source.image.?;
    proof_options.timings = &stats.original;
    const original = try Original.produceWithOptions(a, source.trusted, source.input(), source.current.?.owner.preprocessed.items, source.stages(), options.original, proof_options);
    var original_live = true;
    defer if (original_live) original.deinit();
    stats.original_ns = phase.lap();
    var input = source.input();
    input.native_roots = original.native_roots;
    input.caller_roots = original.caller_roots;
    const metadata = try Metadata.encode(a, source.trusted, input, options.metadata);
    defer a.free(metadata);
    const encoded = try Codec.encode(a, original, source.trusted, input, options.codec);
    defer a.free(encoded);
    try directory.writeFile(.{ .sub_path = "local-0.json", .data = metadata });
    try directory.writeFile(.{ .sub_path = "local-0.proof", .data = encoded });
    const checked_source = original.summary.source;
    var endpoints = source.endpoints.?;
    source.endpoints = null;
    var endpoints_live = true;
    defer if (endpoints_live) endpoints.deinit();
    const lease = original.endpoint_lease orelse return error.MissingMixedPipelineEndpointLease;
    original.endpoint_lease = null;
    var lease_live = true;
    defer if (lease_live) lease.deinit();
    if (!std.meta.eql(checked_source.endpoint_root, lease.tree.root())) return error.MixedPipelineEndpointMismatch;
    stats.source_publication_ns = phase.lap();
    original.deinit();
    original_live = false;
    source.deinit();
    source_live = false;
    stats.wide_release_ns = phase.lap();

    const addresses = try a.alloc(u32, endpoints.endpoints.len);
    defer a.free(addresses);
    for (addresses, endpoints.endpoints) |*address, endpoint| address.* = endpoint.address;
    const external = Bundle.External{ .elf = request.elf, .incoming = request.incoming, .outgoing = request.outgoing, .trusted = request.trusted_window, .config = request.config, .boundary = options.source.boundary };
    const cohorts = Window.CohortPolicy{ .cohort_count = 1, .max_cohort_cycles = request.trusted_window.window.cycles };
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, request.elf, request.incoming, request.outgoing, request.trusted_window, cohorts, addresses, options.source.boundary, options.initial);
    defer window.deinit();
    const policy = Compact.Policy{ .window = &window, .config = request.config, .event_count = @intCast(endpoints.endpoints.len) };
    const stage = try Compact.Stage.init(a, policy, endpoints.net_transitions, options.compact);
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    const bridge_source = BridgeScope.Source{ .local_identity = checked_source.local_identity, .local_epoch = checked_source.local_epoch, .endpoint_root = checked_source.endpoint_root, .endpoint_count = checked_source.endpoint_count, .policy = checked_source.policy };
    var global = try BridgeScope.Owned.init(a, try policy.digest(), request.config, &.{bridge_source}, try stage.entry());
    var global_live = true;
    defer if (global_live) global.deinit();
    stats.memory_preparation_ns = phase.lap();
    var bridge = try Bridge.produceConditional(a, global, &.{.{ .endpoints = endpoints.matrix, .tree = &lease.tree, .tree_allocator = a }}, options.bridge);
    var bridge_live = true;
    defer if (bridge_live) bridge.deinit();
    stats.bridge_ns = phase.lap();
    endpoints.deinit();
    endpoints_live = false;
    lease.deinit();
    lease_live = false;
    stats.narrow_release_ns = phase.lap();
    var memory = try stage.proveConditional(global.epoch, global.entries);
    var memory_live = true;
    defer if (memory_live) memory.deinit();
    stage.deinit();
    stage_live = false;
    stats.global_memory_ns = phase.lap();
    try writeOriginal(a, directory, "bridge-0.proof", "B8GBR001", bridge.stark, bridge.claims, options.artifact_bytes);
    try writeOriginal(a, directory, "global-memory.proof", "B8CMR001", memory.stark, memory.claims, options.artifact_bytes);
    const global_metadata = try std.json.Stringify.valueAlloc(a, Directory.Data(true){
        .schema = "stwo-b8-local-compact-global-memory-metadata-v1",
        .authority = "Fresh original, bridge and global proof verification; ELF and snapshot identities are external policy",
        .global_argument = "compact_endpoint",
        .elf_sha256 = &std.fmt.bytesToHex(request.elf_sha256, .lower),
        .incoming_sha256 = &std.fmt.bytesToHex(request.incoming.identity(), .lower),
        .outgoing_sha256 = &std.fmt.bytesToHex(request.outgoing.identity(), .lower),
        .window = request.trusted_window.window,
        .cohort_policy = cohorts,
        .cohort_count = 1,
        .bridge_batches = 1,
        .endpoint_events = policy.event_count,
        .config = request.config,
        .selected_initial_addresses = window.selection.?.addresses,
        .memory_roots = memory.roots,
        .memory_interval_log = null,
        .compact_ram_log = policy.ramLog(),
        .compact_boundary_log = policy.boundaryLog(),
        .global_epoch = global.epoch.digest,
    }, .{});
    defer a.free(global_metadata);
    try directory.writeFile(.{ .sub_path = "global-public.json", .data = global_metadata });
    bridge.deinit();
    bridge_live = false;
    memory.deinit();
    memory_live = false;
    global.deinit();
    global_live = false;
    stats.global_publication_ns = phase.lap();
    const verified = try Directory.verifyDirectoryCompact(a, directory, external, .{ .endpoint_events_nomination = policy.event_count }, options.receiver);
    stats.fresh_verification_ns = phase.lap();
    stats.whole_ns = whole.read();
    return .{ .verified = verified, .stats = stats };
}

fn writeOriginal(a: std.mem.Allocator, directory: std.fs.Dir, name: []const u8, magic: *const [8]u8, stark: core.proof_suites.Blake3.Proof, claims: anytype, maximum: usize) !void {
    var writer = @import("bounded_artifact_writer_v1.zig").Writer.init(a, maximum);
    defer writer.deinit();
    try writer.writeAll(magic);
    const Wire = @import("block_v7_union_claim_wire_v1.zig");
    try writer.writeAll(&Wire.schemaId(@TypeOf(claims)));
    var items: usize = 1 << 20;
    try Wire.encode(@TypeOf(claims), &writer, claims, &items);
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &writer, stark);
    try directory.writeFile(.{ .sub_path = name, .data = writer.bytes.items });
}
