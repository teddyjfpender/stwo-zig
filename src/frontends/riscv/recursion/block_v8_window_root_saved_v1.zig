const std = @import("std");
const core = @import("stwo_core");
const Window = @import("../prover/block_v7_real_window_policy_v2.zig");
const Directory = @import("../prover/block_v8_endpoint_local_directory_v1.zig");
const Transport = @import("../prover/block_v8_endpoint_local_transport_v1.zig");
const Metadata = @import("../prover/block_v8_endpoint_local_statement_wire_v1.zig");
const Codec = @import("../prover/block_v8_endpoint_local_codec_v1.zig");
const Scope = @import("../prover/block_v8_endpoint_local_scope_v1.zig");
const BridgeScope = @import("../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const L = @import("block_v8_endpoint_recursive_adapter_v1.zig").For(.local_open);
const B = @import("block_v8_endpoint_bridge_recursive_v1.zig");
const G = @import("block_v8_compact_ram_recursive_v1.zig");
const Source = @import("block_v8_endpoint_join_source_v1.zig");
const Pipeline = @import("block_v8_endpoint_join_pipeline_v1.zig");
const Receiver = @import("block_v8_endpoint_join_many_receiver_v1.zig");

pub const Result = struct {
    allocator: std.mem.Allocator,
    public_arena: *std.heap.ArenaAllocator,
    root: Pipeline.Artifact,
    metadata: @import("block_v8_window_root_receiver_v1.zig").Tree,
    pub fn deinit(v: *Result) void {
        v.root.deinit();
        v.public_arena.deinit();
        v.allocator.destroy(v.public_arena);
    }
};
/// Durable original files -> one exact window root. Every original body is
/// captured once; every producer/proof/capture is gone when this returns.
pub fn produce(a: std.mem.Allocator, directory: std.fs.Dir, external: Receiver.External) !Result {
    const config = external.config;
    const elf = external.elf;
    const incoming = external.incoming;
    const outgoing = external.outgoing;
    var phase = try std.time.Timer.start();
    const global_json = try directory.readFileAlloc(a, "global-public.json", 128 << 20);
    defer a.free(global_json);
    var parsed = try std.json.parseFromSlice(Directory.Data(true), a, global_json, .{});
    defer parsed.deinit();
    const data = parsed.value;
    const n = data.cohort_count;
    if (n == 0 or n > 62 or data.bridge_batches != 1 or n != data.cohort_policy.cohort_count or !std.meta.eql(data.window, external.trusted.window) or !std.meta.eql(data.config, config)) return error.InvalidSavedJoinRoster;
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, elf, incoming, outgoing, external.trusted, data.cohort_policy, data.selected_initial_addresses, external.boundary, .{});
    defer window.deinit();
    const extra = Receiver.boundaryBytes(&window);
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
    const provider = Directory.Provider{ .directory = directory, .config = config, .cohorts = n, .local_metadata_bytes = 16 << 20, .local_proof_bytes = 128 << 20, .transport = .{} };
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
        sources[i] = .{ .local = try L.Profile.Owned.derive(a, metadata, decoded.claims, .{}) };
        source_count += 1;
        caps[i] = .{ .local = &local_captures[i] };
        proposed[i] = sources[i].local.claims;
        const source = sources[i].local.scope.source();
        pins[i] = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
        events = try std.math.add(u32, events, source.endpoint_count);
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
    sources[n] = .{ .bridge = try B.Profile.Owned.derive(a, bridge_metadata, bridge.proof.claims, .{}) };
    source_count += 1;
    caps[n] = .{ .bridge = &bridge_capture };
    const global_bytes = try directory.readFileAlloc(a, "global-memory.proof", 128 << 20);
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
    sources[n + 1] = .{ .global = try G.Profile.Owned.derive(a, global_metadata, decoded_global.claims, .{}) };
    source_count += 1;
    caps[n + 1] = .{ .global = &global_capture };

    var writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
    defer writer.deinit();
    var remaining: usize = 1 << 20;
    try @import("../prover/block_v7_union_claim_wire_v1.zig").encode(Receiver.Claims, &writer, .{ .locals = proposed, .bridge = bridge.proof.claims, .global = decoded_global.claims }, &remaining);
    bridge.deinit();
    bridge_live = false;
    decoded_global.deinit();
    decoded_global_live = false;
    var root = try Pipeline.produceWithOptions(a, sources, caps, &extra, .csp_q70_pow26, .{ .source_workers = 1, .global_g_repartition = true });
    errdefer root.deinit();
    for (local_captures[0..cap_count]) |*capture| capture.deinit();
    captures_live = false;
    bridge_capture.deinit();
    bridge_cap_live = false;
    global_capture.deinit();
    global_cap_live = false;
    for (sources[0..source_count]) |source| Source.deinitProfile(source);
    source_count = 0;
    var fresh = try Receiver.verify(a, external, .{ .root = root.bytes, .physical_claims = writer.bytes.items, .local_metadata = metas, .global_roots = data.memory_roots, .cohort_policy = data.cohort_policy, .selected_addresses = data.selected_initial_addresses, .global_g_repartition = true });
    defer fresh.deinit();
    const public_arena = try a.create(std.heap.ArenaAllocator);
    errdefer a.destroy(public_arena);
    public_arena.* = std.heap.ArenaAllocator.init(a);
    errdefer public_arena.deinit();
    const public = public_arena.allocator();
    const metadata_bytes = try public.alloc([]const u8, metas.len);
    for (metadata_bytes, metas) |*dest, bytes| dest.* = try public.dupe(u8, bytes);
    const metadata = @import("block_v8_window_root_receiver_v1.zig").Tree{ .leaf = .{ .external = external, .input = .{ .main_root = fresh.capture.commitments[1], .physical_claims = try public.dupe(u8, writer.bytes.items), .local_metadata = metadata_bytes, .global_roots = data.memory_roots, .cohort_policy = data.cohort_policy, .selected_addresses = try public.dupe(u32, data.selected_initial_addresses), .global_g_repartition = true } } };
    return .{ .allocator = a, .public_arena = public_arena, .root = root, .metadata = metadata };
}
