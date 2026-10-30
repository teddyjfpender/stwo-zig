//! One bounded native Group -> same endpoint roots -> late bridge -> compact
//! global memory. The final receiver reads ONLY files and external pins, and
//! verifies the Group original once. No legacy WORD or companion source proof.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Source = @import("block_v8_endpoint_group_execution_v1.zig");
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Collector = @import("block_v8_ram_endpoint_collector_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const BridgeScope = @import("block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("block_v8_endpoint_global_bridge_proof_v1.zig");
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
const Directory = @import("block_v8_endpoint_group_directory_v1.zig");
const OriginalWriter = @import("block_v8_endpoint_original_writer_v1.zig");
pub const production_active = false;
pub const Options = struct {
    source: Source.Options = .{},
    memory: Compact.Limits = .{},
    bridge: Bridge.Limits = .{},
    directory: Directory.Limits = .{},
    max_artifact_bytes: usize = 128 << 20,
};
pub const Stats = struct {
    source: Source.Stats = .{},
    source_call_ns: u64 = 0,
    global_prepare_ns: u64 = 0,
    bridge_ns: u64 = 0,
    global_proof_ns: u64 = 0,
    artifact_ns: u64 = 0,
    producer_release_ns: u64 = 0,
    fresh_bundle_ns: u64 = 0,
    whole_ns: u64 = 0,
    charged_peak_bytes: usize = 0,
};
pub const Result = struct { stats: Stats, verified: @import("block_v8_endpoint_group_bundle_v1.zig").Summary };
pub fn run(budget: *E.host_budget_allocator.SharedHostBudget, pool: *E.work_pool.WorkPool, directory: std.fs.Dir, request: Source.Request, options: Options) !Result {
    if (options.max_artifact_bytes == 0) return error.InvalidGroupPipelineLimits;
    var entries = directory.iterate();
    if (try entries.next() != null) return error.NonemptyEndpointGroupDirectory;
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    var stats: Stats = .{};
    // No source STARK verification here: conditional generation nominates its
    // sources. The independent file receiver below supplies proof authority.
    const source = try Source.runUnchecked(budget, pool, request, options.source);
    var source_live = true;
    defer if (source_live) source.deinit();
    stats.source = source.stats;
    stats.source_call_ns = timer.lap();
    var binding = try E.work_pool.ScopedPoolBinding.init(pool);
    defer binding.deinit();
    try directory.writeFile(.{ .sub_path = "group-0.proof", .data = source.proof_bytes });
    try directory.writeFile(.{ .sub_path = "group-0.json", .data = source.metadata_bytes });
    var net: std.ArrayList(Collector.Transition) = .empty;
    defer net.deinit(a);
    for (source.endpoints) |ep| try net.appendSlice(a, ep.net_transitions);
    const Ordering = struct {
        fn less(_: void, l: Collector.Transition, r: Collector.Transition) bool {
            return if (l.address != r.address) l.address < r.address else l.clock < r.clock;
        }
    };
    std.mem.sort(Collector.Transition, net.items, {}, Ordering.less);
    var addresses: std.ArrayList(u32) = .empty;
    defer addresses.deinit(a);
    for (net.items) |event| if (addresses.items.len == 0 or addresses.items[addresses.items.len - 1] != event.address) try addresses.append(a, event.address);
    const count: u32 = @intCast(source.endpoints.len);
    const cohort_policy = Window.CohortPolicy{ .cohort_count = count, .max_cohort_cycles = options.source.cohort_cycles };
    var window = try Window.Owned.deriveCohortsForAddresses(a, request.elf, request.incoming, request.outgoing, request.trusted_window, cohort_policy, addresses.items, options.source.initial);
    var window_live = true;
    defer if (window_live) window.deinit();
    const policy = Compact.Policy{ .window = &window, .config = request.config, .event_count = @intCast(net.items.len) };
    const memory = try Compact.Stage.init(a, policy, net.items, options.memory);
    var memory_live = true;
    defer if (memory_live) memory.deinit();
    net.deinit(a);
    net = .empty;
    const nomination = try Scope.Owned.init(a, source.statement.trusted, source.statement.input, options.source.proof.scope);
    var nomination_live = true;
    defer if (nomination_live) nomination.deinit();
    const sources = try a.alloc(BridgeScope.Source, count);
    defer a.free(sources);
    for (sources, nomination.sources) |*out, member| out.* = .{ .local_identity = member.local_identity, .local_epoch = member.local_epoch, .endpoint_root = member.endpoint_root, .endpoint_count = member.endpoint_count, .policy = member.policy };
    var global = try BridgeScope.Owned.init(a, try policy.digest(), request.config, sources, try memory.entry());
    var global_live = true;
    defer if (global_live) global.deinit();
    const stages = try a.alloc(Bridge.Stage, count);
    defer a.free(stages);
    for (stages, source.endpoints, source.leases) |*stage, ep, lease| {
        const retained = lease orelse return error.MissingGroupEndpointLease;
        stage.* = .{ .endpoints = ep.matrix, .tree = &retained.tree, .tree_allocator = a };
    }
    const boundary_log = policy.boundaryLog();
    const ram_log = policy.ramLog();
    stats.global_prepare_ns = timer.lap();
    var batch = try global.batch(a, 0, count);
    var batch_live = true;
    defer if (batch_live) batch.deinit();
    var bridge = try Bridge.produceConditional(a, batch, stages, options.bridge);
    var bridge_live = true;
    defer if (bridge_live) bridge.deinit();
    stats.bridge_ns = timer.lap();
    // The bridge now authenticates the exact same endpoint main roots. The
    // native witness was already destroyed by runUnchecked; narrow rows end now.
    nomination.deinit();
    nomination_live = false;
    source.deinit();
    source_live = false;
    var proof = try memory.proveConditional(global.epoch, global.entries);
    var proof_live = true;
    defer if (proof_live) proof.deinit();
    memory.deinit();
    memory_live = false;
    stats.global_proof_ns = timer.lap();
    _ = try OriginalWriter.write(a, directory, "bridge-0.proof", "B8GBR001", bridge.stark, bridge.claims, options.max_artifact_bytes);
    _ = try OriginalWriter.write(a, directory, "global-memory.proof", "B8CMR001", proof.stark, proof.claims, options.max_artifact_bytes);
    const data = Directory.Data{ .schema = "stwo-b8-group-compact-global-memory-metadata-v1", .elf_sha256 = std.fmt.bytesToHex(request.elf_sha256, .lower), .incoming_sha256 = std.fmt.bytesToHex(request.trusted_window.incoming_sha256, .lower), .outgoing_sha256 = std.fmt.bytesToHex(request.trusted_window.outgoing_sha256, .lower), .window = request.trusted_window.window, .config = request.config, .cohort_policy = cohort_policy, .group_count = 1, .bridge_batches = 1, .endpoint_events = proof.event_count, .selected_initial_addresses = addresses.items, .memory_roots = proof.roots, .ram_log = ram_log, .boundary_log = boundary_log, .global_epoch = global.epoch.digest };
    const metadata = try std.json.Stringify.valueAlloc(a, data, .{});
    defer a.free(metadata);
    if (metadata.len > options.directory.metadata_bytes) return error.GroupPipelineMetadataSizeLimit;
    try directory.writeFile(.{ .sub_path = "global-public.json", .data = metadata });
    stats.artifact_ns = timer.lap();
    // Erase every producer proof, scope and policy before file-only receiving.
    proof.deinit();
    proof_live = false;
    bridge.deinit();
    bridge_live = false;
    batch.deinit();
    batch_live = false;
    global.deinit();
    global_live = false;
    window.deinit();
    window_live = false;
    stats.producer_release_ns = timer.lap();
    const verified = try Directory.verify(a, directory, .{ .elf = request.elf, .incoming = request.incoming, .outgoing = request.outgoing, .trusted = request.trusted_window, .config = request.config }, options.directory);
    stats.fresh_bundle_ns = timer.lap();
    stats.whole_ns = whole.read();
    stats.charged_peak_bytes = budget.snapshot().peak_live_bytes;
    return .{ .stats = stats, .verified = verified };
}
