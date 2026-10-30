//! One genuine mixed original, same-root narrow bridge and compact global RAM.
//! Every source/bridge/global producer is gone before durable directory receive.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Fixture = @import("block_v8_endpoint_mixed_fixture.zig");
const Proof = @import("../block_v8_endpoint_mixed_proof_v1.zig");
const Codec = @import("../block_v8_endpoint_mixed_codec_v1.zig");
const Metadata = @import("../block_v8_endpoint_mixed_statement_wire_v1.zig");
const Dispatch = @import("../block_v8_endpoint_source_wire_dispatch_v1.zig");
const Scope = @import("../block_v8_endpoint_mixed_scope_v1.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Compact = @import("../block_v8_compact_ram_proof_v1.zig");
const BridgeScope = @import("../block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("../block_v8_endpoint_global_bridge_proof_v1.zig");
const Directory = @import("../block_v8_endpoint_local_directory_v1.zig");
fn writeOriginal(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, magic: *const [8]u8, stark: core.proof_suites.Blake3.Proof, claims: anytype) !void {
    var writer = @import("../bounded_artifact_writer_v1.zig").Writer.init(a, 128 << 20);
    defer writer.deinit();
    try writer.writeAll(magic);
    try writer.writeAll(&@import("../block_v7_union_claim_wire_v1.zig").schemaId(@TypeOf(claims)));
    var items: usize = 1 << 20;
    try @import("../block_v7_union_claim_wire_v1.zig").encode(@TypeOf(claims), &writer, claims, &items);
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &writer, stark);
    try dir.writeFile(.{ .sub_path = name, .data = writer.bytes.items });
}
fn run(kind: Fixture.Kind) !void {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const fixture = try Fixture.Owned.initForGlobal(a, kind, config);
    var fixture_live = true;
    defer if (fixture_live) fixture.deinit();
    const elf = try a.dupe(u8, fixture.elf);
    defer a.free(elf);
    const incoming = Capture.Snapshot{ .cpu = fixture.incoming.?.cpu, .words = try a.dupe(Capture.Word, fixture.incoming.?.words) };
    defer a.free(incoming.words);
    const outgoing = Capture.Snapshot{ .cpu = fixture.outgoing.?.cpu, .words = try a.dupe(Capture.Word, fixture.outgoing.?.words) };
    defer a.free(outgoing.words);
    const original = try Proof.produceWithOptions(a, fixture.trusted, fixture.input(), fixture.current.?.owner.preprocessed.items, fixture.stages(), .{}, .{ .program = &fixture.image.? });
    var original_live = true;
    defer if (original_live) original.deinit();
    var input = fixture.input();
    input.native_roots = original.native_roots;
    input.caller_roots = original.caller_roots;
    const metadata = try Metadata.encode(a, fixture.trusted, input, .{});
    defer a.free(metadata);
    const proof = try Codec.encode(a, original, fixture.trusted, input, .{});
    defer a.free(proof);
    const expected = original.summary;
    var endpoints = fixture.endpoints.?;
    fixture.endpoints = null;
    var endpoints_live = true;
    defer if (endpoints_live) endpoints.deinit();
    const lease = original.endpoint_lease.?;
    original.endpoint_lease = null;
    var lease_live = true;
    defer if (lease_live) lease.deinit();
    original.deinit();
    original_live = false;
    fixture.deinit();
    fixture_live = false;
    const trusted = Scope.Trusted{ .elf = elf, .elf_sha256 = Capture.sha(elf), .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
    const checked = try Dispatch.verifyBytes(a, metadata, proof, trusted, .{});
    try std.testing.expectEqual(.mixed_complete, checked.kind);
    try std.testing.expectEqualDeep(expected.source, checked.source);
    try std.testing.expectEqual(expected.external_retirements, checked.external_retirements);
    try std.testing.expectEqual(expected.cycles, checked.cycles);
    // Schema+magic are a strict pair. The dispatcher never retries Local/Mixed.
    const wrong_magic = try a.dupe(u8, proof);
    defer a.free(wrong_magic);
    @memcpy(wrong_magic[0..8], "B8LCO001");
    try std.testing.expectError(error.EndpointSourceSchemaMagicMismatch, Dispatch.verifyBytes(a, metadata, wrong_magic, trusted, .{}));
    const parsed = try std.json.parseFromSlice(std.json.Value, a, metadata, .{});
    defer parsed.deinit();
    const caller_roots = parsed.value.object.get("caller_roots").?.array.items;
    caller_roots[1].array.items[0].integer ^= 1;
    const altered = try std.json.Stringify.valueAlloc(a, parsed.value, .{});
    defer a.free(altered);
    if (Dispatch.verifyBytes(a, altered, proof, trusted, .{})) |_| return error.AcceptedMixedCallerRootMutation else |err| if (err == error.OutOfMemory) return err;
    const addresses = try a.alloc(u32, endpoints.endpoints.len);
    defer a.free(addresses);
    for (addresses, endpoints.endpoints) |*address, point| address.* = point.address;
    const external = @import("../block_v8_endpoint_local_bundle_v1.zig").External{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = trusted.elf_sha256, .incoming_sha256 = incoming.identity(), .outgoing_sha256 = outgoing.identity(), .window = .{ .skip_cycles = 0, .cycles = checked.cycles } }, .config = config };
    const cohorts = Window.CohortPolicy{ .cohort_count = 1, .max_cohort_cycles = checked.cycles };
    var window = try Window.Owned.deriveCohortsForAddresses(a, elf, incoming, outgoing, external.trusted, cohorts, addresses, .{});
    defer window.deinit();
    const policy = Compact.Policy{ .window = &window, .config = config, .event_count = @intCast(endpoints.endpoints.len) };
    const stage = try Compact.Stage.init(a, policy, endpoints.net_transitions, .{});
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    const source = BridgeScope.Source{ .local_identity = checked.source.local_identity, .local_epoch = checked.source.local_epoch, .endpoint_root = checked.source.endpoint_root, .endpoint_count = checked.source.endpoint_count, .policy = checked.source.policy };
    var global = try BridgeScope.Owned.init(a, try policy.digest(), config, &.{source}, try stage.entry());
    defer global.deinit();
    var bridge = try Bridge.produceConditional(a, global, &.{.{ .endpoints = endpoints.matrix, .tree = &lease.tree, .tree_allocator = a }}, .{});
    var bridge_live = true;
    defer if (bridge_live) bridge.deinit();
    // SAME endpoint MAIN root; no caller/native rows survive this point.
    try std.testing.expectEqualDeep(checked.source.endpoint_root, lease.tree.root());
    endpoints.deinit();
    endpoints_live = false;
    lease.deinit();
    lease_live = false;
    var memory = try stage.proveConditional(global.epoch, global.entries);
    var memory_live = true;
    defer if (memory_live) memory.deinit();
    stage.deinit();
    stage_live = false;
    var output = std.testing.tmpDir(.{ .iterate = true });
    defer output.cleanup();
    try output.dir.writeFile(.{ .sub_path = "local-0.json", .data = metadata });
    try output.dir.writeFile(.{ .sub_path = "local-0.proof", .data = proof });
    try writeOriginal(a, output.dir, "bridge-0.proof", "B8GBR001", bridge.stark, bridge.claims);
    try writeOriginal(a, output.dir, "global-memory.proof", "B8CMR001", memory.stark, memory.claims);
    const global_metadata = try std.json.Stringify.valueAlloc(a, Directory.Data(true){ .schema = "stwo-b8-local-compact-global-memory-metadata-v1", .authority = "Explicit Mixed metadata and original must fresh verify; complete snapshots/ELF are external pins", .global_argument = "compact_endpoint", .elf_sha256 = &std.fmt.bytesToHex(trusted.elf_sha256, .lower), .incoming_sha256 = &std.fmt.bytesToHex(incoming.identity(), .lower), .outgoing_sha256 = &std.fmt.bytesToHex(outgoing.identity(), .lower), .window = external.trusted.window, .cohort_policy = cohorts, .cohort_count = 1, .bridge_batches = 1, .endpoint_events = policy.event_count, .config = config, .selected_initial_addresses = addresses, .memory_roots = memory.roots, .memory_interval_log = null, .compact_ram_log = policy.ramLog(), .compact_boundary_log = policy.boundaryLog(), .global_epoch = global.epoch.digest }, .{});
    defer a.free(global_metadata);
    try output.dir.writeFile(.{ .sub_path = "global-public.json", .data = global_metadata });
    bridge.deinit();
    bridge_live = false;
    memory.deinit();
    memory_live = false;
    const received = try Directory.verifyDirectoryCompact(a, output.dir, external, .{ .endpoint_events_nomination = policy.event_count }, .{});
    try std.testing.expectEqual(.declared_window_originals_closed, received.scope);
    try std.testing.expectEqual(@as(u64, checked.cycles), received.cycles);
    try std.testing.expectEqual(@as(u64, checked.external_retirements), received.external_retirements);
    try std.testing.expectEqual(@as(u32, 1), received.cohorts);
    try std.testing.expectEqual(expected.logical_ram_accesses, received.logical_ram_accesses);
    try std.testing.expectEqual(expected.program_fetches, received.program_fetches);
    if (std.posix.getenv("STWO_MIXED_BUNDLE_OUTPUT")) |base| {
        const path = try std.fs.path.join(a, &.{ base, @tagName(kind) });
        defer a.free(path);
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
        defer dir.close();
        for ([_][]const u8{ "local-0.json", "local-0.proof", "bridge-0.proof", "global-memory.proof", "global-public.json" }) |name| {
            const bytes = try output.dir.readFileAlloc(a, name, 128 << 20);
            defer a.free(bytes);
            try dir.writeFile(.{ .sub_path = name, .data = bytes });
        }
        try dir.writeFile(.{ .sub_path = "guest.elf", .data = elf });
        const ib = try incoming.encode(a);
        defer a.free(ib);
        try dir.writeFile(.{ .sub_path = "incoming.b7win", .data = ib });
        const ob = try outgoing.encode(a);
        defer a.free(ob);
        try dir.writeFile(.{ .sub_path = "outgoing.b7win", .data = ob });
        const report = try std.json.Stringify.valueAlloc(a, received, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "report.json", .data = report });
    }
    std.debug.print("MIXED_COMPACT_DURABLE_BUNDLE_VERIFIED kind={s} cycles={d} external={d} endpoints={d} queries=70 pow=26\n", .{ @tagName(kind), received.cycles, received.external_retirements, received.endpoint_events });
}
test "mixed durable SHA Keccak cohort closes same endpoint bridge and compact global original" {
    try run(.sha_keccak);
}
test "mixed durable recovery cohort closes same endpoint bridge and compact global original" {
    try run(.recovery);
}
