//! Genuine typed execution -> local original -> late narrow bridge -> global
//! window RAM. This qualifies a bundle of originals, NOT a recursive root or
//! skipped-prefix/block publication. Native wide producers are destroyed before
//! the bridge, retaining only endpoint rows and their exact PCS lease.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Driver = @import("../block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const Collect = @import("../block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("../block_v8_endpoint_range_provider_v1.zig");
const Source = @import("../block_v8_endpoint_local_scope_v1.zig");
const Proof = @import("../block_v8_endpoint_local_proof_v1.zig");
const Statement = @import("../block_v8_endpoint_local_statement_v1.zig");
const Metadata = @import("../block_v8_endpoint_local_statement_wire_v1.zig");
const Codec = @import("../block_v8_endpoint_local_codec_v1.zig");
const BridgeScope = @import("../block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("../block_v8_endpoint_global_bridge_proof_v1.zig");
const Memory = @import("../block_v7_window_memory_joint_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Counters = @import("../../air/lookups/tables/counter.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
const Artifact = struct {
    a: std.mem.Allocator,
    proof: *Proof.Proof,
    statement: *Statement.Owned,
    endpoints: Collect.Owned,
    proof_bytes: []u8,
    metadata_bytes: []u8,
    source_objects_live: bool = true,
    endpoints_live: bool = true,
    fn deinit(self: *@This()) void {
        if (self.source_objects_live) {
            self.proof.deinit();
            self.statement.deinit();
        }
        if (self.endpoints_live) self.endpoints.deinit();
        self.a.free(self.proof_bytes);
        self.a.free(self.metadata_bytes);
        self.a.destroy(self);
    }
};
const Consumer = struct {
    pub const Result = *Artifact;
    pub fn discardStagedResult(result: Result) void {
        result.deinit();
    }
    pub fn consumeStagedWindow(f: Driver.StagedWindowFixture) !Result {
        const a = f.allocator;
        const resident = f.resident_natives orelse return error.ExpectedResidentLocalFixture;
        if (resident.len != 1 or f.callers.len != 0) return error.ExpectedSingleLocalNative;
        const native = resident[0];
        const events = try @import("../block_v8_endpoint_execution_v1.zig").extractEvents(a, native.owner, native.pin().frame, 1 << 20);
        defer a.free(events);
        var endpoints = try Collect.collectGlobal(a, .{ .frame = native.pin().frame, .cohort_ordinal = 0, .cohort_count = 1 }, events, .{});
        var endpoints_live = true;
        defer if (endpoints_live) endpoints.deinit();
        var ranges = try Range.Owned.init(a, endpoints.matrix, @intCast(endpoints.endpoints.len), .{});
        defer ranges.deinit();
        var counters = try Counters.Set.init(a);
        defer counters.deinit(a);
        counters.mergeFrom(&native.owner.opcode_columns.lookup_counters.?);
        var demand = try LP.nativeDemand(&native.owner.statement, 0);
        try ranges.appendToLookup(counters.get(.range_check_8_8), &demand);
        const lookup_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        var lookup = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, f.trusted.config, null, .{});
        defer lookup.deinit();
        const trusted = Source.Trusted{ .elf = f.trusted.elf, .elf_sha256 = f.trusted.elf_sha256, .profile = f.trusted.profile, .config = f.trusted.config, .cohort_count = 1 };
        var input = Source.Input{ .shape = &native.owner.statement, .frame = native.pin().frame, .cohort_ordinal = 0, .endpoint_count = @intCast(endpoints.endpoints.len), .native_roots = @splat(@splat(0)), .program_plan = f.program_plan, .program_roots = f.program.roots, .lookup_plan = lookup_plan, .lookup_layout = lookup.layout, .lookup_roots = lookup.roots };
        const proof = try Proof.produce(a, trusted, input, native.owner.preprocessed.items, .{ .native_main = native.owner.main.items, .endpoints = &endpoints, .endpoint_range = &ranges, .program = f.program, .program_allocator = a, .lookup = &lookup }, .{});
        errdefer proof.deinit();
        input.native_roots = proof.native_roots;
        const statement = try Statement.Owned.init(a, trusted, input);
        errdefer statement.deinit();
        const proof_bytes = try Codec.encode(a, proof, trusted, input, .{});
        errdefer a.free(proof_bytes);
        const metadata_bytes = try Metadata.encode(a, trusted, input, .{});
        errdefer a.free(metadata_bytes);
        const result = try a.create(Artifact);
        result.* = .{ .a = a, .proof = proof, .statement = statement, .endpoints = endpoints, .proof_bytes = proof_bytes, .metadata_bytes = metadata_bytes };
        endpoints_live = false;
        return result;
    }
};
const SequentialProvider = struct {
    metadata: []const u8,
    proof: []const u8,
    bridge: *const Bridge.Proof,
    active: bool = false,
    bridge_count: u32 = 1,
    const LocalLease = struct {
        metadata: []const u8,
        proof: []const u8,
        owner: *SequentialProvider,
        pub fn deinit(self: *@This()) void {
            self.owner.active = false;
        }
    };
    const BridgeLease = struct {
        first: u32,
        count: u32,
        proof: *const Bridge.Proof,
        owner: *SequentialProvider,
        pub fn deinit(self: *@This()) void {
            self.owner.active = false;
        }
    };
    pub fn loadLocal(self: *SequentialProvider, _: std.mem.Allocator, index: u32) !LocalLease {
        if (index != 0 or self.active) return error.NonSequentialEndpointProvider;
        self.active = true;
        return .{ .metadata = self.metadata, .proof = self.proof, .owner = self };
    }
    pub fn loadBridge(self: *SequentialProvider, _: std.mem.Allocator, index: u32) !BridgeLease {
        if (index != 0 or self.active) return error.NonSequentialEndpointProvider;
        self.active = true;
        return .{ .first = 0, .count = self.bridge_count, .proof = self.bridge, .owner = self };
    }
};
test "diagnostic genuine local execution closes through late bridge and shared global memory" {
    try qualify(@import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config());
}
test "canonical genuine local execution closes through late bridge and shared global memory" {
    try qualify(@import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config());
}
fn qualify(config: core.pcs.PcsConfig) !void {
    return qualifyWithObserver(config, struct {});
}
pub fn qualifyWithObserver(config: core.pcs.PcsConfig, comptime Observer: type) !void {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    defer if (comptime @hasDecl(Observer, "discard")) Observer.discard();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = Guest.elf();
    const pins = Capture.Pins{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    const span = Capture.Window{ .skip_cycles = 9, .cycles = 4 };
    var captured = try Capture.capture(a, &elf, &.{}, pins, span, .{});
    defer captured.deinit();
    const external = Window.Trusted{ .elf_sha256 = pins.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    // Legacy Driver is a TEST-ONLY source of the independently qualified raw
    // native witness. The new local production proof never calls its global
    // memory producer and carries no snapshot/interval in its own statement.
    const result = try Driver.run(budget, directory.dir, .{ .elf = &elf, .elf_sha256 = pins.elf, .cycles = span.cycles, .config = config, .state = .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = external } }, .{ .segment_cycles = 4, .active_callers = true, .sparse_window_initialization = true, .resident_original_stages = true }, &pool, Consumer);
    const artifact = result.value;
    defer artifact.deinit();
    try std.testing.expectEqual(@as(usize, 12), artifact.proof.stark.commitment_scheme_proof.commitments.items.len);
    try std.testing.expectEqualDeep(artifact.proof.native_roots[2], artifact.proof.endpoint_lease.?.tree.root());
    const lease = artifact.proof.endpoint_lease.?;
    artifact.proof.endpoint_lease = null;
    var lease_live = true;
    defer if (lease_live) lease.deinit();
    const producer_summary = artifact.proof.summary;
    artifact.proof.deinit();
    artifact.statement.deinit();
    artifact.source_objects_live = false;
    const trusted = Source.Trusted{ .elf = &elf, .elf_sha256 = pins.elf, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
    const detached = try Metadata.decode(a, artifact.metadata_bytes, trusted, .{});
    defer detached.deinit();
    const verified = try Codec.verifyBytes(a, artifact.proof_bytes, detached.trusted, detached.input, .{});
    try std.testing.expectEqualDeep(producer_summary, verified);
    if (comptime @hasDecl(Observer, "observe")) try Observer.observe(a, detached, artifact.proof_bytes);
    try std.testing.expectEqual(.local_execution_global_ram_open, verified.scope);
    try std.testing.expectEqualDeep(captured.incoming.cpu.regs, detached.input.shape.public_data.initial_regs);
    try std.testing.expectEqualDeep(captured.outgoing.cpu.regs, detached.input.shape.public_data.final_regs);
    try std.testing.expectEqual(captured.incoming.cpu.pc, detached.input.shape.public_data.initial_pc);
    try std.testing.expectEqual(captured.outgoing.cpu.pc, detached.input.shape.public_data.final_pc);
    try std.testing.expectEqual(@as(u64, 1), verified.source.frame.global_first_cycle);
    try std.testing.expectEqual(span.cycles, verified.source.frame.cycle_count);
    const addresses = try a.alloc(u32, artifact.endpoints.endpoints.len);
    defer a.free(addresses);
    for (addresses, artifact.endpoints.endpoints) |*address, endpoint| address.* = endpoint.address;
    var window = try Window.Owned.deriveForAddresses(a, &elf, captured.incoming, captured.outgoing, external, addresses, .{});
    defer window.deinit();
    const info = window.initial.info;
    const policy = @import("../block_v7_execution_policy_v1.zig").Policy{ .initialized = &window.initial, .program_root = window.program_root, .terminal = .{ .final_cycle = span.cycles, .halt_address = info.halt_flag, .length_address = info.output_len, .data_address = info.output_data, .output_end = info.output_end, .output = @splat(0) }, .config = config, .window = &window };
    const memory_stage = try Memory.For(Cpu).Stage.init(a, policy, artifact.endpoints.net_transitions, 0, 4, .{});
    var memory_stage_live = true;
    defer if (memory_stage_live) memory_stage.deinit();
    const source = verified.source; // derived from FRESH original verification
    const bridge_source = BridgeScope.Source{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
    try std.testing.expectEqualDeep(detached.input.native_roots[2], bridge_source.endpoint_root);
    var bridge_scope = try BridgeScope.Owned.init(a, try policy.digest(), config, &.{bridge_source}, try memory_stage.entry());
    defer bridge_scope.deinit();
    var bridge = try Bridge.produceConditional(a, bridge_scope, &.{.{ .endpoints = artifact.endpoints.matrix, .tree = &lease.tree, .tree_allocator = a }}, .{});
    defer bridge.deinit();
    var memory = try memory_stage.prove(bridge_scope.epoch, bridge_scope.entries);
    defer memory.deinit();
    memory_stage.deinit();
    memory_stage_live = false;
    artifact.endpoints.deinit();
    artifact.endpoints_live = false;
    lease.deinit();
    lease_live = false;
    // Every native, endpoint, range, ROM, lookup and global-memory producer,
    // original source object and retained endpoint PCS tree is now gone.
    _ = try Codec.verifyBytes(a, artifact.proof_bytes, detached.trusted, detached.input, .{});
    const transition = try Bridge.verifyConditional(a, bridge_scope, &bridge.stark, bridge.claims, .{});
    const global = try Memory.For(Cpu).verify(a, policy, bridge_scope.epoch, bridge_scope.entries, &memory, .{});
    try std.testing.expectEqual(@as(u64, source.endpoint_count), global.event_count);
    try std.testing.expect(transition.add(global.transition).isZero());
    if (comptime @hasDecl(Observer, "observeBridge")) try Observer.observeBridge(a, &bridge_scope, &bridge);
    std.debug.print("B8_LOCAL_BRIDGE_GLOBAL queries={d} pow={d} native_rows={d} endpoints={d} local_trees=11 bridge_trees=3 global_providers=1 freshly_verified=true\n", .{ config.fri_config.n_queries, config.pow_bits, span.cycles, source.endpoint_count });
    // Production receiver has no producer statement, key or admitted receipt.
    // Its provider releases each serialized local artifact before requesting
    // the next; bridge batches must cover every freshly verified source once.
    const Bundle = @import("../block_v8_endpoint_local_bundle_v1.zig");
    var provider = SequentialProvider{ .metadata = artifact.metadata_bytes, .proof = artifact.proof_bytes, .bridge = &bridge };
    const bundle_input = Bundle.Input{ .cohort_count = 1, .bridge_batches = 1, .selected_initial_addresses = addresses, .global_memory = &memory };
    const bundle_external = Bundle.External{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = external, .config = config };
    const closed = try Bundle.verify(a, bundle_external, bundle_input, &provider, .{});
    try std.testing.expectEqual(.declared_window_originals_closed, closed.scope);
    try std.testing.expectEqual(@as(u64, span.cycles), closed.cycles);
    try std.testing.expectEqual(@as(u64, source.endpoint_count), closed.endpoint_events);
    try std.testing.expect(!provider.active);
    provider.bridge_count = 0;
    try std.testing.expectError(error.IncompleteEndpointBridgeCoverage, Bundle.verify(a, bundle_external, bundle_input, &provider, .{}));
    try std.testing.expect(!provider.active);
    provider.bridge_count = 1;
    var wrong_input = detached.input;
    wrong_input.native_roots[2][0] ^= 1;
    const wrong_metadata = try Metadata.encode(a, trusted, wrong_input, .{});
    defer a.free(wrong_metadata);
    provider.metadata = wrong_metadata;
    try std.testing.expectError(error.UntrustedEndpointEnvelope, Bundle.verify(a, bundle_external, bundle_input, &provider, .{}));
    try std.testing.expect(!provider.active);
    var changed = detached.input;
    changed.native_roots[2][0] ^= 1;
    var decoded = try Codec.decode(a, artifact.proof_bytes, detached.trusted, detached.input, .{});
    defer decoded.deinit();
    try std.testing.expectError(error.UntrustedEndpointLocalProofRoots, Proof.verify(a, detached.trusted, changed, &decoded.stark, decoded.claims, .{}));
    changed = detached.input;
    changed.cohort_ordinal = trusted.cohort_count;
    try std.testing.expectError(error.InvalidEndpointLocalCohort, Source.Owned.init(a, trusted, changed, .{}));
    changed = detached.input;
    changed.lookup_plan.max_requests[0] += 1;
    try std.testing.expectError(error.UntrustedEndpointLocalLookup, Source.Owned.init(a, trusted, changed, .{}));
    var bad_root = source.endpoint_root;
    bad_root[0] ^= 1;
    // Storage nomination cannot substitute a different source commitment.
    // The original lease has deliberately been destroyed; only the bridge's
    // authenticated root remains, so no producer-side shortcut is consulted.
    try std.testing.expect(!std.meta.eql(bad_root, bridge.stark.commitment_scheme_proof.commitments.items[1]));
}
