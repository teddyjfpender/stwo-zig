//! Genuine native execution -> endpoint-local closure -> all global providers
//! in ONE original STARK. This experimental window is not block publication.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Driver = @import("../block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const Collect = @import("../block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("../block_v8_endpoint_range_provider_v1.zig");
const Whole = @import("../block_v8_endpoint_whole_proof_v1.zig");
const Scope = @import("../block_v8_endpoint_whole_scope_v1.zig");
const Statement = @import("../block_v8_endpoint_whole_statement_v1.zig");
const Codec = @import("../block_v8_endpoint_whole_codec_v1.zig");
const Metadata = @import("../block_v8_endpoint_whole_statement_wire_v1.zig");
const Loader = @import("../block_v8_endpoint_whole_loader_v1.zig");
const Memory = @import("../block_v7_window_memory_joint_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Counters = @import("../../air/lookups/tables/counter.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
const Q = core.fields.qm31.QM31;
const Artifact = struct {
    a: std.mem.Allocator,
    proof: *Whole.Proof,
    statement: *Statement.Owned,
    addresses: []u32,
    proof_bytes: []u8,
    metadata_bytes: []u8,
    producer_objects_live: bool = true,
    fn deinit(self: *@This()) void {
        self.a.free(self.addresses);
        self.a.free(self.proof_bytes);
        self.a.free(self.metadata_bytes);
        if (self.producer_objects_live) {
            self.proof.deinit();
            self.statement.deinit();
        }
        self.a.destroy(self);
    }
};
const Consumer = struct {
    pub const Result = *Artifact;
    pub fn discardStagedResult(value: Result) void {
        value.deinit();
    }
    pub fn consumeStagedWindow(f: Driver.StagedWindowFixture) !Result {
        const a = f.allocator;
        const resident = f.resident_natives orelse return error.ExpectedResidentFixture;
        if (resident.len != 1 or f.callers.len != 0) return error.ExpectedSingleNativeCohort;
        const native = resident[0];
        var events: std.ArrayList(Collect.Transition) = .empty;
        defer events.deinit(a);
        for (native.access.source.inputs) |input| for (0..input.trace.domainSize()) |row| {
            const value = try input.trace.row(row);
            if (value.active) try events.append(a, try @import("../block_memory_relation_v2.zig").decodeTransitionTuple(value.tuple));
        };
        const direct_events = try @import("../block_v8_endpoint_execution_v1.zig").extractEvents(a, native.owner, native.pin().frame, 1 << 20);
        defer a.free(direct_events);
        const Ordering = struct {
            fn less(_: void, left: Collect.Transition, right: Collect.Transition) bool {
                if (left.address != right.address) return left.address < right.address;
                return left.clock < right.clock;
            }
        };
        std.mem.sort(Collect.Transition, direct_events, {}, Ordering.less);
        std.mem.sort(Collect.Transition, events.items, {}, Ordering.less);
        try std.testing.expectEqualDeep(events.items, direct_events);
        var endpoints = try Collect.collectGlobal(a, .{ .frame = native.pin().frame, .cohort_ordinal = 0, .cohort_count = 1 }, events.items, .{});
        defer endpoints.deinit();
        var endpoint_range = try Range.Owned.init(a, endpoints.matrix, @intCast(endpoints.endpoints.len), .{});
        defer endpoint_range.deinit();
        // Native counters exclude the old access sidecar's byte requests. The
        // B8 endpoint table contributes exactly its own signed byte requests.
        var counters = try Counters.Set.init(a);
        defer counters.deinit(a);
        counters.mergeFrom(&native.owner.opcode_columns.lookup_counters.?);
        var demand = try LP.nativeDemand(&native.owner.statement, 0);
        try endpoint_range.appendToLookup(counters.get(.range_check_8_8), &demand);
        const lookup_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        var lookup = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, f.trusted.config, null, .{});
        defer lookup.deinit();
        const memory = try Memory.For(Cpu).Stage.init(a, f.policy, endpoints.net_transitions, 0, 4, .{});
        defer memory.deinit();
        const geometries = try a.alloc(@import("../block_v5_ram_lanes_protocol_v1.zig").Claim, memory.witness.ram.len);
        defer a.free(geometries);
        for (geometries, memory.witness.ram) |*geometry, row| geometry.* = row.geometry;
        var input = Scope.Input{ .shape = &native.owner.statement, .frame = native.pin().frame, .endpoint_count = @intCast(endpoints.endpoints.len), .native_roots = @splat(@splat(0)), .program_plan = f.program_plan, .program_roots = f.program.roots, .lookup_plan = lookup_plan, .lookup_layout = lookup.layout, .lookup_roots = lookup.roots, .memory_geometry = geometries, .memory_roots = memory.roots, .memory_interval_log = memory.witness.interval.log };
        const proof = try Whole.produce(a, f.trusted, input, native.owner.preprocessed.items, .{
            .native_main = native.owner.main.items,
            .endpoints = &endpoints,
            .endpoint_range = &endpoint_range,
            .program = f.program,
            .program_allocator = a,
            .lookup = &lookup,
            .memory = memory,
        }, .{});
        errdefer proof.deinit();
        input.native_roots = proof.native_roots;
        const statement = try Statement.Owned.init(a, f.trusted, input);
        errdefer statement.deinit();
        // Clone through the finite canonical statement wire, not unused array
        // tails or pointers into the original native witness owner.
        const ShapeWire = @import("../guest_precompile/proof_artifact_wire.zig");
        var encoded = @import("../bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
        defer encoded.deinit();
        try ShapeWire.encodeBlake3Statement(&encoded, input.shape, .{});
        const shape = try statement.arena.allocator().create(ShapeWire.OwnedBlake3Statement);
        shape.* = try ShapeWire.decodeBlake3Statement(statement.arena.allocator(), encoded.bytes.items, .{});
        statement.input.shape = &shape.value;
        const addresses = try a.alloc(u32, endpoints.endpoints.len);
        errdefer a.free(addresses);
        for (addresses, endpoints.endpoints) |*address, endpoint| address.* = endpoint.address;
        const proof_bytes = try Codec.encode(a, proof, statement.trusted, statement.input, .{});
        errdefer a.free(proof_bytes);
        const metadata_bytes = try Metadata.encode(a, statement.trusted, statement.input, .{});
        errdefer a.free(metadata_bytes);
        const artifact = try a.create(Artifact);
        artifact.* = .{ .a = a, .proof = proof, .statement = statement, .addresses = addresses, .proof_bytes = proof_bytes, .metadata_bytes = metadata_bytes };
        return artifact;
    }
};
fn expectRejected(a: std.mem.Allocator, trusted: @import("../block_v7_execution_receiver_v1.zig").Trusted, input: Scope.Input, proof: *Whole.Proof) !void {
    if (Whole.verify(a, trusted, input, &proof.stark, proof.claims, .{})) |_| {
        return error.AcceptedInvalidEndpointWholeProof;
    } else |_| {}
}
test "diagnostic endpoint whole original proves real native execution with all providers and verifies after producer destruction" {
    try qualify(@import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config());
}
test "canonical endpoint whole original proves real native execution with all providers and verifies after producer destruction" {
    try qualify(@import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config());
}
fn qualify(config: core.pcs.PcsConfig) !void {
    return qualifyWithObserver(config, struct {});
}
/// Test-only observer receives freshly verified original data after every
/// producer has been destroyed and external snapshot trust re-derived.
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
    const span = Capture.Window{ .skip_cycles = 9, .cycles = 4 };
    const pins = Capture.Pins{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    var captured = try Capture.capture(a, &elf, &.{}, pins, span, .{});
    defer captured.deinit();
    const trusted_window = Window.Trusted{ .elf_sha256 = pins.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    const result = try Driver.run(budget, directory.dir, .{ .elf = &elf, .elf_sha256 = pins.elf, .cycles = span.cycles, .config = config, .state = .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = trusted_window } }, .{ .segment_cycles = 4, .active_callers = true, .sparse_window_initialization = true, .resident_original_stages = true }, &pool, Consumer);
    defer result.value.deinit();
    const artifact = result.value;
    try std.testing.expectEqual(@as(u64, 0), result.stats.checkpoint_bytes);
    try std.testing.expectEqual(@as(usize, 14), artifact.proof.stark.commitment_scheme_proof.commitments.items.len);
    try std.testing.expectEqualDeep(config, artifact.proof.stark.commitment_scheme_proof.config);
    std.debug.print("B8_ENDPOINT_WHOLE_SECURITY queries={d} pow={d} layout_version={d}\n", .{ config.fri_config.n_queries, config.pow_bits, @import("../block_v8_native_endpoint_layout_v1.zig").VERSION });
    // Every producer, raw native column, endpoint witness, range multiplicity
    // and source PCS lease has gone. Re-derive trust from complete captured
    // endpoint snapshots and their independent pins, not the cloned producer.
    var external = try Window.Owned.deriveForAddresses(a, &elf, captured.incoming, captured.outgoing, trusted_window, artifact.addresses, .{});
    defer external.deinit();
    var trusted = artifact.statement.trusted;
    trusted.window = &external;
    const input = artifact.statement.input;
    // A separate receiver parses one bounded metadata envelope, reconstructs
    // its ELF/window policy from independent complete snapshots and verifies
    // the full physical-claim/STARK envelope after all producers have gone.
    const detached = try Loader.admitMetadata(a, artifact.metadata_bytes, .{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = trusted_window, .config = config }, .{});
    defer detached.deinit();
    const from_bytes = try Codec.verifyBytes(a, artifact.proof_bytes, detached.trusted, detached.input, .{});
    try std.testing.expectEqualDeep(artifact.proof.summary, from_bytes);
    const bad_bytes = try a.dupe(u8, artifact.proof_bytes);
    defer a.free(bad_bytes);
    // Header schema, epoch, length envelope and body each remain binding.
    for ([_]usize{ 0, 8, 40, 72 }) |offset| {
        bad_bytes[offset] ^= 1;
        if (Codec.verifyBytes(a, bad_bytes, detached.trusted, detached.input, .{})) |_| return error.AcceptedTamperedEndpointWholeEnvelope else |_| {}
        bad_bytes[offset] ^= 1;
    }

    // Corrupt the encoded physical-claim count, before PCS decoding. This
    // deliberately malformed envelope must fail bounded parsing without
    // emitting an expected low-level Merkle error into the test log.
    const count_offset = Codec.HEADER_BYTES;
    const original_count = bad_bytes[count_offset..][0..4].*;
    @memset(bad_bytes[count_offset..][0..4], 255);
    if (Codec.verifyBytes(a, bad_bytes, detached.trusted, detached.input, .{})) |_| return error.AcceptedMalformedEndpointClaimCount else |_| {}
    @memcpy(bad_bytes[count_offset..][0..4], &original_count);
    const verified = try Whole.verify(a, trusted, input, &artifact.proof.stark, artifact.proof.claims, .{});
    try std.testing.expectEqual(.declared_nonterminal_window, verified.scope);
    try std.testing.expectEqual(@as(u32, 4), verified.cycles);
    try std.testing.expect(verified.logical_ram_accesses > 0);
    try std.testing.expect(verified.global_endpoint_events <= verified.logical_ram_accesses);
    try std.testing.expectEqualDeep(verified, artifact.proof.summary);
    if (comptime @hasDecl(Observer, "observe")) try Observer.observe(a, trusted, input, &artifact.proof.stark, artifact.proof.claims);
    // Keep a native+endpoint local relation aggregate unchanged. Physical
    // claim transcript binding must still reject the compensated substitution.
    var layout = try @import("../block_v8_native_endpoint_layout_v1.zig").Layout.init(a, input.shape, 0);
    defer layout.deinit();
    const physical = for (layout.slots, 0..) |slot, index| {
        if (slot.kind == .lookup and slot.kind.lookup.partition == .ordinary_memory_access) break index;
    } else return error.MissingEndpointNativeRamProjection;
    const native_claims = @constCast(artifact.proof.claims.native);
    native_claims[physical].sum = native_claims[physical].sum.add(Q.one());
    artifact.proof.claims.endpoint[0] = artifact.proof.claims.endpoint[0].sub(Q.one());
    try expectRejected(a, trusted, input, artifact.proof);
    native_claims[physical].sum = native_claims[physical].sum.sub(Q.one());
    artifact.proof.claims.endpoint[0] = artifact.proof.claims.endpoint[0].add(Q.one());
    // Compensated range planes preserve their public aggregate too.
    artifact.proof.claims.endpoint[2] = artifact.proof.claims.endpoint[2].add(Q.one());
    artifact.proof.claims.endpoint[3] = artifact.proof.claims.endpoint[3].sub(Q.one());
    try expectRejected(a, trusted, input, artifact.proof);
    artifact.proof.claims.endpoint[2] = artifact.proof.claims.endpoint[2].sub(Q.one());
    artifact.proof.claims.endpoint[3] = artifact.proof.claims.endpoint[3].add(Q.one());
    var bad_input = input;
    bad_input.native_roots[2][0] ^= 1;
    try expectRejected(a, trusted, bad_input, artifact.proof);
    bad_input = input;
    bad_input.endpoint_count += 1;
    try expectRejected(a, trusted, bad_input, artifact.proof);
    external.boundary.outgoing_sha256[0] ^= 1;
    try expectRejected(a, trusted, input, artifact.proof);
    external.boundary.outgoing_sha256[0] ^= 1;
    try std.testing.expectEqualDeep(verified, try Whole.verify(a, trusted, input, &artifact.proof.stark, artifact.proof.claims, .{}));
    // This final gate holds only serialized data and external machine states.
    // Neither the producer proof object nor its public metadata is alive.
    artifact.proof.deinit();
    artifact.statement.deinit();
    artifact.producer_objects_live = false;
    const byte_only = try Loader.admitMetadata(a, artifact.metadata_bytes, .{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = trusted_window, .config = config }, .{});
    defer byte_only.deinit();
    try std.testing.expectEqualDeep(verified, try Codec.verifyBytes(a, artifact.proof_bytes, byte_only.trusted, byte_only.input, .{}));
    if (comptime @hasDecl(Observer, "afterOriginalDestroyed")) try Observer.afterOriginalDestroyed(a, byte_only);
}
