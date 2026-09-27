//! Literal bounded transport/file tests only; no AIR/STARK/FRI/guest execution.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixture = @import("block_v5_native_capacity_fused_transport_fixture_v1.zig");
const Codec = @import("block_v5_native_capacity_fused_codec_v1.zig");
const Proof = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Receiver = @import("block_v5_native_capacity_fused_artifact_receiver_v1.zig");
const Store = @import("block_v5_native_capacity_fused_store_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const limits: Store.Limits = .{ .max_files = 4, .max_file_bytes = 65536, .max_total_bytes = 131072, .max_metadata_bytes = 1 << 20, .max_manifest_bytes = 4096 };

test "capacity fused wire distinct four and five tree inventories roundtrip owned canonical arrays" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |rw| {
        var shape = Fixture.shape(rw);
        const pin = try Fixture.expected(a, &shape);
        var fixture = try Fixture.Fixture.init(a, pin);
        defer fixture.deinit();
        const raw = try Codec.encode(a, &fixture.proof, pin, .{});
        defer a.free(raw);
        var decoded = try Codec.decode(a, raw, pin, .{});
        defer decoded.deinit(a);
        try std.testing.expectEqual(@as(usize, if (rw) 5 else 4), decoded.stark.commitment_scheme_proof.commitments.items.len);
        try std.testing.expect(decoded.claims.ptr != fixture.proof.claims.ptr);
        if (rw) try std.testing.expect(decoded.memory_claims.ptr != fixture.proof.memory_claims.ptr);
        fixture.proof.claims[0].sum = core.fields.qm31.QM31.one();
        try std.testing.expect(decoded.claims[0].sum.isZero());
        const again = try Codec.encode(a, &decoded, pin, .{});
        defer a.free(again);
        try std.testing.expectEqualSlices(u8, raw, again);
    }
}
test "capacity fused wire rejects old grammar count frame mode roots seal and noncanonical claims before received allocations" {
    const a = std.testing.allocator;
    var shape = Fixture.shape(true);
    const pin = try Fixture.expected(a, &shape);
    var fixture = try Fixture.Fixture.init(a, pin);
    defer fixture.deinit();
    const raw = try Codec.encode(a, &fixture.proof, pin, .{});
    defer a.free(raw);
    var inventory = try Codec.Inventory.init(a, pin, .{});
    defer inventory.deinit();
    const bad = try a.dupe(u8, raw);
    defer a.free(bad);
    @memcpy(bad[0..8], "B5CTART1");
    try std.testing.expectError(error.InvalidCapacityFusedWireMagic, Codec.preflightEnvelope(bad, pin, &inventory, .{}));
    @memcpy(bad, raw);
    std.mem.writeInt(u32, bad[8..12], 2, .little);
    try std.testing.expectError(error.UntrustedCapacityFusedProtocol, Codec.preflightEnvelope(bad, pin, &inventory, .{}));
    // Seven independently supplied identities include capacity, exact rows,
    // source seal and word ABI; transport cannot substitute any of them.
    for (0..7) |identity| {
        @memcpy(bad, raw);
        bad[16 + 32 * identity] ^= 1;
        try std.testing.expectError(error.UntrustedCapacityFusedWirePolicy, Codec.preflightEnvelope(bad, pin, &inventory, .{}));
    }
    for ([_]usize{ 240, 244, 248 }) |offset| {
        @memcpy(bad, raw);
        std.mem.writeInt(u32, bad[offset..][0..4], std.math.maxInt(u32), .little);
        try std.testing.expectError(error.UntrustedCapacityFusedWireCensus, Codec.preflightEnvelope(bad, pin, &inventory, .{}));
    }
    @memcpy(bad, raw);
    std.mem.writeInt(u64, bad[252..260], std.math.maxInt(u64), .little);
    try std.testing.expectError(error.CapacityFusedWireProofLimit, Codec.preflightEnvelope(bad, pin, &inventory, .{}));
    @memcpy(bad, raw);
    std.mem.writeInt(u32, bad[Codec.HEADER_BYTES..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalM31, Codec.preflightEnvelope(bad, pin, &inventory, .{}));
    @memcpy(bad, raw);
    std.mem.writeInt(u64, bad[Codec.HEADER_BYTES + 16 ..][0..8], 2, .little);
    try std.testing.expectError(error.InvalidV5FullFusedClaims, Codec.preflightEnvelope(bad, pin, &inventory, .{}));
    var changed = pin;
    changed.frame.global_first_cycle += 1;
    try std.testing.expectError(error.UntrustedCapacityFusedWirePolicy, Codec.Inventory.init(a, changed, .{}));
    changed = pin;
    changed.native_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityFusedWirePolicy, Codec.Inventory.init(a, changed, .{}));
    changed = pin;
    changed.config.pow_bits = 1;
    try std.testing.expectError(error.InvalidProofConfig, Codec.decode(a, raw, changed, .{}));
    try std.testing.expectError(error.CapacityFusedWireClaimLimit, Codec.Inventory.init(a, pin, .{ .max_claims = 1 }));
    try std.testing.expectError(error.CapacityFusedWireClaimLimit, Codec.Inventory.init(a, pin, .{ .max_claim_bytes = 1 }));
}
fn allocationRoundTrip(a: std.mem.Allocator, fixture: *const Fixture.Fixture, expected: Codec.Expected) !void {
    const raw = try Codec.encode(a, &fixture.proof, expected, .{});
    defer a.free(raw);
    var decoded = try Codec.decode(a, raw, expected, .{});
    defer decoded.deinit(a);
    const again = try Codec.encode(a, &decoded, expected, .{});
    defer a.free(again);
    try std.testing.expectEqualSlices(u8, raw, again);
}
test "capacity fused wire every allocation failure preserves decoded array postcard and envelope owners" {
    for ([_]bool{ false, true }) |rw| {
        var shape = Fixture.shape(rw);
        const pin = try Fixture.expected(std.testing.allocator, &shape);
        var fixture = try Fixture.Fixture.init(std.testing.allocator, pin);
        defer fixture.deinit();
        try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRoundTrip, .{ &fixture, pin });
    }
}

const Authority = struct {
    shape: @import("../air/statement.zig").Blake3ExecutionStatement,
    entries: [5]Seal.Entry,
    records: [1]Catalog.Record,
    policy: Store.Policy,
    fn init(self: *Authority, a: std.mem.Allocator, rw: bool) !void {
        self.shape = Fixture.shape(rw);
        const template = try Protocol.Template.fromShape(&self.shape, 0, Fixture.config, .rv32im_zkvm_v1, @splat(4));
        self.records = .{try Catalog.Record.fromTemplate(0, template)};
        const context = Public.Context{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(9), .register_custody_mode = 1, .execution_index = 0, .first_cycle = 11, .last_cycle = 13 };
        const admission = try Public.Admission.init(context, &self.shape.public_data);
        const roots: Seal.Roots = .{ template.fixed_root, @splat(2) };
        const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 11, .cycle_count = 3 };
        const projections = try Source.slotsFromShapeForMode(a, &self.shape, 0, 1);
        defer a.free(projections);
        const memory = try Source.memorySlots(a, &self.shape, 0, frame, 1);
        defer a.free(memory);
        const access: [32]u8 = if (memory.len == 0) try Source.emptyWitnessRoot(1) else @splat(13);
        const execution = Seal.Entry{ .family = .execution, .index = 0, .instance_id = try Protocol.instanceId(self.records[0].template_id, &self.shape, 0, admission, roots, 0), .roots = roots };
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },                                                           execution,
            if (memory.len == 0) try Source.emptyEntry(a, &self.shape, 0, frame, execution, 0, 1) else Memory.packedEntry(execution.instance_id, roots, access, 0, memory), Proof.entry(self.records[0].template_id, execution.instance_id, roots, access, 0, frame, projections, memory),
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
        };
        const catalog: Catalog.Admission = .{ .records = &self.records };
        var counts: [Seal.family_count]u32 = @splat(0);
        inline for (.{ Seal.Family.program, Seal.Family.execution, Seal.Family.execution_sidecar, Seal.Family.program_request, Seal.Family.memory }) |family| counts[@intFromEnum(family) - 1] = 1;
        const pins: Seal.Pins = .{ .job_id = context.job_id, .source_image_digest = context.source_image_digest, .program_root = context.program_root, .program_plan_digest = context.program_plan_digest, .memory_plan_digest = context.memory_plan_digest, .initial_source_plan_digest = context.initial_source_plan_digest, .rw_endpoint_plan_digest = context.rw_endpoint_plan_digest, .register_endpoint_plan_digest = context.register_endpoint_plan_digest, .register_custody_mode = 1, .native_template_catalog_digest = try catalog.digest(), .config = Fixture.config, .counts = counts };
        self.policy = .{ .index = 0, .native = .{ .shape = &self.shape, .external_retirements = 0, .admission = admission, .template = template, .template_id = self.records[0].template_id, .profile = .rv32im_zkvm_v1 }, .memory = .{ .frame = frame, .expected_events = 0, .witness_root = access }, .sealed = try Seal.seal(pins, &self.entries), .pins = pins, .entries = &self.entries, .catalog = catalog };
    }
    fn literal(self: *const Authority, a: std.mem.Allocator) !Proof.Proof {
        const expected = try self.policy.expected(a);
        var fixture = try Fixture.Fixture.init(a, expected);
        defer fixture.deinit();
        const raw = try Codec.encode(a, &fixture.proof, expected, .{});
        defer a.free(raw);
        return Codec.decode(a, raw, expected, .{});
    }
};
test "capacity fused store independently admitted policy owns exclusive publication manifest and one-shot load" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |rw| {
        var authority: Authority = undefined;
        try authority.init(a, rw);
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var writer = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, limits);
        defer writer.deinit();
        var proof = try authority.literal(a);
        const sink = writer.sink();
        try sink.put_fused(sink.context, 0, &proof);
        try std.testing.expectError(error.DuplicateCapacityFusedArtifact, writer.put(0, undefined));
        const pins = try writer.filePins(a);
        defer a.free(pins);
        const sha = try Store.writePins(a, tmp.dir, pins, limits);
        var manifest = try Store.readPins(a, tmp.dir, sha, limits);
        defer manifest.deinit();
        var reader = try Store.Store.initReader(a, tmp.dir, &.{authority.policy}, manifest.pins, Fixture.config, limits);
        defer reader.deinit();
        var received = try reader.take(0);
        defer received.deinit(a);
        try std.testing.expectEqualDeep(authority.entries[1].roots, received.stark.commitment_scheme_proof.commitments.items[0..2].*);
        try reader.requireConsumed();
        try std.testing.expectError(error.RepeatedCapacityFusedLoad, reader.take(0));
        try std.testing.expectError(error.FileNotFound, tmp.dir.access("block-v5-native-capacity-0.proof", .{}));
    }
}
test "capacity fused store rejects root census cap and existing file while retaining producer ownership" {
    const a = std.testing.allocator;
    var authority: Authority = undefined;
    try authority.init(a, true);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var proof = try authority.literal(a);
    defer proof.deinit(a);
    var writer = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, limits);
    defer writer.deinit();
    proof.stark.commitment_scheme_proof.commitments.items[2][0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityFusedWireRoots, writer.put(0, &proof));
    proof.stark.commitment_scheme_proof.commitments.items[2][0] ^= 1;
    proof.claims[0].row_count -= 1;
    try std.testing.expectError(error.InvalidV5FullFusedClaims, writer.put(0, &proof));
    proof.claims[0].row_count += 1;
    var name: [96]u8 = undefined;
    const path = try Store.fileName(&name, 0);
    try Files.publish(tmp.dir, path, "keep");
    try std.testing.expectError(error.ExistingV5BundleArtifact, writer.put(0, &proof));
    const raw = try Files.readPinned(a, tmp.dir, path, 4, Files.hash("keep"), 32);
    defer a.free(raw);
    try std.testing.expectEqualStrings("keep", raw);
    try std.testing.expectError(error.IncompleteCapacityFusedFiles, writer.filePins(a));
    var cap = limits;
    cap.max_total_bytes = 1;
    var bounded = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, cap);
    defer bounded.deinit();
    try std.testing.expectError(error.CapacityFusedStoreTotalLimit, bounded.put(0, &proof));
}
test "capacity fused store independent source policy rejects exact count frame catalog and stale seal replacements" {
    const a = std.testing.allocator;
    var authority: Authority = undefined;
    try authority.init(a, false);
    _ = try authority.policy.expected(a);
    var changed = authority.policy;
    changed.memory.frame.global_first_cycle += 1;
    try std.testing.expectError(error.UntrustedV5FullFusedPin, changed.expected(a));
    changed = authority.policy;
    changed.memory.expected_events = 1;
    try std.testing.expectError(error.InvalidCapacityFusedAbsence, changed.expected(a));
    changed = authority.policy;
    changed.sealed.digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, changed.expected(a));
    changed = authority.policy;
    changed.native.template_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, changed.expected(a));
    var records = authority.records;
    records[0].fixed_root[0] ^= 1;
    changed = authority.policy;
    changed.catalog = .{ .records = &records };
    try std.testing.expectError(error.UntrustedNativeCapacityCatalog, changed.expected(a));
}
fn allocationStore(a: std.mem.Allocator, dir: std.fs.Dir, policy: Store.Policy) !void {
    var writer = try Store.Store.initWriter(a, dir, &.{policy}, Fixture.config, limits);
    defer writer.deinit();
}
test "capacity fused store independent policy and slot owners survive every allocation failure" {
    var authority: Authority = undefined;
    try authority.init(std.testing.allocator, true);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationStore, .{ tmp.dir, authority.policy });
}
fn ownedBody(a: std.mem.Allocator, raw: []const u8, native: Native.Proof, policy: Receiver.Policy) anyerror!@import("block_v5_native_capacity_fused_receiver_v1.zig").Open {
    return Receiver.ForBackend(Cpu).verifyOwned(a, raw, native, policy);
}
fn hookBody(a: std.mem.Allocator, raw: []const u8, native: *const Native.OpenReceipt, policy: Receiver.Policy) anyerror!Proof.Verified {
    return Receiver.ForBackend(Cpu).verifyAfterFreshNative(a, raw, native, policy);
}
fn storeBody(store: *Store.Store, native: Native.Proof) anyerror!@import("block_v5_native_capacity_fused_receiver_v1.zig").Open {
    return store.verifyOwned(Cpu, 0, native);
}
test "capacity fused artifact CPU fresh verifier and owned store bodies compile only" {
    inline for (.{ &ownedBody, &hookBody, &storeBody, &Store.Store.initWriter, &Store.Store.initReader, &Store.Store.put, &Store.Store.take, &Store.writePins, &Store.readPins }) |function| std.mem.doNotOptimizeAway(function);
}
