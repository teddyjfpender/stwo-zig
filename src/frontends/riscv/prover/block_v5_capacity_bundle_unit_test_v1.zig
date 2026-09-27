//! Literal transport and admission checks only. No genuine proof is generated
//! or freshly verified by these fixtures; detached bodies are retained only.
const std = @import("std");
const core = @import("stwo_core");
const StoreModule = @import("block_v5_cpu_bundle_store_v1.zig");
const Store = StoreModule.ForCapacity(true);
const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(true);
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const FusedFixture = @import("block_v5_native_capacity_fused_transport_fixture_v1.zig");
const NativeCodec = @import("block_v5_native_capacity_codec_v1.zig");
const FusedCodec = @import("block_v5_native_capacity_fused_codec_v1.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const limits: Store.Limits = .{ .max_files = 16, .max_file_bytes = 1 << 20, .max_total_bytes = 4 << 20, .max_metadata_bytes = 2 << 20, .max_manifest_bytes = 4096, .max_claims = 4096, .max_proof_bytes = 1 << 19 };
fn nativePolicy(a: std.mem.Allocator, shape: *const Shape) !Store.Policy {
    const expected = try Fixture.expected(shape);
    const fixed = try Capacity.columnLogs(a, shape, 0, .fixed);
    defer a.free(fixed);
    const main = try Capacity.columnLogs(a, shape, 0, .main);
    defer a.free(main);
    const interaction = try Capacity.columnLogs(a, shape, 0, .interaction);
    defer a.free(interaction);
    var count: u32 = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| count += @intCast(@import("../air/lookups/opcode_entries.zig").batchCount(desc.family));
    const log = try NativeCodec.maximumProofColumnLog(expected);
    return .{ .native = expected, .expected = .{ .family = .native, .index = 0, .policy_digest = @splat(1), .config = expected.config, .roots = .{ @splat(1), @splat(2), @splat(0) }, .claim_count = count, .geometry = .{ .tree_count = 4, .tree_columns = .{ @intCast(fixed.len), @intCast(main.len), @intCast(interaction.len), @intCast(core.verifier_types.compositionColumnCount(core.verifier_types.COMPOSITION_LOG_SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE).?), 0 }, .max_column_log = log, .max_merkle_log = log } } };
}
fn fusedPolicy(a: std.mem.Allocator, expected: FusedCodec.Expected) !Store.Policy {
    var inventory = try FusedCodec.Inventory.init(a, expected, .{});
    defer inventory.deinit();
    const geometry = try FusedCodec.geometry(expected, &inventory);
    const rw = inventory.memory.len != 0;
    return .{ .capacity_fused = expected, .expected = .{ .family = .native_fused, .index = expected.index, .policy_digest = @splat(1), .config = expected.config, .roots = .{ expected.native_roots[0], expected.native_roots[1], if (rw) expected.witness_root else @splat(0) }, .root_count = if (rw) 3 else 2, .claim_count = @intCast(inventory.projections.len), .memory_claim_count = @intCast(inventory.memory.len), .geometry = .{ .tree_count = @intCast(geometry.tree_count), .tree_columns = geometry.tree_columns, .max_column_log = geometry.max_log, .max_merkle_log = geometry.max_merkle_log, .sample_width_limits = if (rw) .{ 1, 1, 1, 2, 1 } else .{ 1, 1, 2, 1, 1 } } } };
}

test "capacity bundle typed stack metadata and manifest reject legacy relabel" {
    const CapacityMemoryLoader = @import("block_v5_capacity_word_memory_join_v1.zig").Loader;
    const LegacyMemoryLoader = @import("block_v5_word_memory_join_v1.zig").Loader;
    try std.testing.expect(!@hasField(CapacityMemoryLoader, "take_opcode"));
    try std.testing.expect(@hasField(LegacyMemoryLoader, "take_opcode"));
    var typed_store: Store.Store = undefined;
    const memory_loader = typed_store.executionMemoryLoader();
    const table_loader = typed_store.tableLoader();
    try std.testing.expect(memory_loader.take_external == null);
    try std.testing.expect(table_loader.take_projection == null);
    try std.testing.expect(table_loader.take_caller_state == null);
    try std.testing.expect(table_loader.take_caller_tables == null);
    try std.testing.expect(Store.ProofFor(.native) == @import("block_v5_native_capacity_proof_v1.zig").Proof);
    try std.testing.expect(Store.ProofFor(.native_fused) == @import("block_v5_native_capacity_fused_proof_v1.zig").Proof);
    try std.testing.expect(Store.ProofFor(.native) != StoreModule.ProofFor(.native));
    try std.testing.expect(Store.ProofFor(.rom) == StoreModule.ProofFor(.rom));
    try std.testing.expect(Store.ProofFor(.caller_fused) == StoreModule.ProofFor(.caller_fused));
    try std.testing.expectEqualStrings("B5FILES1", StoreModule.MANIFEST_MAGIC);
    try std.testing.expectEqualStrings("B5CFILE1", Store.MANIFEST_MAGIC);
    try Metadata.requireFormat(Metadata.FORMAT, Metadata.VERSION);
    try std.testing.expectError(error.UnsupportedV5ReceiverPolicy, Metadata.requireFormat(@import("block_v5_cpu_receiver_policy_file_v1.zig").FORMAT, Metadata.VERSION));
    try std.testing.expectError(error.UnsupportedV5ReceiverPolicy, Metadata.requireFormat(Metadata.FORMAT, Metadata.VERSION + 1));
    var name: [96]u8 = undefined;
    try std.testing.expectEqualStrings("block-v5-capacity-native-0.proof", try Store.fileName(&name, .native, 0));
    try std.testing.expectEqualStrings("block-v5-native-0.proof", try StoreModule.fileName(&name, .native, 0));
}

test "capacity bundle literal native publication consumes only success and reloads genuine wire type" {
    const a = std.testing.allocator;
    var shape = Fixture.shape(5);
    const policy = try nativePolicy(a, &shape);
    var fixture = try Fixture.Fixture.init(a, &shape, true);
    defer fixture.deinit();
    const literal = fixture.capacity();
    const raw = try NativeCodec.encode(a, &literal, policy.native.?, .{});
    defer a.free(raw);
    var proof = try NativeCodec.decode(a, raw, policy.native.?, .{});
    var owns = true;
    defer if (owns) proof.deinit(a);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var capped = limits;
    capped.max_total_bytes = raw.len - 1;
    var failed = try Store.Store.initWriter(a, tmp.dir, &.{policy}, Fixture.config, capped);
    defer failed.deinit();
    try std.testing.expectError(error.V5BundleTotalResourceLimit, failed.put(.native, 0, &proof));
    const after = try NativeCodec.encode(a, &proof, policy.native.?, .{});
    defer a.free(after);
    try std.testing.expectEqualSlices(u8, raw, after);
    var writer = try Store.Store.initWriter(a, tmp.dir, &.{policy}, Fixture.config, limits);
    defer writer.deinit();
    try writer.put(.native, 0, &proof);
    owns = false;
    const files = try writer.filePins(a);
    defer a.free(files);
    const sha = try Store.writePins(a, tmp.dir, files, limits);
    var manifest = try Store.readPins(a, tmp.dir, sha, limits);
    defer manifest.deinit();
    var reader = try Store.Store.initReader(a, tmp.dir, &.{policy}, manifest.files, Fixture.config, limits);
    defer reader.deinit();
    var loaded = try reader.take(.native, 0);
    defer loaded.deinit(a);
    try std.testing.expectEqualDeep(policy.native.?.instance_id, loaded.instance_id);
    try reader.requireConsumed();
    try std.testing.expectError(error.RepeatedV5BundleLoad, reader.take(.native, 0));
    const file_bytes = try Store.readPinned(a, tmp.dir, files[0], limits);
    defer a.free(file_bytes);
    try std.testing.expectEqualStrings("B5CTART1", file_bytes[0..8]);
    try std.testing.expectError(error.InvalidNativeV3WireMagic, @import("block_v5_native_codec_v3.zig").decode(a, file_bytes, Fixture.legacyExpected(&shape), .{}));
    const manifest_bytes = try tmp.dir.readFileAlloc(a, Store.MANIFEST, 4096);
    defer a.free(manifest_bytes);
    try @import("block_v5_artifact_files_v1.zig").publish(tmp.dir, StoreModule.MANIFEST, manifest_bytes);
    const legacy_limits: StoreModule.Limits = .{ .max_files = limits.max_files, .max_file_bytes = limits.max_file_bytes, .max_total_bytes = limits.max_total_bytes, .max_metadata_bytes = limits.max_metadata_bytes, .max_manifest_bytes = limits.max_manifest_bytes, .max_claims = limits.max_claims, .max_proof_bytes = limits.max_proof_bytes };
    try std.testing.expectError(error.InvalidV5BundleManifest, StoreModule.readPins(a, tmp.dir, sha, legacy_limits));
}

test "capacity bundle literal fused four and five tree source counts roots caps are independent" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |rw| {
        var shape = FusedFixture.shape(rw);
        const expected = try FusedFixture.expected(a, &shape);
        const policy = try fusedPolicy(a, expected);
        try policy.validate(a, expected.config, limits);
        var changed = policy;
        changed.expected.memory_claim_count += 1;
        // Generic root/tree grammar may reject first; neither path may admit.
        if (changed.validate(a, expected.config, limits)) |_| return error.ChangedCapacityCensusAccepted else |err| if (err == error.OutOfMemory) return err;
        changed = policy;
        changed.expected.geometry.tree_columns[1] -= 1;
        try std.testing.expectError(error.UntrustedV5CapacityFusedPolicy, changed.validate(a, expected.config, limits));
        changed = policy;
        changed.capacity_fused.?.sealed_digest[0] = 0;
        changed.capacity_fused.?.witness_root = @splat(0);
        try std.testing.expectError(error.UntrustedCapacityFusedWirePolicy, changed.validate(a, expected.config, limits));
        var tiny = limits;
        tiny.max_claims = 1;
        try std.testing.expectError(error.UntrustedV5BundleSecurity, policy.validate(a, expected.config, tiny));
        var fixture = try FusedFixture.Fixture.init(a, expected);
        defer fixture.deinit();
        const raw = try FusedCodec.encode(a, &fixture.proof, expected, .{});
        defer a.free(raw);
        var proof = try FusedCodec.decode(a, raw, expected, .{});
        var owns = true;
        defer if (owns) proof.deinit(a);
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var writer = try Store.Store.initWriter(a, tmp.dir, &.{policy}, expected.config, limits);
        defer writer.deinit();
        try writer.put(.native_fused, 0, &proof);
        owns = false;
        const files = try writer.filePins(a);
        defer a.free(files);
        var reader = try Store.Store.initReader(a, tmp.dir, &.{policy}, files, expected.config, limits);
        defer reader.deinit();
        var decoded = try reader.take(.native_fused, 0);
        defer decoded.deinit(a);
        try std.testing.expectEqual(@as(usize, if (rw) 5 else 4), decoded.stark.commitment_scheme_proof.commitments.items.len);
        try reader.requireConsumed();
    }
}

test "capacity bundle metadata and policy resource caps precede decoded authority" {
    const a = std.testing.allocator;
    const bad: Metadata.Limits = .{ .max_file_bytes = 0, .max_owned_bytes = 0, .max_executions = 0, .max_roster_entries = 0, .max_program_words = 0, .max_schedule_wires = 0 };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(error.InvalidV5ReceiverPolicyLimits, Metadata.read(a, tmp.dir, @splat(1), undefined, bad));
    try std.testing.expectError(error.InvalidV5ReceiverPolicyLimits, Metadata.write(a, tmp.dir, undefined, undefined, bad));
    var invalid = limits;
    invalid.max_files = 0;
    try std.testing.expectError(error.InvalidV5BundleStoreLimits, @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(true).build(a, undefined, invalid));
}

test "capacity bundle both fresh detached consumers and policy store bodies retained never invoked" {
    inline for (.{ false, true }) |capacity| {
        const S = StoreModule.ForCapacity(capacity);
        const P = @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(capacity);
        const M = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(capacity);
        const D = @import("block_v5_cpu_detached_receive_v1.zig").ForCapacity(capacity);
        inline for (.{ &P.build, &P.collect, &P.validateStructure, &M.read, &M.write, &D.verify, &S.Store.initWriter, &S.Store.initReader }) |body| std.mem.doNotOptimizeAway(body);
        var store: S.Store = undefined;
        std.mem.doNotOptimizeAway(store.programLoader());
        std.mem.doNotOptimizeAway(store.tableLoader());
        std.mem.doNotOptimizeAway(store.executionMemoryLoader());
        std.mem.doNotOptimizeAway(store.packedMemoryLoader());
        std.mem.doNotOptimizeAway(store.executionSink());
        std.mem.doNotOptimizeAway(store.fusedSink());
        std.mem.doNotOptimizeAway(store.callerSink(@import("block_v5_caller_pipeline_v1.zig").Sink));
    }
}

fn allocationAdmission(a: std.mem.Allocator, expected: FusedCodec.Expected) !void {
    const policy = try fusedPolicy(a, expected);
    try policy.validate(a, expected.config, limits);
}
test "capacity bundle fused policy all allocation failures release derived inventories" {
    var shape = FusedFixture.shape(true);
    const expected = try FusedFixture.expected(std.testing.allocator, &shape);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationAdmission, .{expected});
}

fn separateProofOwner(proof_allocator: std.mem.Allocator, dir: std.fs.Dir, policy: Store.Policy, pin: Store.FilePin) !void {
    var metadata = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var reader = try Store.Store.initReader(metadata.allocator(), dir, &.{policy}, &.{pin}, Fixture.config, limits);
    var live = true;
    defer if (live) reader.deinit();
    const admitted_allocations = metadata.alloc_index;
    metadata.fail_index = admitted_allocations;
    var bound = reader.withProofAllocator(proof_allocator);
    const callbacks = bound.programLoader();
    var proof = callbacks.take_native(callbacks.context, 0) catch |err| {
        try std.testing.expectError(error.RepeatedV5BundleLoad, reader.takeWithAllocator(proof_allocator, .native, 0));
        try reader.requireConsumed();
        try std.testing.expect(!metadata.has_induced_failure);
        return err;
    };
    defer proof.deinit(proof_allocator);
    try reader.requireConsumed();
    try std.testing.expectError(error.RepeatedV5BundleLoad, reader.take(.native, 0));
    try std.testing.expectEqual(admitted_allocations, metadata.alloc_index);
    try std.testing.expect(!metadata.has_induced_failure);
    reader.deinit();
    live = false;
    // Literal transport only: the decoded original proof type outlives all
    // metadata allocations. No STARK verification or proof authority is claimed.
    try std.testing.expectEqualDeep(policy.native.?.instance_id, proof.instance_id);
    try std.testing.expectEqualDeep(policy.expected.roots[0], proof.stark.commitment_scheme_proof.commitments.items[0]);
}
test "bundle reader reuse: separate proof allocator outlives metadata with consuming OOM rollback" {
    const a = std.testing.allocator;
    var shape = Fixture.shape(5);
    const policy = try nativePolicy(a, &shape);
    var literal = try Fixture.Fixture.init(a, &shape, true);
    defer literal.deinit();
    const proof = literal.capacity();
    const bytes = try NativeCodec.encode(a, &proof, policy.native.?, .{});
    defer a.free(bytes);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path: [96]u8 = undefined;
    try @import("block_v5_artifact_files_v1.zig").publish(tmp.dir, try Store.fileName(&path, .native, 0), bytes);
    const pin = Store.FilePin{ .family = .native, .index = 0, .byte_len = bytes.len, .sha256 = Store.hash(bytes) };
    try std.testing.checkAllAllocationFailures(a, separateProofOwner, .{ tmp.dir, policy, pin });
}
