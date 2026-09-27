const std = @import("std");
const Store = @import("block_v5_cpu_bundle_store_v1.zig");
const Policy = @import("block_v5_cpu_bundle_policy_v1.zig");
const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig");
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
const limits = Store.Limits{ .max_files = 32, .max_file_bytes = 4096, .max_total_bytes = 8192, .max_metadata_bytes = 1024 * 1024, .max_manifest_bytes = 4096, .max_claims = 32, .max_proof_bytes = 2048 };

test "block-v5 durable bundle APIs retain typed all-family ownership" {
    var store: Store.Store = undefined;
    _ = store.programLoader();
    _ = store.tableLoader();
    _ = store.executionMemoryLoader();
    _ = store.packedMemoryLoader();
    _ = store.executionSink();
    _ = store.nativeLookupSink();
    _ = store.fusedSink();
    _ = store.providerSink();
    _ = store.packedMemorySink();
    _ = store.callerSink(@import("block_v5_caller_pipeline_v1.zig").Sink);
    _ = store.callback(.opcode_memory);
}
test "block-v5 durable file roster is bounded canonical SHA pinned and single use" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = "structurally invalid proof";
    var path_buffer: [96]u8 = undefined;
    const path = try Store.fileName(&path_buffer, .rom, 0);
    var file = try tmp.dir.createFile(path, .{ .exclusive = true });
    try file.writeAll(bytes);
    file.close();
    const pins = [_]Store.FilePin{.{ .family = .rom, .index = 0, .byte_len = bytes.len, .sha256 = Store.hash(bytes) }};
    const sha = try Store.writePins(a, tmp.dir, &pins, limits);
    var loaded = try Store.readPins(a, tmp.dir, sha, limits);
    defer loaded.deinit();
    try std.testing.expectEqualDeep(pins[0], loaded.files[0]);
    var wrong = sha;
    wrong[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleManifest, Store.readPins(a, tmp.dir, wrong, limits));
    const config = Profile.diagnostic_q8_pow0.config();
    const policies = [_]Store.Policy{.{ .expected = .{ .family = .rom, .index = 0, .policy_digest = @splat(1), .config = config, .roots = .{ @splat(2), @splat(3), @splat(0) }, .claim_count = 1, .geometry = .{ .tree_count = 4, .tree_columns = .{ 6, 0, 4, 16, 0 }, .max_column_log = 6, .max_merkle_log = 7, .sample_width_limits = .{ 2, 6, 2, 1, 1 }, .allow_empty_main_tree = true } } }};
    var reader = try Store.Store.initReader(a, tmp.dir, &policies, loaded.files, config, limits);
    defer reader.deinit();
    try std.testing.expectError(error.IncompleteV5BundleConsumption, reader.requireConsumed());
    const first = reader.take(.rom, 0);
    if (first) |proof_value| {
        var proof = proof_value;
        proof.deinit(a);
        return error.InvalidProofAccepted;
    } else |_| {}
    try std.testing.expectError(error.RepeatedV5BundleLoad, reader.take(.rom, 0));
    try reader.requireConsumed();
    var tiny = limits;
    tiny.max_total_bytes = bytes.len - 1;
    try std.testing.expectError(error.V5BundleTotalResourceLimit, Store.Store.initReader(a, tmp.dir, &policies, loaded.files, config, tiny));
    try std.testing.expectError(error.NoncanonicalV5BundleFiles, Store.writePins(a, tmp.dir, &.{ pins[0], pins[0] }, limits));
}
test "block-v5 independent metadata and geometry builders validate caps before pins" {
    const invalid = Metadata.Limits{ .max_file_bytes = 0, .max_owned_bytes = 0, .max_executions = 0, .max_roster_entries = 0, .max_program_words = 0, .max_schedule_wires = 0 };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(error.InvalidV5ReceiverPolicyLimits, Metadata.write(std.testing.allocator, tmp.dir, undefined, undefined, invalid));
    try std.testing.expectError(error.InvalidV5ReceiverPolicyLimits, Metadata.read(std.testing.allocator, tmp.dir, @splat(1), undefined, invalid));
    var invalid_store = limits;
    invalid_store.max_files = 0;
    try std.testing.expectError(error.InvalidV5BundleStoreLimits, Policy.build(std.testing.allocator, undefined, invalid_store));
}

test {
    _ = @import("block_v5_cpu_counting_writer_v1.zig");
}

test "block-v5 fused canonical transport and global consumer APIs compile without proving" {
    const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Global = @import("block_v5_global_receiver_v1.zig").ForBackend(Cpu);
    const Programs = @import("block_v5_program_native_batch_receiver_v3.zig").ForBackend(Cpu);
    const FusedReceiver = @import("block_v5_native_projection_fused_receiver_v2.zig").ForBackend(Cpu);
    const put: *const @TypeOf(putFused) = &putFused;
    const take: *const @TypeOf(takeFused) = &takeFused;
    std.mem.doNotOptimizeAway(put);
    std.mem.doNotOptimizeAway(take);
    const encode: *const @TypeOf(encodeFused) = &encodeFused;
    const decode: *const @TypeOf(decodeFused) = &decodeFused;
    std.mem.doNotOptimizeAway(encode);
    std.mem.doNotOptimizeAway(decode);
    const programs: *const @TypeOf(Programs.verifyWithCompositeHooks) = &Programs.verifyWithCompositeHooks;
    const globals: *const @TypeOf(Global.verifyGlobals) = &Global.verifyGlobals;
    const empty: *const @TypeOf(FusedReceiver.verifyOwned) = &FusedReceiver.verifyOwned;
    const policy: *const @TypeOf(Policy.collect) = &Policy.collect;
    const assembly: *const @TypeOf(@import("block_v5_cpu_assembly_v1.zig").assemble) = &@import("block_v5_cpu_assembly_v1.zig").assemble;
    std.mem.doNotOptimizeAway(programs);
    std.mem.doNotOptimizeAway(globals);
    std.mem.doNotOptimizeAway(empty);
    std.mem.doNotOptimizeAway(policy);
    std.mem.doNotOptimizeAway(assembly);
    try std.testing.expectEqual(@as(u32, 14), @intFromEnum(Codec.Family.native_fused));
}

fn putFused(store: *Store.Store, index: u32, proof: *@import("block_v5_native_projection_fused_proof_v2.zig").Proof) !void {
    return store.put(.native_fused, index, proof);
}
fn takeFused(store: *Store.Store, index: u32) !@import("block_v5_native_projection_fused_proof_v2.zig").Proof {
    return store.take(.native_fused, index);
}
fn encodeFused(a: std.mem.Allocator, proof: *const @import("block_v5_native_projection_fused_proof_v2.zig").Proof, expected: @import("block_v5_cpu_stark_codec_v1.zig").Expected, caps: @import("block_v5_cpu_stark_codec_v1.zig").Limits) ![]u8 {
    return @import("block_v5_cpu_stark_codec_v1.zig").encode(.native_fused, a, proof, expected, caps);
}
fn decodeFused(a: std.mem.Allocator, raw: []const u8, expected: @import("block_v5_cpu_stark_codec_v1.zig").Expected, caps: @import("block_v5_cpu_stark_codec_v1.zig").Limits) !@import("block_v5_native_projection_fused_proof_v2.zig").Proof {
    return @import("block_v5_cpu_stark_codec_v1.zig").decode(.native_fused, a, raw, expected, caps);
}

test "block-v5 fused transport rejects separate format and unpinned envelope before allocation" {
    const a = std.testing.allocator;
    const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
    const config = Profile.diagnostic_q8_pow0.config();
    const expected = Codec.Expected{ .family = .native_fused, .index = 7, .policy_digest = @splat(1), .config = config, .roots = .{ @splat(2), @splat(3), @splat(0) }, .claim_count = 2, .geometry = .{ .tree_count = 4, .tree_columns = .{ 2, 18, 8, 16, 0 }, .max_column_log = 1, .max_merkle_log = 1, .sample_width_limits = .{ 2, 6, 2, 1, 1 } } };
    var raw: [64]u8 = @splat(0);
    @memcpy(raw[0..8], "B5STOR01");
    std.mem.writeInt(u32, raw[12..16], 7, .little);
    @memcpy(raw[16..48], &expected.policy_digest);
    std.mem.writeInt(u32, raw[48..52], 2, .little);
    for ([_]Codec.Family{ .request, .native_projection }) |old| {
        std.mem.writeInt(u32, raw[8..12], @intFromEnum(old), .little);
        try std.testing.expectError(error.UntrustedV5BundleEnvelope, Codec.decode(.native_fused, a, &raw, expected, .{ .artifact_bytes = 4096, .proof_bytes = 2048, .max_claims = 32 }));
    }
    std.mem.writeInt(u32, raw[8..12], @intFromEnum(Codec.Family.native_fused), .little);
    raw[16] ^= 1;
    try std.testing.expectError(error.UntrustedV5BundleEnvelope, Codec.decode(.native_fused, a, &raw, expected, .{ .artifact_bytes = 4096, .proof_bytes = 2048, .max_claims = 32 }));
    raw[16] ^= 1;
    std.mem.writeInt(u32, raw[48..52], 3, .little);
    try std.testing.expectError(error.UntrustedV5BundleEnvelope, Codec.decode(.native_fused, a, &raw, expected, .{ .artifact_bytes = 4096, .proof_bytes = 2048, .max_claims = 32 }));
}

test "block-v5 fused transport independently pins secondary census and tree grammar" {
    const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
    var expected = Codec.Expected{ .family = .native_fused, .index = 0, .policy_digest = @splat(1), .config = Profile.diagnostic_q8_pow0.config(), .roots = .{ @splat(2), @splat(3), @splat(4) }, .claim_count = 2, .geometry = .{ .tree_count = 4, .tree_columns = .{ 2, 18, 8, 16, 0 }, .max_column_log = 1, .max_merkle_log = 1, .sample_width_limits = .{ 2, 6, 2, 1, 1 } } };
    try expected.validate();
    expected.memory_claim_count = 1;
    try std.testing.expectError(error.InvalidV5BundleExpected, expected.validate());
    expected.root_count = 3;
    expected.geometry.tree_count = 5;
    expected.geometry.tree_columns = .{ 2, 18, 40, 40, 16 };
    expected.geometry.sample_width_limits = .{ 2, 6, 1, 2, 1 };
    try expected.validate();
    expected.memory_claim_count = 0;
    try std.testing.expectError(error.InvalidV5BundleExpected, expected.validate());
    expected.memory_claim_count = 1;
    expected.family = .opcode_memory;
    try std.testing.expectError(error.InvalidV5BundleExpected, expected.validate());
}

test "block-v5 fused transport rejects secondary census before proof parsing or allocation" {
    const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
    const expected = Codec.Expected{ .family = .native_fused, .index = 0, .policy_digest = @splat(1), .config = Profile.diagnostic_q8_pow0.config(), .roots = .{ @splat(2), @splat(3), @splat(4) }, .root_count = 3, .claim_count = 1, .memory_claim_count = 1, .geometry = .{ .tree_count = 5, .tree_columns = .{ 2, 18, 40, 40, 16 }, .max_column_log = 1, .max_merkle_log = 1, .sample_width_limits = .{ 2, 6, 1, 2, 1 } } };
    var raw: [69]u8 = @splat(0);
    @memcpy(raw[0..8], "B5STOR01");
    std.mem.writeInt(u32, raw[8..12], @intFromEnum(Codec.Family.native_fused), .little);
    @memcpy(raw[16..48], &expected.policy_digest);
    std.mem.writeInt(u32, raw[48..52], expected.claim_count, .little);
    std.mem.writeInt(u32, raw[52..56], 4, .little);
    std.mem.writeInt(u64, raw[56..64], 1, .little);
    // The one proof byte is deliberately invalid; count admission must fail
    // first, without scanning that proof or using any allocator storage.
    std.mem.writeInt(u32, raw[64..68], std.math.maxInt(u32), .little);
    var storage: [0]u8 = .{};
    var empty = std.heap.FixedBufferAllocator.init(&storage);
    try std.testing.expectError(error.UntrustedV5BundleMemoryClaimCount, Codec.decode(.native_fused, empty.allocator(), &raw, expected, .{ .artifact_bytes = 4096, .proof_bytes = 2048, .max_claims = 32 }));
    const tiny = Codec.Limits{ .artifact_bytes = 4096, .proof_bytes = 2048, .max_claims = 1 };
    try std.testing.expectError(error.UntrustedV5BundleProofPolicy, Codec.decode(.native_fused, empty.allocator(), &raw, expected, tiny));
}

fn putCallerFused(store: *Store.Store, index: u32, proof: *@import("block_v5_caller_fused_proof_v1.zig").Proof) !void {
    return store.put(.caller_fused, index, proof);
}
fn takeCallerFused(store: *Store.Store, index: u32) !@import("block_v5_caller_fused_proof_v1.zig").Proof {
    return store.take(.caller_fused, index);
}
fn encodeCallerFused(a: std.mem.Allocator, proof: *const @import("block_v5_caller_fused_proof_v1.zig").Proof, expected: @import("block_v5_cpu_stark_codec_v1.zig").Expected, caps: @import("block_v5_cpu_stark_codec_v1.zig").Limits) ![]u8 {
    return @import("block_v5_cpu_stark_codec_v1.zig").encode(.caller_fused, a, proof, expected, caps);
}
fn decodeCallerFused(a: std.mem.Allocator, raw: []const u8, expected: @import("block_v5_cpu_stark_codec_v1.zig").Expected, caps: @import("block_v5_cpu_stark_codec_v1.zig").Limits) !@import("block_v5_caller_fused_proof_v1.zig").Proof {
    return @import("block_v5_cpu_stark_codec_v1.zig").decode(.caller_fused, a, raw, expected, caps);
}
test "block-v5 caller fused canonical producer transport consumers compile without proving" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    inline for (.{ &putCallerFused, &takeCallerFused, &encodeCallerFused, &decodeCallerFused, &@import("block_v5_caller_pipeline_v1.zig").ForBackend(Cpu).proveStaged, &@import("block_v5_caller_pipeline_v1.zig").ForBackend(Cpu).proveSegment }) |function| std.mem.doNotOptimizeAway(function);
    try std.testing.expectEqual(@as(u32, 15), @intFromEnum(@import("block_v5_cpu_stark_codec_v1.zig").Family.caller_fused));
}
test "block-v5 caller fused transport independently caps all four arrays before allocation" {
    const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
    const expected = Codec.Expected{ .family = .caller_fused, .index = 0, .policy_digest = @splat(1), .config = Profile.diagnostic_q8_pow0.config(), .roots = .{ @splat(2), @splat(3), @splat(4) }, .root_count = 3, .claim_count = 2, .state_claim_count = 2, .table_claim_count = 3, .memory_claim_count = 4, .geometry = .{ .tree_count = 5, .tree_columns = .{ 2, 18, 40, 40, 16 }, .max_column_log = 1, .max_merkle_log = 1, .sample_width_limits = .{ 2, 6, 1, 2, 1 } } };
    try expected.validate();
    try std.testing.expectEqual(@as(u32, 11), try expected.totalClaims());
    var raw: [77]u8 = @splat(0);
    @memcpy(raw[0..8], "B5STOR01");
    std.mem.writeInt(u32, raw[8..12], @intFromEnum(Codec.Family.caller_fused), .little);
    @memcpy(raw[16..48], &expected.policy_digest);
    std.mem.writeInt(u32, raw[48..52], expected.claim_count, .little);
    std.mem.writeInt(u32, raw[52..56], 12, .little);
    std.mem.writeInt(u64, raw[56..64], 1, .little);
    std.mem.writeInt(u32, raw[64..68], expected.memory_claim_count, .little);
    std.mem.writeInt(u32, raw[68..72], expected.state_claim_count, .little);
    std.mem.writeInt(u32, raw[72..76], expected.table_claim_count, .little);
    var storage: [0]u8 = .{};
    var empty = std.heap.FixedBufferAllocator.init(&storage);
    const caps = Codec.Limits{ .artifact_bytes = 4096, .proof_bytes = 2048, .max_claims = 11 };
    std.mem.writeInt(u32, raw[48..52], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.UntrustedV5BundleEnvelope, Codec.decode(.caller_fused, empty.allocator(), &raw, expected, caps));
    std.mem.writeInt(u32, raw[48..52], expected.claim_count, .little);
    for ([_]usize{ 68, 72 }) |offset| {
        const original = std.mem.readInt(u32, raw[offset..][0..4], .little);
        std.mem.writeInt(u32, raw[offset..][0..4], std.math.maxInt(u32), .little);
        try std.testing.expectError(error.UntrustedV5BundleProjectionClaimCount, Codec.decode(.caller_fused, empty.allocator(), &raw, expected, caps));
        std.mem.writeInt(u32, raw[offset..][0..4], original, .little);
    }
    std.mem.writeInt(u32, raw[64..68], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.UntrustedV5BundleMemoryClaimCount, Codec.decode(.caller_fused, empty.allocator(), &raw, expected, caps));
    std.mem.writeInt(u32, raw[64..68], expected.memory_claim_count, .little);
    var too_small = caps;
    too_small.max_claims = 10;
    try std.testing.expectError(error.UntrustedV5BundleProofPolicy, Codec.decode(.caller_fused, empty.allocator(), &raw, expected, too_small));
    for ([_]Codec.Family{ .caller_program, .caller_state, .caller_tables, .external_memory }) |old| {
        std.mem.writeInt(u32, raw[8..12], @intFromEnum(old), .little);
        try std.testing.expectError(error.UntrustedV5BundleEnvelope, Codec.decode(.caller_fused, empty.allocator(), &raw, expected, caps));
    }
    var invalid = expected;
    invalid.state_claim_count = 1;
    try std.testing.expectError(error.InvalidV5BundleExpected, invalid.validate());
    invalid = expected;
    invalid.root_count = 2;
    try std.testing.expectError(error.InvalidV5BundleExpected, invalid.validate());
}
