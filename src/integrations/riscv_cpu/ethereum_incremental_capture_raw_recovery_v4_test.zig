const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("ethereum_incremental_capture_raw_recovery_v4.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");

test "raw recovery manifest roundtrips exact ordered cold inventory" {
    const allocator = std.testing.allocator;
    const execution = try fixtureExecution(3);
    const records = try fixtureRecords(execution);
    const manifest = try fixtureManifest(execution, &records);
    const bytes = try subject.encodeManifestAlloc(allocator, &manifest);
    defer allocator.free(bytes);
    var decoded = try subject.decodeManifestAlloc(allocator, bytes);
    defer decoded.deinit();

    try std.testing.expectEqualDeep(manifest.execution, decoded.value.execution);
    try std.testing.expectEqualDeep(
        manifest.materialization_result,
        decoded.value.materialization_result,
    );
    try std.testing.expectEqualDeep(
        manifest.execution_profile_receipt,
        decoded.value.execution_profile_receipt,
    );
    try std.testing.expectEqual(manifest.records.len, decoded.value.records.len);
    for (manifest.records, decoded.value.records) |expected, actual|
        try std.testing.expectEqualDeep(expected, actual);
    try std.testing.expectEqualSlices(
        u8,
        &manifest.content_sha256,
        &decoded.value.content_sha256,
    );
    try std.testing.expectEqual(
        @as(usize, 412 + 3 * 552 + 32),
        bytes.len,
    );
}

test "resealed recovery manifest rejects lineage and order drift" {
    const execution = try fixtureExecution(3);
    var records = try fixtureRecords(execution);
    records[1].entry_memory_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalRawRecoveryChainV4,
        fixtureManifest(execution, &records),
    );
    records = try fixtureRecords(execution);
    std.mem.swap(
        subject.SegmentRecordV4,
        &records[0],
        &records[1],
    );
    try std.testing.expectError(
        error.InvalidIncrementalRawRecoveryChainV4,
        fixtureManifest(execution, &records),
    );
}

test "resealed recovery manifest rejects empty relabel and role drift" {
    const execution = try fixtureExecution(3);
    var records = try fixtureRecords(execution);
    records[0].role_completion =
        frontend.air.public_data.Completion.canonicalSelfLoop(0x1000);
    try std.testing.expectError(
        error.InvalidIncrementalRawRecoveryRoleV4,
        fixtureManifest(execution, &records),
    );
    records = try fixtureRecords(execution);
    records[2].role_completion =
        frontend.air.public_data.Completion.unretiredProgramFetch(
            0x1008,
            0x13,
        );
    try std.testing.expectError(
        error.InvalidIncrementalRawRecoveryRoleV4,
        fixtureManifest(execution, &records),
    );
}

test "raw recovery codec rejects mutation truncation and trailing bytes" {
    const allocator = std.testing.allocator;
    const execution = try fixtureExecution(3);
    const records = try fixtureRecords(execution);
    const manifest = try fixtureManifest(execution, &records);
    const bytes = try subject.encodeManifestAlloc(allocator, &manifest);
    defer allocator.free(bytes);

    var corrupted = try allocator.dupe(u8, bytes);
    defer allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalRawRecoveryManifestV4,
        subject.decodeManifestAlloc(allocator, corrupted),
    );
    try std.testing.expectError(
        error.InvalidIncrementalRawRecoveryEncodingV4,
        subject.decodeManifestAlloc(allocator, bytes[0 .. bytes.len - 1]),
    );
    const trailing = try std.mem.concat(allocator, u8, &.{ bytes, &.{0} });
    defer allocator.free(trailing);
    try std.testing.expectError(
        error.InvalidIncrementalRawRecoveryEncodingV4,
        subject.decodeManifestAlloc(allocator, trailing),
    );
}

test "recovery contract requires real compact replay and remains inactive" {
    comptime {
        _ = subject.replayAndAttribute;
        _ = subject.OwnedSegmentRecoveryV4.mergeInto;
    }
    try std.testing.expect(subject.PC_ATTRIBUTION_REPLAYED_FROM_COLD_RAW);
    try std.testing.expect(!subject.VM_REEXECUTION_REQUIRED);
    try std.testing.expect(!subject.PRODUCTION_ACTIVE);
}

fn fixtureManifest(
    execution: publication.ExecutionAuthorityV4,
    records: []const subject.SegmentRecordV4,
) !subject.ManifestV4 {
    return subject.ManifestV4.seal(.{
        .execution = execution,
        .materialization_result = identity(20),
        .source_request = identity(30),
        .journal = identity(40),
        .execution_profile_receipt = identity(50),
        .program_identity_sha256 = digest(60),
        .session_identity_sha256 = try execution.sessionIdentity(),
        .segment_count = execution.segment_count,
        .records = records,
        .content_sha256 = undefined,
    });
}

fn fixtureExecution(
    segment_count: u32,
) !publication.ExecutionAuthorityV4 {
    const result = publication.ExecutionAuthorityV4{
        .elf = identity(1),
        .input = identity(2),
        .expected_output = identity(3),
        .execution_profile_semantic_sha256 = digest(4),
        .segment_count = segment_count,
        .segment_step_budget = 1 << 22,
    };
    try result.validate();
    return result;
}

fn fixtureRecords(
    execution: publication.ExecutionAuthorityV4,
) ![3]subject.SegmentRecordV4 {
    var result: [3]subject.SegmentRecordV4 = undefined;
    const session = try execution.sessionIdentity();
    const program = digest(60);
    var prior_memory = digest(70);
    var prior_cpu = digest(80);
    for (&result, 0..) |*record, index| {
        const exit_memory = digest(90 + @as(u8, @intCast(index)));
        const exit_cpu = digest(100 + @as(u8, @intCast(index)));
        record.* = .{
            .segment_index = @intCast(index),
            .segment_count = execution.segment_count,
            .global_first_cycle = 1 + @as(u64, @intCast(index)) * 3,
            .cycle_count = 3,
            .core_cycle_count = 2,
            .keccak_call_count = 1,
            .recovery_call_count = 0,
            .role_completion = if (index + 1 == result.len)
                frontend.air.public_data.Completion.canonicalSelfLoop(
                    0x1000 + @as(u32, @intCast(index * 4)),
                )
            else
                frontend.air.public_data.Completion.unretiredProgramFetch(
                    0x1000 + @as(u32, @intCast(index * 4)),
                    0x13 + @as(u32, @intCast(index)),
                ),
            .compact_tape = identity(110 + @as(u8, @intCast(index))),
            .public_wire = identity(120 + @as(u8, @intCast(index))),
            .source = identity(130 + @as(u8, @intCast(index))),
            .journal_record_sha256 = digest(140 + @as(u8, @intCast(index))),
            .program_identity_sha256 = program,
            .input_identity_sha256 = execution.input.sha256,
            .session_identity_sha256 = session,
            .entry_memory_sha256 = prior_memory,
            .exit_memory_sha256 = exit_memory,
            .entry_boundary_sha256 = digest(150 + @as(u8, @intCast(index))),
            .exit_boundary_sha256 = digest(160 + @as(u8, @intCast(index))),
            .entry_cpu_sha256 = prior_cpu,
            .exit_cpu_sha256 = exit_cpu,
            .leaf_seal_sha256 = digest(170 + @as(u8, @intCast(index))),
            .public_wire_id = wordDigest(180 + @as(u32, @intCast(index * 8))),
        };
        try record.validate();
        prior_memory = exit_memory;
        prior_cpu = exit_cpu;
    }
    return result;
}

fn identity(seed: u8) publication.ArtifactIdentityV4 {
    return .{ .byte_count = seed, .sha256 = digest(seed) };
}

fn digest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn wordDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}
