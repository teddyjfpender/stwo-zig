const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const campaign =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const complete_mod =
    @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4.zig");
const manifest =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");

const shared = frontend.recursion.segment_shared_poseidon_schedule_v2;

test "row34 geometry binds transcript child IO publication and verifier core" {
    var authority = try campaign.testing.mintOwnedFromObservations(
        std.testing.allocator,
        identity(41),
        &[_]u32{ 5, 3 },
        &[_][32]u8{ identity(71), identity(101) },
    );
    defer authority.deinit();
    try std.testing.expectEqual(
        @as(u32, 144),
        authority.view().provider_geometry.provider_active_row_count,
    );

    const transcript_count: usize = 64;
    const child_io_hash_count: usize = 32;
    const publication_count: usize = 144;
    const native_identity_count: usize = 32;
    const verifier_core_count: usize = 64;
    const statement_authority_count = child_io_hash_count + publication_count + native_identity_count;
    const total = transcript_count + statement_authority_count +
        verifier_core_count;
    const calls = try std.testing.allocator.alloc(shared.Call, total);
    defer std.testing.allocator.free(calls);
    for (calls) |*call| call.* = .{
        .input = [_]u32{0} ** 16,
        .io = true,
    };
    const layout = try shared.SharedPoseidonCallLayoutV2.initComplete(
        transcript_count,
        statement_authority_count,
        verifier_core_count,
        calls,
    );
    const complete = try complete_mod.CompleteProviderGeometryV4.mint(
        &layout,
        calls,
        .{
            .child_io_hash = child_io_hash_count,
            .field_publication = publication_count,
            .native_identity_hash = native_identity_count,
        },
        9,
    );
    try complete.validate();
    try std.testing.expectEqual(@as(u16, 5), complete.schema_version);
    try std.testing.expectEqual(@as(u32, native_identity_count), complete.native_identity_hash_call_count);
    try std.testing.expect(!@hasField(complete_mod.StatementAuthorityCallCountsV4, "child_claim_hash"));
    try std.testing.expect(!@hasField(complete_mod.CompleteProviderGeometryV4, "child_claim_hash_call_count"));
    var old_schema = complete;
    old_schema.schema_version = 3;
    try std.testing.expectError(error.EthereumIncrementalCompleteProviderGeometryMismatchV4, old_schema.validate());
    try std.testing.expectEqual(@as(u32, total), complete.total_call_count);
    try std.testing.expectEqual(@as(u32, 9), complete.provider_log_size);

    var logs = [_]u32{4} ** manifest.COMPONENT_COUNT;
    logs[@intFromEnum(manifest.ComponentKey.poseidon2)] = 9;
    logs[@intFromEnum(manifest.ComponentKey.range_check_8_8)] = 16;
    const value = try manifest.buildForCampaignAuthority(
        logs,
        &authority,
        complete,
    );
    try manifest.validateExactForCampaignAuthority(
        &value,
        logs,
        &authority,
        complete,
    );
    // A valid receipt cannot relabel native identity work as campaign
    // publication work, even while preserving the full call count.
    const mislabeled = try complete_mod.CompleteProviderGeometryV4.mint(&layout, calls, .{
        .child_io_hash = child_io_hash_count,
        .field_publication = publication_count + native_identity_count,
    }, 9);
    try std.testing.expectError(error.EthereumIncrementalUniversalManifestMismatchV4, manifest.buildForCampaignAuthority(logs, &authority, mislabeled));
    var changed_identity_count = complete;
    changed_identity_count.native_identity_hash_call_count -= 1;
    try std.testing.expectError(error.EthereumIncrementalCompleteProviderGeometryMismatchV4, changed_identity_count.validate());
    const public_program = identity(131);
    const admitted = try manifest.identitiesWithPublicSumsProgram(logs, &authority, complete, public_program);
    const expected = try manifest.bindPublicSumsProgram(
        try manifest.contractIdentity(logs, &authority, complete),
        value.seal,
        public_program,
    );
    try std.testing.expectEqualDeep(expected, admitted);
    var different_program = public_program;
    different_program[0] ^= 1;
    const changed = try manifest.identitiesWithPublicSumsProgram(logs, &authority, complete, different_program);
    try std.testing.expect(!std.meta.eql(admitted, changed));
    try std.testing.expect(!std.mem.eql(u8, &admitted.contract, &try manifest.contractIdentity(logs, &authority, complete)));

    var publication_only_logs = logs;
    publication_only_logs[@intFromEnum(manifest.ComponentKey.poseidon2)] =
        authority.view().provider_geometry.provider_log_size;
    try std.testing.expectError(
        error.EthereumIncrementalUniversalManifestMismatchV4,
        manifest.buildForCampaignAuthority(
            publication_only_logs,
            &authority,
            complete,
        ),
    );
}

test "publication boundary receipt cannot mint complete row34 geometry" {
    const transcript_count: usize = 64;
    const publication_count: usize = 144;
    const calls = try std.testing.allocator.alloc(
        shared.Call,
        transcript_count + publication_count,
    );
    defer std.testing.allocator.free(calls);
    for (calls) |*call| call.* = .{
        .input = [_]u32{0} ** 16,
        .io = true,
    };
    const boundary = try shared.SharedPoseidonCallLayoutV2.initBoundaryPrefix(
        transcript_count,
        publication_count,
        calls,
    );
    try std.testing.expectError(
        error.EthereumIncrementalCompleteProviderGeometryMismatchV4,
        complete_mod.CompleteProviderGeometryV4.mint(
            &boundary,
            calls,
            .{
                .child_io_hash = 16,
                .field_publication = publication_count - 16,
            },
            8,
        ),
    );
}

test "row34 receipt rejects publication-only authority subdivision" {
    const transcript_count: usize = 64;
    const publication_count: usize = 144;
    const verifier_core_count: usize = 64;
    const total = transcript_count + publication_count + verifier_core_count;
    const calls = try std.testing.allocator.alloc(shared.Call, total);
    defer std.testing.allocator.free(calls);
    for (calls) |*call| call.* = .{
        .input = [_]u32{0} ** 16,
        .io = true,
    };
    const layout = try shared.SharedPoseidonCallLayoutV2.initComplete(
        transcript_count,
        publication_count,
        verifier_core_count,
        calls,
    );
    try std.testing.expectError(
        error.EthereumIncrementalCompleteProviderGeometryMismatchV4,
        complete_mod.CompleteProviderGeometryV4.mint(
            &layout,
            calls,
            .{
                .child_io_hash = 0,
                .field_publication = publication_count,
            },
            9,
        ),
    );
}

fn identity(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*value, index|
        value.* = seed +% @as(u8, @intCast(index));
    return result;
}
