const std = @import("std");
const subject =
    @import("ethereum_incremental_full_leaf_prepared_authority_parity_v4.zig");

test "Stage101 prepared parity live API type-instantiates" {
    std.testing.refAllDecls(subject);
    std.testing.refAllDecls(
        @import("ethereum_incremental_full_leaf_prepared_replay_producer_v4.zig"),
    );
    try std.testing.expect(!subject.DIGEST_IS_ADMISSION);
}

test "Stage101 prepared and legacy authority snapshots compare exactly" {
    const expected = fixture();
    const result = try subject.compareSnapshots(expected, expected);
    switch (result) {
        .exact => |receipt| {
            try receipt.validate();
            try std.testing.expectEqual(@as(u16, 11), receipt.exact_authority_count);
            try std.testing.expectEqualDeep(expected, receipt.snapshot);
        },
        .mismatch => return error.UnexpectedPreparedAuthorityMismatch,
    }
}

test "Stage101 prepared parity reports every authority class mutation" {
    const expected = fixture();
    inline for ([_]subject.MismatchFieldV1{
        subject.MismatchFieldV1.core_trace,
        .statement,
        .workspace_statement,
        .public_wire,
        .ethereum_witness,
        .extension,
        .base_geometry,
        .bridge_geometry,
        .public_boundary,
        .profile,
        .call_counts,
    }) |field| {
        var changed = expected;
        switch (field) {
            .core_trace => changed.core_trace_sha256[0] ^= 1,
            .statement => changed.statement_authority_id[0] +%= 1,
            .workspace_statement => changed.workspace_statement_authority_id[0] +%= 1,
            .public_wire => changed.public_wire_id[0] +%= 1,
            .ethereum_witness => changed.witness_shapes_sha256[0] ^= 1,
            .extension => changed.extension_identity_sha256[0] ^= 1,
            .base_geometry => changed.base_geometry_identity_sha256[0] ^= 1,
            .bridge_geometry => changed.bridge_geometry_identity_sha256[0] ^= 1,
            .public_boundary => changed.public_boundary_identity_sha256[0] ^= 1,
            .profile => changed.profile_identity_sha256[0] ^= 1,
            .call_counts => {
                changed.keccak_calls += 1;
                changed.external_retirements += 1;
            },
        }
        const result = try subject.compareSnapshots(expected, changed);
        switch (result) {
            .exact => return error.ExpectedPreparedAuthorityMismatch,
            .mismatch => |mismatch| {
                try std.testing.expectEqual(field, mismatch.field);
                try std.testing.expectEqualDeep(expected, mismatch.prepared);
                try std.testing.expectEqualDeep(changed, mismatch.legacy);
            },
        }
    }
}

test "Stage101 prepared parity receipt rejects count and identity drift" {
    const exact = try subject.compareSnapshots(fixture(), fixture());
    var receipt = switch (exact) {
        .exact => |value| value,
        .mismatch => return error.UnexpectedPreparedAuthorityMismatch,
    };
    receipt.exact_authority_count -= 1;
    try std.testing.expectError(
        error.InvalidStage101PreparedAuthorityParityReceiptV4,
        receipt.validate(),
    );
    receipt.exact_authority_count += 1;
    receipt.snapshot.profile_identity_sha256 = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.InvalidStage101PreparedAuthoritySnapshotV4,
        receipt.validate(),
    );
}

fn fixture() subject.AuthoritySnapshotV1 {
    return .{
        .core_trace_sha256 = [_]u8{1} ** 32,
        .statement_authority_id = [_]u32{2} ** 8,
        .workspace_statement_authority_id = [_]u32{2} ** 8,
        .public_wire_id = [_]u32{3} ** 8,
        .witness_shapes_sha256 = [_]u8{4} ** 32,
        .extension_identity_sha256 = [_]u8{5} ** 32,
        .base_geometry_identity_sha256 = [_]u8{6} ** 32,
        .bridge_geometry_identity_sha256 = [_]u8{7} ** 32,
        .public_boundary_identity_sha256 = [_]u8{8} ** 32,
        .profile_identity_sha256 = [_]u8{9} ** 32,
        .keccak_calls = 11,
        .signer_calls = 13,
        .external_retirements = 24,
    };
}
