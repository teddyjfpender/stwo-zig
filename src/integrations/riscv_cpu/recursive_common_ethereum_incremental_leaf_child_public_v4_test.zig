const std = @import("std");

const subject =
    @import("recursive_common_ethereum_incremental_leaf_child_public_v4.zig");

test "child-public binding rejects a resealed claim-hash drift" {
    const claim = digest(101);
    const input = digest(211);
    const output = digest(307);
    var value = subject.ChildPublicBindingV4{
        .stage101_capability_identity_sha256 = identity(11),
        .role_io_identity_sha256 = identity(43),
        .field_source_digest = digest(59),
        .statement_words_identity_sha256 = identity(71),
        .claim_words_identity_sha256 = identity(83),
        .claim_digest = claim,
        .claim_hash_output_digest = claim,
        .public_input_digest = input,
        .public_output_digest = output,
        .io_hash_output_digests = .{ input, output },
        .child_claim_hash_call_count = 33,
        .child_io_hash_call_count = 67,
        .identity_sha256 = undefined,
    };
    value = subject.testing.resealBinding(value);
    try value.validate();

    var drift = value;
    drift.claim_hash_output_digest[0] += 1;
    drift = subject.testing.resealBinding(drift);
    try std.testing.expectError(
        error.EthereumIncrementalChildPublicMismatchV4,
        drift.validate(),
    );
}

test "child-public binding rejects an independently resealed IO hash" {
    const claim = digest(401);
    const input = digest(503);
    const output = digest(607);
    var value = subject.ChildPublicBindingV4{
        .stage101_capability_identity_sha256 = identity(19),
        .role_io_identity_sha256 = identity(29),
        .field_source_digest = digest(37),
        .statement_words_identity_sha256 = identity(47),
        .claim_words_identity_sha256 = identity(57),
        .claim_digest = claim,
        .claim_hash_output_digest = claim,
        .public_input_digest = input,
        .public_output_digest = output,
        .io_hash_output_digests = .{ input, output },
        .child_claim_hash_call_count = 17,
        .child_io_hash_call_count = 35,
        .identity_sha256 = undefined,
    };
    value = subject.testing.resealBinding(value);
    try value.validate();

    var drift = value;
    drift.io_hash_output_digests[1][3] += 1;
    drift = subject.testing.resealBinding(drift);
    try std.testing.expectError(
        error.EthereumIncrementalChildPublicMismatchV4,
        drift.validate(),
    );
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn identity(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
