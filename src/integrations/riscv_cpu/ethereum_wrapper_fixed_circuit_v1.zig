//! Field session namespace derived solely from an admitted fixed root/key.
//! Call buffers, transcript witnesses, public450 values and claims never enter.
const std = @import("std");
const recursion = @import("stwo_riscv_frontend").recursion;
const field = @import("ethereum_wrapper_field_transcript_v1.zig");
pub const VERSION: u32 = 1;

/// The caller admits the fixed key independently. This deterministic projection
/// does not turn an arbitrary key or root into an admission certificate.
pub fn sessionFields(key: anytype) !field.SessionFieldsV1 {
    try key.session_fields.protocol.requireSecure();
    _ = try key.parameters.validate(&key.manifest);
    return sessionFieldsFromValidatedKey(key);
}

/// Pure projection after structural key validation, without repeating AIR or
/// manifest checks. It accepts no witness fields or previous namespace IDs.
pub fn sessionFieldsFromValidatedKey(key: anytype) !field.SessionFieldsV1 {
    var hash = fixedHeader("stwo-zig/ethereum-fixed-field-circuit/v1\x00", .{ VERSION, key.version, key.transcript_version, key.manifest_schema, @import("recursive_common_ethereum_incremental_leaf_transcript_program_types_v4.zig").FIELD_EXECUTION_PROFILE_VERSION }, key.manifest.seal, key.session_fields.protocol, key.preprocessed_root);
    hash.update(&key.parameters.query_reference.authority_digest);
    word(&hash, key.parameters.poseidon_active_rows);
    word(&hash, key.wire_terms.len);
    for (key.wire_terms) |term| {
        word(&hash, term.lane);
        word(&hash, @intFromEnum(term.active_in));
        word(&hash, @intFromEnum(term.role));
        word(&hash, term.circuit_id);
        word(&hash, term.node_id);
        for (term.value.toM31Array()) |value| word(&hash, value.toU32());
        word(&hash, term.multiplicity);
    }
    return namespaceFromDigest(key.session_fields.protocol, hash.finalResult(), .{ 0x4546_564b, 0x4546_4e4b, 0x4546_4150 });
}

/// Shared fixed-circuit prefix. Role domains and version fields are explicit;
/// no public statement, proof bytes or custody identity is accepted here.
pub fn fixedHeader(comptime domain: []const u8, versions: [5]u32, manifest_seal: [32]u8, protocol: @import("recursive_temporal_secure_parent_protocol_v1.zig").AuthorityV1, root: recursion.poseidon2_channel.Digest) std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    for (versions) |version| word(&hash, version);
    hash.update(&manifest_seal);
    hash.update(&protocol.identity_sha256);
    for (root) |value| word(&hash, value);
    return hash;
}

pub fn namespaceFromDigest(protocol: @import("recursive_temporal_secure_parent_protocol_v1.zig").AuthorityV1, fixed_identity: [32]u8, domains: [3]u32) !field.SessionFieldsV1 {
    const result = field.SessionFieldsV1{
        .protocol = protocol,
        .verification_key_id = recursion.poseidon2_channel.hashBytes(&fixed_identity, domains[0]),
        .next_parent_vk_id = recursion.poseidon2_channel.hashBytes(&fixed_identity, domains[1]),
        .air_program_id = recursion.poseidon2_channel.hashBytes(&fixed_identity, domains[2]),
    };
    try result.validate();
    return result;
}

pub fn word(hash: anytype, value: anytype) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
