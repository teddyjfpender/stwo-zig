//! One canonical, allocation-free manifest encoder. Session hashing and byte
//! emission both call these functions; there is no second hash preimage.

const std = @import("std");
const hash = @import("hash.zig");
const types = @import("types.zig");

pub const HEADER_ENCODED_LEN: usize =
    8 + 2 + 2 + types.AGGREGATION_PROFILE_TAG.len +
    32 + 2 + 32 + 32 + 4 + 2 + 2 + 4 + 32 + 1 + 7 + 4;

pub const DESCRIPTOR_ENCODED_LEN: usize =
    4 + 4 + 1 + 1 + 2 +
    32 + 32 + 32 + 32 + 32 + 32 + 8 + 32 + 2 + 2 + 32 + 32 + 4 + 2 + 2;

pub fn encodedLen(descriptor_count: usize) !usize {
    const descriptors_len = std.math.mul(
        usize,
        descriptor_count,
        DESCRIPTOR_ENCODED_LEN,
    ) catch return error.ManifestTooLarge;
    return std.math.add(usize, HEADER_ENCODED_LEN, descriptors_len) catch
        return error.ManifestTooLarge;
}

pub fn writeHeader(
    sink: anytype,
    header: types.ManifestHeaderV1,
    descriptor_count: u32,
) !void {
    try sink.writeAll(&header.magic);
    try hash.writeU16(sink, header.version);
    try hash.writeU16(sink, header.aggregation_profile_id);
    try sink.writeAll(types.AGGREGATION_PROFILE_TAG);
    try sink.writeAll(&header.proof_protocol_digest);
    try hash.writeU16(sink, header.execution_profile_id);
    try sink.writeAll(&header.execution_semantic_digest);
    try sink.writeAll(&header.relation_registry_digest);
    try hash.writeU32(sink, header.relation_schema_id);
    try hash.writeU16(sink, header.relation_schema_version);
    try hash.writeU16(sink, header.relation_arity);
    try hash.writeU32(sink, header.leaf_count);
    try sink.writeAll(&header.request_set_digest);
    try sink.writeAll(&.{@intFromEnum(header.tree_policy)});
    try sink.writeAll(&header.reserved);
    try hash.writeU32(sink, descriptor_count);
}

pub fn writeDescriptor(
    sink: anytype,
    descriptor: types.LeafDescriptorV1,
) !void {
    try hash.writeU32(sink, descriptor.leaf_index);
    try hash.writeU32(sink, descriptor.pair_index);
    try sink.writeAll(&.{@intFromEnum(descriptor.role)});
    try sink.writeAll(&.{descriptor.flags});
    try hash.writeU16(sink, descriptor.reserved);
    try sink.writeAll(&descriptor.job_digest);
    try sink.writeAll(&descriptor.leaf_statement_digest);
    try sink.writeAll(&descriptor.leaf_air_artifact_digest);
    try sink.writeAll(&descriptor.preprocessed_root);
    try sink.writeAll(&descriptor.main_root);
    try sink.writeAll(&descriptor.guest_call_commitment);
    try hash.writeU64(sink, descriptor.guest_call_count);
    try sink.writeAll(&descriptor.proof_protocol_digest);
    try hash.writeU16(sink, descriptor.execution_profile_id);
    try hash.writeU16(sink, descriptor.relation_schema_version);
    try sink.writeAll(&descriptor.execution_semantic_digest);
    try sink.writeAll(&descriptor.relation_registry_digest);
    try hash.writeU32(sink, descriptor.relation_schema_id);
    try hash.writeU16(sink, descriptor.relation_arity);
    try hash.writeU16(sink, descriptor.reserved_tail);
}

pub fn hashDescriptor(descriptor: types.LeafDescriptorV1) hash.Digest {
    var sink = hash.HashSink.init(hash.DESCRIPTOR_DOMAIN);
    writeDescriptor(&sink, descriptor) catch unreachable;
    return sink.finalize();
}
