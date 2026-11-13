//! One byte-level identity authority for live contexts and policy regressions.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const ContextV1 = @import("ethereum_leaf_context.zig").ContextV1;
const ComponentAuthorityV1 = @import("ethereum_leaf_context.zig").ComponentAuthorityV1;
const CONTEXT_DOMAIN = @import("ethereum_leaf_context.zig").CONTEXT_DOMAIN;

pub fn computeIdentityDigest(self: *const ContextV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CONTEXT_DOMAIN);
    hashInt(&hash, u16, self.schema_version);
    hashInt(&hash, u32, self.base_component_count);
    hashInt(&hash, u32, self.full_component_count);
    hashInt(&hash, u32, self.base_preprocessed_columns);
    hashInt(&hash, u32, self.base_main_columns);
    hashInt(&hash, u32, self.base_interaction_columns);
    hash.update(&self.statement_sha256);
    hash.update(&self.claim_sha256);
    hashInt(&hash, u32, self.components.len);
    for (self.components) |component| hashComponent(&hash, component);
    hashInt(&hash, u32, self.relation_draws.len);
    for (self.relation_draws) |draw| hashQm31(&hash, draw);
    return hash.finalResult();
}

pub fn hashComponent(hash: *Sha256, value: ComponentAuthorityV1) void {
    hashInt(hash, u8, @intFromEnum(value.kind));
    inline for (.{
        value.log_size,
        value.n_rows,
        value.preprocessed_offset,
        value.preprocessed_columns,
        value.main_offset,
        value.main_columns,
        value.interaction_offset,
        value.interaction_columns,
        value.direct_constraint_count,
        value.interaction_batch_count,
    }) |field| hashInt(hash, u32, field);
    hash.update(&value.semantic_digest);
    hashQm31(hash, value.component_sum);
    hash.update(&value.detailed_batch_sums_sha256);
}

pub fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn validateQm31(value: QM31) !void {
    for (value.toM31Array()) |limb|
        if (limb.toU32() >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidEthereumRelationDraw;
}
