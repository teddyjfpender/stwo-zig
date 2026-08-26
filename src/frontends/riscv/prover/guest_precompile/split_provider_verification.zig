//! Independent provider preprocessed-root and interaction-claim checks.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const guest_interaction = @import("../../air/guest_precompile/interaction.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_types = @import("../../aggregation/types.zig");

const provider_claim_domain_words = [6]u32{
    0x5357_5453,
    0x3143_4950,
    1,
    @intFromEnum(aggregation_types.LeafRole.poseidon2_provider),
    guest_interaction.provider_batch_count,
    guest_interaction.provider_column_count,
};

/// Rebuild the two canonical provider selector columns on a fresh scheme.
/// This keeps verifier authority independent of both the supplied proof and
/// the manifest descriptor while leaving the actual proof transcript untouched.
pub fn verifyProviderPreprocessedRootV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    component: component_registry.Descriptor,
    expected: aggregation_hash.Digest,
) !void {
    try component.validate();
    if (component.kind != .guest_poseidon2_provider_compat_v1 or
        component.log_size >= @bitSizeOf(usize))
    {
        return error.InvalidProviderPreprocessedGeometry;
    }
    const domain_size = @as(usize, 1) << @intCast(component.log_size);
    if (component.n_rows > domain_size)
        return error.InvalidProviderPreprocessedGeometry;
    const columns = try allocator.alloc(ColumnEvaluation, 2);
    var initialized: usize = 0;
    var columns_owned = true;
    errdefer {
        if (columns_owned) {
            for (columns[0..initialized]) |column_value| {
                allocator.free(@constCast(column_value.values));
            }
            allocator.free(columns);
        }
    }
    for (0..2) |index| {
        const values = try allocator.alloc(M31, domain_size);
        @memset(values, M31.zero());
        if (index == 0) {
            values[guest_main_trace.committedRow(0, component.log_size)] = M31.one();
        } else {
            for (0..component.n_rows) |logical_row| {
                values[
                    guest_main_trace.committedRow(logical_row, component.log_size)
                ] = M31.one();
            }
        }
        columns[index] = .{ .log_size = component.log_size, .values = values };
        initialized += 1;
    }

    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    // `Engine.commit` consumes every owned column on both success and error.
    // Transfer the entire allocation atomically before entering that API.
    columns_owned = false;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or
        !aggregation_hash.eql(roots.items[0], expected))
    {
        return error.InvalidProviderPreprocessedRoot;
    }
}

pub fn mixProviderInteractionClaim(
    channel: anytype,
    authority: component_registry.ProviderConstruction,
    claim: provider_component.Claim,
) !void {
    try claim.validate(authority);
    channel.mixU32s(&provider_claim_domain_words);
    channel.mixFelts(&claim.batch_sums);
    channel.mixFelts(&.{claim.component_sum});
}
