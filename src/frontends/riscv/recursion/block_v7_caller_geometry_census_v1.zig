//! Exact original arithmetic geometry, not a wall-time or active-row estimate.
//! A zero-call group can still contain required fixed-table provider rows; the
//! census does not authorize deleting those AIRs or their LogUp relations.
const std = @import("std");
const Profile = @import("block_v7_caller_joint_fixed_profile_v1.zig");
const Family = @import("../prover/blake3_ethereum_sha_profile.zig");
pub const Row = struct {
    component: []const u8,
    logical_rows: u32,
    domain_rows: u64,
    fixed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,
    committed_cells: u64,
    lde_cells: u64,
    constraints: u32,
    zero_signer_group: bool,
};
pub fn rows(profile: *const Profile.Owned) ![Family.component_count]Row {
    try profile.admitted.validate();
    const statement = &profile.admitted.arithmetic.statement;
    var result: [Family.component_count]Row = undefined;
    const names = [_][]const u8{ "keccak_shard", "keccak_chi_table", "keccak_xor5_table", "product_base", "product_scalar", "linear_base", "linear_scalar", "point", "split", "scalar", "table", "recovery", "byte", "recovery_caller", "sha_source", "sha_schedule", "sha_round", "sha_feed_forward", "sha_caller" };
    for (Family.descriptors(statement), profile.admitted.arithmetic.components, &result, names, 0..) |descriptor, component, *row, name, i| {
        const domain_rows = @as(u64, 1) << @intCast(descriptor.log_size);
        const columns = try std.math.add(u64, descriptor.preprocessed_columns, try std.math.add(u64, descriptor.main_columns, descriptor.interaction_columns));
        const cells = try std.math.mul(u64, domain_rows, columns);
        row.* = .{ .component = name, .logical_rows = if (i < 14) statement.ethereum.components[i].n_rows else statement.sha.descriptors[i - 14].live_rows, .domain_rows = domain_rows, .fixed_columns = descriptor.preprocessed_columns, .main_columns = descriptor.main_columns, .interaction_columns = descriptor.interaction_columns, .committed_cells = cells, .lde_cells = try std.math.mul(u64, cells, @as(u64, 1) << @intCast(profile.config.fri_config.log_blowup_factor)), .constraints = component.direct_constraint_count + component.interaction_batch_count, .zero_signer_group = i >= 3 and i < 14 and statement.ethereum.counts.signer_calls == 0 };
    }
    return result;
}
