//! Borrowed Ethereum main columns plus owned fixed-table multiplicities.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const keccak_component = @import("../../air/guest_precompile/keccakf_component.zig");
const secp_bundle = @import("../../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_config = @import("../../air/guest_precompile/secp256k1_component_config.zig");
const secp_trace = @import("../../air/guest_precompile/secp256k1_component_trace.zig");
const external_tree = @import("external_profile_tree.zig");
const ethereum_witness = @import("ethereum_witness.zig");
pub const Range = struct { start: usize, count: usize, log_size: u32 };
pub const Generated = struct {
    columns: []Column,
    ranges: [14]Range,
    tables: [2][]M31,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        for (self.tables) |values| a.free(values);
        a.free(self.columns);
        self.* = undefined;
    }
};
pub fn generate(allocator: std.mem.Allocator, extension: *const ethereum_witness.Witness) !Generated {
    const shard = keccakMainColumns(&extension.keccak_shard);
    const chi_values = try extension.keccak_counters.committedColumn(allocator, .chi);
    errdefer allocator.free(chi_values);
    const xor_values = try extension.keccak_counters.committedColumn(allocator, .xor5);
    errdefer allocator.free(xor_values);
    const chi = [1][]const M31{chi_values};
    const xor5 = [1][]const M31{xor_values};
    const product_base = secpMainColumns(secp_bundle.ProductBase, &extension.secp.product_base);
    const product_scalar = secpMainColumns(secp_bundle.ProductScalar, &extension.secp.product_scalar);
    const linear_base = secpMainColumns(secp_bundle.LinearBase, &extension.secp.linear_base);
    const linear_scalar = secpMainColumns(secp_bundle.LinearScalar, &extension.secp.linear_scalar);
    const point = secpMainColumns(secp_config.Point, &extension.secp.point);
    const split = secpMainColumns(secp_config.Split, &extension.secp.split);
    const scalar = secpMainColumns(secp_config.ScalarProgram, &extension.secp.scalar);
    const table = secpMainColumns(secp_config.Table, &extension.secp.table);
    const recovery = secpMainColumns(secp_config.Recovery, &extension.secp.recovery);
    const byte = secpMainColumns(secp_config.ByteTable, &extension.secp.byte);
    var caller: [secp_config.RecoveryCallerLocalZero.main_column_count][]const M31 = undefined;
    const caller_count: usize = if (extension.recovery_caller_local_zero) |*owned| blk: {
        caller = secpMainColumns(secp_config.RecoveryCallerLocalZero, owned);
        break :blk caller.len;
    } else blk: {
        const legacy = secpMainColumns(secp_config.RecoveryCaller, &extension.recovery_caller);
        @memcpy(caller[0..legacy.len], &legacy);
        break :blk legacy.len;
    };
    const ethereum_blocks = [_]external_tree.BorrowedBlock{
        block(extension.keccak_shard.log_size, shard[0..extension.keccak_shard.mainColumnCount()]),
        block(@import("../../air/guest_precompile/keccakf_tables.zig").logSize(.chi), &chi),
        block(@import("../../air/guest_precompile/keccakf_tables.zig").logSize(.xor5), &xor5),
        block(extension.secp.product_base.log_size, &product_base),
        block(extension.secp.product_scalar.log_size, &product_scalar),
        block(extension.secp.linear_base.log_size, &linear_base),
        block(extension.secp.linear_scalar.log_size, &linear_scalar),
        block(extension.secp.point.log_size, &point),
        block(extension.secp.split.log_size, &split),
        block(extension.secp.scalar.log_size, &scalar),
        block(extension.secp.table.log_size, &table),
        block(extension.secp.recovery.log_size, &recovery),
        block(extension.secp.byte.log_size, &byte),
        block(extension.recoveryCallerLogSize(), caller[0..caller_count]),
    };
    var columns: std.ArrayList(Column) = .empty;
    errdefer columns.deinit(allocator);
    var ranges: [14]Range = undefined;
    for (ethereum_blocks, &ranges) |entry, *range| {
        range.* = .{ .start = columns.items.len, .count = entry.columns.len, .log_size = entry.log_size };
        for (entry.columns) |values| try columns.append(allocator, .{ .log_size = entry.log_size, .values = values });
    }
    return .{ .columns = try columns.toOwnedSlice(allocator), .ranges = ranges, .tables = .{ chi_values, xor_values } };
}
fn block(log_size: u32, columns: []const []const M31) external_tree.BorrowedBlock {
    return .{ .log_size = log_size, .columns = columns };
}
fn keccakMainColumns(
    trace: *const @import("../../air/guest_precompile/keccakf_trace.zig").Shard,
) [keccak_component.main_column_count + 2][]const M31 {
    var result: [keccak_component.main_column_count + 2][]const M31 = undefined;
    for (result[0..trace.mainColumnCount()], 0..) |*column, index| column.* = trace.mainColumn(index);
    return result;
}

fn secpMainColumns(
    comptime Config: type,
    trace: *const secp_trace.Trace(Config),
) [Config.main_column_count][]const M31 {
    var result: [Config.main_column_count][]const M31 = undefined;
    for (&result, 0..) |*column, index| column.* = trace.mainColumn(index);
    return result;
}
