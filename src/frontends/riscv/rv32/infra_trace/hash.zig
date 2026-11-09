//! Poseidon2 and Merkle infrastructure column generators.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const poseidon2 = @import("stwo_riscv_memory").primitives_common_poseidon2;
const permutation = @import("stwo_riscv_air_lang").shared_infra_trace_permutation;

pub const POSEIDON2_TRACE_COLS: usize = 443;
pub const MERKLE_TRACE_COLS: usize = 10;

pub fn genPoseidon2Columns(
    allocator: std.mem.Allocator,
    hash_traces: []const poseidon2.PermuteTrace,
    log_size: u32,
) !struct { columns: [POSEIDON2_TRACE_COLS][]M31, n_real_rows: usize } {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var columns = try permutation.allocZeroColumns(allocator, POSEIDON2_TRACE_COLS, domain_size);
    errdefer for (&columns) |column| allocator.free(column);
    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);

    for (hash_traces, 0..) |trace, row| {
        if (row >= domain_size) break;
        const flat = trace.flatten();
        for (&columns, 0..) |column, index| {
            permutation.placeValue(column, row, placement, flat[index]);
        }
    }
    return .{ .columns = columns, .n_real_rows = hash_traces.len };
}

pub fn freePoseidon2Columns(
    allocator: std.mem.Allocator,
    columns: *[POSEIDON2_TRACE_COLS][]M31,
) void {
    for (columns) |column| allocator.free(column);
}

pub fn genMerkleColumns(
    allocator: std.mem.Allocator,
    n_nodes: usize,
    log_size: u32,
) !struct { columns: [MERKLE_TRACE_COLS][]M31, n_real_rows: usize } {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var columns = try permutation.allocZeroColumns(allocator, MERKLE_TRACE_COLS, domain_size);
    errdefer for (&columns) |column| allocator.free(column);
    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);

    for (0..@min(n_nodes, domain_size)) |row| {
        permutation.placeValue(columns[0], row, placement, M31.one());
        permutation.placeValue(columns[1], row, placement, M31.fromU64(row));
    }
    return .{ .columns = columns, .n_real_rows = n_nodes };
}

pub fn freeMerkleColumns(
    allocator: std.mem.Allocator,
    columns: *[MERKLE_TRACE_COLS][]M31,
) void {
    for (columns) |column| allocator.free(column);
}
