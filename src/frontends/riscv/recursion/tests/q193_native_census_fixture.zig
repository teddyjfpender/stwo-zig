//! Native descriptor roster used for the retained q193 leaf Tree0 census.
const authority = @import("../detached_segment_authority_boundary_v1.zig");

pub const DESCRIPTORS = authority.DescriptorsV1{
    .components = &.{
        .{ .family = .base_alu_imm, .log_size = 4, .n_rows = 12, .n_columns = 35 },
        .{ .family = .load_store, .log_size = 5, .n_rows = 22, .n_columns = 50 },
        .{ .family = .lui, .log_size = 4, .n_rows = 1, .n_columns = 18 },
    },
    .infrastructure = &.{
        .{ .kind = .program, .log_size = 6, .n_rows = 36, .n_columns = 10 },
        .{ .kind = .merkle, .log_size = 9, .n_rows = 466, .n_columns = 10 },
        .{ .kind = .poseidon2, .log_size = 9, .n_rows = 466, .n_columns = 445 },
        .{ .kind = .clock_update, .log_size = 4, .n_rows = 0, .n_columns = 10 },
        .{ .kind = .bitwise, .log_size = 18, .n_rows = 262144, .n_columns = 1 },
        .{ .kind = .range_check_20, .log_size = 20, .n_rows = 1048576, .n_columns = 1 },
        .{ .kind = .range_check_8_11, .log_size = 19, .n_rows = 524288, .n_columns = 1 },
        .{ .kind = .range_check_8_8_4, .log_size = 20, .n_rows = 1048576, .n_columns = 1 },
        .{ .kind = .range_check_8_8, .log_size = 16, .n_rows = 65536, .n_columns = 1 },
        .{ .kind = .range_check_m31, .log_size = 15, .n_rows = 32768, .n_columns = 1 },
    },
};
