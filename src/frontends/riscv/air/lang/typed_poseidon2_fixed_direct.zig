//! Exact fixed direct-polynomial profile for the typed Poseidon2 pilot.
//!
//! Scope is deliberately the permutation direct AIR, not the surrounding
//! RISC-V hash-component shell or its LogUp interaction constraints. The
//! caller inserts candidate materialization equalities between the prefix and
//! suffix roots.

const fixed = @import("materialization_fixed_direct.zig");
const compat = @import("typed_poseidon2_compat.zig");

pub const cost_scope_id = "stwo.typed-air.cost.poseidon2-permutation-direct";
pub const cost_scope_version: u16 = 1;
pub const width: u32 = compat.WIDTH;
pub const fixed_root_count: u32 = 4;
pub const main_prefix_columns: u32 = compat.TEMPORARY_START;
pub const canonical_digest: fixed.Digest = .{
    0xef, 0x32, 0x02, 0x4b, 0xa1, 0xd2, 0x5b, 0x47,
    0x0c, 0x21, 0x7e, 0xf9, 0x6a, 0xf9, 0x5b, 0x52,
    0x03, 0x89, 0x48, 0xc6, 0x7f, 0x6a, 0xc4, 0xce,
    0x1e, 0x14, 0x87, 0x5b, 0xf6, 0x8e, 0xa6, 0xa5,
};

pub const ColumnIndex = enum(u32) {
    enabler = 0,
    wide = 1,
    io = 2,
};

pub const columns = [_]fixed.Column{
    .{
        .role = "enabler",
        .binding = .gate,
        .tree = .main,
        .placement = .{ .absolute = 0 },
    },
    .{
        .role = "wide",
        .binding = .component,
        .tree = .main,
        .placement = .{ .after_materializations = .{
            .prefix_columns = main_prefix_columns,
            .trailing_offset = 0,
        } },
    },
    .{
        .role = "io",
        .binding = .component,
        .tree = .main,
        .placement = .{ .after_materializations = .{
            .prefix_columns = main_prefix_columns,
            .trailing_offset = 1,
        } },
    },
};

/// Topological node order also fixes first-intern evaluation order:
///
/// `e`, `1`, `1-e`, `e(1-e)`, then after candidate equalities
/// `wide`, `1-wide`, `wide(1-wide)`, `io`, `1-io`, `io(1-io)`, `wide*io`.
pub const nodes = [_]fixed.Node{
    .{ .op = .column, .value = @intFromEnum(ColumnIndex.enabler) },
    .{ .op = .constant, .value = 1 },
    .{ .op = .sub, .lhs = 1, .rhs = 0 },
    .{ .op = .mul, .lhs = 0, .rhs = 2 },
    .{ .op = .column, .value = @intFromEnum(ColumnIndex.wide) },
    .{ .op = .sub, .lhs = 1, .rhs = 4 },
    .{ .op = .mul, .lhs = 4, .rhs = 5 },
    .{ .op = .column, .value = @intFromEnum(ColumnIndex.io) },
    .{ .op = .sub, .lhs = 1, .rhs = 7 },
    .{ .op = .mul, .lhs = 7, .rhs = 8 },
    .{ .op = .mul, .lhs = 4, .rhs = 7 },
};

pub const prefix_roots = [_]fixed.NodeId{@enumFromInt(3)};
pub const suffix_roots = [_]fixed.NodeId{
    @enumFromInt(6),
    @enumFromInt(9),
    @enumFromInt(10),
};

pub const program = fixed.Program{
    .scope_id = cost_scope_id,
    .scope_version = cost_scope_version,
    .materialization_tree = .main,
    .materialization_column_start = main_prefix_columns,
    .columns = &columns,
    .nodes = &nodes,
    .prefix_roots = &prefix_roots,
    .suffix_roots = &suffix_roots,
};

comptime {
    if (columns.len != 3 or nodes.len != 11 or
        prefix_roots.len + suffix_roots.len != fixed_root_count or
        compat.ENABLER_COLUMN != 0 or compat.N_MATERIALIZATIONS != 426 or
        compat.WIDE_COLUMN != main_prefix_columns + compat.N_MATERIALIZATIONS or
        compat.IO_COLUMN != compat.WIDE_COLUMN + 1)
    {
        @compileError("Poseidon2 fixed direct profile geometry drifted");
    }
}
