//! Canonical native proof descriptors shared by admission and AIR components.
pub const MAX_COMPONENTS: usize = 256;
pub const MAX_INFRA_COMPONENTS: usize = 512;

pub const FamilyComponentDesc = struct {
    family: @import("../opcode_manifest.zig").Family,
    log_size: u32,
    n_rows: u32,
    n_columns: u32 = 10,
};

pub const InfraKind = enum(u32) {
    program,
    memory,
    clock_update,
    poseidon2,
    merkle,
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

pub const InfraComponentDesc = struct {
    kind: InfraKind,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
};
