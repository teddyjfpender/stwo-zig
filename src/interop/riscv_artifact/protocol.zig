//! Pinned protocol metadata required to validate a wire without loading prover code.
//!
//! The adapter contains a parity test against the production RISC-V registries.

const schema = @import("schema.zig");

pub const FAMILY_COUNT: usize = 17;
pub const LOOKUP_TABLE_COUNT: usize = 6;

/// Interaction PoW for proof-artifact schema v3. A change requires a schema
/// version bump rather than accepting a value from an artifact or caller.
pub const INTERACTION_POW_SCHEMA_VERSION: u32 = 4;
pub const INTERACTION_POW_BITS: u32 = 10;

pub const Family = struct {
    ordinal: u8,
    n_main_columns: u32,
    n_interaction_batches: u32,
};

/// Canonical proof component order, independent of Zig enum declaration order.
pub const FAMILIES = [FAMILY_COUNT]Family{
    .{ .ordinal = 9, .n_main_columns = 29, .n_interaction_batches = 6 }, // auipc
    .{ .ordinal = 1, .n_main_columns = 35, .n_interaction_batches = 8 }, // base_alu_imm
    .{ .ordinal = 0, .n_main_columns = 43, .n_interaction_batches = 9 }, // base_alu_reg
    .{ .ordinal = 6, .n_main_columns = 30, .n_interaction_batches = 5 }, // branch_eq
    .{ .ordinal = 7, .n_main_columns = 37, .n_interaction_batches = 6 }, // branch_lt
    .{ .ordinal = 15, .n_main_columns = 67, .n_interaction_batches = 22 }, // div
    .{ .ordinal = 11, .n_main_columns = 20, .n_interaction_batches = 4 }, // jal
    .{ .ordinal = 10, .n_main_columns = 32, .n_interaction_batches = 6 }, // jalr
    .{ .ordinal = 12, .n_main_columns = 56, .n_interaction_batches = 8 }, // load_store
    .{ .ordinal = 5, .n_main_columns = 37, .n_interaction_batches = 6 }, // lt_imm
    .{ .ordinal = 4, .n_main_columns = 44, .n_interaction_batches = 7 }, // lt_reg
    .{ .ordinal = 8, .n_main_columns = 18, .n_interaction_batches = 4 }, // lui
    .{ .ordinal = 13, .n_main_columns = 39, .n_interaction_batches = 16 }, // mul
    .{ .ordinal = 14, .n_main_columns = 47, .n_interaction_batches = 22 }, // mulh
    .{ .ordinal = 3, .n_main_columns = 51, .n_interaction_batches = 7 }, // shifts_imm
    .{ .ordinal = 2, .n_main_columns = 60, .n_interaction_batches = 9 }, // shifts_reg
    .{ .ordinal = 16, .n_main_columns = 6, .n_interaction_batches = 2 }, // fence
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

pub const Table = struct {
    kind: InfraKind,
    log_size: u32,
    n_rows: u32,
    preprocessed_columns: u32,
};

pub const TABLES = [LOOKUP_TABLE_COUNT]Table{
    .{ .kind = .bitwise, .log_size = 18, .n_rows = 1 << 18, .preprocessed_columns = 5 },
    .{ .kind = .range_check_20, .log_size = 20, .n_rows = 1 << 20, .preprocessed_columns = 2 },
    .{ .kind = .range_check_8_11, .log_size = 19, .n_rows = 1 << 19, .preprocessed_columns = 3 },
    .{ .kind = .range_check_8_8_4, .log_size = 20, .n_rows = 1 << 20, .preprocessed_columns = 4 },
    .{ .kind = .range_check_8_8, .log_size = 16, .n_rows = 1 << 16, .preprocessed_columns = 3 },
    .{ .kind = .range_check_m31, .log_size = 15, .n_rows = 1 << 15, .preprocessed_columns = 3 },
};

pub fn familyByOrdinal(ordinal: u8) ?Family {
    for (FAMILIES) |family| {
        if (family.ordinal == ordinal) return family;
    }
    return null;
}

pub fn familyRank(ordinal: u8) ?usize {
    for (FAMILIES, 0..) |family, index| {
        if (family.ordinal == ordinal) return index;
    }
    return null;
}

pub fn claimCount(kind: InfraKind) u32 {
    return switch (kind) {
        .program => 4,
        .merkle => 3,
        .memory => 4,
        .poseidon2 => 2,
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => 1,
        .clock_update => 1,
    };
}

pub fn preprocessedColumns(kind: InfraKind) u32 {
    for (TABLES) |table| {
        if (table.kind == kind) return table.preprocessed_columns;
    }
    return 2;
}

pub fn mainColumns(kind: InfraKind) u32 {
    return switch (kind) {
        .program => 10,
        .memory, .clock_update => 8,
        .poseidon2 => 445,
        .merkle => 10,
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => 1,
    };
}

comptime {
    if (schema.SCHEMA_VERSION != INTERACTION_POW_SCHEMA_VERSION)
        @compileError("review interaction PoW before changing the RISC-V artifact schema");
    var seen = [_]bool{false} ** FAMILY_COUNT;
    for (FAMILIES) |family| {
        if (family.ordinal >= FAMILY_COUNT or seen[family.ordinal])
            @compileError("wire family registry is incomplete or duplicated");
        seen[family.ordinal] = true;
    }
    for (seen) |present| {
        if (!present) @compileError("wire family registry omits an opcode family");
    }
}
