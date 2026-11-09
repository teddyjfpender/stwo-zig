//! Common-fold statement profile. The frozen universal/CSP catalog is unchanged.
const air = struct {
    const field_public_word_v3 = @import("stwo_riscv_recursion_air").modules.field_public_word;
    const field_statement_word_v3 = @import("stwo_riscv_recursion_air").modules.field_statement_word;
    const fixed_wire_v3 = @import("stwo_riscv_recursion_air").modules.fixed_wire;
    const universal_catalog = @import("stwo_riscv_recursion_air").modules.universal_catalog;
    const vm_public_claim_hash = @import("stwo_riscv_recursion_air").modules.vm_public_claim_hash;
};
pub const Entry = air.universal_catalog.Entry;
pub const LOGICAL_ROWS = blk: {
    var rows: [air.universal_catalog.LOGICAL_COUNT]Entry = undefined;
    for (air.universal_catalog.LOGICAL_ROWS, 0..) |entry, index| rows[index] = entry;
    rows[10].Air = air.fixed_wire_v3;
    rows[12].Air = air.field_statement_word_v3;
    for (13..17) |index| rows[index].Air = air.vm_public_claim_hash;
    rows[17].Air = air.field_public_word_v3;
    break :blk rows;
};
pub const LOGICAL_COUNT = LOGICAL_ROWS.len;
