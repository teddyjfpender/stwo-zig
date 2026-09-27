const air = struct {
    const control_witness = @import("air/control_witness.zig");
    const relation_challenge_witness = @import("air/relation_challenge_witness.zig");
    const transcript_air_witness = @import("air/transcript_air_witness.zig");
    const transcript_binding_witness = @import("air/transcript_binding_witness.zig");
    const transcript_payload_witness = @import("air/transcript_payload_witness.zig");
    const transcript_state_witness = @import("air/transcript_state_witness.zig");
    const transcript_word_witness = @import("air/transcript_word_witness.zig");
    const verifier_randomness_witness = @import("air/verifier_randomness_witness.zig");
};
const M31 = @import("stwo_core").fields.m31.M31;
const catalog = @import("common_fold_catalog_v3.zig");
pub fn logicalRow(comptime index: usize, row: anytype) ![catalog.LOGICAL_ROWS[index].Air.LOGICAL_INPUT_COUNT]M31 {
    return switch (index) {
        0 => air.control_witness.logicalRow(row, .binary_node),
        1 => air.transcript_air_witness.logicalRow(row),
        2 => air.transcript_binding_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        3 => air.transcript_state_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        4 => air.transcript_word_witness.logicalRow(row.preprocessing, row.value, .binary_node),
        5 => air.transcript_payload_witness.logicalRowForRecordedFrame(row.preprocessing, row.value, .binary_node),
        6, 7, 12 => row,
        8 => air.relation_challenge_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        9 => air.verifier_randomness_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        else => @compileError("inactive transcript component"),
    };
}
