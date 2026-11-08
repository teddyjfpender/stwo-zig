//! Compatibility QM31 facade; explicit wide-field authority is ForField.
pub const ForField = @import("fri_packing_family.zig").ForField;
const Default = ForField(@import("stwo_core").fields.qm31.QM31);
pub const PackedSecureColumns = Default.PackedSecureColumns;
pub const shouldPack = Default.shouldPack;
pub const packedQueryPositions = Default.packedQueryPositions;
