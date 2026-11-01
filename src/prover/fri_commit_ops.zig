//! Compatibility QM31 facade; explicit wide-field authority is ForField.
pub const ForField = @import("fri_commit_ops_family.zig").ForField;
const Default = ForField(@import("stwo_core").fields.qm31.QM31);
pub const CommitOps = Default.CommitOps;
