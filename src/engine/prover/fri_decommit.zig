//! Compatibility QM31 facade; explicit wide-field authority is ForField.
pub const ForField = @import("fri_decommit_family.zig").ForField;
const Default = ForField(@import("stwo_core").fields.qm31.QM31);
pub const FriDecommitError = Default.FriDecommitError;
pub const ValueEntry = Default.ValueEntry;
pub const DecommitmentPositionsResult = Default.DecommitmentPositionsResult;
pub const LayerDecommitResult = Default.LayerDecommitResult;
pub const FriDecommitResult = Default.FriDecommitResult;
pub const decommitLayerExtended = Default.decommitLayerExtended;
pub const decommitLayerExtendedWithRetainedPacking = Default.decommitLayerExtendedWithRetainedPacking;
pub const computeDecommitmentPositionsAndWitnessEvals = Default.computeDecommitmentPositionsAndWitnessEvals;
pub const decommitLayer = Default.decommitLayer;
