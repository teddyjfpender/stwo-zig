//! Verifier-owned FRI query captures for recursive witness generation.

const std = @import("std");
const QM31 = @import("../fields/qm31.zig").QM31;

pub const ForField = @import("query_capture_family.zig").ForField;
const Default = ForField(QM31);
pub const SampledQueryPositions = Default.SampledQueryPositions;
pub const FriLayerQueryCapture = Default.FriLayerQueryCapture;
pub const FriQueryCapture = Default.FriQueryCapture;
