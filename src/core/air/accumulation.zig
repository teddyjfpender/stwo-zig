const std = @import("std");
const qm31 = @import("../fields/qm31.zig");
const m31 = @import("../fields/m31.zig");

const QM31 = qm31.QM31;
const M31 = m31.M31;

pub const ForField = @import("accumulation_family.zig").ForField;
const Default = ForField(QM31);
pub const PointEvaluationAccumulator = Default.PointEvaluationAccumulator;
