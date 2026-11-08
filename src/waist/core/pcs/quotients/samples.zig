//! PCS sample representation, periodicity expansion, and stable point grouping.
//!
//! Random coefficient powers are assigned in upstream tree/column/sample order.
//! That ordering is part of the transcript law and must not be parallelized or
//! reordered without Rust-oracle evidence.

const std = @import("std");
const circle = @import("../../circle.zig");
const qm31_mod = @import("../../fields/qm31.zig");
const canonic = @import("../../poly/circle/canonic.zig");
const pcs_utils = @import("../utils.zig");

const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;
const QM31 = qm31_mod.QM31;
const TreeVec = pcs_utils.TreeVec;

pub const ForField = @import("samples_family.zig").ForField;
const Default = ForField(QM31);
pub const PointSample = Default.PointSample;
pub const SampleWithRandomness = Default.SampleWithRandomness;
pub const NumeratorData = Default.NumeratorData;
pub const ColumnSampleBatch = Default.ColumnSampleBatch;
pub const buildSamplesWithRandomnessAndPeriodicity = Default.buildSamplesWithRandomnessAndPeriodicity;
pub const buildColumnSampleBatchesFromParallelInputs = Default.buildColumnSampleBatchesFromParallelInputs;
