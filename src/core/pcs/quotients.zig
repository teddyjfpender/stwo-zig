//! Backend-independent PCS quotient construction.
//!
//! This stable facade preserves the public API while focused submodules own
//! sample ordering, row evaluation, and FRI query orchestration.

const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const cm31_mod = @import("../fields/cm31.zig");
const m31_mod = @import("../fields/m31.zig");
const qm31_mod = @import("../fields/qm31.zig");
const pcs_utils = @import("utils.zig");
const fri_answers = @import("quotients/fri_answers.zig");
const row_evaluation = @import("quotients/row_evaluation.zig");
const sample_ops = @import("quotients/samples.zig");

const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CM31 = cm31_mod.CM31;
const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;

pub const ForField = @import("quotients_family.zig").ForField;
const Default = ForField(QM31);
pub const TreeVec = Default.TreeVec;
pub const PointSample = Default.PointSample;
pub const SampleWithRandomness = Default.SampleWithRandomness;
pub const NumeratorData = Default.NumeratorData;
pub const ColumnSampleBatch = Default.ColumnSampleBatch;
pub const QuotientConstants = Default.QuotientConstants;
pub const columnLineCoeffs = Default.columnLineCoeffs;
pub const quotientConstants = Default.quotientConstants;
pub const denominatorInverses = Default.denominatorInverses;
pub const RowQuotientWorkspace = Default.RowQuotientWorkspace;
pub const accumulateRowQuotientsWithWorkspace = Default.accumulateRowQuotientsWithWorkspace;
pub const accumulateRowPartialNumerators = Default.accumulateRowPartialNumerators;
pub const accumulateRowQuotients = Default.accumulateRowQuotients;
pub const finalizeRowQuotients = Default.finalizeRowQuotients;
pub const buildSamplesWithRandomnessAndPeriodicity = Default.buildSamplesWithRandomnessAndPeriodicity;
pub const buildColumnSampleBatchesFromParallelInputs = Default.buildColumnSampleBatchesFromParallelInputs;
pub const friAnswers = Default.friAnswers;
