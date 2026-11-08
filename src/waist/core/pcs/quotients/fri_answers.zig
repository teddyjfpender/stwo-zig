//! FRI query-row orchestration over backend-independent quotient laws.

const std = @import("std");
const circle = @import("../../circle.zig");
const m31_mod = @import("../../fields/m31.zig");
const qm31_mod = @import("../../fields/qm31.zig");
const canonic = @import("../../poly/circle/canonic.zig");
const core_utils = @import("../../utils.zig");
const pcs_utils = @import("../utils.zig");
const row_evaluation = @import("row_evaluation.zig");
const samples = @import("samples.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;
const TreeVec = pcs_utils.TreeVec;
const ColumnSampleBatch = samples.ColumnSampleBatch;
const QuotientConstants = row_evaluation.QuotientConstants;
const RowQuotientWorkspace = row_evaluation.RowQuotientWorkspace;

pub const ForField = @import("fri_answers_family.zig").ForField;
const Default = ForField(QM31);
pub const friAnswers = Default.friAnswers;
