//! Backend-independent quotient evaluation for one queried domain row.
//!
//! The allocating and reusable-workspace entry points implement the same law.
//! Optimized backends may replace mechanics, but not line construction,
//! denominator semantics, or accumulation order without oracle evidence.

const std = @import("std");
const circle = @import("../../circle.zig");
const constraints = @import("../../constraints.zig");
const cm31_mod = @import("../../fields/cm31.zig");
const fields = @import("../../fields/mod.zig");
const m31_mod = fields.m31;
const qm31_mod = @import("../../fields/qm31.zig");
const samples = @import("samples.zig");

const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CM31 = cm31_mod.CM31;
const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;
const ColumnSampleBatch = samples.ColumnSampleBatch;

pub const ForField = @import("row_evaluation_family.zig").ForField;
const Default = ForField(QM31);
pub const QuotientConstants = Default.QuotientConstants;
pub const columnLineCoeffs = Default.columnLineCoeffs;
pub const quotientConstants = Default.quotientConstants;
pub const denominatorInverses = Default.denominatorInverses;
pub const RowQuotientWorkspace = Default.RowQuotientWorkspace;
pub const accumulateRowQuotientsWithWorkspace = Default.accumulateRowQuotientsWithWorkspace;
pub const accumulateRowPartialNumerators = Default.accumulateRowPartialNumerators;
pub const accumulateRowQuotients = Default.accumulateRowQuotients;
pub const finalizeRowQuotients = Default.finalizeRowQuotients;
