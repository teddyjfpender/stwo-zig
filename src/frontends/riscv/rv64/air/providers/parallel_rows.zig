//! Joined disjoint row ranges for the existing bounded prover pool.
//! Both supported field accumulators use the same scheduler and failure joins.
pub const ForField = @import("parallel_rows_family.zig").ForField;
const Default = ForField(@import("stwo_core").fields.qm31.QM31);
pub const Kernel = Default.Kernel;
pub const MIN_STACK = Default.MIN_STACK;
pub const MAX_COOPERATIVE_CHUNKS = Default.MAX_COOPERATIVE_CHUNKS;
pub const evaluate = Default.evaluate;
pub const testing = Default.testing;
