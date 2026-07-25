//! Typed resident CUDA proof-stage dispatch.

pub const commitment = @import("commitment.zig");
pub const cairo_base = @import("cairo_base.zig");
pub const cairo_ec_op = @import("cairo_ec_op.zig");
pub const cairo_eval = @import("cairo_eval.zig");
pub const cairo_ec_op_contract = @import("cairo_ec_op_contract.zig");
pub const cairo_witness = @import("cairo_witness.zig");
pub const cairo_witness_plan = @import("cairo_witness_plan.zig");
pub const common = @import("common.zig");
pub const composition_split = @import("composition_split.zig");
pub const composition_lift = @import("composition_lift.zig");
pub const constraint_power = @import("constraint_power.zig");
pub const decommit = @import("decommit.zig");
pub const fri = @import("fri.zig");
pub const oods = @import("oods.zig");
pub const oods_plan = @import("oods_plan.zig");
pub const quotient = @import("quotient.zig");
pub const relation = @import("relation.zig");
pub const relation_completion = @import("relation_completion.zig");
pub const resident_layout = @import("resident_layout.zig");
pub const trace = @import("trace.zig");
pub const transcript = @import("transcript.zig");
pub const transform = @import("transform.zig");

test {
    _ = commitment;
    _ = cairo_base;
    _ = cairo_ec_op;
    _ = cairo_eval;
    _ = cairo_ec_op_contract;
    _ = cairo_witness;
    _ = cairo_witness_plan;
    _ = common;
    _ = composition_split;
    _ = composition_lift;
    _ = constraint_power;
    _ = decommit;
    _ = fri;
    _ = oods;
    _ = oods_plan;
    _ = quotient;
    _ = relation;
    _ = relation_completion;
    _ = resident_layout;
    _ = trace;
    _ = transcript;
    _ = transform;
    _ = @import("commitment_test.zig");
    _ = @import("cairo_base/fixed_tables_test.zig");
    _ = @import("cairo_witness_compact_test.zig");
    _ = @import("contract_test.zig");
    _ = @import("quotient_compact_test.zig");
    _ = @import("relation_test.zig");
    _ = @import("trace_test.zig");
    _ = @import("transform_test.zig");
}
