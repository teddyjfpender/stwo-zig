//! Typed resident CUDA proof-stage dispatch.

pub const commitment = @import("commitment.zig");
pub const common = @import("common.zig");
pub const composition_split = @import("composition_split.zig");
pub const constraint_power = @import("constraint_power.zig");
pub const decommit = @import("decommit.zig");
pub const fri = @import("fri.zig");
pub const oods = @import("oods.zig");
pub const oods_plan = @import("oods_plan.zig");
pub const quotient = @import("quotient.zig");
pub const resident_layout = @import("resident_layout.zig");
pub const trace = @import("trace.zig");
pub const transcript = @import("transcript.zig");
pub const transform = @import("transform.zig");

test {
    _ = commitment;
    _ = common;
    _ = composition_split;
    _ = constraint_power;
    _ = decommit;
    _ = fri;
    _ = oods;
    _ = oods_plan;
    _ = quotient;
    _ = resident_layout;
    _ = trace;
    _ = transcript;
    _ = transform;
    _ = @import("commitment_test.zig");
    _ = @import("contract_test.zig");
    _ = @import("trace_test.zig");
}
