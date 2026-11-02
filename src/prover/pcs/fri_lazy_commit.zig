const std = @import("std");
const core_fri = @import("stwo_core").fri;
const circle_domain = @import("stwo_core").poly.circle.domain;
const quotient_ops = @import("quotient_ops.zig");
const work_profile = @import("stwo_prover_api").work_profile;

pub const ForField = @import("fri_lazy_commit_family.zig").ForField;
const Default = ForField(@import("stwo_core").fields.qm31.QM31);
pub const commitLazy = Default.commitLazy;
