//! Six-commitment geometry from independent B6CJ equations. No proof, captured
//! masks, trace values, final channel or candidate key participates in derivation.
const std = @import("std");
const core = @import("stwo_core");
const Admission = @import("../prover/block_v6_caller_joint_admission_v1.zig");
const Original = @import("block_v6_original_fixed_shape_v1.zig");
pub const Owned = Original.Owned;
pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared) !Owned {
    try admitted.validate();
    const arithmetic = try @import("../prover/blake3_ethereum_sha_profile.zig").ExtensionClaim.zeroForStatement(&admitted.arithmetic.statement);
    var relations = try Admission.zeroClaims(a, &admitted.relations.schedule);
    defer relations.deinit(a);
    const equations = try Admission.EquationOwner.create(a, admitted, &arithmetic, &relations);
    defer equations.destroy();
    const logs = admitted.logs();
    return Original.Owned.initForTraceTrees(5, a, &logs, core.air.components.Components{ .components = &.{equations.joint.asVerifierComponent()}, .n_preprocessed_columns = logs[0].len }, admitted.arithmetic.config, .{ .max_columns = try std.math.mul(usize, admitted.limits.max_columns, 6) });
}
