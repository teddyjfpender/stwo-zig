//! Authenticated direct-constraint compiler with per-component bounded capacity.
const implementation = @import("direct_constraint_program_sized.zig");
pub const MAX_NODES: usize = 512;
pub const MAX_CONSTRAINTS: usize = 192;
const Default = implementation.WithLimits(MAX_NODES, MAX_CONSTRAINTS);
pub const Error = Default.Error;
pub const Op = Default.Op;
pub const Node = Default.Node;
pub const Constraint = Default.Constraint;
pub const Program = Default.Program;
pub const authenticate = Default.authenticate;
/// Existing AIRs retain the exact original storage geometry. Wider components
/// explicitly admit larger compile/evaluation bounds without inflating all plans.
pub fn ForAir(comptime Air: type) type {
    return implementation.WithLimits(
        if (@hasDecl(Air, "DIRECT_PROGRAM_NODE_LIMIT")) Air.DIRECT_PROGRAM_NODE_LIMIT else MAX_NODES,
        if (@hasDecl(Air, "DIRECT_PROGRAM_CONSTRAINT_LIMIT")) Air.DIRECT_PROGRAM_CONSTRAINT_LIMIT else MAX_CONSTRAINTS,
    );
}
test "direct constraint compiler default tests" {
    _ = Default;
}
