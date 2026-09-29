//! In-circuit constraint evaluators, interpreted from the compiled-AIR
//! projection (design §5.4).
//!
//! - `projection`: reader of `vectors/circuit/official/compiled_air_constraints_v1.bin`.
//! - `interpreter`: replays one projected function through the builder in the
//!   generated code's exact op order (callee resolution lives in `projection`,
//!   call frames in `interpreter`).
//! - `cairo_components`, `circuit_components`: the 83-slot and 11-slot tables,
//!   in the projection header's slot order.
//! - `manual`: the six hand-written evaluators.
//!
//! Builder surface. Every evaluator is generic over a builder context type
//! `Ctx` with `Var` and `Value` declarations and the methods `zero()`,
//! `one()`, `constant(QM31) !Var`, `add/sub/mul(Var, Var) !Var`,
//! `eq(Var, Var) !void`, `inv(Var) !Var` and `newVar(Value) !Var`, with the
//! semantics of `crates/circuits/src/{context,ops}.rs`. The M2 builder's
//! `builder.Context(V)` has exactly this surface.

pub const projection = @import("projection.zig");
pub const interpreter = @import("interpreter.zig");
pub const component_table = @import("component_table.zig");
pub const cairo_components = @import("cairo_components.zig");
pub const circuit_components = @import("circuit_components.zig");

test {
    _ = projection;
    _ = interpreter;
    _ = component_table;
    _ = cairo_components;
    _ = circuit_components;
}
