//! Explicit, synchronous device binding for one recursive parent composition.
//! Original handles retain their authenticated polynomial export capabilities;
//! normalized handles carry the exact heterogeneous quotient extension policy.
//! Both slices borrow the current proof and must be forgotten by `release`.
const engine = @import("stwo_prover_engine");
const Component = engine.air.component_prover.ComponentProver;

pub const Executor = struct {
    context: *anyopaque,
    /// Bind only this proof's handles. Errors are terminal, never fallback.
    /// A successful bind acquires exactly one lease, released after core proof
    /// completion on success or failure. The stage must evaluate all components.
    bind: *const fn (*anyopaque, []const Component, []const Component) anyerror!engine.air.device_composition.Stage,
    release: *const fn (*anyopaque) void,
};
