//! Proof-owned CUDA runtime surface.

pub const arena = @import("arena.zig");
pub const context = @import("context.zig");
pub const device_admission = @import("device_admission.zig");
pub const column = @import("column.zig");
pub const constraints = @import("constraints/mod.zig");
pub const execution_plan = @import("execution_plan.zig");
pub const execution_cache = @import("execution_cache.zig");
pub const function_cache = @import("function_cache.zig");
pub const graph_execution = @import("graph_execution.zig");
pub const interactions = @import("interactions/mod.zig");
pub const kernel = @import("kernel.zig");
pub const persistent_allocation = @import("persistent_allocation.zig");
pub const provider = @import("provider.zig");
pub const proof_transaction = @import("proof_transaction.zig");
pub const process_runtime = @import("process_runtime.zig");
pub const proof_assembly = @import("proof_assembly/mod.zig");
pub const runtime_error = @import("error.zig");
pub const session = @import("session.zig");
pub const statements = struct {
    pub const state_machine = @import("statements/state_machine.zig");
};
pub const stages = @import("stages/mod.zig");
pub const telemetry = @import("telemetry.zig");
pub const traces = @import("traces/mod.zig");
pub const verdict = @import("verdict.zig");

pub const NativeContext = context.NativeContext;
pub const NativeBaseFieldColumn = column.NativeBaseFieldColumn;
pub const NativeSession = session.NativeSession;
pub const NativeRuntime = process_runtime.NativeRuntime;
pub const CuMetalSession = session.CuMetalSession;
pub const CuMetalRuntime = process_runtime.CuMetalRuntime;

test {
    _ = arena;
    _ = context;
    _ = device_admission;
    _ = column;
    _ = constraints;
    _ = execution_plan;
    _ = execution_cache;
    _ = function_cache;
    _ = graph_execution;
    _ = interactions;
    _ = kernel;
    _ = persistent_allocation;
    _ = provider;
    _ = proof_transaction;
    _ = process_runtime;
    _ = proof_assembly;
    _ = runtime_error;
    _ = session;
    _ = statements;
    _ = stages;
    _ = telemetry;
    _ = traces;
    _ = verdict;
    _ = @import("context_additional_test.zig");
    _ = @import("graph_execution_test.zig");
    _ = @import("resident_zero_test.zig");
    _ = @import("session_test.zig");
}
