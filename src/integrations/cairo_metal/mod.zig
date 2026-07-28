//! Cairo proving orchestration implemented by the resident Metal backend.

pub const arena_binding = @import("arena_binding.zig");
pub const memory_trace = @import("memory_trace.zig");
pub const oods = @import("oods.zig");
pub const quotient_inputs = @import("quotient_inputs.zig");
pub const quotient_reference = @import("quotient_reference.zig");
pub const runtime_decommit_geometry = @import("runtime_decommit_geometry.zig");
pub const eval_codegen = @import("eval_codegen.zig");
pub const composition_aot = @import("composition_aot.zig");
pub const composition_prewarm = @import("composition_prewarm.zig");
pub const witness_aot = @import("witness_aot.zig");
pub const witness_codegen = @import("witness_codegen.zig");
pub const process_backend = @import("process/backend.zig");

test {
    _ = @import("schedule_bindings_test.zig");
}

test {
    _ = oods;
    _ = quotient_inputs;
    _ = quotient_reference;
    _ = eval_codegen;
    _ = composition_aot;
    _ = composition_prewarm;
    _ = witness_aot;
    _ = witness_codegen;
    _ = process_backend;
}
