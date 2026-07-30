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
pub const composition_eval_arena = @import("composition_eval_arena.zig");
pub const composition_stage = @import("composition_stage.zig");
pub const witness_aot = @import("witness_aot.zig");
pub const witness_codegen = @import("witness_codegen.zig");
pub const prover = @import("prover/mod.zig");
pub const interaction_executor = @import("prover/interaction_executor.zig");
pub const resident_lookup = @import("prover/resident_lookup.zig");
pub const process_backend = @import("process/backend.zig");
pub const process_runner = @import("process/runner.zig");
pub const recipe_requirements = @import("recipe_requirements.zig");
pub const schedule_bindings = @import("schedule_bindings.zig");
pub const transcript_fixture = @import("diagnostics/transcript_fixture.zig");

test "api signature: Cairo Metal transaction satisfies the stable prover contract" {
    comptime @import("stwo_prover_engine").engine.assertProverEngine(
        prover.transaction.Engine,
    );
}

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
    _ = composition_eval_arena;
    _ = composition_stage;
    _ = witness_aot;
    _ = witness_codegen;
    _ = interaction_executor;
    _ = resident_lookup;
    _ = process_backend;
}
