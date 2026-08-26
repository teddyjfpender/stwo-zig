//! Test-only authority substitutions at the opcode workspace boundary.
//!
//! This keeps proof-level A/B machinery out of the production main-trace
//! orchestration while preserving its exact placement before lookup ingestion.

const std = @import("std");
const statement_mod = @import("../air/statement.zig");
const trace = @import("../runner/trace.zig");
const opcode_trace = @import("opcode_trace.zig");
const witness_hook = @import("test_witness_hook.zig");

pub fn apply(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: *opcode_trace.Columns,
    exec_trace: *const trace.Trace,
    mutation: witness_hook.Mutation,
) !bool {
    if (try witness_hook.applyLegacyOpcodeAuthority(
        allocator,
        statement,
        &columns.components,
        exec_trace,
        mutation,
    )) {
        // The generated path accumulated these while writing its rows. Force
        // the A/B arm to derive them from the independently rewritten cells.
        columns.discardLookupCounters(allocator);
    }
    return witness_hook.applyOpcodeWitness(
        allocator,
        statement,
        &columns.components,
        mutation,
    );
}
