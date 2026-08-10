//! Profile-scoped program authority for the Poseidon2 guest extension.
//!
//! This adapter is the only guest-facing path that selects the Poseidon2
//! decoder while constructing the program commitment. The base proof keeps
//! calling `air/program/commitment.buildDeclared` and therefore retains its
//! closed RV32IM decoder and exact commitment bytes.

const std = @import("std");
const component_registry = @import("component_registry.zig");
const program_commitment = @import("../program/commitment.zig");
const program_decode = @import("../program/decode.zig");
const program_table = @import("../program/table.zig");
const memory_state = @import("../../runner/memory_state.zig");
const guest_runner = @import("../../runner/guest_precompile/poseidon2_v1.zig");
const trace = @import("../../runner/trace.zig");

pub const ProgramValues = program_decode.ProgramValues;
pub const Commitment = program_commitment.Commitment;
pub const FrozenExecutionRows = guest_runner.FrozenExecutionRows;

/// Decode one declared word under the exact Poseidon2 v1 execution profile.
pub fn decodeProgramWord(word: u32) program_decode.ProfileError!ProgramValues {
    return program_decode.decodeProgramWordForProfile(
        .rv32im_zkvm_poseidon2_v1,
        word,
    );
}

/// Commit the union of ordinary retirements, frozen guest retirements, and an
/// optional public completion fetch against one declared program image.
///
/// Both execution slices are borrowed and traversed directly. The generic
/// commitment accumulator performs no union-buffer allocation.
pub fn buildDeclared(
    allocator: std.mem.Allocator,
    base_execution_rows: []const trace.TraceRow,
    guest_execution_rows: *const FrozenExecutionRows,
    program_words: []const memory_state.WordState,
    completion_fetch: ?program_table.Fetch,
) !Commitment {
    return program_commitment.buildDeclaredForProfile(
        allocator,
        .rv32im_zkvm_poseidon2_v1,
        base_execution_rows,
        guest_execution_rows.rows(),
        program_words,
        completion_fetch,
    );
}

comptime {
    if (program_decode.poseidon2_v1_program_opcode_id !=
        @as(u32, component_registry.guest_opcode_id))
    {
        @compileError("guest program opcode authority drifted from component identity");
    }
}
