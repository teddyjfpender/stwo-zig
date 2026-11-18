//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const air = @import("tests/focused/air.zig");
    pub const alu_parallel_interaction = @import("tests/focused/alu_parallel_interaction.zig");
    pub const arith256_truth = @import("tests/focused/arith256_truth.zig");
    pub const coset_evaluation = @import("tests/focused/coset_evaluation.zig");
    pub const curves_truth = @import("tests/focused/curves_truth.zig");
    pub const index_control = @import("tests/focused/index_control.zig");
    pub const keccak_sponge = @import("tests/focused/keccak_sponge.zig");
    pub const ls_dword = @import("tests/focused/ls_dword.zig");
    pub const parallel = @import("tests/focused/parallel.zig");
    pub const program = @import("tests/focused/program.zig");
    pub const rom_lookup = @import("tests/focused/rom_lookup.zig");
    pub const rv64_execution = @import("tests/focused/rv64_execution.zig");
    pub const sha256_truth = @import("tests/focused/sha256_truth.zig");
    pub const simd_fields = @import("tests/focused/simd_fields.zig");
    pub const word16_alu = @import("tests/focused/word16_alu.zig");
    pub const word16_binary_source = @import("tests/focused/word16_binary_source.zig");
    pub const word16_bulk_memory = @import("tests/focused/word16_bulk_memory.zig");
    pub const word16_chips = @import("tests/focused/word16_chips.zig");
    pub const word16_division_product = @import("tests/focused/word16_division_product.zig");
    pub const word16_shift = @import("tests/focused/word16_shift.zig");
    pub const word16_shift_packed_table = @import("tests/focused/word16_shift_packed_table.zig");
    pub const word16_shift_source = @import("tests/focused/word16_shift_source.zig");
    pub const word16_shift_word = @import("tests/focused/word16_shift_word.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
