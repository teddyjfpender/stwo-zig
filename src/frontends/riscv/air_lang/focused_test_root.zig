//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const air_function_frames_1 = @import("tests/focused/air_function_frames_1.zig");
    pub const air_semantics_0 = @import("tests/focused/air_semantics_0.zig");
    pub const air_semantics_1 = @import("tests/focused/air_semantics_1.zig");
    pub const air_semantics_2 = @import("tests/focused/air_semantics_2.zig");
    pub const air_semantics_3 = @import("tests/focused/air_semantics_3.zig");
    pub const parent_canonical_admission_2 = @import("tests/focused/parent_canonical_admission_2.zig");
    pub const parent_canonical_admission_4 = @import("tests/focused/parent_canonical_admission_4.zig");
    pub const polynomial_compiler = @import("tests/focused/polynomial_compiler.zig");
    pub const recursion_framework_export = @import("tests/focused/recursion_framework_export.zig");
    pub const recursion_framework_interaction = @import("tests/focused/recursion_framework_interaction.zig");
    pub const universal_roster = @import("tests/focused/universal_roster.zig");
    pub const universal_challenges = @import("tests/focused/universal_challenges.zig");
    pub const runtime_profile_symbolic = @import("tests/focused/runtime_profile_symbolic.zig");
    pub const air_lang_transcript_support = @import("tests/focused/air_lang_transcript_support.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
