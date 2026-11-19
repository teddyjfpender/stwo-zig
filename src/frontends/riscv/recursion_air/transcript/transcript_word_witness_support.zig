//! Internal transcript word witness authority shard; use transcript_word_witness.zig publicly.

const dependency_0 = @import("transcript_word_witness_binding.zig");

const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const component = dependency_0.component;

comptime {
    if (MAIN_COLUMN_COUNT != 2 or PREPROCESSED_COLUMN_COUNT != 15 or
        component.DIGEST_WORD_COUNT != component.RATE or
        component.TRANSCRIPT_HEADER_WORD_COUNT != component.RATE)
    {
        @compileError("transcript-word witness geometry drifted");
    }
}
