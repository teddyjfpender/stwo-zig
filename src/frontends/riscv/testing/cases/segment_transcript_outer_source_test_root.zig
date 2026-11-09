//! Focused compile/test root for the resumed-segment V2 rows 0--9 source.

const source = @import("stwo_riscv_recursion").modules.segment_transcript_outer_source_v2;

test "V2 transcript outer source instantiates" {
    _ = source.PreparedV2;
    _ = source.DestinationsV2;
    _ = source.PoseidonRequestRangeV2;
}

test {
    _ = @import("stwo_riscv_recursion").modules.tests_segment_transcript_outer_source_test;
}
