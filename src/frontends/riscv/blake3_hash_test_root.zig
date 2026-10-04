comptime {
    _ = @import("recursion/air/tests/blake3_g_packed_test.zig");
    _ = @import("recursion/air/tests/blake3_committed_test.zig");
    _ = @import("recursion/air/tests/blake3_native_recorder_test.zig");
    _ = @import("recursion/air/tests/blake3_transcript_plan_test.zig");
    _ = @import("recursion/air/tests/blake3_projection_links_test.zig");
    _ = @import("recursion/air/tests/readonly_consistency_test.zig");
    _ = @import("recursion/air/tests/blake3_bounded_draw_test.zig");
    _ = @import("recursion/air/tests/blake3_counter_step_test.zig");
    _ = @import("recursion/air/tests/blake3_retry_control_test.zig");
    _ = @import("recursion/air/tests/qm31_pack_wire_test.zig");
    _ = @import("recursion/tests/pcs_arithmetic_capture_test.zig");
    _ = @import("recursion/air/tests/scalar_wire_source_test.zig");
    _ = @import("recursion/air/tests/blake3_field_bytes_test.zig");
    _ = @import("recursion/air/blake3_query_path_plan.zig");
    _ = @import("recursion/air/tests/blake3_query_witness_test.zig");
    _ = @import("recursion/air/tests/blake3_query_mask_test.zig");
    _ = @import("recursion/air/tests/blake3_frame_witness_test.zig");
    _ = @import("recursion/air/tests/blake3_draw_witness_test.zig");
    _ = @import("recursion/air/tests/blake3_challenge_block_test.zig");
    _ = @import("recursion/air/tests/blake3_byte_route_test.zig");
    _ = @import("recursion/air/tests/blake3_path_select_test.zig");
    _ = @import("recursion/air/tests/blake3_frame_test.zig");
    _ = @import("recursion/air/tests/blake3_private_input_test.zig");
    _ = @import("recursion/air/tests/blake3_hash_test.zig");
}
