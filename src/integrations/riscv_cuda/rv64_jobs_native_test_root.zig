//! M8 native-job host tests (and opt-in real-GPU tests, env-gated): PCS framing,
//! commit plan, opening tail, stage transcripts. GPU tests skip without
//! STWO_RV64_M8_GPU_BASE / STWO_RV64_M8_JOBS_LIBRARY.
test {
    _ = @import("rv64/jobs/native_commit.zig");
    _ = @import("rv64/jobs/native_commit_test.zig");
    _ = @import("rv64/jobs/native_gpu_support_test.zig");
    _ = @import("rv64/jobs/native_pcs.zig");
    _ = @import("rv64/jobs/native_pcs_test.zig");
    _ = @import("rv64/jobs/native_tail_test.zig");
}
