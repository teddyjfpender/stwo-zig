//! M8 GPU-native TruthJob + device seed fill host tests (recursion stream,
//! piece r-truth): challenge scripts, parameter programs, class plans and
//! seed programs. No GPU.
test {
    _ = @import("rv64/jobs/truth_challenges.zig");
    _ = @import("rv64/jobs/truth_params.zig");
    _ = @import("rv64/jobs/truth_interaction.zig");
    _ = @import("rv64/jobs/truth_class.zig");
    _ = @import("rv64/jobs/truth_job.zig");
    _ = @import("rv64/jobs/truth_factory.zig");
    // gn-bind: the service binding composes the native and truth factories.
    _ = @import("rv64/jobs/driver_bind.zig");
    _ = @import("rv64/jobs/truth_oods.zig");
}
