//! Source and table admission contracts requiring no CUDA device or runtime.
comptime {
    _ = @import("tests/eval_slices_test.zig");

    _ = @import("canonical_eval_aot.zig");
    _ = @import("canonical_feeds.zig");
    _ = @import("canonical_source.zig");
    _ = @import("canonical_input.zig");
    _ = @import("recorded_witness.zig");
    _ = @import("tests/witness_multi_edge_test.zig");
    _ = @import("executor/ingress/relation_binding.zig");
    _ = @import("executor/ingress/writer_base_tables.zig");
    _ = @import("executor/trace_commit.zig");
    _ = @import("executor/canonical_twiddles.zig");
    _ = @import("executor/eval/topology_test.zig");
    _ = @import("executor/tests/trace_commit_test.zig");
    _ = @import("executor/pcs_oods_topology.zig");
    _ = @import("executor/tests/pcs_oods_topology_test.zig");
    _ = @import("executor/quotient/controller_test.zig");
    _ = @import("executor/quotient/buckets.zig");
    _ = @import("executor/tests/pcs_decommit_topology_test.zig");
    _ = @import("executor/tests/pcs_fri_controller_test.zig");
}
