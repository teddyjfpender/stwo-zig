//! Source and table admission contracts requiring no CUDA device or runtime.
comptime {
    _ = @import("canonical_feeds.zig");
    _ = @import("canonical_source.zig");
    _ = @import("witness_multi_edge_test.zig");
    _ = @import("executor/ingress/relation_binding.zig");
    _ = @import("executor/ingress/writer_base_tables.zig");
    _ = @import("executor/trace_commit.zig");
    _ = @import("executor/pcs_oods_topology.zig");
    _ = @import("executor/pcs_oods_topology_test.zig");
}
