//! Marker retains actual original producers/receivers, never executes them.
const std = @import("std");
const Attach = @import("recursion/block_v5_recursive_fixed_attachments_v1.zig");
const Graph = @import("recursion/air/block_v5_recursive_fixed_graph_attach_v1.zig");
const Namespace = @import("recursion/air/block_v5_recursive_fixed_namespace_v1.zig");
const Pieces = @import("recursion/block_v5_recursive_parent_fixed_pieces_v1.zig");
const Wire = @import("recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire;
fn collectOriginalFixedChild(a: std.mem.Allocator, pieces: *const Pieces.Owned, term_count: usize, child: u32) ![]Wire {
    return @import("recursion/air/block_v5_recursive_fixed_child_suppliers_v1.zig").collect(a, pieces.transcript.fixed.fixed, &pieces.composition, term_count, child, @import("recursion/block_v5_closed_input_request_forest_source_v2.zig").PUBLIC_CIRCUIT);
}
pub export fn stwo_recursive_fixed_attachments_body_gate() void {
    inline for (.{ &Namespace.prepare, &Namespace.prepareForArithmetic, &Namespace.apply, &Namespace.Plan.deinit, &Graph.Owned.derive, &Graph.Owned.validateLive, &Graph.Owned.deinit, &Attach.Scoped.init, &Attach.Scoped.appendChild, &Attach.Scoped.appendChildWithArithmetic, &Attach.Scoped.appendGraph, &Attach.Scoped.appendGraphWithArithmetic, &Attach.Scoped.project, &Attach.Scoped.deinit, &Attach.Projected.deinit, &collectOriginalFixedChild, &@import("recursion/air/arithmetic_fusion_rows.zig").materializeIdentifiers }) |body| std.mem.doNotOptimizeAway(body);
    // Genuine bounded RAM/PAGE setup/preparation/fresh source bodies, plus
    // public21's distinct external-public grammar. No fake captures/keys.
    std.mem.doNotOptimizeAway(&@import("block_v5_ram_range_forest_owned_codegen_v1.zig").stwo_ram_range_forest_owned_body_gate);
    std.mem.doNotOptimizeAway(&@import("block_v5_memory_source_page_forest_codegen_v1.zig").stwo_source_page_forest_body_gate);
    const PublicProducer = @import("recursion/block_v5_requester_public_producer_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    inline for (.{ &@import("recursion/block_v5_requester_public_preparation_v1.zig").prepare, &@import("recursion/block_v5_requester_public_receiver_v1.zig").verify, &PublicProducer.deriveKey, &PublicProducer.init, &PublicProducer.proveEncodedConsuming }) |body| std.mem.doNotOptimizeAway(body);
    std.mem.doNotOptimizeAway(&@import("block_v5_recursive_parent_fixed_roster_codegen_v1.zig").stwo_recursive_parent_fixed_roster_body_gate);
}
