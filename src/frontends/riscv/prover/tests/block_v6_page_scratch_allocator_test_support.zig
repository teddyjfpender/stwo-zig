//! Test-only genuine PAGE public validation with admission scratch clamped to
//! its measured metadata need. This rejects charging wide fixed data to it.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.HostBudgetAllocator;
const Semantic = @import("../block_v5_memory_source_page_semantic_columns_v1.zig");
const Admission = @import("../block_v5_memory_source_page_recursive_admission_v1.zig");
const Public = @import("../../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig");
pub fn check(comptime kind: Semantic.Kind, a: std.mem.Allocator, admitted: *const Admission.ForKind(kind).Prepared, claims: Public.ForKind(kind).Claims) !void {
    var metadata = Budget.init(a, 8 << 20);
    var limited = admitted.*;
    limited.allocator = metadata.allocator();
    try limited.validate(limited.template_id);
    try std.testing.expectEqual(@as(usize, 0), metadata.live_bytes);
    const metadata_peak = metadata.peak_live_bytes;
    metadata.limit = metadata_peak;
    var live = Budget.init(a, admitted.limits.page.max_receiver_heap_bytes);
    var values = try Public.ForKind(kind).Values.init(live.allocator(), &limited, claims);
    try values.validate();
    values.deinit();
    try std.testing.expectEqual(@as(usize, 0), live.live_bytes);
    try std.testing.expectEqual(metadata_peak, metadata.peak_live_bytes);
    try std.testing.expect(!metadata.didExceedBudget());
    try std.testing.expect(live.peak_live_bytes > metadata_peak);
}
