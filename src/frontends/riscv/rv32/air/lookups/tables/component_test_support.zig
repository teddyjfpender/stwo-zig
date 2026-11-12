//! Dependency-light assertions for lookup-table prepared-domain accounting.

const std = @import("std");

pub fn verifyPreparedDomainResources(
    comptime resourcesFor: anytype,
    secure_element_bytes: usize,
    expected_shared_bytes: usize,
    expected_worker_stack_bytes: usize,
    cancellation_poll_rows: usize,
) !void {
    const owned_count: usize = 3;
    const resources = try resourcesFor(17, owned_count);
    try std.testing.expectEqual(17 * secure_element_bytes, resources.final_output_bytes);
    try std.testing.expectEqual(expected_shared_bytes, resources.shared_resident_bytes);
    try std.testing.expectEqual(expected_worker_stack_bytes, resources.worker_stack_bytes);
    try std.testing.expect(cancellation_poll_rows <= 4096);
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        resourcesFor(std.math.maxInt(usize) / secure_element_bytes, owned_count),
    );
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        resourcesFor(17, std.math.maxInt(usize)),
    );
}
