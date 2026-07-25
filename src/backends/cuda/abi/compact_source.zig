//! Stable logical-column descriptors for compact resident source arenas.

/// One logical source column inside a compact, variably-strided backing.
///
/// The explicit 64-bit offset keeps the device ABI stable across hosts and
/// admits Cairo-scale arenas without truncating word offsets.
pub const Descriptor = extern struct {
    offset_words: u64,
    stride_words: u32,
    log_size: u32,
};

/// One logical source column at an authenticated, address-stable device
/// location. This is the multi-arena form used when proof-persistent and
/// request-local commitment trees participate in the same quotient.
pub const AddressedDescriptor = extern struct {
    address: u64,
    stride_words: u32,
    log_size: u32,
};

test "compact source ABI is stable" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Descriptor));
    try std.testing.expectEqual(@as(usize, 8), @alignOf(Descriptor));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Descriptor, "offset_words"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Descriptor, "stride_words"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(Descriptor, "log_size"));
    try std.testing.expectEqual(
        @as(usize, 16),
        @sizeOf(AddressedDescriptor),
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        @alignOf(AddressedDescriptor),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        @offsetOf(AddressedDescriptor, "address"),
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        @offsetOf(AddressedDescriptor, "stride_words"),
    );
    try std.testing.expectEqual(
        @as(usize, 12),
        @offsetOf(AddressedDescriptor, "log_size"),
    );
}
