//! Exact field and hash layouts used by the imported CUDA kernels.

const std = @import("std");

pub const SecureField = extern struct {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
};

pub const CirclePointBaseField = extern struct {
    x: u32,
    y: u32,
};

pub const SecureCirclePoint = extern struct {
    x: SecureField,
    y: SecureField,
};

pub const Blake2sHash = extern struct {
    bytes: [32]u8 align(32),
};

pub const ProgressiveBlake2sState = extern struct {
    h: [8]u32,
    pending: [16]u32,
};

pub const MerkleLayerDescriptor = extern struct {
    offset_hashes: u64,
    hash_count: u32,
    reserved: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(SecureField) == 16);
    std.debug.assert(@alignOf(SecureField) == 4);
    std.debug.assert(@sizeOf(CirclePointBaseField) == 8);
    std.debug.assert(@sizeOf(SecureCirclePoint) == 32);
    std.debug.assert(@alignOf(SecureCirclePoint) == 4);
    std.debug.assert(@sizeOf(Blake2sHash) == 32);
    std.debug.assert(@alignOf(Blake2sHash) == 32);
    std.debug.assert(@sizeOf(ProgressiveBlake2sState) == 96);
    std.debug.assert(@offsetOf(ProgressiveBlake2sState, "pending") == 32);
    std.debug.assert(@sizeOf(MerkleLayerDescriptor) == 16);
    std.debug.assert(@alignOf(MerkleLayerDescriptor) == 8);
}

test "CUDA field layouts remain plain explicit words" {
    try std.testing.expectEqual(
        @as(usize, 4),
        @sizeOf(SecureField) / @sizeOf(u32),
    );
}
