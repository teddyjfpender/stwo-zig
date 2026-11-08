/// Advances four independent BLAKE2s G functions in lockstep. Grouping each
/// dependency level exposes four-way instruction-level parallelism while
/// retaining the caller's four-message SIMD lane layout.
pub inline fn g4Interleaved(
    comptime V: type,
    comptime rotate: anytype,
    v: *[16]V,
    comptime a_indices: [4]u8,
    comptime b_indices: [4]u8,
    comptime c_indices: [4]u8,
    comptime d_indices: [4]u8,
    x: [4]V,
    y: [4]V,
) void {
    inline for (0..4) |i| {
        v[a_indices[i]] = v[a_indices[i]] +% v[b_indices[i]] +% x[i];
    }
    inline for (0..4) |i| {
        v[d_indices[i]] = rotate(v[d_indices[i]] ^ v[a_indices[i]], 16);
    }
    inline for (0..4) |i| {
        v[c_indices[i]] +%= v[d_indices[i]];
    }
    inline for (0..4) |i| {
        v[b_indices[i]] = rotate(v[b_indices[i]] ^ v[c_indices[i]], 12);
    }
    inline for (0..4) |i| {
        v[a_indices[i]] = v[a_indices[i]] +% v[b_indices[i]] +% y[i];
    }
    inline for (0..4) |i| {
        v[d_indices[i]] = rotate(v[d_indices[i]] ^ v[a_indices[i]], 8);
    }
    inline for (0..4) |i| {
        v[c_indices[i]] +%= v[d_indices[i]];
    }
    inline for (0..4) |i| {
        v[b_indices[i]] = rotate(v[b_indices[i]] ^ v[c_indices[i]], 7);
    }
}
