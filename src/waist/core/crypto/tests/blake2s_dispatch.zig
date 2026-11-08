const std = @import("std");
const backend = @import("../blake2s_backend.zig");

test "blake2s backend: backend selection is observable and captured per hasher" {
    const scalar = backend.Blake2sHasher.initWithMode(.scalar);
    try std.testing.expectEqual(backend.BackendMode.scalar, scalar.backendSelection().requested);
    try std.testing.expectEqual(backend.BackendMode.scalar, scalar.backendSelection().effective);
    try std.testing.expectEqual(@as(usize, 4), scalar.backendSelection().explicit_simd_width);

    const automatic = backend.selectBackend(.auto);
    try std.testing.expectEqual(
        if (backend.supportsSimdBackend()) backend.BackendMode.simd else backend.BackendMode.scalar,
        automatic.effective,
    );
    try std.testing.expectEqual(backend.supportsSimdBackend(), automatic.simd_supported);

    const requested_simd = backend.Blake2sHasher.initWithMode(.simd).backendSelection();
    try std.testing.expectEqual(backend.BackendMode.simd, requested_simd.requested);
    try std.testing.expectEqual(
        if (backend.supportsSimdBackend()) backend.BackendMode.simd else backend.BackendMode.scalar,
        requested_simd.effective,
    );
}

test "blake2s backend: process default changes do not alter existing hashers" {
    const previous = backend.getDefaultBackendMode();
    defer backend.setDefaultBackendMode(previous);

    backend.setDefaultBackendMode(.scalar);
    var scalar = backend.Blake2sHasher.init();
    backend.setDefaultBackendMode(.simd);
    try std.testing.expectEqual(backend.BackendMode.scalar, scalar.backendSelection().effective);
    scalar.update("captured backend selection");
    const captured = scalar.finalize();
    const expected = backend.Blake2sHasher.hashWithMode(.scalar, "captured backend selection");
    try std.testing.expectEqualSlices(u8, expected[0..], captured[0..]);
}

test "blake2s backend: compatibility selectors preserve default semantics" {
    const previous = backend.getBackendMode();
    defer backend.setBackendMode(previous);

    backend.setBackendMode(.scalar);
    try std.testing.expectEqual(backend.BackendMode.scalar, backend.getBackendMode());
    try std.testing.expectEqual(backend.BackendMode.scalar, backend.getEffectiveBackendMode());

    backend.setBackendMode(.simd);
    try std.testing.expectEqual(backend.BackendMode.simd, backend.getBackendMode());
    try std.testing.expectEqual(
        if (backend.supportsSimdBackend()) backend.BackendMode.simd else backend.BackendMode.scalar,
        backend.getEffectiveBackendMode(),
    );
}

test "blake2s backend: four-lane helpers honor explicit dispatch mode" {
    const prefix = [_]u8{0x42} ** 64;
    const blocks = [_][64]u8{[_]u8{0x24} ** 64} ** 4;
    const seed = backend.Blake2sHasher.seedAfterFixed64WithMode(.scalar, &prefix);

    backend.resetTestCompressionCounts();
    _ = backend.Blake2sHasher.hashFinal64FromSeed4WithMode(.scalar, seed, &blocks);
    const scalar_counts = backend.testCompressionCounts();
    try std.testing.expect(scalar_counts.scalar >= 4);
    try std.testing.expectEqual(@as(u64, 0), scalar_counts.simd);
    try std.testing.expectEqual(@as(u64, 0), scalar_counts.parallel_simd_4);

    backend.resetTestCompressionCounts();
    _ = backend.Blake2sHasher.hashFinal64FromSeed4WithMode(.simd, seed, &blocks);
    const simd_counts = backend.testCompressionCounts();
    if (backend.supportsSimdBackend()) {
        try std.testing.expectEqual(@as(u64, 0), simd_counts.scalar);
        try std.testing.expectEqual(@as(u64, 0), simd_counts.simd);
        try std.testing.expectEqual(@as(u64, 1), simd_counts.parallel_simd_4);
    } else {
        try std.testing.expect(simd_counts.scalar >= 4);
        try std.testing.expectEqual(@as(u64, 0), simd_counts.parallel_simd_4);
    }
}

test "blake2s backend: four-way read-only aliases and scalar tails are supported" {
    var prng = std.Random.DefaultPrng.init(0xbb67_ae85_84ca_a73b);
    var prefix: [64]u8 = undefined;
    var storage: [260]u8 = undefined;
    prng.random().bytes(prefix[0..]);
    prng.random().bytes(storage[0..]);
    const seed = backend.Blake2sHasher.seedAfterFixed64WithMode(.scalar, &prefix);

    try std.testing.expectEqual(@as(usize, 1), backend.SimdContract.input_alignment);
    try std.testing.expectEqual(@as(usize, 0), backend.SimdContract.caller_scratch_bytes);
    try std.testing.expect(backend.SimdContract.scalar_tail_supported);
    try std.testing.expect(backend.SimdContract.read_only_input_aliasing_supported);

    inline for (.{ @as(usize, 1), 63, 64, 65, 129, 257 }) |len| {
        const shared = storage[1 .. 1 + len];
        const aliases = [4][]const u8{ shared, shared, shared, shared };
        const batched = backend.Blake2sHasher.hashEqualFromSeed4(seed, &aliases);
        var scalar = backend.Blake2sHasher.initWithMode(.scalar);
        scalar.update(prefix[0..]);
        scalar.update(shared);
        const expected = scalar.finalize();
        for (batched) |digest| {
            try std.testing.expectEqualSlices(u8, expected[0..], digest[0..]);
        }
    }
}
