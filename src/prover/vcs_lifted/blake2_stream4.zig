//! Prover-side adapter for four-message BLAKE2s leaf continuation.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const BackendHasher = stwo_core.crypto.blake2s_backend.Blake2sHasher;
const CoreHasher = stwo_core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;

pub fn supports(comptime H: type) bool {
    return H == CoreHasher;
}

pub fn hashChildren8(
    seed: CoreHasher.NodeSeed,
    children: *const [16]CoreHasher.Hash,
) [8]CoreHasher.Hash {
    var payloads: [8][64]u8 = undefined;
    for (&payloads, 0..) |*payload, lane| {
        @memcpy(payload[0..32], children[2 * lane][0..]);
        @memcpy(payload[32..64], children[2 * lane + 1][0..]);
    }
    return BackendHasher.hashFinal64FromSeed8(seed, &payloads);
}

fn loadStates(hashers: *const [4]CoreHasher) [4]BackendHasher {
    var states: [4]BackendHasher = undefined;
    for (0..4) |lane| states[lane] = hashers[lane].inner.ctx;
    return states;
}

fn storeStates(hashers: *[4]CoreHasher, states: *const [4]BackendHasher) void {
    for (0..4) |lane| hashers[lane].inner.ctx = states[lane];
}

pub fn updatePacked4(
    hashers: *[4]CoreHasher,
    packed_bytes: *const [4][]const u8,
) void {
    var states = loadStates(hashers);
    BackendHasher.updateEqual4(&states, packed_bytes);
    storeStates(hashers, &states);
}

pub fn updateM31Columns4(
    hashers: *[4]CoreHasher,
    columns: anytype,
    position: usize,
) void {
    var states = loadStates(hashers);
    BackendHasher.updateM31Columns4(&states, columns, position);
    storeStates(hashers, &states);
}

pub fn finalize4(hashers: *const [4]CoreHasher) [4]CoreHasher.Hash {
    const states = loadStates(hashers);
    const empty = [_]u8{};
    const tails = [_][]const u8{empty[0..]} ** 4;
    return BackendHasher.finalizeEqualTail4(&states, &tails);
}

pub fn finalizeTail4(
    hashers: *const [4]CoreHasher,
    tail_values: *const [4][]const M31,
) [4]CoreHasher.Hash {
    if (comptime builtin.cpu.arch.endian() != .little) {
        var out: [4]CoreHasher.Hash = undefined;
        for (&out, 0..) |*digest, lane| {
            var hasher = hashers[lane];
            hasher.updateLeaf(tail_values[lane]);
            digest.* = hasher.finalize();
        }
        return out;
    }

    const states = loadStates(hashers);
    var byte_views: [4][]const u8 = undefined;
    for (0..4) |lane| byte_views[lane] = std.mem.sliceAsBytes(tail_values[lane]);
    return BackendHasher.finalizeEqualTail4(&states, &byte_views);
}

test "prover lifted BLAKE2s: direct continuation matches scalar streams" {
    const Column = struct { values: []const M31 };
    var prefixes: [4][17]M31 = undefined;
    var storage: [33][4]M31 = undefined;
    var columns: [storage.len]Column = undefined;
    var expected: [4]CoreHasher = undefined;
    var actual: [4]CoreHasher = undefined;

    for (0..4) |lane| {
        for (&prefixes[lane], 0..) |*value, index| {
            value.* = M31.fromCanonical(@intCast(3 + lane * 701 + index * 29));
        }
        expected[lane] = CoreHasher.defaultWithInitialState();
        expected[lane].updateLeaf(prefixes[lane][0..]);
        actual[lane] = expected[lane];
    }
    for (&storage, &columns, 0..) |*values, *column, column_index| {
        for (values, 0..) |*value, lane| {
            value.* = M31.fromCanonical(@intCast(7 + column_index * 43 + lane * 101));
        }
        column.* = .{ .values = values };
    }

    updateM31Columns4(&actual, &columns, 0);
    for (0..4) |lane| {
        var row: [storage.len]M31 = undefined;
        for (storage, 0..) |values, column_index| row[column_index] = values[lane];
        expected[lane].updateLeaf(row[0..]);
        const expected_hash = expected[lane].finalize();
        const actual_hash = actual[lane].finalize();
        try std.testing.expectEqualSlices(u8, expected_hash[0..], actual_hash[0..]);
    }
}
