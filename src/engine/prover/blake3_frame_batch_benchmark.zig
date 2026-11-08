//! Opt-in bounded CPU primitive diagnostic, never a prover performance claim.
//! No work starts on import or in production. Tests call only invalid limits,
//! which fail before timers, warm-up or compression work starts.
const std = @import("std");
const core = @import("stwo_core");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const scalar = core.crypto.blake3_compression;
const pow_batch = @import("pcs/blake3_pow_batch.zig");
pub const max_iterations: u32 = 65536;
pub const sample_count = 4;
pub const Sample = struct {
    batch_first: bool,
    node_scalar_ns: u64,
    node_batch4_ns: u64,
    pow_final_block_scalar_ns: u64,
    pow_final_block_batch4_ns: u64,
    node_checksum: u64,
    pow_checksum: u64,
};
pub const Report = struct {
    iterations: u32,
    // Each path processes four nodes/candidates per iteration.
    operations_per_sample: u64,
    samples: [sample_count]Sample,
};
const NodeResult = struct { ns: u64, final: [4]H.Hash };
fn nodes(comptime batched: bool, iterations: u32) !NodeResult {
    var children: [8]H.Hash = undefined;
    for (&children, 0..) |*child, i| child.* = @splat(@as(u8, @intCast(17 + i * 29)));
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        var result: [4]H.Hash = undefined;
        if (batched) {
            result = H.hashChildrenWithSeed4(H.nodeSeed(), &children);
        } else {
            for (&result, 0..) |*digest, lane| digest.* = H.hashChildren(.{ .left = children[2 * lane], .right = children[2 * lane + 1] });
        }
        // Four independent chains prevent the loop from hashing a constant.
        for (result, 0..) |digest, lane| children[2 * lane] = digest;
    }
    const final: [4]H.Hash = .{ children[0], children[2], children[4], children[6] };
    std.mem.doNotOptimizeAway(&final);
    const ns = timer.read();
    return .{ .ns = ns, .final = final };
}
const PowResult = struct { ns: u64, checksum: u64 };
fn powWordsScalar(cv: [8]u32, nonces: [4]u64) [4]u32 {
    var result: [4]u32 = undefined;
    for (nonces, &result) |nonce, *word| {
        var block: [16]u32 = @splat(0);
        block[0] = @truncate(nonce);
        block[1] = @truncate(nonce >> 32);
        const output = scalar.compress(cv, block, 0, 8, 2 | 8) catch unreachable;
        word.* = output[0];
    }
    return result;
}
fn powFinalBlocks(comptime batched: bool, iterations: u32, cv: [8]u32) !PowResult {
    var checksum: u64 = 0;
    var timer = try std.time.Timer.start();
    for (0..iterations) |iteration| {
        const first: u64 = 0xfffffffc + @as(u64, @intCast(iteration)) * 4;
        const nonces: [4]u64 = .{ first, first + 1, first + 2, first + 3 };
        const words = if (batched) pow_batch.firstWords(cv, nonces) else powWordsScalar(cv, nonces);
        for (words) |word| checksum +%= word;
    }
    std.mem.doNotOptimizeAway(&checksum);
    const ns = timer.read();
    return .{ .ns = ns, .checksum = checksum };
}
fn nodeChecksum(digests: [4]H.Hash) u64 {
    var result: u64 = 0;
    for (digests) |digest| {
        for (digest) |byte| result = (result *% 257) +% byte;
    }
    return result;
}
/// Four ABBA-order samples, constant bounded stack storage and no heap.
/// Compares equal work: framed node chains, then nonce final compressions with
/// the same already-compressed prefix. It does not search for a winning nonce.
pub fn run(iterations: u32) !Report {
    if (iterations == 0 or iterations > max_iterations) return error.InvalidBlake3BenchmarkIterations;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x12345678, 26, 0xffffffff });
    const cv = try channel.powChainingValue(26);
    _ = try nodes(false, 32);
    _ = try nodes(true, 32);
    _ = try powFinalBlocks(false, 32, cv);
    _ = try powFinalBlocks(true, 32, cv);
    var report: Report = .{ .iterations = iterations, .operations_per_sample = @as(u64, iterations) * 4, .samples = undefined };
    for (&report.samples, 0..) |*sample, index| {
        const batch_first = index == 1 or index == 2;
        const first_nodes = if (batch_first) try nodes(true, iterations) else try nodes(false, iterations);
        const second_nodes = if (batch_first) try nodes(false, iterations) else try nodes(true, iterations);
        const first_pow = if (batch_first) try powFinalBlocks(true, iterations, cv) else try powFinalBlocks(false, iterations, cv);
        const second_pow = if (batch_first) try powFinalBlocks(false, iterations, cv) else try powFinalBlocks(true, iterations, cv);
        if (!std.meta.eql(first_nodes.final, second_nodes.final) or first_pow.checksum != second_pow.checksum) return error.Blake3BenchmarkDigestMismatch;
        sample.* = .{
            .batch_first = batch_first,
            .node_scalar_ns = if (batch_first) second_nodes.ns else first_nodes.ns,
            .node_batch4_ns = if (batch_first) first_nodes.ns else second_nodes.ns,
            .pow_final_block_scalar_ns = if (batch_first) second_pow.ns else first_pow.ns,
            .pow_final_block_batch4_ns = if (batch_first) first_pow.ns else second_pow.ns,
            .node_checksum = nodeChecksum(first_nodes.final),
            .pow_checksum = first_pow.checksum,
        };
    }
    return report;
}
