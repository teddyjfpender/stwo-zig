//! Known answers and a CPU sweep for the circuit grinds, shared by the
//! emulation tests (any host) and the device tests (a GPU host).
//!
//! A grind under test is `fn (Output, prefix, pow_bits) !u64`. It must
//! return exactly the CPU channel's canonical nonce
//! (`Blake2s{,M31}Channel.grindWithWorkerCount`, Rust Stwo's `SimdBackend`
//! order, `core/channel/blake2s_pow_order.zig`).

const std = @import("std");
const core = @import("stwo_core");
const device_grind = @import("device_grind.zig");

const Blake2sChannel = core.channel.blake2s.Blake2sChannel;
const Blake2sM31Channel = core.channel.blake2s.Blake2sM31Channel;
const Output = device_grind.Output;

fn ChannelOf(comptime output: Output) type {
    return switch (output) {
        .plain => Blake2sChannel,
        .m31 => Blake2sM31Channel,
    };
}

const Vector = struct { output: Output, seed: u64, bits: u32, nonce: u64 };

/// `core/channel/blake2s.zig`'s Rust Stwo `SimdBackend` known answers
/// (7b211ed, and proving@5a7c5ed after `mix_u64(0x1111222233334344)`),
/// including both 26-bit production shapes.
pub const rust_vectors = [_]Vector{
    .{ .output = .plain, .seed = 1, .bits = 20, .nonce = 12885063745 },
    .{ .output = .plain, .seed = 0, .bits = 24, .nonce = 77309505868 },
    .{ .output = .plain, .seed = 0, .bits = 26, .nonce = 34360584583 },
    .{ .output = .m31, .seed = 1, .bits = 20, .nonce = 12885632339 },
    .{ .output = .m31, .seed = 1, .bits = 24, .nonce = 4295766292 },
    .{ .output = .m31, .seed = 0x1111_2222_3333_4344, .bits = 26, .nonce = 150324282603 },
    .{ .output = .plain, .seed = 0x1111_2222_3333_4344, .bits = 10, .nonce = 0x413 },
    .{ .output = .m31, .seed = 0x1111_2222_3333_4344, .bits = 10, .nonce = 0x415 },
    .{ .output = .plain, .seed = 0x1111_2222_3333_4344, .bits = 20, .nonce = 0xede9 },
    .{ .output = .m31, .seed = 0x1111_2222_3333_4344, .bits = 20, .nonce = 0x1_0005_a700 },
    .{ .output = .plain, .seed = 0x1111_2222_3333_4344, .bits = 24, .nonce = 0x9_000e_1aa1 },
    .{ .output = .m31, .seed = 0x1111_2222_3333_4344, .bits = 24, .nonce = 0xf_0001_6fbd },
    .{ .output = .plain, .seed = 0, .bits = 20, .nonce = 674794 },
    .{ .output = .m31, .seed = 0, .bits = 20, .nonce = 340382 },
};

fn prefixFor(comptime output: Output, seed: u64, bits: u32) [32]u8 {
    var channel = ChannelOf(output){};
    channel.mixU64(seed);
    return channel.computePowPrefix(bits);
}

/// Every Rust known answer; `max_bits` skips the slow ones.
pub fn expectRustVectors(grind: anytype, max_bits: u32) !void {
    for (rust_vectors) |vector| {
        if (vector.bits > max_bits) continue;
        const prefix = switch (vector.output) {
            inline else => |output| prefixFor(output, vector.seed, vector.bits),
        };
        const nonce = try grind(vector.output, prefix, vector.bits);
        if (nonce != vector.nonce) {
            std.debug.print("{s} seed 0x{x} bits {d}: got 0x{x}, want 0x{x}\n", .{
                @tagName(vector.output), vector.seed, vector.bits, nonce, vector.nonce,
            });
            return error.TestExpectedEqual;
        }
    }
}

/// Both channels, `seeds` transcripts each, every width in `bits`, against
/// the CPU grind.
pub fn expectCpuSweep(grind: anytype, seeds: u64, bits: []const u32) !void {
    inline for (.{ Output.plain, Output.m31 }) |output| {
        for (0..seeds) |seed_index| {
            var channel = ChannelOf(output){};
            channel.mixU64(0x9e37_79b9_7f4a_7c15 *% (seed_index + 1));
            for (bits) |pow_bits| {
                const expected = channel.grindWithWorkerCount(pow_bits, 8);
                const nonce = try grind(output, channel.computePowPrefix(pow_bits), pow_bits);
                if (nonce != expected) {
                    std.debug.print("{s} seed #{d} bits {d}: got 0x{x}, want 0x{x}\n", .{
                        @tagName(output), seed_index, pow_bits, nonce, expected,
                    });
                    return error.TestExpectedEqual;
                }
                try std.testing.expect(channel.verifyPowNonce(pow_bits, nonce));
            }
        }
    }
}
