const std = @import("std");
const arithmetic = @import("stwo_riscv_precompiles").primitives.arith256;
const limbs = arithmetic.limbs;
const mulAddModPacket = arithmetic.mulAddModPacket;

test "packet arith256_mod matches the candidate executor's semantics" {
    const Candidate = @import("stwo_riscv_rv64").ethereum_services.candidate_services;
    var prng = std.Random.DefaultPrng.init(0x21);
    const rng = prng.random();
    for (0..256) |i| {
        var packet: [20]u64 = undefined;
        for (&packet) |*w| w.* = rng.int(u64);
        if (i % 7 == 0) @memset(packet[12..16], 0);
        if (i % 5 == 0) @memset(packet[13..16], 0);
        const expected = Candidate.mulAddMod(limbs(packet[0..4]), limbs(packet[4..8]), limbs(packet[8..12]), limbs(packet[12..16]));
        try std.testing.expectEqual(expected, limbs(&mulAddModPacket(packet)));
    }
}
