//! Original independent pointer-packet oracle, separate from admitted primitives.
const std = @import("std");
const curves = @import("../services/curve_packets.zig");
const C = @import("../ethereum_services/candidate_curves.zig");
const ALL = curves.ALL;
const MAX_WORDS = curves.MAX_WORDS;
const words = curves.words;
const tag = curves.tag;
const execute = curves.execute;

test "admitted inline packets agree with the candidate pointer-packet executor" {
    const memory = @import("../memory.zig");
    var prng = std.Random.DefaultPrng.init(0x30100);
    const rng = prng.random();
    const base: u64 = 0x10000;
    var mem = memory.Memory.init(std.testing.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = base, .size = 0x4000, .permissions = .{ .read = true, .write = true } });
    for (ALL) |op| {
        var done: usize = 0;
        while (done < 24) {
            var packet: [MAX_WORDS]u64 = @splat(0);
            for (packet[0..words(op)]) |*w| w.* = rng.int(u64);
            // Mostly-canonical operands: clear the top bits of each value.
            const limbs: usize = if (@intFromEnum(op) <= 7) 4 else 6;
            const values = @min(4, words(op) / limbs);
            for (0..values) |i| packet[i * limbs + limbs - 1] &= if (limbs == 4) 0x0fffffffffffffff else 0x00ffffffffffffff;
            if (op == .arith384_mont) packet[12] |= 1;
            const after = execute(op, packet[0..words(op)]) catch continue;
            // Candidate: operands at separate addresses, pointer packet at base.
            const k = C.kindOf(tag(op)).?;
            const operand = base + 0x100;
            for (0..words(op)) |i| try mem.storeWords(operand + 8 * i, &.{packet[i]});
            const out = base + 0x800;
            const ptrs: []const u64 = switch (op) {
                .bn254_g1_add, .bn254_fp2_mul => &.{ out, operand, operand + 64 },
                .bn254_g1_double => &.{ out, operand },
                .bls12_381_fp2_mul, .bls12_381_g1_add => &.{ out, operand, operand + 96 },
                .bls12_381_g1_double => &.{ out, operand },
                .arith384_mont => &.{ operand, operand + 48, operand + 96, out },
            };
            try mem.storeWords(base, ptrs);
            _ = try C.execute(k, base, &mem);
            const out_words = if (op == .arith384_mont) @as(usize, 6) else 2 * limbs;
            for (0..out_words) |i| try std.testing.expectEqual(try mem.load(out + 8 * i, 8), after[i]);
            for (out_words..words(op)) |i| try std.testing.expectEqual(packet[i], after[i]);
            done += 1;
        }
    }
}
