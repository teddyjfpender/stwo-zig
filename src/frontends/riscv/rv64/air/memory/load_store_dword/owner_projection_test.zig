//! Independent integer oracle for affine OWNER coordinates, including rows
//! outside Boolean witness support: projection equality must hold there too.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("mod.zig");
const M = core.fields.m31.M31;
const L = D.layout;
const P: i128 = core.fields.m31.Modulus;
fn canonical(value: i128) u32 {
    return @intCast(@mod(value, P));
}
fn degree(comptime F: type) usize {
    return if (F == M) 1 else @typeInfo(@TypeOf(F.zero().toM31Array())).array.len;
}
fn fromWords(comptime F: type, words: [degree(F)]M) F {
    return if (F == M) words[0] else F.fromM31Array(words);
}
fn wordsOf(comptime F: type, value: F) [degree(F)]M {
    return if (F == M) .{value} else value.toM31Array();
}
fn logicalCoordinate(row: anytype, logical: usize, coordinate: usize) i128 {
    return row[L.column(logical)][coordinate].v;
}
test "LS-D64 OWNER high-residue affine coordinates match independent integer residues" {
    const seed = 0x358_d640_87323;
    var random = std.Random.DefaultPrng.init(seed);
    inline for (.{ M, core.fields.qm31.QM31, core.fields.om31.OM31 }) |F| {
        for (0..64) |trial| {
            errdefer std.debug.print("Dword OWNER seed=0x{x} field={s} trial={d}\n", .{ seed, @typeName(F), trial });
            var input: [L.MAIN][degree(F)]M = undefined;
            var row: [L.MAIN]F = undefined;
            for (&input, &row, 0..) |*coordinates, *value, column| {
                for (coordinates, 0..) |*coordinate, i| {
                    const raw = if (trial == 0) core.fields.m31.Modulus - 1 else if (trial == 1) core.fields.m31.Modulus - 2 - @as(u32, @intCast((column + i) % 3)) else random.random().uintLessThan(u32, core.fields.m31.Modulus);
                    coordinate.* = M.fromCanonical(raw);
                }
                value.* = fromWords(F, coordinates.*);
            }
            const actual = D.equations.ownerTuple(F, &row);
            for (0..degree(F)) |coordinate| {
                var expected: [19]u32 = undefined;
                const active = logicalCoordinate(input, 0, coordinate);
                const store = logicalCoordinate(input, 1, coordinate);
                expected[0] = canonical((active - store) * L.LD_OPCODE + store * L.SD_OPCODE);
                for (0..4) |limb| {
                    const operand_a = logicalCoordinate(input, 28 + limb, coordinate);
                    const operand_b = logicalCoordinate(input, 36 + limb, coordinate);
                    const address = if (limb == 0) 8 * logicalCoordinate(input, 68, coordinate) else logicalCoordinate(input, 4 + limb, coordinate);
                    const carry = logicalCoordinate(input, 75 + limb, coordinate);
                    const carry_in = if (limb == 0) 0 else logicalCoordinate(input, 74 + limb, coordinate);
                    expected[1 + limb] = canonical(operand_a);
                    expected[5 + limb] = canonical(address + 65536 * carry - operand_a - carry_in);
                    expected[9 + limb] = canonical(operand_b);
                    expected[13 + limb] = canonical(logicalCoordinate(input, 18 + limb, coordinate) - operand_b);
                }
                expected[17] = canonical(logicalCoordinate(input, 9, coordinate));
                expected[18] = canonical(logicalCoordinate(input, 12, coordinate) + 65536 * logicalCoordinate(input, 13, coordinate));
                for (actual, expected) |value, reference| try std.testing.expectEqual(reference, wordsOf(F, value)[coordinate].v);
            }
        }
    }
}
