const std = @import("std");
const P = @import("policy.zig");
const G = @import("../../../../word16_execution/geometry.zig");
test "classic grouping covers every original fraction exactly once at degree three" {
    for (std.enums.values(G.Role)) |role| {
        const p = P.forRole(role);
        var seen = [_]bool{false} ** P.MAX_TERMS;
        for (p.groups[0..p.group_count]) |g| {
            try std.testing.expect(!seen[g.first]);
            seen[g.first] = true;
            const first = p.degree[g.first];
            var dd = first.denominator;
            var nd = first.weight;
            if (g.second) |j| {
                try std.testing.expect(!seen[j]);
                seen[j] = true;
                const second = p.degree[j];
                dd += second.denominator;
                nd = @max(first.weight + second.denominator, second.weight + first.denominator);
            }
            try std.testing.expect(dd + 1 <= 3 and nd + 1 <= 3);
        }
        for (seen[0..p.terms]) |value| try std.testing.expect(value);
    }
    const cpu = P.forRole(.cpu);
    try std.testing.expectEqual(@as(usize, 9), cpu.group_count);
    try std.testing.expectEqual(@as(usize, 80), cpu.width());
    try std.testing.expectEqual(@as(u8, 2), cpu.degree[6].denominator); // FUNCTION
    try std.testing.expectEqual(@as(u8, 2), cpu.degree[7].denominator); // ROM
    try std.testing.expectEqual(@as(u8, 1), cpu.degree[8].denominator); // OWNER
}

test "affine pair grouping preserves the exact wide rational sum with signed and zero weights" {
    const O = @import("stwo_core").fields.om31.OM31;
    const M = @import("stwo_core").fields.m31.M31;
    var random = std.Random.DefaultPrng.init(0x147a99);
    for (0..100) |_| {
        const d0 = O.fromBase(M.fromCanonical(random.random().intRangeAtMost(u32, 1, 100000)));
        const d1 = O.fromBase(M.fromCanonical(random.random().intRangeAtMost(u32, 1, 100000)));
        const n0 = O.fromBase(M.fromCanonical(random.random().intRangeAtMost(u32, 0, 100000)));
        const n1 = O.fromBase(M.fromCanonical(random.random().intRangeAtMost(u32, 0, 100000))).neg();
        const original = n0.mul((try d0.inv())).add(n1.mul((try d1.inv())));
        const paired = n0.mul(d1).add(n1.mul(d0)).mul((try d0.mul(d1).inv()));
        try std.testing.expect(original.eql(paired));
    }
}
