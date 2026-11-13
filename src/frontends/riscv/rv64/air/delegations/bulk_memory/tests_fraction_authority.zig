//! fraction authority cases; fixture authority is shared with the other test owners.
//! Known-answer and adversarial tests for the bulk-memory AIR.
//!
//! A forged witness is accepted only if every local residual is zero, every
//! U16 lookup value lies in the table, RAM14 closes against the honest memory
//! chain endpoints (INIT/TERM of every touched word) and OWNER19 closes
//! against the honest CPU ECALL tuples. Each adversarial case names the check
//! that rejects it.
const std = @import("std");
const core = @import("stwo_core");
const B = @import("mod.zig");
const T = B.types;
const L = B.layout;
const Eq = B.equations;
const M = core.fields.m31.M31;
const Q = T.Q;
const testing = std.testing;

const Support = @import("tests_support.zig");
const q = Support.q;
const challenges = Support.challenges;

test "bulk all nine fraction authorities preserve QM31 law with full OM31 challenges" {
    const O = core.fields.om31.OM31;
    const Embed = struct {
        fn pair(low: Q, high: Q) O {
            var limbs: [8]M = undefined;
            limbs[0..4].* = low.toM31Array();
            limbs[4..8].* = high.toM31Array();
            return O.fromM31Array(limbs);
        }
    };
    const goldens = .{
        .desc = "f950e0d5dc04d3d50a85daa29afcb468f061181f04ed1b456ef0e902def1ce50",
        .copy = "2e62f3d99bae0e2ed996514255809cc67aeb9aa84abd118aa93f5a44c0f51327",
        .set = "7856ee664177837e4c3546681ea4594f3cc2ed1f1f481f577e258a0d16846767",
        .ucopy = "df4887dde66ceefc9e66e267f62ddc9983fdf29ae63cb13ffce4ecae81b30af0",
        .cdesc = "d0d4a93949ce7ddc4ef6ee0f451eb9c5e1988782f0c011569258c13b4bf0fc00",
        .cmp = "c8d60ab35764236324de4728ec34be8d5fffe4b9a876f137589057c0bfc98c61",
        .jdesc = "79c95609b8f4ca793c9359388870a9d0c6027c45811df8a219367ab7794dfcc2",
        .jscan = "9e544211617e085634ea65b489cf4880b3df04ddc51dd78077205ada05b77375",
        .jtab = "5846a1dee6c9be5a5fc6b340efcbecc605dab166c866486b18bfde4c460f4813",
    };
    const low = challenges();
    var high = low;
    high.ram.offset = q(701);
    for (&high.ram.coefficients, 0..) |*c, i| c.* = q(@intCast(710 + i));
    high.owner.offset = q(702);
    for (&high.owner.coefficients, 0..) |*c, i| c.* = q(@intCast(740 + i));
    high.range16 = .{ .offset = q(703), .coefficient = q(704) };
    var wide: T.ChallengesFor(O) = undefined;
    wide.ram.offset = Embed.pair(low.ram.offset, high.ram.offset);
    for (&wide.ram.coefficients, low.ram.coefficients, high.ram.coefficients) |*w, a, b| w.* = Embed.pair(a, b);
    wide.owner.offset = Embed.pair(low.owner.offset, high.owner.offset);
    for (&wide.owner.coefficients, low.owner.coefficients, high.owner.coefficients) |*w, a, b| w.* = Embed.pair(a, b);
    wide.range16 = .{ .offset = Embed.pair(low.range16.offset, high.range16.offset), .coefficient = Embed.pair(low.range16.coefficient, high.range16.coefficient) };
    inline for (comptime std.enums.values(L.Kind)) |kind| {
        var fixed: [L.fixedWidth(kind)]Q = undefined;
        var main: [L.main(kind)]Q = undefined;
        var wide_fixed: [fixed.len]O = undefined;
        var wide_main: [main.len]O = undefined;
        for (&fixed, &wide_fixed, 0..) |*a, *b, i| {
            a.* = q(@intCast(i + 101));
            b.* = O.fromInner(a.*);
        }
        for (&main, &wide_main, 0..) |*a, *b, i| {
            a.* = q(@intCast(i + 201));
            b.* = O.fromInner(a.*);
        }
        const a = Eq.fractions(Q, kind, &fixed, &main, low);
        var fingerprint = std.crypto.hash.sha2.Sha256.init(.{});
        for (a) |value| {
            for (value.d.toM31Array() ++ value.w.toM31Array()) |limb| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, limb.v, .little);
                fingerprint.update(&bytes);
            }
            fingerprint.update(&.{value.relation});
        }
        try testing.expectEqualStrings(@field(goldens, @tagName(kind)), &std.fmt.bytesToHex(fingerprint.finalResult(), .lower));
        const b = Eq.fractions(Q, kind, &fixed, &main, high);
        const actual = Eq.fractions(O, kind, &wide_fixed, &wide_main, wide);
        for (actual, a, b) |w, x, y| {
            try testing.expect(w.d.eql(Embed.pair(x.d, y.d)));
            try testing.expect(w.w.eql(O.fromInner(x.w)));
            try testing.expectEqual(x.relation, w.relation);
        }
    }
}
