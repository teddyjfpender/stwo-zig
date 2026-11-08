const std = @import("std");
const Core = @import("stwo_core");
const P = @import("stwo_circuit_cpu_integration").om31.protocol;
test "outer FS observed root mix is byte identical to legacy root mix" {
    for (0..64) |seed| {
        var channel = P.Channel.init();
        channel.mixU32s(&.{ @intCast(seed), @intCast(seed * 1789) });
        _ = channel.drawSecureFelt();
        var legacy = channel;
        var root: [32]u8 = undefined;
        for (&root, 0..) |*byte, i| byte.* = @truncate(seed * 71 + i * 13);
        P.MC.mixRoot(&channel, root);
        Core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&legacy.inner, root);
        try std.testing.expectEqualDeep(legacy.inner, channel.inner);
        try std.testing.expectEqualDeep(legacy.drawSecureFelt(), channel.drawSecureFelt());
    }
}
