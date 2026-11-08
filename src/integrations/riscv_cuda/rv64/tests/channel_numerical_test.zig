const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
extern "c" fn rv64_test_channel(*const [9]u32, [*]const u32, u32, u32, [*]u32, *[9]u32) void;
test "resident OM31 channel reference agrees with native raw Blake for every padding boundary" {
    const C = core.channel.raw_mod_m31.Om31Channel;
    var random = std.Random.DefaultPrng.init(0x659800a731);
    const rng = random.random();
    var input: [1024]u32 = undefined;
    for (&input) |*v| v.* = rng.int(u32);
    for ([_]usize{ 0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1024 }) |n| {
        for ([_]u32{ 1, 2, 3, 9 }) |count| {
            var c = C.init();
            // Import an actual profile-bound channel checkpoint after prior draws.
            _ = c.drawSecureFelt();
            var seed: [9]u32 = undefined;
            for (0..8) |i| seed[i] = std.mem.readInt(u32, c.inner.digest[i * 4 ..][0..4], .little);
            seed[8] = c.inner.n_draws;
            c.mixU32s(input[0..n]);
            var got: [72]u32 = undefined;
            var checkpoint: [9]u32 = undefined;
            rv64_test_channel(&seed, &input, @intCast(n), count, &got, &checkpoint);
            for (0..count) |i| {
                const value: O = c.drawSecureFelt();
                for (value.toM31Array(), 0..) |v, k| try std.testing.expectEqual(v.v, got[8 * i + k]);
            }
            for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, c.inner.digest[i * 4 ..][0..4], .little), checkpoint[i]);
            try std.testing.expectEqual(c.inner.n_draws, checkpoint[8]);
        }
    }
}
