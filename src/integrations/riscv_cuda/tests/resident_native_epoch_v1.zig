const std = @import("std");
const core = @import("stwo_core");
const Epoch = @import("../../../frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
const Native = @import("../resident_native_epoch_v1.zig");
test "native epoch resident schedule matches original paired and single draw consumption" {
    const a = std.testing.allocator;
    for (0..32) |seed| {
        var counts: Epoch.Counts = @splat(0);
        counts[@intFromEnum(Epoch.Family.window_memory_joint)] = @intCast(seed % 2);
        var digest: [32]u8 = undefined;
        for (&digest, 0..) |*byte, i| byte.* = @truncate(seed * 137 + i * 71);
        const epoch = Epoch.Epoch{ .statement = @splat(1), .digest = digest, .counts = counts, .config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() };
        var plan = try Native.Plan.init(a, epoch);
        defer plan.deinit();
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(plan.words[0..3]);
        ch.mixRoot(epoch.digest);
        var got: [Native.DRAW_COUNT]core.fields.qm31.QM31 = undefined;
        var singles: usize = 0;
        for (plan.steps) |step| switch (step) {
            .words => |span| ch.mixU32s(plan.words[span.first..][0..span.count]),
            .secure => |span| {
                const values = try ch.drawSecureFelts(a, span.count);
                defer a.free(values);
                @memcpy(got[span.first..][0..span.count], values);
                singles += @intFromBool(span.count == 1);
            },
        };
        const expected = try epoch.draw(a);
        for (expected.word.universal_prefix.elements, 0..) |element, i| {
            try std.testing.expectEqualDeep(element.z, got[2 * i]);
            try std.testing.expectEqualDeep(element.alpha, got[2 * i + 1]);
        }
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
            const element = @field(expected.word, name);
            try std.testing.expectEqualDeep(element.z, got[94 + 2 * i]);
            try std.testing.expectEqualDeep(element.alpha, got[95 + 2 * i]);
        }
        try std.testing.expectEqualDeep(expected.memory.interval.z, got[104]);
        try std.testing.expectEqualDeep(expected.memory.interval.powers[1], got[105]);
        try std.testing.expectEqualDeep(expected.channel.digestBytes(), ch.digestBytes());
        try std.testing.expectEqual(@as(usize, 2), singles);
    }
}

test "native epoch controller typechecks resident operations" {
    std.mem.doNotOptimizeAway(&Native.Bound.execute);
}
