const std = @import("std");
const core = @import("core");
const workers = 8;
const missing = std.math.maxInt(u64);
var found = std.atomic.Value(u64).init(missing);
var checked = std.atomic.Value(u64).init(0);
fn search(lane: u64) void {
    var timer = std.time.Timer.start() catch return;
    var seed = lane;
    var count: u64 = 0;
    while (seed < 1 << 31) : (seed += workers) {
        if (count % 65536 == 0 and (found.load(.monotonic) != missing or timer.read() > 300 * std.time.ns_per_s)) break;
        var channel = core.channel.blake3.Channel{};
        channel.mixU64(seed);
        const words = channel.drawU32s();
        count += 1;
        for (words) |word| if (core.channel.blake3.sampleWord(word) == null) {
            _ = found.cmpxchgStrong(missing, seed, .monotonic, .monotonic);
            break;
        };
    }
    _ = checked.fetchAdd(count, .monotonic);
}
pub fn main() !void {
    var threads: [workers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        found.store(0, .monotonic);
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, search, .{@as(u64, i)});
        spawned += 1;
    }
    for (threads) |thread| thread.join();
    const seed = found.load(.monotonic);
    std.debug.print("checked={d} seed={d}\n", .{ checked.load(.monotonic), seed });
    if (seed == missing) return error.SearchLimit;
    var channel = core.channel.blake3.Channel{};
    channel.mixU64(seed);
    std.debug.print("state={s}\n", .{std.fmt.bytesToHex(channel.digestBytes(), .lower)});
    for (0..3) |_| std.debug.print("words={any}\n", .{channel.drawU32s()});
}
