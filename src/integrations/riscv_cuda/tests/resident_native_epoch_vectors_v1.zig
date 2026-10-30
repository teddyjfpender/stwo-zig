//! CPU reference vectors only; expected numerical outputs are never GPU inputs.
const std = @import("std");
const core = @import("stwo_core");
const Epoch = @import("../../../frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
const Native = @import("../resident_native_epoch_v1.zig");
fn word(w: anytype, x: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, x, .little);
    try w.writeAll(&bytes);
}
fn secure(w: anytype, q: core.fields.qm31.QM31) !void {
    for (q.toM31Array()) |m| try word(w, m.v);
}
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.ExpectedVectorOutputPath;
    var out = std.Io.Writer.Allocating.init(a);
    const w = &out.writer;
    try word(w, 32);
    for (0..32) |seed| {
        var counts: Epoch.Counts = @splat(0);
        counts[@intFromEnum(Epoch.Family.window_memory_joint)] = @intCast(seed % 2);
        var digest: [32]u8 = undefined;
        for (&digest, 0..) |*byte, i| byte.* = @truncate(seed * 137 + i * 71);
        const epoch = Epoch.Epoch{ .statement = @splat(1), .digest = digest, .counts = counts, .config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() };
        var plan = try Native.Plan.init(a, epoch);
        defer plan.deinit();
        try word(w, @intCast(plan.words.len));
        for (plan.words) |value| try word(w, value);
        for (0..8) |i| try word(w, std.mem.readInt(u32, digest[i * 4 ..][0..4], .little));
        try word(w, @intCast(plan.steps.len));
        for (plan.steps) |step| switch (step) {
            .words => |s| {
                try word(w, 1);
                try word(w, @intCast(s.first));
                try word(w, @intCast(s.count));
            },
            .secure => |s| {
                try word(w, 5);
                try word(w, @intCast(s.first));
                try word(w, @intCast(s.count));
            },
        };
        const expected = try epoch.draw(a);
        for (expected.word.universal_prefix.elements) |element| {
            try secure(w, element.z);
            try secure(w, element.alpha);
        }
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |name| {
            const e = @field(expected.word, name);
            try secure(w, e.z);
            try secure(w, e.alpha);
        }
        try secure(w, expected.memory.interval.z);
        try secure(w, expected.memory.interval.powers[1]);
        const final = expected.channel.digestBytes();
        for (0..8) |i| try word(w, std.mem.readInt(u32, final[i * 4 ..][0..4], .little));
        try word(w, @truncate(expected.channel.n_draws));
        try word(w, @truncate(expected.channel.n_draws >> 32));
    }
    try std.fs.cwd().writeFile(.{ .sub_path = args[1], .data = out.written() });
}
