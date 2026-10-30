//! Admission framing fixtures only. These do not certify any execution proof.
const std = @import("std");
const core = @import("stwo_core");
const Program = @import("../resident_parent_program_v1.zig");
const Native = @import("../../../frontends/riscv/recursion/block_v7_native_public_v1.zig");
const Mixed = @import("../../../frontends/riscv/recursion/block_v7_mixed_protocol_v1.zig");
const Shared = @import("../../../frontends/riscv/recursion/block_v7_shared_epoch_mixed_protocol_v1.zig");
const Epoch = @import("../../../frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
const Q = core.fields.qm31.QM31;
fn replay(a: std.mem.Allocator, p: *const Program.Owned) !core.channel.blake3.Channel {
    var ch = core.channel.blake3.Channel{};
    const prefix = p.view().transcript_prefix;
    for (prefix.frames) |frame| {
        const words = prefix.words[frame.first..][0..frame.count];
        switch (frame.kind) {
            .words => ch.mixU32s(words),
            .root => {
                var root: [32]u8 = undefined;
                for (words, 0..) |w, i| std.mem.writeInt(u32, root[i * 4 ..][0..4], w, .little);
                ch.mixRoot(root);
            },
            .felts => {
                const values = try a.alloc(Q, words.len / 4);
                defer a.free(values);
                for (values, 0..) |*v, i| v.* = Q.fromU32Unchecked(words[i * 4], words[i * 4 + 1], words[i * 4 + 2], words[i * 4 + 3]);
                ch.mixFelts(values);
            },
        }
    }
    return ch;
}
test "resident mixed and shared epochs preserve independent original domains and public ownership" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const words = try temp.alloc(u32, 24);
    for (words, 0..) |*w, i| w.* = @intCast(i + 1);
    const fields = try temp.alloc(Q, 0);
    const public = try temp.alloc(Q, 1);
    public[0] = Q.fromU32Unchecked(11, 13, 17, 19);
    const value = Native.Values{ .allocator = temp, .template = @splat(11), .statement = .{ .allocator = temp, .words = words, .felts = fields, .first = &.{}, .claims = &.{}, .sealed_offset = 16, .roots_offset = .{ 0, 8, 0 } }, .public = public, .roots_count = 2 };
    const roots = [_][32]u8{ try value.statement.digest(0), try value.statement.digest(8) };
    const expected = [_]Mixed.Bus.Expected{.{ .kind = .native, .index = 0, .template = value.template, .epoch = try value.statement.digest(16), .entry = try Epoch.Entry.init(.native, 0, @splat(13), &roots) }};
    const children = [_]Mixed.Bus.Child{.{ .index = 0, .value = .{ .native = value } }};
    const wires = [_]Mixed.Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .child = 0, .source = .{ .native = .public_input }, .coordinate = 0 }};
    const base = try Program.fixtureAdmission();
    var ids: [2][32]u8 = undefined;
    inline for (.{ Mixed, Shared }, 0..) |P, i| {
        const key = try P.Key.fromGeometry(base.key, &wires, &expected);
        ids[i] = try key.identity();
        const admission = try P.Admission.init(key, ids[i], &wires, .{ .children = &children }, &expected);
        const p = if (i == 0) try Program.Owned.deriveMixed(a, admission, .{}) else try Program.Owned.deriveSharedMixed(a, admission, .{});
        defer p.deinit();
        try p.view().validate();
        try std.testing.expectEqualDeep(ids[i], p.view().proofKeyID());
        var actual = try replay(a, p);
        var original = core.channel.blake3.Channel{};
        try admission.mix(&original);
        try std.testing.expectEqualDeep(original, actual);
        const claims = [_]Q{Q.one()} ** Program.COMPONENT_COUNT;
        try admission.mixClaims(&original, &claims);
        actual.mixU32s(p.view().transcript_prefix.words[p.view().transcript_prefix.claims_start..][0..3]);
        actual.mixFelts(&claims);
        try std.testing.expectEqualDeep(original, actual);
        try std.testing.expect(p.view().transcript_prefix.words.len > 22);
    }
    try std.testing.expect(!std.meta.eql(ids[0], ids[1]));
}
