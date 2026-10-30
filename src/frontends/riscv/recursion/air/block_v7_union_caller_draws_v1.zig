//! Additional per-caller challenge streams in a joined original verifier.
//! Replayed epoch draws are constrained but discarded; only the fourteen new
//! extension pairs per caller receive distinct exported ports. Entry constants
//! come from the independently reconstructed, request-specific fixed profile.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Profile = @import("../block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Source = @import("../../prover/block_v7_caller_active_source_v1.zig");
const Extension = @import("../../prover/blake3_ethereum_sha_profile.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Epoch = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Live = @import("blake3_native_recorder.zig");
const Port = @import("blake3_transcript_witness.zig").Caller;
pub const BASE_PAIRS: usize = 53;
pub const CALLER_PAIRS: usize = 14;
pub fn pairCount(callers: usize) !usize {
    if (callers > 64) return error.InvalidUnionCallerCount;
    return std.math.add(usize, BASE_PAIRS, try std.math.mul(usize, CALLER_PAIRS, callers));
}
fn Discard(comptime cold: bool) type {
    return struct {
        r: *if (cold) Cold.Recorder else Live.Recorder,
        pub fn mixU32s(self: *@This(), words: []const u32) void {
            self.r.mixU32s(words);
        }
        pub fn drawSecureFelts(self: *@This(), a: std.mem.Allocator, count: usize) ![]Q {
            if (!cold) return self.r.drawSecureFeltsDiscarded(a, count);
            if (count % 2 != 0) return error.InvalidUnionCallerDrawCount;
            const values = try a.alloc(Q, count);
            @memset(values, Q.zero());
            for (0..count / 2) |_| self.r.append(.{ .secure = .{ .output = null, .discard_output = true, .attempts = 0, .consumption = .two, .values = @splat(core.fields.m31.M31.zero()) } });
            try self.r.check();
            return values;
        }
        pub fn drawSecureFelt(self: *@This()) Q {
            if (!cold) return self.r.drawSecureFeltDiscarded();
            self.r.append(.{ .secure = .{ .output = null, .discard_output = true, .attempts = 0, .consumption = .one, .values = @splat(core.fields.m31.M31.zero()) } });
            return Q.zero();
        }
    };
}
const FixedExport = struct {
    r: *Cold.Recorder,
    next: usize,
    pub fn mixU32s(self: *@This(), words: []const u32) void {
        self.r.mixU32s(words);
    }
    pub fn drawSecureFelts(self: *@This(), a: std.mem.Allocator, count: usize) ![]Q {
        if (count % 2 != 0) return error.InvalidUnionCallerDrawCount;
        try self.r.universalPairs(self.next, count / 2);
        self.next = try std.math.add(usize, self.next, count / 2);
        const values = try a.alloc(Q, count);
        @memset(values, Q.zero());
        return values;
    }
};
fn EntrySink(comptime cold: bool) type {
    return struct {
        r: *if (cold) Cold.Recorder else Live.Recorder,
        pub fn mixU32s(self: *@This(), words: []const u32) void {
            self.r.mixU32s(words);
        }
        pub fn mixRoot(self: *@This(), root: [32]u8) void {
            self.r.mixStaticRoot(root);
        }
    };
}
pub fn appendFixed(a: std.mem.Allocator, r: *Cold.Recorder, profile: *const Profile.Owned, epoch_port: Port) !void {
    return append(true, a, r, profile, epoch_port);
}
pub fn appendLive(a: std.mem.Allocator, r: *Live.Recorder, profile: *const Profile.Owned, epoch_port: Port) !void {
    if (r.relation_count != BASE_PAIRS) return error.InvalidUnionCallerDrawPorts;
    try append(false, a, r, profile, epoch_port);
    if (r.relation_count != try pairCount(profile.statement.input.callers.len)) return error.InvalidUnionCallerDrawPorts;
}
fn append(comptime cold: bool, a: std.mem.Allocator, r: *if (cold) Cold.Recorder else Live.Recorder, profile: *const Profile.Owned, epoch_port: Port) !void {
    const epoch = profile.statement.input.epoch;
    for (profile.statement.input.callers, 0..) |pin, index| {
        const entry = try pin.require(a, epoch, profile.statement.input.entries);
        try r.restartChannel();
        r.mixU32s(&.{ epoch.sharedTag(), Epoch.VERSION, 2 });
        r.mixPublicRoot(epoch_port, epoch.digest);
        var discarded = Discard(cold){ .r = r };
        const word = try Word.Challenges.drawFromChannel(a, &discarded);
        r.mixU32s(&.{ 0x4237494e, Epoch.VERSION, 6 });
        _ = discarded.drawSecureFelt();
        _ = discarded.drawSecureFelt();
        r.mixU32s(&.{ Source.TAG, Source.VERSION, 1 });
        var entry_sink = EntrySink(cold){ .r = r };
        entry.mix(&entry_sink);
        if (cold) {
            var exported = FixedExport{ .r = r, .next = BASE_PAIRS + CALLER_PAIRS * index };
            _ = try Extension.Relations.drawAfterVm(a, &exported, word.universal_prefix);
            if (exported.next != BASE_PAIRS + CALLER_PAIRS * (index + 1)) return error.InvalidUnionCallerDrawPorts;
        } else {
            _ = try Extension.Relations.drawAfterVm(a, r, word.universal_prefix);
            const expected = try Source.draw(a, epoch, entry);
            if (!std.meta.eql(expected.channel, r.native)) return error.InvalidUnionCallerDrawReplay;
        }
        try r.check();
    }
}
