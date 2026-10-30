//! V7 whole-execution first-round commitment schedule. An Epoch binds metadata
//! and challenge order only; it is never a proof or accepted-source receipt.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Byte = @import("block_memory_relation_v2.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Elements = @import("../air/relation_challenges.zig");
pub const VERSION: u32 = 3;
pub const Family = enum(u32) { native, caller_arithmetic, caller_fused, program, lookup, ram, interval, range16, terminal, memory_joint, window_memory_joint };
pub const FAMILY_COUNT = std.meta.fields(Family).len;
pub const Counts = [FAMILY_COUNT]u32;
pub const Entry = struct {
    family: Family,
    index: u32,
    identity: [32]u8,
    root_count: u32,
    roots: [4][32]u8,
    pub fn init(family: Family, index: u32, identity: [32]u8, roots: []const [32]u8) !Entry {
        if (roots.len == 0 or roots.len > 4) return error.InvalidV7EpochRoots;
        var out = Entry{ .family = family, .index = index, .identity = identity, .root_count = @intCast(roots.len), .roots = @splat(@splat(0)) };
        @memcpy(out.roots[0..roots.len], roots);
        try out.validate();
        return out;
    }
    pub fn validate(self: Entry) !void {
        if (self.root_count == 0 or self.root_count > 4 or std.mem.allEqual(u8, &self.identity, 0)) return error.InvalidV7EpochEntry;
        for (self.roots[0..self.root_count]) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidV7EpochRoots;
        for (self.roots[self.root_count..]) |root| if (!std.mem.allEqual(u8, &root, 0)) return error.InvalidV7EpochPadding;
    }
    pub fn mix(self: Entry, ch: anytype) void {
        ch.mixU32s(&.{ @intFromEnum(self.family), self.index, self.root_count });
        ch.mixRoot(self.identity);
        for (self.roots[0..self.root_count]) |root| ch.mixRoot(root);
    }
};
pub const Epoch = struct {
    statement: [32]u8,
    config: core.pcs.PcsConfig,
    counts: Counts,
    digest: [32]u8,
    pub fn init(statement: [32]u8, config: core.pcs.PcsConfig, counts: Counts, entries: []const Entry, max_entries: usize) !Epoch {
        try @import("blake3_execution_protocol.zig").validateConfig(config);
        if (std.mem.allEqual(u8, &statement, 0) or entries.len == 0 or entries.len > max_entries) return error.InvalidV7Epoch;
        var ch = suite.Channel{};
        ch.mixU32s(&.{ if (counts[@intFromEnum(Family.window_memory_joint)] != 0) @as(u32, 0x42375745) else @as(u32, 0x42374550), VERSION, 1 });
        ch.mixRoot(statement);
        config.mixInto(&ch);
        if (counts[@intFromEnum(Family.window_memory_joint)] != 0) ch.mixU32s(&counts) else ch.mixU32s(counts[0..10]);
        var offset: usize = 0;
        inline for (std.meta.fields(Family), 0..) |field, family| {
            const n = counts[family];
            if (n > entries.len - offset) return error.InvalidV7EpochRoster;
            for (entries[offset..][0..n], 0..) |entry, index| {
                try entry.validate();
                if (entry.family != @field(Family, field.name) or entry.index != index) return error.InvalidV7EpochRoster;
                entry.mix(&ch);
            }
            offset += n;
        }
        if (offset != entries.len) return error.InvalidV7EpochRoster;
        return .{ .statement = statement, .config = config, .counts = counts, .digest = ch.digestBytes() };
    }
    pub fn require(self: Epoch, statement: [32]u8, config: core.pcs.PcsConfig, counts: Counts, entries: []const Entry, max_entries: usize) !void {
        if (!std.meta.eql(self, try init(statement, config, counts, entries, max_entries))) return error.UntrustedV7Epoch;
    }
    pub fn requireEntry(self: Epoch, entries: []const Entry, expected: Entry) !void {
        try self.require(self.statement, self.config, self.counts, entries, entries.len);
        for (entries) |entry| if (entry.family == expected.family and entry.index == expected.index) {
            if (!std.meta.eql(entry, expected)) return error.UntrustedV7SourceEntry;
            return;
        };
        return error.MissingV7SourceEntry;
    }
    pub fn sharedTag(self: Epoch) u32 {
        return if (self.counts[@intFromEnum(Family.window_memory_joint)] != 0) 0x42375745 else 0x42374550;
    }
    pub fn sharedChannel(self: Epoch) suite.Channel {
        var ch = suite.Channel{};
        ch.mixU32s(&.{ self.sharedTag(), VERSION, 2 });
        ch.mixRoot(self.digest);
        return ch;
    }
    /// Production closure additionally requires every declared source to have
    /// a freshly verified original proof and every typed relation to close.
    pub fn requireCompleteFamilies(self: Epoch) !void {
        if (self.counts[@intFromEnum(Family.native)] == 0) return error.IncompleteV7Epoch;
        for ([_]Family{ .program, .lookup }) |family| if (self.counts[@intFromEnum(family)] != 1) return error.IncompleteV7Epoch;
        const window = self.counts[@intFromEnum(Family.window_memory_joint)];
        if (window != 0) {
            if (window != 1) return error.IncompleteV7Epoch;
            for ([_]Family{ .ram, .interval, .range16, .terminal, .memory_joint }) |family| if (self.counts[@intFromEnum(family)] != 0) return error.MixedV7MemoryLayouts;
            return;
        }
        const joint = self.counts[@intFromEnum(Family.memory_joint)];
        if (joint == 0) {
            if (self.counts[@intFromEnum(Family.ram)] == 0) return error.IncompleteV7Epoch;
            for ([_]Family{ .interval, .range16, .terminal }) |family| if (self.counts[@intFromEnum(family)] != 1) return error.IncompleteV7Epoch;
        } else {
            if (joint != 1) return error.IncompleteV7Epoch;
            for ([_]Family{ .ram, .interval, .range16, .terminal }) |family| if (self.counts[@intFromEnum(family)] != 0) return error.MixedV7MemoryLayouts;
        }
    }
    pub fn draw(self: Epoch, a: std.mem.Allocator) !Drawn {
        var ch = self.sharedChannel();
        const word = try Word.Challenges.drawFromChannel(a, &ch);
        ch.mixU32s(&.{ 0x4237494e, VERSION, 6 });
        const z = ch.drawSecureFelt();
        const alpha = ch.drawSecureFelt();
        const interval = Elements.RelationElements(6).init(z, alpha);
        // The legacy byte-bus carrier is required by the existing access
        // component's type. Its packed path uses only word/universal fields;
        // derive its original prefix independently rather than invent values.
        var compatibility = self.sharedChannel();
        const bytes = try Byte.Challenges.drawFromChannel(a, &compatibility);
        if (!std.meta.eql(bytes.universal_prefix, word.universal_prefix)) return error.InvalidV7UniversalPrefix;
        return .{ .word = word, .bytes = bytes, .memory = .{ .transition = .from(word.transition), .link = .from(word.link), .interval = .from(interval), .range16 = .from(word.range16) }, .channel = ch };
    }
};
pub const Drawn = struct { word: Word.Challenges, bytes: Byte.Challenges, memory: R.Challenges(Q), channel: suite.Channel };

test "v7 epoch admits exactly one complete memory layout" {
    var counts: Counts = @splat(0);
    for ([_]Family{ .native, .program, .lookup, .ram, .interval, .range16, .terminal }) |family| counts[@intFromEnum(family)] = 1;
    var epoch = Epoch{ .statement = @splat(1), .config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(), .counts = counts, .digest = @splat(2) };
    try epoch.requireCompleteFamilies();
    epoch.counts[@intFromEnum(Family.memory_joint)] = 1;
    try std.testing.expectError(error.MixedV7MemoryLayouts, epoch.requireCompleteFamilies());
    for ([_]Family{ .ram, .interval, .range16, .terminal }) |family| epoch.counts[@intFromEnum(family)] = 0;
    try epoch.requireCompleteFamilies();
    epoch.counts[@intFromEnum(Family.memory_joint)] = 2;
    try std.testing.expectError(error.IncompleteV7Epoch, epoch.requireCompleteFamilies());
    epoch.counts[@intFromEnum(Family.memory_joint)] = 0;
    try std.testing.expectError(error.IncompleteV7Epoch, epoch.requireCompleteFamilies());
}

test "v7 window extension preserves exact historical epoch framing" {
    const config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    const pin = try Entry.init(.native, 0, @splat(7), &.{@splat(9)});
    var counts: Counts = @splat(0);
    counts[0] = 1;
    const epoch = try Epoch.init(@splat(5), config, counts, &.{pin}, 1);
    var old = suite.Channel{};
    old.mixU32s(&.{ 0x42374550, VERSION, 1 });
    old.mixRoot(@splat(5));
    config.mixInto(&old);
    old.mixU32s(counts[0..10]);
    pin.mix(&old);
    try std.testing.expectEqualDeep(old.digestBytes(), epoch.digest);
    var shared = suite.Channel{};
    shared.mixU32s(&.{ 0x42374550, VERSION, 2 });
    shared.mixRoot(epoch.digest);
    try std.testing.expectEqualDeep(shared.digestBytes(), epoch.sharedChannel().digestBytes());
    for ([_]Family{ .program, .lookup, .window_memory_joint }) |family| counts[@intFromEnum(family)] = 1;
    var window = epoch;
    window.counts = counts;
    try window.requireCompleteFamilies();
    window.counts[@intFromEnum(Family.memory_joint)] = 1;
    try std.testing.expectError(error.MixedV7MemoryLayouts, window.requireCompleteFamilies());
}
