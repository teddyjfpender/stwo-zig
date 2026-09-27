//! Block-v2 source roster binding. This forks the already sealed v1 manifest
//! transcript without changing its digest or the legacy universal draw count.
const std = @import("std");
const core = @import("stwo_core");
const manifest = @import("block_commitment_manifest.zig");

pub const Digest = [32]u8;
pub const Channel = core.proof_suites.Blake3.Channel;
pub const TAG: u32 = 0x42325353; // B2SS
pub const FORMAT_VERSION: u32 = 3;
pub const EXTENSION_FORMAT_VERSION: u32 = 4;
pub const EXTENSION_TAG: u32 = 0x42325853; // B2XS

pub const FirstRoundFamily = enum(u32) {
    memory = 1,
    range_table = 2,
    execution = 3,
    execution_sidecar_witness = 7,
    execution_range_table = 8,
    execution_range_plan = 9,
    execution_extension_witness = 10,
    execution_extension_range_table = 11,
    execution_extension_range_plan = 12,
    initial_rw = 4,
    initial_program = 5,
    hash = 6,
};

pub const FirstRoundEntry = struct {
    family: FirstRoundFamily,
    index: u32,
    roots: [2][32]u8,
};

/// Caller supplies the complete ordered first-round roster; the final batch
/// receiver recomputes it from independently pinned commitment admissions.
pub fn digestFirstRoundRoster(entries: []const FirstRoundEntry) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-memory/first-round-roster/v3\x00");
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, @intCast(entries.len), .little);
    hash.update(&word);
    for (entries) |entry| {
        std.mem.writeInt(u32, &word, @intFromEnum(entry.family), .little); hash.update(&word);
        std.mem.writeInt(u32, &word, entry.index, .little); hash.update(&word);
        hash.update(&entry.roots[0]);
        hash.update(&entry.roots[1]);
    }
    return hash.finalResult();
}

pub const SourceSeal = struct {
    base: manifest.Sealed,
    /// Public register-use mask, derived before relation challenges. The
    /// register provider must prove or deterministically replay exactly this
    /// mask's selected initial values.
    register_mask: u32,
    /// Execution proof count is independently planned after the block-v2
    /// memory architecture changes; it need not equal the legacy base count.
    execution_instance_count: u32,
    /// Exact number of sorted-memory PCS instances in the public block roster.
    memory_instance_count: u32,
    /// Digest of the ordered set of admitted source-chunk roster digests,
    /// including the authenticated RW root and program-source descriptors.
    /// The receiver recomputes this aggregate from public provider rosters.
    roster_digest: Digest,
    /// Exact field-safe byte-table shard roster and all fixed/main PCS roots
    /// are committed here before any universal or block-v2 challenge draw.
    range_shard_digest: Digest = @splat(0),
    first_round_roster_digest: Digest = @splat(0),
    bound_rosters: bool = false,
    /// Optional v4 suffix. Zero-call statements retain the qualified v3
    /// transcript exactly; nonzero extension calls must use this bound form.
    extension_range_shard_digest: Digest = @splat(0),
    extension_rosters_bound: bool = false,

    pub fn init(base: manifest.Sealed, register_mask: u32, roster_digest: Digest) !SourceSeal {
        return initWithMemoryCount(base, register_mask, roster_digest, base.instance_count);
    }

    pub fn initWithMemoryCount(base: manifest.Sealed, register_mask: u32, roster_digest: Digest, memory_instance_count: u32) !SourceSeal {
        if (base.instance_count == 0 or memory_instance_count == 0)
            return error.EmptyBlockSourceManifest;
        return .{ .base = base, .register_mask = register_mask, .execution_instance_count = base.instance_count, .memory_instance_count = memory_instance_count, .roster_digest = roster_digest };
    }

    pub fn initBound(base: manifest.Sealed, register_mask: u32, source_roster_digest: Digest, execution_instance_count: u32, memory_instance_count: u32, range_shard_digest: Digest, first_round_roster_digest: Digest) !SourceSeal {
        if (execution_instance_count == 0) return error.EmptyBlockSourceManifest;
        var result = try initWithMemoryCount(base, register_mask, source_roster_digest, memory_instance_count);
        result.execution_instance_count = execution_instance_count;
        result.range_shard_digest = range_shard_digest;
        result.first_round_roster_digest = first_round_roster_digest;
        result.bound_rosters = true;
        return result;
    }

    pub fn initBoundWithExtension(base: manifest.Sealed, register_mask: u32, source_roster_digest: Digest, execution_instance_count: u32, memory_instance_count: u32, range_shard_digest: Digest, first_round_roster_digest: Digest, extension_range_shard_digest: Digest) !SourceSeal {
        var result = try initBound(base, register_mask, source_roster_digest, execution_instance_count, memory_instance_count, range_shard_digest, first_round_roster_digest);
        result.extension_range_shard_digest = extension_range_shard_digest;
        result.extension_rosters_bound = true;
        return result;
    }

    /// All 47 universal challenges and the block-only suffix are drawn from
    /// this channel. Neither the old v1 manifest digest nor its local proof
    /// transcript changes.
    pub fn sharedChannel(self: SourceSeal) Channel {
        var channel = self.base.sharedChannel();
        channel.mixU32s(&.{ TAG, FORMAT_VERSION, self.register_mask, self.execution_instance_count, self.memory_instance_count, @intFromBool(self.bound_rosters) });
        channel.mixRoot(self.roster_digest);
        channel.mixRoot(self.range_shard_digest);
        channel.mixRoot(self.first_round_roster_digest);
        if (self.extension_rosters_bound) {
            channel.mixU32s(&.{ EXTENSION_TAG, EXTENSION_FORMAT_VERSION });
            channel.mixRoot(self.extension_range_shard_digest);
        }
        return channel;
    }
};

test "block-v2 source seal changes the shared challenge seed without changing v1" {
    const base = manifest.Sealed{ .digest = @splat(13), .instance_count = 2 };
    const original = base.sharedChannel();
    const first = try SourceSeal.init(base, 5, @splat(17));
    const changed_mask = try SourceSeal.init(base, 4, @splat(17));
    const changed_roster = try SourceSeal.init(base, 5, @splat(18));
    try std.testing.expect(!std.meta.eql(first.sharedChannel(), changed_mask.sharedChannel()));
    try std.testing.expect(!std.meta.eql(first.sharedChannel(), changed_roster.sharedChannel()));
    try std.testing.expectEqualDeep(original, base.sharedChannel());
    const entry = FirstRoundEntry{ .family = .range_table, .index = 0, .roots = .{ @splat(1), @splat(2) } };
    const bound = try SourceSeal.initBound(base, 5, @splat(17), 2, 2, @splat(19), digestFirstRoundRoster(&.{entry}));
    try std.testing.expect(bound.bound_rosters);
    try std.testing.expect(!std.meta.eql(first.sharedChannel(), bound.sharedChannel()));
    const extension = try SourceSeal.initBoundWithExtension(base, 5, @splat(17), 2, 2, @splat(19), digestFirstRoundRoster(&.{entry}), @splat(20));
    try std.testing.expect(extension.extension_rosters_bound);
    try std.testing.expect(!std.meta.eql(bound.sharedChannel(), extension.sharedChannel()));
}
