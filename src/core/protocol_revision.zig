//! Protocol revisions whose PCS transcript and commitment-height laws differ.
//!
//! A lane selects one revision at comptime; nothing here branches at runtime.
//! The two revisions differ in exactly three places:
//!
//! | Law                | `stwo_7b211ed`                          | `proving_5a7c5ed`                         |
//! |--------------------|-----------------------------------------|-------------------------------------------|
//! | config type        | `pcs.PcsConfig` (PoW bits beside FRI)   | `pcs.config_v2.PcsConfigV2` (PoW in FRI)  |
//! | config mix         | 1 felt, or 2 when fork options are set  | always 2 felts, from the FRI config       |
//! | Merkle tree height | largest committed column                | explicit per-tree lifting height          |
//!
//! `stwo_7b211ed` is the rule set of the existing Native (stwo a8fcf4b) and
//! Cairo (stwo 7b211ed, stwo-cairo 82f2125) lanes; their bytes are defined by
//! `pcs.PcsConfig` and do not change. `proving_5a7c5ed` is the vendored stwo of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, used by circuit recursion.

const std = @import("std");
const pcs = @import("pcs/mod.zig");
const config_v2 = @import("pcs/config_v2.zig");

pub const Revision = enum {
    stwo_7b211ed,
    proving_5a7c5ed,

    pub fn PcsConfig(comptime self: Revision) type {
        return switch (self) {
            .stwo_7b211ed => pcs.PcsConfig,
            .proving_5a7c5ed => config_v2.PcsConfigV2,
        };
    }

    /// Mixes the PCS configuration into the channel at the start of a proof.
    pub fn mixConfig(comptime self: Revision, config: self.PcsConfig(), channel: anytype) void {
        switch (self) {
            .stwo_7b211ed => config.mixInto(channel),
            .proving_5a7c5ed => config.fri_config.mixInto(channel),
        }
    }

    /// Merkle height of the `tree_index`-th committed tree, given its
    /// blowup-extended column log sizes. An empty tree has height 0 under
    /// `stwo_7b211ed`; under `proving_5a7c5ed` it is valid only when its
    /// configured lifting height is 0 (`PcsConfigV2.treeHeight`).
    pub fn treeHeight(
        comptime self: Revision,
        config: self.PcsConfig(),
        tree_index: usize,
        extended_log_sizes: []const u32,
    ) config_v2.PcsConfigV2.Error!u32 {
        return switch (self) {
            .stwo_7b211ed => std.mem.max(u32, if (extended_log_sizes.len == 0) &[_]u32{0} else extended_log_sizes),
            .proving_5a7c5ed => config.treeHeight(tree_index, extended_log_sizes),
        };
    }
};

const channel_blake2s = @import("channel/blake2s.zig");
const fri_config = @import("fri/config.zig");

test "protocol revision: stwo_7b211ed keeps the legacy transcript and heights" {
    const legacy = pcs.PcsConfig{ .pow_bits = 10, .fri_config = try fri_config.FriConfig.init(0, 1, 3) };
    var expected = channel_blake2s.Blake2sChannel{};
    legacy.mixInto(&expected);
    var actual = channel_blake2s.Blake2sChannel{};
    Revision.stwo_7b211ed.mixConfig(legacy, &actual);
    try std.testing.expectEqualSlices(u8, &expected.digestBytes(), &actual.digestBytes());
    try std.testing.expectEqual(@as(u32, 7), try Revision.stwo_7b211ed.treeHeight(legacy, 1, &.{ 3, 7, 5 }));
    try std.testing.expectEqual(@as(u32, 0), try Revision.stwo_7b211ed.treeHeight(legacy, 1, &.{}));
}

test "protocol revision: the two revisions fork on identical FRI parameters" {
    // Same PoW, blowup, queries and fold step: the legacy lane mixes one felt,
    // the proving revision two, so the transcripts differ from the first mix.
    const legacy = pcs.PcsConfig{ .pow_bits = 10, .fri_config = try fri_config.FriConfig.init(0, 1, 3) };
    const v2 = config_v2.PcsConfigV2.fromFriAndLiftingSize(try config_v2.FriConfigV2.init(10, 0, 1, 3, 1), 5);
    var legacy_channel = channel_blake2s.Blake2sChannel{};
    Revision.stwo_7b211ed.mixConfig(legacy, &legacy_channel);
    var v2_channel = channel_blake2s.Blake2sChannel{};
    Revision.proving_5a7c5ed.mixConfig(v2, &v2_channel);
    try std.testing.expect(!std.mem.eql(u8, &legacy_channel.digestBytes(), &v2_channel.digestBytes()));

    // Heights: largest column versus the explicit lifting height.
    try std.testing.expectEqual(@as(u32, 5), try Revision.proving_5a7c5ed.treeHeight(v2, 1, &.{ 3, 4 }));
    try std.testing.expectEqual(@as(u32, 4), try Revision.stwo_7b211ed.treeHeight(legacy, 1, &.{ 3, 4 }));
}
