//! Complete v7 epoch and exact contiguous batch coverage admission.
//! No STARK verifier, summary equation, proof receipt or block authority lives
//! here. Whole-job metadata remains O(roster); the 64-child limit is per batch.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v7_mixed_public_v1.zig");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { max_children: usize = 1 << 20, max_batches: usize = 1 << 20, max_metadata_bytes: usize = 64 << 20 };
pub const Scope = struct {
    epoch: E.Epoch,
    profile: Base.Profile,
    /// Identity of the independently selected whole-job public request.
    public_input_identity: [32]u8,
    pub fn mix(self: Scope, channel: anytype) !void {
        if (zero(self.epoch.digest) or zero(self.public_input_identity) or !std.meta.eql(self.epoch.config, self.profile.config())) return error.InvalidMixedBatchScope;
        try self.epoch.requireCompleteFamilies();
        if (self.epoch.counts[@intFromEnum(E.Family.caller_arithmetic)] != 0) return error.InvalidMixedBatchScope;
        channel.mixU32s(&.{ VERSION, @intFromEnum(self.profile) });
        self.profile.config().mixInto(channel);
        channel.mixRoot(self.epoch.digest);
        channel.mixRoot(self.epoch.statement);
        channel.mixRoot(self.public_input_identity);
    }
};
pub const Range = struct {
    ordinal: u32,
    first: u32,
    count: u32,
    /// Original direct-bus roster digest, not a digest of host success flags.
    roster_digest: [32]u8,
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    scope: Scope,
    roster_digest: [32]u8,
    identity: [32]u8,
    children: u32,
    ranges: []Range,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.ranges);
        self.* = undefined;
    }
};
/// Public proposal to be authenticated by the future recursive verifier.
/// Key and public-input identities are compared to independent expected pins,
/// but this host check DOES NOT establish that the referenced proof exists.
pub const Batch = struct {
    job_identity: [32]u8,
    range: Range,
    epoch: E.Epoch,
    config: core.pcs.PcsConfig,
    public_input_identity: [32]u8,
    key_id: [32]u8,
};
pub const ExpectedProof = struct { key_id: [32]u8, public_input_identity: [32]u8 };

fn zero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

/// Validate cross-batch order using the existing canonical direct-bus parser.
/// Pairwise windows deliberately retain its family/index ordering definition.
pub fn wholeRosterDigest(a: std.mem.Allocator, scope: Scope, roster: []const Bus.Expected, limits: Limits) ![32]u8 {
    if (roster.len == 0 or roster.len > limits.max_children or roster.len >= 1 << 30) return error.MixedBatchResourceLimit;
    const metadata_bytes = try std.math.mul(usize, roster.len, @sizeOf(E.Entry));
    if (metadata_bytes > limits.max_metadata_bytes) return error.MixedBatchResourceLimit;
    const entries = try a.alloc(E.Entry, roster.len);
    defer a.free(entries);
    for (roster, entries) |pin, *entry| entry.* = pin.entry;
    try scope.epoch.require(scope.epoch.statement, scope.profile.config(), scope.epoch.counts, entries, limits.max_children);
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x4237524a, VERSION, @intCast(roster.len) });
    try scope.mix(&channel);
    for (roster, 0..) |pin, i| {
        if (i != 0) _ = try Bus.rosterDigest(roster[i - 1 .. i + 1]);
        if (!std.meta.eql(pin.epoch, scope.epoch.digest)) return error.UntrustedMixedBatchScope;
        channel.mixRoot(try Bus.rosterDigest(&.{pin}));
    }
    return channel.digestBytes();
}

/// Counts are selected by geometry/memory planning, never rounded up with
/// dummy children. Their exact order and full coverage are authenticated.
pub fn create(a: std.mem.Allocator, scope: Scope, roster: []const Bus.Expected, counts: []const u32, limits: Limits) !Plan {
    const digest = try wholeRosterDigest(a, scope, roster, limits);
    if (counts.len == 0 or counts.len > limits.max_batches or counts.len > roster.len or
        try std.math.mul(usize, counts.len, @sizeOf(Range)) > limits.max_metadata_bytes) return error.MixedBatchResourceLimit;
    const ranges = try a.alloc(Range, counts.len);
    errdefer a.free(ranges);
    var next: usize = 0;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x4237524e, VERSION, @intCast(counts.len) });
    channel.mixRoot(digest);
    for (counts, ranges, 0..) |count, *range, i| {
        if (count == 0 or count > Bus.MAX_CHILDREN or count > roster.len - next) return error.InvalidMixedBatchCoverage;
        range.* = .{ .ordinal = @intCast(i), .first = @intCast(next), .count = count, .roster_digest = try Bus.rosterDigest(roster[next..][0..count]) };
        channel.mixU32s(&.{ range.ordinal, range.first, range.count });
        channel.mixRoot(range.roster_digest);
        next += count;
    }
    if (next != roster.len) return error.InvalidMixedBatchCoverage;
    return .{ .allocator = a, .scope = scope, .roster_digest = digest, .identity = channel.digestBytes(), .children = @intCast(roster.len), .ranges = ranges };
}

/// Recompute from the independent original roster before accepting proposals.
/// A resealed caller-created range/digest cannot select a different roster.
pub fn requireCoverage(a: std.mem.Allocator, scope: Scope, roster: []const Bus.Expected, expected_counts: []const u32, proposals: []const Batch, expected_proofs: []const ExpectedProof, limits: Limits) !void {
    var expected = try create(a, scope, roster, expected_counts, limits);
    defer expected.deinit();
    if (proposals.len != expected.ranges.len or expected_proofs.len != proposals.len) return error.InvalidMixedBatchCoverage;
    for (proposals, expected.ranges, expected_proofs) |proposal, range, proof| {
        if (!std.meta.eql(proposal.range, range) or !std.meta.eql(proposal.job_identity, expected.identity)) return error.UntrustedMixedBatchRange;
        if (!std.meta.eql(proposal.config, scope.profile.config()) or !std.meta.eql(proposal.epoch, scope.epoch)) return error.UntrustedMixedBatchScope;
        if (zero(proof.key_id) or zero(proof.public_input_identity) or !std.meta.eql(proposal.key_id, proof.key_id) or
            !std.meta.eql(proposal.public_input_identity, proof.public_input_identity)) return error.UntrustedMixedBatchProofPin;
    }
}
