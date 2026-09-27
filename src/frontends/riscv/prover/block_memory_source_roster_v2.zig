//! Canonical prechallenge source roster for the block-v2 initial authority.
//! Entry digests are independently pinned by their source-specific receiver;
//! this module binds their exact ordered set into SourceSeal v3.
const std = @import("std");
const seal_mod = @import("block_memory_source_seal_v2.zig");

pub const Digest = [32]u8;
pub const Family = enum(u32) { public_rw_fallback = 1, program = 2, hash = 3 };
pub const Entry = struct { family: Family, index: u32, digest: Digest };
pub const MAX_ENTRIES: usize = 4096;
const tag = "stwo-zig/block-memory/source-roster/v2\x00";

/// Program authority comes from the independently decoded ELF/ROM root and
/// is cross-checked against every freshly verified native statement.
pub fn programDescriptor(program_root: Digest) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-memory/program-source/v2\x00");
    hash.update(&program_root);
    return hash.finalResult();
}

/// One hash-provider descriptor per native execution instance. The trusted
/// prepared verifier validates both IDs against its public statement and
/// fixed commitment before this digest is admitted into SourceSeal.
pub fn hashDescriptor(instance_index: u32, commitment_plan_id: Digest, native_key_id: Digest) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-memory/hash-source/v2\x00");
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, instance_index, .little);
    hash.update(&word);
    hash.update(&commitment_plan_id);
    hash.update(&native_key_id);
    return hash.finalResult();
}

/// Exactly one public RW entry comes first. Program and hash descriptors
/// follow in contiguous index order; both families must be represented.
pub fn validate(entries: []const Entry) !void {
    if (entries.len < 3 or entries.len > MAX_ENTRIES or entries[0].family != .public_rw_fallback or entries[0].index != 0)
        return error.InvalidBlockSourceRoster;
    var prior_family: Family = .public_rw_fallback;
    var next_index: u32 = 1;
    var program_count: u32 = 0;
    var hash_count: u32 = 0;
    for (entries[1..]) |entry| {
        if (@intFromEnum(entry.family) < @intFromEnum(prior_family) or entry.family == .public_rw_fallback)
            return error.InvalidBlockSourceRoster;
        if (entry.family != prior_family) next_index = 0;
        if (entry.index != next_index) return error.InvalidBlockSourceRoster;
        next_index = try std.math.add(u32, next_index, 1);
        prior_family = entry.family;
        switch (entry.family) {
            .program => program_count += 1,
            .hash => hash_count += 1,
            .public_rw_fallback => unreachable,
        }
    }
    if (program_count == 0 or hash_count == 0) return error.IncompleteBlockSourceRoster;
}

pub fn digest(entries: []const Entry) !Digest {
    try validate(entries);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(tag);
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, @intCast(entries.len), .little);
    hasher.update(&word);
    for (entries) |entry| {
        std.mem.writeInt(u32, &word, @intFromEnum(entry.family), .little);
        hasher.update(&word);
        std.mem.writeInt(u32, &word, entry.index, .little);
        hasher.update(&word);
        hasher.update(&entry.digest);
    }
    return hasher.finalResult();
}

/// Bind the independently recomputed fallback digest to the first entry and
/// the complete aggregate to the prechallenge SourceSeal.
pub fn admit(sealed: seal_mod.SourceSeal, entries: []const Entry, recomputed_rw_digest: Digest) !void {
    if (!sealed.bound_rosters or entries.len == 0 or !std.meta.eql(entries[0].digest, recomputed_rw_digest))
        return error.UnboundPublicInitialRoster;
    if (!std.meta.eql(try digest(entries), sealed.roster_digest))
        return error.UnboundBlockSourceRoster;
}

/// Source-specific verifiers compare trusted descriptors here before any
/// aggregate can authorize a complete-block receiver.
pub fn admitExpected(entries: []const Entry, expected_program: []const Digest, expected_hash: []const Digest) !void {
    try validate(entries);
    if (expected_program.len == 0 or expected_hash.len == 0 or
        expected_program.len + expected_hash.len + 1 != entries.len)
        return error.InvalidPinnedSourceDescriptors;
    var at: usize = 1;
    for (expected_program, 0..) |expected, index| {
        const present = entries[at];
        if (present.family != .program or present.index != @as(u32, @intCast(index)) or !std.meta.eql(present.digest, expected))
            return error.InvalidPinnedSourceDescriptors;
        at += 1;
    }
    for (expected_hash, 0..) |expected, index| {
        const present = entries[at];
        if (present.family != .hash or present.index != @as(u32, @intCast(index)) or !std.meta.eql(present.digest, expected))
            return error.InvalidPinnedSourceDescriptors;
        at += 1;
    }
}

test "source roster binds exact ordered RW, program, and hash descriptors" {
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(1), .instance_count = 1 };
    const entries = [_]Entry{
        .{ .family = .public_rw_fallback, .index = 0, .digest = @splat(2) },
        .{ .family = .program, .index = 0, .digest = @splat(3) },
        .{ .family = .hash, .index = 0, .digest = @splat(4) },
    };
    const aggregate = try digest(&entries);
    const sealed = try seal_mod.SourceSeal.initBound(base, 0, aggregate, 1, 1, @splat(5), @splat(6));
    try admit(sealed, &entries, @splat(2));
    try admitExpected(&entries, &.{@splat(3)}, &.{@splat(4)});
    var changed = entries;
    changed[0].digest[0] ^= 1;
    try std.testing.expectError(error.UnboundPublicInitialRoster, admit(sealed, &changed, @splat(2)));
    changed = entries;
    changed[1].digest[0] ^= 1;
    try std.testing.expectError(error.UnboundBlockSourceRoster, admit(sealed, &changed, @splat(2)));
    try std.testing.expectError(error.InvalidPinnedSourceDescriptors, admitExpected(&changed, &.{@splat(3)}, &.{@splat(4)}));
    changed = entries;
    changed[1].index = 1;
    try std.testing.expectError(error.InvalidBlockSourceRoster, digest(&changed));
    changed = entries;
    changed[1] = entries[2];
    try std.testing.expectError(error.InvalidBlockSourceRoster, digest(&changed));
    try std.testing.expectError(error.InvalidBlockSourceRoster, digest(entries[0..2]));
    try std.testing.expect(!std.meta.eql(programDescriptor(@splat(7)), programDescriptor(@splat(8))));
    try std.testing.expect(!std.meta.eql(hashDescriptor(0, @splat(9), @splat(10)), hashDescriptor(1, @splat(9), @splat(10))));
}
