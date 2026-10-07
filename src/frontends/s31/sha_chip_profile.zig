//! Verifier-owned SHA256d chip roster for one or two private Bitcoin headers.
//!
//! This pins the SHA-side AIR identities and geometry. A joint S31 proof must
//! add its circuit AIR and circuit-to-chip lookup bridge to the same transcript;
//! this SHA-only profile is not a verifier for a private header on its own.
const std = @import("std");
const provider = @import("s31_sha_provider");

pub const Airs = .{ provider.Source, provider.Schedule, provider.Round, provider.FeedForward, provider.Boundary };
pub const names = [_][:0]const u8{ "s31_sha_source", "s31_sha_schedule", "s31_sha_round", "s31_sha_feed_forward", "s31_sha_private_boundary" };
pub const lookup_kinds = provider.lookup_kinds;
pub const rows_per_call = [_]u32{ 88, 48, 64, 8, 32 };
pub const format_version: u32 = 1;

fn protocolDegree(comptime Air: type) u32 {
    const compatible = if (@hasDecl(Air, "REFERENCE_MAXIMUM_CONSTRAINT_DEGREE"))
        Air.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE
    else
        @max(Air.MAXIMUM_CONSTRAINT_DEGREE, if (Air.INTERACTION_BATCH_COUNT == 0) @as(u32, 0) else 3);
    return if (@hasDecl(Air, "LOWERED_MAXIMUM_CONSTRAINT_DEGREE"))
        @max(compatible, Air.LOWERED_MAXIMUM_CONSTRAINT_DEGREE)
    else
        compatible;
}

/// Component placement without importing the universal prover roster into
/// S31's lightweight frontend module. The proof builder must construct a
/// corresponding roster and compare each placement before proving/verifying.
pub const Origin = struct {
    columns: [4]u32 = @splat(0),
    claimed_sum_index: u32 = 0,
};
pub const Placement = struct {
    preprocessed_offset: u32,
    main_offset: u32,
    interaction_offset: u32,
    constraint_offset: u32,
    claimed_sum_index: u32,
    log_size: u32,
};
pub const Manifest = struct {
    descriptors: [Airs.len]Descriptor,
    origin: Origin,
    pub fn placement(self: Manifest, index: usize) !Placement {
        if (index >= Airs.len) return error.InvalidShaComponent;
        var offsets = self.origin.columns;
        for (self.descriptors, 0..) |descriptor, i| {
            const located = Placement{
                .preprocessed_offset = offsets[0],
                .main_offset = offsets[1],
                .interaction_offset = offsets[2],
                .constraint_offset = offsets[3],
                .claimed_sum_index = try std.math.add(u32, self.origin.claimed_sum_index, @intCast(i)),
                .log_size = descriptor.log_size,
            };
            offsets[0] = try std.math.add(u32, offsets[0], descriptor.preprocessed_columns);
            offsets[1] = try std.math.add(u32, offsets[1], descriptor.main_columns);
            offsets[2] = try std.math.add(u32, offsets[2], descriptor.interaction_columns);
            offsets[3] = try std.math.add(u32, offsets[3], try std.math.add(u32, descriptor.direct_constraints, descriptor.interaction_batches));
            if (i == index) return located;
        }
        unreachable;
    }
};

pub const Descriptor = struct {
    live_rows: u32,
    log_size: u32,
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,
    direct_constraints: u32,
    interaction_batches: u32,
    maximum_degree: u32,
    semantic_digest: [32]u8,
};

pub const Profile = struct {
    call_count: u32,
    descriptors: [Airs.len]Descriptor,

    pub fn canonical(count: u32) !Profile {
        // The current S31 Bitcoin programs admit exactly one or two headers.
        if (count != 3 and count != 6) return error.UnsupportedShaHeaderCount;
        const compression = try provider.Geometry.init(count);
        const boundary_rows = try std.math.mul(u32, count, rows_per_call[4]);
        const boundary_log: u32 = @intCast(std.math.log2_int_ceil(u32, boundary_rows));
        const logs = compression.logs ++ .{boundary_log};
        var descriptors: [Airs.len]Descriptor = undefined;
        inline for (Airs, 0..) |Air, index| descriptors[index] = .{
            .live_rows = try std.math.mul(u32, count, rows_per_call[index]),
            .log_size = logs[index],
            .preprocessed_columns = Air.PREPROCESSED_COLUMN_COUNT,
            .main_columns = Air.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = Air.INTERACTION_COLUMN_COUNT,
            .direct_constraints = Air.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = Air.INTERACTION_BATCH_COUNT,
            .maximum_degree = protocolDegree(Air),
            .semantic_digest = Air.SEMANTIC_DIGEST,
        };
        return .{ .call_count = count, .descriptors = descriptors };
    }

    pub fn validate(self: Profile, expected_count: u32) !void {
        if (!std.meta.eql(self, try canonical(expected_count))) return error.InvalidS31ShaChipProfile;
    }

    /// The containing proof protocol calls this before the first commitment.
    pub fn mixInto(self: Profile, channel: anytype) !void {
        try self.validate(self.call_count);
        channel.mixU32s(&.{ 0x53335348, format_version, Airs.len, self.call_count });
        for (self.descriptors, 0..) |descriptor, index| {
            channel.mixU32s(&.{ @intCast(index), descriptor.live_rows, descriptor.log_size, descriptor.preprocessed_columns, descriptor.main_columns, descriptor.interaction_columns, descriptor.direct_constraints, descriptor.interaction_batches, descriptor.maximum_degree });
            var digest_words: [8]u32 = undefined;
            for (&digest_words, 0..) |*word, i| word.* = std.mem.readInt(u32, descriptor.semantic_digest[i * 4 ..][0..4], .little);
            channel.mixU32s(&digest_words);
        }
        channel.mixU32s(&.{lookup_kinds.len});
        for (lookup_kinds) |kind| channel.mixU32s(&.{@intFromEnum(kind)});
    }

    pub fn manifest(self: Profile, origin: Origin) !Manifest {
        try self.validate(self.call_count);
        const result = Manifest{ .descriptors = self.descriptors, .origin = origin };
        inline for (0..Airs.len) |i| _ = try result.placement(i);
        return result;
    }
};

test "S31 SHA chip profile pins three- and six-call AIR identities and shapes" {
    const TestChannel = struct {
        words: [128]u32 = undefined,
        len: usize = 0,
        pub fn mixU32s(self: *@This(), values: []const u32) void {
            @memcpy(self.words[self.len..][0..values.len], values);
            self.len += values.len;
        }
    };
    for ([_]u32{ 3, 6 }, [_][5]u32{ .{ 9, 8, 8, 5, 7 }, .{ 10, 9, 9, 6, 8 } }) |count, expected_logs| {
        const profile = try Profile.canonical(count);
        try profile.validate(count);
        var channel = TestChannel{};
        try profile.mixInto(&channel);
        try std.testing.expectEqualSlices(u32, &.{ 0x53335348, format_version, Airs.len, count }, channel.words[0..4]);
        try std.testing.expectEqual(@as(u32, lookup_kinds.len), channel.words[channel.len - lookup_kinds.len - 1]);
        for (lookup_kinds, 0..) |kind, i| try std.testing.expectEqual(@as(u32, @intFromEnum(kind)), channel.words[channel.len - lookup_kinds.len + i]);
        for (profile.descriptors, expected_logs, 0..) |descriptor, log, i| {
            try std.testing.expectEqual(log, descriptor.log_size);
            try std.testing.expectEqual(count * rows_per_call[i], descriptor.live_rows);
            try std.testing.expect(descriptor.maximum_degree >= 3);
        }
        const roster = try profile.manifest(.{ .columns = .{ 7, 11, 13, 17 }, .claimed_sum_index = 19 });
        var main_offset: u32 = 11;
        inline for (0..Airs.len) |i| {
            const placement = try roster.placement(i);
            try std.testing.expectEqual(main_offset, placement.main_offset);
            try std.testing.expectEqual(@as(u32, 19 + i), placement.claimed_sum_index);
            main_offset += profile.descriptors[i].main_columns;
        }
        var forged = profile;
        forged.descriptors[0].semantic_digest[0] ^= 1;
        try std.testing.expectError(error.InvalidS31ShaChipProfile, forged.validate(count));
        forged = profile;
        forged.descriptors[4].log_size += 1;
        try std.testing.expectError(error.InvalidS31ShaChipProfile, forged.validate(count));
        try std.testing.expectError(error.InvalidS31ShaChipProfile, profile.validate(if (count == 3) 6 else 3));
    }
    try std.testing.expectError(error.UnsupportedShaHeaderCount, Profile.canonical(0));
    try std.testing.expectError(error.UnsupportedShaHeaderCount, Profile.canonical(9));
}
