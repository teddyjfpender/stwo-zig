//! Verifier-owned SHA roster geometry and semantic identity.
//! Executable capability admission is a separate combined-profile contract.
const std = @import("std");
const provider = @import("sha256_compression_rows.zig");
const source = @import("sha256_packed_source.zig");
const caller = @import("sha256_memory_caller.zig");
pub fn AirsForRecipe(comptime local_zero: bool) @TypeOf(.{ source, provider.Schedule, provider.Round, provider.FeedForward, if (local_zero) @import("sha256_caller_local_zero_v1.zig") else caller }) {
    return .{ source, provider.Schedule, provider.Round, provider.FeedForward, if (local_zero) @import("sha256_caller_local_zero_v1.zig") else caller };
}
pub const Airs = AirsForRecipe(false);
pub const LocalZeroAirs = AirsForRecipe(true);
pub const names = [_][:0]const u8{ "sha_source", "sha_schedule", "sha_round", "sha_feed_forward", "sha_caller" };
pub const Roster = @import("../../recursion/air/universal_component_roster.zig").ForAirs(Airs, &names);
pub const LocalZeroRoster = @import("../../recursion/air/universal_component_roster.zig").ForAirs(LocalZeroAirs, &names);
pub const format_version: u32 = 1;
pub const lookup_kinds = [_]@import("../lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8, .range_check_8_8_4, .range_check_20 };
pub const rows_per_call = [_]usize{ @import("sha256_compression_graph.zig").source_count, provider.topology.expansion.len, provider.topology.rounds.len, provider.topology.feed_forward.len, 1 };

pub fn callerLog(count: usize) !u32 {
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(count, 16)));
    if (log > 24) return error.ShaTraceTooLarge;
    return log;
}

pub const Geometry = struct {
    calls: usize,
    logs: [Airs.len]u32,
    pub fn init(count: usize) !Geometry {
        const compression = try provider.Geometry.init(count);
        for (compression.logs) |log| if (log > 24) return error.ShaTraceTooLarge;
        return .{ .calls = count, .logs = compression.logs ++ .{try callerLog(count)} };
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
        return canonicalForRecipe(count, false);
    }
    pub fn canonicalForRecipe(count: u32, comptime local_zero: bool) !Profile {
        const geometry = try Geometry.init(count);
        var descriptors: [Airs.len]Descriptor = undefined;
        inline for (AirsForRecipe(local_zero), 0..) |Air, i| descriptors[i] = .{
            .live_rows = @intCast(try std.math.mul(usize, count, rows_per_call[i])),
            .log_size = geometry.logs[i],
            .preprocessed_columns = Air.PREPROCESSED_COLUMN_COUNT,
            .main_columns = Air.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = Air.INTERACTION_COLUMN_COUNT,
            .direct_constraints = Air.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = Air.INTERACTION_BATCH_COUNT,
            .maximum_degree = @import("../../recursion/air/universal_typed_geometry.zig").protocolMaximumConstraintDegree(Air),
            .semantic_digest = Air.SEMANTIC_DIGEST,
        };
        return .{ .call_count = count, .descriptors = descriptors };
    }

    pub fn validate(self: Profile, total_steps: u32) !void {
        return self.validateForRecipe(total_steps, false);
    }
    pub fn validateForRecipe(self: Profile, total_steps: u32, local_zero: bool) !void {
        if (self.call_count > total_steps) return error.InvalidShaCallCount;
        const expected = if (local_zero) try canonicalForRecipe(self.call_count, true) else try canonical(self.call_count);
        if (!std.meta.eql(self, expected)) return error.InvalidShaComponentProfile;
    }

    /// Mix before commitments/challenges, in the containing proof protocol.
    /// Columns, degrees, order and AIR identities cannot be selected by a proof.
    pub fn mixInto(self: Profile, channel: anytype) !void {
        return self.mixIntoForRecipe(channel, false);
    }
    pub fn mixIntoForRecipe(self: Profile, channel: anytype, local_zero: bool) !void {
        try self.validateForRecipe(self.call_count, local_zero);
        channel.mixU32s(&.{ 0x53485046, if (local_zero) 2 else format_version, Airs.len, self.call_count });
        for (self.descriptors, 0..) |descriptor, index| {
            channel.mixU32s(&.{ @intCast(index), descriptor.live_rows, descriptor.log_size, descriptor.preprocessed_columns, descriptor.main_columns, descriptor.interaction_columns, descriptor.direct_constraints, descriptor.interaction_batches, descriptor.maximum_degree });
            var words: [8]u32 = undefined;
            for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, descriptor.semantic_digest[i * 4 ..][0..4], .little);
            channel.mixU32s(&words);
        }
    }

    pub fn manifest(self: Profile, origin: Roster.Origin) !Roster.Manifest {
        return self.manifestForRecipe(origin, false);
    }
    pub fn manifestForRecipe(self: Profile, origin: Roster.Origin, comptime local_zero: bool) !(if (local_zero) LocalZeroRoster else Roster).Manifest {
        const RecipeRoster = if (local_zero) LocalZeroRoster else Roster;
        try self.validateForRecipe(self.call_count, local_zero);
        var logs: [Airs.len]u32 = undefined;
        for (self.descriptors, &logs) |descriptor, *log| log.* = descriptor.log_size;
        const result = RecipeRoster.Manifest{ .log_sizes = logs, .origin = .{ .columns = origin.columns, .claimed_sum_index = origin.claimed_sum_index } };
        // Force checked cumulative placement before returning any handle.
        inline for (0..Airs.len) |i| _ = try result.placement(@enumFromInt(i));
        return result;
    }
};

test "SHA provider profile pins geometry semantics and checked component placement" {
    for ([_]u32{ 0, 1, 16, 64 }) |count| {
        const profile = try Profile.canonical(count);
        try profile.validate(count);
        const manifest = try profile.manifest(.{ .columns = .{ 11, 13, 17, 19 }, .claimed_sum_index = 23 });
        var main: u32 = 13;
        inline for (0..Airs.len) |i| {
            const placement = try manifest.placement(@enumFromInt(i));
            try std.testing.expectEqual(main, placement.main_offset);
            try std.testing.expectEqual(@as(u32, 23 + i), placement.claimed_sum_index);
            main += profile.descriptors[i].main_columns;
        }
        var forged = profile;
        forged.descriptors[0].semantic_digest[0] ^= 1;
        try std.testing.expectError(error.InvalidShaComponentProfile, forged.validate(count));
        forged = profile;
        forged.descriptors[4].log_size += 1;
        try std.testing.expectError(error.InvalidShaComponentProfile, forged.validate(count));
        try std.testing.expectError(error.Overflow, profile.manifest(.{ .columns = @splat(std.math.maxInt(u32)) }));
    }
    try std.testing.expectError(error.InvalidShaCallCount, (try Profile.canonical(2)).validate(1));
}
