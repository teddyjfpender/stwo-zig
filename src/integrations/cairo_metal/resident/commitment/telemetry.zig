//! Opt-in commitment diagnostics over resident arena bindings.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;

pub fn logCommitSourceDigests(
    resident_arena: *arena_plan.ResidentArena,
    coefficient_cursor: usize,
    sources: []const arena_plan.Binding,
) !void {
    const target_index = if (std.posix.getenv("STWO_ZIG_SN2_LOG_COMMIT_SOURCE_INDEX")) |encoded|
        try std.fmt.parseUnsigned(usize, encoded, 10)
    else
        2241;
    for (sources, 0..) |source, group_index| {
        const sorted_index = coefficient_cursor + group_index;
        if (sorted_index != target_index) continue;
        const bytes = try resident_arena.bytes(source);
        var digest: u64 = 0xcbf29ce484222325;
        for (bytes) |byte| {
            digest ^= byte;
            digest *%= 0x100000001b3;
        }
        const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
        std.debug.print(
            "commit_source_digest sorted_index={} log_size={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
            .{ sorted_index, std.math.log2_int(usize, words.len), words[0], words[words.len - 1], digest },
        );
    }
}

pub fn logCommitLdeDigests(
    resident_arena: *arena_plan.ResidentArena,
    coefficient_cursor: usize,
    sources: []const arena_plan.Binding,
    output_offsets: []const u32,
    output_logs: []const u32,
) void {
    const arena_bytes: [*]const u8 = @ptrCast(resident_arena.buffer.contents);
    for (sources, output_offsets, output_logs, 0..) |source, offset, log_size, group_index| {
        const word_count = @as(usize, 1) << @intCast(log_size);
        const bytes = arena_bytes[@as(usize, offset) * 4 ..][0 .. word_count * 4];
        var digest: u64 = 0xcbf29ce484222325;
        for (bytes) |byte| {
            digest ^= byte;
            digest *%= 0x100000001b3;
        }
        const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
        std.debug.print(
            "commit_lde_digest sorted_index={} source_offset={} output_offset={} log_size={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
            .{ coefficient_cursor + group_index, source.offset_bytes / 4, offset, log_size, words[0], words[words.len - 1], digest },
        );
    }
}

pub fn logBindingDigest(
    resident_arena: *arena_plan.ResidentArena,
    label: []const u8,
    index: usize,
    binding: arena_plan.Binding,
) !void {
    const bytes = try resident_arena.bytes(binding);
    var digest: u64 = 0xcbf29ce484222325;
    for (bytes) |byte| {
        digest ^= byte;
        digest *%= 0x100000001b3;
    }
    std.debug.print(
        "{s}_digest index={} words={} fnv64={x:0>16}\n",
        .{ label, index, bytes.len / 4, digest },
    );
}

pub fn logCommitStepSamples(
    resident_arena: *arena_plan.ResidentArena,
    group_index: usize,
    output_offsets: []const u32,
    output_logs: []const u32,
    leaf_state: arena_plan.Binding,
) !void {
    const arena_bytes: [*]const u8 = @ptrCast(resident_arena.buffer.contents);
    var tile_digest: u64 = 0xcbf29ce484222325;
    for (output_offsets, output_logs) |offset, log_size| {
        const words = @as(u32, 1) << @intCast(log_size);
        for (0..16) |sample| {
            const word_index = offset + @as(u32, @intCast((@as(u64, words - 1) * sample) / 15));
            const value = std.mem.readInt(u32, arena_bytes[@as(usize, word_index) * 4 ..][0..4], .little);
            for (std.mem.asBytes(&value)) |byte| {
                tile_digest ^= byte;
                tile_digest *%= 0x100000001b3;
            }
        }
    }
    const leaf_bytes = try resident_arena.bytes(leaf_state);
    const leaf_count = leaf_bytes.len / 32;
    var leaf_digest: u64 = 0xcbf29ce484222325;
    for (0..16) |sample| {
        const leaf_index = ((leaf_count - 1) * sample) / 15;
        for (leaf_bytes[leaf_index * 32 ..][0..32]) |byte| {
            leaf_digest ^= byte;
            leaf_digest *%= 0x100000001b3;
        }
    }
    std.debug.print(
        "commit_step group={} tile_sample={x:0>16} leaf_sample={x:0>16}\n",
        .{ group_index, tile_digest, leaf_digest },
    );
}

pub fn sampleCommitOutputs(
    resident_arena: *arena_plan.ResidentArena,
    output_offsets: []const u32,
    output_log: u32,
) u64 {
    const arena_bytes: [*]const u8 = @ptrCast(resident_arena.buffer.contents);
    const words = @as(u32, 1) << @intCast(output_log);
    var digest: u64 = 0xcbf29ce484222325;
    for (output_offsets) |offset| {
        for (0..256) |sample| {
            const word_index = offset + @as(u32, @intCast((@as(u64, words - 1) * sample) / 255));
            const value = std.mem.readInt(u32, arena_bytes[@as(usize, word_index) * 4 ..][0..4], .little);
            for (std.mem.asBytes(&value)) |byte| {
                digest ^= byte;
                digest *%= 0x100000001b3;
            }
        }
    }
    return digest;
}
