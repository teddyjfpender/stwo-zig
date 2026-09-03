//! Deterministic cold reconstruction of the role-aware V1 public boundary.
//!
//! Scalar CPU/root/completion authority comes from authenticated PublicDataV2.
//! The admitted ELF layout supplies addresses; the globally bound raw input
//! and expected output supply bytes. Exact output words (including unused high
//! bytes) and clocks come only from cold-reconstructed STWIMT04 sources. No
//! host-observed VM result is used.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");

const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const public_logup_v3 = frontend.air.incremental_public_logup_v3;
const statement_v2 = frontend.air.statement_v2;
const memory_state = frontend.runner.memory_state;

pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;

pub fn reconstruct(
    allocator: std.mem.Allocator,
    native: *const public_data_v2.PublicDataV2,
    layout: memory_state.MemoryLayout,
    retained_input: []const u8,
    retained_expected_output: []const u8,
    boundary_sources: []const boundary_v4.WordBoundarySourceV4,
) !public_logup_v3.OwnedPublicDataV3 {
    try native.validate();
    const metadata = try native.metadata();
    const input_words = if (metadata.is_first)
        try public_data.packInputWords(allocator, retained_input)
    else
        try allocator.alloc(u32, 0);
    defer allocator.free(input_words);
    const output_words = if (metadata.is_final)
        try reconstructOutput(
            allocator,
            layout,
            retained_expected_output,
            boundary_sources,
        )
    else
        try allocator.alloc(public_data.OutputWord, 0);
    defer allocator.free(output_words);

    var value = try statement_v2.canonicalCorePublicData(native);
    if (value.completion == null) {
        value.completion = public_data.Completion.canonicalSelfLoop(
            value.final_pc,
        );
    }
    value.io_entries = .{
        .input_start = layout.input_base,
        .input_len = if (metadata.is_first)
            std.math.cast(u32, retained_input.len) orelse
                return error.IncrementalRolePublicInputTooLargeV4
        else
            0,
        .input_words = input_words,
        .output_len = if (metadata.is_final)
            std.math.cast(u32, retained_expected_output.len) orelse
                return error.IncrementalRolePublicOutputTooLargeV4
        else
            0,
        .output_len_addr = layout.output_len_addr,
        .output_data_addr = layout.output_data_addr,
        .output_words = output_words,
    };
    const authority = boundary_v4.SegmentPublicAuthorityV4{
        .coordinate = .{
            .segment_index = metadata.segment_index,
            .segment_count = metadata.segment_count,
        },
        .segment_role = .{
            .is_first = metadata.is_first,
            .is_last = metadata.is_final,
        },
        .layout = layout,
        .public_data = &value,
        .continuation_roots = .{
            .entry = metadata.entry_continuation_root,
            .exit = metadata.exit_continuation_root,
        },
    };
    const validated = try boundary_v4.ValidatedSegmentPublicAuthorityV4.init(
        authority,
    );
    try validated.validateInventory(boundary_sources);
    return public_logup_v3.OwnedPublicDataV3.initVerified(
        allocator,
        native,
        &value,
    );
}

fn reconstructOutput(
    allocator: std.mem.Allocator,
    layout: memory_state.MemoryLayout,
    retained: []const u8,
    boundary_sources: []const boundary_v4.WordBoundarySourceV4,
) ![]public_data.OutputWord {
    const output_len = std.math.cast(u32, retained.len) orelse
        return error.IncrementalRolePublicOutputTooLargeV4;
    if (output_len == 0)
        return allocator.alloc(public_data.OutputWord, 0);
    if ((layout.output_len_addr & 3) != 0 or
        (layout.output_data_addr & 3) != 0)
    {
        return error.InvalidMemoryLayout;
    }
    const data_count = std.math.divCeil(usize, retained.len, 4) catch
        return error.IncrementalRolePublicOutputTooLargeV4;
    const words = try allocator.alloc(public_data.OutputWord, data_count + 1);
    errdefer allocator.free(words);
    words[0] = .{
        .addr = layout.output_len_addr,
        .value = undefined,
        .clock = undefined,
    };
    for (words[1..], 0..) |*word, index| {
        const offset = std.math.mul(u32, @intCast(index), 4) catch
            return error.IncrementalRolePublicOutputTooLargeV4;
        word.* = .{
            .addr = std.math.add(u32, layout.output_data_addr, offset) catch
                return error.IncrementalRolePublicOutputTooLargeV4,
            .value = undefined,
            .clock = undefined,
        };
    }
    for (words, 0..) |left, index| for (words[index + 1 ..]) |right| {
        if (left.addr == right.addr) return error.InvalidMemoryLayout;
    };

    for (words) |*word| {
        const source = findSource(boundary_sources, word.addr) orelse
            return error.IncrementalRolePublicOutputMissingV4;
        word.value = source.word.final_word;
        word.clock = source.word.final_clock;
    }
    if (words[0].value != output_len)
        return error.IncrementalRolePublicOutputLengthMismatchV4;
    for (retained, 0..) |expected, index| {
        const word = words[1 + index / 4].value;
        const actual: u8 = @truncate(word >> @intCast((index % 4) * 8));
        if (actual != expected)
            return error.IncrementalRolePublicOutputMismatchV4;
    }
    return words;
}

fn findSource(
    sources: []const boundary_v4.WordBoundarySourceV4,
    address: u32,
) ?boundary_v4.WordBoundarySourceV4 {
    var low: usize = 0;
    var high = sources.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const source = sources[mid];
        if (source.word.addr < address) {
            low = mid + 1;
        } else if (source.word.addr > address) {
            high = mid;
        } else {
            return source;
        }
    }
    return null;
}
