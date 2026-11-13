//! Byte-offset helpers for adversarial materialization-frontier wire tests.

const std = @import("std");

pub const SectionView = struct {
    header_start: usize,
    payload_start: usize,
    payload: []const u8,
};

pub fn section(bytes: []const u8, wanted: u8) !SectionView {
    var cursor: usize = 12;
    while (cursor < bytes.len) {
        const header_start = cursor;
        if (bytes.len - cursor < 6) return error.TestUnexpectedResult;
        const tag = bytes[cursor];
        const length: usize = std.mem.readInt(
            u32,
            bytes[cursor + 2 ..][0..4],
            .little,
        );
        cursor += 6;
        if (length > bytes.len - cursor) return error.TestUnexpectedResult;
        if (tag == wanted) return .{
            .header_start = header_start,
            .payload_start = cursor,
            .payload = bytes[cursor..][0..length],
        };
        cursor += length;
    }
    return error.TestUnexpectedResult;
}

pub fn runWireLength() usize {
    return 32 + 4 * 4 + 2 + 1 + 1 + 2;
}

pub fn proposalWireLength(
    selected_count: usize,
    scenario_count: usize,
    has_removed: bool,
    has_added: bool,
) usize {
    return proposalScenarioCountOffset(selected_count, has_removed, has_added) + 2 +
        scenario_count * 6 * 8;
}

pub fn proposalScenarioCountOffset(
    selected_count: usize,
    has_removed: bool,
    has_added: bool,
) usize {
    return 32 + 32 + 1 + 2 + 32 + optionalWireLength(has_removed) +
        optionalWireLength(has_added) + 4 + selected_count * 4 + 13 * 8;
}

fn optionalWireLength(present: bool) usize {
    return if (present) 5 else 1;
}
