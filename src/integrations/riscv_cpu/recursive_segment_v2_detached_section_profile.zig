//! Independently admitted retained-section geometry for a detached parent.
//! This is a structural profile, not a parser or compiler-policy certificate.
//! Production callers supply it from their pinned parent admission; no API
//! derives a trusted profile from candidate proof/public-input bytes.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const wire = frontend.recursion.segment_statement_v2;
const layout = wire.fixed_layout;

pub const SectionV1 = struct {
    tag: wire.Tag,
    header_start: usize,
    payload_start: usize,
    count: u32,
    count_offset: usize,
    digest_offset: usize,
    domain: u32,
    pub fn payloadWords(self: SectionV1) usize {
        return @as(usize, self.count) * wire.RETAINED_ENTRY_WORDS;
    }
};
pub const SectionProfileV1 = struct {
    version: u16 = 1,
    /// Entry snapshot, exit snapshot, entry clocks, exit clocks.
    counts: [4]u32,

    pub fn sections(self: SectionProfileV1, wire_word_count: usize) ![4]SectionV1 {
        if (self.version != 1) return error.InvalidBoundarySectionProfile;
        var result: [4]SectionV1 = undefined;
        var at: usize = wire.FIXED_CANONICAL_WORDS;
        inline for (.{ wire.Tag.entry_memory_state, wire.Tag.exit_memory_state, wire.Tag.entry_memory_clocks, wire.Tag.exit_memory_clocks }, .{ layout.entry_snapshot_count, layout.exit_snapshot_count, layout.entry_memory_clock_count, layout.exit_memory_clock_count }, .{ layout.entry_snapshot_id, layout.exit_snapshot_id, layout.entry_memory_clock_id, layout.exit_memory_clock_id }, 0..) |tag, count_offset, digest_offset, index| {
            const count = self.counts[index];
            if (count > wire.MAX_SPARSE_BOUNDARY_ENTRIES) return error.InvalidBoundarySectionProfile;
            result[index] = .{ .tag = tag, .header_start = at, .payload_start = at + wire.SECTION_HEADER_WORDS, .count = count, .count_offset = count_offset, .digest_offset = digest_offset, .domain = if (index < 2) wire.MEMORY_STATE_ID_DOMAIN else wire.MEMORY_CLOCK_ID_DOMAIN };
            at = std.math.add(usize, result[index].payload_start, result[index].payloadWords()) catch return error.InvalidBoundarySectionProfile;
        }
        if (at != wire_word_count) return error.InvalidBoundarySectionProfile;
        return result;
    }

    /// Full wire authentication remains the caller's ingress obligation. This
    /// check separately requires its observed partition to match admitted shape.
    pub fn validateView(self: SectionProfileV1, view: *const wire.CanonicalWireViewV2) !void {
        const exact = try self.sections(view.words.len);
        inline for (.{ view.entry_snapshot, view.exit_snapshot, view.entry_memory_clocks, view.exit_memory_clocks }, 0..) |observed, index| {
            if (observed.count != exact[index].count or observed.payload_start != exact[index].payload_start)
                return error.BoundarySectionProfileMismatch;
        }
    }
};
