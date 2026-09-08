//! Exhaustive canonical V2 transcript word classification. This describes
//! routing obligations, not proof authority: dynamic data never becomes a
//! constant merely because a native recording supplies its value.
const std = @import("std");
const contract = @import("segment_statement_v2_contract.zig");
const view_mod = @import("segment_statement_v2_canonical_wire_view_v2.zig");
const M31 = contract.M31;
pub const Error = contract.Error;
pub const fixed_layout = contract.fixed_layout;
pub const FIXED_WORD_COUNT = contract.FIXED_CANONICAL_WORDS;
pub const SECTION_HEADER_WORDS = contract.SECTION_HEADER_WORDS;
pub const ENTRY_WORD_COUNT = contract.RETAINED_ENTRY_WORDS;
pub const Side = enum(u1) { entry, exit };
pub const Section = enum(u2) {
    entry_snapshot,
    exit_snapshot,
    entry_memory_clocks,
    exit_memory_clocks,

    pub fn tag(self: Section) contract.Tag {
        return switch (self) {
            .entry_snapshot => .entry_memory_state,
            .exit_snapshot => .exit_memory_state,
            .entry_memory_clocks => .entry_memory_clocks,
            .exit_memory_clocks => .exit_memory_clocks,
        };
    }

    pub fn countHeaderIndex(self: Section) usize {
        return switch (self) {
            .entry_snapshot => fixed_layout.entry_snapshot_count,
            .exit_snapshot => fixed_layout.exit_snapshot_count,
            .entry_memory_clocks => fixed_layout.entry_memory_clock_count,
            .exit_memory_clocks => fixed_layout.exit_memory_clock_count,
        };
    }
};
pub const SECTIONS = [_]Section{ .entry_snapshot, .exit_snapshot, .entry_memory_clocks, .exit_memory_clocks };
pub const DigestField = enum {
    session_id,
    job_id,
    position_id,
    entry_lineage_id,
    exit_lineage_id,
    lineage_id,
    base_statement_id,
    entry_snapshot_id,
    exit_snapshot_id,
    entry_memory_clock_id,
    exit_memory_clock_id,
};
pub const CompletionField = enum(u3) { tag, kind, address_low, address_high, value_low, value_high, clock_low, clock_high };
pub const RetainedField = enum { address, value, clock };
pub const Data = union(enum) {
    digest: struct { field: DigestField, limb: u3 },
    span_word: u16,
    continuation_root: struct { side: Side, limb: u1 },
    register_clock: struct { side: Side, register: u5, limb: u1 },
    completion: CompletionField,
    retained: struct { section: Section, entry: u32, field: RetainedField, limb: u1 },
};
pub const CountWord = struct { section: Section, limb: u1, value: u16 };
pub const Word = union(enum) {
    /// Schema values and section tags; independent of witness and shape.
    fixed: u32,
    /// Counts must come from an independently admitted geometry. Both copies
    /// of each count share this exact coordinate; reading a wire is not admission.
    geometry: CountWord,
    /// Requires a real public/committed/derived source in the recursive AIR.
    data: Data,
};

pub const Layout = struct {
    counts: [SECTIONS.len]u32,
    sections: [SECTIONS.len]contract.RetainedSectionV2,
    total_words: usize,

    /// Callers must separately authenticate/admit these counts. No payload
    /// value or presence flag is accepted as a reason to classify data as fixed.
    pub fn init(counts: [SECTIONS.len]u32) Error!Layout {
        var sections: [SECTIONS.len]contract.RetainedSectionV2 = undefined;
        var at: usize = FIXED_WORD_COUNT;
        for (counts, &sections) |count, *retained| {
            if (count > contract.MAX_SPARSE_BOUNDARY_ENTRIES) return error.ExecutionRangeOutOfBounds;
            const payload_start = std.math.add(usize, at, SECTION_HEADER_WORDS) catch return error.CanonicalLengthMismatch;
            const payload_len = std.math.mul(usize, count, ENTRY_WORD_COUNT) catch return error.CanonicalLengthMismatch;
            retained.* = .{ .payload_start = payload_start, .count = count };
            at = std.math.add(usize, payload_start, payload_len) catch return error.CanonicalLengthMismatch;
        }
        return .{ .counts = counts, .sections = sections, .total_words = at };
    }

    pub fn fromStatement(statement: *const contract.StatementV2) Error!Layout {
        return init(.{ statement.entry_snapshot_count, statement.exit_snapshot_count, statement.entry_memory_clock_count, statement.exit_memory_clock_count });
    }

    /// Structural check against an already authenticated native view. This
    /// intentionally does not repeat its expensive digest/snapshot validation.
    pub fn fromView(view: *const view_mod.CanonicalWireViewV2) Error!Layout {
        const result = try fromStatement(&view.statement);
        if (view.words.len != result.total_words or !std.meta.eql(result.sections, [4]contract.RetainedSectionV2{ view.entry_snapshot, view.exit_snapshot, view.entry_memory_clocks, view.exit_memory_clocks }))
            return error.RetainedBoundaryMismatch;
        return result;
    }

    pub fn section(self: *const Layout, id: Section) contract.RetainedSectionV2 {
        return self.sections[@intFromEnum(id)];
    }

    pub fn wordCount(self: *const Layout) usize {
        return self.total_words;
    }

    pub fn word(self: *const Layout, index: usize) Error!Word {
        if (index >= self.total_words) return error.CanonicalLengthMismatch;
        if (index < 4) return .{ .fixed = ([_]u32{ @intFromEnum(contract.Tag.segment_statement_v2), contract.FORMAT_VERSION, contract.SCHEMA_VERSION, contract.KNOWN_FLAGS })[index] };
        inline for (std.meta.fields(DigestField)) |field| {
            const start = @field(fixed_layout, field.name);
            if (index >= start and index < start + 8)
                return .{ .data = .{ .digest = .{ .field = @enumFromInt(field.value), .limb = @intCast(index - start) } } };
        }
        if (index >= fixed_layout.base_statement and index < fixed_layout.entry_snapshot_id)
            return .{ .data = .{ .span_word = @intCast(index - fixed_layout.base_statement) } };
        for (SECTIONS) |id| {
            const start = id.countHeaderIndex();
            if (index >= start and index < start + 2) return self.countWord(id, @intCast(index - start));
        }
        if (index >= fixed_layout.entry_continuation_root and index < fixed_layout.entry_continuation_root + 2)
            return .{ .data = .{ .continuation_root = .{ .side = .entry, .limb = @intCast(index - fixed_layout.entry_continuation_root) } } };
        if (index >= fixed_layout.exit_continuation_root and index < fixed_layout.exit_continuation_root + 2)
            return .{ .data = .{ .continuation_root = .{ .side = .exit, .limb = @intCast(index - fixed_layout.exit_continuation_root) } } };
        if (index >= fixed_layout.entry_register_clocks and index < fixed_layout.completion) {
            const offset = index - fixed_layout.entry_register_clocks;
            return .{ .data = .{ .register_clock = .{ .side = @enumFromInt(offset / 64), .register = @intCast((offset % 64) / 2), .limb = @intCast(offset % 2) } } };
        }
        if (index >= fixed_layout.completion and index < FIXED_WORD_COUNT)
            return .{ .data = .{ .completion = @enumFromInt(index - fixed_layout.completion) } };
        for (SECTIONS) |id| {
            const retained = self.section(id);
            const header_start = retained.payload_start - SECTION_HEADER_WORDS;
            if (index == header_start) return .{ .fixed = @intFromEnum(id.tag()) };
            if (index > header_start and index < retained.payload_start)
                return self.countWord(id, @intCast(index - header_start - 1));
            if (index >= retained.payload_start and index < retained.payload_start + @as(usize, retained.count) * ENTRY_WORD_COUNT) {
                const offset = index - retained.payload_start;
                return .{ .data = .{ .retained = .{
                    .section = id,
                    .entry = @intCast(offset / ENTRY_WORD_COUNT),
                    .field = if (offset % ENTRY_WORD_COUNT < 2) .address else switch (id) {
                        .entry_snapshot, .exit_snapshot => .value,
                        .entry_memory_clocks, .exit_memory_clocks => .clock,
                    },
                    .limb = @intCast(offset % 2),
                } } };
            }
        }
        // No catchall constant: an unclassified word is a layout error.
        return error.CanonicalLengthMismatch;
    }

    fn countWord(self: *const Layout, id: Section, limb: u1) Word {
        const count = self.counts[@intFromEnum(id)];
        return .{ .geometry = .{ .section = id, .limb = limb, .value = @truncate(count >> (@as(u5, limb) * 16)) } };
    }
};

comptime {
    if (fixed_layout.base_statement != 60 or fixed_layout.entry_snapshot_id != 472 or
        fixed_layout.entry_register_clocks != 516 or fixed_layout.completion != 644 or FIXED_WORD_COUNT != 652)
        @compileError("raw V2 transcript routing ranges drifted");
}
