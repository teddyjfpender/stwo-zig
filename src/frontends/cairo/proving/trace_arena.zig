//! One contiguous, claim-planned arena for the Cairo base trace.
//!
//! Campaign 1's rejected base-trace ownership retrofit recorded the governing
//! constraint: the Metal backend accepts a true no-copy host source only when
//! all columns cover one contiguous arena, and retrofitting ownership after
//! fragmented allocation does not remove the representation transform. The
//! successor therefore allocates one backend-shaped arena *before* component
//! execution and lets witness generation write every generated and implicit
//! column directly at its final offset.
//!
//! The plan is derived from the live claim: `template_binding.instantiate`
//! already produces a claim-derived composition bundle whose per-component
//! base-tree spans give the column count and whose `trace_log_size` gives the
//! row count. That is everything the layout needs, and it is available before
//! witness execution.
//!
//! Layout. Columns are grouped by `log_size` in first-appearance order, which
//! is exactly the order `pcs.columns.circle_transforms.buildLogSizeGroupsFromColumns`
//! produces at commit time, and within a group they keep ascending flat-column
//! order. Each group starts on a page boundary. A commit-time adopter can then
//! recognise each group's source columns as one contiguous page-aligned run and
//! bind them with no copy.
//!
//! Interaction columns are *reserved* by the same plan (offsets and length are
//! computed and exposed) but not materialized here: they are written after the
//! base commit, per Fiat-Shamir, so only the reservation is a planning concern.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const composition_bundle = @import("../witness/composition_bundle.zig");
const resident_geometry = @import("../witness/resident_geometry.zig");

const M31 = core.fields.m31.M31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;

pub const Error = error{
    /// The claim-derived geometry cannot be laid out (empty component, empty
    /// span, non-power-of-two or out-of-range row count). Structural
    /// admission: the caller falls back to the fragmented path.
    UnsupportedArenaGeometry,
    /// The layout does not fit the word-count budget.
    ArenaTooLarge,
    /// Witness execution produced a component width the plan did not predict.
    /// Fail closed rather than write outside a planned range.
    ArenaPlanMismatch,
};

/// Refuse to plan an arena larger than 8 GiB of M31 words. A Cairo base trace
/// at the composition bundle's `max_evaluation_log_size = 24` and 4,000 columns
/// is 256 GiB short of this, so the bound only catches corrupt geometry.
pub const max_arena_words: usize = 1 << 31;

/// Minimum planned base words below which the arena is not worth its page
/// padding. Small proofs keep the fragmented path; this is a structural size
/// admission, never a workload name.
pub const min_arena_words: usize = 1 << 16;

pub const Group = struct {
    log_size: u32,
    /// Word offset of the group's first column inside the arena. Page-aligned.
    offset: usize,
    column_count: usize,
};

/// Word offset of every base column, indexed by flat commit-order column index.
pub const Layout = struct {
    allocator: std.mem.Allocator,
    offsets: []usize,
    log_sizes: []u32,
    groups: []Group,
    /// Flat column index at which each component's columns begin.
    component_starts: []usize,
    /// Number of base columns each component contributes.
    component_widths: []usize,
    /// Total words the base region occupies, page-padded.
    base_words: usize,
    /// Reserved interaction region, planned but not allocated by this module.
    interaction_offset: usize,
    interaction_words: usize,

    pub fn deinit(self: *Layout) void {
        self.allocator.free(self.offsets);
        self.allocator.free(self.log_sizes);
        self.allocator.free(self.groups);
        self.allocator.free(self.component_starts);
        self.allocator.free(self.component_widths);
        self.* = undefined;
    }

    pub fn columnCount(self: *const Layout) usize {
        return self.offsets.len;
    }

    /// Total planned words including the reserved interaction region.
    pub fn totalWords(self: *const Layout) usize {
        return self.interaction_offset + self.interaction_words;
    }
};

fn pageWords() usize {
    const page = std.heap.pageSize();
    return @max(@as(usize, 1), page / @sizeOf(M31));
}

/// Derives the arena layout from the live claim-derived composition bundle.
///
/// Returns `Error.UnsupportedArenaGeometry` (not a panic) for any geometry the
/// layout cannot express, so the product can fall back to today's fragmented
/// allocation unchanged.
pub fn plan(
    allocator: std.mem.Allocator,
    components: []const composition_bundle.Component,
) Error!Layout {
    if (components.len == 0) return Error.UnsupportedArenaGeometry;
    const page_words = pageWords();

    const component_starts = allocator.alloc(usize, components.len) catch
        return Error.ArenaTooLarge;
    errdefer allocator.free(component_starts);
    const component_widths = allocator.alloc(usize, components.len) catch
        return Error.ArenaTooLarge;
    errdefer allocator.free(component_widths);

    var total_columns: usize = 0;
    for (components, component_starts, component_widths) |component, *start, *width| {
        const span = resident_geometry.componentSpan(component, 1) catch
            return Error.UnsupportedArenaGeometry;
        if (span.start != total_columns or span.end <= span.start)
            return Error.UnsupportedArenaGeometry;
        if (component.trace_log_size < 4 or component.trace_log_size >= 30)
            return Error.UnsupportedArenaGeometry;
        start.* = total_columns;
        width.* = span.end - span.start;
        total_columns = span.end;
    }
    if (total_columns == 0) return Error.UnsupportedArenaGeometry;

    const offsets = allocator.alloc(usize, total_columns) catch
        return Error.ArenaTooLarge;
    errdefer allocator.free(offsets);
    const log_sizes = allocator.alloc(u32, total_columns) catch
        return Error.ArenaTooLarge;
    errdefer allocator.free(log_sizes);
    for (components, component_starts, component_widths) |component, start, width| {
        @memset(log_sizes[start..][0..width], component.trace_log_size);
    }

    // Groups in first-appearance order of log size, matching the commit-time
    // grouping exactly so a group's columns form one contiguous arena run.
    var groups = std.ArrayList(Group).empty;
    errdefer groups.deinit(allocator);
    for (log_sizes) |log_size| {
        var seen = false;
        for (groups.items) |group| seen = seen or group.log_size == log_size;
        if (!seen) groups.append(allocator, .{
            .log_size = log_size,
            .offset = 0,
            .column_count = 0,
        }) catch return Error.ArenaTooLarge;
    }
    for (log_sizes) |log_size| {
        for (groups.items) |*group| if (group.log_size == log_size) {
            group.column_count += 1;
        };
    }

    var cursor: usize = 0;
    for (groups.items) |*group| {
        cursor = std.mem.alignForward(usize, cursor, page_words);
        group.offset = cursor;
        const rows = std.math.shl(usize, 1, group.log_size);
        const span = std.math.mul(usize, group.column_count, rows) catch
            return Error.ArenaTooLarge;
        cursor = std.math.add(usize, cursor, span) catch return Error.ArenaTooLarge;
        if (cursor > max_arena_words) return Error.ArenaTooLarge;
    }
    const base_words = std.mem.alignForward(usize, cursor, page_words);
    if (base_words > max_arena_words) return Error.ArenaTooLarge;
    if (base_words < min_arena_words) return Error.UnsupportedArenaGeometry;

    // Assign each flat column its offset inside its group, in ascending flat
    // order — the same order the commit-time group builder walks.
    const group_cursor = allocator.alloc(usize, groups.items.len) catch
        return Error.ArenaTooLarge;
    defer allocator.free(group_cursor);
    for (groups.items, group_cursor) |group, *slot| slot.* = group.offset;
    for (log_sizes, offsets) |log_size, *offset| {
        const rows = std.math.shl(usize, 1, log_size);
        for (groups.items, group_cursor) |group, *slot| {
            if (group.log_size != log_size) continue;
            offset.* = slot.*;
            slot.* += rows;
            break;
        }
    }

    // Reserve the interaction region from the same claim. Interaction columns
    // are written after the base commit, so this is a reservation only.
    var interaction_words: usize = 0;
    for (components) |component| {
        const span = resident_geometry.componentSpan(component, 2) catch
            return Error.UnsupportedArenaGeometry;
        if (span.end < span.start) return Error.UnsupportedArenaGeometry;
        const width = span.end - span.start;
        const rows = std.math.shl(usize, 1, component.trace_log_size);
        const span_words = std.math.mul(usize, width, rows) catch
            return Error.ArenaTooLarge;
        interaction_words = std.math.add(usize, interaction_words, span_words) catch
            return Error.ArenaTooLarge;
    }
    const interaction_offset = base_words;
    const total = std.math.add(usize, interaction_offset, interaction_words) catch
        return Error.ArenaTooLarge;
    if (total > max_arena_words) return Error.ArenaTooLarge;

    const owned_groups = groups.toOwnedSlice(allocator) catch return Error.ArenaTooLarge;
    return .{
        .allocator = allocator,
        .offsets = offsets,
        .log_sizes = log_sizes,
        .groups = owned_groups,
        .component_starts = component_starts,
        .component_widths = component_widths,
        .base_words = base_words,
        .interaction_offset = interaction_offset,
        .interaction_words = std.mem.alignForward(usize, interaction_words, page_words),
    };
}

/// One allocation plus the layout that addresses it.
pub const Arena = struct {
    allocator: std.mem.Allocator,
    layout: Layout,
    words: []M31,
    /// True when the allocation actually landed on a page boundary. The
    /// no-copy device binding additionally requires this; a non-aligned arena
    /// is still byte-correct and still one contiguous run, it just costs one
    /// device-side copy.
    page_aligned: bool,

    pub fn deinit(self: *Arena) void {
        self.allocator.free(self.words);
        self.layout.deinit();
        self.* = undefined;
    }

    /// The planned destination of one flat base column.
    pub fn columnValues(self: *const Arena, index: usize) Error![]M31 {
        if (index >= self.layout.offsets.len) return Error.ArenaPlanMismatch;
        const rows = std.math.shl(usize, 1, self.layout.log_sizes[index]);
        const offset = self.layout.offsets[index];
        if (offset + rows > self.words.len) return Error.ArenaPlanMismatch;
        return self.words[offset..][0..rows];
    }

    /// The single backing buffer a commit path adopts.
    pub fn backing(self: *const Arena, allocator: std.mem.Allocator) ![][]M31 {
        const buffers = try allocator.alloc([]M31, 1);
        buffers[0] = self.words;
        return buffers;
    }
};

/// Allocates the planned base region as one buffer. Only the base region is
/// materialized: the reserved interaction region is written after the base
/// commit and is allocated by whoever writes it.
pub fn allocate(allocator: std.mem.Allocator, layout: Layout) !Arena {
    var owned = layout;
    errdefer owned.deinit();
    const words = try allocator.alloc(M31, owned.base_words);
    // Every planned range is written by construction, but a component that
    // exposes fewer rows than its declared log size would otherwise publish
    // uninitialized words to the Merkle leaf hash. Zero first; the cost is one
    // linear pass over an arena the witness is about to fill anyway.
    @memset(words, M31.zero());
    const page = std.heap.pageSize();
    return .{
        .allocator = allocator,
        .layout = owned,
        .words = words,
        .page_aligned = @intFromPtr(words.ptr) % page == 0 and
            (words.len * @sizeOf(M31)) % page == 0,
    };
}

/// Plans and allocates in one step, mapping every planning refusal to `null`
/// so the caller keeps today's fragmented path unchanged.
pub fn tryPrepare(
    allocator: std.mem.Allocator,
    components: []const composition_bundle.Component,
) ?Arena {
    const layout = plan(allocator, components) catch return null;
    return allocate(allocator, layout) catch |err| {
        var owned = layout;
        owned.deinit();
        if (err == error.OutOfMemory) return null;
        return null;
    };
}

/// Asserts that the flat column list a commit path is about to receive really
/// does cover the arena at the planned offsets. This is the invariant the
/// no-copy device binding rests on, so it is checked rather than assumed.
pub fn columnsMatchPlan(arena: *const Arena, columns: []const ColumnEvaluation) bool {
    if (columns.len != arena.layout.offsets.len) return false;
    for (columns, arena.layout.offsets, arena.layout.log_sizes) |column, offset, log_size| {
        if (column.log_size != log_size) return false;
        const rows = std.math.shl(usize, 1, log_size);
        if (column.values.len != rows) return false;
        if (column.values.ptr != arena.words.ptr + offset) return false;
    }
    return true;
}
