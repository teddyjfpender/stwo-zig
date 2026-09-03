//! Process-local ABI for diagnostic quotient boundary observations.
//!
//! This ABI is never serialized and carries no proof capability. It lets the
//! Objective-C runtime expose the exact cumulative numerator state after each
//! segmented raw-source dispatch to an independently implemented Zig oracle.

const std = @import("std");

pub const SCHEMA_VERSION: u32 = 1;

pub const PhaseV1 = enum(u32) {
    raw_segment = 1,
    finalized_quotient = 2,
};

pub const FLAG_RESIDENT_SOURCE: u32 = 1 << 0;
pub const FLAG_PAGE_ALIAS_SOURCE: u32 = 1 << 1;
pub const KNOWN_FLAGS: u32 = FLAG_RESIDENT_SOURCE | FLAG_PAGE_ALIAS_SOURCE;

pub const RawViewV1 = extern struct {
    offset: u32,
    length: u32,
    batch: u32,
    shift: u32,
    direct: u32,
    coeff_a: u32,
    coeff_b: u32,
    coeff_c: u32,
    coeff_d: u32,
};

pub const EventV1 = extern struct {
    schema_version: u32,
    phase: u32,
    segment_index: u32,
    segment_count: u32,
    first_column: u32,
    column_count: u32,
    view_count: u32,
    batch_count: u32,
    row_count: u64,
    flat_offset: u64,
    run_words: u64,
    source_binding_offset: u64,
    flags: u32,
    min_batch: u32,
    max_batch: u32,
    reserved: u32,
    min_original_offset: u64,
    max_original_offset: u64,
    min_rebased_offset: u64,
    max_rebased_offset: u64,
};

pub const ObserverV1 = *const fn (
    context: ?*anyopaque,
    event: *const EventV1,
    mapped_views: ?[*]const RawViewV1,
    domain_x: [*]const u32,
    domain_y: [*]const u32,
    values: [*]const u32,
    value_count: usize,
) callconv(.c) bool;

comptime {
    std.debug.assert(@sizeOf(RawViewV1) == 36);
    std.debug.assert(@alignOf(RawViewV1) == 4);
    std.debug.assert(@sizeOf(EventV1) == 112);
    std.debug.assert(@alignOf(EventV1) == 8);
    std.debug.assert(@offsetOf(EventV1, "row_count") == 32);
    std.debug.assert(@offsetOf(EventV1, "flags") == 64);
    std.debug.assert(@offsetOf(EventV1, "min_original_offset") == 80);
}
