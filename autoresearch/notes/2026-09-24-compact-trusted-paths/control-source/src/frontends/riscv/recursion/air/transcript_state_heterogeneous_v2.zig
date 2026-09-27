//! Row-3 state-transition preprocessing derived from heterogeneous row 2.

const std = @import("std");
const binding_v2 = @import("transcript_data_rows_heterogeneous_v2.zig");
const schedule = @import("verifier_schedule.zig");
const state = @import("transcript_state_witness_contract.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/transcript-state-heterogeneous/v2\x00";

pub const Error = state.Error || error{
    InvalidHeterogeneousScheduleAuthority,
    InvalidHeterogeneousTranscriptStateAuthority,
};

pub const PreprocessedV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    log_size: u32,
    rows: []state.PreprocessedRow,
    frame_counts: [LANE_COUNT]usize,
    call_counts: [LANE_COUNT]usize,
    schemas: [LANE_COUNT]schedule.Schema,
    schedule_digests: [LANE_COUNT][8]u32,
    binding_authority_sha256: [32]u8,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        calls: *const binding_v2.TranscriptBindingPreprocessedV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!PreprocessedV2 {
        try calls.validateAgainst(vm, left, right);
        const call_lanes = try callLanes(calls);
        var frame_counts: [LANE_COUNT]usize = undefined;
        var row_count: usize = 0;
        for (call_lanes, &frame_counts) |lane, *count| {
            count.* = try state.frameCount(lane);
            row_count = std.math.add(
                usize,
                row_count,
                count.*,
            ) catch return error.ArithmeticOverflow;
        }
        const rows = try allocator.alloc(state.PreprocessedRow, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        inline for (call_lanes, 0..) |lane, lane_index|
            try state.appendCallRows(
                rows,
                &cursor,
                lane,
                @intCast(lane_index),
                @intFromBool(lane_index == 0),
                @intFromBool(lane_index != 0),
            );
        if (cursor != rows.len)
            return error.InvalidHeterogeneousTranscriptStateAuthority;
        for (rows) |row| try state.validatePreprocessedRow(row);
        var result = PreprocessedV2{
            .allocator = allocator,
            .log_size = try state.traceLogSize(row_count),
            .rows = rows,
            .frame_counts = frame_counts,
            .call_counts = calls.counts,
            .schemas = calls.schemas,
            .schedule_digests = calls.schedule_digests,
            .binding_authority_sha256 = calls.authority_sha256,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = identity(&result);
        try result.validateAgainst(calls, vm, left, right);
        return result;
    }

    pub fn deinit(self: *PreprocessedV2) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const PreprocessedV2,
        calls: *const binding_v2.TranscriptBindingPreprocessedV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidHeterogeneousTranscriptStateAuthority;
        }
        try calls.validateAgainst(vm, left, right);
        if (!std.meta.eql(self.call_counts, calls.counts) or
            !std.meta.eql(self.schemas, calls.schemas) or
            !std.meta.eql(self.schedule_digests, calls.schedule_digests) or
            !std.mem.eql(
                u8,
                &self.binding_authority_sha256,
                &calls.authority_sha256,
            )) return error.InvalidHeterogeneousTranscriptStateAuthority;
        const call_lanes = try callLanes(calls);
        var row_count: usize = 0;
        for (call_lanes, self.frame_counts) |lane, frame_count| {
            if (frame_count != try state.frameCount(lane))
                return error.InvalidHeterogeneousTranscriptStateAuthority;
            row_count = std.math.add(
                usize,
                row_count,
                frame_count,
            ) catch return error.ArithmeticOverflow;
        }
        if (self.rows.len != row_count or
            self.log_size != try state.traceLogSize(row_count))
        {
            return error.InvalidHeterogeneousTranscriptStateAuthority;
        }
        var cursor: usize = 0;
        inline for (call_lanes, 0..) |lane, lane_index|
            try state.compareCallRows(
                self.rows,
                &cursor,
                lane,
                @intCast(lane_index),
                @intFromBool(lane_index == 0),
                @intFromBool(lane_index != 0),
            );
        if (cursor != self.rows.len or !std.mem.eql(
            u8,
            &self.authority_sha256,
            &identity(self),
        )) return error.InvalidHeterogeneousTranscriptStateAuthority;
    }
};

fn callLanes(
    calls: *const binding_v2.TranscriptBindingPreprocessedV2,
) Error![LANE_COUNT][]const state.binding_witness.PreprocessedRow {
    var result: [LANE_COUNT][]const state.binding_witness.PreprocessedRow =
        undefined;
    var start: usize = 0;
    for (calls.counts, &result) |count, *lane| {
        const end = std.math.add(usize, start, count) catch
            return error.ArithmeticOverflow;
        if (end > calls.rows.len)
            return error.InvalidHeterogeneousTranscriptStateAuthority;
        lane.* = calls.rows[start..end];
        start = end;
    }
    if (start != calls.rows.len)
        return error.InvalidHeterogeneousTranscriptStateAuthority;
    return result;
}

fn identity(self: *const PreprocessedV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, self.format_version);
    hashInt(&hash, u16, self.schema_version);
    hashInt(&hash, u32, self.log_size);
    for (
        self.frame_counts,
        self.call_counts,
        self.schemas,
        self.schedule_digests,
    ) |frames, calls, schema, schedule_digest| {
        hashInt(&hash, u64, frames);
        hashInt(&hash, u64, calls);
        hashInt(&hash, u16, @intFromEnum(schema));
        for (schedule_digest) |word| hashInt(&hash, u32, word);
    }
    hash.update(&self.binding_authority_sha256);
    hashInt(&hash, u64, self.rows.len);
    for (self.rows) |row| for (row.values()) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3)
        @compileError("heterogeneous transcript-state contract drifted");
}
