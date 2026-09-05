//! Segment-local tape for one-retirement bulk-memcpy calls and word witnesses.

const std = @import("std");

const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const caller = @import("../../air/guest_precompile/bulk_memcpy_caller_candidate_v1.zig");
const words = @import("../../air/guest_precompile/bulk_memcpy_word_candidate_v1.zig");
const call_buffer = @import("bulk_memcpy_call_buffer_v1.zig");

pub const CallerRecord = caller.Record;
pub const Call = words.Call;
pub const WordRow = words.Row;
pub const CallRecord = call_buffer.Record;
pub const fixed_inst_word = abi.fixed_word;

pub const ExecutionRow = struct {
    execution_clock: u32,
    pc: u32,
    inst_word: u32,
    call_index: u32,
    first_word_row: u32,
    word_row_count: u32,
};

pub const Frozen = struct {
    calls: call_buffer.Frozen,
    execution_rows: std.ArrayList(ExecutionRow),
    allocator: std.mem.Allocator,
    external_step_origin: usize,

    pub fn records(self: *const Frozen) []const call_buffer.Record {
        return self.calls.records();
    }

    pub fn wordRows(self: *const Frozen) []const words.Row {
        return self.calls.rows();
    }

    pub fn rows(self: *const Frozen) []const ExecutionRow {
        return self.execution_rows.items;
    }

    pub fn externalStepOrigin(self: *const Frozen) usize {
        return self.external_step_origin;
    }

    pub fn validate(self: *const Frozen) !void {
        try self.calls.validate();
        try validateRows(self.records(), self.rows());
    }

    pub fn deinit(self: *Frozen) void {
        self.calls.deinit();
        self.execution_rows.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Builder = struct {
    calls: call_buffer.Builder,
    execution_rows: std.ArrayList(ExecutionRow) = .empty,
    allocator_value: std.mem.Allocator,
    call_limit: usize,
    external_step_origin: usize,

    pub fn init(
        backing_allocator: std.mem.Allocator,
        call_limit: usize,
        word_row_limit: usize,
        external_step_origin: usize,
    ) !Builder {
        return .{
            .calls = try .init(backing_allocator, call_limit, word_row_limit),
            .allocator_value = backing_allocator,
            .call_limit = call_limit,
            .external_step_origin = external_step_origin,
        };
    }

    pub fn deinit(self: *Builder) void {
        self.calls.deinit();
        self.execution_rows.deinit(self.allocator_value);
        self.* = undefined;
    }

    pub fn allocator(self: *const Builder) std.mem.Allocator {
        return self.allocator_value;
    }

    pub fn len(self: *const Builder) usize {
        return self.calls.len();
    }

    pub fn wordLen(self: *const Builder) usize {
        return self.calls.wordLen();
    }

    pub fn rowLen(self: *const Builder) usize {
        return self.execution_rows.items.len;
    }

    pub fn records(self: *const Builder) []const call_buffer.Record {
        return self.calls.records();
    }

    pub fn wordRows(self: *const Builder) []const words.Row {
        return self.calls.rows();
    }

    pub fn rows(self: *const Builder) []const ExecutionRow {
        return self.execution_rows.items;
    }

    pub fn externalStepOrigin(self: *const Builder) usize {
        return self.external_step_origin;
    }

    pub fn reserveOne(self: *Builder, word_row_count: usize) !void {
        try self.calls.reserveOne(word_row_count);
        if (self.execution_rows.items.len >= self.call_limit)
            return error.BulkMemcpyTapeLimitExceeded;
        try self.execution_rows.ensureUnusedCapacity(self.allocator_value, 1);
    }

    pub fn appendAssumeCapacity(
        self: *Builder,
        inst_word: u32,
        record: caller.Record,
        word_rows: []const words.Row,
    ) void {
        const execution = ExecutionRow{
            .execution_clock = record.execution_clock,
            .pc = record.pc,
            .inst_word = inst_word,
            .call_index = @intCast(self.calls.len()),
            .first_word_row = @intCast(self.calls.wordLen()),
            .word_row_count = @intCast(word_rows.len),
        };
        std.debug.assert(self.execution_rows.items.len < self.call_limit);
        self.calls.appendAssumeCapacity(record, word_rows);
        self.execution_rows.appendAssumeCapacity(execution);
    }

    pub fn validate(self: *const Builder) !void {
        try self.calls.validate();
        try validateRows(self.records(), self.rows());
    }

    pub fn externalCounts(self: *const Builder) struct { calls: usize, rows: usize } {
        return .{ .calls = self.len(), .rows = self.rowLen() };
    }

    pub fn freeze(self: *Builder) Frozen {
        const result = Frozen{
            .calls = self.calls.freeze(),
            .execution_rows = self.execution_rows,
            .allocator = self.allocator_value,
            .external_step_origin = self.external_step_origin,
        };
        self.execution_rows = .empty;
        self.call_limit = 0;
        self.external_step_origin = 0;
        return result;
    }
};

fn validateRows(
    records: []const call_buffer.Record,
    execution_rows: []const ExecutionRow,
) !void {
    if (records.len != execution_rows.len)
        return error.InvalidBulkMemcpySessionTape;
    for (records, execution_rows, 0..) |record, row, index| {
        _ = abi.decode(row.inst_word) catch
            return error.InvalidBulkMemcpySessionTape;
        if (row.execution_clock != record.caller.execution_clock or
            row.pc != record.caller.pc or
            row.call_index != @as(u32, @intCast(index)) or
            row.call_index != record.caller.call_index or
            row.first_word_row != record.first_word_row or
            row.word_row_count != record.word_row_count)
        {
            return error.InvalidBulkMemcpySessionTape;
        }
    }
}

comptime {
    if (abi.production_active or caller.production_active or words.production_active)
        @compileError("bulk memcpy session tape is candidate-only");
}
