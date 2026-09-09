//! Allocator-owned, cold-validatable custody for U256 swap calls and lanes.

const std = @import("std");
const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const caller = @import("../../air/guest_precompile/stack_swap_caller_candidate_v1.zig");
const words = @import("../../air/guest_precompile/stack_swap_word_candidate_v1.zig");

pub const max_calls: usize = 0x0fff_ffff;

pub const Record = struct {
    caller: caller.Record,
    first_word_row: u32,
    word_row_count: u32,

    pub fn validateAgainst(
        self: Record,
        expected_call_index: u32,
        expected_first_word_row: u32,
        rows: []const words.Row,
    ) !void {
        try self.caller.validate();
        const call = self.caller.call();
        if (self.caller.call_index != expected_call_index or
            self.first_word_row != expected_first_word_row or
            self.word_row_count != @as(u32, @intCast(words.lane_count)) or
            rows.len != words.lane_count)
        {
            return error.InvalidStackSwapSessionTape;
        }
        for (rows, 0..) |row, index| {
            const lane = words.Lane.at(@intCast(index));
            const expected = try words.materializeRow(call, lane, .{
                .lhs_previous_clock = row.lhs_previous_clock,
                .rhs_previous_clock = row.rhs_previous_clock,
                .lhs_before = row.lhs_before,
                .rhs_before = row.rhs_before,
            });
            if (!std.meta.eql(row, expected))
                return error.InvalidStackSwapSessionTape;
        }
        const caller_row = try caller.materialize(self.caller);
        if (!std.meta.eql((try caller_row.call()).tuple(), try rows[0].callTuple(.at(0))))
            return error.InvalidStackSwapSessionTape;
    }
};

pub const ExecutionRow = struct {
    execution_clock: u32,
    pc: u32,
    inst_word: u32,
    call_index: u32,
    first_word_row: u32,
    word_row_count: u32,
};

pub const Frozen = struct {
    authority: abi.Authority,
    calls: std.ArrayList(Record),
    word_rows: std.ArrayList(words.Row),
    execution_rows: std.ArrayList(ExecutionRow),
    allocator: std.mem.Allocator,
    external_step_origin: usize,

    pub fn records(self: *const Frozen) []const Record {
        return self.calls.items;
    }

    pub fn wordRows(self: *const Frozen) []const words.Row {
        return self.word_rows.items;
    }

    pub fn rows(self: *const Frozen) []const ExecutionRow {
        return self.execution_rows.items;
    }

    pub fn validate(self: *const Frozen) !void {
        try self.authority.validate();
        try validateAll(self.authority, self.records(), self.wordRows(), self.rows());
    }

    /// Cold validation requires transaction-external authority custody. A
    /// self-consistent replacement allocation or session origin is rejected.
    pub fn validateAgainst(
        self: *const Frozen,
        expected_authority: abi.Authority,
        expected_external_step_origin: usize,
    ) !void {
        try expected_authority.validate();
        if (!std.meta.eql(self.authority, expected_authority) or
            self.external_step_origin != expected_external_step_origin)
        {
            return error.InvalidStackSwapSessionAuthority;
        }
        try self.validate();
    }

    pub fn captureIdentity(self: *const Frozen) ![32]u8 {
        try self.validate();
        return hashCapture(
            self.authority,
            self.external_step_origin,
            self.records(),
            self.wordRows(),
            self.rows(),
        );
    }

    pub fn deinit(self: *Frozen) void {
        self.calls.deinit(self.allocator);
        self.word_rows.deinit(self.allocator);
        self.execution_rows.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Builder = struct {
    authority: abi.Authority,
    calls: std.ArrayList(Record) = .empty,
    word_rows: std.ArrayList(words.Row) = .empty,
    execution_rows: std.ArrayList(ExecutionRow) = .empty,
    allocator_value: std.mem.Allocator,
    call_limit: usize,
    external_step_origin: usize,

    pub fn init(
        backing_allocator: std.mem.Allocator,
        authority: abi.Authority,
        call_limit: usize,
        external_step_origin: usize,
    ) !Builder {
        try authority.validate();
        if (call_limit > max_calls) return error.StackSwapTapeLimitExceeded;
        return .{
            .authority = authority,
            .allocator_value = backing_allocator,
            .call_limit = call_limit,
            .external_step_origin = external_step_origin,
        };
    }

    pub fn deinit(self: *Builder) void {
        self.calls.deinit(self.allocator_value);
        self.word_rows.deinit(self.allocator_value);
        self.execution_rows.deinit(self.allocator_value);
        self.* = undefined;
    }

    pub fn allocator(self: *const Builder) std.mem.Allocator {
        return self.allocator_value;
    }

    pub fn len(self: *const Builder) usize {
        return self.calls.items.len;
    }

    pub fn wordLen(self: *const Builder) usize {
        return self.word_rows.items.len;
    }

    pub fn rowLen(self: *const Builder) usize {
        return self.execution_rows.items.len;
    }

    pub fn records(self: *const Builder) []const Record {
        return self.calls.items;
    }

    pub fn wordRows(self: *const Builder) []const words.Row {
        return self.word_rows.items;
    }

    pub fn rows(self: *const Builder) []const ExecutionRow {
        return self.execution_rows.items;
    }

    pub fn externalCounts(self: *const Builder) struct { calls: usize, rows: usize } {
        return .{ .calls = self.len(), .rows = self.rowLen() };
    }

    pub fn reserveOne(self: *Builder) !void {
        if (self.len() >= self.call_limit)
            return error.StackSwapTapeLimitExceeded;
        try self.calls.ensureUnusedCapacity(self.allocator_value, 1);
        try self.word_rows.ensureUnusedCapacity(self.allocator_value, words.lane_count);
        try self.execution_rows.ensureUnusedCapacity(self.allocator_value, 1);
    }

    pub fn appendAssumeCapacity(
        self: *Builder,
        inst_word: u32,
        caller_record: caller.Record,
        word_rows: *const [words.lane_count]words.Row,
    ) void {
        const first_word_row: u32 = @intCast(self.wordLen());
        const record = Record{
            .caller = caller_record,
            .first_word_row = first_word_row,
            .word_row_count = @intCast(words.lane_count),
        };
        self.calls.appendAssumeCapacity(record);
        self.word_rows.appendSliceAssumeCapacity(word_rows);
        self.execution_rows.appendAssumeCapacity(.{
            .execution_clock = caller_record.execution_clock,
            .pc = caller_record.pc,
            .inst_word = inst_word,
            .call_index = caller_record.call_index,
            .first_word_row = first_word_row,
            .word_row_count = @intCast(words.lane_count),
        });
    }

    pub fn validate(self: *const Builder) !void {
        try self.authority.validate();
        try validateAll(
            self.authority,
            self.calls.items,
            self.word_rows.items,
            self.execution_rows.items,
        );
    }

    pub fn freeze(self: *Builder) Frozen {
        const result = Frozen{
            .authority = self.authority,
            .calls = self.calls,
            .word_rows = self.word_rows,
            .execution_rows = self.execution_rows,
            .allocator = self.allocator_value,
            .external_step_origin = self.external_step_origin,
        };
        self.calls = .empty;
        self.word_rows = .empty;
        self.execution_rows = .empty;
        self.call_limit = 0;
        self.external_step_origin = 0;
        return result;
    }
};

fn validateAll(
    authority: abi.Authority,
    records: []const Record,
    word_rows: []const words.Row,
    execution_rows: []const ExecutionRow,
) !void {
    if (records.len != execution_rows.len or
        word_rows.len != records.len * words.lane_count)
    {
        return error.InvalidStackSwapSessionTape;
    }
    var first_word: u32 = 0;
    for (records, execution_rows, 0..) |record, execution, index| {
        _ = try authority.decode(execution.inst_word);
        const row_count: usize = @intCast(record.word_row_count);
        const end = @as(usize, first_word) + row_count;
        if (end > word_rows.len or
            execution.execution_clock != record.caller.execution_clock or
            execution.pc != record.caller.pc or
            execution.call_index != @as(u32, @intCast(index)) or
            execution.call_index != record.caller.call_index or
            execution.first_word_row != first_word or
            execution.word_row_count != @as(u32, @intCast(words.lane_count)))
        {
            return error.InvalidStackSwapSessionTape;
        }
        try record.validateAgainst(
            @intCast(index),
            first_word,
            word_rows[@intCast(first_word)..end],
        );
        first_word = @intCast(end);
    }
}

fn hashCapture(
    authority: abi.Authority,
    external_step_origin: usize,
    records: []const Record,
    word_rows: []const words.Row,
    execution_rows: []const ExecutionRow,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.u256-swap-session-capture.v1\x00");
    hash.update(&authority.semantic_identity);
    hash.update(&u64Bytes(@intCast(external_step_origin)));
    hash.update(&u32Bytes(@intCast(records.len)));
    for (records) |record| {
        hash.update(&u32Bytes(record.caller.execution_clock));
        hash.update(&u32Bytes(record.caller.pc));
        hash.update(&u32Bytes(record.caller.lhs_previous_clock));
        hash.update(&u32Bytes(record.caller.rhs_previous_clock));
        hash.update(&u32Bytes(record.caller.lhs_pointer));
        hash.update(&u32Bytes(record.caller.rhs_pointer));
        hash.update(&u32Bytes(record.caller.call_index));
    }
    for (word_rows) |row| {
        hash.update(&u32Bytes(row.lhs_previous_clock));
        hash.update(&u32Bytes(row.rhs_previous_clock));
        hash.update(&row.lhs_before);
        hash.update(&row.rhs_before);
    }
    for (execution_rows) |row| hash.update(&u32Bytes(row.inst_word));
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn u32Bytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

fn u64Bytes(value: u64) [8]u8 {
    var result: [8]u8 = undefined;
    std.mem.writeInt(u64, &result, value, .little);
    return result;
}

comptime {
    if (abi.production_active or caller.production_active or words.production_active)
        @compileError("stack-swap session is candidate-only");
}
