//! Candidate-only, proof-facing traces for the bulk-memcpy runner tape.
//!
//! This module materializes the already frozen caller and word witnesses into
//! exact bit-reversed, column-major evaluation storage.  It deliberately does
//! not register a component or alter the production statement.  In
//! particular, the deterministic boundary selectors are only trace custody;
//! the future component must constrain them and handle the cyclic last-row
//! transition explicitly before this candidate can be activated.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const circle = stwo_core.circle;
const core_utils = stwo_core.utils;
const isa_profile = @import("../../isa/profile.zig");
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");
const session = @import("../../runner/guest_precompile/bulk_memcpy_session_tape_v1.zig");

pub const preprocessed_column_count: usize = 3;
pub const domain_first_column: usize = 0;
pub const domain_last_column: usize = 1;
pub const active_prefix_column: usize = 2;
pub const minimum_log_size: u32 = 1;

/// Degree-three components evaluate on a domain one log larger than the trace.
/// Retain that extension below the circle-domain order even though no component
/// is registered by this candidate module yet.
pub const maximum_log_size: u32 = circle.M31_CIRCLE_LOG_ORDER - 2;

pub const Error = error{
    InvalidExecutionOrder,
    InvalidProgramCounter,
    TraceContentMismatch,
    TraceLogTooLarge,
    TraceShapeMismatch,
    TraceSizeOverflow,
};

pub fn OwnedTrace(comptime main_column_count: usize) type {
    return struct {
        const Self = @This();
        pub const MainRow = [main_column_count]M31;

        allocator: std.mem.Allocator,
        preprocessed_storage: []M31,
        main_storage: []M31,
        log_size: u32,
        logical_rows: u32,

        pub fn init(allocator: std.mem.Allocator, logical_rows: usize) !Self {
            const log_size = try traceLogSize(logical_rows);
            if (logical_rows > std.math.maxInt(u32))
                return error.TraceSizeOverflow;
            const domain_size = @as(usize, 1) << @intCast(log_size);
            const preprocessed_cells = std.math.mul(
                usize,
                preprocessed_column_count,
                domain_size,
            ) catch return error.TraceSizeOverflow;
            const main_cells = std.math.mul(
                usize,
                main_column_count,
                domain_size,
            ) catch return error.TraceSizeOverflow;
            _ = std.math.mul(usize, preprocessed_cells, @sizeOf(M31)) catch
                return error.TraceSizeOverflow;
            _ = std.math.mul(usize, main_cells, @sizeOf(M31)) catch
                return error.TraceSizeOverflow;

            const preprocessed = try allocator.alloc(M31, preprocessed_cells);
            errdefer allocator.free(preprocessed);
            const main = try allocator.alloc(M31, main_cells);
            errdefer allocator.free(main);
            @memset(preprocessed, M31.zero());
            @memset(main, M31.zero());

            const first = committedRow(0, log_size);
            const last = committedRow(domain_size - 1, log_size);
            preprocessed[domain_first_column * domain_size + first] = M31.one();
            preprocessed[domain_last_column * domain_size + last] = M31.one();
            for (0..logical_rows) |logical| {
                preprocessed[
                    active_prefix_column * domain_size + committedRow(logical, log_size)
                ] = M31.one();
            }

            return .{
                .allocator = allocator,
                .preprocessed_storage = preprocessed,
                .main_storage = main,
                .log_size = log_size,
                .logical_rows = @intCast(logical_rows),
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.main_storage);
            self.allocator.free(self.preprocessed_storage);
            self.* = undefined;
        }

        pub fn domainSize(self: *const Self) usize {
            return @as(usize, 1) << @intCast(self.log_size);
        }

        pub fn preprocessedColumn(self: *const Self, column: usize) []const M31 {
            std.debug.assert(column < preprocessed_column_count);
            const size = self.domainSize();
            return self.preprocessed_storage[column * size ..][0..size];
        }

        pub fn mainColumn(self: *const Self, column: usize) []const M31 {
            std.debug.assert(column < main_column_count);
            const size = self.domainSize();
            return self.main_storage[column * size ..][0..size];
        }

        pub fn mainRow(self: *const Self, logical_row: usize) MainRow {
            std.debug.assert(logical_row < self.domainSize());
            var result: MainRow = undefined;
            const physical = committedRow(logical_row, self.log_size);
            for (&result, 0..) |*value, column| {
                value.* = self.main_storage[column * self.domainSize() + physical];
            }
            return result;
        }

        fn writeMainRow(self: *Self, logical_row: usize, row: MainRow) void {
            std.debug.assert(logical_row < self.logical_rows);
            const size = self.domainSize();
            const physical = committedRow(logical_row, self.log_size);
            for (row, 0..) |value, column| {
                self.main_storage[column * size + physical] = value;
            }
        }

        fn validateStructure(self: *const Self) !void {
            if (self.log_size > maximum_log_size or
                self.log_size != try traceLogSize(self.logical_rows))
            {
                return error.TraceShapeMismatch;
            }
            const size = self.domainSize();
            const expected_preprocessed = std.math.mul(
                usize,
                preprocessed_column_count,
                size,
            ) catch return error.TraceShapeMismatch;
            const expected_main = std.math.mul(
                usize,
                main_column_count,
                size,
            ) catch return error.TraceShapeMismatch;
            if (self.preprocessed_storage.len != expected_preprocessed or
                self.main_storage.len != expected_main or
                self.logical_rows > size)
            {
                return error.TraceShapeMismatch;
            }

            for (0..size) |logical| {
                const physical = committedRow(logical, self.log_size);
                const expected_first = logical == 0;
                const expected_last = logical + 1 == size;
                const expected_active = logical < self.logical_rows;
                if (!self.preprocessedColumn(domain_first_column)[physical].eql(
                    feltBool(expected_first),
                ) or !self.preprocessedColumn(domain_last_column)[physical].eql(
                    feltBool(expected_last),
                ) or !self.preprocessedColumn(active_prefix_column)[physical].eql(
                    feltBool(expected_active),
                )) return error.TraceContentMismatch;

                if (expected_active) continue;
                for (0..main_column_count) |column| {
                    if (!self.mainColumn(column)[physical].isZero())
                        return error.TraceContentMismatch;
                }
            }
        }
    };
}

pub const CallerTrace = OwnedTrace(caller.main_column_count);
pub const WordTrace = OwnedTrace(words.main_column_count);

pub const Bundle = struct {
    caller: CallerTrace,
    words: WordTrace,

    pub fn deinit(self: *Bundle) void {
        self.words.deinit();
        self.caller.deinit();
        self.* = undefined;
    }

    /// Cold reconstruction rejects any custody, ordering, selector, active-row,
    /// or padding drift without relying on the producer that filled the trace.
    pub fn validateAgainst(self: *const Bundle, tape: *const session.Frozen) !void {
        try tape.validate();
        try validateProofFacingTape(tape);
        try self.caller.validateStructure();
        try self.words.validateStructure();
        if (self.caller.logical_rows != tape.records().len or
            self.words.logical_rows != tape.wordRows().len)
        {
            return error.TraceShapeMismatch;
        }
        for (tape.records(), 0..) |record, logical| {
            const expected = (try caller.materialize(record.caller)).encode();
            if (!std.meta.eql(expected, self.caller.mainRow(logical)))
                return error.TraceContentMismatch;
        }
        for (tape.wordRows(), 0..) |row, logical| {
            if (!std.meta.eql(row.encode(), self.words.mainRow(logical)))
                return error.TraceContentMismatch;
        }
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    tape: *const session.Frozen,
) !Bundle {
    // Finish all semantic checks before allocating proof-facing storage. This
    // also protects candidate Row.encode from noncanonical/cold-mutated PCs.
    try tape.validate();
    try validateProofFacingTape(tape);

    var caller_trace = try CallerTrace.init(allocator, tape.records().len);
    errdefer caller_trace.deinit();
    var word_trace = try WordTrace.init(allocator, tape.wordRows().len);
    errdefer word_trace.deinit();

    for (tape.records(), 0..) |record, logical| {
        caller_trace.writeMainRow(
            logical,
            (try caller.materialize(record.caller)).encode(),
        );
    }
    for (tape.wordRows(), 0..) |row, logical| {
        word_trace.writeMainRow(logical, row.encode());
    }
    return .{ .caller = caller_trace, .words = word_trace };
}

fn validateProofFacingTape(tape: *const session.Frozen) !void {
    var previous_clock: ?u32 = null;
    for (tape.records()) |record| {
        isa_profile.requireProgramWordAddress(record.caller.pc) catch
            return error.InvalidProgramCounter;
        if (previous_clock) |clock| {
            if (record.caller.execution_clock <= clock)
                return error.InvalidExecutionOrder;
        }
        previous_clock = record.caller.execution_clock;
    }
}

fn traceLogSize(logical_rows: usize) !u32 {
    const row_count = @max(@as(usize, 1), logical_rows);
    const log_size: u32 = @max(
        minimum_log_size,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, row_count))),
    );
    if (log_size > maximum_log_size) return error.TraceLogTooLarge;
    return log_size;
}

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

fn feltBool(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

comptime {
    if (caller.production_active or words.production_active or
        caller.main_column_count != 99 or words.main_column_count != 37 or
        preprocessed_column_count != 3)
    {
        @compileError("bulk memcpy candidate trace geometry drifted");
    }
}
