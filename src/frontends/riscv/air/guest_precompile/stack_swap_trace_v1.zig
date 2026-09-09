//! Proof-facing traces for the nonproduction atomic-U256-swap candidate.
//!
//! Three current-point canonical columns suffice for both components.  Word
//! traces are strictly padded, so no live edge wraps the circle domain and no
//! shifted preprocessed sample is required by the OODS evaluator.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const circle = stwo_core.circle;
const core_utils = stwo_core.utils;
const isa_profile = @import("../../isa/profile.zig");
const caller = @import("stack_swap_caller_candidate_v1.zig");
const words = @import("stack_swap_word_candidate_v1.zig");
const session = @import("../../runner/guest_precompile/stack_swap_session_tape_v1.zig");

pub const preprocessed_column_count: usize = 3;
pub const domain_first_column: usize = 0;
pub const active_prefix_column: usize = 1;
pub const lane_last_column: usize = 2;
pub const minimum_caller_log_size: u32 = 1;
pub const minimum_word_log_size: u32 = 3;
pub const maximum_log_size: u32 = circle.M31_CIRCLE_LOG_ORDER - 2;

pub const Error = error{
    InvalidExecutionOrder,
    InvalidProgramCounter,
    TraceContentMismatch,
    TraceLogTooLarge,
    TraceShapeMismatch,
    TraceSizeOverflow,
};

pub fn OwnedTrace(
    comptime main_column_count: usize,
    comptime minimum_log_size: u32,
    comptime strictly_padded: bool,
) type {
    return struct {
        const Self = @This();
        pub const MainRow = [main_column_count]M31;

        allocator: std.mem.Allocator,
        preprocessed_storage: []M31,
        main_storage: []M31,
        log_size: u32,
        logical_rows: u32,

        pub fn init(allocator: std.mem.Allocator, logical_rows: usize) !Self {
            const log_size = try traceLogSize(
                logical_rows,
                minimum_log_size,
                strictly_padded,
            );
            if (logical_rows > std.math.maxInt(u32))
                return error.TraceSizeOverflow;
            const size = @as(usize, 1) << @intCast(log_size);
            const pp_cells = std.math.mul(
                usize,
                preprocessed_column_count,
                size,
            ) catch return error.TraceSizeOverflow;
            const main_cells = std.math.mul(
                usize,
                main_column_count,
                size,
            ) catch return error.TraceSizeOverflow;
            const pp = try allocator.alloc(M31, pp_cells);
            errdefer allocator.free(pp);
            const main = try allocator.alloc(M31, main_cells);
            errdefer allocator.free(main);
            @memset(pp, M31.zero());
            @memset(main, M31.zero());

            pp[domain_first_column * size + committedRow(0, log_size)] =
                M31.one();
            for (0..size) |logical| {
                const physical = committedRow(logical, log_size);
                if (logical < logical_rows)
                    pp[active_prefix_column * size + physical] = M31.one();
                if (logical % words.lane_count == words.lane_count - 1)
                    pp[lane_last_column * size + physical] = M31.one();
            }
            return .{
                .allocator = allocator,
                .preprocessed_storage = pp,
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

        pub fn preprocessedAt(self: *const Self, column: usize, logical: usize) M31 {
            return self.preprocessedColumn(column)[committedRow(logical, self.log_size)];
        }

        pub fn mainColumn(self: *const Self, column: usize) []const M31 {
            std.debug.assert(column < main_column_count);
            const size = self.domainSize();
            return self.main_storage[column * size ..][0..size];
        }

        pub fn mainRow(self: *const Self, logical: usize) MainRow {
            std.debug.assert(logical < self.domainSize());
            var result: MainRow = undefined;
            const physical = committedRow(logical, self.log_size);
            for (&result, 0..) |*value, column|
                value.* = self.main_storage[column * self.domainSize() + physical];
            return result;
        }

        fn writeMainRow(self: *Self, logical: usize, row: MainRow) void {
            std.debug.assert(logical < self.logical_rows);
            const size = self.domainSize();
            const physical = committedRow(logical, self.log_size);
            for (row, 0..) |value, column|
                self.main_storage[column * size + physical] = value;
        }

        fn validateStructure(self: *const Self) !void {
            if (self.log_size != try traceLogSize(
                self.logical_rows,
                minimum_log_size,
                strictly_padded,
            )) return error.TraceShapeMismatch;
            const size = self.domainSize();
            if (self.preprocessed_storage.len != preprocessed_column_count * size or
                self.main_storage.len != main_column_count * size or
                self.logical_rows > size)
            {
                return error.TraceShapeMismatch;
            }
            for (0..size) |logical| {
                const physical = committedRow(logical, self.log_size);
                if (!self.preprocessedColumn(domain_first_column)[physical].eql(
                    feltBool(logical == 0),
                ) or !self.preprocessedColumn(active_prefix_column)[physical].eql(
                    feltBool(logical < self.logical_rows),
                ) or !self.preprocessedColumn(lane_last_column)[physical].eql(
                    feltBool(logical % words.lane_count == words.lane_count - 1),
                )) return error.TraceContentMismatch;
                if (logical < self.logical_rows) continue;
                for (0..main_column_count) |column|
                    if (!self.mainColumn(column)[physical].isZero())
                        return error.TraceContentMismatch;
            }
        }
    };
}

pub const CallerTrace = OwnedTrace(
    caller.main_column_count,
    minimum_caller_log_size,
    false,
);
pub const WordTrace = OwnedTrace(
    words.main_column_count,
    minimum_word_log_size,
    true,
);

pub const Bundle = struct {
    caller: CallerTrace,
    words: WordTrace,

    pub fn deinit(self: *Bundle) void {
        self.words.deinit();
        self.caller.deinit();
        self.* = undefined;
    }

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
        for (tape.wordRows(), 0..) |row, logical|
            if (!std.meta.eql(row.encode(), self.words.mainRow(logical)))
                return error.TraceContentMismatch;
    }
};

pub fn generate(allocator: std.mem.Allocator, tape: *const session.Frozen) !Bundle {
    try tape.validate();
    try validateProofFacingTape(tape);
    var caller_trace = try CallerTrace.init(allocator, tape.records().len);
    errdefer caller_trace.deinit();
    var word_trace = try WordTrace.init(allocator, tape.wordRows().len);
    errdefer word_trace.deinit();
    for (tape.records(), 0..) |record, logical|
        caller_trace.writeMainRow(
            logical,
            (try caller.materialize(record.caller)).encode(),
        );
    for (tape.wordRows(), 0..) |row, logical|
        word_trace.writeMainRow(logical, row.encode());
    return .{ .caller = caller_trace, .words = word_trace };
}

fn validateProofFacingTape(tape: *const session.Frozen) !void {
    if (tape.wordRows().len != tape.records().len * words.lane_count)
        return error.TraceShapeMismatch;
    var previous_clock: ?u32 = null;
    for (tape.records()) |record| {
        isa_profile.requireProgramWordAddress(record.caller.pc) catch
            return error.InvalidProgramCounter;
        if (previous_clock) |clock| if (record.caller.execution_clock <= clock)
            return error.InvalidExecutionOrder;
        previous_clock = record.caller.execution_clock;
    }
}

fn traceLogSize(logical_rows: usize, minimum: u32, strictly_padded: bool) !u32 {
    var log_size: u32 = @max(
        minimum,
        @as(u32, @intCast(std.math.log2_int_ceil(
            usize,
            @max(@as(usize, 1), logical_rows),
        ))),
    );
    if (strictly_padded and logical_rows != 0 and
        logical_rows == @as(usize, 1) << @intCast(log_size))
    {
        log_size = std.math.add(u32, log_size, 1) catch
            return error.TraceLogTooLarge;
    }
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
        preprocessed_column_count != 3 or caller.main_column_count != 37 or
        words.main_column_count != 16 or minimum_word_log_size != 3)
    {
        @compileError("stack-swap proof trace geometry drifted");
    }
}
