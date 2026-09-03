//! Owned call and word-row custody for the nonproduction bulk-memcpy profile.
//!
//! A call record owns the fixed-register caller witness and an exact contiguous
//! range in `word_rows`.  Freeze transfers both allocations without copying;
//! cold validation reconstructs every candidate row and rejects call-index,
//! range, byte, mask, and previous-clock mutations.

const std = @import("std");

const access_clock = @import("../../access_clock.zig");
const caller = @import("../../air/guest_precompile/bulk_memcpy_caller_candidate_v1.zig");
const words = @import("../../air/guest_precompile/bulk_memcpy_word_candidate_v1.zig");

pub const max_calls: usize = 0x7fff_fffe;
pub const max_word_rows: usize = 0x7fff_fffe;

pub const WordSpanIdentity = struct {
    first_word: u32,
    word_count: u32,
    end_word_exclusive: u32,
};

pub const AlignedSpanIdentity = struct {
    source: WordSpanIdentity,
    destination: WordSpanIdentity,

    pub fn validate(self: AlignedSpanIdentity) !void {
        const source_end = std.math.add(
            u32,
            self.source.first_word,
            self.source.word_count,
        ) catch return error.InvalidBulkMemcpyAlignedSpanIdentity;
        const destination_end = std.math.add(
            u32,
            self.destination.first_word,
            self.destination.word_count,
        ) catch return error.InvalidBulkMemcpyAlignedSpanIdentity;
        if (self.source.word_count == 0 or
            self.source.word_count != self.destination.word_count or
            self.source.end_word_exclusive != source_end or
            self.destination.end_word_exclusive != destination_end or
            !(self.source.end_word_exclusive <= self.destination.first_word or
                self.destination.end_word_exclusive <= self.source.first_word))
        {
            return error.InvalidBulkMemcpyAlignedSpanIdentity;
        }
    }
};

pub const Record = struct {
    caller: caller.Record,
    aligned_spans: AlignedSpanIdentity,
    first_word_row: u32,
    word_row_count: u32,

    pub fn validateAgainst(
        self: Record,
        expected_call_index: u32,
        expected_first_word_row: u32,
        rows: []const words.Row,
    ) !void {
        const call = self.caller.call();
        try validateRunnerCall(call);
        try self.caller.validate();
        const expected_spans = try alignedSpanIdentity(call);
        try self.aligned_spans.validate();
        if (self.caller.call_index != expected_call_index or
            !std.meta.eql(self.aligned_spans, expected_spans) or
            self.first_word_row != expected_first_word_row or
            self.word_row_count != call.expectedWordCount() or
            rows.len != @as(usize, self.word_row_count))
        {
            return error.InvalidBulkMemcpyCallBuffer;
        }
        const caller_row = try caller.materialize(self.caller);
        const memory_clock = access_clock.encode(call.execution_clock, .second);
        for (rows, 0..) |row, index| {
            if (row.source_previous_clock >= memory_clock or
                row.destination_previous_clock >= memory_clock)
            {
                return error.InvalidBulkMemcpyCallBuffer;
            }
            const word_index: u32 = @intCast(index);
            const expected = try words.materializeRow(call, word_index, .{
                .source_previous_clock = row.source_previous_clock,
                .destination_previous_clock = row.destination_previous_clock,
                .source_bytes = row.source_bytes,
                .destination_before = row.destination_before,
            });
            if (!std.meta.eql(row, expected))
                return error.InvalidBulkMemcpyCallBuffer;
        }
        if (!std.meta.eql(
            try caller_row.callTuple(),
            try rows[0].firstCallTuple(),
        )) return error.InvalidBulkMemcpyCallBuffer;
    }
};

/// Preserve an exact diagnostic classification for the aligned-word rule now
/// proved by the caller AIR. The candidate's public error remains deliberately
/// coarse, while runner telemetry needs to distinguish this measured subset.
pub fn validateRunnerCall(call: words.Call) !void {
    call.validate() catch |err| {
        if (byteCallIsAdmissible(call)) {
            const identity = alignedSpanIdentityUnchecked(call);
            identity.validate() catch
                return error.BulkMemcpyWordSpansOverlap;
        }
        return err;
    };
}

pub fn alignedSpanIdentity(call: words.Call) !AlignedSpanIdentity {
    try validateRunnerCall(call);
    const result = alignedSpanIdentityUnchecked(call);
    try result.validate();
    return result;
}

fn alignedSpanIdentityUnchecked(call: words.Call) AlignedSpanIdentity {
    const word_count = call.expectedWordCount();
    const source_first_word = call.source / @sizeOf(u32);
    const destination_first_word = call.destination / @sizeOf(u32);
    return .{
        .source = .{
            .first_word = source_first_word,
            .word_count = word_count,
            .end_word_exclusive = source_first_word + word_count,
        },
        .destination = .{
            .first_word = destination_first_word,
            .word_count = word_count,
            .end_word_exclusive = destination_first_word + word_count,
        },
    };
}

fn byteCallIsAdmissible(call: words.Call) bool {
    if (call.execution_clock == 0 or
        access_clock.maximum(call.execution_clock) > std.math.maxInt(u32) or
        call.length < words.minimum_admitted_length or
        (call.source ^ call.destination) & 3 != 0)
    {
        return false;
    }
    const source_end = std.math.add(u32, call.source, call.length) catch
        return false;
    const destination_end = std.math.add(
        u32,
        call.destination,
        call.length,
    ) catch return false;
    return source_end <= words.data_address_limit and
        destination_end <= words.data_address_limit and
        (source_end <= call.destination or destination_end <= call.source);
}

pub const ExactFraction = struct {
    numerator: u64,
    denominator: u64,
};

/// Opt-in diagnostic classification. This remains separate from the session
/// tape so a rejected instruction cannot mutate proof-custody state.
pub const AdmissionTelemetry = struct {
    observed: u64 = 0,
    admitted: u64 = 0,
    rejected_aligned_word_overlap: u64 = 0,
    rejected_other: u64 = 0,

    pub fn observe(self: *AdmissionTelemetry, call: words.Call) !void {
        self.observed = try std.math.add(u64, self.observed, 1);
        validateRunnerCall(call) catch |err| {
            switch (err) {
                error.BulkMemcpyWordSpansOverlap => {
                    self.rejected_aligned_word_overlap = try std.math.add(
                        u64,
                        self.rejected_aligned_word_overlap,
                        1,
                    );
                },
                else => {
                    self.rejected_other = try std.math.add(
                        u64,
                        self.rejected_other,
                        1,
                    );
                },
            }
            return;
        };
        self.admitted = try std.math.add(u64, self.admitted, 1);
    }

    /// Exact rejection ratio among calls that otherwise satisfy the byte-level
    /// V1 contract. A zero denominator is retained as 0/0.
    pub fn alignedWordRejectedFraction(self: AdmissionTelemetry) !ExactFraction {
        return .{
            .numerator = self.rejected_aligned_word_overlap,
            .denominator = try std.math.add(
                u64,
                self.admitted,
                self.rejected_aligned_word_overlap,
            ),
        };
    }

    pub fn validate(self: AdmissionTelemetry) !void {
        const classified = try std.math.add(
            u64,
            self.admitted,
            self.rejected_aligned_word_overlap,
        );
        const total = try std.math.add(u64, classified, self.rejected_other);
        if (total != self.observed)
            return error.InvalidBulkMemcpyAdmissionTelemetry;
    }
};

pub const Frozen = struct {
    calls: std.ArrayList(Record),
    word_rows: std.ArrayList(words.Row),
    allocator: std.mem.Allocator,
    allocation_growths: usize,

    pub fn records(self: *const Frozen) []const Record {
        return self.calls.items;
    }

    pub fn rows(self: *const Frozen) []const words.Row {
        return self.word_rows.items;
    }

    pub fn len(self: *const Frozen) usize {
        return self.calls.items.len;
    }

    pub fn wordLen(self: *const Frozen) usize {
        return self.word_rows.items.len;
    }

    pub fn validate(self: *const Frozen) !void {
        return validateRecordsAndRows(self.records(), self.rows());
    }

    pub fn deinit(self: *Frozen) void {
        self.calls.deinit(self.allocator);
        self.word_rows.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Builder = struct {
    calls: std.ArrayList(Record) = .empty,
    word_rows: std.ArrayList(words.Row) = .empty,
    allocator: std.mem.Allocator,
    call_limit: usize,
    word_row_limit: usize,
    allocation_growths: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        call_limit: usize,
        word_row_limit: usize,
    ) error{BulkMemcpyTapeLimitExceeded}!Builder {
        if (call_limit > max_calls or word_row_limit > max_word_rows)
            return error.BulkMemcpyTapeLimitExceeded;
        return .{
            .allocator = allocator,
            .call_limit = call_limit,
            .word_row_limit = word_row_limit,
        };
    }

    pub fn deinit(self: *Builder) void {
        self.calls.deinit(self.allocator);
        self.word_rows.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const Builder) usize {
        return self.calls.items.len;
    }

    pub fn wordLen(self: *const Builder) usize {
        return self.word_rows.items.len;
    }

    pub fn records(self: *const Builder) []const Record {
        return self.calls.items;
    }

    pub fn rows(self: *const Builder) []const words.Row {
        return self.word_rows.items;
    }

    /// Reserve both variable-length stores without changing their logical
    /// lengths. Capacity growth may remain after a later prepare-stage error.
    pub fn reserveOne(
        self: *Builder,
        word_row_count: usize,
    ) error{ OutOfMemory, BulkMemcpyTapeLimitExceeded }!void {
        if (word_row_count == 0 or self.calls.items.len >= self.call_limit or
            word_row_count > self.word_row_limit - self.word_rows.items.len)
        {
            return error.BulkMemcpyTapeLimitExceeded;
        }
        const old_call_capacity = self.calls.capacity;
        const old_word_capacity = self.word_rows.capacity;
        try self.calls.ensureUnusedCapacity(self.allocator, 1);
        try self.word_rows.ensureUnusedCapacity(self.allocator, word_row_count);
        if (self.calls.capacity != old_call_capacity) self.allocation_growths += 1;
        if (self.word_rows.capacity != old_word_capacity) self.allocation_growths += 1;
    }

    pub fn appendAssumeCapacity(
        self: *Builder,
        record: caller.Record,
        word_rows: []const words.Row,
    ) void {
        const call_index: u32 = @intCast(self.calls.items.len);
        const first_word_row: u32 = @intCast(self.word_rows.items.len);
        const owned = Record{
            .caller = record,
            .aligned_spans = alignedSpanIdentity(record.call()) catch unreachable,
            .first_word_row = first_word_row,
            .word_row_count = @intCast(word_rows.len),
        };
        std.debug.assert(self.calls.items.len < self.call_limit);
        std.debug.assert(word_rows.len <= self.word_row_limit - self.word_rows.items.len);
        owned.validateAgainst(call_index, first_word_row, word_rows) catch unreachable;
        self.calls.appendAssumeCapacity(owned);
        self.word_rows.appendSliceAssumeCapacity(word_rows);
    }

    pub fn validate(self: *const Builder) !void {
        return validateRecordsAndRows(self.records(), self.rows());
    }

    pub fn freeze(self: *Builder) Frozen {
        const result = Frozen{
            .calls = self.calls,
            .word_rows = self.word_rows,
            .allocator = self.allocator,
            .allocation_growths = self.allocation_growths,
        };
        self.calls = .empty;
        self.word_rows = .empty;
        self.call_limit = 0;
        self.word_row_limit = 0;
        self.allocation_growths = 0;
        return result;
    }
};

pub fn validateRecordsAndRows(
    records: []const Record,
    rows: []const words.Row,
) !void {
    var cursor: usize = 0;
    for (records, 0..) |record, call_index| {
        const count: usize = record.word_row_count;
        const end = std.math.add(usize, cursor, count) catch
            return error.InvalidBulkMemcpyCallBuffer;
        if (end > rows.len)
            return error.InvalidBulkMemcpyCallBuffer;
        try record.validateAgainst(
            @intCast(call_index),
            @intCast(cursor),
            rows[cursor..end],
        );
        cursor = end;
    }
    if (cursor != rows.len) return error.InvalidBulkMemcpyCallBuffer;
}
