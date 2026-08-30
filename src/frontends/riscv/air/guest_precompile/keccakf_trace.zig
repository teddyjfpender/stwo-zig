//! Bounded, committed-order main trace for the paired Keccak-f component.
//!
//! A shard holds at most one log-16 domain (roughly 504 MiB at the maximum
//! width).  Larger call sets use multiple components while sharing one global
//! lookup multiplicity authority.  This keeps allocation explicit and avoids
//! a monolithic multi-gigabyte witness.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const call_buffer = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const authority = @import("keccakf_authority.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const relations = @import("keccakf_relations.zig");
const witness = @import("keccakf_witness.zig");

pub const minimum_log_size: u32 = 5;
pub const maximum_log_size: u32 = 16;
pub const maximum_slots_per_shard: usize =
    (@as(usize, 1) << maximum_log_size) / witness.row_count;
pub const maximum_calls_per_shard: usize =
    maximum_slots_per_shard * authority.candidate.operations_per_slot;

pub const Layout = struct {
    pub const in_use_a: usize = 0;
    pub const in_use_b: usize = 1;
    pub const io_a: usize = 2;
    pub const io_b: usize = io_a + relations.io_arity;
    pub const state: usize = io_b + relations.io_arity;
    pub const parity: usize = state + witness.state_cell_count;
    pub const main_columns: usize = parity + witness.parity_cell_count;

    pub const is_first: usize = 0;
    pub const row_group: usize = 1;
    pub const second_active: usize = row_group + witness.row_count;
    pub const preprocessed_columns: usize = second_active + 1;
};

pub const Error = counters_mod.Error || relations.Error || error{
    CallIndexOutOfRange,
    CallRangeTooLarge,
    EmptyShard,
    OutputMismatch,
    TraceSizeOverflow,
};

pub const Shard = struct {
    allocator: std.mem.Allocator,
    preprocessed_storage: []M31,
    main_storage: []M31,
    log_size: u32,
    n_rows: u32,
    first_call_index: u32,
    call_count: u32,

    pub fn deinit(self: *Shard) void {
        self.allocator.free(self.main_storage);
        self.allocator.free(self.preprocessed_storage);
        self.* = undefined;
    }

    pub fn domainSize(self: *const Shard) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }

    pub fn preprocessedColumn(self: *const Shard, index: usize) []const M31 {
        std.debug.assert(index < Layout.preprocessed_columns);
        const size = self.domainSize();
        return self.preprocessed_storage[index * size ..][0..size];
    }

    pub fn mainColumn(self: *const Shard, index: usize) []const M31 {
        std.debug.assert(index < Layout.main_columns);
        const size = self.domainSize();
        return self.main_storage[index * size ..][0..size];
    }

    pub fn mainAt(self: *const Shard, column: usize, logical_row: usize) M31 {
        return self.mainColumn(column)[committedRow(logical_row, self.log_size)];
    }
};

pub fn generateShard(
    allocator: std.mem.Allocator,
    records: []const call_buffer.Record,
    first_call_index: usize,
    counters: *counters_mod.Counters,
) Error!Shard {
    if (records.len == 0) return error.EmptyShard;
    if (records.len > maximum_calls_per_shard) return error.CallRangeTooLarge;
    const call_end = std.math.add(usize, first_call_index, records.len) catch
        return error.CallIndexOutOfRange;
    if (call_end > authority.candidate.maximum_calls)
        return error.CallIndexOutOfRange;
    const slot_count = std.math.divCeil(
        usize,
        records.len,
        authority.candidate.operations_per_slot,
    ) catch unreachable;
    const n_rows = std.math.mul(usize, slot_count, witness.row_count) catch
        return error.TraceSizeOverflow;
    const log_size: u32 = @max(
        minimum_log_size,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, n_rows))),
    );
    if (log_size > maximum_log_size) return error.CallRangeTooLarge;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    const preprocessed_cells = std.math.mul(
        usize,
        Layout.preprocessed_columns,
        domain_size,
    ) catch return error.TraceSizeOverflow;
    const main_cells = std.math.mul(
        usize,
        Layout.main_columns,
        domain_size,
    ) catch return error.TraceSizeOverflow;
    _ = std.math.mul(usize, main_cells, @sizeOf(M31)) catch
        return error.TraceSizeOverflow;

    const preprocessed = try allocator.alloc(M31, preprocessed_cells);
    errdefer allocator.free(preprocessed);
    const main = try allocator.alloc(M31, main_cells);
    errdefer allocator.free(main);
    @memset(preprocessed, M31.zero());
    @memset(main, M31.zero());

    var result = Shard{
        .allocator = allocator,
        .preprocessed_storage = preprocessed,
        .main_storage = main,
        .log_size = log_size,
        .n_rows = @intCast(n_rows),
        .first_call_index = @intCast(first_call_index),
        .call_count = @intCast(records.len),
    };
    result.preprocessed_storage[committedRow(0, log_size)] = M31.one();

    for (0..slot_count) |slot_index| {
        const first_record = &records[2 * slot_index];
        const second_record = if (2 * slot_index + 1 < records.len)
            &records[2 * slot_index + 1]
        else
            null;
        const input_a = stateFromWords(first_record.input);
        const output_a = stateFromWords(first_record.output);
        const input_b = if (second_record) |record| stateFromWords(record.input) else null;
        const output_b = if (second_record) |record| stateFromWords(record.output) else null;
        var slot = try witness.buildSlot(input_a, input_b);
        if (!std.mem.eql(u64, &output_a, &stateFromBoundary(&slot.rows[27].state))) {
            return error.OutputMismatch;
        }
        if (second_record != null) {
            if (!std.mem.eql(u64, &output_b.?, &stateFromBoundary(&slot.rows[28].state))) {
                return error.OutputMismatch;
            }
        }
        try counters.recordSlot(&slot);
        writeSlot(
            &result,
            slot_index,
            try relations.ioTuple(
                first_call_index + 2 * slot_index,
                input_a,
                output_a,
            ),
            if (input_b) |second_input| try relations.ioTuple(
                first_call_index + 2 * slot_index + 1,
                second_input,
                output_b.?,
            ) else null,
            &slot,
        );
    }
    return result;
}

fn writeSlot(
    shard: *Shard,
    slot_index: usize,
    io_a: relations.IoTuple,
    io_b: ?relations.IoTuple,
    slot: *const witness.Slot,
) void {
    const size = shard.domainSize();
    for (slot.rows, 0..) |row, group| {
        const logical_row = slot_index * witness.row_count + group;
        const destination = committedRow(logical_row, shard.log_size);
        shard.preprocessed_storage[
            (Layout.row_group + group) * size + destination
        ] = M31.one();
        if (row.in_use_b != 0) shard.preprocessed_storage[
            Layout.second_active * size + destination
        ] = M31.one();

        shard.main_storage[Layout.in_use_a * size + destination] =
            M31.fromCanonical(row.in_use_a);
        shard.main_storage[Layout.in_use_b * size + destination] =
            M31.fromCanonical(row.in_use_b);
        for (io_a, 0..) |value, field| shard.main_storage[
            (Layout.io_a + field) * size + destination
        ] = value;
        if (io_b) |tuple| {
            for (tuple, 0..) |value, field| shard.main_storage[
                (Layout.io_b + field) * size + destination
            ] = value;
        }
        for (row.state, 0..) |value, cell| shard.main_storage[
            (Layout.state + cell) * size + destination
        ] = M31.fromCanonical(value);
        for (row.parity, 0..) |value, cell| shard.main_storage[
            (Layout.parity + cell) * size + destination
        ] = M31.fromCanonical(value);
    }
}

pub fn stateFromWords(words: [call_buffer.word_count]u32) authority.State {
    var result: authority.State = undefined;
    for (&result, 0..) |*lane, index| lane.* =
        words[2 * index] | (@as(u64, words[2 * index + 1]) << 32);
    return result;
}

fn stateFromBoundary(bits: *const [witness.state_cell_count]u8) authority.State {
    var result: authority.State = @splat(0);
    for (0..authority.lane_count) |lane| for (0..authority.lane_bits) |z| {
        result[lane] |= @as(u64, bits[lane * authority.lane_bits + z]) << @intCast(z);
    };
    return result;
}

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return @import("stwo_core").utils.bitReverseIndex(
        @import("stwo_core").utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

comptime {
    if (Layout.main_columns != 2140 or Layout.preprocessed_columns != 31 or
        maximum_slots_per_shard != 2259 or maximum_calls_per_shard != 4518)
    {
        @compileError("Keccak-f shard geometry drifted");
    }
}
