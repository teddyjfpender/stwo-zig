//! Canonical resident compaction for Cairo multiset witness inputs.

const std = @import("std");
const abi = @import("../../abi/stages/cairo_witness.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

const pointer_words = @sizeOf(u64) / @sizeOf(u32);
const edge_descriptor_words: usize = 6;
const absent_slot = std.math.maxInt(u32);

pub const Native = OpsFor(abi);

pub const TempBytes = struct {
    sort: usize,
    scan: usize,

    pub fn sortWords(self: TempBytes) runtime_error.Error!usize {
        return bytesToWords(self.sort);
    }

    pub fn scanWords(self: TempBytes) runtime_error.Error!usize {
        return bytesToWords(self.scan);
    }
};

pub const Binding = struct {
    producer_pointer_table: common.Words,
    edge_descriptors: common.Words,
    edge_count: u32,
    tuple_words: u32,
    key_words: u32,
    total_rows: u32,
    sort_rows: u32,
    consumer_rows: u32,
    input_count: u32,
    consumer_pointer_table: common.Words,
    enabler_slot: ?u32,
    iota_slot: ?u32,
    multiplicity_slot: u32,
    tuples: common.Words,
    keys_a: common.Words,
    keys_b: common.Words,
    indices_a: common.Words,
    indices_b: common.Words,
    heads: common.Words,
    positions: common.Words,
    unique_count: common.Words,
    sort_temp: common.Words,
    sort_temp_bytes: usize,
    scan_temp: common.Words,
    scan_temp_bytes: usize,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn tempBytes(sort_rows: u32) runtime_error.Error!TempBytes {
            if (!isPowerOfTwo(sort_rows)) return error.InvalidKernelDescriptor;
            var result = TempBytes{ .sort = 0, .scan = 0 };
            try runtime_error.check(
                Api.stwo_witness_input_compact_sort_temp_bytes(
                    sort_rows,
                    &result.sort,
                ),
            );
            try runtime_error.check(
                Api.stwo_witness_input_compact_scan_temp_bytes(
                    sort_rows,
                    &result.scan,
                ),
            );
            if (result.sort == 0 or result.scan == 0)
                return error.InvalidKernelDescriptor;
            _ = try result.sortWords();
            _ = try result.scanWords();
            return result;
        }

        pub fn compact(
            session: anytype,
            binding: Binding,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try validateGeometry(binding);

            const producers = try pointerTable(
                session,
                binding.producer_pointer_table,
                binding.edge_count,
            );
            const descriptors = try exactWords(
                session,
                binding.edge_descriptors,
                try mul(binding.edge_count, edge_descriptor_words),
            );
            const consumers = try pointerTable(
                session,
                binding.consumer_pointer_table,
                binding.input_count,
            );
            const tuple_count = try mul(binding.sort_rows, binding.tuple_words);
            const tuples = try exactWords(session, binding.tuples, tuple_count);
            const keys_a = try exactWords(
                session,
                binding.keys_a,
                binding.sort_rows,
            );
            const keys_b = try exactWords(
                session,
                binding.keys_b,
                binding.sort_rows,
            );
            const indices_a = try exactWords(
                session,
                binding.indices_a,
                binding.sort_rows,
            );
            const indices_b = try exactWords(
                session,
                binding.indices_b,
                binding.sort_rows,
            );
            const heads = try exactWords(
                session,
                binding.heads,
                binding.sort_rows,
            );
            const positions = try exactWords(
                session,
                binding.positions,
                binding.sort_rows,
            );
            const unique_count = try exactWords(
                session,
                binding.unique_count,
                1,
            );
            const sort_temp = try byteWorkspace(
                session,
                binding.sort_temp,
                binding.sort_temp_bytes,
            );
            const scan_temp = try byteWorkspace(
                session,
                binding.scan_temp,
                binding.scan_temp_bytes,
            );

            const writes = [_]layout.DeviceRange{
                tuples.range,
                keys_a.range,
                keys_b.range,
                indices_a.range,
                indices_b.range,
                heads.range,
                positions.range,
                unique_count.range,
                sort_temp.range,
                scan_temp.range,
            };
            try layout.requireDisjoint(
                &writes,
                &.{ producers.range, descriptors.range, consumers.range },
            );

            const status = Api.stwo_witness_input_compact_v2_on(
                producers.pointer,
                descriptors.pointer,
                binding.edge_count,
                binding.tuple_words,
                binding.key_words,
                binding.total_rows,
                binding.sort_rows,
                binding.consumer_rows,
                binding.input_count,
                consumers.pointer,
                binding.enabler_slot orelse absent_slot,
                binding.iota_slot orelse absent_slot,
                binding.multiplicity_slot,
                tuples.pointer,
                keys_a.pointer,
                keys_b.pointer,
                indices_a.pointer,
                indices_b.pointer,
                heads.pointer,
                positions.pointer,
                @ptrCast(unique_count.pointer),
                @ptrCast(sort_temp.pointer),
                binding.sort_temp_bytes,
                @ptrCast(scan_temp.pointer),
                binding.scan_temp_bytes,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn validateGeometry(binding: Binding) runtime_error.Error!void {
    if (binding.edge_count == 0 or binding.tuple_words == 0 or
        binding.key_words == 0 or binding.key_words > binding.tuple_words or
        binding.total_rows == 0 or binding.total_rows > binding.sort_rows or
        !isPowerOfTwo(binding.sort_rows) or binding.consumer_rows < 16 or
        !isPowerOfTwo(binding.consumer_rows) or binding.input_count == 0 or
        binding.multiplicity_slot >= binding.input_count or
        binding.multiplicity_slot < binding.tuple_words or
        binding.sort_temp_bytes == 0 or binding.scan_temp_bytes == 0)
    {
        return error.InvalidKernelDescriptor;
    }
    var expected_inputs = std.math.add(
        u32,
        binding.tuple_words,
        1,
    ) catch return error.SizeOverflow;
    if (binding.enabler_slot) |slot| {
        if (slot != expected_inputs - 1) return error.InvalidKernelDescriptor;
        expected_inputs = std.math.add(
            u32,
            expected_inputs,
            1,
        ) catch return error.SizeOverflow;
    }
    if (binding.iota_slot) |slot| {
        if (slot != expected_inputs - 1) return error.InvalidKernelDescriptor;
        expected_inputs = std.math.add(
            u32,
            expected_inputs,
            1,
        ) catch return error.SizeOverflow;
    }
    if (binding.multiplicity_slot != expected_inputs - 1 or
        binding.input_count != expected_inputs)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn pointerTable(
    session: anytype,
    words: common.Words,
    count: u32,
) runtime_error.Error!layout.Resident(u64) {
    const required = try mul(count, pointer_words);
    if (words.len != required) return error.InvalidKernelDescriptor;
    return layout.resident(session, u64, try words.cast(u64), count);
}

fn exactWords(
    session: anytype,
    words: common.Words,
    count: anytype,
) runtime_error.Error!layout.Resident(u32) {
    const exact = std.math.cast(usize, count) orelse return error.SizeOverflow;
    if (words.len != exact) return error.InvalidKernelDescriptor;
    return layout.resident(session, u32, words, exact);
}

fn byteWorkspace(
    session: anytype,
    words: common.Words,
    bytes: usize,
) runtime_error.Error!layout.Resident(u32) {
    const required = try bytesToWords(bytes);
    return exactWords(session, words, required);
}

fn bytesToWords(bytes: usize) runtime_error.Error!usize {
    if (bytes == 0) return error.InvalidKernelDescriptor;
    const rounded = std.math.add(
        usize,
        bytes,
        @sizeOf(u32) - 1,
    ) catch return error.SizeOverflow;
    return rounded / @sizeOf(u32);
}

fn mul(left: anytype, right: anytype) runtime_error.Error!usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch return error.SizeOverflow;
}

fn isPowerOfTwo(value: u32) bool {
    return value != 0 and value & (value - 1) == 0;
}
