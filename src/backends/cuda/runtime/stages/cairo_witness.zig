//! Resident construction of canonical CASM input columns.

const std = @import("std");
const abi = @import("../../abi/stages/cairo_witness.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub const Geometry = struct {
    real_rows: u32,
    consumer_rows: u32,
    include_iota: bool,

    pub fn validate(self: Geometry) runtime_error.Error!void {
        if (self.real_rows == 0 or self.real_rows > (@as(u32, 1) << 31))
            return error.InvalidKernelDescriptor;
        var expected: u32 = 16;
        while (expected < self.real_rows) {
            expected = std.math.mul(u32, expected, 2) catch
                return error.SizeOverflow;
        }
        if (self.consumer_rows != expected)
            return error.InvalidKernelDescriptor;
    }
};

pub const Columns = struct {
    pc: common.Words,
    ap: common.Words,
    fp: common.Words,
    enabler: common.Words,
    iota: common.Words,
};

pub const SeedGeometry = struct {
    real_rows: u32,
    consumer_rows: u32,
    include_enabler: bool,
    include_iota: bool,

    pub fn validate(self: SeedGeometry) runtime_error.Error!void {
        if (self.real_rows == 0 or
            self.real_rows > self.consumer_rows or
            self.consumer_rows == 0 or
            self.consumer_rows % 16 != 0)
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

pub const EdgeGeometry = struct {
    producer_rows: u32,
    word_base: u32,
    words_per_instance: u32,
    instance_count: u32,
    consumer_rows: u32,
    include_enabler: bool,
    include_iota: bool,

    pub fn realRows(self: EdgeGeometry) runtime_error.Error!u32 {
        const rows = std.math.mul(
            u64,
            self.producer_rows,
            self.instance_count,
        ) catch return error.SizeOverflow;
        if (rows > (@as(u64, 1) << 31)) return error.SizeOverflow;
        return @intCast(rows);
    }

    pub fn validate(self: EdgeGeometry) runtime_error.Error!void {
        if (self.producer_rows == 0 or self.producer_rows % 16 != 0 or
            self.words_per_instance == 0 or self.instance_count == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        const real_rows = try self.realRows();
        var expected: u32 = 16;
        while (expected < real_rows) {
            expected = std.math.mul(u32, expected, 2) catch
                return error.SizeOverflow;
        }
        if (self.consumer_rows != expected)
            return error.InvalidKernelDescriptor;
    }
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn scatter(
            session: anytype,
            geometry: Geometry,
            rows: common.Words,
            columns: Columns,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();

            const real_rows: usize = geometry.real_rows;
            const consumer_rows: usize = geometry.consumer_rows;
            const source_words = std.math.mul(usize, real_rows, 3) catch
                return error.SizeOverflow;
            if (rows.len != source_words or
                columns.pc.len != consumer_rows or
                columns.ap.len != consumer_rows or
                columns.fp.len != consumer_rows or
                columns.enabler.len != consumer_rows or
                (geometry.include_iota and columns.iota.len != consumer_rows) or
                (!geometry.include_iota and columns.iota.len != 0))
            {
                return error.InvalidKernelDescriptor;
            }

            const source = try layout.resident(
                session,
                u32,
                rows,
                source_words,
            );
            const pc = try layout.resident(
                session,
                u32,
                columns.pc,
                consumer_rows,
            );
            const ap = try layout.resident(
                session,
                u32,
                columns.ap,
                consumer_rows,
            );
            const fp = try layout.resident(
                session,
                u32,
                columns.fp,
                consumer_rows,
            );
            const enabler = try layout.resident(
                session,
                u32,
                columns.enabler,
                consumer_rows,
            );
            var write_ranges: [5]layout.DeviceRange = undefined;
            write_ranges[0] = pc.range;
            write_ranges[1] = ap.range;
            write_ranges[2] = fp.range;
            write_ranges[3] = enabler.range;
            var write_count: usize = 4;
            var iota_pointer: ?[*]u32 = null;
            if (geometry.include_iota) {
                const iota = try layout.resident(
                    session,
                    u32,
                    columns.iota,
                    consumer_rows,
                );
                write_ranges[4] = iota.range;
                write_count = 5;
                iota_pointer = iota.pointer;
            }
            try layout.requireDisjoint(
                write_ranges[0..write_count],
                &.{source.range},
            );

            const status = Api.stwo_witness_casm_input_scatter_on(
                source.pointer,
                geometry.real_rows,
                geometry.consumer_rows,
                pc.pointer,
                ap.pointer,
                fp.pointer,
                enabler.pointer,
                iota_pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn seed(
            session: anytype,
            geometry: SeedGeometry,
            scalars: common.Words,
            outputs: common.WordMatrix,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            if (scalars.len == 0) return error.InvalidKernelDescriptor;
            const scalar_count = try common.count(scalars.len);
            const output_columns = std.math.add(
                usize,
                scalars.len,
                @intFromBool(geometry.include_enabler),
            ) catch return error.SizeOverflow;
            const exact_columns = std.math.add(
                usize,
                output_columns,
                @intFromBool(geometry.include_iota),
            ) catch return error.SizeOverflow;
            const exact_capacity = std.math.mul(
                usize,
                outputs.column_stride_words,
                exact_columns,
            ) catch return error.SizeOverflow;
            if (outputs.column_stride_words < geometry.consumer_rows or
                outputs.storage.len != exact_capacity)
            {
                return error.InvalidKernelDescriptor;
            }

            const source = try layout.resident(
                session,
                u32,
                scalars,
                scalars.len,
            );
            const destination = try layout.wordMatrix(
                session,
                outputs,
                geometry.consumer_rows,
            );
            if (destination.column_count != try common.count(exact_columns))
                return error.InvalidKernelDescriptor;
            try layout.requireDisjoint(
                &.{destination.range},
                &.{source.range},
            );
            const status = Api.stwo_witness_input_seed_contiguous_on(
                source.pointer,
                scalar_count,
                geometry.real_rows,
                geometry.consumer_rows,
                destination.pointer,
                outputs.column_stride_words,
                outputs.storage.len,
                @intFromBool(geometry.include_enabler),
                @intFromBool(geometry.include_iota),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn gatherEdge(
            session: anytype,
            geometry: EdgeGeometry,
            producer: common.Words,
            outputs: common.WordMatrix,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            const instance_words = std.math.mul(
                usize,
                geometry.words_per_instance,
                geometry.instance_count,
            ) catch return error.SizeOverflow;
            const source_word_end = std.math.add(
                usize,
                geometry.word_base,
                instance_words,
            ) catch return error.SizeOverflow;
            const required_source_words = std.math.mul(
                usize,
                source_word_end,
                geometry.producer_rows,
            ) catch return error.SizeOverflow;
            if (producer.len < required_source_words)
                return error.InvalidKernelDescriptor;
            const output_columns = std.math.add(
                usize,
                geometry.words_per_instance,
                @intFromBool(geometry.include_enabler),
            ) catch return error.SizeOverflow;
            const exact_columns = std.math.add(
                usize,
                output_columns,
                @intFromBool(geometry.include_iota),
            ) catch return error.SizeOverflow;
            const exact_capacity = std.math.mul(
                usize,
                outputs.column_stride_words,
                exact_columns,
            ) catch return error.SizeOverflow;
            if (outputs.column_stride_words < geometry.consumer_rows or
                outputs.storage.len != exact_capacity)
            {
                return error.InvalidKernelDescriptor;
            }

            const source = try layout.resident(
                session,
                u32,
                producer,
                producer.len,
            );
            const destination = try layout.wordMatrix(
                session,
                outputs,
                geometry.consumer_rows,
            );
            if (destination.column_count != try common.count(exact_columns))
                return error.InvalidKernelDescriptor;
            try layout.requireDisjoint(
                &.{destination.range},
                &.{source.range},
            );
            const status = Api.stwo_witness_edge_gather_contiguous_on(
                source.pointer,
                producer.len,
                geometry.producer_rows,
                geometry.word_base,
                geometry.words_per_instance,
                geometry.instance_count,
                geometry.consumer_rows,
                destination.pointer,
                outputs.column_stride_words,
                outputs.storage.len,
                @intFromBool(geometry.include_enabler),
                @intFromBool(geometry.include_iota),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}
