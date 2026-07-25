//! One authenticated fixed-table materialization launch.

const std = @import("std");
const abi = @import("../../../abi/stages/cairo_base.zig");
const common = @import("../common.zig");
const layout = @import("../resident_layout.zig");
const runtime_error = @import("../../error.zig");
const telemetry = @import("../../telemetry.zig");

const pointer_words = @sizeOf(u64) / @sizeOf(u32);
const descriptor_words = 4;

pub const Native = OpsFor(abi);

pub const Geometry = struct {
    source_column_count: u32,
    multiplicity_column_count: u32,
    trace_output_count: u32,
    lookup_output_count: u32,
    row_count: u32,

    pub fn validate(self: Geometry) runtime_error.Error!void {
        if (self.multiplicity_column_count == 0 or
            self.trace_output_count == 0 or
            self.lookup_output_count == 0 or
            self.row_count < 16 or
            !std.math.isPowerOfTwo(self.row_count))
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

pub const Buffers = struct {
    source_pointer_table: common.Words,
    multiplicity_pointer_table: common.Words,
    trace_multiplicity_columns: common.Words,
    trace_output_pointer_table: common.Words,
    lookup_descriptors: common.Words,
    lookup_output_pointer_table: common.Words,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn materialize(
            session: anytype,
            geometry: Geometry,
            buffers: Buffers,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            try validateLengths(geometry, buffers);

            const sources = optionalPointerTable(
                session,
                buffers.source_pointer_table,
                geometry.source_column_count,
            ) catch |err| {
                printFailure("source-pointers", err);
                return err;
            };
            const multiplicities = pointerTable(
                session,
                buffers.multiplicity_pointer_table,
                geometry.multiplicity_column_count,
            ) catch |err| {
                printFailure("multiplicity-pointers", err);
                return err;
            };
            const trace_columns = layout.resident(
                session,
                u32,
                buffers.trace_multiplicity_columns,
                geometry.trace_output_count,
            ) catch |err| {
                printFailure("trace-multiplicities", err);
                return err;
            };
            const trace_outputs = pointerTable(
                session,
                buffers.trace_output_pointer_table,
                geometry.trace_output_count,
            ) catch |err| {
                printFailure("trace-output-pointers", err);
                return err;
            };
            const descriptors = layout.resident(
                session,
                u32,
                buffers.lookup_descriptors,
                @as(usize, geometry.lookup_output_count) *
                    descriptor_words,
            ) catch |err| {
                printFailure("lookup-descriptors", err);
                return err;
            };
            const lookup_outputs = pointerTable(
                session,
                buffers.lookup_output_pointer_table,
                geometry.lookup_output_count,
            ) catch |err| {
                printFailure("lookup-output-pointers", err);
                return err;
            };

            var immutable = [_]layout.DeviceRange{
                multiplicities.range,
                trace_columns.range,
                trace_outputs.range,
                descriptors.range,
                lookup_outputs.range,
                undefined,
            };
            var immutable_count: usize = 5;
            if (sources) |source| {
                immutable[immutable_count] = source.range;
                immutable_count += 1;
            }
            try layout.requireDisjoint(
                immutable[0..immutable_count],
                &.{},
            );

            const status = Api.stwo_fixed_table_materialize_on(
                if (sources) |source| source.pointer else null,
                multiplicities.pointer,
                trace_columns.pointer,
                trace_outputs.pointer,
                geometry.trace_output_count,
                descriptors.pointer,
                lookup_outputs.pointer,
                geometry.lookup_output_count,
                geometry.row_count,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn printFailure(label: []const u8, err: anyerror) void {
    std.debug.print(
        "cairo-cuda fixed buffer {s} failed: {s}\n",
        .{ label, @errorName(err) },
    );
}

fn validateLengths(
    geometry: Geometry,
    buffers: Buffers,
) runtime_error.Error!void {
    if (buffers.source_pointer_table.len !=
        tableWords(geometry.source_column_count) or
        buffers.multiplicity_pointer_table.len !=
            tableWords(geometry.multiplicity_column_count) or
        buffers.trace_multiplicity_columns.len !=
            geometry.trace_output_count or
        buffers.trace_output_pointer_table.len !=
            tableWords(geometry.trace_output_count) or
        buffers.lookup_descriptors.len !=
            @as(usize, geometry.lookup_output_count) * descriptor_words or
        buffers.lookup_output_pointer_table.len !=
            tableWords(geometry.lookup_output_count))
    {
        return error.InvalidKernelDescriptor;
    }
}

fn optionalPointerTable(
    session: anytype,
    words: common.Words,
    count: u32,
) runtime_error.Error!?layout.Resident(u64) {
    if (count == 0) {
        if (words.len != 0) return error.InvalidKernelDescriptor;
        return null;
    }
    return try pointerTable(session, words, count);
}

fn pointerTable(
    session: anytype,
    words: common.Words,
    count: u32,
) runtime_error.Error!layout.Resident(u64) {
    if (count == 0 or words.len != tableWords(count))
        return error.InvalidKernelDescriptor;
    const pointers = try words.cast(u64);
    return layout.resident(session, u64, pointers, count);
}

fn tableWords(count: u32) usize {
    return @as(usize, count) * pointer_words;
}
