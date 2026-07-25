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
    };
}
