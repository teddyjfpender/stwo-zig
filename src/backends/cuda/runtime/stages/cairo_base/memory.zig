//! Allocation-free resident construction of Cairo memory base tables.

const std = @import("std");
const abi = @import("../../../abi/stages/cairo_base.zig");
const common = @import("../common.zig");
const layout = @import("../resident_layout.zig");
const runtime_error = @import("../../error.zig");
const telemetry = @import("../../telemetry.zig");

pub const Native = OpsFor(abi);

pub const big_limb_count: usize = 28;
pub const small_limb_count: usize = 8;
pub const address_column_count: usize = 32;
pub const range_check_pair_columns: usize = 8;
pub const range_check_table_rows: usize = 1 << 18;

pub const SplitGeometry = struct {
    kind: enum { big, small },
    value_count: u32,
    row_count: u32,

    pub fn limbCount(self: SplitGeometry) usize {
        return switch (self.kind) {
            .big => big_limb_count,
            .small => small_limb_count,
        };
    }

    pub fn wordsPerValue(self: SplitGeometry) usize {
        return switch (self.kind) {
            .big => 8,
            .small => 4,
        };
    }

    pub fn validate(self: SplitGeometry) runtime_error.Error!void {
        if (self.row_count < 16 or !std.math.isPowerOfTwo(self.row_count) or
            self.value_count > self.row_count)
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

pub const SplitBuffers = struct {
    values: common.Words,
    outputs: []const common.Words,
};

pub const AddressGeometry = struct {
    address_id_words: u32,
    row_count: u32,

    pub fn multiplicityWords(self: AddressGeometry) runtime_error.Error!usize {
        return std.math.mul(usize, self.row_count, 16) catch
            return error.SizeOverflow;
    }

    pub fn validate(self: AddressGeometry) runtime_error.Error!void {
        if (self.row_count < 16 or !std.math.isPowerOfTwo(self.row_count) or
            self.address_id_words == 0 or
            self.address_id_words > try self.multiplicityWords())
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

pub const AddressBuffers = struct {
    address_ids: common.Words,
    multiplicities: common.Words,
    outputs: []const common.Words,
};

pub const ValueGeometry = struct {
    limb_count: u32,
    source_words: u32,
    row_count: u32,

    pub fn validate(self: ValueGeometry) runtime_error.Error!void {
        if (self.row_count < 16 or !std.math.isPowerOfTwo(self.row_count) or
            (self.limb_count != big_limb_count and
                self.limb_count != small_limb_count) or
            self.source_words == 0 or self.source_words > self.row_count)
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

pub const ValueBuffers = struct {
    sources: []const common.Words,
    multiplicities: common.Words,
    outputs: []const common.Words,
};

pub const RangeCheckGeometry = struct {
    pair_count: u32,
    row_count: u32,

    pub fn validate(self: RangeCheckGeometry) runtime_error.Error!void {
        if (self.row_count < 16 or !std.math.isPowerOfTwo(self.row_count) or
            self.pair_count == 0 or self.pair_count > big_limb_count / 2)
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

pub const RangeCheckBuffers = struct {
    limbs: []const common.Words,
    input_to_row: common.Words,
    counts: common.Words,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn split(
            session: anytype,
            geometry: SplitGeometry,
            buffers: SplitBuffers,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            const limb_count = geometry.limbCount();
            if (buffers.outputs.len != limb_count)
                return error.InvalidKernelDescriptor;

            const value_words = std.math.mul(
                usize,
                geometry.value_count,
                geometry.wordsPerValue(),
            ) catch return error.SizeOverflow;
            if (value_words == 0 and buffers.values.len != 0)
                return error.InvalidKernelDescriptor;
            const values = if (value_words == 0)
                null
            else
                (try exactResident(session, buffers.values, value_words)).pointer;

            var pointers: [big_limb_count][*]u32 = undefined;
            var writes: [big_limb_count]layout.DeviceRange = undefined;
            for (buffers.outputs, 0..) |output, index| {
                const resident = try exactResident(
                    session,
                    output,
                    geometry.row_count,
                );
                pointers[index] = resident.pointer;
                writes[index] = resident.range;
            }
            const reads = if (value_words == 0)
                &[_]layout.DeviceRange{}
            else
                &[_]layout.DeviceRange{try layout.elementRange(
                    buffers.values.address,
                    value_words,
                    @sizeOf(u32),
                )};
            try layout.requireDisjoint(writes[0..limb_count], reads);

            const status = switch (geometry.kind) {
                .big => Api.stwo_cairo_memory_split_big_on(
                    values,
                    geometry.value_count,
                    geometry.row_count,
                    &pointers,
                    session.context.stream,
                ),
                .small => Api.stwo_cairo_memory_split_small_on(
                    values,
                    geometry.value_count,
                    geometry.row_count,
                    &pointers,
                    session.context.stream,
                ),
            };
            try common.record(session, stage, status);
        }

        pub fn addressBase(
            session: anytype,
            geometry: AddressGeometry,
            buffers: AddressBuffers,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            if (buffers.outputs.len != address_column_count)
                return error.InvalidKernelDescriptor;
            const address_ids = try exactResident(
                session,
                buffers.address_ids,
                geometry.address_id_words,
            );
            const multiplicity_words = try geometry.multiplicityWords();
            const multiplicities = try exactResident(
                session,
                buffers.multiplicities,
                multiplicity_words,
            );
            var outputs: [address_column_count][*]u32 = undefined;
            var writes: [address_column_count]layout.DeviceRange = undefined;
            for (buffers.outputs, 0..) |output, index| {
                const resident = try exactResident(
                    session,
                    output,
                    geometry.row_count,
                );
                outputs[index] = resident.pointer;
                writes[index] = resident.range;
            }
            try layout.requireDisjoint(
                &writes,
                &.{ address_ids.range, multiplicities.range },
            );
            const status = Api.stwo_cairo_memory_address_base_on(
                address_ids.pointer,
                geometry.address_id_words,
                multiplicities.pointer,
                try common.count(multiplicity_words),
                geometry.row_count,
                &outputs,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn valueBase(
            session: anytype,
            geometry: ValueGeometry,
            buffers: ValueBuffers,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            const limb_count: usize = geometry.limb_count;
            if (buffers.sources.len != limb_count or
                buffers.outputs.len != limb_count + 1)
            {
                return error.InvalidKernelDescriptor;
            }

            var sources: [big_limb_count][*]const u32 = undefined;
            var reads: [big_limb_count + 1]layout.DeviceRange = undefined;
            for (buffers.sources, 0..) |source, index| {
                const resident = try exactResident(
                    session,
                    source,
                    geometry.source_words,
                );
                sources[index] = resident.pointer;
                reads[index] = resident.range;
            }
            const multiplicities = try exactResident(
                session,
                buffers.multiplicities,
                geometry.row_count,
            );
            reads[limb_count] = multiplicities.range;

            var outputs: [big_limb_count + 1][*]u32 = undefined;
            var writes: [big_limb_count + 1]layout.DeviceRange = undefined;
            for (buffers.outputs, 0..) |output, index| {
                const resident = try exactResident(
                    session,
                    output,
                    geometry.row_count,
                );
                outputs[index] = resident.pointer;
                writes[index] = resident.range;
            }
            try layout.requireDisjoint(
                writes[0 .. limb_count + 1],
                reads[0 .. limb_count + 1],
            );
            const status = Api.stwo_cairo_memory_value_base_on(
                &sources,
                geometry.limb_count,
                geometry.source_words,
                multiplicities.pointer,
                geometry.row_count,
                geometry.row_count,
                &outputs,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn rangeCheck9_9(
            session: anytype,
            geometry: RangeCheckGeometry,
            buffers: RangeCheckBuffers,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            const limb_count = @as(usize, geometry.pair_count) * 2;
            if (buffers.limbs.len != limb_count)
                return error.InvalidKernelDescriptor;

            var limbs: [big_limb_count][*]const u32 = undefined;
            var reads: [big_limb_count + 1]layout.DeviceRange = undefined;
            for (buffers.limbs, 0..) |limb, index| {
                const resident = try exactResident(
                    session,
                    limb,
                    geometry.row_count,
                );
                limbs[index] = resident.pointer;
                reads[index] = resident.range;
            }
            const input_to_row = try exactResident(
                session,
                buffers.input_to_row,
                range_check_table_rows,
            );
            reads[limb_count] = input_to_row.range;
            const count_words = range_check_pair_columns *
                range_check_table_rows;
            const counts = try exactResident(
                session,
                buffers.counts,
                count_words,
            );
            try layout.requireDisjoint(
                &.{counts.range},
                reads[0 .. limb_count + 1],
            );
            const status = Api.stwo_cairo_memory_range_check_9_9_on(
                &limbs,
                geometry.pair_count,
                geometry.row_count,
                input_to_row.pointer,
                range_check_table_rows,
                counts.pointer,
                count_words,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn exactResident(
    session: anytype,
    slice: common.Words,
    expected: usize,
) runtime_error.Error!layout.Resident(u32) {
    if (slice.len != expected or slice.address % @alignOf(u32) != 0)
        return error.InvalidKernelDescriptor;
    return layout.resident(session, u32, slice, expected);
}

test {
    _ = @import("memory_test.zig");
}
