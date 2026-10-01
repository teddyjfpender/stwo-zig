//! Checked resident circuit gate witness. The five launches share the same
//! zeroed table counts and report bad value addresses through a device flag.
const std = @import("std");
const abi = @import("../../abi/stages/circuit_base.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const gate_count: usize = 5;
pub const pp_widths = [gate_count]usize{ 1, 7, 4, 1, 10 };
pub const output_widths = [gate_count]usize{ 4, 12, 20, 4, 52 };
pub const count_lengths = [22]usize{
    1 << 16, 1 << 16,
    1 << 20, 1 << 20,
    1 << 20, 1 << 20,
    1 << 20, 1 << 20,
    1 << 20, 1 << 20,
    1 << 20, 1 << 20,
    1 << 20, 1 << 20,
    1 << 20, 1 << 20,
    1 << 20, 1 << 20,
    1 << 8,  1 << 14,
    1 << 18, 1 << 16,
};

pub const Gate = enum(u32) { eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate };

pub const Geometry = struct {
    gate: Gate,
    row_count: u32,
    value_count: u32,
    first_permutation_row: u32 = 0,

    pub fn validate(self: Geometry) runtime_error.Error!void {
        if (self.row_count < 16 or !std.math.isPowerOfTwo(self.row_count) or
            self.value_count == 0 or self.value_count > std.math.maxInt(u32) / 4)
            return error.InvalidKernelDescriptor;
        if (self.gate == .qm31_ops and (self.first_permutation_row > self.row_count or
            (self.row_count - self.first_permutation_row) % 2 != 0))
            return error.InvalidKernelDescriptor;
    }
};

pub const Buffers = struct {
    values: common.Words,
    preprocessed: []const common.Words,
    outputs: []const common.Words,
    counts: []const common.Words,
    error_flag: common.Words,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn clear(session: anytype, counts: []const common.Words, error_flag: common.Words) runtime_error.Error!void {
            try common.requireStage(session, .trace_generation);
            if (counts.len != count_lengths.len or error_flag.len != 1)
                return error.InvalidKernelDescriptor;
            for (counts, count_lengths) |buffer, expected| {
                if (buffer.len != expected) return error.InvalidKernelDescriptor;
                try session.context.zeroDeviceSlice(u32, buffer);
            }
            try session.context.zeroDeviceSlice(u32, error_flag);
        }

        pub fn gate(session: anytype, geometry: Geometry, buffers: Buffers) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            try geometry.validate();
            const kind: usize = @intFromEnum(geometry.gate);
            if (buffers.preprocessed.len != pp_widths[kind] or
                buffers.outputs.len != output_widths[kind] or
                buffers.counts.len != count_lengths.len or
                buffers.values.len != @as(usize, geometry.value_count) * 4 or
                buffers.error_flag.len != 1)
                return error.InvalidKernelDescriptor;

            const values = try layout.resident(session, u32, buffers.values, buffers.values.len);
            const error_flag = try layout.resident(session, u32, buffers.error_flag, 1);
            var pp: [11][*]const u32 = undefined;
            var outs: [52][*]u32 = undefined;
            var counts: [count_lengths.len][*]u32 = undefined;
            var reads: [12]layout.DeviceRange = undefined;
            var writes: [output_widths[4] + count_lengths.len + 1]layout.DeviceRange = undefined;
            reads[0] = values.range;
            for (buffers.preprocessed, 0..) |buffer, index| {
                const source = try layout.resident(session, u32, buffer, geometry.row_count);
                if (buffer.len != geometry.row_count) return error.InvalidKernelDescriptor;
                pp[index] = source.pointer;
                reads[index + 1] = source.range;
            }
            var write_count: usize = 0;
            for (buffers.outputs, 0..) |buffer, index| {
                const output = try layout.resident(session, u32, buffer, geometry.row_count);
                if (buffer.len != geometry.row_count) return error.InvalidKernelDescriptor;
                outs[index] = output.pointer;
                writes[write_count] = output.range;
                write_count += 1;
            }
            for (buffers.counts, count_lengths, 0..) |buffer, expected, index| {
                const output = try layout.resident(session, u32, buffer, expected);
                if (buffer.len != expected) return error.InvalidKernelDescriptor;
                counts[index] = output.pointer;
                writes[write_count] = output.range;
                write_count += 1;
            }
            writes[write_count] = error_flag.range;
            write_count += 1;
            try layout.requireDisjoint(writes[0..write_count], reads[0 .. buffers.preprocessed.len + 1]);

            const status = Api.stwo_circuit_base_witness_on(
                @intFromEnum(geometry.gate),
                values.pointer,
                geometry.value_count,
                geometry.row_count,
                geometry.first_permutation_row,
                &pp,
                @intCast(buffers.preprocessed.len),
                &outs,
                @intCast(buffers.outputs.len),
                &counts,
                @intCast(buffers.counts.len),
                error_flag.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

test "circuit gate witness table geometry follows CPU component order" {
    try std.testing.expectEqual(@as(usize, 22), count_lengths.len);
    try std.testing.expectEqual(@as(usize, 1 << 24), count_lengths[2..18].len * count_lengths[2]);
    try std.testing.expectError(error.InvalidKernelDescriptor, (Geometry{
        .gate = .qm31_ops,
        .row_count = 32,
        .value_count = 4,
        .first_permutation_row = 31,
    }).validate());
}
