//! Checked resident fraction generation for all eleven circuit components.
const std = @import("std");
const abi = @import("../../abi/stages/circuit_interaction.zig");
const relation_abi = @import("../../abi/stages/relation.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi, relation_abi);
pub const component_count: usize = 11;
pub const pp_widths = [component_count]usize{ 2, 8, 5, 3, 11, 3, 0, 3, 3, 3, 1 };
pub const base_widths = [component_count]usize{ 4, 12, 20, 4, 52, 2, 16, 1, 1, 1, 1 };
pub const lookup_counts = [component_count]usize{ 2, 3, 12, 5, 26, 2, 16, 1, 1, 1, 1 };
pub const secure_widths = [component_count]usize{ 1, 2, 6, 3, 13, 1, 8, 1, 1, 1, 1 };

pub const Geometry = struct {
    component: u32,
    rows: u32,

    pub fn validate(self: Geometry) runtime_error.Error!void {
        if (self.component >= component_count or self.rows < 16 or
            !std.math.isPowerOfTwo(self.rows) or self.rows >= 1 << 31)
            return error.InvalidKernelDescriptor;
    }
};

pub const Buffers = struct {
    preprocessed: []const common.Words,
    base_columns: []const common.Words,
    output_columns: []const common.Words,
    powers: common.SecureFields,
    z: common.SecureFields,
    denominators: common.SecureFields,
    error_flag: common.Words,
};

pub fn OpsFor(comptime Api: type, comptime ChallengeApi: type) type {
    return struct {
        pub fn expandChallenges(
            session: anytype,
            drawn_z_alpha: common.SecureFields,
            powers: common.SecureFields,
            z: common.SecureFields,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_commit;
            try common.requireStage(session, stage);
            if (drawn_z_alpha.len != 2 or powers.len != 6 or z.len != 1)
                return error.InvalidKernelDescriptor;
            const field = @import("../../abi/field.zig").SecureField;
            const drawn = try layout.resident(session, field, drawn_z_alpha, 2);
            const expanded = try layout.resident(session, field, powers, 6);
            const extracted = try layout.resident(session, field, z, 1);
            try layout.requireDisjoint(&.{ expanded.range, extracted.range }, &.{drawn.range});
            try common.record(session, stage, ChallengeApi.stwo_relation_expand_challenges_on(
                drawn.pointer,
                expanded.pointer,
                6,
                @ptrCast(extracted.pointer),
                session.context.stream,
            ));
        }

        pub fn generate(session: anytype, geometry: Geometry, buffers: Buffers) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_commit;
            try common.requireStage(session, stage);
            try geometry.validate();
            const component = geometry.component;
            const secure = secure_widths[component];
            if (buffers.preprocessed.len != pp_widths[component] or
                buffers.base_columns.len != base_widths[component] or
                buffers.output_columns.len != 4 * secure or
                buffers.powers.len != 6 or buffers.z.len != 1 or
                buffers.denominators.len != secure * @as(usize, geometry.rows) or
                buffers.error_flag.len != 1)
                return error.InvalidKernelDescriptor;
            var pp: [11][*]const u32 = undefined;
            var source: [52][*]const u32 = undefined;
            var output: [52][*]u32 = undefined;
            var reads: [11 + 52 + 6]layout.DeviceRange = undefined;
            var writes: [52 + 2]layout.DeviceRange = undefined;
            var read_count: usize = 0;
            var write_count: usize = 0;
            for (buffers.preprocessed, 0..) |column, index| {
                if (column.len != geometry.rows) return error.InvalidKernelDescriptor;
                const resident = try layout.resident(session, u32, column, geometry.rows);
                pp[index] = resident.pointer;
                reads[read_count] = resident.range;
                read_count += 1;
            }
            for (buffers.base_columns, 0..) |column, index| {
                if (column.len != geometry.rows) return error.InvalidKernelDescriptor;
                const resident = try layout.resident(session, u32, column, geometry.rows);
                source[index] = resident.pointer;
                reads[read_count] = resident.range;
                read_count += 1;
            }
            for (buffers.output_columns, 0..) |column, index| {
                if (column.len != geometry.rows) return error.InvalidKernelDescriptor;
                const resident = try layout.resident(session, u32, column, geometry.rows);
                output[index] = resident.pointer;
                writes[write_count] = resident.range;
                write_count += 1;
            }
            const powers = try layout.resident(session, @import("../../abi/field.zig").SecureField, buffers.powers, 6);
            const z = try layout.resident(session, @import("../../abi/field.zig").SecureField, buffers.z, 1);
            const denominators = try layout.resident(session, @import("../../abi/field.zig").SecureField, buffers.denominators, buffers.denominators.len);
            const error_flag = try layout.resident(session, u32, buffers.error_flag, 1);
            reads[read_count] = powers.range;
            read_count += 1;
            reads[read_count] = z.range;
            read_count += 1;
            writes[write_count] = denominators.range;
            write_count += 1;
            writes[write_count] = error_flag.range;
            write_count += 1;
            try layout.requireDisjoint(writes[0..write_count], reads[0..read_count]);
            const status = Api.stwo_circuit_interaction_fractions_on(
                component,
                geometry.rows,
                &pp,
                @intCast(buffers.preprocessed.len),
                &source,
                @intCast(buffers.base_columns.len),
                &output,
                @intCast(buffers.output_columns.len),
                powers.pointer,
                6,
                z.pointer,
                denominators.pointer,
                @intCast(buffers.denominators.len),
                error_flag.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

test "circuit interaction width is four coordinates per paired lookup" {
    for (lookup_counts, secure_widths) |lookups, width|
        try std.testing.expectEqual((lookups + 1) / 2, width);
}
