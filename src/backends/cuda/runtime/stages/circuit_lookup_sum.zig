//! Device-side global circuit LogUp admission before interaction commitment.
const std = @import("std");
const abi = @import("../../abi/stages/circuit_lookup_sum.zig");
const field = @import("../../abi/field.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub const Buffers = struct {
    claimed_sums: common.SecureFields,
    output_values: common.SecureFields,
    alpha_powers: common.SecureFields,
    z: common.SecureFields,
    error_flag: common.Words,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn check(session: anytype, buffers: Buffers) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_commit;
            try common.requireStage(session, stage);
            if (buffers.claimed_sums.len != 11 or buffers.alpha_powers.len != 6 or
                buffers.z.len != 1 or buffers.error_flag.len != 1 or
                buffers.output_values.len > @as(usize, std.math.maxInt(u32) - 3))
                return error.InvalidKernelDescriptor;
            const claims = try layout.resident(session, field.SecureField, buffers.claimed_sums, 11);
            const outputs = if (buffers.output_values.len == 0)
                null
            else
                try layout.resident(session, field.SecureField, buffers.output_values, buffers.output_values.len);
            const powers = try layout.resident(session, field.SecureField, buffers.alpha_powers, 6);
            const z = try layout.resident(session, field.SecureField, buffers.z, 1);
            const error_flag = try layout.resident(session, u32, buffers.error_flag, 1);
            var reads = [_]layout.DeviceRange{ claims.range, powers.range, z.range, claims.range };
            if (outputs) |resident| reads[3] = resident.range;
            try layout.requireDisjoint(&.{error_flag.range}, reads[0..if (outputs == null) 3 else 4]);
            try common.record(session, stage, Api.stwo_circuit_lookup_sum_on(
                claims.pointer,
                if (outputs) |resident| resident.pointer else null,
                @intCast(buffers.output_values.len),
                powers.pointer,
                6,
                z.pointer,
                error_flag.pointer,
                session.context.stream,
            ));
        }
    };
}
