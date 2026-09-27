//! Exact original scoped joins for the two missing public coordinates. These
//! equations confer no source authority and never recount native compensation.
const Join = @import("../../prover/block_v5_global_join_algebra_v1.zig");
pub fn Algebra(comptime S: type) type {
    return struct {
        pub fn window(sink: anytype, native_original: S, native_export: S, registers: S, register_compensation: S) !void {
            try sink.zero(native_original.sub(native_export), error.UntrustedGlobalNativeCompensation);
            const claims = [_]S{registers.add(register_compensation)};
            try Join.Algebra(S).registers(sink, 1, &claims);
        }
        pub fn terminal(sink: anytype, program: S, boundary: S) !void {
            const parts = [_]struct { claim: S }{.{ .claim = boundary }};
            try Join.Algebra(S).program(sink, program, &parts);
        }
        pub fn accounting(sink: anytype, known_residual: S, boundary: S, register_compensation: S) !void {
            const bytes = [_]struct { sum: S }{};
            try Join.Algebra(S).accounting(sink, .{ .native_open_sum = known_residual, .precompile_open_sum = S.zero(), .public_program_boundary_sum = boundary, .program_provider_sum = S.zero(), .table_provider_sum = S.zero(), .ordinary_memory_opposite = S.zero(), .external_memory_opposite = S.zero(), .auxiliary_clock_memory_sum = S.zero(), .register_compensation_sum = register_compensation }, &bytes);
        }
    };
}
