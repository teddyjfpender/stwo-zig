//! Optional, caller-owned Circle transform primitive. This deliberately uses
//! core types: execution receipts and prover TwiddleTree are higher-layer APIs.
//! Existing LDE hooks may compose this primitive without moving proof semantics.
const std = @import("std");
const core = @import("stwo_core");
const signature = @import("signature.zig");
const M31 = core.fields.m31.M31;
pub const Direction = enum { evaluate, interpolate };
pub const Twiddles = struct {
    root_coset: core.circle.Coset,
    twiddles: []const M31,
    itwiddles: []const M31,
};

/// Buffers and twiddles are borrowed for the duration of the blocking call.
/// Each buffer has exactly domain.size() canonical values. Interpolation includes
/// inverse normalization. Output ordering is the existing Circle FFT ordering.
/// Errors must be surfaced, never silently rerouted and counted as acceleration.
pub fn assertCapability(comptime B: type, comptime enabled: bool) void {
    comptime {
        if (!enabled) {
            if (@hasDecl(B, "transformCircleBuffers")) @compileError("transformCircleBuffers requires circle_transform");
            return;
        }
        if (!@hasDecl(B, "transformCircleBuffers")) @compileError("circle_transform requires transformCircleBuffers");
        const Result = @TypeOf(B.transformCircleBuffers(
            @as(std.mem.Allocator, undefined),
            @as([]const []M31, undefined),
            @as(core.poly.circle.domain.CircleDomain, undefined),
            @as(Twiddles, undefined),
            @as(Direction, undefined),
        ));
        signature.assertErrorUnionPayload(Result, void, "transformCircleBuffers must return !void");
    }
}
