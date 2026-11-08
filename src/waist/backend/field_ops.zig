//! Optional host field-operation capability for prover backends.
//!
//! This capability deliberately describes host slices. A device-native batch
//! inverse needs its own typed contract rather than weakening this one.

const std = @import("std");
const signature = @import("signature.zig");
const M31 = @import("stwo_core").fields.m31.M31;

pub fn assertCapability(comptime B: type, comptime enabled: bool) void {
    comptime {
        if (!enabled) {
            if (@hasDecl(B, "batchInverse")) {
                @compileError(
                    "Backend declares `batchInverse` but does not claim `host_batch_inverse`.",
                );
            }
            return;
        }
        if (!@hasDecl(B, "batchInverse")) {
            @compileError(
                "Backend claims `host_batch_inverse` but does not declare `batchInverse`.",
            );
        }
        const Result = @TypeOf(B.batchInverse(
            M31,
            @as(std.mem.Allocator, undefined),
            @as([]const M31, undefined),
        ));
        signature.assertErrorUnionPayload(
            Result,
            []M31,
            "`batchInverse` must accept `(comptime F, allocator, []const F)` and return `![]F`.",
        );
    }
}
