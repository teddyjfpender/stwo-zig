//! Authenticated AOT kernel closure required by the Native Poseidon route.

const std = @import("std");
const ir = @import("stwo_backend_contracts").proof_program;
const schema = @import("../../../backends/cuda/abi/schema.zig");
const telemetry = @import(
    "../../../backends/cuda/runtime/telemetry.zig",
);
const witness = @import(
    "../../../backends/cuda/runtime/traces/m31_permutation.zig",
);
const constraint = @import(
    "../../../backends/cuda/runtime/constraints/poseidon.zig",
);

pub const sm89: u32 = 89;

pub const Entry = struct {
    stage: telemetry.Stage,
    abi_schema: schema.KernelSchema,
    cache_key: u64,
    kernel_name: []const u8,
};

pub const entries = [_]Entry{
    .{
        .stage = .trace_generation,
        .abi_schema = .native_m31_permutation_trace_v3,
        .cache_key = witness.cache_key,
        .kernel_name = witness.kernel_name,
    },
    .{
        .stage = .constraint_evaluation,
        .abi_schema = .native_poseidon_constraint_v1,
        .cache_key = constraint.cache_key,
        .kernel_name = constraint.kernel_name,
    },
};

pub const identity: ir.Digest = blk: {
    @setEvalBranchQuota(10_000);
    break :blk ir.identityDigest(
        "stwo-zig/native-cuda/poseidon/aot-pack/v3;" ++
            "sm=89;" ++
            "witness=m31-permutation:0ce5a65a150f8601;" ++
            "constraint=poseidon:fab354a9f2437fcb",
    );
};

test "Poseidon AOT pack binds the exact witness and constraint descriptors" {
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    const witness_descriptor = try witness.descriptor(7);
    const constraint_descriptor = try constraint.descriptor(7);
    try std.testing.expectEqual(
        entries[0].abi_schema,
        witness_descriptor.abi_schema,
    );
    try std.testing.expectEqual(
        entries[0].cache_key,
        witness_descriptor.cache_key,
    );
    try std.testing.expectEqualStrings(
        entries[0].kernel_name,
        witness_descriptor.name,
    );
    try std.testing.expectEqual(
        entries[1].abi_schema,
        constraint_descriptor.abi_schema,
    );
    try std.testing.expectEqual(
        entries[1].cache_key,
        constraint_descriptor.cache_key,
    );
    try std.testing.expectEqualStrings(
        entries[1].kernel_name,
        constraint_descriptor.name,
    );
}
