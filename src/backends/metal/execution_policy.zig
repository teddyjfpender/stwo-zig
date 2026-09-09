//! Explicit host-work admission for the Metal proving route.
//! This is an execution policy, not a protocol or performance profile. Until
//! each bulk stage has device support, strict requests fail at that stage.
const std = @import("std");

pub const environment_variable = "STWO_ZIG_METAL_REQUIRE_GPU";
pub const Mode = enum {
    hybrid,
    require_gpu,

    pub fn parse(value: ?[]const u8) !Mode {
        const text = value orelse return .hybrid;
        if (std.mem.eql(u8, text, "0")) return .hybrid;
        if (std.mem.eql(u8, text, "1")) return .require_gpu;
        return error.InvalidMetalExecutionPolicy;
    }

    pub fn admitHost(self: Mode, operation: HostOperation) !void {
        if (self == .hybrid) return;
        return switch (operation) {
            .recursive_preparation => error.MetalHostRecursivePreparationForbidden,
            .witness_generation => error.MetalHostWitnessGenerationForbidden,
            .composition => error.MetalHostCompositionForbidden,
            .merkle_commit => error.MetalHostMerkleCommitForbidden,
            .circle_interpolation => error.MetalHostInterpolationForbidden,
            .circle_evaluation => error.MetalHostEvaluationForbidden,
            .circle_lde => error.MetalHostLdeForbidden,
            .fri_inverse_preparation => error.MetalHostFriInversePreparationForbidden,
            .proof_of_work => error.MetalHostProofOfWorkForbidden,
        };
    }
};

pub const HostOperation = enum {
    recursive_preparation,
    witness_generation,
    composition,
    merkle_commit,
    circle_interpolation,
    circle_evaluation,
    circle_lde,
    fri_inverse_preparation,
    proof_of_work,
};

pub fn requested() !Mode {
    return Mode.parse(std.posix.getenv(environment_variable));
}

/// Call before host allocation/computation, not after observing a GPU dispatch
/// elsewhere in the proof. CPU verification and serialization are not proving
/// operations and do not call this admission boundary.
pub fn admitHost(operation: HostOperation) !void {
    try (try requested()).admitHost(operation);
}

test "strict Metal policy cannot silently parse invalid values as hybrid" {
    try std.testing.expectEqual(Mode.hybrid, try Mode.parse(null));
    try std.testing.expectEqual(Mode.hybrid, try Mode.parse("0"));
    try std.testing.expectEqual(Mode.require_gpu, try Mode.parse("1"));
    for ([_][]const u8{ "", "true", "false", "01", " 1", "2" }) |value|
        try std.testing.expectError(error.InvalidMetalExecutionPolicy, Mode.parse(value));
}

test "strict Metal policy rejects each known bulk host operation" {
    inline for (std.meta.tags(HostOperation)) |operation| {
        try Mode.hybrid.admitHost(operation);
        if (Mode.require_gpu.admitHost(operation)) |_| {
            return error.TestExpectedError;
        } else |_| {}
    }
    try std.testing.expectError(error.MetalHostCompositionForbidden, Mode.require_gpu.admitHost(.composition));
}
