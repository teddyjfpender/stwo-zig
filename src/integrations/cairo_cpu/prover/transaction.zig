//! CPU/SIMD binding for the backend-neutral official Cairo transaction.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const CpuBackend = @import("../../../backends/cpu_scalar/mod.zig").CpuBackend;
const adapter = @import("stwo_cairo_frontend").adapter;
const generic = @import("stwo_cairo_frontend").proving.transaction;
const preprocessed = @import("stwo_cairo_frontend").preprocessed;

pub const Hasher =
    core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
pub const MerkleChannel =
    core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleChannel;
pub const Channel = core.channel.blake2s.Blake2sChannel;
pub const Engine = prover.engine.ProverEngine(
    CpuBackend,
    Hasher,
    MerkleChannel,
    Channel,
);

pub const Fixture = generic.Fixture;
pub const Result = generic.Result(Engine);
pub const official_pcs_config = generic.official_pcs_config;

comptime {
    prover.engine.assertProverEngine(Engine);
}

pub fn proveFixture(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
) !Result {
    return generic.proveFixture(Engine, allocator, fixture, variant);
}

pub fn proveFixtureWithRecorder(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
    recorder: ?*prover.stage_profile.Recorder,
) !Result {
    return generic.proveFixtureWithRecorder(
        Engine,
        allocator,
        fixture,
        variant,
        recorder,
    );
}

pub fn verifyAndConsume(
    input: *const adapter.ProverInput,
    result: *Result,
) !void {
    return generic.verifyAndConsume(Engine, input, result);
}

test "CPU binding uses the official plain Blake2s protocol" {
    try std.testing.expectEqual(@as(u32, 26), official_pcs_config.pow_bits);
    try std.testing.expect(Engine.Backend == CpuBackend);
}
