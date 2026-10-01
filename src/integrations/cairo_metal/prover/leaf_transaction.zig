//! The pinned Blake2s-M31 Cairo leaf lane on the Metal prover backend.

const std = @import("std");
const core = @import("stwo_core");
const metal = @import("stwo_metal_backend");
const prover = @import("stwo_prover_engine");
const cairo = @import("stwo_cairo_frontend");
const generic = cairo.proving.transaction;
const stage = @import("../composition_stage.zig");

pub const MerkleChannel = core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel;
pub const Hasher = MerkleChannel.MerkleHasher;
pub const Channel = MerkleChannel.Channel;
pub const Engine = prover.engine.ProverEngine(metal.MetalCommitBackend, Hasher, MerkleChannel, Channel);
pub const Lane = generic.leaf_lane.Lane;
pub const ProverParameters = generic.leaf_lane.ProverParameters;
pub const Fixture = generic.Fixture;
pub const Result = generic.Result(Engine);

comptime {
    prover.engine.assertProverEngine(Engine);
}

pub fn compositionDevice(assets: []const u8) ?cairo.proving.air.device_stage.Device {
    return stage.productDevice(assets);
}

pub fn proveLeafCairo(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    params: ProverParameters,
    recorder: ?*prover.stage_profile.Recorder,
) !Result {
    const lane = try Lane.fromParameters(params);
    return generic.proveFixtureForLane(Engine, allocator, fixture, lane.variant, recorder, lane);
}

test "leaf lane uses the pinned Blake2s-M31 channel on Metal" {
    try std.testing.expect(Engine.Backend == metal.MetalCommitBackend);
    try std.testing.expect(Channel == core.channel.blake2s.Blake2sM31Channel);
}
