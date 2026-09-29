//! CPU/SIMD binding of the Cairo leaf lane: upstream
//! `prove_cairo::<Blake2sM31MerkleChannel>` under a circuit registry's
//! `cairo_prover_params` (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, `crates/leaf_prover`).
//!
//! The same generic transaction and CPU backend as `transaction.zig`; only the
//! engine's Merkle channel differs, which is the channel profile that fixes the
//! M31-reduced Fiat-Shamir channel, `mix_hash` and the Rust grind order.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const official = @import("transaction.zig");
const generic = @import("stwo_cairo_frontend").proving.transaction;

pub const MerkleChannel = core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel;
pub const Hasher = MerkleChannel.MerkleHasher;
pub const Channel = MerkleChannel.Channel;
pub const Engine = prover.engine.ProverEngine(
    official.Engine.Backend,
    Hasher,
    MerkleChannel,
    Channel,
);

pub const Lane = generic.leaf_lane.Lane;
pub const ProverParameters = generic.leaf_lane.ProverParameters;
pub const Fixture = generic.Fixture;
pub const Result = generic.Result(Engine);

comptime {
    @import("stwo_prover_api").assertProverEngine(Engine);
}

/// Proves `fixture` as a leaf Cairo proof under `params` (the registry's
/// `cairo_prover_params`); `channel_hash` is ignored, as upstream does.
pub fn proveLeafCairo(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    params: ProverParameters,
    recorder: ?*prover.stage_profile.Recorder,
) !Result {
    const lane = try Lane.fromParameters(params);
    return generic.proveFixtureForLane(Engine, allocator, fixture, lane.variant, recorder, lane);
}

test "leaf binding shares the official CPU backend and hasher" {
    try std.testing.expect(Engine.Backend == official.Engine.Backend);
    try std.testing.expect(Hasher == official.Hasher);
    try std.testing.expect(Channel == core.channel.blake2s.Blake2sM31Channel);
}
