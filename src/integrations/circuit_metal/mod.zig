//! The circuit prover on Metal (design §4.6, milestone M12): the transcript
//! of `circuit_cpu.prove` (`crates/circuit_prover/src/prover.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) bound to `MetalCommitBackend`,
//! so interpolation, LDE, Merkle commitments, quotients, FRI and both §4.7
//! grinds (M31 and plain Blake2s kernels in the Rust `(hi, lo < 2^20)`
//! order) run on the device, and composition runs through the Cairo lane's
//! device stage over the circuit AIR bundle with the circuit's pinned
//! composition library (`cairo_metal.composition_stage.circuitDevice`). The
//! witness is the CPU integration's; only where the work runs differs, and a
//! device proof must be byte-equal to the CPU scalar oracle (R7-R9 on
//! device).
//!
//! Fail closed: with `STWO_ZIG_METAL_REQUIRE_GPU=1` any stage the device
//! cannot take (a missing kernel, a component the composition library does
//! not cover, a mid-stage device error) is an error, never a silent CPU run.

const std = @import("std");
const core = @import("stwo_core");
const metal = @import("stwo_metal_backend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const cairo_metal = @import("stwo_cairo_metal_integration");

const prove = circuit_cpu.prove;
const QM31 = core.fields.qm31.QM31;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

pub const Backend = metal.MetalCommitBackend;
const profiles = core.vcs_lifted.channel_profile.proving_5a7c5ed;

/// Leaves and internal folds (`Blake2sM31MerkleChannel`).
pub const Internal = Device(prove.ProverOn(Backend, profiles.Blake2sM31MerkleChannel));
/// The root (`Blake2sMerkleChannel`).
pub const Root = Device(prove.ProverOn(Backend, profiles.Blake2sMerkleChannel));

/// `P` with the Metal composition stage injected into every proof.
fn Device(comptime P: type) type {
    return struct {
        pub const Backend = P.Backend;
        pub const MerkleChannel = P.MerkleChannel;
        pub const Channel = P.Channel;
        pub const Hasher = P.Hasher;
        pub const Engine = P.Engine;
        pub const Hash = P.Hash;
        pub const CircuitProof = P.CircuitProof;

        pub fn prove(
            allocator: std.mem.Allocator,
            values: []const QM31,
            pp: *const @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit,
            air_template: *const circuit_cpu.air.Bundle,
            pcs_config: PcsConfigV2,
            options: circuit_cpu.prove.Options,
            observer: anytype,
        ) !CircuitProof {
            var device_options = options;
            if (device_options.composition_device == null)
                device_options.composition_device = cairo_metal.composition_stage.circuitDevice();
            // Wraps and folds both use blowup one. Their committed columns
            // are already on the quotient domain, so retaining evaluations
            // avoids repeatedly re-extending compact coefficients for
            // composition, queries, and decommitment. Keep the caller's
            // storage policy for circuits with a larger blowup.
            if (device_options.compact_polynomial_min_log != null and
                pcs_config.fri_config.log_blowup_factor == 1)
            {
                device_options.compact_polynomial_min_log = null;
                device_options.evaluations_only = true;
            }
            return P.prove(allocator, values, pp, air_template, pcs_config, device_options, observer);
        }
    };
}

/// Both profiles on Metal, for the recursion drivers (`LeafWrap.provers`,
/// `Fold.provers`).
pub const provers = prove.Provers.of(Internal, Root);

test "api signature: both channel profiles bind the Metal engine" {
    comptime @import("stwo_prover_api").assertProverEngine(Internal.Engine);
    comptime @import("stwo_prover_api").assertProverEngine(Root.Engine);
}

test "invariant: the Metal provers commit with the CPU oracle's hasher and channels" {
    try std.testing.expect(Internal.Hasher == circuit_cpu.Internal.Hasher);
    try std.testing.expect(Internal.Channel == circuit_cpu.Internal.Channel);
    try std.testing.expect(Root.Channel == circuit_cpu.Root.Channel);
    try std.testing.expect(Internal.CircuitProof == circuit_cpu.Internal.CircuitProof);
}

test "invariant: the Metal grinds are the device kernels, not a host fallback" {
    try std.testing.expect(@hasDecl(Backend, "grindBlake2sM31ProofOfWork"));
    try std.testing.expect(@hasDecl(Backend, "grindBlake2sProofOfWork"));
    try std.testing.expect(@hasDecl(Backend, "admitHostProving"));
}
