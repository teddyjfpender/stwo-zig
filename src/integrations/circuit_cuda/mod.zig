//! Circuit CUDA integration. The currently exported `provers` are a hybrid
//! CPU PCS with NVIDIA CUDA grinds (design 02-design.md §4.6, §9.2 item 7,
//! milestone M12): the transcript of `circuit_cpu.prove`
//! (`crates/circuit_prover/src/prover.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) on the CPU PCS, with both §4.7
//! grinds of every proof (the 20-bit interaction grind and the FRI grind,
//! 26 bits in production) on the device (`device_grind.zig`,
//! `native/circuit_grind.cu`).
//!
//! Why the grinds first. `stwo_cuda_backend` is a resident proof session,
//! not the host-slice PCS contract `ProverEngine` binds, so the resident
//! circuit prover (LDE, Merkle, quotients and FRI on the device) is not a
//! re-binding the way `circuit_metal` is; it is listed as open work in
//! `README.md`. The grinds are the part the design names as the reason for
//! the kernels (§9.2 item 7): a 26-bit grind is about 2^26 Blake2s
//! compressions per proof, on the CPU a large share of a small reduction.
//!
//! The exported hybrid proof is byte-equal to the CPU scalar oracle. Its
//! nonces are the canonical minimum of
//! `core/channel/blake2s_pow_order.zig`, which the kernel computes and the
//! engine revalidates. The R7 rung proves it on a GPU host
//! (`circuit-parity-r7-cuda`); on any host it runs against the kernel's
//! host emulation (`circuit-parity-r7-cuda-emulated`).

const std = @import("std");
const core = @import("stwo_core");
const cpu_backend = @import("stwo_cpu_backend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");

pub const device_grind = @import("device_grind.zig");
/// The kernel's search run on the host (tests; links
/// `native/circuit_grind.cu` built with `STWO_CIRCUIT_GRIND_HOST_EMULATION`).
pub const emulation = @import("emulation.zig");
/// Known answers for a grind under test (emulation and device tests).
pub const grind_vectors = @import("grind_vectors.zig");
pub const air_aot = @import("air_aot.zig");
pub const geometry = @import("geometry.zig");
pub const transcript_prefix = @import("transcript_prefix.zig");
pub const resident_transcript = @import("resident_transcript.zig");
pub const resident_commit = @import("resident_commit.zig");
pub const resident_witness = @import("resident_witness.zig");
pub const resident_interaction = @import("resident_interaction.zig");
pub const resident_composition = @import("resident_composition.zig");
pub const resident_composition_controller = @import("resident_composition_controller.zig");
pub const resident_oods = @import("resident_oods.zig");
pub const resident_fri = @import("resident_fri.zig");
pub const resident_quotient = @import("resident_quotient.zig");
pub const resident_decommit = @import("resident_decommit.zig");
pub const resident_terminal_bundle = @import("resident_terminal_bundle.zig");
pub const resident_terminal_decode = @import("resident_terminal_decode.zig");
pub const resident_terminal_capture = @import("resident_terminal_capture.zig");
pub const resident_proof_layout = @import("resident_proof_layout.zig");
pub const resident_pipeline = @import("resident_pipeline.zig");
pub const resident_memory_plan = @import("resident_memory_plan.zig");
pub const resident_memory_binding = @import("resident_memory_binding.zig");
pub const resident_prover = @import("resident_prover.zig");
pub const resident_verifier = @import("resident_verifier.zig");
pub const recursion_source = @import("recursion_source.zig");

const profiles = core.vcs_lifted.channel_profile.proving_5a7c5ed;

/// The CPU PCS with every grind sent to `Grind` (a proof-of-work provider:
/// `device_grind.Device`, or the emulation in tests).
pub fn BackendWith(comptime Grind: type) type {
    return cpu_backend.configured(.{ .wide_preparation = true, .proof_of_work = Grind });
}

/// Both channel profiles' provers with grinds on `Grind`.
pub fn ProversWith(comptime Grind: type) type {
    const B = BackendWith(Grind);
    const I = circuit_cpu.prove.ProverOn(B, profiles.Blake2sM31MerkleChannel);
    const R = circuit_cpu.prove.ProverOn(B, profiles.Blake2sMerkleChannel);
    return struct {
        pub const Backend = B;
        /// Leaves and internal folds (`Blake2sM31MerkleChannel`).
        pub const Internal = I;
        /// The root (`Blake2sMerkleChannel`).
        pub const Root = R;
        /// Both profiles, for the recursion drivers (`LeafWrap.provers`,
        /// `Fold.provers`).
        pub const provers = circuit_cpu.prove.Provers.of(I, R);
    };
}

/// The circuit provers with both grinds on the CUDA device. Fail closed:
/// without a device, every proof errors at its interaction grind.
pub const Device = ProversWith(device_grind.Device);
pub const Backend = Device.Backend;
pub const Internal = Device.Internal;
pub const Root = Device.Root;
pub const provers = Device.provers;

test "api signature: both channel profiles bind the CPU engine with a device grind" {
    comptime @import("stwo_prover_api").assertProverEngine(Internal.Engine);
    comptime @import("stwo_prover_api").assertProverEngine(Root.Engine);
    comptime std.debug.assert(Backend.ProofOfWork == device_grind.Device);
}

test "invariant: the CUDA provers commit with the CPU oracle's hasher, channels and proof types" {
    try std.testing.expect(Internal.Hasher == circuit_cpu.Internal.Hasher);
    try std.testing.expect(Internal.Channel == circuit_cpu.Internal.Channel);
    try std.testing.expect(Root.Channel == circuit_cpu.Root.Channel);
    try std.testing.expect(Internal.CircuitProof == circuit_cpu.Internal.CircuitProof);
    try std.testing.expect(Root.CircuitProof == circuit_cpu.Root.CircuitProof);
}

test {
    _ = emulation;
    _ = grind_vectors;
    _ = air_aot;
    _ = geometry;
    _ = transcript_prefix;
    _ = resident_transcript;
    _ = resident_commit;
    _ = resident_witness;
    _ = resident_interaction;
    _ = resident_composition;
    _ = resident_composition_controller;
    _ = resident_oods;
    _ = resident_fri;
    _ = resident_quotient;
    _ = resident_decommit;
    _ = resident_memory_plan;
    _ = resident_memory_binding;
    _ = resident_prover;
    _ = resident_verifier;
    _ = recursion_source;
}

test "provider path: the engine's grind returns the CPU channel's nonce through the (emulated) kernel" {
    const grindForBackend = @import("stwo_prover_engine").pcs.proof_of_work.grindForBackend;
    const Emulated = ProversWith(emulation.Provider).Backend;
    inline for (.{ core.channel.blake2s.Blake2sChannel, core.channel.blake2s.Blake2sM31Channel }) |Channel| {
        var channel = Channel{};
        channel.mixU64(0x1111_2222_3333_4344);
        for ([_]u32{ 1, 10, 20 }) |bits| {
            try std.testing.expectEqual(channel.grindWithWorkerCount(bits, 8), try grindForBackend(Emulated, &channel, bits));
        }
        try std.testing.expectEqual(@as(u64, 0), try grindForBackend(Emulated, &channel, 0));
    }
}

test "fail closed: the provider refuses a host grind it has no kernel for" {
    try std.testing.expectError(error.CudaHostProofOfWorkForbidden, device_grind.Device.admitHostProving(.proof_of_work));
}

test "invariant: the CPU oracle keeps its host grind" {
    try std.testing.expect(circuit_cpu.prove.Internal.Backend.ProofOfWork == void);
}
