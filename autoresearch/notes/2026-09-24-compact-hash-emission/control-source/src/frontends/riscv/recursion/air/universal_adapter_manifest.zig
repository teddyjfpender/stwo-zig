//! Public manifest API with the prover/verifier adapter handoff.
//! Geometry, transcript and claim data share a pure contract owner.
const core = @import("stwo_core");
const core_components = core.air.components;
const QM31 = core.fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const digest = @import("../../air/lang/digest.zig");
const contract = @import("universal_manifest_contract.zig");

pub const ComponentKey = contract.ComponentKey;
pub const COMPONENT_COUNT = contract.COMPONENT_COUNT;
pub const keyIndex = contract.keyIndex;
pub const FORMAT_VERSION = contract.FORMAT_VERSION;
pub const TRANSCRIPT_FORMAT_VERSION = contract.TRANSCRIPT_FORMAT_VERSION;
pub const TRANSCRIPT_DOMAIN = contract.TRANSCRIPT_DOMAIN;
pub const DOMAIN = contract.DOMAIN;
pub const CLAIM_DOMAIN = contract.CLAIM_DOMAIN;
pub const TREE_COUNT = contract.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = contract.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = contract.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = contract.INTERACTION_TREE_INDEX;
pub const Error = contract.Error;
pub const Geometry = contract.Geometry;
pub const Placement = contract.Placement;
pub const Manifest = contract.Manifest;
pub const Builder = contract.Builder;
pub const ClaimVector = contract.ClaimVector;

/// Type-erased binding returned by one concrete typed adapter.  The component
/// object remains caller-owned and must stay at a stable address through the
/// prove/verify call, matching the underlying STWO component contract.
pub const AdapterBinding = struct {
    manifest_seal: digest.Digest,
    placement: Placement,
    claimed_sum: QM31,
    verifier: core_components.Component,
    prover: prover_component.ComponentProver,
};

pub const ProofGate = @import("manifest_proof_protocol.zig").TypesWithClaims(@This(), ClaimVector).ProofGate;
