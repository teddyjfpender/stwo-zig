//! Versioned row-11 arithmetic graph for unequal-height V3 temporal folds.
//!
//! The legacy Stark-V row-11 graph and its verifier key remain unchanged.
//! This graph constrains each child/parent slot from its own executed segment
//! interval, permitting an odd carried child to meet a taller left subtree.
//! It is not a parent proof or proof-verifier publication.
const contract = @import("statement_semantics_circuit_contract.zig").ContractTemporalV3();
const implementation = @import("statement_semantics_circuit_build.zig").Build(contract);

pub const PRODUCTION_ACTIVATION = false;
pub const PARENT_PROOF_AVAILABLE = false;
pub const Witness = contract.Witness;
pub const Circuit = contract.Circuit;
pub const IDENTITY_DOMAIN = contract.IDENTITY_DOMAIN;
pub const IDENTITY_DIGEST = contract.IDENTITY_DIGEST;
pub const INPUT_COUNT = contract.INPUT_COUNT;
pub const NODE_COUNT = contract.NODE_COUNT;
pub const OUTPUT_COUNT = contract.OUTPUT_COUNT;
pub const build = implementation.build;
