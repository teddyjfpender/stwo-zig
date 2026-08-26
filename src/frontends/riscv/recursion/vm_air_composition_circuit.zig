//! Zig-native VM AIR composition graph for universal recursion row 18.
//!
//! The graph is recorded by replaying the production component sources over a
//! hash-consing scalar. Opcode semantics, lookup batches, program/memory,
//! clock, Merkle, table, and Poseidon constraints therefore have one source of
//! truth for native and recursive verification. The only local logic is the
//! protocol-level mask mapping, quotient denominator, Horner accumulation, and
//! split-composition reconstruction already defined by STWO core.

const shard_0 = @import("vm_air_composition_circuit_error.zig");
const shard_1 = @import("vm_air_composition_circuit_circuit.zig");
const shard_2 = @import("vm_air_composition_circuit_validate_sample_geometry.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const CIRCUIT_DOMAIN = shard_0.CIRCUIT_DOMAIN;
pub const CIRCUIT_ID = shard_0.CIRCUIT_ID;
pub const TREE_COUNT = shard_0.TREE_COUNT;
pub const Error = shard_0.Error;
pub const Circuit = shard_1.Circuit;
pub const Evaluation = shard_2.Evaluation;
/// Fully admitted row-18 authority and witness derived from one successful
/// native verification. This is the stable, non-generic handoff consumed by
/// backend outer provers: no statement pointer or decoded proof storage is
/// retained, and every owned layer revalidates its independent seal.
pub const Prepared = shard_1.Prepared;
pub const build = shard_1.build;
