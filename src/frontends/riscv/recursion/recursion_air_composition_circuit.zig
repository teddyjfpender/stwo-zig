//! Exact high-level binary-recursion AIR composition graph producer.
//!
//! The graph has the row-18 ABI fixed by `air/composition_circuit.zig`:
//! parent selector, three child-kind selectors, 412 parent-statement words,
//! verifier-captured samples, 36 roster claims, two Poseidon2 partial claims,
//! 47 challenge pairs,
//! composition randomness, and the OODS seed.  Component equations are never
//! copied here.  A live verifier adapter contributes only its authenticated
//! direct program, authenticated relation plan, fixed parameters, and sealed
//! manifest placement; `composition_graph_recorder.zig` replays both programs.
//!
//! Construction is deliberately a session.  The successful PCS capture and
//! initialized heterogeneous adapters coexist only while `Session` records
//! the graph.  `finish` then returns an owned circuit and owned row-18 input
//! bindings, with no borrow of either object.  All three proof-kind programs
//! must enumerate all 36 rows in canonical order before publication.
const shard_0 = @import("recursion_air_composition_circuit_contract.zig");
const shard_1 = @import("recursion_air_composition_circuit_session.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const CIRCUIT_DOMAIN = shard_0.CIRCUIT_DOMAIN;
pub const TREE_COUNT = shard_0.TREE_COUNT;
pub const COMPOSITION_TREE_INDEX = shard_0.COMPOSITION_TREE_INDEX;
pub const ROSTER_CLAIM_COUNT = shard_0.ROSTER_CLAIM_COUNT;
pub const POSEIDON_AUX_START = shard_0.POSEIDON_AUX_START;
pub const COMPOSITION_CLAIM_INPUT_COUNT = shard_0.COMPOSITION_CLAIM_INPUT_COUNT;
pub const RELATION_CHALLENGE_COUNT = shard_0.RELATION_CHALLENGE_COUNT;
pub const STATEMENT_WORD_COUNT = shard_0.STATEMENT_WORD_COUNT;
pub const Error = shard_0.Error;
pub const ProgramStatistics = shard_0.ProgramStatistics;
/// All concrete values are verifier-owned.  `sampled_values`, randomness, and
/// the OODS seed come from a transactionally published `VerifiedProofCapture`;
/// claims and challenges come from the already successful outer transcript.
pub const Witness = shard_0.Witness;
/// Owned graph product suitable for transactional attachment to a successful
/// outer verification receipt.  Evaluation is allocation-free with two
/// caller-owned scratch slices.
pub const Circuit = shard_0.Circuit;
/// Cold graph-construction transaction.  It must stay at a stable address
/// while active because the generic recorder installs its builder thread-locally.
pub const Session = shard_1.Session;
