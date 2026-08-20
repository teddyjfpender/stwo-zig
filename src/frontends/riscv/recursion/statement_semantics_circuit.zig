//! Production arithmetic authority for universal recursion row 11.
//!
//! The graph is proof-independent.  It binds four canonical 412-word statement
//! scopes and three proof selectors, then expresses every leaf-validity and
//! binary-fold invariant as a distinct zero output.  Private inputs are limited
//! to boolean decompositions, tag flags, and u16-addition carries; each has a
//! deterministic internal descriptor while the public AIR boundary retains the
//! exact row-11 `InputBinding` vocabulary.
//!
//! Source receipt: Stark-V commit
//! `59172a201bd01f2f4b699bc2f7d4442d8ee81597`,
//! `crates/recursion/src/statement_semantics_circuit.rs`, SHA-256
//! `1c136c50f45ae592806649abf802e41b49d78320086ba729990d03e704107899`.
//! The equations are adapted to `span_statement.zig`; this module does not use
//! host validation as a substitute for circuit constraints.
const shard_0 = @import("statement_semantics_circuit_contract.zig");
const shard_1 = @import("statement_semantics_circuit_tracked_builder.zig");
const shard_2 = @import("statement_semantics_circuit_build.zig");

pub const ProofKind = shard_0.ProofKind;
pub const InputBinding = shard_0.InputBinding;
pub const StatementWords = shard_0.StatementWords;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const IDENTITY_DOMAIN = shard_0.IDENTITY_DOMAIN;
pub const STARK_V_COMMIT = shard_0.STARK_V_COMMIT;
pub const STARK_V_SOURCE_SHA256 = shard_0.STARK_V_SOURCE_SHA256;
pub const IDENTITY_DIGEST_HEX = shard_0.IDENTITY_DIGEST_HEX;
pub const IDENTITY_DIGEST = shard_0.IDENTITY_DIGEST;
pub const SELECTOR_INPUT_COUNT = shard_0.SELECTOR_INPUT_COUNT;
pub const STATEMENT_INPUT_COUNT = shard_0.STATEMENT_INPUT_COUNT;
pub const PRIVATE_INPUT_COUNT = shard_0.PRIVATE_INPUT_COUNT;
pub const INPUT_COUNT = shard_0.INPUT_COUNT;
pub const NODE_COUNT = shard_0.NODE_COUNT;
pub const OUTPUT_COUNT = shard_0.OUTPUT_COUNT;
pub const Error = shard_0.Error;
/// Raw values for one universal row-11 instance.  Inactive statement scopes are
/// zeroed by `prepareInputsInto`; callers do not need to allocate zero arrays.
/// Invalid selector combinations remain representable and are rejected by the
/// graph's one-hot equations.
pub const Witness = shard_0.Witness;
pub const Circuit = shard_0.Circuit;
pub const Evaluation = shard_0.Evaluation;
pub const build = shard_2.build;
