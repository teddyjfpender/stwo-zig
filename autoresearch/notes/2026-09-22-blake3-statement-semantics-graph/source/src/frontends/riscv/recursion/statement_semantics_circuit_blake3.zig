//! BLAKE3 Span semantics graph; use with the BLAKE3 input AIR schedule.
const shard_0 = @import("statement_semantics_circuit_contract.zig").Contract(true);
const shard_1 = @import("statement_semantics_circuit_tracked_builder.zig").Builder(shard_0);
const shard_2 = @import("statement_semantics_circuit_build.zig").Build(shard_0);

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
