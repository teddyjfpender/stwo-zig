//! Verified-capture authority for one universal `binary_node` recursion input.
//!
//! This is the custody boundary immediately before a future
//! `recursive_pair_outer` prover. Two fixed proof wires, two canonical span
//! statements, and two verifier-owned child receipts enter once. Construction
//! revalidates the fixed wires, executes both recursion transcripts, derives
//! every child identity from those checked values, authenticates the ordered
//! pair, folds the statements, and snapshots universal rows 1--11.
//!
//! The module deliberately does not produce or verify the parent STARK. Rows
//! 12--16 are exposed as an explicit inactive binary VM-public contract. Row
//! 17 remains live: it consumes the public-LogUp control step from each of the
//! two recursion-verifier lanes emitted by row 0. Row 35 remains the shared
//! authenticated `(8, 8)` range-table provider. The returned value
//! is therefore integration-ready source authority, not recursive-proof
//! production evidence.
const shard_0 = @import("binary_pair_authority_contract.zig");
const shard_1 = @import("binary_pair_authority_prepared.zig");
const shard_2 = @import("binary_pair_authority_wire_identity_sentinel.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const PROOF_KIND = shard_0.PROOF_KIND;
pub const FIRST_AUTHORITY_ROW = shard_0.FIRST_AUTHORITY_ROW;
pub const LAST_SNAPSHOTTED_ROW = shard_0.LAST_SNAPSHOTTED_ROW;
pub const FIRST_INACTIVE_VM_ROW = shard_0.FIRST_INACTIVE_VM_ROW;
pub const LAST_INACTIVE_VM_ROW = shard_0.LAST_INACTIVE_VM_ROW;
pub const BINARY_PUBLIC_LOGUP_CONTROL_ROW = shard_0.BINARY_PUBLIC_LOGUP_CONTROL_ROW;
pub const SHARED_RANGE_ROW = shard_0.SHARED_RANGE_ROW;
pub const SHARED_RANGE_LOG_SIZE = shard_0.SHARED_RANGE_LOG_SIZE;
pub const VALIDATION_SCRATCH_LEN = shard_0.VALIDATION_SCRATCH_LEN;
/// This source closes custody and exact binary witness derivation. It does not
/// itself instantiate the 36 components or make a parent proof.
pub const RECURSIVE_PROOF_PRODUCTION = shard_0.RECURSIVE_PROOF_PRODUCTION;
pub const Error = shard_0.Error;
/// Whether the supplied plans must be the exact frozen V1 reconstruction.
/// `sealed_candidate` exists only for separately domain-reviewed profiling and
/// tests; production callers use `frozen_v1`.
pub const PlanAdmission = shard_0.PlanAdmission;
/// Proof-independent preprocessing shared with the segment path. The native
/// universal layout intentionally contains one VM lane and two recursion
/// lanes, so the same authenticated preprocessing is the single source of
/// truth for both modes.
pub const TranscriptPreprocessing = shard_0.TranscriptPreprocessing;
/// One reusable allocation for mutation-resistant statement-circuit replay.
/// Keeping this outside `Prepared` avoids doubling every retained row-11
/// snapshot and makes repeated validation allocation-free.
pub const ValidationWorkspace = shard_1.ValidationWorkspace;
/// Verifier-produced metadata retained beside one successful child capture.
/// No identity is trusted from this record: `Prepared.init` re-derives the
/// statement, fixed-proof, transcript, and summary identities and compares the
/// complete result to `verified` before pair authentication.
pub const VerifiedChildCapture = shard_1.VerifiedChildCapture;
pub const FixedChild = shard_1.FixedChild;
pub const PairInputs = shard_0.PairInputs;
/// Exact branch contract consumed by rows 0--17 and the shared range provider.
/// Rows 12--16 are inactive for a binary node by protocol, not placeholders.
/// Row 17 is schedule control, not a VM-public witness: it must consume both
/// binary recursion lanes or row 0's exact schedule tuples cannot close.
pub const RowContract = shard_0.RowContract;
pub const Prepared = shard_1.Prepared;
