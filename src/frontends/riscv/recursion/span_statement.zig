//! Canonical 412-word execution statement for recursive leaves and folds.
//!
//! The geometry and tags are the pinned Stark-V V1 ABI.  Local scalar Merkle
//! roots are embedded injectively as the first limb of an eight-word digest;
//! the remaining limbs are zero.  A segment leaf is constructed only from an
//! already validated canonical VM claim, keeping one authority for machine
//! state, public IO digests, and statement words.
const shard_0 = @import("span_statement_executed_span.zig");
const shard_1 = @import("span_statement_span_statement.zig");

pub const Digest = shard_0.Digest;
pub const MACHINE_STATE_CANONICAL_WORDS = shard_0.MACHINE_STATE_CANONICAL_WORDS;
pub const COMPLETE_EXECUTION_CANONICAL_WORDS = shard_0.COMPLETE_EXECUTION_CANONICAL_WORDS;
pub const JOB_CONTEXT_CANONICAL_WORDS = shard_0.JOB_CONTEXT_CANONICAL_WORDS;
pub const SLOT_SPAN_CANONICAL_WORDS = shard_0.SLOT_SPAN_CANONICAL_WORDS;
pub const EDGE_CLAIM_CANONICAL_WORDS = shard_0.EDGE_CLAIM_CANONICAL_WORDS;
pub const EXECUTED_SPAN_CANONICAL_WORDS = shard_0.EXECUTED_SPAN_CANONICAL_WORDS;
pub const SPAN_BODY_CANONICAL_WORDS = shard_0.SPAN_BODY_CANONICAL_WORDS;
pub const SPAN_STATEMENT_CANONICAL_WORDS = shard_0.SPAN_STATEMENT_CANONICAL_WORDS;
pub const StatementWords = shard_0.StatementWords;
pub const MAX_SLOT_HEIGHT = shard_0.MAX_SLOT_HEIGHT;
pub const SLOT_BOUND = shard_0.SLOT_BOUND;
pub const Tag = shard_0.Tag;
pub const canonical_layout = shard_0.canonical_layout;
pub const Error = shard_0.Error;
pub const MachineState = shard_0.MachineState;
pub const CompleteExecution = shard_0.CompleteExecution;
pub const JobContext = shard_0.JobContext;
pub const SlotSpan = shard_0.SlotSpan;
pub const EdgeClaim = shard_0.EdgeClaim;
pub const ExecutedSpan = shard_0.ExecutedSpan;
pub const SpanBody = shard_0.SpanBody;
pub const SpanStatement = shard_1.SpanStatement;
pub const RootStatement = shard_1.RootStatement;
/// Allocation-free production result for a complete one-segment VM proof.
pub const SegmentLeaf = shard_1.SegmentLeaf;
pub const expandRoot = shard_1.expandRoot;
pub const isIntegerWord = shard_1.isIntegerWord;
