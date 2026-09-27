//! Version 1 BLAKE3 Span statement: B3SP tag, explicit version, 525 M31 words.
//! All fourteen identities preserve 256 bits in sixteen 16-bit limbs each.
//! This exposes semantic admission, encoding and folding; a production leaf
//! constructor awaits migrated public-claim and memory-commitment authorities.
const shard_0 = @import("span_statement_executed_span.zig").Contract(true);
const shard_1 = @import("span_statement_semantics.zig").Semantics(shard_0);

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
/// Join consecutive execution spans independently of binary proof-tree slots.
pub const foldExecuted = shard_0.foldExecuted;
pub const SpanBody = shard_0.SpanBody;
pub const SpanStatement = shard_1.SpanStatement;
pub const RootStatement = shard_1.RootStatement;
pub const isIntegerWord = shard_1.isIntegerWord;
pub const DIGEST_WORD_COUNT = shard_0.DIGEST_WORD_COUNT;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const isDigestWord = shard_1.isDigestWord;

/// Versioned native identity preimages shared with recursive witness routing.
pub const identity = @import("span_identity_blake3.zig");
