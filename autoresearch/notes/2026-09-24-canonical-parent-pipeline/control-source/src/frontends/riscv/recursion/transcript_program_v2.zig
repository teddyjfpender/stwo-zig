//! Exact generic-channel transcript authority for resumed-segment V2 proofs.
//!
//! V1 recursion deliberately uses a separately framed transcript. V2 does not
//! reinterpret that frozen protocol: this program expands an admitted VM
//! verifier plan into the exact low-level calls made by the ordinary
//! Poseidon2-M31 channel. In particular, the bootstrap is the production order
//! `PcsConfig.mixInto`, V2 domain/version/schema/length, wire identity, then the
//! complete variable-length canonical statement wire.
//!
//! `Program` is proof-independent and verifier-owned. `Execution` records the
//! resulting Poseidon calls in the existing rows-0--9 trace ABI. Its native
//! identities are defensive custody seals; recursive soundness comes from
//! constraining the exposed calls and payload-source relations in the outer
//! AIR, never from trusting an identity as a MAC.
const shard_0 = @import("transcript_program_v2_contract.zig");
const shard_1 = @import("transcript_program_v2_program.zig");
const shard_2 = @import("transcript_program_v2_execute.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const PROGRAM_ID_DOMAIN = shard_0.PROGRAM_ID_DOMAIN;
pub const EVIDENCE_ID_DOMAIN = shard_0.EVIDENCE_ID_DOMAIN;
pub const RATE = shard_0.RATE;
pub const WIDTH = shard_0.WIDTH;
pub const COMPONENT_CLAIM_COUNT = shard_0.COMPONENT_CLAIM_COUNT;
pub const TranscriptTrace = shard_0.TranscriptTrace;
pub const PoseidonCall = shard_0.PoseidonCall;
pub const HashFrame = shard_0.HashFrame;
pub const HashPurpose = shard_0.HashPurpose;
pub const Check = shard_0.Check;
pub const Digest = shard_0.Digest;
pub const Draw = shard_0.Draw;
pub const Error = shard_0.Error;
pub const Kind = shard_0.Kind;
pub const Effect = shard_0.Effect;
/// One exact generic-channel call (or one verify-then-absorb PoW transaction).
/// `args` are kind-specific, verifier-owned constants and are always included
/// in the program identity.
pub const Instruction = shard_0.Instruction;
/// Verifier-owned expansion of one admitted V2 VM transcript shape.
pub const Program = shard_1.Program;
/// Dynamic proof values consumed in verifier-program order. Statement and VM
/// geometry are deliberately absent: those come from authenticated authority.
pub const Inputs = shard_1.Inputs;
pub const Operation = shard_1.Operation;
/// Value-only recursive handoff for rows 0--9 and the shared Poseidon provider.
pub const Evidence = shard_1.Evidence;
/// Exact raw sponge evidence. Construction owns five retained allocations and
/// publishes nothing on failure.
pub const Execution = shard_1.Execution;
pub const execute = shard_2.execute;
