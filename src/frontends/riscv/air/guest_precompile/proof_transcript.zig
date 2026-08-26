//! Claim-phase Fiat--Shamir protocol for the Poseidon2 extension profile.
//!
//! The base profile is deliberately not generalized here.  Its claim types,
//! shard manifest, twelve relation pairs, and transcript helpers remain
//! unchanged.  This module owns only the separately versioned profile path:
//! a canonical artifact binding before Tree 0, two appended components after
//! Tree 1, and one appended relation pair.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const artifact = @import("artifact_identity.zig");
const components = @import("component_registry.zig");
const proof_admission = @import("proof_admission.zig");
const profile_relations = @import("relation_challenges.zig");
const statement_mod = @import("statement.zig");
const base_opcode_entries = @import("../lookups/opcode_entries.zig");
const base_opcode_interaction = @import("../lookups/opcode_interaction.zig");
const base_statement = @import("../statement.zig");
const base_transcript = @import("../transcript/mod.zig");
const interaction_witness_work = @import("../../prover/interaction_witness_work.zig");

pub const profile_transcript_version: u32 = 2;
pub const artifact_word_count: usize = artifact.encoded_size / @sizeOf(u32);

/// Little-endian bytes `STWGPTI1`, followed by the transcript version and
/// canonical artifact word count.  Keeping these as words makes the channel
/// encoding explicit and endian-independent through `mixU32s`.
pub const identity_domain_words = [4]u32{
    0x4757_5453,
    0x3149_5450,
    profile_transcript_version,
    artifact_word_count,
};

/// Little-endian bytes `STWGSHD1`, followed by the transcript version and the
/// exact number of appended component descriptors.
pub const extension_shard_domain_words = [4]u32{
    0x4757_5453,
    0x3144_4853,
    profile_transcript_version,
    components.extension_component_count,
};

/// Little-endian bytes `STWGDCL2`, followed by the profile transcript version
/// and the exact number of extension claim families. The dynamic base claim
/// count and the fixed caller/provider counts complete this frame at runtime.
pub const detailed_claim_domain_words = [4]u32{
    0x4757_5453,
    0x324c_4344,
    profile_transcript_version,
    components.extension_component_count,
};

pub const descriptor_word_count: usize = 8;
pub const Error = proof_admission.Error || error{InvalidInteractionClaim};
pub const PrefixError = base_transcript.PrefixError;
pub const Relations = profile_relations.Poseidon2V1Relations;

pub const ProverRelations = struct {
    interaction_pow: u64,
    relations: Relations,
    base_challenge_work_receipt: ?interaction_witness_work.ProducerReceipt = null,
    guest_challenge_work_receipt: ?interaction_witness_work.ProducerReceipt = null,
};

/// Detailed terminal claims consumed by the component boundary constraints.
///
/// These values are distinct from the component aggregates: the random
/// composition coefficient must be sampled only after every physical
/// recurrence boundary is bound. Exact-size guest arrays make omission a type
/// error, while base values are traversed from authenticated statement order.
pub const DetailedInteractionClaim = struct {
    base: *const base_statement.RiscVInteractionClaim,
    caller: *const [components.caller_batch_count]QM31,
    provider: *const [components.provider_batch_count]QM31,
};

/// Validate the complete extension and decoded artifact before changing the
/// channel, then bind the canonical envelope as domain-separated LE words.
///
/// The caller places this after the unchanged PCS/public-data prefix and
/// before committing Tree 0.  Invalid prover-supplied artifact fields are
/// rejected while the channel is still untouched.
pub fn mixProfileIdentity(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    identity: artifact.Identity,
) Error!void {
    try proof_admission.validate(core, extension, identity, .proof);

    const encoded = identity.encode();
    var words: [identity_domain_words.len + artifact_word_count]u32 = undefined;
    @memcpy(words[0..identity_domain_words.len], &identity_domain_words);
    inline for (0..artifact_word_count) |index| {
        const offset = index * @sizeOf(u32);
        words[identity_domain_words.len + index] = std.mem.readInt(
            u32,
            encoded[offset..][0..@sizeOf(u32)],
            .little,
        );
    }
    channel.mixU32s(&words);
}

/// Prover claim phase after Tree 1: the 30-slot main claim, unchanged base
/// shard manifest, two extension descriptors, PoW, twelve base pairs, then the
/// guest pair.
pub fn proveToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
) !ProverRelations {
    try mixPostTree1Authority(channel, core, extension);
    const nonce = channel.grind(base_transcript.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    return .{
        .interaction_pow = nonce,
        .relations = try Relations.draw(allocator, channel),
    };
}

/// Profiling-only sibling preserving the exact twelve-base-then-one-guest draw
/// sequence of `proveToRelations`.
pub fn proveToRelationsWithWorkReceipt(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    authority: *const interaction_witness_work.Authority,
) !ProverRelations {
    var result = try proveToRelations(allocator, channel, core, extension);
    const binding = interaction_witness_work.guestSessionDigest(
        result.interaction_pow,
        &result.relations,
    );
    result.base_challenge_work_receipt =
        try interaction_witness_work.completeBaseChallenges(
            authority,
            .poseidon2_guest,
            binding,
        );
    result.guest_challenge_work_receipt =
        try interaction_witness_work.completeGuestChallenges(authority, binding);
    return result;
}

/// Verifier replay of the exact post-Tree-1 profile prefix.  An invalid
/// supplied nonce fails before the nonce is mixed and before any challenge is
/// drawn.
pub fn verifyToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    interaction_pow: u64,
) !Relations {
    try mixPostTree1Authority(channel, core, extension);
    if (!channel.verifyPowNonce(
        base_transcript.INTERACTION_POW_BITS,
        interaction_pow,
    )) return PrefixError.InvalidInteractionProofOfWork;
    channel.mixU64(interaction_pow);
    return Relations.draw(allocator, channel);
}

/// Authenticate and mix both the canonical aggregate interaction claim and
/// every detailed recurrence boundary immediately before Tree 2.
///
/// The second, domain-separated frame is security-critical. Components consume
/// individual batch claims during random-coefficient composition, so binding
/// only their aggregate would let a prover choose compensating batch deltas
/// after seeing that coefficient.
pub fn mixInteractionClaim(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    claim: *const statement_mod.InteractionClaim,
    detailed: DetailedInteractionClaim,
) Error!void {
    try extension.validate(core);
    try validateInteractionLogSizes(core, extension, claim);
    const base_claim_count = try validateDetailedClaim(core, detailed);

    claim.mixInto(channel);

    channel.mixU32s(&[detailed_claim_domain_words.len + 3]u32{
        detailed_claim_domain_words[0],
        detailed_claim_domain_words[1],
        detailed_claim_domain_words[2],
        detailed_claim_domain_words[3],
        @intCast(base_claim_count),
        components.caller_batch_count,
        components.provider_batch_count,
    });
    for (core.component_descs[0..core.n_components], 0..) |descriptor, index| {
        channel.mixFelts(try detailed.base.opcodeClaims(descriptor.family, index));
    }
    for (core.infra_descs[0..core.n_infra], 0..) |descriptor, index| {
        channel.mixFelts(try detailed.base.infraClaims(descriptor.kind, index));
    }
    channel.mixFelts(detailed.caller);
    channel.mixFelts(detailed.provider);
}

/// Number of active base batch claims in canonical component declaration
/// order. Fixed-capacity slack is never transcript-visible.
pub fn detailedBaseClaimCount(
    core: *const base_statement.RiscVStatement,
) error{InvalidInteractionClaim}!usize {
    var count: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        count = std.math.add(
            usize,
            count,
            base_opcode_entries.batchCount(descriptor.family),
        ) catch return error.InvalidInteractionClaim;
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        count = std.math.add(
            usize,
            count,
            base_statement.nClaimedSumsForInfra(descriptor.kind),
        ) catch return error.InvalidInteractionClaim;
    }
    return count;
}

fn validateDetailedClaim(
    core: *const base_statement.RiscVStatement,
    detailed: DetailedInteractionClaim,
) error{InvalidInteractionClaim}!usize {
    if (detailed.base.n_components != core.n_components or
        detailed.base.n_infra != core.n_infra)
    {
        return error.InvalidInteractionClaim;
    }
    return detailedBaseClaimCount(core);
}

fn mixPostTree1Authority(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
) Error!void {
    // Validation precedes the first mix so malformed dynamic geometry cannot
    // leave a partially advanced channel.
    try extension.validate(core);

    const main_claim = statement_mod.MainClaim.init(
        core.canonicalMainClaim(),
        extension,
    );
    main_claim.mixInto(channel);

    // Preserve every base call boundary and payload, then append a distinct
    // versioned frame containing exactly caller and provider.
    core.mixShardManifest(channel);
    channel.mixU32s(&extension_shard_domain_words);
    for (extension.components) |descriptor| mixDescriptor(channel, descriptor);
}

fn mixDescriptor(channel: anytype, descriptor: components.Descriptor) void {
    channel.mixU32s(&[descriptor_word_count]u32{
        @intFromEnum(descriptor.slot),
        @intFromEnum(descriptor.kind),
        descriptor.version,
        descriptor.n_rows,
        descriptor.log_size,
        descriptor.preprocessed_columns,
        descriptor.main_columns,
        descriptor.interaction_columns,
    });
}

fn validateInteractionLogSizes(
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    claim: *const statement_mod.InteractionClaim,
) error{InvalidInteractionClaim}!void {
    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        const count = base_opcode_interaction.nColumns(descriptor.family);
        if (!consumeLogSizes(
            claim.base.log_sizes,
            &cursor,
            count,
            descriptor.log_size,
        )) return error.InvalidInteractionClaim;
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        if (!consumeLogSizes(
            claim.base.log_sizes,
            &cursor,
            base_statement.nInteractionColsForInfra(descriptor.kind),
            descriptor.log_size,
        )) return error.InvalidInteractionClaim;
    }
    if (cursor != claim.base.log_sizes.len or
        !std.meta.eql(claim.extension_log_sizes, .{
            extension.components[0].log_size,
            extension.components[1].log_size,
        }))
    {
        return error.InvalidInteractionClaim;
    }
}

fn consumeLogSizes(
    actual: []const u32,
    cursor: *usize,
    count: usize,
    expected: u32,
) bool {
    if (count > actual.len -| cursor.*) return false;
    const end = cursor.* + count;
    for (actual[cursor.*..end]) |log_size| {
        if (log_size != expected) return false;
    }
    cursor.* = end;
    return true;
}

comptime {
    if (artifact.encoded_size % @sizeOf(u32) != 0 or
        artifact_word_count != 38 or
        components.base_component_count != 28 or
        components.component_count != 30 or
        components.extension_component_count != 2 or
        profile_relations.relation_count != 13 or
        descriptor_word_count != 8)
    {
        @compileError("guest profile transcript geometry drifted");
    }
}
