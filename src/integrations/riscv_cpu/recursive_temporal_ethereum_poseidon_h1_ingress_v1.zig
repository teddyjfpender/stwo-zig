//! Verifier-minted ingress authority for two full Ethereum Poseidon leaves.
//!
//! The live authority can be minted only from two `VerifiedPoseidonV4`
//! capabilities, their exact STWESG31 sources, and the matching DescriptorV1
//! and NodePublicV2 values.  It projects the field-native inputs consumed by
//! the existing Ethereum leaf-link AIRs and derives the unique adjacent h1
//! statement.  The canonical encoding is custody only: cold re-admission must
//! reopen both source files and rerun both complete leaf proof verifiers.
//!
//! This module deliberately does not publish a parent proof.  Production is
//! fail-closed until the secure parent PCS policy, verifier-minted h1 profile,
//! and canonical parent proof codec/fresh-verifier route all exist.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const leaf_support = @import("ethereum_block_leaf_support.zig");
const leaf_descriptor =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const node_public_mod =
    @import("recursive_temporal_node_public_authority_v2.zig");
const node_profile = @import("recursive_temporal_node_profile_v1.zig");
const proof_security = @import("recursive_temporal_proof_security_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const recursion = frontend.recursion;
const link_program = recursion.ethereum_leaf_link_program_v1;
const child_program = recursion.ethereum_leaf_child_field_program_v1;
const program_field = recursion.ethereum_vm_program_field_authority_v1;
const source_air = recursion.air.ethereum_leaf_link_source_v1;
const projection_air = recursion.air.ethereum_leaf_link_projection_v1;
const child_router_air = recursion.air.ethereum_leaf_child_field_router_v1;
const hash_air = recursion.air.vm_public_claim_hash;
const global_v3 = recursion.segment_leaf_local_authority_v3;
const link_v3 = recursion.segment_leaf_local_verified_link_v3;
const span = recursion.span_statement;
const source_wire = leaf_support.source_wire;
const channel = recursion.poseidon2_channel;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const AIR_COMPONENT_COUNT: usize = 4;
pub const PUBLIC_AUTHORITY_DIGEST_COUNT: usize =
    link_program.PUBLIC_AUTHORITY_DIGEST_COUNT;
pub const PRODUCTION_ACTIVATION = false;
pub const SECURE_PARENT_PROOF_POLICY_AVAILABLE = false;
pub const VERIFIER_MINTED_H1_PROFILE_AVAILABLE = false;
pub const CANONICAL_PARENT_PROOF_CODEC_AVAILABLE = false;

const AIR_CONTRACT_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-air-contract/v1\x00";
const LOCAL_WIRE_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-local-wire/v1\x00";
const LEAF_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-leaf/v1\x00";
const INGRESS_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-ingress/v1\x00";
const PROFILE_BINDING_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-profile-binding/v1\x00";

pub const PublicationPredicateV1 = enum(u8) {
    secure_parent_proof_policy = 1,
    verifier_minted_h1_profile = 2,
    canonical_parent_proof_codec = 3,
};

pub const MISSING_PRODUCTION_PREDICATES = [3]PublicationPredicateV1{
    .secure_parent_proof_policy,
    .verifier_minted_h1_profile,
    .canonical_parent_proof_codec,
};

pub const AirComponentKindV1 = enum(u8) {
    ethereum_link_source = 1,
    ethereum_link_projection = 2,
    ethereum_child_field_router = 3,
    poseidon_preimage_hash = 4,
};

pub const AirComponentBindingV1 = struct {
    kind: AirComponentKindV1,
    reserved: [3]u8 = .{ 0, 0, 0 },
    main_columns: u32,
    preprocessed_columns: u32,
    interaction_columns: u32,
    maximum_constraint_degree: u32,
    semantic_digest: [32]u8,
};

/// Exact typed-AIR ABI consumed by the future h1 wrapper.  These identities
/// are compiler semantic digests, not transport hashes selected by a caller.
pub const AirContractV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    component_count: u16 = AIR_COMPONENT_COUNT,
    reserved: u16 = 0,
    source_row_count: u32,
    projection_row_count: u32,
    poseidon_call_count: u32,
    transcript_claim_count: u32,
    child_router_base_row_count: u32,
    child_router_words_per_descriptor: u32,
    components: [AIR_COMPONENT_COUNT]AirComponentBindingV1,
    required_leaf_security_sha256: [32]u8,
    required_parent_security_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validate(self: *const AirContractV1) !void {
        const expected = fixedAirContract();
        if (!std.meta.eql(self.*, expected))
            return error.InvalidEthereumPoseidonH1AirContract;
    }
};

/// Exact real-h1 profile projection.  The two V2 manifest fields remain
/// separate: the dynamic full-Ethereum child composition roster is not the
/// fixed parent outer-STARK roster.  This is plan custody, not a verifier-
/// minted profile receipt.
pub const H1ProfileBindingV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: node_profile.KindV1 = .real_parent_h1,
    parent_height: u8 = 1,
    admitted_child_security_kind: proof_security.KindV1,
    parent_proof_security_kind: proof_security.KindV1,
    node_profile_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    admitted_child_security_sha256: [32]u8,
    parent_proof_security_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,
    profile_id: channel.Digest,
    identity_sha256: [32]u8,

    pub fn validate(self: *const H1ProfileBindingV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.kind != .real_parent_h1 or self.parent_height != 1 or
            self.admitted_child_security_kind !=
                .ethereum_segment_v3_poseidon2 or
            (self.parent_proof_security_kind != .recursive_parent_functional and
                self.parent_proof_security_kind != .recursive_parent_secure))
        {
            return error.InvalidEthereumPoseidonH1Profile;
        }
        inline for (.{
            self.node_profile_sha256,
            self.child_composition_manifest_sha256,
            self.parent_outer_manifest_sha256,
            self.admitted_child_security_sha256,
            self.parent_proof_security_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.verification_key_id,
            self.next_parent_vk_id,
            self.air_program_id,
            self.profile_id,
        }) |value| try requireDigest(value);
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &profileBindingIdentity(self),
        )) return error.InvalidEthereumPoseidonH1Profile;
    }
};

/// Transaction-local inputs.  The descriptor is deliberately repeated: the
/// constructor requires equality across the verifier capability, DescriptorV1
/// transport, and NodePublicV2 transport before projecting any AIR values.
pub const FreshLeafInputV1 = struct {
    verified: *const leaf_support.VerifiedPoseidonV4,
    source: *const source_wire.Source,
    descriptor: *const leaf_descriptor.DescriptorV1,
    node_public: *const node_public_mod.EthereumLeafAuthorityV2,
};

pub const FreshMintInputV1 = struct {
    profile: *const node_profile.NodeProfileV1,
    left: FreshLeafInputV1,
    right: FreshLeafInputV1,
};

/// Inputs required to turn a decoded custody record back into a live
/// verifier-minted authority.  `proof_bytes` are always fully decoded and
/// freshly verified; their SHA-256 is never accepted as proof admission.
pub const ColdLeafInputV1 = struct {
    source_bytes: []const u8,
    proof_bytes: []const u8,
    node_public: *const node_public_mod.EthereumLeafAuthorityV2,
};

pub const ColdReadmissionInputV1 = struct {
    profile: *const node_profile.NodeProfileV1,
    left: ColdLeafInputV1,
    right: ColdLeafInputV1,
};

/// Pointer-free algebraic/custody projection of one freshly verified leaf.
/// Structural validation is intentionally weaker than live verification.
pub const LeafAuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    reserved: u32 = 0,
    source_authority_sha256: [32]u8,
    source_public_statement_sha256: [32]u8,
    journal_record_sha256: [32]u8,
    descriptor_sha256: [32]u8,
    descriptor_subtree_sha256: [32]u8,
    node_public_authority_sha256: [32]u8,
    node_public_subtree_sha256: [32]u8,
    node_public_subtree_digest: channel.Digest,
    metadata_words: global_v3.IdentityWords,
    verified_link_words: link_v3.IdentityWords,
    global_statement_words: span.StatementWords,
    local_statement_words: span.StatementWords,
    transcript_claimed_sums: [link_program.TRANSCRIPT_CLAIM_COUNT]QM31,
    child_component_count: u32,
    child_infra_count: u32,
    child_router_row_count: u32,
    child_authority_word_count: u32,
    vm_field_authority: program_field.AuthorityV1,
    public_authority_digests: [PUBLIC_AUTHORITY_DIGEST_COUNT]channel.Digest,
    local_wire_word_count: u32,
    local_wire_sha256: [32]u8,
    proof_artifact_byte_count: u64,
    proof_artifact_sha256: [32]u8,
    proof_root_sha256: [32]u8,
    transcript_state_sha256: [32]u8,
    proof_capture_sha256: [32]u8,
    capture_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validate(self: *const LeafAuthorityV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.reserved != 0 or
            self.proof_artifact_byte_count == 0 or
            self.local_wire_word_count == 0)
        {
            return error.InvalidEthereumPoseidonH1Leaf;
        }
        inline for (.{
            self.source_authority_sha256,
            self.source_public_statement_sha256,
            self.journal_record_sha256,
            self.descriptor_sha256,
            self.descriptor_subtree_sha256,
            self.node_public_authority_sha256,
            self.node_public_subtree_sha256,
            self.local_wire_sha256,
            self.proof_artifact_sha256,
            self.proof_root_sha256,
            self.transcript_state_sha256,
            self.proof_capture_sha256,
            self.capture_identity_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        try requireDigest(self.node_public_subtree_digest);
        try self.vm_field_authority.validate();
        for (self.metadata_words) |word| try requireM31(word);
        for (self.verified_link_words) |word| try requireM31(word);
        for (self.transcript_claimed_sums) |value|
            for (value.toM31Array()) |word| try requireM31(word);
        for (self.public_authority_digests) |value| try requireDigest(value);

        const global_statement = try span.SpanStatement.fromCanonicalWords(
            &self.global_statement_words,
        );
        const local_statement = try span.SpanStatement.fromCanonicalWords(
            &self.local_statement_words,
        );
        if (global_statement.slots.height != 0 or
            local_statement.slots.height != 0 or
            !std.meta.eql(
                self.global_statement_words,
                self.metadata_words[link_program.METADATA_BASE_START..][0..span.SPAN_STATEMENT_CANONICAL_WORDS].*,
            ) or self.verified_link_words[0].toU32() != link_v3.FORMAT_VERSION or
            self.verified_link_words[1].toU32() != link_v3.SCHEMA_VERSION)
        {
            return error.InvalidEthereumPoseidonH1Leaf;
        }
        const metadata_identity = channel.hashCanonicalWords(
            &self.metadata_words,
            global_v3.METADATA_ID_DOMAIN,
        );
        if (!digestEqualsWords(
            metadata_identity,
            self.verified_link_words[2..10],
        )) return error.InvalidEthereumPoseidonH1Leaf;
        const link_identity = channel.hashCanonicalWords(
            &self.verified_link_words,
            link_v3.IDENTITY_DOMAIN,
        );
        if (!std.meta.eql(
            link_identity,
            self.public_authority_digests[0],
        ) or !std.meta.eql(
            self.vm_field_authority.verifier_program_authority,
            self.public_authority_digests[1],
        )) return error.InvalidEthereumPoseidonH1Leaf;
        const descriptor_count = std.math.add(
            u32,
            self.child_component_count,
            self.child_infra_count,
        ) catch return error.InvalidEthereumPoseidonH1Leaf;
        const expected_router_rows = std.math.add(
            u32,
            @intCast(child_program.BASE_ROUTER_ROW_COUNT),
            std.math.mul(
                u32,
                descriptor_count,
                @intCast(child_program.WORDS_PER_DESCRIPTOR),
            ) catch return error.InvalidEthereumPoseidonH1Leaf,
        ) catch return error.InvalidEthereumPoseidonH1Leaf;
        const expected_authority_words = std.math.add(
            u32,
            @intCast(child_program.AUTHORITY_FIXED_WORD_COUNT),
            std.math.mul(
                u32,
                descriptor_count,
                @intCast(child_program.WORDS_PER_DESCRIPTOR),
            ) catch return error.InvalidEthereumPoseidonH1Leaf,
        ) catch return error.InvalidEthereumPoseidonH1Leaf;
        if (self.child_component_count == 0 or self.child_infra_count == 0 or
            self.child_router_row_count != expected_router_rows or
            self.child_authority_word_count != expected_authority_words or
            !std.mem.eql(u8, &self.identity_sha256, &leafIdentity(self)))
        {
            return error.InvalidEthereumPoseidonH1Leaf;
        }
    }
};

/// Canonically serializable custody.  Decoding this value never recreates
/// `VerifiedPoseidonV4` and therefore never produces `FreshIngressV1`.
pub const CustodyV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    height: u8 = 1,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: u16 = 0,
    air_contract: AirContractV1,
    h1_profile: H1ProfileBindingV1,
    children: [CHILD_COUNT]LeafAuthorityV1,
    parent_statement_words: span.StatementWords,
    parent_statement_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validate(self: *const CustodyV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.height != 1 or
            self.production_activation or self.reserved != 0)
        {
            return error.InvalidEthereumPoseidonH1Ingress;
        }
        try self.air_contract.validate();
        try self.h1_profile.validate();
        for (&self.children) |*child| try child.validate();
        const left = try span.SpanStatement.fromCanonicalWords(
            &self.children[0].global_statement_words,
        );
        const right = try span.SpanStatement.fromCanonicalWords(
            &self.children[1].global_statement_words,
        );
        const parent = try span.SpanStatement.fold(left, right);
        const parent_words = try parent.canonicalWords();
        if (parent.slots.height != 1 or
            !std.meta.eql(self.parent_statement_words, parent_words) or
            !std.mem.eql(
                u8,
                &self.parent_statement_sha256,
                &statement_plan.statementSha256(&parent_words),
            ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &ingressIdentity(self),
        )) return error.InvalidEthereumPoseidonH1Ingress;
    }

    pub fn encodeCanonical(self: *const CustodyV1) ![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeCustody(&writer, self);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !CustodyV1 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidEthereumPoseidonH1Ingress;
        var reader = Reader{ .bytes = bytes };
        const result = try readCustody(&reader);
        if (reader.at != bytes.len)
            return error.InvalidEthereumPoseidonH1Ingress;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidEthereumPoseidonH1Ingress;
        return result;
    }
};

/// Non-serializable live result.  Its only constructor is the verifier success
/// edge below (or the cold path, which invokes that same edge after verifying
/// both retained proofs).
pub const FreshIngressV1 = struct {
    custody: CustodyV1,

    pub fn validateAgainst(
        self: *const FreshIngressV1,
        allocator: std.mem.Allocator,
        input: FreshMintInputV1,
    ) !void {
        const expected = try buildCustody(allocator, input);
        if (!std.meta.eql(self.custody, expected))
            return error.EthereumPoseidonH1FreshAuthorityMismatch;
    }

    pub fn requireProductionPublication(
        self: *const FreshIngressV1,
        allocator: std.mem.Allocator,
        input: FreshMintInputV1,
    ) !void {
        try self.validateAgainst(allocator, input);
        for (MISSING_PRODUCTION_PREDICATES) |predicate|
            try requireProductionPredicate(predicate);
        if (!PRODUCTION_ACTIVATION)
            return error.EthereumPoseidonH1PublicationUnavailable;
    }
};

pub fn mintFromFreshVerifier(
    allocator: std.mem.Allocator,
    input: FreshMintInputV1,
) !FreshIngressV1 {
    return .{ .custody = try buildCustody(allocator, input) };
}

pub fn coldReadmit(
    allocator: std.mem.Allocator,
    expected: *const CustodyV1,
    input: ColdReadmissionInputV1,
) !FreshIngressV1 {
    try expected.validate();
    const left_source = try source_wire.decode(input.left.source_bytes);
    const right_source = try source_wire.decode(input.right.source_bytes);
    var left_verified = try leaf_support.verifyPoseidonArtifactWithCapture(
        allocator,
        input.left.proof_bytes,
        &left_source,
    );
    defer left_verified.deinit(allocator);
    var right_verified = try leaf_support.verifyPoseidonArtifactWithCapture(
        allocator,
        input.right.proof_bytes,
        &right_source,
    );
    defer right_verified.deinit(allocator);
    const fresh = try mintFromFreshVerifier(allocator, .{
        .profile = input.profile,
        .left = .{
            .verified = &left_verified,
            .source = &left_source,
            .descriptor = &input.left.node_public.descriptor,
            .node_public = input.left.node_public,
        },
        .right = .{
            .verified = &right_verified,
            .source = &right_source,
            .descriptor = &input.right.node_public.descriptor,
            .node_public = input.right.node_public,
        },
    });
    if (!std.meta.eql(fresh.custody, expected.*))
        return error.EthereumPoseidonH1ColdReadmissionMismatch;
    return fresh;
}

pub fn requireProductionPredicate(
    predicate: PublicationPredicateV1,
) !void {
    switch (predicate) {
        .secure_parent_proof_policy => {
            if (!SECURE_PARENT_PROOF_POLICY_AVAILABLE)
                return error.SecureParentProofPolicyUnavailable;
        },
        .verifier_minted_h1_profile => {
            if (!VERIFIER_MINTED_H1_PROFILE_AVAILABLE)
                return error.VerifierMintedH1ProfileUnavailable;
        },
        .canonical_parent_proof_codec => {
            if (!CANONICAL_PARENT_PROOF_CODEC_AVAILABLE)
                return error.CanonicalParentProofCodecUnavailable;
        },
    }
}

fn buildCustody(
    allocator: std.mem.Allocator,
    input: FreshMintInputV1,
) !CustodyV1 {
    const h1_profile = try bindProfile(input.profile);
    try global_v3.requireAdjacentMetadata(
        &input.left.source.metadata,
        &input.right.source.metadata,
    );
    const children = [CHILD_COUNT]LeafAuthorityV1{
        try buildLeaf(allocator, input.left),
        try buildLeaf(allocator, input.right),
    };
    const left = try span.SpanStatement.fromCanonicalWords(
        &children[0].global_statement_words,
    );
    const right = try span.SpanStatement.fromCanonicalWords(
        &children[1].global_statement_words,
    );
    const parent = try span.SpanStatement.fold(left, right);
    const parent_words = try parent.canonicalWords();
    var result = CustodyV1{
        .air_contract = fixedAirContract(),
        .h1_profile = h1_profile,
        .children = children,
        .parent_statement_words = parent_words,
        .parent_statement_sha256 = statement_plan.statementSha256(&parent_words),
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = ingressIdentity(&result);
    try result.validate();
    return result;
}

fn bindProfile(
    profile: *const node_profile.NodeProfileV1,
) !H1ProfileBindingV1 {
    try profile.validate();
    if (profile.kind != .real_parent_h1 or profile.parent_height != 1 or
        profile.admitted_child_security.kind !=
            .ethereum_segment_v3_poseidon2)
    {
        return error.InvalidEthereumPoseidonH1Profile;
    }
    var result = H1ProfileBindingV1{
        .admitted_child_security_kind = profile.admitted_child_security.kind,
        .parent_proof_security_kind = profile.parent_proof_security.kind,
        .node_profile_sha256 = profile.identity,
        .child_composition_manifest_sha256 = profile.child_composition_manifest_sha_id,
        .parent_outer_manifest_sha256 = profile.manifest_sha_id,
        .admitted_child_security_sha256 = profile.admitted_child_security.identity,
        .parent_proof_security_sha256 = profile.parent_proof_security.identity,
        .verification_key_id = profile.verification_key_id,
        .next_parent_vk_id = profile.next_parent_vk_id,
        .air_program_id = profile.air_program_id,
        .profile_id = profile.profile_id,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = profileBindingIdentity(&result);
    try result.validate();
    return result;
}

fn buildLeaf(
    allocator: std.mem.Allocator,
    input: FreshLeafInputV1,
) !LeafAuthorityV1 {
    try input.verified.validateAgainst(input.source);
    try input.descriptor.validateAgainst(
        input.source,
        &input.verified.verifier_program.program,
    );
    try input.node_public.validate();
    if (!std.meta.eql(input.verified.leaf_descriptor, input.descriptor.*) or
        !std.meta.eql(input.node_public.descriptor, input.descriptor.*) or
        !std.meta.eql(input.node_public.metadata, input.source.metadata))
    {
        return error.EthereumPoseidonH1LeafAuthorityMismatch;
    }
    const capture = &input.verified.capture;
    var lookup_manifest = frontend.air.lookup_physical_manifest_v2.Manifest.native();
    const authenticated_lookup = try frontend.air.lookup_physical_manifest_v2
        .AuthenticatedStatement.init(
        &capture.core_statement.core,
        &lookup_manifest,
    );
    const field_authority = try program_field.compile(
        allocator,
        &input.verified.verifier_program.program,
        .{
            .core_statement = &capture.core_statement.core,
            .extension_statement = &capture.extension_statement,
            .lookup_manifest = &lookup_manifest,
            .authenticated_lookup = &authenticated_lookup,
            .base_profile = &capture.base.vm_air.profile,
        },
    );
    const local_view = try recursion.segment_statement_v2
        .authenticateCanonicalWire(capture.base.public_data.data.words());
    const local_statement = try local_view.statement.base();
    var transcript_claimed_sums: [link_program.TRANSCRIPT_CLAIM_COUNT]QM31 = undefined;
    const base_claim_count = capture.base.vm_air.canonical_claims.len;
    if (base_claim_count + capture.extension_context.components.len !=
        transcript_claimed_sums.len)
    {
        return error.EthereumPoseidonH1LeafAuthorityMismatch;
    }
    @memcpy(
        transcript_claimed_sums[0..base_claim_count],
        &capture.base.vm_air.canonical_claims,
    );
    for (
        capture.extension_context.components,
        transcript_claimed_sums[base_claim_count..],
    ) |component, *destination| destination.* = component.component_sum;

    const source_bytes = try source_wire.encodeValue(input.source);
    const metadata_words = try capture.global_metadata.identityWords();
    const link_words = try capture.verified_link.identityWords();
    const core_statement = &capture.core_statement.core;
    const component_count = std.math.cast(u32, core_statement.n_components) orelse
        return error.EthereumPoseidonH1LeafAuthorityMismatch;
    const infra_count = std.math.cast(u32, core_statement.n_infra) orelse
        return error.EthereumPoseidonH1LeafAuthorityMismatch;
    const descriptor_count = std.math.add(u32, component_count, infra_count) catch
        return error.EthereumPoseidonH1LeafAuthorityMismatch;
    const router_rows = std.math.add(
        u32,
        @intCast(child_program.BASE_ROUTER_ROW_COUNT),
        std.math.mul(
            u32,
            descriptor_count,
            @intCast(child_program.WORDS_PER_DESCRIPTOR),
        ) catch return error.EthereumPoseidonH1LeafAuthorityMismatch,
    ) catch return error.EthereumPoseidonH1LeafAuthorityMismatch;
    const authority_words = std.math.add(
        u32,
        @intCast(child_program.AUTHORITY_FIXED_WORD_COUNT),
        std.math.mul(
            u32,
            descriptor_count,
            @intCast(child_program.WORDS_PER_DESCRIPTOR),
        ) catch return error.EthereumPoseidonH1LeafAuthorityMismatch,
    ) catch return error.EthereumPoseidonH1LeafAuthorityMismatch;
    const local_words = capture.base.public_data.data.words();
    const local_word_count = std.math.cast(u32, local_words.len) orelse
        return error.EthereumPoseidonH1LeafAuthorityMismatch;
    const provider = &input.node_public.provider;
    var result = LeafAuthorityV1{
        .source_authority_sha256 = sha256(&source_bytes),
        .source_public_statement_sha256 = input.descriptor.source_public_statement_sha256,
        .journal_record_sha256 = input.source.journal_record_sha256,
        .descriptor_sha256 = input.descriptor.descriptor_sha256,
        .descriptor_subtree_sha256 = input.descriptor.subtree_sha256,
        .node_public_authority_sha256 = input.node_public.authority_sha256,
        .node_public_subtree_sha256 = input.node_public.subtree_sha256,
        .node_public_subtree_digest = input.node_public.subtree_digest,
        .metadata_words = metadata_words,
        .verified_link_words = link_words,
        .global_statement_words = capture.global_metadata.base_statement_words,
        .local_statement_words = try local_statement.canonicalWords(),
        .transcript_claimed_sums = transcript_claimed_sums,
        .child_component_count = component_count,
        .child_infra_count = infra_count,
        .child_router_row_count = router_rows,
        .child_authority_word_count = authority_words,
        .vm_field_authority = field_authority,
        .public_authority_digests = .{
            capture.verified_link.identity,
            field_authority.verifier_program_authority,
            input.descriptor.program.preprocessed_commitment_root,
            provider.relation_context_digest,
            provider.core_claim_digest,
            provider.shard_manifest_digest,
            provider.aggregate_cancellation_digest,
        },
        .local_wire_word_count = local_word_count,
        .local_wire_sha256 = localWireSha256(local_words),
        .proof_artifact_byte_count = input.verified.proof_artifact_byte_count,
        .proof_artifact_sha256 = input.verified.proof_artifact_sha256,
        .proof_root_sha256 = input.verified.root_sha256,
        .transcript_state_sha256 = input.verified.transcript_state_sha256,
        .proof_capture_sha256 = capture.proof_capture_sha256,
        .capture_identity_sha256 = capture.identity_digest,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = leafIdentity(&result);
    try result.validate();
    return result;
}

fn fixedAirContract() AirContractV1 {
    var result = AirContractV1{
        .source_row_count = link_program.SOURCE_ROW_COUNT,
        .projection_row_count = link_program.PROJECTION_ROW_COUNT,
        .poseidon_call_count = link_program.POSEIDON_CALL_COUNT,
        .transcript_claim_count = link_program.TRANSCRIPT_CLAIM_COUNT,
        .child_router_base_row_count = child_program.BASE_ROUTER_ROW_COUNT,
        .child_router_words_per_descriptor = child_program.WORDS_PER_DESCRIPTOR,
        .components = .{
            airBinding(.ethereum_link_source, source_air),
            airBinding(.ethereum_link_projection, projection_air),
            airBinding(.ethereum_child_field_router, child_router_air),
            airBinding(.poseidon_preimage_hash, hash_air),
        },
        .required_leaf_security_sha256 = proof_security.ProofSecurityV1
            .ethereumSegmentV3Poseidon2().identity,
        .required_parent_security_sha256 = proof_security.ProofSecurityV1
            .recursiveParentSecure().identity,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = airContractIdentity(&result);
    return result;
}

fn airBinding(
    kind: AirComponentKindV1,
    comptime Component: type,
) AirComponentBindingV1 {
    return .{
        .kind = kind,
        .main_columns = Component.PHYSICAL_MAIN_COLUMN_COUNT,
        .preprocessed_columns = Component.PREPROCESSED_COLUMN_COUNT,
        .interaction_columns = Component.INTERACTION_COLUMN_COUNT,
        .maximum_constraint_degree = Component.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = Component.SEMANTIC_DIGEST,
    };
}

fn localWireSha256(words: []const M31) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LOCAL_WIRE_DOMAIN);
    hashInt(&hash, u32, @as(u32, @intCast(words.len)));
    for (words) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn airContractIdentity(value: *const AirContractV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AIR_CONTRACT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u16, value.component_count);
    hashInt(&hash, u16, value.reserved);
    inline for (.{
        value.source_row_count,
        value.projection_row_count,
        value.poseidon_call_count,
        value.transcript_claim_count,
        value.child_router_base_row_count,
        value.child_router_words_per_descriptor,
    }) |item| hashInt(&hash, u32, item);
    for (value.components) |component| hashAirBinding(&hash, component);
    hash.update(&value.required_leaf_security_sha256);
    hash.update(&value.required_parent_security_sha256);
    return hash.finalResult();
}

fn leafIdentity(value: *const LeafAuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LEAF_DOMAIN);
    var buffer: [LEAF_ENCODED_BYTE_COUNT - 32]u8 = undefined;
    var writer = Writer{ .bytes = &buffer };
    writeLeafWithoutIdentity(&writer, value);
    std.debug.assert(writer.at == buffer.len);
    hash.update(&buffer);
    return hash.finalResult();
}

fn ingressIdentity(value: *const CustodyV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(INGRESS_DOMAIN);
    hash.update(&value.air_contract.identity_sha256);
    hash.update(&value.h1_profile.identity_sha256);
    for (value.children) |child| hash.update(&child.identity_sha256);
    for (value.parent_statement_words) |word|
        hashInt(&hash, u32, word.toU32());
    hash.update(&value.parent_statement_sha256);
    return hash.finalResult();
}

fn profileBindingIdentity(value: *const H1ProfileBindingV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PROFILE_BINDING_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u8, value.parent_height);
    hashInt(&hash, u8, @intFromEnum(value.admitted_child_security_kind));
    hashInt(&hash, u8, @intFromEnum(value.parent_proof_security_kind));
    inline for (.{
        value.node_profile_sha256,
        value.child_composition_manifest_sha256,
        value.parent_outer_manifest_sha256,
        value.admitted_child_security_sha256,
        value.parent_proof_security_sha256,
    }) |item| hash.update(&item);
    inline for (.{
        value.verification_key_id,
        value.next_parent_vk_id,
        value.air_program_id,
        value.profile_id,
    }) |item| hashDigest(&hash, item);
    return hash.finalResult();
}

const AIR_BINDING_ENCODED_BYTE_COUNT: usize = 52;
const AIR_CONTRACT_ENCODED_BYTE_COUNT: usize = 336;
const PROFILE_BINDING_ENCODED_BYTE_COUNT: usize = 328;
const LEAF_ENCODED_BYTE_COUNT: usize = 7416;
pub const ENCODED_BYTE_COUNT: usize = 17_216;

fn writeCustody(writer: *Writer, value: *const CustodyV1) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(value.height);
    writer.u8Value(@intFromBool(value.production_activation));
    writer.u16Value(value.reserved);
    writeAirContract(writer, &value.air_contract);
    writeProfileBinding(writer, value.h1_profile);
    for (&value.children) |*child| writeLeaf(writer, child);
    writer.m31s(&value.parent_statement_words);
    writer.sha(value.parent_statement_sha256);
    writer.sha(value.identity_sha256);
}

fn writeProfileBinding(writer: *Writer, value: H1ProfileBindingV1) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromEnum(value.kind));
    writer.u8Value(value.parent_height);
    writer.u8Value(@intFromEnum(value.admitted_child_security_kind));
    writer.u8Value(@intFromEnum(value.parent_proof_security_kind));
    inline for (.{
        value.node_profile_sha256,
        value.child_composition_manifest_sha256,
        value.parent_outer_manifest_sha256,
        value.admitted_child_security_sha256,
        value.parent_proof_security_sha256,
    }) |item| writer.sha(item);
    inline for (.{
        value.verification_key_id,
        value.next_parent_vk_id,
        value.air_program_id,
        value.profile_id,
    }) |item| writer.digest(item);
    writer.sha(value.identity_sha256);
}

fn writeAirContract(writer: *Writer, value: *const AirContractV1) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u16Value(value.component_count);
    writer.u16Value(value.reserved);
    inline for (.{
        value.source_row_count,
        value.projection_row_count,
        value.poseidon_call_count,
        value.transcript_claim_count,
        value.child_router_base_row_count,
        value.child_router_words_per_descriptor,
    }) |item| writer.u32Value(item);
    for (value.components) |component| writeAirBinding(writer, component);
    writer.sha(value.required_leaf_security_sha256);
    writer.sha(value.required_parent_security_sha256);
    writer.sha(value.identity_sha256);
}

fn writeAirBinding(writer: *Writer, value: AirComponentBindingV1) void {
    writer.u8Value(@intFromEnum(value.kind));
    writer.bytesValue(&value.reserved);
    writer.u32Value(value.main_columns);
    writer.u32Value(value.preprocessed_columns);
    writer.u32Value(value.interaction_columns);
    writer.u32Value(value.maximum_constraint_degree);
    writer.sha(value.semantic_digest);
}

fn writeLeaf(writer: *Writer, value: *const LeafAuthorityV1) void {
    writeLeafWithoutIdentity(writer, value);
    writer.sha(value.identity_sha256);
}

fn writeLeafWithoutIdentity(writer: *Writer, value: *const LeafAuthorityV1) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u32Value(value.reserved);
    inline for (.{
        value.source_authority_sha256,
        value.source_public_statement_sha256,
        value.journal_record_sha256,
        value.descriptor_sha256,
        value.descriptor_subtree_sha256,
        value.node_public_authority_sha256,
        value.node_public_subtree_sha256,
    }) |item| writer.sha(item);
    writer.digest(value.node_public_subtree_digest);
    writer.m31s(&value.metadata_words);
    writer.m31s(&value.verified_link_words);
    writer.m31s(&value.global_statement_words);
    writer.m31s(&value.local_statement_words);
    for (value.transcript_claimed_sums) |item| writer.qm31Value(item);
    writer.u32Value(value.child_component_count);
    writer.u32Value(value.child_infra_count);
    writer.u32Value(value.child_router_row_count);
    writer.u32Value(value.child_authority_word_count);
    writeFieldAuthority(writer, value.vm_field_authority);
    for (value.public_authority_digests) |item| writer.digest(item);
    writer.u32Value(value.local_wire_word_count);
    writer.sha(value.local_wire_sha256);
    writer.u64Value(value.proof_artifact_byte_count);
    inline for (.{
        value.proof_artifact_sha256,
        value.proof_root_sha256,
        value.transcript_state_sha256,
        value.proof_capture_sha256,
        value.capture_identity_sha256,
    }) |item| writer.sha(item);
}

fn writeFieldAuthority(
    writer: *Writer,
    value: program_field.AuthorityV1,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u32Value(value.program_word_count);
    writer.u32Value(value.manifest_word_count);
    writer.digest(value.verifier_program_authority);
    writer.digest(value.component_manifest_authority);
}

fn readCustody(reader: *Reader) !CustodyV1 {
    var result = CustodyV1{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .height = reader.u8Value(),
        .production_activation = try reader.boolValue(),
        .reserved = reader.u16Value(),
        .air_contract = try readAirContract(reader),
        .h1_profile = try readProfileBinding(reader),
        .children = undefined,
        .parent_statement_words = undefined,
        .parent_statement_sha256 = undefined,
        .identity_sha256 = undefined,
    };
    for (&result.children) |*child| child.* = try readLeaf(reader);
    try reader.m31s(&result.parent_statement_words);
    result.parent_statement_sha256 = reader.sha();
    result.identity_sha256 = reader.sha();
    return result;
}

fn readProfileBinding(reader: *Reader) !H1ProfileBindingV1 {
    return .{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .kind = std.meta.intToEnum(
            node_profile.KindV1,
            reader.u8Value(),
        ) catch return error.InvalidEthereumPoseidonH1Profile,
        .parent_height = reader.u8Value(),
        .admitted_child_security_kind = std.meta.intToEnum(
            proof_security.KindV1,
            reader.u8Value(),
        ) catch return error.InvalidEthereumPoseidonH1Profile,
        .parent_proof_security_kind = std.meta.intToEnum(
            proof_security.KindV1,
            reader.u8Value(),
        ) catch return error.InvalidEthereumPoseidonH1Profile,
        .node_profile_sha256 = reader.sha(),
        .child_composition_manifest_sha256 = reader.sha(),
        .parent_outer_manifest_sha256 = reader.sha(),
        .admitted_child_security_sha256 = reader.sha(),
        .parent_proof_security_sha256 = reader.sha(),
        .verification_key_id = reader.digest(),
        .next_parent_vk_id = reader.digest(),
        .air_program_id = reader.digest(),
        .profile_id = reader.digest(),
        .identity_sha256 = reader.sha(),
    };
}

fn readAirContract(reader: *Reader) !AirContractV1 {
    var result = AirContractV1{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .component_count = reader.u16Value(),
        .reserved = reader.u16Value(),
        .source_row_count = reader.u32Value(),
        .projection_row_count = reader.u32Value(),
        .poseidon_call_count = reader.u32Value(),
        .transcript_claim_count = reader.u32Value(),
        .child_router_base_row_count = reader.u32Value(),
        .child_router_words_per_descriptor = reader.u32Value(),
        .components = undefined,
        .required_leaf_security_sha256 = undefined,
        .required_parent_security_sha256 = undefined,
        .identity_sha256 = undefined,
    };
    for (&result.components) |*component|
        component.* = try readAirBinding(reader);
    result.required_leaf_security_sha256 = reader.sha();
    result.required_parent_security_sha256 = reader.sha();
    result.identity_sha256 = reader.sha();
    return result;
}

fn readAirBinding(reader: *Reader) !AirComponentBindingV1 {
    return .{
        .kind = std.meta.intToEnum(
            AirComponentKindV1,
            reader.u8Value(),
        ) catch return error.InvalidEthereumPoseidonH1AirContract,
        .reserved = reader.array(3),
        .main_columns = reader.u32Value(),
        .preprocessed_columns = reader.u32Value(),
        .interaction_columns = reader.u32Value(),
        .maximum_constraint_degree = reader.u32Value(),
        .semantic_digest = reader.sha(),
    };
}

fn readLeaf(reader: *Reader) !LeafAuthorityV1 {
    var result = LeafAuthorityV1{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .reserved = reader.u32Value(),
        .source_authority_sha256 = reader.sha(),
        .source_public_statement_sha256 = reader.sha(),
        .journal_record_sha256 = reader.sha(),
        .descriptor_sha256 = reader.sha(),
        .descriptor_subtree_sha256 = reader.sha(),
        .node_public_authority_sha256 = reader.sha(),
        .node_public_subtree_sha256 = reader.sha(),
        .node_public_subtree_digest = reader.digest(),
        .metadata_words = undefined,
        .verified_link_words = undefined,
        .global_statement_words = undefined,
        .local_statement_words = undefined,
        .transcript_claimed_sums = undefined,
        .child_component_count = undefined,
        .child_infra_count = undefined,
        .child_router_row_count = undefined,
        .child_authority_word_count = undefined,
        .vm_field_authority = undefined,
        .public_authority_digests = undefined,
        .local_wire_word_count = undefined,
        .local_wire_sha256 = undefined,
        .proof_artifact_byte_count = undefined,
        .proof_artifact_sha256 = undefined,
        .proof_root_sha256 = undefined,
        .transcript_state_sha256 = undefined,
        .proof_capture_sha256 = undefined,
        .capture_identity_sha256 = undefined,
        .identity_sha256 = undefined,
    };
    try reader.m31s(&result.metadata_words);
    try reader.m31s(&result.verified_link_words);
    try reader.m31s(&result.global_statement_words);
    try reader.m31s(&result.local_statement_words);
    for (&result.transcript_claimed_sums) |*item|
        item.* = try reader.qm31Value();
    result.child_component_count = reader.u32Value();
    result.child_infra_count = reader.u32Value();
    result.child_router_row_count = reader.u32Value();
    result.child_authority_word_count = reader.u32Value();
    result.vm_field_authority = try readFieldAuthority(reader);
    for (&result.public_authority_digests) |*item|
        item.* = reader.digest();
    result.local_wire_word_count = reader.u32Value();
    result.local_wire_sha256 = reader.sha();
    result.proof_artifact_byte_count = reader.u64Value();
    result.proof_artifact_sha256 = reader.sha();
    result.proof_root_sha256 = reader.sha();
    result.transcript_state_sha256 = reader.sha();
    result.proof_capture_sha256 = reader.sha();
    result.capture_identity_sha256 = reader.sha();
    result.identity_sha256 = reader.sha();
    return result;
}

fn readFieldAuthority(reader: *Reader) !program_field.AuthorityV1 {
    const result = program_field.AuthorityV1{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .program_word_count = reader.u32Value(),
        .manifest_word_count = reader.u32Value(),
        .verifier_program_authority = reader.digest(),
        .component_manifest_authority = reader.digest(),
    };
    try result.validate();
    return result;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }
    fn sha(self: *Writer, value: [32]u8) void {
        self.bytesValue(&value);
    }
    fn digest(self: *Writer, value: channel.Digest) void {
        for (value) |word| self.u32Value(word);
    }
    fn m31s(self: *Writer, values: []const M31) void {
        for (values) |word| self.u32Value(word.toU32());
    }
    fn qm31Value(self: *Writer, value: QM31) void {
        self.m31s(&value.toM31Array());
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) []const u8 {
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }
    fn array(self: *Reader, comptime count: usize) [count]u8 {
        return self.take(count)[0..count].*;
    }
    fn u8Value(self: *Reader) u8 {
        const result = self.bytes[self.at];
        self.at += 1;
        return result;
    }
    fn boolValue(self: *Reader) !bool {
        return switch (self.u8Value()) {
            0 => false,
            1 => true,
            else => error.InvalidEthereumPoseidonH1Ingress,
        };
    }
    fn u16Value(self: *Reader) u16 {
        return std.mem.readInt(u16, self.take(2)[0..2], .little);
    }
    fn u32Value(self: *Reader) u32 {
        return std.mem.readInt(u32, self.take(4)[0..4], .little);
    }
    fn u64Value(self: *Reader) u64 {
        return std.mem.readInt(u64, self.take(8)[0..8], .little);
    }
    fn sha(self: *Reader) [32]u8 {
        return self.array(32);
    }
    fn digest(self: *Reader) channel.Digest {
        var result: channel.Digest = undefined;
        for (&result) |*word| word.* = self.u32Value();
        return result;
    }
    fn m31s(self: *Reader, destination: []M31) !void {
        for (destination) |*word| {
            const value = self.u32Value();
            if (value >= core.fields.m31.Modulus)
                return error.InvalidEthereumPoseidonH1Ingress;
            word.* = M31.fromCanonical(value);
        }
    }
    fn qm31Value(self: *Reader) !QM31 {
        var limbs: [4]M31 = undefined;
        try self.m31s(&limbs);
        return QM31.fromM31Array(limbs);
    }
};

fn hashAirBinding(hash: *Sha256, value: AirComponentBindingV1) void {
    hashInt(hash, u8, @intFromEnum(value.kind));
    hash.update(&value.reserved);
    hashInt(hash, u32, value.main_columns);
    hashInt(hash, u32, value.preprocessed_columns);
    hashInt(hash, u32, value.interaction_columns);
    hashInt(hash, u32, value.maximum_constraint_degree);
    hash.update(&value.semantic_digest);
}

fn digestEqualsWords(digest: channel.Digest, words: []const M31) bool {
    if (words.len != digest.len) return false;
    for (digest, words) |expected, actual|
        if (actual.toU32() != expected) return false;
    return true;
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidEthereumPoseidonH1Ingress;
}

fn requireDigest(value: channel.Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= core.fields.m31.Modulus)
            return error.InvalidEthereumPoseidonH1Ingress;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidEthereumPoseidonH1Ingress;
}

fn requireM31(value: M31) !void {
    if (value.toU32() >= core.fields.m31.Modulus)
        return error.InvalidEthereumPoseidonH1Ingress;
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn fixedContract() AirContractV1 {
        requireTest();
        return fixedAirContract();
    }

    pub fn resealLeaf(value: *LeafAuthorityV1) void {
        requireTest();
        value.identity_sha256 = leafIdentity(value);
    }

    pub fn resealCustody(value: *CustodyV1) void {
        requireTest();
        value.identity_sha256 = ingressIdentity(value);
    }

    pub fn resealProfile(value: *H1ProfileBindingV1) void {
        requireTest();
        value.identity_sha256 = profileBindingIdentity(value);
    }

    pub fn localWireIdentity(words: []const M31) [32]u8 {
        requireTest();
        return localWireSha256(words);
    }

    fn requireTest() void {
        if (!builtin.is_test)
            @panic("Ethereum h1 testing helper used outside a test build");
    }
};

comptime {
    if (CHILD_COUNT != 2 or AIR_COMPONENT_COUNT != 4 or
        PUBLIC_AUTHORITY_DIGEST_COUNT != 7 or
        AIR_BINDING_ENCODED_BYTE_COUNT != 52 or
        AIR_CONTRACT_ENCODED_BYTE_COUNT != 336 or
        PROFILE_BINDING_ENCODED_BYTE_COUNT != 328 or
        LEAF_ENCODED_BYTE_COUNT != 7416 or ENCODED_BYTE_COUNT != 17_216 or
        link_program.TRANSCRIPT_CLAIM_COUNT != 42 or
        global_v3.METADATA_IDENTITY_WORDS != 608 or
        link_v3.IDENTITY_WORDS != 50 or PRODUCTION_ACTIVATION or
        SECURE_PARENT_PROOF_POLICY_AVAILABLE or
        VERIFIER_MINTED_H1_PROFILE_AVAILABLE or
        CANONICAL_PARENT_PROOF_CODEC_AVAILABLE)
    {
        @compileError("Ethereum Poseidon h1 ingress ABI drifted");
    }
}
