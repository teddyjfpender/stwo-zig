//! Field-native output of one freshly verified provider-shard child.
//!
//! This emitter is intended to run on the success edge of the native V2 fresh
//! verifier. It cold-recompiles the proof-independent child program, validates
//! the typed statement/claim against the admitted shard plan, and Poseidon-
//! hashes only canonical M31 data: graph semantics, protocol profile, roots,
//! relation challenges, and claims. Native SHA-256 identities remain transport
//! cross-checks and are deliberately absent from every field preimage.
//!
//! The result is not yet a recursive publication. A wrapper AIR must consume
//! these values for every dynamically counted shard and fresh verification
//! must bind its preprocessed commitment before production activation.

const std = @import("std");
const core = @import("stwo_core");

const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const provider_authority =
    @import("../prover/memory_provider_shards/authority.zig");
const provider_order =
    @import("../prover/memory_provider_shards/provider_order_component.zig");
const proof_authority =
    @import("../prover/memory_provider_shards/joint_proof_authority.zig");
const graph = @import("air/composition_circuit.zig");
const channel = @import("poseidon2_channel.zig");
const program_mod = @import("provider_shard_composition_program_v1.zig");
const protocol = @import("protocol.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROGRAM_DOMAIN: u32 = 0x5056_5031; // "PVP1"
pub const RELATION_DOMAIN: u32 = 0x5052_4332; // "PRC2"
pub const CLAIM_DOMAIN: u32 = 0x5053_4332; // "PSC2"
pub const INSTANCE_DOMAIN: u32 = 0x5053_4931; // "PSI1"
pub const WRAPPER_MANIFEST_DOMAIN: u32 = 0x5057_4d31; // "PWM1"
pub const WRAPPER_CANCELLATION_DOMAIN: u32 = 0x5057_4331; // "PWC1"
pub const WRAPPER_AUTHORITY_DOMAIN: u32 = 0x5057_4131; // "PWA1"
pub const PRODUCTION_ACTIVATION = false;

pub const VerifiedRootsV1 = struct {
    preprocessed_commitment_root: channel.Digest,
    main_commitment_root: channel.Digest,
    interaction_commitment_root: channel.Digest,
    composition_commitment_root: channel.Digest,

    pub fn validate(self: VerifiedRootsV1) !void {
        inline for (.{
            self.preprocessed_commitment_root,
            self.main_commitment_root,
            self.interaction_commitment_root,
            self.composition_commitment_root,
        }) |root| try requireDigest(root);
    }
};

/// Caller-owned transaction values. The native verifier must supply `roots`
/// directly from the proof it just accepted; no artifact SHA is accepted as a
/// substitute for any commitment.
pub const FreshVerifierInputV1 = struct {
    program: *const program_mod.ProviderShardCompositionProgramV1,
    compiler_input: program_mod.CompilerInputV1,
    statement: proof_authority.ProviderStatementV2,
    fresh_claim: proof_authority.FreshProviderClaimV2,
    relation: provider_authority.PoseidonRelationContextV1,
    roots: VerifiedRootsV1,
};

/// Proof-independent field projection of the cold-compiled child program.
/// It is distinct from every proof-instance root and claim.
pub const ProgramFieldAuthorityV1 = struct {
    word_count: u32,
    verifier_program_authority: channel.Digest,

    pub fn validate(self: ProgramFieldAuthorityV1) !void {
        if (self.word_count == 0)
            return error.InvalidProviderShardProgramFieldAuthority;
        try requireDigest(self.verifier_program_authority);
    }

    pub fn validateAgainst(
        self: ProgramFieldAuthorityV1,
        program: *const program_mod.ProviderShardCompositionProgramV1,
        compiler_input: program_mod.CompilerInputV1,
    ) !void {
        try self.validate();
        const expected = try compileProgramFieldAuthority(
            program,
            compiler_input,
        );
        if (!std.meta.eql(self, expected))
            return error.ProviderShardProgramFieldAuthorityMismatch;
    }
};

pub fn compileProgramFieldAuthority(
    program: *const program_mod.ProviderShardCompositionProgramV1,
    compiler_input: program_mod.CompilerInputV1,
) !ProgramFieldAuthorityV1 {
    try program.validateAgainst(compiler_input);
    var encoder = Encoder.init(PROGRAM_DOMAIN);
    try encodeProgram(&encoder, program);
    const encoded = encoder.finalize();
    const result = ProgramFieldAuthorityV1{
        .word_count = encoded.word_count,
        .verifier_program_authority = encoded.digest,
    };
    try result.validate();
    return result;
}

pub const ChildFieldAuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    program_word_count: u32,
    claim_word_count: u32,
    verifier_program_authority: channel.Digest,
    provider_relation_context: channel.Digest,
    provider_claim: channel.Digest,
    preprocessed_commitment_root: channel.Digest,
    main_commitment_root: channel.Digest,
    interaction_commitment_root: channel.Digest,
    composition_commitment_root: channel.Digest,
    verified_instance_authority: channel.Digest,

    pub fn validate(self: ChildFieldAuthorityV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.program_word_count == 0 or self.claim_word_count == 0)
        {
            return error.InvalidProviderShardFieldAuthority;
        }
        inline for (.{
            self.verifier_program_authority,
            self.provider_relation_context,
            self.provider_claim,
            self.preprocessed_commitment_root,
            self.main_commitment_root,
            self.interaction_commitment_root,
            self.composition_commitment_root,
            self.verified_instance_authority,
        }) |value| try requireDigest(value);
    }

    pub fn validateAgainst(
        self: ChildFieldAuthorityV1,
        input: FreshVerifierInputV1,
    ) !void {
        try self.validate();
        const expected = try emitUnchecked(input);
        if (!std.meta.eql(self, expected))
            return error.ProviderShardFieldAuthorityMismatch;
    }
};

/// One transaction-local child supplied to the dynamic wrapper boundary.
/// The verifier program remains shard-local and contains no shard-count
/// constant; only this ordered slice determines N.
pub const VerifiedWrapperChildV1 = struct {
    authority: ChildFieldAuthorityV1,
    verifier_input: FreshVerifierInputV1,
};

pub const WrapperManifestInputV1 = struct {
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    relation: provider_authority.PoseidonRelationContextV1,
    core_claim: provider_authority.CorePoseidonClaimV1,
    children: []const VerifiedWrapperChildV1,
};

/// Field-native dynamic-N manifest to be consumed by the future provider
/// wrapper AIR. It is not a proof receipt or recursive publication.
pub const WrapperManifestAuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    shard_count: u32,
    total_call_count: u64,
    manifest_word_count: u32,
    cancellation_word_count: u32,
    relation_context: channel.Digest,
    ordered_child_manifest: channel.Digest,
    core_claim: QM31,
    provider_claim: QM31,
    closed_sum: QM31,
    aggregate_cancellation: channel.Digest,
    wrapper_instance_authority: channel.Digest,

    pub fn validate(self: WrapperManifestAuthorityV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.shard_count == 0 or
            self.total_call_count == 0 or self.manifest_word_count == 0 or
            self.cancellation_word_count == 0 or !self.closed_sum.isZero() or
            !self.core_claim.add(self.provider_claim).eql(self.closed_sum))
        {
            return error.InvalidProviderWrapperManifest;
        }
        inline for (.{
            self.relation_context,
            self.ordered_child_manifest,
            self.aggregate_cancellation,
            self.wrapper_instance_authority,
        }) |value| try requireDigest(value);
    }

    pub fn validateAgainst(
        self: WrapperManifestAuthorityV1,
        input: WrapperManifestInputV1,
    ) !void {
        try self.validate();
        const expected = try emitWrapperManifestUnchecked(input);
        if (!std.meta.eql(self, expected))
            return error.ProviderWrapperManifestMismatch;
    }
};

pub fn compileWrapperManifest(
    input: WrapperManifestInputV1,
) !WrapperManifestAuthorityV1 {
    try validateWrapperManifestInput(input);
    const result = try emitWrapperManifestUnchecked(input);
    try result.validateAgainst(input);
    return result;
}

/// Must be invoked transaction-locally after `verifyProviderFreshV2` succeeds.
/// The API validates the retained fresh receipt but does not turn its native
/// boolean into recursive authority; that authority comes only when wrapper
/// AIR rows consume this result.
pub fn emitFromFreshVerifier(
    input: FreshVerifierInputV1,
) !ChildFieldAuthorityV1 {
    try validateInput(input);
    const result = try emitUnchecked(input);
    try result.validateAgainst(input);
    return result;
}

fn emitWrapperManifestUnchecked(
    input: WrapperManifestInputV1,
) !WrapperManifestAuthorityV1 {
    try validateWrapperManifestInput(input);
    var manifest_encoder = Encoder.init(WRAPPER_MANIFEST_DOMAIN);
    try manifest_encoder.word(FORMAT_VERSION);
    try manifest_encoder.word(SCHEMA_VERSION);
    try manifest_encoder.word(input.plan.shard_count);
    try manifest_encoder.u64Value(input.plan.total_call_count);
    const relation_context = input.children[0].authority.provider_relation_context;
    try manifest_encoder.digest(relation_context);
    var provider_claim = QM31.zero();
    for (input.children, input.plan.shards, 0..) |child, descriptor, index| {
        try manifest_encoder.word(index);
        try manifest_encoder.u64Value(descriptor.first_call);
        try manifest_encoder.word(descriptor.call_count);
        try manifest_encoder.word(descriptor.expected_log_size);
        try manifest_encoder.digest(child.authority.verifier_program_authority);
        try manifest_encoder.digest(child.authority.provider_relation_context);
        try manifest_encoder.digest(child.authority.provider_claim);
        try manifest_encoder.digest(child.authority.preprocessed_commitment_root);
        try manifest_encoder.digest(child.authority.main_commitment_root);
        try manifest_encoder.digest(child.authority.interaction_commitment_root);
        try manifest_encoder.digest(child.authority.composition_commitment_root);
        try manifest_encoder.digest(child.authority.verified_instance_authority);
        provider_claim = provider_claim.add(
            child.verifier_input.statement.claims.total(),
        );
    }
    const manifest = manifest_encoder.finalize();
    const closed_sum = input.core_claim.claim.add(provider_claim);

    var cancellation_encoder = Encoder.init(WRAPPER_CANCELLATION_DOMAIN);
    try cancellation_encoder.digest(manifest.digest);
    try cancellation_encoder.digest(relation_context);
    try cancellation_encoder.qm31(input.core_claim.claim);
    try cancellation_encoder.qm31(provider_claim);
    try cancellation_encoder.qm31(closed_sum);
    const cancellation = cancellation_encoder.finalize();

    var authority_encoder = Encoder.init(WRAPPER_AUTHORITY_DOMAIN);
    try authority_encoder.digest(manifest.digest);
    try authority_encoder.digest(cancellation.digest);
    try authority_encoder.word(input.plan.shard_count);
    try authority_encoder.u64Value(input.plan.total_call_count);
    const authority = authority_encoder.finalize();
    const result = WrapperManifestAuthorityV1{
        .shard_count = input.plan.shard_count,
        .total_call_count = input.plan.total_call_count,
        .manifest_word_count = manifest.word_count,
        .cancellation_word_count = cancellation.word_count,
        .relation_context = relation_context,
        .ordered_child_manifest = manifest.digest,
        .core_claim = input.core_claim.claim,
        .provider_claim = provider_claim,
        .closed_sum = closed_sum,
        .aggregate_cancellation = cancellation.digest,
        .wrapper_instance_authority = authority.digest,
    };
    try result.validate();
    return result;
}

fn emitUnchecked(input: FreshVerifierInputV1) !ChildFieldAuthorityV1 {
    try validateInput(input);
    const program = try compileProgramFieldAuthority(
        input.program,
        input.compiler_input,
    );

    var relation_encoder = Encoder.init(RELATION_DOMAIN);
    try relation_encoder.qm31(input.relation.z);
    try relation_encoder.qm31(input.relation.alpha);
    const relation = relation_encoder.finalize();

    var claim_encoder = Encoder.init(CLAIM_DOMAIN);
    try claim_encoder.digest(program.verifier_program_authority);
    try claim_encoder.digest(relation.digest);
    try encodeGeometry(&claim_encoder, input.program.geometry);
    try claim_encoder.word(input.statement.shard_index);
    for (input.statement.claims.sums) |claim| try claim_encoder.qm31(claim);
    try claim_encoder.qm31(input.statement.ordered_call_claim.terminal);
    const claim = claim_encoder.finalize();

    var instance_encoder = Encoder.init(INSTANCE_DOMAIN);
    try instance_encoder.digest(program.verifier_program_authority);
    try instance_encoder.digest(relation.digest);
    try instance_encoder.digest(claim.digest);
    inline for (.{
        input.roots.preprocessed_commitment_root,
        input.roots.main_commitment_root,
        input.roots.interaction_commitment_root,
        input.roots.composition_commitment_root,
    }) |root| try instance_encoder.digest(root);
    const instance = instance_encoder.finalize();

    const result = ChildFieldAuthorityV1{
        .program_word_count = program.word_count,
        .claim_word_count = claim.word_count,
        .verifier_program_authority = program.verifier_program_authority,
        .provider_relation_context = relation.digest,
        .provider_claim = claim.digest,
        .preprocessed_commitment_root = input.roots.preprocessed_commitment_root,
        .main_commitment_root = input.roots.main_commitment_root,
        .interaction_commitment_root = input.roots.interaction_commitment_root,
        .composition_commitment_root = input.roots.composition_commitment_root,
        .verified_instance_authority = instance.digest,
    };
    try result.validate();
    return result;
}

fn validateWrapperManifestInput(input: WrapperManifestInputV1) !void {
    try input.plan.validate(input.calls);
    try input.relation.validate(input.plan.session);
    if (input.children.len == 0 or
        input.children.len != input.plan.shards.len or
        !std.mem.eql(
            u8,
            &input.core_claim.plan_identity,
            &input.plan.identity,
        ) or !std.mem.eql(
        u8,
        &input.core_claim.relation_context_identity,
        &input.relation.identity,
    )) {
        return error.InvalidProviderWrapperManifest;
    }
    for (input.children, input.plan.shards, 0..) |child, descriptor, index| {
        const child_input = child.verifier_input;
        const child_index = std.math.cast(u32, index) orelse
            return error.InvalidProviderWrapperManifest;
        if (child_input.compiler_input.shard_index != child_index or
            child_input.compiler_input.plan.shards.len <= index or
            child_input.compiler_input.plan.shard_count !=
                input.plan.shard_count or
            !std.mem.eql(
                u8,
                &child_input.compiler_input.plan.identity,
                &input.plan.identity,
            ) or !callsEqual(child_input.compiler_input.calls, input.calls) or
            !std.meta.eql(
                child_input.compiler_input.plan.shards[index],
                descriptor,
            ) or !std.meta.eql(child_input.relation, input.relation))
        {
            return error.InvalidProviderWrapperManifest;
        }
        try child.authority.validateAgainst(child_input);
    }
}

fn callsEqual(
    left: []const poseidon2_air.Call,
    right: []const poseidon2_air.Call,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

fn validateInput(input: FreshVerifierInputV1) !void {
    try input.program.validateAgainst(input.compiler_input);
    try input.compiler_input.plan.validate(input.compiler_input.calls);
    try input.relation.validate(input.compiler_input.plan.session);
    try input.fresh_claim.validate();
    try input.roots.validate();
    const index: usize = @intCast(input.compiler_input.shard_index);
    if (index >= input.compiler_input.plan.shards.len)
        return error.InvalidProviderShardFieldAuthority;
    const descriptor = input.compiler_input.plan.shards[index];
    const first = std.math.cast(usize, descriptor.first_call) orelse
        return error.InvalidProviderShardFieldAuthority;
    const count = std.math.cast(usize, descriptor.call_count) orelse
        return error.InvalidProviderShardFieldAuthority;
    const end = std.math.add(usize, first, count) catch
        return error.InvalidProviderShardFieldAuthority;
    if (end > input.compiler_input.calls.len)
        return error.InvalidProviderShardFieldAuthority;
    var relations = relations_mod.Relations.dummy();
    relations.poseidon2 = relations_mod.RelationElements(16).init(
        input.relation.z,
        input.relation.alpha,
    );
    const expected_order = try provider_order.expectedClaim(
        descriptor.first_call,
        input.compiler_input.calls[first..end],
        &relations,
    );
    const expected_geometry =
        try proof_authority.ProviderTree2GeometryV2.canonical(
            descriptor.expected_log_size,
        );
    const statement = input.statement;
    const receipt = input.fresh_claim;
    if (statement.format != proof_authority.provider_format_version_v2 or
        statement.shard_index != input.compiler_input.shard_index or
        statement.first_call != descriptor.first_call or
        statement.call_count != descriptor.call_count or
        statement.log_size != descriptor.expected_log_size or
        !std.meta.eql(statement.tree2_geometry, expected_geometry) or
        statement.ordered_call_claim.format != provider_order.format_version or
        statement.ordered_call_claim.first_call != descriptor.first_call or
        statement.ordered_call_claim.call_count != descriptor.call_count or
        !std.meta.eql(statement.ordered_call_claim, expected_order) or
        !std.meta.eql(statement.claims, receipt.native_claim.claims) or
        !std.meta.eql(statement.ordered_call_claim, receipt.ordered_call_claim) or
        !std.mem.eql(u8, &statement.plan_identity, &input.compiler_input.plan.identity) or
        !std.mem.eql(u8, &statement.descriptor_identity, &descriptor.identity) or
        !std.mem.eql(u8, &statement.relation_context_identity, &input.relation.identity) or
        !std.mem.eql(
            u8,
            &statement.call_list_commitment,
            &input.compiler_input.plan.call_list_commitment,
        ) or !std.mem.eql(
        u8,
        &statement.identity,
        &proof_authority.providerStatementIdentityV2(statement),
    ) or !std.mem.eql(
        u8,
        &receipt.statement_identity,
        &statement.identity,
    ) or !std.mem.eql(
        u8,
        &receipt.manifest_identity,
        &statement.manifest_identity,
    ) or !std.mem.eql(
        u8,
        &receipt.native_claim.plan_identity,
        &input.compiler_input.plan.identity,
    ) or receipt.native_claim.shard_index !=
        input.compiler_input.shard_index or
        !std.mem.eql(
            u8,
            &receipt.native_claim.descriptor_identity,
            &descriptor.identity,
        ) or !std.mem.eql(
        u8,
        &receipt.native_claim.relation_context_identity,
        &input.relation.identity,
    )) {
        return error.InvalidProviderShardFieldAuthority;
    }
}

fn encodeProgram(
    encoder: *Encoder,
    program: *const program_mod.ProviderShardCompositionProgramV1,
) !void {
    try encoder.word(FORMAT_VERSION);
    try encoder.word(SCHEMA_VERSION);
    try encoder.word(program.format_version);
    try encoder.word(program.schema_version);
    try encoder.word(program_mod.CIRCUIT_ID);
    try encodeGeometry(encoder, program.geometry);
    try encodeInputProfile(encoder, program.input_profile);
    const profile = protocol.Profile{};
    try profile.validate();
    for (profile.words()) |word| try encoder.word(word);
    try encoder.digest(protocol.protocolId());

    try encoder.count(program.nodes.len);
    for (program.nodes) |node| try encodeNode(encoder, node);
    try encoder.count(program.outputs.len);
    for (program.outputs) |output| try encoder.word(output);
    try encoder.count(program.bindings.len);
    for (program.bindings) |binding| try encodeBinding(encoder, binding);
}

fn encodeGeometry(
    encoder: *Encoder,
    value: program_mod.SemanticGeometryV1,
) !void {
    try encoder.u64Value(value.first_call);
    try encoder.word(value.call_count);
    try encoder.word(value.log_size);
    try encoder.word(value.max_constraint_log_degree_bound);
    try encoder.word(value.composition_log_size);
    try encoder.word(value.composition_log_split);
}

fn encodeInputProfile(encoder: *Encoder, value: graph.InputProfile) !void {
    try encoder.word(value.sampled_value_count);
    try encoder.word(value.claimed_sum_count);
    try encoder.word(value.relation_challenge_count);
    try encoder.word(value.transcript_claimed_sum_count);
    try encoder.word(value.public_wire_boundary_count);
}

fn encodeNode(encoder: *Encoder, node: graph.Node) !void {
    var tag: u32 = undefined;
    var payload = [_]u32{0} ** 5;
    switch (node.op) {
        .input => tag = 1,
        .constant => |words| {
            tag = 2;
            @memcpy(payload[0..words.len], &words);
        },
        .add => |operands| {
            tag = 3;
            payload[0] = operands.lhs;
            payload[1] = operands.rhs;
        },
        .sub => |operands| {
            tag = 4;
            payload[0] = operands.lhs;
            payload[1] = operands.rhs;
        },
        .mul => |operands| {
            tag = 5;
            payload[0] = operands.lhs;
            payload[1] = operands.rhs;
        },
        .neg => |operand| {
            tag = 6;
            payload[0] = operand;
        },
        .inverse => |operand| {
            tag = 7;
            payload[0] = operand;
        },
    }
    try encoder.word(tag);
    for (payload) |word| try encoder.word(word);
}

fn encodeBinding(encoder: *Encoder, binding: graph.VmInputBinding) !void {
    try encoder.word(binding.node_id);
    var tag: u32 = undefined;
    var first: u32 = 0;
    var second: u32 = 0;
    switch (binding.source) {
        .segment_selector => tag = 1,
        .sampled_value => |coordinate| {
            tag = 2;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
        .claimed_sum => |coordinate| {
            tag = 3;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
        .relation_challenge => |coordinate| {
            tag = 4;
            first = coordinate.challenge;
            second = coordinate.word_index;
        },
        .composition_randomness => |word_index| {
            tag = 5;
            first = word_index;
        },
        .oods_point => |word_index| {
            tag = 6;
            first = word_index;
        },
        .transcript_claimed_sum => |coordinate| {
            tag = 7;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
    }
    try encoder.word(tag);
    try encoder.word(first);
    try encoder.word(second);
}

const EncodedDigest = struct {
    digest: channel.Digest,
    word_count: u32,
};

const Encoder = struct {
    hasher: channel.CanonicalWordHasher,
    word_count: u32 = 0,

    fn init(domain: u32) Encoder {
        return .{ .hasher = channel.CanonicalWordHasher.init(domain) };
    }

    fn word(self: *Encoder, value: anytype) !void {
        const canonical = std.math.cast(u32, value) orelse
            return error.NonCanonicalProviderShardFieldWord;
        if (canonical >= m31.Modulus)
            return error.NonCanonicalProviderShardFieldWord;
        self.hasher.update(&.{M31.fromCanonical(canonical)});
        self.word_count = std.math.add(u32, self.word_count, 1) catch
            return error.ProviderShardFieldAuthorityOverflow;
    }

    fn count(self: *Encoder, value: usize) !void {
        try self.word(std.math.cast(u32, value) orelse
            return error.ProviderShardFieldAuthorityOverflow);
    }

    fn u64Value(self: *Encoder, value: u64) !void {
        var remaining = value;
        for (0..5) |_| {
            try self.word(@as(u32, @intCast(remaining & 0x7fff)));
            remaining >>= 15;
        }
        if (remaining != 0)
            return error.NonCanonicalProviderShardFieldWord;
    }

    fn qm31(self: *Encoder, value: QM31) !void {
        for (value.toM31Array()) |limb| try self.word(limb.toU32());
    }

    fn digest(self: *Encoder, value: channel.Digest) !void {
        for (value) |limb| try self.word(limb);
    }

    fn finalize(self: *Encoder) EncodedDigest {
        return .{
            .digest = self.hasher.finalize(),
            .word_count = self.word_count,
        };
    }
};

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidProviderShardFieldAuthority;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.InvalidProviderShardFieldAuthority;
}

comptime {
    if (PROGRAM_DOMAIN >= m31.Modulus or RELATION_DOMAIN >= m31.Modulus or
        CLAIM_DOMAIN >= m31.Modulus or INSTANCE_DOMAIN >= m31.Modulus or
        program_mod.SAMPLED_VALUE_COUNT != 479 or
        proof_authority.provider_format_version_v2 != 2 or
        provider_order.format_version != 1 or PRODUCTION_ACTIVATION)
    {
        @compileError("provider-shard child field-emitter ABI drifted");
    }
}
