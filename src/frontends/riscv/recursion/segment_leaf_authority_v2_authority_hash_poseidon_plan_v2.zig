//! Internal segment leaf authority v2 authority shard; use segment_leaf_authority_v2.zig publicly.

const dependency_0 = @import("segment_leaf_authority_v2_contract.zig");
const dependency_1 = @import("segment_leaf_authority_v2_source_preflight_public_log_up_publication_v2.zig");

const AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT = dependency_0.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT;
const AUTHORITY_HASH_PLAN_ID_DOMAIN = dependency_0.AUTHORITY_HASH_PLAN_ID_DOMAIN;
const AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE = dependency_0.AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE;
const AUTHORITY_HASH_WORDS_PER_DESCRIPTOR = dependency_0.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const IdentityHasher = dependency_0.IdentityHasher;
const LOGUP_PUBLICATION_WORD_COUNT = dependency_0.LOGUP_PUBLICATION_WORD_COUNT;
const M31 = dependency_0.M31;
const NATIVE_PUBLICATION_ID_DOMAIN = dependency_0.NATIVE_PUBLICATION_ID_DOMAIN;
const NativeTemporalContextV2 = dependency_0.NativeTemporalContextV2;
const PUBLIC_LOGUP_V2_KIND = dependency_0.PUBLIC_LOGUP_V2_KIND;
const PreparedV2 = dependency_1.PreparedV2;
const PublicLogUpPublicationV2 = dependency_1.PublicLogUpPublicationV2;
const QM31 = dependency_0.QM31;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const SEGMENT_V2_VERIFIER_ID = dependency_0.SEGMENT_V2_VERIFIER_ID;
const ShaTupleEvidenceV2 = dependency_1.ShaTupleEvidenceV2;
const SourcePreflightPublicLogUpPublicationV2 = dependency_1.SourcePreflightPublicLogUpPublicationV2;
const VERIFIED_NATIVE_LOGUP_ID_DOMAIN = dependency_0.VERIFIED_NATIVE_LOGUP_ID_DOMAIN;
const VERIFIED_NATIVE_LOGUP_TAG = dependency_0.VERIFIED_NATIVE_LOGUP_TAG;
const VERIFIER_INPUT_RELATION_DOMAIN = dependency_0.VERIFIER_INPUT_RELATION_DOMAIN;
const channel = dependency_0.channel;
const derivePublicLogUp = dependency_1.derivePublicLogUp;
const logupPublicationId = dependency_1.logupPublicationId;
const m31 = dependency_0.m31;
const native_relations = dependency_0.native_relations;
const overlap = dependency_1.overlap;
const poseidon2 = dependency_0.poseidon2;
const poseidon2_air = dependency_0.poseidon2_air;
const preflight = dependency_1.preflight;
const public_data_v2 = dependency_0.public_data_v2;
const public_logup_v2 = dependency_0.public_logup_v2;
const relation = dependency_0.relation;
const relationContextId = dependency_1.relationContextId;
const requireDigest = dependency_0.requireDigest;
const statement_v1 = dependency_0.statement_v1;
const statement_v2 = dependency_0.statement_v2;
const std = dependency_0.std;
const validateNativeContextSelf = dependency_0.validateNativeContextSelf;
const verifierInputEvidence = dependency_1.verifierInputEvidence;
const writeLogUpWordsAssumeValid = dependency_1.writeLogUpWordsAssumeValid;

/// Exact native-verifier compensation admitted from a successful verifier
/// capture.  The full receipt and native-sum seals are retained as typed
/// fields, while their identities are folded into the final canonical word so
/// the 55-word verifier-input ABI remains fixed.
///
/// This is stronger than source preflight but still not an outer-proof
/// receipt: `productionReady` remains false until the authority hash program
/// and every other universal domain close inside a verified outer STARK.
pub const VerifiedNativePublicLogUpPublicationV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    wire_tag: u32 = VERIFIED_NATIVE_LOGUP_TAG,
    statement_version: u32 = public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
    source_id: Digest,
    authenticated_context_id: Digest,
    relation_context_id: Digest,
    statement_authority_id: Digest,
    statement_wire_id: Digest,
    receipt: statement_v2.VerifiedReceipt,
    native_public_sums_identity: Digest,
    native_relation_context_id: Digest,
    sums: public_logup_v2.Sums,
    total: QM31,
    identity: Digest,
    verifier_input_evidence: ShaTupleEvidenceV2,

    pub fn validate(
        self: *const VerifiedNativePublicLogUpPublicationV2,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.wire_tag != VERIFIED_NATIVE_LOGUP_TAG or
            self.statement_version != public_data_v2.STATEMENT_TRANSCRIPT_VERSION)
        {
            return error.UnsupportedVersion;
        }
        inline for (.{
            self.source_id,
            self.authenticated_context_id,
            self.relation_context_id,
            self.statement_authority_id,
            self.statement_wire_id,
            self.receipt.identity,
            self.native_public_sums_identity,
            self.native_relation_context_id,
            self.identity,
        }) |digest| try requireDigest(digest);
        if (!std.meta.eql(self.receipt.authority_id, self.statement_authority_id) or
            !std.meta.eql(self.receipt.wire_id, self.statement_wire_id) or
            !self.total.eql(self.sums.total()) or
            !std.meta.eql(self.identity, verifiedNativeLogupPublicationId(self)))
        {
            return error.NativeVerifierCustodyMismatch;
        }
        try self.verifier_input_evidence.validate();
        const expected_evidence = verifierInputEvidence(self);
        if (!std.meta.eql(expected_evidence, self.verifier_input_evidence))
            return error.InvalidPublication;
    }

    pub fn validateAgainst(
        self: *const VerifiedNativePublicLogUpPublicationV2,
        prepared: *const PreparedV2,
        data: *const public_data_v2.PublicDataV2,
        relations: *const native_relations.Relations,
        native_sums: *const statement_v2.NativePublicSums,
        receipt: *const statement_v2.VerifiedReceipt,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!void {
        const expected = try deriveVerifiedNativePublicLogUp(
            prepared,
            data,
            relations,
            native_sums,
            receipt,
            component_descs,
            infra_descs,
        );
        if (!std.meta.eql(self.*, expected))
            return error.NativeVerifierCustodyMismatch;
    }

    pub fn canonicalWords(
        self: *const VerifiedNativePublicLogUpPublicationV2,
    ) Error![LOGUP_PUBLICATION_WORD_COUNT]M31 {
        try self.validate();
        var result: [LOGUP_PUBLICATION_WORD_COUNT]M31 = undefined;
        writeLogUpWordsAssumeValid(self, &result);
        return result;
    }

    pub fn productionReady(_: *const VerifiedNativePublicLogUpPublicationV2) bool {
        return false;
    }
};

/// Value-only plan for the exact Poseidon2-M31 program used by
/// `statement_v2.authorityIdentityFromGeometry`.  It does not retain borrowed
/// descriptor or wire storage.  Every append re-authenticates those sources,
/// replays the canonical encoder and checks the final digest before exposing
/// calls to the single shared row-34 provider.
pub const AuthorityHashPoseidonPlanV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    statement_version: u32 = public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
    wire_id: Digest,
    receipt_id: Digest,
    statement_authority_id: Digest,
    component_count: u32,
    infra_count: u32,
    preimage_word_count: u32,
    poseidon_call_count: u32,
    identity: Digest,

    pub fn init(
        data: *const public_data_v2.PublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!AuthorityHashPoseidonPlanV2 {
        try receipt.validateAgainst(data);
        const statement_authority_id = try statement_v2.authorityIdentityFromGeometry(
            data,
            component_descs,
            infra_descs,
        );
        if (!std.meta.eql(receipt.authority_id, statement_authority_id) or
            !std.meta.eql(receipt.wire_id, data.wireId()))
        {
            return error.NativeVerifierCustodyMismatch;
        }
        const descriptor_count = std.math.add(
            usize,
            component_descs.len,
            infra_descs.len,
        ) catch return error.ArithmeticOverflow;
        const descriptor_words = std.math.mul(
            usize,
            descriptor_count,
            AUTHORITY_HASH_WORDS_PER_DESCRIPTOR,
        ) catch return error.ArithmeticOverflow;
        const word_count = std.math.add(
            usize,
            AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT,
            descriptor_words,
        ) catch return error.ArithmeticOverflow;
        var result = AuthorityHashPoseidonPlanV2{
            .wire_id = receipt.wire_id,
            .receipt_id = receipt.identity,
            .statement_authority_id = statement_authority_id,
            .component_count = std.math.cast(u32, component_descs.len) orelse
                return error.ArithmeticOverflow,
            .infra_count = std.math.cast(u32, infra_descs.len) orelse
                return error.ArithmeticOverflow,
            .preimage_word_count = std.math.cast(u32, word_count) orelse
                return error.ArithmeticOverflow,
            .poseidon_call_count = std.math.cast(
                u32,
                channel.canonicalWordPermutationCount(word_count),
            ) orelse return error.ArithmeticOverflow,
            .identity = undefined,
        };
        result.identity = authorityHashPlanId(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const AuthorityHashPoseidonPlanV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.statement_version != public_data_v2.STATEMENT_TRANSCRIPT_VERSION or
            self.component_count > statement_v1.MAX_COMPONENTS or
            self.infra_count > statement_v1.MAX_INFRA_COMPONENTS)
        {
            return error.InvalidPublication;
        }
        inline for (.{
            self.wire_id,
            self.receipt_id,
            self.statement_authority_id,
            self.identity,
        }) |digest| try requireDigest(digest);
        const descriptor_count = std.math.add(
            u32,
            self.component_count,
            self.infra_count,
        ) catch return error.InvalidPublication;
        const descriptor_words = std.math.mul(
            u32,
            descriptor_count,
            AUTHORITY_HASH_WORDS_PER_DESCRIPTOR,
        ) catch return error.InvalidPublication;
        const expected_words = std.math.add(
            u32,
            AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT,
            descriptor_words,
        ) catch return error.InvalidPublication;
        if (self.preimage_word_count != expected_words or
            self.poseidon_call_count != channel.canonicalWordPermutationCount(
                expected_words,
            ) or !std.meta.eql(self.identity, authorityHashPlanId(self)))
        {
            return error.InvalidPublication;
        }
    }

    pub fn validateAgainst(
        self: *const AuthorityHashPoseidonPlanV2,
        data: *const public_data_v2.PublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!void {
        const expected = try AuthorityHashPoseidonPlanV2.init(
            data,
            receipt,
            component_descs,
            infra_descs,
        );
        if (!std.meta.eql(self.*, expected))
            return error.NativeVerifierCustodyMismatch;
    }

    pub fn poseidonCallCount(self: *const AuthorityHashPoseidonPlanV2) Error!usize {
        try self.validate();
        return self.poseidon_call_count;
    }

    /// Appends exactly this plan's call range.  The destination contains the
    /// standard native `poseidon2_air.Call` ABI and can be concatenated in
    /// canonical source order with every other requester before row 34 is
    /// materialized.  No second provider is instantiated here.
    pub fn appendPoseidonCallsInto(
        self: *const AuthorityHashPoseidonPlanV2,
        destination: []poseidon2_air.Call,
        data: *const public_data_v2.PublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!void {
        const destination_bytes = std.mem.sliceAsBytes(destination);
        inline for (.{
            std.mem.asBytes(self),
            std.mem.asBytes(data),
            std.mem.sliceAsBytes(data.words()),
            std.mem.asBytes(receipt),
            std.mem.sliceAsBytes(component_descs),
            std.mem.sliceAsBytes(infra_descs),
        }) |input| if (overlap(destination_bytes, input))
            return error.AliasedDestination;
        try self.validateAgainst(
            data,
            receipt,
            component_descs,
            infra_descs,
        );
        if (destination.len != self.poseidon_call_count)
            return error.PoseidonCallCountMismatch;

        var recorder = AuthorityHashCallRecorder.init(destination);
        recorder.u32Value(statement_v2.FORMAT_VERSION);
        recorder.u32Value(statement_v2.SCHEMA_VERSION);
        recorder.u32Value(self.component_count);
        recorder.u32Value(self.infra_count);
        const core_public = try statement_v2.canonicalCorePublicData(data);
        recorder.u32Value(core_public.initial_pc);
        recorder.u32Value(core_public.final_pc);
        recorder.u32Value(core_public.clock);
        recorder.digest(data.wireId());
        for (component_descs) |descriptor| {
            recorder.u32Value(@intFromEnum(descriptor.family));
            recorder.u32Value(descriptor.log_size);
            recorder.u32Value(descriptor.n_rows);
            recorder.u32Value(descriptor.n_columns);
        }
        for (infra_descs) |descriptor| {
            recorder.u32Value(@intFromEnum(descriptor.kind));
            recorder.u32Value(descriptor.log_size);
            recorder.u32Value(descriptor.n_rows);
            recorder.u32Value(descriptor.n_columns);
        }
        const output = recorder.finalize();
        if (!std.meta.eql(output, self.statement_authority_id) or
            recorder.call_at != destination.len)
        {
            return error.NativeVerifierCustodyMismatch;
        }
    }

    pub fn productionReady(_: *const AuthorityHashPoseidonPlanV2) bool {
        return AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE;
    }
};

pub const VerifierInputEventV2 = struct {
    domain: relation.Domain = VERIFIER_INPUT_RELATION_DOMAIN,
    role: relation.Role = .consume,
    tuple: [5]M31,
};

pub fn preparePublicLogUpInto(
    destination: *SourcePreflightPublicLogUpPublicationV2,
    prepared: *const PreparedV2,
    data: *const public_data_v2.PublicDataV2,
    relations: *const native_relations.Relations,
) Error!void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(prepared)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(data)) or
        overlap(std.mem.asBytes(destination), std.mem.sliceAsBytes(data.words())) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(relations)))
    {
        return error.AliasedDestination;
    }
    const staged = try derivePublicLogUp(prepared, data, relations);
    destination.* = staged;
}

/// Allocation-free, fail-atomic construction from verifier-owned custody.
/// Callers at the integration boundary must invoke their capture-level
/// validation first; this function independently revalidates every value it
/// consumes and recomputes the statement authority from the authenticated
/// wire and verifier-owned component geometry.
pub fn prepareVerifiedNativePublicLogUpInto(
    destination: *VerifiedNativePublicLogUpPublicationV2,
    prepared: *const PreparedV2,
    data: *const public_data_v2.PublicDataV2,
    relations: *const native_relations.Relations,
    native_sums: *const statement_v2.NativePublicSums,
    receipt: *const statement_v2.VerifiedReceipt,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!void {
    const destination_bytes = std.mem.asBytes(destination);
    inline for (.{
        std.mem.asBytes(prepared),
        std.mem.asBytes(data),
        std.mem.sliceAsBytes(data.words()),
        std.mem.asBytes(relations),
        std.mem.asBytes(native_sums),
        std.mem.asBytes(receipt),
        std.mem.sliceAsBytes(component_descs),
        std.mem.sliceAsBytes(infra_descs),
    }) |input| if (overlap(destination_bytes, input))
        return error.AliasedDestination;
    const staged = try deriveVerifiedNativePublicLogUp(
        prepared,
        data,
        relations,
        native_sums,
        receipt,
        component_descs,
        infra_descs,
    );
    destination.* = staged;
}

pub fn writeVerifierInputEventsInto(
    publication: *const SourcePreflightPublicLogUpPublicationV2,
    destination: []VerifierInputEventV2,
) Error!void {
    if (overlap(std.mem.sliceAsBytes(destination), std.mem.asBytes(publication)))
        return error.AliasedDestination;
    try publication.validate();
    if (destination.len != LOGUP_PUBLICATION_WORD_COUNT)
        return error.DestinationLengthMismatch;
    const words = try publication.canonicalWords();
    for (destination, words, 0..) |*event, word, index| {
        event.* = .{ .tuple = .{
            M31.fromCanonical(SEGMENT_V2_VERIFIER_ID),
            M31.fromCanonical(PUBLIC_LOGUP_V2_KIND),
            M31.fromCanonical(@intCast(index)),
            M31.zero(),
            word,
        } };
    }
}

pub fn writeVerifiedNativeVerifierInputEventsInto(
    publication: *const VerifiedNativePublicLogUpPublicationV2,
    destination: []VerifierInputEventV2,
) Error!void {
    if (overlap(std.mem.sliceAsBytes(destination), std.mem.asBytes(publication)))
        return error.AliasedDestination;
    try publication.validate();
    if (destination.len != LOGUP_PUBLICATION_WORD_COUNT)
        return error.DestinationLengthMismatch;
    const words = try publication.canonicalWords();
    for (destination, words, 0..) |*event, word, index| {
        event.* = .{ .tuple = .{
            M31.fromCanonical(SEGMENT_V2_VERIFIER_ID),
            M31.fromCanonical(PUBLIC_LOGUP_V2_KIND),
            M31.fromCanonical(@intCast(index)),
            M31.zero(),
            word,
        } };
    }
}

/// Native verifier handoff.  SHA tuple evidence is not embedded here.
pub const NativeTemporalPublicationV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    context: NativeTemporalContextV2,
    source_id: Digest,
    public_logup_id: Digest,
    identity: Digest,

    pub fn validate(self: *const NativeTemporalPublicationV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidPublication;
        }
        try validateNativeContextSelf(&self.context);
        inline for (.{
            self.source_id,
            self.public_logup_id,
            self.identity,
        }) |digest| try requireDigest(digest);
        if (!std.meta.eql(self.identity, nativePublicationId(self)))
            return error.InvalidPublication;
    }

    pub fn validateAgainst(
        self: *const NativeTemporalPublicationV2,
        prepared: *const PreparedV2,
        logup: *const PublicLogUpPublicationV2,
    ) Error!void {
        try self.validate();
        if (!std.meta.eql(self.context, prepared.context) or
            !std.meta.eql(self.source_id, prepared.source_id) or
            !std.meta.eql(self.public_logup_id, logup.identity))
        {
            return error.InvalidPublication;
        }
    }
};

/// Closure plumbing keeps byte identities in their native SHA representation.
pub const ShaClosurePublicationV2 = struct {
    statement_relation: ShaTupleEvidenceV2,
    verifier_input: ShaTupleEvidenceV2,

    pub fn validate(self: *const ShaClosurePublicationV2) Error!void {
        try self.statement_relation.validate();
        try self.verifier_input.validate();
    }
};

pub fn deriveVerifiedNativePublicLogUp(
    prepared: *const PreparedV2,
    data: *const public_data_v2.PublicDataV2,
    relations: *const native_relations.Relations,
    native_sums: *const statement_v2.NativePublicSums,
    receipt: *const statement_v2.VerifiedReceipt,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!VerifiedNativePublicLogUpPublicationV2 {
    try prepared.validateAgainst(data, &prepared.verifier_keys);
    try receipt.validateAgainst(data);
    try native_sums.validateAgainst(data, relations);
    const statement_authority_id = try statement_v2.authorityIdentityFromGeometry(
        data,
        component_descs,
        infra_descs,
    );
    if (!std.meta.eql(receipt.authority_id, statement_authority_id) or
        !std.meta.eql(receipt.wire_id, data.wireId()) or
        !std.meta.eql(receipt.wire_id, prepared.context.segment_wire_id) or
        !std.meta.eql(native_sums.wire_id, receipt.wire_id))
    {
        return error.NativeVerifierCustodyMismatch;
    }
    var result = VerifiedNativePublicLogUpPublicationV2{
        .source_id = prepared.source_id,
        .authenticated_context_id = prepared.context.authenticated_context_id,
        .relation_context_id = relationContextId(relations),
        .statement_authority_id = statement_authority_id,
        .statement_wire_id = receipt.wire_id,
        .receipt = receipt.*,
        .native_public_sums_identity = native_sums.identity,
        .native_relation_context_id = native_sums.relation_context_id,
        .sums = native_sums.sums,
        .total = native_sums.total,
        .identity = undefined,
        .verifier_input_evidence = undefined,
    };
    result.identity = verifiedNativeLogupPublicationId(&result);
    result.verifier_input_evidence = verifierInputEvidence(&result);
    try result.validate();
    return result;
}

/// Capture-backed publication identity.  The stable bare encoder above is the
/// single encoder for the common 55-word claim; this extension folds its
/// result together with successful-verifier custody and exact native
/// compensation under a disjoint domain.
pub fn verifiedNativeLogupPublicationId(
    publication: *const VerifiedNativePublicLogUpPublicationV2,
) Digest {
    const common_id = logupPublicationId(publication);
    var hash = IdentityHasher.init(VERIFIED_NATIVE_LOGUP_ID_DOMAIN);
    hash.scalar(publication.format_version);
    hash.scalar(publication.schema_version);
    hash.scalar(publication.statement_version);
    hash.digest(common_id);
    hash.digest(publication.statement_authority_id);
    hash.digest(publication.statement_wire_id);
    hash.digest(publication.receipt.identity);
    hash.digest(publication.native_public_sums_identity);
    hash.digest(publication.native_relation_context_id);
    return hash.finalize();
}

pub fn authorityHashPlanId(plan: *const AuthorityHashPoseidonPlanV2) Digest {
    var hash = IdentityHasher.init(AUTHORITY_HASH_PLAN_ID_DOMAIN);
    hash.scalar(plan.format_version);
    hash.scalar(plan.schema_version);
    hash.scalar(plan.statement_version);
    hash.digest(plan.wire_id);
    hash.digest(plan.receipt_id);
    hash.digest(plan.statement_authority_id);
    hash.scalar(plan.component_count);
    hash.scalar(plan.infra_count);
    hash.scalar(plan.preimage_word_count);
    hash.scalar(plan.poseidon_call_count);
    return hash.finalize();
}

pub fn nativePublicationId(publication: *const NativeTemporalPublicationV2) Digest {
    var hash = IdentityHasher.init(NATIVE_PUBLICATION_ID_DOMAIN);
    hash.scalar(publication.format_version);
    hash.scalar(publication.schema_version);
    hash.digest(publication.context.authenticated_context_id);
    hash.digest(publication.source_id);
    hash.digest(publication.public_logup_id);
    return hash.finalize();
}

/// Streaming mirror of `poseidon2_channel.CanonicalWordHasher` which retains
/// each permutation input in the native provider ABI.  It deliberately has no
/// dynamic storage and no independent sponge semantics.
pub const AuthorityHashCallRecorder = struct {
    state: [poseidon2_air.WIDTH]M31,
    filled: usize = 0,
    calls: []poseidon2_air.Call,
    call_at: usize = 0,

    fn init(calls: []poseidon2_air.Call) AuthorityHashCallRecorder {
        var state = [_]M31{M31.zero()} ** poseidon2_air.WIDTH;
        state[poseidon2_air.WIDTH - 1] = M31.fromCanonical(
            statement_v2.AUTHORITY_ID_DOMAIN,
        );
        return .{ .state = state, .calls = calls };
    }

    fn canonical(self: *AuthorityHashCallRecorder, value: u32) void {
        std.debug.assert(value < m31.Modulus);
        self.state[self.filled] = self.state[self.filled].add(
            M31.fromCanonical(value),
        );
        self.filled += 1;
        if (self.filled == channel.RATE) self.permute();
    }

    fn u32Value(self: *AuthorityHashCallRecorder, value: u32) void {
        self.canonical(value & 0xffff);
        self.canonical(value >> 16);
    }

    fn digest(self: *AuthorityHashCallRecorder, value: Digest) void {
        for (value) |word| self.canonical(word);
    }

    fn permute(self: *AuthorityHashCallRecorder) void {
        std.debug.assert(self.call_at < self.calls.len);
        var input: [poseidon2_air.WIDTH]u32 = undefined;
        for (&input, self.state) |*destination, word|
            destination.* = word.toU32();
        self.calls[self.call_at] = .{
            .input = input,
            .wide = false,
            .io = true,
            .narrow_output = null,
        };
        self.call_at += 1;
        poseidon2.permute(&self.state);
        self.filled = 0;
    }

    fn finalize(self: *AuthorityHashCallRecorder) Digest {
        self.canonical(1);
        if (self.filled != 0) self.permute();
        var result: Digest = undefined;
        for (&result, self.state[0..channel.RATE]) |*destination, word|
            destination.* = word.toU32();
        return result;
    }
};
