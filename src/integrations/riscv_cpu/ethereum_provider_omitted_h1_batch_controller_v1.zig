//! Fail-closed structural admission of the canonical 210 omitted-provider
//! leaves into the existing 105-pair Ethereum H1 ingress.
//!
//! This controller performs no H1 proof.  It reopens the retained corpus,
//! validates the statement and batch plans against all 210 STWESG31 sources,
//! cold-verifies every omitted-provider bundle, and delegates only the missing
//! verifier-owned pair capability to a typed backend.  The backend boundary is
//! intentionally generic and has no digest-only default implementation.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const batch_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_batch_v1.zig");
const bundle_mod = @import("ethereum_provider_omitted_leaf_bundle_v1.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const journal_mod = @import("ethereum_block_leaf_journal.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const structural =
    @import("ethereum_provider_omitted_h1_batch_contract_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub const production_active = false;
pub const h1_proofs_executed = false;
pub const upper_or_root_admitted = false;
pub const maximum_elf_bytes: usize = 512 * 1024 * 1024;
pub const maximum_input_bytes: usize = 512 * 1024 * 1024;
pub const maximum_journal_bytes: usize = 512 * 1024 * 1024;
pub const maximum_output_bytes: usize = 64 * 1024 * 1024;

comptime {
    if (production_active or h1_proofs_executed or upper_or_root_admitted)
        @compileError("omitted-provider structural controller activated");
}

pub const Options = struct {
    request_path: []const u8,
    result_path: []const u8,

    pub fn validate(self: Options) !void {
        if (!std.fs.path.isAbsolute(self.request_path) or
            !std.fs.path.isAbsolute(self.result_path) or
            std.mem.eql(u8, self.request_path, self.result_path))
        {
            return error.InvalidOmittedH1ControllerOptions;
        }
    }
};

/// Generic backend contract, checked only when this function is instantiated:
///
/// * `openLeafAuthority(allocator, index, source) !LeafAuthorityLease`
/// * `leafAuthority(*LeafAuthorityLease) !bundle_mod.Authority(Engine)`
/// * `closeLeafAuthority(allocator, *LeafAuthorityLease) void`
/// * `mintPairCapability(allocator, batch, ordinal, left_fresh,
///   left_authority, right_fresh, right_authority) !PairCapability`
/// * `closePairCapability(allocator, *PairCapability) void`
///
/// `PairCapability` must implement the existing verifier-minted H1 surface.
/// No backend is supplied here until verifier-owned omitted-core and ordered
/// provider-shard captures can mint that surface without synthesis.
pub fn run(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    options: Options,
    materialized: *const statement_plan.MaterializedPlanV1,
    batch: *const batch_mod.BatchPlanV1,
    backend: anytype,
    limits: bundle_mod.Limits,
) !void {
    try options.validate();
    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        options.request_path,
        structural.maximum_json_bytes,
    );
    defer allocator.free(request_bytes);
    const result_bytes = try coldAdmitAlloc(
        Engine,
        allocator,
        request_bytes,
        materialized,
        batch,
        backend,
        limits,
    );
    defer allocator.free(result_bytes);
    try structural.publishResultCreateOnly(options.result_path, result_bytes);
}

/// Returns a sealed proofless result only after all 210 cold verifications and
/// all 105 live H1 pair admissions succeed.  Pair resources are released after
/// each adjacent pair, so this controller never retains 210 proof decodings.
pub fn coldAdmitAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    request_bytes: []const u8,
    materialized: *const statement_plan.MaterializedPlanV1,
    batch: *const batch_mod.BatchPlanV1,
    backend: anytype,
    limits: bundle_mod.Limits,
) ![]u8 {
    if (production_active or h1_proofs_executed or upper_or_root_admitted)
        return error.OmittedH1StructuralControllerActivated;
    try limits.validate();
    var parsed_request = try structural.parseRequest(allocator, request_bytes);
    defer parsed_request.deinit();
    const request = parsed_request.value.unsigned();
    try request.validateAgainstPlans(allocator, materialized, batch);

    var corpus = try openCorpus(allocator, request, materialized, batch);
    defer corpus.deinit();

    var admissions: [structural.pair_count]batch_mod.FreshPairAdmissionV1 =
        undefined;
    for (&admissions, 0..) |*admission, ordinal| {
        admission.* = try admitPair(
            Engine,
            allocator,
            request,
            batch,
            backend,
            limits,
            &corpus.sources,
            ordinal,
        );
    }
    const batch_admission = try batch_mod.BatchAdmissionV1.init(
        batch,
        admissions,
    );

    var owned_records: [structural.pair_count]structural.OwnedPairAdmissionRecordV1 = undefined;
    var wire_records: [structural.pair_count]structural.PairAdmissionRecordV1 = undefined;
    for (admissions, 0..) |admission, ordinal| {
        owned_records[ordinal] = try .init(admission, batch);
        wire_records[ordinal] = owned_records[ordinal].wire();
        const expected_task = try contract.parseSha256(
            request.pairs[ordinal].task_identity_sha256,
        );
        if (!std.mem.eql(
            u8,
            &admission.task_identity_sha256,
            &expected_task,
        )) return error.OmittedH1PairTaskMismatch;
    }
    const batch_admission_hex = std.fmt.bytesToHex(
        batch_admission.identity_sha256,
        .lower,
    );
    const result = structural.UnsignedStructuralResultV1{
        .all_bundles_cold_verified = true,
        .all_pair_capabilities_validated = true,
        .batch_admission_identity_sha256 = &batch_admission_hex,
        .batch_plan_identity_sha256 = request.batch_plan_identity_sha256,
        .pair_admissions = &wire_records,
        .request_content_sha256 = parsed_request.value.content_sha256,
    };
    return structural.encodeResultAlloc(allocator, result);
}

const OpenedCorpusV1 = struct {
    sources: [structural.leaf_count]support.source_wire.Source,

    fn deinit(self: *OpenedCorpusV1) void {
        self.* = undefined;
    }
};

fn openCorpus(
    allocator: std.mem.Allocator,
    request: structural.UnsignedRequestSetV1,
    materialized: *const statement_plan.MaterializedPlanV1,
    batch: *const batch_mod.BatchPlanV1,
) !OpenedCorpusV1 {
    const materialization_bytes = try readIdentity(
        allocator,
        request.materialization_result,
        structural.maximum_json_bytes,
    );
    defer allocator.free(materialization_bytes);
    var parsed_materialization = try contract.parseMaterializationResult(
        allocator,
        materialization_bytes,
    );
    defer parsed_materialization.deinit();
    const retained = parsed_materialization.value;

    const source_bytes = try readTypedIdentity(
        allocator,
        request.source_request,
        structural.maximum_json_bytes,
    );
    defer allocator.free(source_bytes);
    var parsed_source = try contract.parseRecursiveSource(
        allocator,
        source_bytes,
    );
    defer parsed_source.deinit();
    const source = parsed_source.value;
    try validateCorpusJoin(request, retained, source);

    try reopenAndDiscard(allocator, request.elf, maximum_elf_bytes);
    const journal_bytes = try readIdentity(
        allocator,
        request.execution_journal,
        maximum_journal_bytes,
    );
    defer allocator.free(journal_bytes);
    const journal_records = try journal_mod.validate(
        allocator,
        journal_bytes,
        source,
    );
    defer allocator.free(journal_records);
    if (journal_records.len != structural.leaf_count)
        return error.OmittedH1JournalCountMismatch;
    try reopenAndDiscard(allocator, request.input, maximum_input_bytes);
    try reopenAndDiscard(
        allocator,
        request.expected_output,
        maximum_output_bytes,
    );

    var result = OpenedCorpusV1{
        .sources = undefined,
    };
    var expected: [structural.leaf_count]statement_plan.ExpectedRealLeafV1 = undefined;
    for (request.bundles, 0..) |record, index| {
        const retained_leaf = retained.leaf_sources[index];
        if (!identityEql(record.source_authority, retained_leaf.authority))
            return error.OmittedH1SourceAuthorityMismatch;
        const bytes = try readIdentity(
            allocator,
            record.source_authority,
            support.source_wire.encoded_size,
        );
        defer allocator.free(bytes);
        if (bytes.len != support.source_wire.encoded_size)
            return error.OmittedH1SourceAuthorityMismatch;
        const decoded = try support.source_wire.decode(bytes);
        if (decoded.metadata.segment_index != @as(u32, @intCast(index)) or
            decoded.metadata.segment_count != structural.leaf_count or
            !std.mem.eql(
                u8,
                &decoded.journal_record_sha256,
                &journal_records[index],
            )) return error.OmittedH1SourceAuthorityMismatch;
        result.sources[index] = decoded;
        expected[index] = .{
            .metadata = decoded.metadata,
            .metadata_id = try decoded.metadata.identity(),
            .source_sha_id = try contract.parseSha256(
                record.source_authority.sha256,
            ),
        };
    }
    try materialized.validateAgainst(&expected);
    try batch.validateAgainst(allocator, materialized);
    return result;
}

fn admitPair(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    request: structural.UnsignedRequestSetV1,
    batch: *const batch_mod.BatchPlanV1,
    backend: anytype,
    limits: bundle_mod.Limits,
    sources: *const [structural.leaf_count]support.source_wire.Source,
    ordinal: usize,
) !batch_mod.FreshPairAdmissionV1 {
    const left_index = 2 * ordinal;
    const right_index = left_index + 1;

    var left_lease = try backend.openLeafAuthority(
        allocator,
        left_index,
        &sources[left_index],
    );
    defer backend.closeLeafAuthority(allocator, &left_lease);
    const left_authority = try backend.leafAuthority(&left_lease);
    if (left_authority.source != &sources[left_index])
        return error.OmittedH1LeafAuthoritySourceMismatch;
    var left_fresh = try coldVerifyLeaf(
        Engine,
        allocator,
        request.bundles[left_index],
        left_authority,
        limits,
    );
    defer left_fresh.deinit();

    var right_lease = try backend.openLeafAuthority(
        allocator,
        right_index,
        &sources[right_index],
    );
    defer backend.closeLeafAuthority(allocator, &right_lease);
    const right_authority = try backend.leafAuthority(&right_lease);
    if (right_authority.source != &sources[right_index])
        return error.OmittedH1LeafAuthoritySourceMismatch;
    var right_fresh = try coldVerifyLeaf(
        Engine,
        allocator,
        request.bundles[right_index],
        right_authority,
        limits,
    );
    defer right_fresh.deinit();

    var capability = try backend.mintPairCapability(
        allocator,
        batch,
        ordinal,
        &left_fresh,
        left_authority,
        &right_fresh,
        right_authority,
    );
    defer backend.closePairCapability(allocator, &capability);
    return batch_mod.admitVerifierMintedPair(
        allocator,
        batch,
        ordinal,
        &capability,
    );
}

fn coldVerifyLeaf(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    record: structural.BundleRecordV1,
    authority: bundle_mod.Authority(Engine),
    limits: bundle_mod.Limits,
) !bundle_mod.FreshVerifiedOmittedLeafV1(Engine) {
    const bytes = try readIdentity(
        allocator,
        record.artifact,
        limits.max_bundle_bytes,
    );
    defer allocator.free(bytes);
    var fresh = try bundle_mod.coldVerify(
        Engine,
        allocator,
        bytes,
        authority,
        limits,
    );
    errdefer fresh.deinit();
    const expected_authority = try contract.parseSha256(
        record.authority_identity_sha256,
    );
    if (!std.mem.eql(
        u8,
        &fresh.authority_identity,
        &expected_authority,
    )) return error.OmittedH1LeafAuthorityIdentityMismatch;
    try fresh.validateAgainstArtifact(authority, bytes);
    return fresh;
}

fn validateCorpusJoin(
    request: structural.UnsignedRequestSetV1,
    materialization: contract.MaterializationResult,
    source: contract.RecursiveSourceRequestV2,
) !void {
    if (source.segment_count != structural.leaf_count or
        materialization.segment_count != structural.leaf_count or
        materialization.leaf_sources.len != structural.leaf_count or
        !identityEql(request.elf, source.elf) or
        !identityEql(request.execution_journal, source.execution_journal) or
        !identityEql(request.execution_journal, materialization.execution_journal) or
        !identityEql(request.expected_output, source.expected_output) or
        !identityEql(request.expected_output, materialization.expected_output) or
        !identityEql(request.input, source.input) or
        !identityEql(request.input, materialization.input) or
        !typedIdentityEql(request.source_request, materialization.source_request) or
        !std.mem.eql(
            u8,
            request.source_request.schema,
            contract.recursive_source_schema,
        )) return error.OmittedH1CorpusAuthorityMismatch;
}

fn reopenAndDiscard(
    allocator: std.mem.Allocator,
    identity: contract.Identity,
    maximum_bytes: usize,
) !void {
    const bytes = try readIdentity(allocator, identity, maximum_bytes);
    defer allocator.free(bytes);
}

fn readIdentity(
    allocator: std.mem.Allocator,
    identity: contract.Identity,
    maximum_bytes: usize,
) ![]u8 {
    try identity.validate(identity.bytes == 0);
    if (!std.fs.path.isAbsolute(identity.path) or
        identity.bytes > maximum_bytes)
    {
        return error.OmittedH1FileIdentityMismatch;
    }
    const bytes = try artifact_io.readFileBounded(
        allocator,
        identity.path,
        maximum_bytes,
    );
    errdefer allocator.free(bytes);
    if (bytes.len != identity.bytes)
        return error.OmittedH1FileIdentityMismatch;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const expected = try contract.parseSha256(identity.sha256);
    if (!std.mem.eql(u8, &digest, &expected))
        return error.OmittedH1FileIdentityMismatch;
    return bytes;
}

fn readTypedIdentity(
    allocator: std.mem.Allocator,
    identity: contract.TypedIdentity,
    maximum_bytes: usize,
) ![]u8 {
    try identity.validate();
    return readIdentity(allocator, .{
        .bytes = identity.bytes,
        .path = identity.path,
        .sha256 = identity.sha256,
    }, maximum_bytes);
}

fn identityEql(left: contract.Identity, right: contract.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn typedIdentityEql(
    left: contract.TypedIdentity,
    right: contract.TypedIdentity,
) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.schema, right.schema) and
        std.mem.eql(u8, left.sha256, right.sha256);
}
