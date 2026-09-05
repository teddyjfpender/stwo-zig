//! Immutable strict-prefix journal for freshly verified provider-V2 proofs.
//!
//! Prefix zero records the freshly verified core. Prefix N records exactly
//! provider ordinals `[0, N)`, links the prior create-only prefix by exact file
//! and content identity, and binds the durable call artifact used for every
//! recomputation. No prefix is a verification oracle: finalization must reopen
//! every raw proof and call the fresh verifier again in one transaction.
//!
//! The terminal closure is a separate create-only receipt and is published
//! last. The current joint proof remains nonproduction because the full RISC-V
//! caller and recursive admission are not active, even though every provider
//! V2 proof AIR-binds its ordered call range and endpoint.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const lifecycle = @import("ethereum_poseidon_provider_stage_b_lifecycle_v1.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const stage_a = @import("ethereum_poseidon_provider_stage_a_checkpoint_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const joint_v1 = frontend.testing.narrow_memory_provider_joint_proof;
const provider_v2 = frontend.testing.narrow_memory_provider_joint_proof_v2;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;

pub const prefix_schema =
    "stwo.ethereum.poseidon-provider-stage-b-prefix.v2";
pub const prefix_status = "fresh-prefix-nonproduction";
pub const closure_schema =
    "stwo.ethereum.poseidon-provider-joint-closure.v2";
pub const closure_status = "fresh-joint-closure-nonproduction";
pub const max_prefix_bytes: usize = 8 * 1024 * 1024;
pub const max_closure_bytes: usize = 1024 * 1024;

pub const CoreRecord = struct {
    artifact: contract.Identity,
    artifact_content_sha256: []const u8,
    claim_identity_sha256: []const u8,
    manifest_identity_sha256: []const u8,
    proof: contract.Identity,
    proof_commitments_identity_sha256: []const u8,
    relation_context_identity_sha256: []const u8,
    statement_identity_sha256: []const u8,
    verifier_sha256: []const u8,
    verify_timing: evidence.Timing,

    fn validate(self: CoreRecord) !void {
        try self.artifact.validate(false);
        try self.proof.validate(false);
        if (!std.fs.path.isAbsolute(self.artifact.path) or
            !std.fs.path.isAbsolute(self.proof.path) or
            self.verify_timing.wall_ns == 0)
        {
            return error.InvalidProviderStageBPrefix;
        }
        inline for (.{
            self.artifact_content_sha256,
            self.claim_identity_sha256,
            self.manifest_identity_sha256,
            self.proof_commitments_identity_sha256,
            self.relation_context_identity_sha256,
            self.statement_identity_sha256,
            self.verifier_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
    }
};

pub const ProviderRecord = struct {
    artifact: contract.Identity,
    artifact_content_sha256: []const u8,
    call_count: u32,
    claim_identity_sha256: []const u8,
    descriptor_identity_sha256: []const u8,
    first_call: u64,
    manifest_identity_sha256: []const u8,
    ordered_call_air_verified: bool,
    ordered_call_claim_recomputed: bool,
    ordered_call_terminal_m31: [4]u32,
    proof: contract.Identity,
    proof_commitments_identity_sha256: []const u8,
    relation_context_identity_sha256: []const u8,
    shard_index: u32,
    statement_identity_sha256: []const u8,
    verifier_sha256: []const u8,
    verify_timing: evidence.Timing,

    fn validate(self: ProviderRecord, expected_ordinal: usize) !void {
        try self.artifact.validate(false);
        try self.proof.validate(false);
        if (!std.fs.path.isAbsolute(self.artifact.path) or
            !std.fs.path.isAbsolute(self.proof.path) or
            self.shard_index != expected_ordinal or self.call_count == 0 or
            !self.ordered_call_air_verified or
            !self.ordered_call_claim_recomputed or
            self.verify_timing.wall_ns == 0)
        {
            return error.InvalidProviderStageBPrefix;
        }
        inline for (.{
            self.artifact_content_sha256,
            self.claim_identity_sha256,
            self.descriptor_identity_sha256,
            self.manifest_identity_sha256,
            self.proof_commitments_identity_sha256,
            self.relation_context_identity_sha256,
            self.statement_identity_sha256,
            self.verifier_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        for (self.ordered_call_terminal_m31) |word|
            if (word >= m31.Modulus)
                return error.NonCanonicalProviderStageBClaim;
    }
};

pub const Prefix = struct {
    content_sha256: []const u8,
    call_artifact: contract.Identity,
    call_artifact_content_sha256: []const u8,
    call_list_commitment_sha256: []const u8,
    complete_ordered_provider_prefix: bool,
    core: CoreRecord,
    manifest_identity_sha256: []const u8,
    next_provider_ordinal: u32,
    plan_identity_sha256: []const u8,
    previous_prefix: ?contract.Identity,
    previous_prefix_content_sha256: ?[]const u8,
    production_eligible: bool,
    providers: []const ProviderRecord,
    recursive_admissible: bool,
    relation_context_identity_sha256: []const u8,
    resource_plan_identity_sha256: []const u8,
    schema: []const u8,
    session_sha256: []const u8,
    shard_count: u32,
    stage_a_checkpoint: contract.Identity,
    stage_a_checkpoint_content_sha256: []const u8,
    status: []const u8,

    pub fn validate(self: Prefix) !void {
        if (!std.mem.eql(u8, self.schema, prefix_schema) or
            !std.mem.eql(u8, self.status, prefix_status) or
            self.production_eligible or self.recursive_admissible or
            self.shard_count == 0 or
            self.providers.len != self.next_provider_ordinal or
            self.next_provider_ordinal > self.shard_count or
            self.complete_ordered_provider_prefix !=
                (self.next_provider_ordinal == self.shard_count))
        {
            return error.InvalidProviderStageBPrefix;
        }
        try self.call_artifact.validate(false);
        try self.stage_a_checkpoint.validate(false);
        if (!std.fs.path.isAbsolute(self.call_artifact.path) or
            !std.fs.path.isAbsolute(self.stage_a_checkpoint.path))
        {
            return error.InvalidProviderStageBPrefix;
        }
        inline for (.{
            self.content_sha256,
            self.call_artifact_content_sha256,
            self.call_list_commitment_sha256,
            self.manifest_identity_sha256,
            self.plan_identity_sha256,
            self.relation_context_identity_sha256,
            self.resource_plan_identity_sha256,
            self.session_sha256,
            self.stage_a_checkpoint_content_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        try self.core.validate();
        for (self.providers, 0..) |provider, index|
            try provider.validate(index);
        if (self.next_provider_ordinal == 0) {
            if (self.previous_prefix != null or
                self.previous_prefix_content_sha256 != null)
            {
                return error.InvalidProviderStageBPrefix;
            }
        } else {
            const previous = self.previous_prefix orelse
                return error.InvalidProviderStageBPrefix;
            try previous.validate(false);
            if (!std.fs.path.isAbsolute(previous.path))
                return error.InvalidProviderStageBPrefix;
            _ = try contract.parseSha256(
                self.previous_prefix_content_sha256 orelse
                    return error.InvalidProviderStageBPrefix,
            );
        }
    }
};

pub const ClosureWire = struct {
    closed_sum_m31: [4]u32,
    complete_ordered_coverage: bool,
    core_claim_identity_sha256: []const u8,
    core_claim_m31: [4]u32,
    every_ordered_call_air_verified: bool,
    every_proof_freshly_verified: bool,
    format: u32,
    identity_sha256: []const u8,
    manifest_identity_sha256: []const u8,
    one_shared_relation_context: bool,
    ordered_provider_claims_identity_sha256: []const u8,
    plan_identity_sha256: []const u8,
    production_eligible: bool,
    provider_claim_m31: [4]u32,
    relation_context_identity_sha256: []const u8,
    shard_count: u32,

    fn validate(self: ClosureWire) !void {
        inline for (.{
            self.core_claim_identity_sha256,
            self.identity_sha256,
            self.manifest_identity_sha256,
            self.ordered_provider_claims_identity_sha256,
            self.plan_identity_sha256,
            self.relation_context_identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        inline for (.{
            self.closed_sum_m31,
            self.core_claim_m31,
            self.provider_claim_m31,
        }) |words| for (words) |word|
            if (word >= m31.Modulus)
                return error.NonCanonicalProviderStageBClaim;
        if (self.format != provider_v2.format_version or
            self.shard_count == 0 or
            !self.every_ordered_call_air_verified or
            !self.every_proof_freshly_verified or
            !self.complete_ordered_coverage or
            !self.one_shared_relation_context or self.production_eligible or
            !qm31(self.closed_sum_m31).isZero())
        {
            return error.InvalidProviderJointClosure;
        }
    }
};

pub const FinalReceipt = struct {
    content_sha256: []const u8,
    closure: ClosureWire,
    complete_prefix: contract.Identity,
    complete_prefix_content_sha256: []const u8,
    production_eligible: bool,
    recursive_admissible: bool,
    schema: []const u8,
    status: []const u8,

    pub fn validate(self: FinalReceipt) !void {
        if (!std.mem.eql(u8, self.schema, closure_schema) or
            !std.mem.eql(u8, self.status, closure_status) or
            self.production_eligible or self.recursive_admissible)
        {
            return error.InvalidProviderJointClosure;
        }
        try self.complete_prefix.validate(false);
        if (!std.fs.path.isAbsolute(self.complete_prefix.path))
            return error.InvalidProviderJointClosure;
        _ = try contract.parseSha256(self.content_sha256);
        _ = try contract.parseSha256(self.complete_prefix_content_sha256);
        try self.closure.validate();
    }
};

pub const Authority = struct {
    call_artifact: evidence.FileIdentity,
    call_artifact_content_sha256: [32]u8,
    call_artifact_value: *const call_artifact.Artifact,
    context: lifecycle.Context,

    pub fn validate(self: Authority) !void {
        try self.context.validate();
        if (!std.fs.path.isAbsolute(self.call_artifact.path) or
            self.call_artifact.bytes == 0)
        {
            return error.InvalidProviderStageBAuthority;
        }
        try self.call_artifact_value.validate();
        if (!std.mem.eql(
            u8,
            self.call_artifact_value.content_sha256,
            &hex(self.call_artifact_content_sha256),
        ) or !std.mem.eql(
            u8,
            self.call_artifact_value.call_list_commitment_sha256,
            &hex(self.context.plan.call_list_commitment),
        ) or !std.mem.eql(
            u8,
            self.call_artifact_value.resource_plan_identity_sha256,
            &hex(self.context.resource_plan.identity),
        ) or !std.mem.eql(
            u8,
            self.call_artifact_value.session_sha256,
            &hex(self.context.plan.session),
        ) or self.call_artifact_value.call_count !=
            self.context.plan.total_call_count)
        {
            return error.InvalidProviderStageBAuthority;
        }
    }
};

const CoreHexStorage = struct {
    artifact: [64]u8,
    artifact_content: [64]u8,
    claim: [64]u8,
    manifest: [64]u8,
    proof: [64]u8,
    proof_commitments: [64]u8,
    relation: [64]u8,
    statement: [64]u8,
    verifier: [64]u8,
};

const ProviderHexStorage = struct {
    artifact: [64]u8,
    artifact_content: [64]u8,
    claim: [64]u8,
    descriptor: [64]u8,
    manifest: [64]u8,
    proof: [64]u8,
    proof_commitments: [64]u8,
    relation: [64]u8,
    statement: [64]u8,
    verifier: [64]u8,
};

const PrefixHexStorage = struct {
    call_artifact: [64]u8,
    call_artifact_content: [64]u8,
    call_list: [64]u8,
    manifest: [64]u8,
    plan: [64]u8,
    relation: [64]u8,
    resource_plan: [64]u8,
    session: [64]u8,
    stage_a: [64]u8,
    stage_a_content: [64]u8,
};

pub fn encodeCorePrefix(
    allocator: std.mem.Allocator,
    authority_value: Authority,
    fresh: *const lifecycle.FreshCore,
) ![]u8 {
    try authority_value.validate();
    try validateFreshCore(authority_value, fresh);
    const core_storage = coreStorage(fresh);
    const prefix_storage = prefixStorage(authority_value);
    const placeholder = [_]u8{'0'} ** 64;
    const value = Prefix{
        .content_sha256 = &placeholder,
        .call_artifact = identity(
            authority_value.call_artifact,
            &prefix_storage.call_artifact,
        ),
        .call_artifact_content_sha256 = &prefix_storage.call_artifact_content,
        .call_list_commitment_sha256 = &prefix_storage.call_list,
        .complete_ordered_provider_prefix = false,
        .core = coreRecord(fresh, &core_storage),
        .manifest_identity_sha256 = &prefix_storage.manifest,
        .next_provider_ordinal = 0,
        .plan_identity_sha256 = &prefix_storage.plan,
        .previous_prefix = null,
        .previous_prefix_content_sha256 = null,
        .production_eligible = false,
        .providers = &.{},
        .recursive_admissible = false,
        .relation_context_identity_sha256 = &prefix_storage.relation,
        .resource_plan_identity_sha256 = &prefix_storage.resource_plan,
        .schema = prefix_schema,
        .session_sha256 = &prefix_storage.session,
        .shard_count = authority_value.context.plan.shard_count,
        .stage_a_checkpoint = identity(
            authority_value.context.stage_a_checkpoint,
            &prefix_storage.stage_a,
        ),
        .stage_a_checkpoint_content_sha256 = &prefix_storage.stage_a_content,
        .status = prefix_status,
    };
    return sealPrefix(allocator, value);
}

pub fn encodeAppendProvider(
    allocator: std.mem.Allocator,
    authority_value: Authority,
    previous: Prefix,
    previous_file: evidence.FileIdentity,
    fresh: *const lifecycle.FreshProviderV2,
) ![]u8 {
    try authority_value.validate();
    try validateAgainst(previous, authority_value);
    if (previous.complete_ordered_provider_prefix or
        previous_file.bytes == 0 or
        !std.fs.path.isAbsolute(previous_file.path))
    {
        return error.InvalidProviderStageBPrefix;
    }
    const ordinal = previous.next_provider_ordinal;
    try validateFreshProvider(authority_value, ordinal, fresh);
    const providers = try allocator.alloc(
        ProviderRecord,
        previous.providers.len + 1,
    );
    defer allocator.free(providers);
    @memcpy(providers[0..previous.providers.len], previous.providers);
    const provider_storage = providerStorage(fresh);
    providers[previous.providers.len] = providerRecord(
        fresh,
        &provider_storage,
    );
    const previous_sha = hex(previous_file.sha256);
    const prefix_storage = prefixStorage(authority_value);
    const placeholder = [_]u8{'0'} ** 64;
    const next = ordinal + 1;
    const value = Prefix{
        .content_sha256 = &placeholder,
        .call_artifact = identity(
            authority_value.call_artifact,
            &prefix_storage.call_artifact,
        ),
        .call_artifact_content_sha256 = &prefix_storage.call_artifact_content,
        .call_list_commitment_sha256 = &prefix_storage.call_list,
        .complete_ordered_provider_prefix = next == authority_value.context.plan.shard_count,
        .core = previous.core,
        .manifest_identity_sha256 = &prefix_storage.manifest,
        .next_provider_ordinal = next,
        .plan_identity_sha256 = &prefix_storage.plan,
        .previous_prefix = identity(previous_file, &previous_sha),
        .previous_prefix_content_sha256 = previous.content_sha256,
        .production_eligible = false,
        .providers = providers,
        .recursive_admissible = false,
        .relation_context_identity_sha256 = &prefix_storage.relation,
        .resource_plan_identity_sha256 = &prefix_storage.resource_plan,
        .schema = prefix_schema,
        .session_sha256 = &prefix_storage.session,
        .shard_count = authority_value.context.plan.shard_count,
        .stage_a_checkpoint = identity(
            authority_value.context.stage_a_checkpoint,
            &prefix_storage.stage_a,
        ),
        .stage_a_checkpoint_content_sha256 = &prefix_storage.stage_a_content,
        .status = prefix_status,
    };
    const bytes = try sealPrefix(allocator, value);
    errdefer allocator.free(bytes);
    var parsed = try parsePrefix(allocator, bytes);
    defer parsed.deinit();
    try validateSuccessor(previous, previous_file, parsed.value);
    return bytes;
}

pub fn parsePrefix(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Prefix) {
    if (bytes.len == 0 or bytes.len > max_prefix_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Prefix, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    try requireCanonical(allocator, bytes, parsed.value);
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub const OpenedPrefix = struct {
    bytes: []u8,
    file: evidence.FileIdentity,
    parsed: std.json.Parsed(Prefix),

    pub fn deinit(self: *OpenedPrefix, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Reopens a prefix through NOFOLLOW custody and derives its file identity
/// from the exact bytes that were parsed. The caller never supplies a digest
/// for a not-yet-authenticated resume point.
pub fn openPrefix(
    allocator: std.mem.Allocator,
    path: []const u8,
) !OpenedPrefix {
    if (!std.fs.path.isAbsolute(path))
        return error.InvalidProviderStageBPrefix;
    const bytes = try artifact_io.readFileBounded(
        allocator,
        path,
        max_prefix_bytes,
    );
    errdefer allocator.free(bytes);
    var parsed = try parsePrefix(allocator, bytes);
    errdefer parsed.deinit();
    return .{
        .bytes = bytes,
        .file = evidence.identity(path, bytes),
        .parsed = parsed,
    };
}

/// Same reopen when the predecessor identity is already sealed by a later
/// authority. This rejects path, length, or digest drift before parsing.
pub fn openExpectedPrefix(
    allocator: std.mem.Allocator,
    expected: contract.Identity,
) !OpenedPrefix {
    const bytes = try support.readIdentity(
        allocator,
        expected,
        max_prefix_bytes,
    );
    errdefer allocator.free(bytes);
    var parsed = try parsePrefix(allocator, bytes);
    errdefer parsed.deinit();
    return .{
        .bytes = bytes,
        .file = evidence.identity(expected.path, bytes),
        .parsed = parsed,
    };
}

pub fn publishPrefixCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}

pub fn validateAgainst(
    prefix: Prefix,
    authority_value: Authority,
) !void {
    try prefix.validate();
    try authority_value.validate();
    const context = authority_value.context;
    if (!identityMatches(prefix.call_artifact, authority_value.call_artifact) or
        !std.mem.eql(
            u8,
            prefix.call_artifact_content_sha256,
            &hex(authority_value.call_artifact_content_sha256),
        ) or !std.mem.eql(
        u8,
        prefix.call_list_commitment_sha256,
        &hex(context.plan.call_list_commitment),
    ) or !std.mem.eql(
        u8,
        prefix.manifest_identity_sha256,
        &hex(context.stage_a_reopened.manifest.identity),
    ) or !std.mem.eql(
        u8,
        prefix.plan_identity_sha256,
        &hex(context.plan.identity),
    ) or !std.mem.eql(
        u8,
        prefix.relation_context_identity_sha256,
        &hex(context.stage_a_reopened.shared_relation.relation_context.identity),
    ) or !std.mem.eql(
        u8,
        prefix.resource_plan_identity_sha256,
        &hex(context.resource_plan.identity),
    ) or !std.mem.eql(
        u8,
        prefix.session_sha256,
        &hex(context.plan.session),
    ) or prefix.shard_count != context.plan.shard_count or
        !identityMatches(prefix.stage_a_checkpoint, context.stage_a_checkpoint) or
        !std.mem.eql(
            u8,
            prefix.stage_a_checkpoint_content_sha256,
            &hex(context.stage_a_checkpoint_content_sha256),
        ))
    {
        return error.ProviderStageBPrefixAuthorityMismatch;
    }
    try validateCoreAgainst(prefix.core, context);
    for (prefix.providers, 0..) |provider, index|
        try validateProviderAgainst(provider, context, index);
}

pub fn validateSuccessor(
    previous: Prefix,
    previous_file: evidence.FileIdentity,
    next: Prefix,
) !void {
    try previous.validate();
    try next.validate();
    const expected_next = std.math.add(
        u32,
        previous.next_provider_ordinal,
        1,
    ) catch return error.NonCanonicalProviderStageBSuccessor;
    if (next.next_provider_ordinal != expected_next or
        next.providers.len != previous.providers.len + 1 or
        next.previous_prefix == null or
        !identityMatches(next.previous_prefix.?, previous_file) or
        !std.mem.eql(
            u8,
            next.previous_prefix_content_sha256.?,
            previous.content_sha256,
        ) or !coreRecordsEqual(next.core, previous.core) or
        !samePrefixAuthority(previous, next))
    {
        return error.NonCanonicalProviderStageBSuccessor;
    }
    for (previous.providers, next.providers[0..previous.providers.len]) |
        expected,
        actual,
    | if (!providerRecordsEqual(expected, actual))
        return error.NonCanonicalProviderStageBSuccessor;
}

/// Final transaction: reopen every retained proof named by the complete
/// prefix, freshly verify it against the independently reopened authorities,
/// compare the verifier-minted claims to the journal, and close only that
/// exact ordered set. No prior receipt is treated as proof authority.
pub fn reverifyCompleteAndClose(
    allocator: std.mem.Allocator,
    authority_value: Authority,
    expected_producer_sha256: [32]u8,
    verifier_sha256: [32]u8,
    prefix: Prefix,
) !provider_v2.VerifiedJointClosureV2 {
    try validateAgainst(prefix, authority_value);
    if (!prefix.complete_ordered_provider_prefix or
        prefix.providers.len != authority_value.context.plan.shard_count)
    {
        return error.IncompleteProviderProofPrefix;
    }
    var fresh_core = try lifecycle.verifyCoreFresh(
        allocator,
        authority_value.context,
        expected_producer_sha256,
        verifier_sha256,
        try evidenceIdentity(prefix.core.artifact),
    );
    defer fresh_core.deinit(allocator);
    try compareFreshCore(prefix.core, &fresh_core);

    const claims = try allocator.alloc(
        provider_v2.FreshProviderClaimV2,
        prefix.providers.len,
    );
    defer allocator.free(claims);
    for (prefix.providers, claims, 0..) |record, *claim, index| {
        var fresh = try lifecycle.verifyProviderV2Fresh(
            allocator,
            authority_value.context,
            expected_producer_sha256,
            verifier_sha256,
            @intCast(index),
            try evidenceIdentity(record.artifact),
        );
        defer fresh.deinit(allocator);
        try compareFreshProvider(record, &fresh);
        claim.* = fresh.claim;
    }
    return lifecycle.closeFreshV2(
        allocator,
        authority_value.context,
        fresh_core.claim,
        claims,
    );
}

pub fn encodeFinalReceipt(
    allocator: std.mem.Allocator,
    authority_value: Authority,
    complete_prefix: Prefix,
    complete_prefix_file: evidence.FileIdentity,
    closure: provider_v2.VerifiedJointClosureV2,
) ![]u8 {
    try validateAgainst(complete_prefix, authority_value);
    if (!complete_prefix.complete_ordered_provider_prefix or
        complete_prefix_file.bytes == 0 or
        !std.fs.path.isAbsolute(complete_prefix_file.path))
    {
        return error.IncompleteProviderProofPrefix;
    }
    try closure.validate();
    const context = authority_value.context;
    if (!std.meta.eql(closure.plan_identity, context.plan.identity) or
        !std.meta.eql(
            closure.manifest_identity,
            context.stage_a_reopened.manifest.identity,
        ) or !std.meta.eql(
        closure.relation_context_identity,
        context.stage_a_reopened.shared_relation.relation_context.identity,
    ) or closure.shard_count != context.plan.shard_count) {
        return error.ProviderJointClosureAuthorityMismatch;
    }
    const placeholder = [_]u8{'0'} ** 64;
    const prefix_sha = hex(complete_prefix_file.sha256);
    const core_claim = hex(closure.core_claim_identity);
    const closure_identity = hex(closure.identity);
    const manifest = hex(closure.manifest_identity);
    const ordered_claims = hex(closure.ordered_provider_claims_identity);
    const plan = hex(closure.plan_identity);
    const relation = hex(closure.relation_context_identity);
    const value = FinalReceipt{
        .content_sha256 = &placeholder,
        .closure = .{
            .closed_sum_m31 = qm31Words(closure.closed_sum),
            .complete_ordered_coverage = closure.complete_ordered_coverage,
            .core_claim_identity_sha256 = &core_claim,
            .core_claim_m31 = qm31Words(closure.core_claim),
            .every_ordered_call_air_verified = closure.every_ordered_call_air_verified,
            .every_proof_freshly_verified = closure.every_proof_freshly_verified,
            .format = closure.format,
            .identity_sha256 = &closure_identity,
            .manifest_identity_sha256 = &manifest,
            .one_shared_relation_context = closure.one_shared_relation_context,
            .ordered_provider_claims_identity_sha256 = &ordered_claims,
            .plan_identity_sha256 = &plan,
            .production_eligible = closure.production_eligible,
            .provider_claim_m31 = qm31Words(closure.provider_claim),
            .relation_context_identity_sha256 = &relation,
            .shard_count = closure.shard_count,
        },
        .complete_prefix = identity(complete_prefix_file, &prefix_sha),
        .complete_prefix_content_sha256 = complete_prefix.content_sha256,
        .production_eligible = false,
        .recursive_admissible = false,
        .schema = closure_schema,
        .status = closure_status,
    };
    const bytes = try sealValue(allocator, value);
    errdefer allocator.free(bytes);
    var parsed = try parseFinalReceipt(allocator, bytes);
    parsed.deinit();
    return bytes;
}

pub fn parseFinalReceipt(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(FinalReceipt) {
    if (bytes.len == 0 or bytes.len > max_closure_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(FinalReceipt, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    try requireCanonical(allocator, bytes, parsed.value);
    try parsed.value.validate();
    const closure = try closureValue(parsed.value.closure);
    try closure.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn publishFinalCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}

pub fn closureValue(
    value: ClosureWire,
) !provider_v2.VerifiedJointClosureV2 {
    try value.validate();
    const result = provider_v2.VerifiedJointClosureV2{
        .format = value.format,
        .plan_identity = try contract.parseSha256(value.plan_identity_sha256),
        .manifest_identity = try contract.parseSha256(
            value.manifest_identity_sha256,
        ),
        .relation_context_identity = try contract.parseSha256(
            value.relation_context_identity_sha256,
        ),
        .core_claim_identity = try contract.parseSha256(
            value.core_claim_identity_sha256,
        ),
        .ordered_provider_claims_identity = try contract.parseSha256(
            value.ordered_provider_claims_identity_sha256,
        ),
        .shard_count = value.shard_count,
        .core_claim = qm31(value.core_claim_m31),
        .provider_claim = qm31(value.provider_claim_m31),
        .closed_sum = qm31(value.closed_sum_m31),
        .every_proof_freshly_verified = value.every_proof_freshly_verified,
        .every_ordered_call_air_verified = value.every_ordered_call_air_verified,
        .complete_ordered_coverage = value.complete_ordered_coverage,
        .one_shared_relation_context = value.one_shared_relation_context,
        .production_eligible = value.production_eligible,
        .identity = try contract.parseSha256(value.identity_sha256),
    };
    try result.validate();
    return result;
}

fn validateFreshCore(
    authority_value: Authority,
    fresh: *const lifecycle.FreshCore,
) !void {
    try fresh.claim.validate();
    const context = authority_value.context;
    if (!std.meta.eql(fresh.claim.plan_identity, context.plan.identity) or
        !std.meta.eql(
            fresh.claim.manifest_identity,
            context.stage_a_reopened.manifest.identity,
        ) or !std.meta.eql(
        fresh.claim.relation_context_identity,
        context.stage_a_reopened.shared_relation.relation_context.identity,
    )) return error.ProviderStageBPrefixAuthorityMismatch;
}

fn validateFreshProvider(
    authority_value: Authority,
    ordinal: u32,
    fresh: *const lifecycle.FreshProviderV2,
) !void {
    try fresh.claim.validate();
    const context = authority_value.context;
    if (ordinal >= context.plan.shard_count)
        return error.ShardIndexOutOfRange;
    const descriptor = context.plan.shards[ordinal];
    if (fresh.claim.native_claim.shard_index != ordinal or
        !std.meta.eql(
            fresh.claim.manifest_identity,
            context.stage_a_reopened.manifest.identity,
        ) or !std.meta.eql(
        fresh.claim.native_claim.plan_identity,
        context.plan.identity,
    ) or !std.meta.eql(
        fresh.claim.native_claim.descriptor_identity,
        descriptor.identity,
    ) or !std.meta.eql(
        fresh.claim.native_claim.relation_context_identity,
        context.stage_a_reopened.shared_relation.relation_context.identity,
    ) or fresh.claim.ordered_call_claim.first_call != descriptor.first_call or
        fresh.claim.ordered_call_claim.call_count != descriptor.call_count)
    {
        return error.ProviderStageBPrefixAuthorityMismatch;
    }
}

fn compareFreshCore(
    record: CoreRecord,
    fresh: *const lifecycle.FreshCore,
) !void {
    if (!identityMatches(record.artifact, fresh.artifact.borrowed()) or
        !identityMatches(record.proof, fresh.proof.borrowed()) or
        !std.mem.eql(
            u8,
            record.artifact_content_sha256,
            &hex(fresh.artifact_content_sha256),
        ) or !std.mem.eql(
        u8,
        record.claim_identity_sha256,
        &hex(fresh.claim.identity),
    ) or !std.mem.eql(
        u8,
        record.proof_commitments_identity_sha256,
        &hex(fresh.claim.proof_commitments_identity),
    ) or !std.mem.eql(
        u8,
        record.statement_identity_sha256,
        &hex(fresh.claim.statement_identity),
    ) or !std.mem.eql(
        u8,
        record.verifier_sha256,
        &hex(fresh.verifier_sha256),
    )) return error.ProviderStageBFreshVerificationMismatch;
}

fn compareFreshProvider(
    record: ProviderRecord,
    fresh: *const lifecycle.FreshProviderV2,
) !void {
    if (!identityMatches(record.artifact, fresh.artifact.borrowed()) or
        !identityMatches(record.proof, fresh.proof.borrowed()) or
        !std.mem.eql(
            u8,
            record.artifact_content_sha256,
            &hex(fresh.artifact_content_sha256),
        ) or !std.mem.eql(
        u8,
        record.claim_identity_sha256,
        &hex(fresh.claim.identity),
    ) or !std.mem.eql(
        u8,
        record.proof_commitments_identity_sha256,
        &hex(fresh.claim.proof_commitments_identity),
    ) or !std.mem.eql(
        u8,
        record.statement_identity_sha256,
        &hex(fresh.claim.statement_identity),
    ) or !std.mem.eql(
        u8,
        record.verifier_sha256,
        &hex(fresh.verifier_sha256),
    ) or !std.meta.eql(
        record.ordered_call_terminal_m31,
        qm31Words(fresh.claim.ordered_call_claim.terminal),
    )) return error.ProviderStageBFreshVerificationMismatch;
}

fn validateCoreAgainst(
    record: CoreRecord,
    context: lifecycle.Context,
) !void {
    if (!std.mem.eql(
        u8,
        record.manifest_identity_sha256,
        &hex(context.stage_a_reopened.manifest.identity),
    ) or !std.mem.eql(
        u8,
        record.relation_context_identity_sha256,
        &hex(context.stage_a_reopened.shared_relation.relation_context.identity),
    )) return error.ProviderStageBPrefixAuthorityMismatch;
}

fn validateProviderAgainst(
    record: ProviderRecord,
    context: lifecycle.Context,
    index: usize,
) !void {
    if (index >= context.plan.shards.len)
        return error.ShardIndexOutOfRange;
    const descriptor = context.plan.shards[index];
    if (record.shard_index != index or
        record.first_call != descriptor.first_call or
        record.call_count != descriptor.call_count or
        !std.mem.eql(
            u8,
            record.descriptor_identity_sha256,
            &hex(descriptor.identity),
        ) or !std.mem.eql(
        u8,
        record.manifest_identity_sha256,
        &hex(context.stage_a_reopened.manifest.identity),
    ) or !std.mem.eql(
        u8,
        record.relation_context_identity_sha256,
        &hex(context.stage_a_reopened.shared_relation.relation_context.identity),
    )) return error.ProviderStageBPrefixAuthorityMismatch;
}

fn coreStorage(fresh: *const lifecycle.FreshCore) CoreHexStorage {
    return .{
        .artifact = hex(fresh.artifact.sha256),
        .artifact_content = hex(fresh.artifact_content_sha256),
        .claim = hex(fresh.claim.identity),
        .manifest = hex(fresh.claim.manifest_identity),
        .proof = hex(fresh.proof.sha256),
        .proof_commitments = hex(fresh.claim.proof_commitments_identity),
        .relation = hex(fresh.claim.relation_context_identity),
        .statement = hex(fresh.claim.statement_identity),
        .verifier = hex(fresh.verifier_sha256),
    };
}

fn providerStorage(fresh: *const lifecycle.FreshProviderV2) ProviderHexStorage {
    return .{
        .artifact = hex(fresh.artifact.sha256),
        .artifact_content = hex(fresh.artifact_content_sha256),
        .claim = hex(fresh.claim.identity),
        .descriptor = hex(fresh.claim.native_claim.descriptor_identity),
        .manifest = hex(fresh.claim.manifest_identity),
        .proof = hex(fresh.proof.sha256),
        .proof_commitments = hex(fresh.claim.proof_commitments_identity),
        .relation = hex(fresh.claim.native_claim.relation_context_identity),
        .statement = hex(fresh.claim.statement_identity),
        .verifier = hex(fresh.verifier_sha256),
    };
}

fn prefixStorage(value: Authority) PrefixHexStorage {
    const context = value.context;
    return .{
        .call_artifact = hex(value.call_artifact.sha256),
        .call_artifact_content = hex(value.call_artifact_content_sha256),
        .call_list = hex(context.plan.call_list_commitment),
        .manifest = hex(context.stage_a_reopened.manifest.identity),
        .plan = hex(context.plan.identity),
        .relation = hex(
            context.stage_a_reopened.shared_relation.relation_context.identity,
        ),
        .resource_plan = hex(context.resource_plan.identity),
        .session = hex(context.plan.session),
        .stage_a = hex(context.stage_a_checkpoint.sha256),
        .stage_a_content = hex(context.stage_a_checkpoint_content_sha256),
    };
}

fn coreRecord(
    fresh: *const lifecycle.FreshCore,
    storage: *const CoreHexStorage,
) CoreRecord {
    return .{
        .artifact = ownedIdentity(fresh.artifact, &storage.artifact),
        .artifact_content_sha256 = &storage.artifact_content,
        .claim_identity_sha256 = &storage.claim,
        .manifest_identity_sha256 = &storage.manifest,
        .proof = ownedIdentity(fresh.proof, &storage.proof),
        .proof_commitments_identity_sha256 = &storage.proof_commitments,
        .relation_context_identity_sha256 = &storage.relation,
        .statement_identity_sha256 = &storage.statement,
        .verifier_sha256 = &storage.verifier,
        .verify_timing = fresh.verify_timing,
    };
}

fn providerRecord(
    fresh: *const lifecycle.FreshProviderV2,
    storage: *const ProviderHexStorage,
) ProviderRecord {
    return .{
        .artifact = ownedIdentity(fresh.artifact, &storage.artifact),
        .artifact_content_sha256 = &storage.artifact_content,
        .call_count = fresh.claim.ordered_call_claim.call_count,
        .claim_identity_sha256 = &storage.claim,
        .descriptor_identity_sha256 = &storage.descriptor,
        .first_call = fresh.claim.ordered_call_claim.first_call,
        .manifest_identity_sha256 = &storage.manifest,
        .ordered_call_air_verified = fresh.claim.ordered_call_air_verified,
        .ordered_call_claim_recomputed = fresh.claim.ordered_call_claim_recomputed,
        .ordered_call_terminal_m31 = qm31Words(
            fresh.claim.ordered_call_claim.terminal,
        ),
        .proof = ownedIdentity(fresh.proof, &storage.proof),
        .proof_commitments_identity_sha256 = &storage.proof_commitments,
        .relation_context_identity_sha256 = &storage.relation,
        .shard_index = fresh.claim.native_claim.shard_index,
        .statement_identity_sha256 = &storage.statement,
        .verifier_sha256 = &storage.verifier,
        .verify_timing = fresh.verify_timing,
    };
}

fn sealPrefix(allocator: std.mem.Allocator, value: Prefix) ![]u8 {
    const bytes = try sealValue(allocator, value);
    errdefer allocator.free(bytes);
    var parsed = try parsePrefix(allocator, bytes);
    parsed.deinit();
    return bytes;
}

fn sealValue(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const with_placeholder = try std.json.Stringify.valueAlloc(
        allocator,
        value,
        .{},
    );
    defer allocator.free(with_placeholder);
    const unsigned = try removeContentPlaceholder(allocator, with_placeholder);
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

fn requireCanonical(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    value: anytype,
) !void {
    const canonical = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
}

fn removeContentPlaceholder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderStageBPrefix;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderStageBPrefix;
    return std.fmt.allocPrint(allocator, "{{{s}", .{bytes[end + 2 ..]});
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try contract.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidContentSha256;
    const start = prefix.len;
    const end = start + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',' or
        !std.mem.eql(u8, bytes[start..end], expected))
    {
        return error.InvalidContentSha256;
    }
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{bytes[end + 2 ..]},
    );
    defer allocator.free(unsigned);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    if (!std.mem.eql(u8, &hex(digest), expected))
        return error.InvalidContentSha256;
}

fn samePrefixAuthority(left: Prefix, right: Prefix) bool {
    return identityEqual(left.call_artifact, right.call_artifact) and
        std.mem.eql(
            u8,
            left.call_artifact_content_sha256,
            right.call_artifact_content_sha256,
        ) and std.mem.eql(
        u8,
        left.call_list_commitment_sha256,
        right.call_list_commitment_sha256,
    ) and std.mem.eql(
        u8,
        left.manifest_identity_sha256,
        right.manifest_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.plan_identity_sha256,
        right.plan_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.relation_context_identity_sha256,
        right.relation_context_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.resource_plan_identity_sha256,
        right.resource_plan_identity_sha256,
    ) and std.mem.eql(u8, left.session_sha256, right.session_sha256) and
        left.shard_count == right.shard_count and
        identityEqual(left.stage_a_checkpoint, right.stage_a_checkpoint) and
        std.mem.eql(
            u8,
            left.stage_a_checkpoint_content_sha256,
            right.stage_a_checkpoint_content_sha256,
        );
}

fn coreRecordsEqual(left: CoreRecord, right: CoreRecord) bool {
    return identityEqual(left.artifact, right.artifact) and
        std.mem.eql(
            u8,
            left.artifact_content_sha256,
            right.artifact_content_sha256,
        ) and std.mem.eql(
        u8,
        left.claim_identity_sha256,
        right.claim_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.manifest_identity_sha256,
        right.manifest_identity_sha256,
    ) and identityEqual(left.proof, right.proof) and std.mem.eql(
        u8,
        left.proof_commitments_identity_sha256,
        right.proof_commitments_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.relation_context_identity_sha256,
        right.relation_context_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.statement_identity_sha256,
        right.statement_identity_sha256,
    ) and std.mem.eql(u8, left.verifier_sha256, right.verifier_sha256) and
        std.meta.eql(left.verify_timing, right.verify_timing);
}

fn providerRecordsEqual(left: ProviderRecord, right: ProviderRecord) bool {
    return identityEqual(left.artifact, right.artifact) and
        std.mem.eql(
            u8,
            left.artifact_content_sha256,
            right.artifact_content_sha256,
        ) and left.call_count == right.call_count and std.mem.eql(
        u8,
        left.claim_identity_sha256,
        right.claim_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.descriptor_identity_sha256,
        right.descriptor_identity_sha256,
    ) and left.first_call == right.first_call and std.mem.eql(
        u8,
        left.manifest_identity_sha256,
        right.manifest_identity_sha256,
    ) and left.ordered_call_air_verified ==
        right.ordered_call_air_verified and
        left.ordered_call_claim_recomputed ==
            right.ordered_call_claim_recomputed and
        std.meta.eql(
            left.ordered_call_terminal_m31,
            right.ordered_call_terminal_m31,
        ) and identityEqual(left.proof, right.proof) and std.mem.eql(
        u8,
        left.proof_commitments_identity_sha256,
        right.proof_commitments_identity_sha256,
    ) and std.mem.eql(
        u8,
        left.relation_context_identity_sha256,
        right.relation_context_identity_sha256,
    ) and left.shard_index == right.shard_index and std.mem.eql(
        u8,
        left.statement_identity_sha256,
        right.statement_identity_sha256,
    ) and std.mem.eql(u8, left.verifier_sha256, right.verifier_sha256) and
        std.meta.eql(left.verify_timing, right.verify_timing);
}

fn identityEqual(left: contract.Identity, right: contract.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn identityMatches(
    actual: contract.Identity,
    expected: evidence.FileIdentity,
) bool {
    if (actual.bytes != expected.bytes or
        !std.mem.eql(u8, actual.path, expected.path)) return false;
    const digest = contract.parseSha256(actual.sha256) catch return false;
    return std.meta.eql(digest, expected.sha256);
}

fn evidenceIdentity(value: contract.Identity) !evidence.FileIdentity {
    return .{
        .bytes = value.bytes,
        .path = value.path,
        .sha256 = try contract.parseSha256(value.sha256),
    };
}

fn identity(value: evidence.FileIdentity, digest: *const [64]u8) contract.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = digest };
}

fn ownedIdentity(
    value: lifecycle.OwnedFileIdentity,
    digest: *const [64]u8,
) contract.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = digest };
}

fn qm31Words(value: QM31) [4]u32 {
    var result: [4]u32 = undefined;
    for (value.toM31Array(), &result) |word, *destination|
        destination.* = word.toU32();
    return result;
}

fn qm31(words: [4]u32) QM31 {
    return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

comptime {
    if (provider_v2.ACTIVATES_PRODUCTION_PROOF or
        !provider_v2.PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        provider_v2.FULL_RISCV_CORE_EXTERNALIZED or
        provider_v2.RECURSIVE_VERIFICATION_IMPLEMENTED)
    {
        @compileError("provider Stage-B prefix readiness drifted");
    }
}

pub const testing = struct {
    pub fn structuralPrefixChain(allocator: std.mem.Allocator) !void {
        const digest = [_]u8{0x61} ** 32;
        const digest_hex = hex(digest);
        const placeholder = [_]u8{'0'} ** 64;
        const file = contract.Identity{
            .bytes = 17,
            .path = "/retained/artifact",
            .sha256 = &digest_hex,
        };
        const core_record = CoreRecord{
            .artifact = file,
            .artifact_content_sha256 = &digest_hex,
            .claim_identity_sha256 = &digest_hex,
            .manifest_identity_sha256 = &digest_hex,
            .proof = file,
            .proof_commitments_identity_sha256 = &digest_hex,
            .relation_context_identity_sha256 = &digest_hex,
            .statement_identity_sha256 = &digest_hex,
            .verifier_sha256 = &digest_hex,
            .verify_timing = .{ .wall_ns = 1, .user_ns = 0, .system_ns = 0 },
        };
        const prefix0_value = Prefix{
            .content_sha256 = &placeholder,
            .call_artifact = file,
            .call_artifact_content_sha256 = &digest_hex,
            .call_list_commitment_sha256 = &digest_hex,
            .complete_ordered_provider_prefix = false,
            .core = core_record,
            .manifest_identity_sha256 = &digest_hex,
            .next_provider_ordinal = 0,
            .plan_identity_sha256 = &digest_hex,
            .previous_prefix = null,
            .previous_prefix_content_sha256 = null,
            .production_eligible = false,
            .providers = &.{},
            .recursive_admissible = false,
            .relation_context_identity_sha256 = &digest_hex,
            .resource_plan_identity_sha256 = &digest_hex,
            .schema = prefix_schema,
            .session_sha256 = &digest_hex,
            .shard_count = 2,
            .stage_a_checkpoint = file,
            .stage_a_checkpoint_content_sha256 = &digest_hex,
            .status = prefix_status,
        };
        const prefix0_bytes = try sealPrefix(allocator, prefix0_value);
        defer allocator.free(prefix0_bytes);
        var prefix0 = try parsePrefix(allocator, prefix0_bytes);
        defer prefix0.deinit();
        const prefix0_file = evidence.identity(
            "/retained/prefix-0000.json",
            prefix0_bytes,
        );
        const prefix0_file_sha = hex(prefix0_file.sha256);
        const provider = ProviderRecord{
            .artifact = file,
            .artifact_content_sha256 = &digest_hex,
            .call_count = 11,
            .claim_identity_sha256 = &digest_hex,
            .descriptor_identity_sha256 = &digest_hex,
            .first_call = 0,
            .manifest_identity_sha256 = &digest_hex,
            .ordered_call_air_verified = true,
            .ordered_call_claim_recomputed = true,
            .ordered_call_terminal_m31 = .{ 1, 2, 3, 4 },
            .proof = file,
            .proof_commitments_identity_sha256 = &digest_hex,
            .relation_context_identity_sha256 = &digest_hex,
            .shard_index = 0,
            .statement_identity_sha256 = &digest_hex,
            .verifier_sha256 = &digest_hex,
            .verify_timing = .{ .wall_ns = 2, .user_ns = 0, .system_ns = 0 },
        };
        const providers = [_]ProviderRecord{provider};
        const prefix1_value = Prefix{
            .content_sha256 = &placeholder,
            .call_artifact = file,
            .call_artifact_content_sha256 = &digest_hex,
            .call_list_commitment_sha256 = &digest_hex,
            .complete_ordered_provider_prefix = false,
            .core = core_record,
            .manifest_identity_sha256 = &digest_hex,
            .next_provider_ordinal = 1,
            .plan_identity_sha256 = &digest_hex,
            .previous_prefix = identity(prefix0_file, &prefix0_file_sha),
            .previous_prefix_content_sha256 = prefix0.value.content_sha256,
            .production_eligible = false,
            .providers = &providers,
            .recursive_admissible = false,
            .relation_context_identity_sha256 = &digest_hex,
            .resource_plan_identity_sha256 = &digest_hex,
            .schema = prefix_schema,
            .session_sha256 = &digest_hex,
            .shard_count = 2,
            .stage_a_checkpoint = file,
            .stage_a_checkpoint_content_sha256 = &digest_hex,
            .status = prefix_status,
        };
        const prefix1_bytes = try sealPrefix(allocator, prefix1_value);
        defer allocator.free(prefix1_bytes);
        var prefix1 = try parsePrefix(allocator, prefix1_bytes);
        defer prefix1.deinit();
        try validateSuccessor(prefix0.value, prefix0_file, prefix1.value);

        var wrong_provider = provider;
        wrong_provider.shard_index = 1;
        const wrong_providers = [_]ProviderRecord{wrong_provider};
        var wrong_prefix = prefix1_value;
        wrong_prefix.providers = &wrong_providers;
        try std.testing.expectError(
            error.InvalidProviderStageBPrefix,
            sealPrefix(allocator, wrong_prefix),
        );
    }
};
