//! Final create-only result for an opt-in matched A/B baseline leaf proof.
//!
//! The ordinary proof, producer result, and detailed stage profile retain their
//! existing schemas. This final marker cold-binds those exact files to the
//! separately typed four-worker execution authority and is intentionally
//! ineligible for production admission.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const base = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const profile_receipt = @import("ethereum_poseidon_leaf_profile_receipt.zig");

const matched = frontend.prover_mod.guest_precompile
    .ethereum_leaf_matched_ab_execution_profile_v1;

pub const schema = "stwo.ethereum.poseidon-v4-leaf-matched-ab-result.v1";
pub const status = "proved-profiled-matched-ab-non-production";
pub const production_eligible = false;
pub const default_command_unchanged = true;
pub const max_result_bytes: usize = 1024 * 1024;

pub const ProfileAuthority = struct {
    format: u16,
    schema: u16,
    identity_sha256: []const u8,
    leaf_worker_count: u16,
    leaf_host_byte_budget: u64,
    leaf_contention_policy: []const u8,
    provider_concurrent_owner_limit: u16,
    provider_engine_worker_cap: u16,
    production_eligible: bool,
    proof_semantics_unchanged: bool,

    pub fn validate(self: ProfileAuthority) !void {
        const authority = matched.Authority.canonical();
        try authority.validate();
        const identity = try base.parseSha256(self.identity_sha256);
        if (self.format != authority.format or
            self.schema != authority.schema or
            self.leaf_worker_count != authority.leaf_workers or
            self.leaf_host_byte_budget != authority.leaf_host_budget_bytes or
            !std.mem.eql(u8, self.leaf_contention_policy, "strict") or
            self.provider_concurrent_owner_limit != authority.provider_owner_limit or
            self.provider_engine_worker_cap != authority.provider_worker_cap or
            self.production_eligible or
            !self.proof_semantics_unchanged or
            !std.mem.eql(u8, &identity, &authority.identity))
        {
            return error.InvalidMatchedAbProfileAuthority;
        }
    }
};

pub const Result = struct {
    content_sha256: []const u8,
    default_command_unchanged: bool,
    ordinary_result_validated: bool,
    producer_result: base.Identity,
    producer_sha256: []const u8,
    production_eligible: bool,
    profile: ProfileAuthority,
    profile_receipt: base.Identity,
    profile_receipt_validated: bool,
    proof: base.Identity,
    request: base.Identity,
    request_content_sha256: []const u8,
    schema: []const u8,
    segment_index: u32,
    status: []const u8,

    pub fn validate(self: Result) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            self.production_eligible or
            !self.default_command_unchanged or
            !self.ordinary_result_validated or
            !self.profile_receipt_validated)
        {
            return error.InvalidMatchedAbLeafResult;
        }
        try self.profile.validate();
        try self.producer_result.validate(false);
        try self.profile_receipt.validate(false);
        try self.proof.validate(false);
        try self.request.validate(false);
        inline for (.{
            self.producer_result.path,
            self.profile_receipt.path,
            self.proof.path,
            self.request.path,
        }) |path| if (!std.fs.path.isAbsolute(path))
            return error.InvalidMatchedAbLeafResult;
        inline for (.{
            self.content_sha256,
            self.producer_sha256,
            self.request_content_sha256,
        }) |digest| _ = try base.parseSha256(digest);
    }

    pub fn validateAgainst(
        self: Result,
        ordinary: product.ProducerResult,
        profile_value: profile_receipt.Receipt,
    ) !void {
        try self.validate();
        try ordinary.validate();
        try profile_value.validate();
        if (ordinary.segment_index != self.segment_index or
            profile_value.segment_index != self.segment_index or
            !std.mem.eql(
                u8,
                ordinary.producer_sha256,
                self.producer_sha256,
            ) or !std.mem.eql(
            u8,
            profile_value.producer_sha256,
            self.producer_sha256,
        ) or !std.mem.eql(
            u8,
            ordinary.request_sha256,
            self.request_content_sha256,
        ) or !identityEql(ordinary.proof, self.proof) or
            !identityEql(profile_value.proof, self.proof) or
            !identityEql(profile_value.request, self.request) or
            !identityEql(
                profile_value.producer_result,
                self.producer_result,
            ) or profile_value.execution_policy.worker_count !=
            matched.leaf_worker_count or
            profile_value.execution_policy.host_byte_budget !=
                matched.leaf_host_byte_budget or
            profile_value.execution_policy.host_byte_budget_unbounded or
            !std.mem.eql(
                u8,
                profile_value.execution_policy.contention_policy,
                "strict",
            ))
        {
            return error.MatchedAbLeafResultAuthorityMismatch;
        }
    }
};

pub const Input = struct {
    default_command_unchanged: bool = default_command_unchanged,
    ordinary_result_validated: bool = true,
    producer_result: base.Identity,
    producer_sha256: []const u8,
    production_eligible: bool = production_eligible,
    profile: ProfileAuthority,
    profile_receipt: base.Identity,
    profile_receipt_validated: bool = true,
    proof: base.Identity,
    request: base.Identity,
    request_content_sha256: []const u8,
    schema: []const u8 = schema,
    segment_index: u32,
    status: []const u8 = status,
};

pub fn profileAuthority(
    authority: matched.Authority,
    identity_hex: *const [64]u8,
) !ProfileAuthority {
    try authority.validate();
    const expected_identity = std.fmt.bytesToHex(authority.identity, .lower);
    if (!std.mem.eql(u8, identity_hex, &expected_identity))
        return error.InvalidMatchedAbProfileAuthority;
    return .{
        .format = authority.format,
        .schema = authority.schema,
        .identity_sha256 = identity_hex,
        .leaf_worker_count = authority.leaf_workers,
        .leaf_host_byte_budget = authority.leaf_host_budget_bytes,
        .leaf_contention_policy = "strict",
        .provider_concurrent_owner_limit = authority.provider_owner_limit,
        .provider_engine_worker_cap = authority.provider_worker_cap,
        .production_eligible = authority.production_eligible,
        .proof_semantics_unchanged = authority.proof_semantics_unchanged,
    };
}

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
    const unsigned = try std.json.Stringify.valueAlloc(allocator, input, .{});
    defer allocator.free(unsigned);
    const bytes = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    parsed.deinit();
    return bytes;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Result) {
    if (bytes.len == 0 or bytes.len > max_result_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Result, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    try parsed.value.validate();
    try validateSeal(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

fn identityEql(left: base.Identity, right: base.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn validateSeal(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try base.parseSha256(expected);
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
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, expected))
        return error.InvalidContentSha256;
}

test "matched A/B result seals its exact typed execution profile" {
    const allocator = std.testing.allocator;
    const authority = matched.Authority.canonical();
    const authority_hex = std.fmt.bytesToHex(authority.identity, .lower);
    const digest = [_]u8{'a'} ** 64;
    const bytes = try encode(allocator, .{
        .producer_result = fixtureIdentity("/retained/result.json", &digest),
        .producer_sha256 = &digest,
        .profile = try profileAuthority(authority, &authority_hex),
        .profile_receipt = fixtureIdentity("/retained/profile.json", &digest),
        .proof = fixtureIdentity("/retained/proof.stw", &digest),
        .request = fixtureIdentity("/retained/request.json", &digest),
        .request_content_sha256 = &digest,
        .segment_index = 0,
    });
    defer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 4), parsed.value.profile.leaf_worker_count);
    try std.testing.expectEqual(
        @as(u64, 48 * 1024 * 1024 * 1024),
        parsed.value.profile.leaf_host_byte_budget,
    );

    var mutated = parsed.value;
    mutated.profile.leaf_worker_count = 8;
    try std.testing.expectError(
        error.InvalidMatchedAbProfileAuthority,
        mutated.validate(),
    );
}

fn fixtureIdentity(path: []const u8, digest: []const u8) base.Identity {
    return .{ .bytes = 1, .path = path, .sha256 = digest };
}
