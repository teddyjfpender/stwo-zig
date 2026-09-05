//! Cold-admission receipt for the retained unoptimized Ethereum leaf baseline.
//!
//! This receipt binds exact executable and corpus bytes, then records the
//! authority reconstructed from SourceRequest V2, its materialization, the
//! selected STWESG31 leaf and the one-leaf request.  It deliberately has no
//! Git source closure and therefore cannot authorize production or proof/H1
//! admission.  Those limitations are data, not comments, and are fail-closed.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

const evidence = @import("ethereum_block_leaf_evidence.zig");

pub const Digest = [32]u8;
pub const schema =
    "stwo.ethereum.unoptimized-baseline-cold-admission-receipt.v1";
pub const format_version: u16 = 1;
pub const authority_scope = "bytes-build-profile-only";
pub const admission_status = "cold-admitted-non-production";
pub const h1_status = "pending-leaf-proof-and-cold-fresh-verification";
pub const production_eligible = false;
pub const proof_or_fresh_verification = false;
pub const git_source_closure_present = false;

const authority_identity_domain =
    "stwo.ethereum.unoptimized-baseline-authority.v1\x00";

pub const FileIdentity = struct {
    bytes: u64,
    path: []const u8,
    sha256: Digest,

    pub fn validate(self: FileIdentity, allow_empty: bool) !void {
        if (!std.fs.path.isAbsolute(self.path) or
            (!allow_empty and self.bytes == 0) or isZero(self.sha256))
        {
            return error.InvalidUnoptimizedBaselineFileIdentity;
        }
    }
};

pub const BuildAuthority = struct {
    authority_scope: []const u8 = authority_scope,
    host_executable: FileIdentity,
    immutable_guest_elf: FileIdentity,
    source_declared_guest_elf: FileIdentity,
    git_source_closure_present: bool = git_source_closure_present,
    git_source_closure_identity: ?Digest = null,

    pub fn validate(self: BuildAuthority) !void {
        try self.host_executable.validate(false);
        try self.immutable_guest_elf.validate(false);
        try self.source_declared_guest_elf.validate(false);
        if (!std.mem.eql(u8, self.authority_scope, authority_scope) or
            self.git_source_closure_present or
            self.git_source_closure_identity != null or
            self.immutable_guest_elf.bytes !=
                self.source_declared_guest_elf.bytes or
            !std.mem.eql(
                u8,
                &self.immutable_guest_elf.sha256,
                &self.source_declared_guest_elf.sha256,
            ))
        {
            return error.InvalidUnoptimizedBaselineBuildAuthority;
        }
    }
};

pub const CorpusAuthority = struct {
    source_request_v2: FileIdentity,
    materialization_v2: FileIdentity,
    execution_journal: FileIdentity,
    input: FileIdentity,
    expected_output: FileIdentity,
    selected_source_segment: FileIdentity,
    leaf_request: FileIdentity,

    pub fn validate(self: CorpusAuthority) !void {
        try self.source_request_v2.validate(false);
        try self.materialization_v2.validate(false);
        try self.execution_journal.validate(false);
        try self.input.validate(true);
        try self.expected_output.validate(false);
        try self.selected_source_segment.validate(false);
        try self.leaf_request.validate(false);
    }
};

pub const ProfileAuthority = struct {
    execution_profile: []const u8,
    profile_wire_id: u16,
    profile_abi_version: u16,
    profile_semantic_digest: Digest,
    segment_step_budget: u64,

    pub fn validate(self: ProfileAuthority) !void {
        if (!std.mem.eql(
            u8,
            self.execution_profile,
            "rv32im-zkvm-ethereum-v1",
        ) or self.profile_wire_id != 3 or self.profile_abi_version != 1 or
            isZero(self.profile_semantic_digest) or self.segment_step_budget == 0)
        {
            return error.InvalidUnoptimizedBaselineProfileAuthority;
        }
    }
};

pub const JobAuthority = struct {
    final_state_sha256: Digest,
    initial_state_sha256: Digest,
    job_sha256: Digest,
    program_m31_le: Digest,
    public_input_m31_le: Digest,
    public_output_m31_le: Digest,

    pub fn validate(self: JobAuthority) !void {
        inline for (.{
            self.final_state_sha256,
            self.initial_state_sha256,
            self.job_sha256,
        }) |digest| if (isZero(digest))
            return error.InvalidUnoptimizedBaselineJobAuthority;
        inline for (.{
            self.program_m31_le,
            self.public_input_m31_le,
            self.public_output_m31_le,
        }) |digest| if (!isCanonicalM31Digest(digest))
            return error.InvalidUnoptimizedBaselineJobAuthority;
    }
};

pub const LeafAuthority = struct {
    segment_index: u32,
    segment_count: u32,
    total_cycles: u64,
    global_cycle_start: u64,
    global_cycle_end: u64,
    local_cycle_count: u32,
    materialization_content_sha256: Digest,
    leaf_request_content_sha256: Digest,
    producer_executable_sha256: Digest,
    verifier_executable_sha256: Digest,
    session_sha256: Digest,
    session_m31_le: Digest,
    journal_record_sha256: Digest,
    metadata_id_m31_le: Digest,
    statement_id_m31_le: Digest,
    source_public_statement_sha256: Digest,
    recursive_statement_sha256: Digest,
    job: JobAuthority,
    open_authority_reconstructed: bool,
    session_reconstructed: bool,
    statement_reconstructed: bool,
    h1_status: []const u8 = h1_status,

    pub fn validate(self: LeafAuthority, host_sha256: Digest) !void {
        try self.job.validate();
        const expected_end = std.math.add(
            u64,
            self.global_cycle_start,
            self.local_cycle_count,
        ) catch return error.InvalidUnoptimizedBaselineLeafAuthority;
        if (self.segment_count < 2 or self.segment_index >= self.segment_count or
            self.total_cycles == 0 or self.local_cycle_count == 0 or
            self.global_cycle_end != expected_end or
            !std.mem.eql(
                u8,
                &self.producer_executable_sha256,
                &host_sha256,
            ) or !std.mem.eql(
            u8,
            &self.verifier_executable_sha256,
            &host_sha256,
        ) or isZero(self.materialization_content_sha256) or
            isZero(self.leaf_request_content_sha256) or
            isZero(self.session_sha256) or
            !isCanonicalM31Digest(self.session_m31_le) or
            isZero(self.journal_record_sha256) or
            !isCanonicalM31Digest(self.metadata_id_m31_le) or
            !isCanonicalM31Digest(self.statement_id_m31_le) or
            isZero(self.source_public_statement_sha256) or
            isZero(self.recursive_statement_sha256) or
            !self.open_authority_reconstructed or !self.session_reconstructed or
            !self.statement_reconstructed or
            !std.mem.eql(u8, self.h1_status, h1_status))
        {
            return error.InvalidUnoptimizedBaselineLeafAuthority;
        }
    }
};

pub const AuthorityBody = struct {
    format_version: u16 = format_version,
    status: []const u8 = admission_status,
    production_eligible: bool = production_eligible,
    proof_or_fresh_verification: bool = proof_or_fresh_verification,
    build: BuildAuthority,
    corpus: CorpusAuthority,
    profile: ProfileAuthority,
    leaf: LeafAuthority,

    pub fn validate(self: AuthorityBody) !void {
        if (self.format_version != format_version or
            !std.mem.eql(u8, self.status, admission_status) or
            self.production_eligible or self.proof_or_fresh_verification)
        {
            return error.InvalidUnoptimizedBaselineAdmissionAuthority;
        }
        try self.build.validate();
        try self.corpus.validate();
        try self.profile.validate();
        try self.leaf.validate(self.build.host_executable.sha256);
    }
};

pub const Authority = struct {
    body: AuthorityBody,
    identity: Digest,

    pub fn create(
        allocator: std.mem.Allocator,
        body: AuthorityBody,
    ) !Authority {
        try body.validate();
        const result = Authority{
            .body = body,
            .identity = try authorityIdentity(allocator, body),
        };
        try result.validate(allocator);
        return result;
    }

    pub fn validate(
        self: Authority,
        allocator: std.mem.Allocator,
    ) !void {
        try self.body.validate();
        const expected = try authorityIdentity(allocator, self.body);
        if (!std.mem.eql(u8, &self.identity, &expected))
            return error.InvalidUnoptimizedBaselineAdmissionAuthorityIdentity;
    }

    /// Reopens and hashes every path named by the authority. Semantic source,
    /// journal, session and statement reconstruction is performed by the
    /// admission module in addition to this byte-custody check.
    pub fn validateReopenedFiles(self: Authority) !void {
        try reopenIdentity(self.body.build.host_executable);
        try reopenIdentity(self.body.build.immutable_guest_elf);
        try reopenIdentity(self.body.build.source_declared_guest_elf);
        try reopenIdentity(self.body.corpus.source_request_v2);
        try reopenIdentity(self.body.corpus.materialization_v2);
        try reopenIdentity(self.body.corpus.execution_journal);
        try reopenIdentity(self.body.corpus.input);
        try reopenIdentity(self.body.corpus.expected_output);
        try reopenIdentity(self.body.corpus.selected_source_segment);
        try reopenIdentity(self.body.corpus.leaf_request);
    }
};

pub const Unsigned = struct {
    schema: []const u8 = schema,
    status: []const u8 = admission_status,
    production_eligible: bool = production_eligible,
    proof_or_fresh_verification: bool = proof_or_fresh_verification,
    git_source_closure_present: bool = git_source_closure_present,
    authority: Authority,

    pub fn validate(self: Unsigned, allocator: std.mem.Allocator) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, admission_status) or
            self.production_eligible or self.proof_or_fresh_verification or
            self.git_source_closure_present)
        {
            return error.InvalidUnoptimizedBaselineAdmissionReceipt;
        }
        try self.authority.validate(allocator);
    }
};

pub const Sealed = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_eligible: bool,
    proof_or_fresh_verification: bool,
    git_source_closure_present: bool,
    authority: Authority,

    pub fn unsigned(self: Sealed) Unsigned {
        return .{
            .schema = self.schema,
            .status = self.status,
            .production_eligible = self.production_eligible,
            .proof_or_fresh_verification = self.proof_or_fresh_verification,
            .git_source_closure_present = self.git_source_closure_present,
            .authority = self.authority,
        };
    }
};

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    authority: Authority,
) ![]u8 {
    const value = Unsigned{ .authority = authority };
    try value.validate(allocator);
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    const encoded = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(encoded);
    var parsed = try decodeAlloc(allocator, encoded);
    parsed.deinit();
    return encoded;
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) !std.json.Parsed(Sealed) {
    if (encoded.len == 0 or encoded[encoded.len - 1] != '\n' or
        (encoded.len > 1 and encoded[encoded.len - 2] == '\n'))
    {
        return error.InvalidUnoptimizedBaselineCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Sealed, allocator, encoded, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    try parsed.value.unsigned().validate(allocator);
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != encoded.len or
        !std.mem.eql(u8, canonical, encoded[0..canonical.len]))
    {
        return error.InvalidUnoptimizedBaselineCanonicalJson;
    }
    try validateContentSha256(allocator, encoded, parsed.value.content_sha256);
    return parsed;
}

pub fn fileIdentity(path: []const u8, bytes: []const u8) FileIdentity {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .bytes = bytes.len, .path = path, .sha256 = digest };
}

pub fn fileIdentityEql(left: FileIdentity, right: FileIdentity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, &left.sha256, &right.sha256);
}

fn authorityIdentity(
    allocator: std.mem.Allocator,
    body: AuthorityBody,
) !Digest {
    const encoded = try std.json.Stringify.valueAlloc(allocator, body, .{});
    defer allocator.free(encoded);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(authority_identity_domain);
    hash.update(encoded);
    return hash.finalResult();
}

fn reopenIdentity(identity: FileIdentity) !void {
    try identity.validate(true);
    var file = std.fs.openFileAbsolute(identity.path, .{}) catch
        return error.UnoptimizedBaselineFileIdentityMismatch;
    defer file.close();
    const stat = file.stat() catch
        return error.UnoptimizedBaselineFileIdentityMismatch;
    if (stat.kind != .file or stat.size != identity.bytes)
        return error.UnoptimizedBaselineFileIdentityMismatch;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = file.read(&buffer) catch
            return error.UnoptimizedBaselineFileIdentityMismatch;
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    const digest = hash.finalResult();
    if (!std.mem.eql(u8, &digest, &identity.sha256))
        return error.UnoptimizedBaselineFileIdentityMismatch;
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: []const u8,
) !void {
    if (expected.len != 64) return error.InvalidUnoptimizedBaselineContentSha256;
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, encoded, prefix))
        return error.InvalidUnoptimizedBaselineContentSha256;
    const start = prefix.len;
    const end = start + 64;
    if (end + 1 >= encoded.len or encoded[end] != '"' or
        encoded[end + 1] != ',' or
        !std.mem.eql(u8, encoded[start..end], expected))
    {
        return error.InvalidUnoptimizedBaselineContentSha256;
    }
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{encoded[end + 2 ..]},
    );
    defer allocator.free(unsigned);
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    const expected_digest = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &expected_digest, expected))
        return error.InvalidUnoptimizedBaselineContentSha256;
}

fn isCanonicalM31Digest(value: Digest) bool {
    for (0..8) |index| {
        const word = std.mem.readInt(
            u32,
            value[index * 4 ..][0..4],
            .little,
        );
        if (word >= m31.Modulus) return false;
    }
    return true;
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

pub const testing = struct {
    pub fn coldReopenAndMutationGate(
        allocator: std.mem.Allocator,
    ) !void {
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const root = try temporary.dir.realpathAlloc(allocator, ".");
        defer allocator.free(root);
        const path = try std.fs.path.join(
            allocator,
            &.{ root, "baseline-authority.bin" },
        );
        defer allocator.free(path);
        const retained = "retained-baseline-authority";
        try temporary.dir.writeFile(.{
            .sub_path = "baseline-authority.bin",
            .data = retained,
        });
        const file = fileIdentity(path, retained);
        const sha_a = sha256("a");
        const sha_b = sha256("b");
        const m31_a = m31Digest(1);
        const m31_b = m31Digest(17);
        const body = AuthorityBody{
            .build = .{
                .host_executable = file,
                .immutable_guest_elf = file,
                .source_declared_guest_elf = file,
            },
            .corpus = .{
                .source_request_v2 = file,
                .materialization_v2 = file,
                .execution_journal = file,
                .input = file,
                .expected_output = file,
                .selected_source_segment = file,
                .leaf_request = file,
            },
            .profile = .{
                .execution_profile = "rv32im-zkvm-ethereum-v1",
                .profile_wire_id = 3,
                .profile_abi_version = 1,
                .profile_semantic_digest = sha_a,
                .segment_step_budget = 4_194_304,
            },
            .leaf = .{
                .segment_index = 0,
                .segment_count = 210,
                .total_cycles = 880_760_229,
                .global_cycle_start = 0,
                .global_cycle_end = 4_194_304,
                .local_cycle_count = 4_194_304,
                .materialization_content_sha256 = sha_a,
                .leaf_request_content_sha256 = sha_b,
                .producer_executable_sha256 = file.sha256,
                .verifier_executable_sha256 = file.sha256,
                .session_sha256 = sha_a,
                .session_m31_le = m31_a,
                .journal_record_sha256 = sha_b,
                .metadata_id_m31_le = m31_a,
                .statement_id_m31_le = m31_b,
                .source_public_statement_sha256 = sha_a,
                .recursive_statement_sha256 = sha_b,
                .job = .{
                    .final_state_sha256 = sha_a,
                    .initial_state_sha256 = sha_b,
                    .job_sha256 = file.sha256,
                    .program_m31_le = m31_a,
                    .public_input_m31_le = m31_b,
                    .public_output_m31_le = m31_a,
                },
                .open_authority_reconstructed = true,
                .session_reconstructed = true,
                .statement_reconstructed = true,
            },
        };
        const authority = try Authority.create(allocator, body);
        const encoded = try encodeAlloc(allocator, authority);
        defer allocator.free(encoded);
        var parsed = try decodeAlloc(allocator, encoded);
        defer parsed.deinit();
        try parsed.value.authority.validateReopenedFiles();

        try temporary.dir.writeFile(.{
            .sub_path = "baseline-authority.bin",
            .data = "mutated-baseline-authority",
        });
        try std.testing.expectError(
            error.UnoptimizedBaselineFileIdentityMismatch,
            parsed.value.authority.validateReopenedFiles(),
        );
        try temporary.dir.writeFile(.{
            .sub_path = "baseline-authority.bin",
            .data = retained,
        });
        try parsed.value.authority.validateReopenedFiles();

        const mutated = try allocator.dupe(u8, encoded);
        defer allocator.free(mutated);
        const content_prefix = "{\"content_sha256\":\"";
        mutated[content_prefix.len] = if (mutated[content_prefix.len] == '0')
            '1'
        else
            '0';
        try std.testing.expectError(
            error.InvalidUnoptimizedBaselineContentSha256,
            decodeAlloc(allocator, mutated),
        );

        var activated = body;
        activated.production_eligible = true;
        try std.testing.expectError(
            error.InvalidUnoptimizedBaselineAdmissionAuthority,
            activated.validate(),
        );
        var fabricated_git = body;
        fabricated_git.build.git_source_closure_present = true;
        try std.testing.expectError(
            error.InvalidUnoptimizedBaselineBuildAuthority,
            fabricated_git.validate(),
        );
    }

    fn sha256(bytes: []const u8) Digest {
        var result: Digest = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
        return result;
    }

    fn m31Digest(start: u32) Digest {
        var result: Digest = undefined;
        for (0..8) |index| std.mem.writeInt(
            u32,
            result[index * 4 ..][0..4],
            start + @as(u32, @intCast(index)),
            .little,
        );
        return result;
    }
};

comptime {
    if (production_eligible or proof_or_fresh_verification or
        git_source_closure_present)
    {
        @compileError("unoptimized baseline admission became authoritative");
    }
}
