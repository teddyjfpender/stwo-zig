//! Create-only diagnostic authority for exact pre-Engine Ethereum leaf geometry.
//!
//! This transport is deliberately nonpromotable. It binds the expected source
//! request and retained leaf, records the complete ordered Tree0,
//! non-candidate Tree1, and Tree2 log-size arrays, and carries cold-derived
//! degree-5/degree-6 residency estimates. No commitment scheme is initialized
//! and no proof publication is possible through this module.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const base = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");

const orchestration = frontend.prover_mod.guest_precompile
    .ethereum_segment_orchestration;
const CandidateProfile = orchestration.PoseidonCandidateProfile;
const CandidateGeometry = orchestration.PoseidonCandidateGeometry;
const CandidateResidencyEstimate =
    orchestration.PoseidonCandidateResidencyEstimate;

pub const schema = "stwo.ethereum.poseidon-v4-leaf-pre-engine-geometry.v1";
pub const status = "diagnostic-nonpromotable";
pub const max_snapshot_bytes: usize = 16 * 1024 * 1024;

pub const Candidate = struct {
    candidate_identity_sha256: []const u8,
    direct_program_sha256: []const u8,
    geometry: CandidateGeometry,
    profile: []const u8,
    residency: CandidateResidencyEstimate,
};

pub const Snapshot = struct {
    content_sha256: []const u8,
    candidate_degree5: Candidate,
    candidate_degree6: Candidate,
    engine_initialized: bool,
    legacy_poseidon: orchestration.LegacyPoseidonSpan,
    log_blowup_factor: u32,
    producer_sha256: []const u8,
    proof_started: bool,
    recursive_admissible: bool,
    request: base.Identity,
    request_content_sha256: []const u8,
    schema: []const u8,
    segment_index: u32,
    source_request: base.TypedIdentity,
    source_segment: base.Identity,
    status: []const u8,
    tree0_log_sizes: []const u32,
    tree1_non_candidate_log_sizes: []const u32,
    tree2_log_sizes: []const u32,

    pub fn validate(self: Snapshot) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            self.engine_initialized or self.proof_started or
            self.recursive_admissible or self.log_blowup_factor == 0 or
            self.tree0_log_sizes.len == 0 or
            self.tree1_non_candidate_log_sizes.len == 0 or
            self.tree2_log_sizes.len == 0 or
            self.legacy_poseidon.main_column_count != 445 or
            self.legacy_poseidon.log_size == 0 or
            self.candidate_degree5.residency.retention_policy != .never or
            self.candidate_degree6.residency.retention_policy != .never or
            !std.mem.eql(u8, self.candidate_degree5.profile, "degree5") or
            !std.mem.eql(u8, self.candidate_degree6.profile, "degree6"))
        {
            return error.InvalidGeometrySnapshot;
        }
        try self.request.validate(false);
        try self.source_request.validate();
        try self.source_segment.validate(false);
        inline for (.{
            self.request.path,
            self.source_request.path,
            self.source_segment.path,
        }) |path| if (!std.fs.path.isAbsolute(path))
            return error.InvalidGeometrySnapshot;
        inline for (.{
            self.content_sha256,
            self.producer_sha256,
            self.request_content_sha256,
            self.candidate_degree5.candidate_identity_sha256,
            self.candidate_degree5.direct_program_sha256,
            self.candidate_degree6.candidate_identity_sha256,
            self.candidate_degree6.direct_program_sha256,
        }) |digest| _ = try base.parseSha256(digest);
        try validateCandidate(
            self.candidate_degree5,
            .degree5,
            self.legacy_poseidon.log_size,
            self.log_blowup_factor,
            self.tree0_log_sizes,
            self.tree1_non_candidate_log_sizes,
            self.tree2_log_sizes,
        );
        try validateCandidate(
            self.candidate_degree6,
            .degree6,
            self.legacy_poseidon.log_size,
            self.log_blowup_factor,
            self.tree0_log_sizes,
            self.tree1_non_candidate_log_sizes,
            self.tree2_log_sizes,
        );
    }
};

pub const Input = struct {
    geometry: *const orchestration.GeometrySnapshot,
    log_blowup_factor: u32,
    producer_sha256: [32]u8,
    request: evidence.FileIdentity,
    request_content_sha256: [32]u8,
    request_value: *const product.Request,
};

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
    if (input.log_blowup_factor == 0)
        return error.InvalidGeometrySnapshot;
    const producer_hex = hex(input.producer_sha256);
    const request_file_hex = hex(input.request.sha256);
    const request_content_hex = hex(input.request_content_sha256);
    const degree5_identity = hex(input.geometry.degree5.candidate_identity);
    const degree5_program = hex(input.geometry.degree5.direct_program_digest);
    const degree6_identity = hex(input.geometry.degree6.candidate_identity);
    const degree6_program = hex(input.geometry.degree6.direct_program_digest);
    const value = Snapshot{
        .candidate_degree5 = .{
            .candidate_identity_sha256 = &degree5_identity,
            .direct_program_sha256 = &degree5_program,
            .geometry = input.geometry.degree5.geometry,
            .profile = "degree5",
            .residency = input.geometry.degree5.residency,
        },
        .candidate_degree6 = .{
            .candidate_identity_sha256 = &degree6_identity,
            .direct_program_sha256 = &degree6_program,
            .geometry = input.geometry.degree6.geometry,
            .profile = "degree6",
            .residency = input.geometry.degree6.residency,
        },
        .content_sha256 = &([_]u8{'0'} ** 64),
        .engine_initialized = false,
        .legacy_poseidon = input.geometry.legacy_poseidon,
        .log_blowup_factor = input.log_blowup_factor,
        .producer_sha256 = &producer_hex,
        .proof_started = false,
        .recursive_admissible = false,
        .request = .{
            .bytes = input.request.bytes,
            .path = input.request.path,
            .sha256 = &request_file_hex,
        },
        .request_content_sha256 = &request_content_hex,
        .schema = schema,
        .segment_index = input.request_value.segment_index,
        .source_request = input.request_value.source_request,
        .source_segment = input.request_value.source_segment,
        .status = status,
        .tree0_log_sizes = input.geometry.tree0_log_sizes,
        .tree1_non_candidate_log_sizes = input.geometry.tree1_non_candidate_log_sizes,
        .tree2_log_sizes = input.geometry.tree2_log_sizes,
    };
    const unsigned_with_placeholder = try std.json.Stringify.valueAlloc(
        allocator,
        value,
        .{},
    );
    defer allocator.free(unsigned_with_placeholder);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, unsigned_with_placeholder, prefix))
        return error.InvalidGeometrySnapshot;
    const digest_end = prefix.len + 64;
    if (digest_end + 1 >= unsigned_with_placeholder.len or
        unsigned_with_placeholder[digest_end] != '"' or
        unsigned_with_placeholder[digest_end + 1] != ',')
    {
        return error.InvalidGeometrySnapshot;
    }
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{unsigned_with_placeholder[digest_end + 2 ..]},
    );
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
) !std.json.Parsed(Snapshot) {
    if (bytes.len == 0 or bytes.len > max_snapshot_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Snapshot, allocator, bytes, .{
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
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn publishCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}

fn validateCandidate(
    value: Candidate,
    profile: CandidateProfile,
    trace_log_size: u32,
    log_blowup_factor: u32,
    tree0: []const u32,
    tree1_non_candidate: []const u32,
    tree2: []const u32,
) !void {
    const expected = profile.expected();
    if (value.geometry.maximum_constraint_degree !=
        profile.maximumConstraintDegree() or
        value.geometry.materialization_columns !=
            expected.materialization_columns or
        value.geometry.main_columns != expected.main_columns or
        value.geometry.composition_columns !=
            profile.compositionColumns())
    {
        return error.InvalidGeometrySnapshot;
    }
    const estimate = try orchestration.testing.candidateEstimate(
        std.heap.page_allocator,
        profile,
        trace_log_size,
        log_blowup_factor,
        tree0,
        tree1_non_candidate,
        tree2,
    );
    if (!std.meta.eql(estimate.residency, value.residency) or
        !std.meta.eql(
            estimate.candidate_identity,
            try base.parseSha256(value.candidate_identity_sha256),
        ) or !std.meta.eql(
        estimate.direct_program_digest,
        try base.parseSha256(value.direct_program_sha256),
    ))
        return error.InvalidGeometrySnapshot;
}

fn validateContentSha256(
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
    const encoded = hex(digest);
    if (!std.mem.eql(u8, &encoded, expected))
        return error.InvalidContentSha256;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

pub const testing = struct {
    pub fn canonicalRoundTrip(allocator: std.mem.Allocator) !void {
        const tree0 = try allocator.dupe(u32, &.{ 3, 4 });
        errdefer allocator.free(tree0);
        const tree1 = try allocator.dupe(u32, &.{ 5, 6 });
        errdefer allocator.free(tree1);
        const tree2 = try allocator.dupe(u32, &.{ 7, 8 });
        errdefer allocator.free(tree2);
        const degree5 = try orchestration.testing.candidateEstimate(
            allocator,
            .degree5,
            4,
            1,
            tree0,
            tree1,
            tree2,
        );
        const degree6 = try orchestration.testing.candidateEstimate(
            allocator,
            .degree6,
            4,
            1,
            tree0,
            tree1,
            tree2,
        );
        var geometry = orchestration.GeometrySnapshot{
            .allocator = allocator,
            .tree0_log_sizes = tree0,
            .tree1_non_candidate_log_sizes = tree1,
            .tree2_log_sizes = tree2,
            .legacy_poseidon = .{
                .infra_index = 3,
                .main_column_offset = 9,
                .main_column_count = 445,
                .log_size = 4,
                .n_rows = 11,
            },
            .degree5 = degree5,
            .degree6 = degree6,
        };
        defer geometry.deinit();

        const digest = [_]u8{0x11} ** 32;
        const digest_hex = hex(digest);
        const request_value = product.Request{
            .content_sha256 = &digest_hex,
            .expected_recursive_statement_sha256 = &digest_hex,
            .expected_source_public_statement_sha256 = &digest_hex,
            .producer_sha256 = &digest_hex,
            .schema = product.request_schema,
            .segment_index = 0,
            .session_id = &digest_hex,
            .source_request = .{
                .bytes = 1,
                .path = "/retained/source-v2.json",
                .schema = base.recursive_source_schema,
                .sha256 = &digest_hex,
            },
            .source_segment = .{
                .bytes = 1,
                .path = "/retained/segment-0.stwesg31",
                .sha256 = &digest_hex,
            },
            .verifier_sha256 = &digest_hex,
        };
        const encoded = try encode(allocator, .{
            .geometry = &geometry,
            .log_blowup_factor = 1,
            .producer_sha256 = digest,
            .request = .{
                .bytes = 1,
                .path = "/retained/request.json",
                .sha256 = digest,
            },
            .request_content_sha256 = digest,
            .request_value = &request_value,
        });
        defer allocator.free(encoded);
        var parsed = try parse(allocator, encoded);
        defer parsed.deinit();
        try std.testing.expectEqual(@as(u32, 445), parsed.value
            .legacy_poseidon.main_column_count);
        try std.testing.expectEqualSlices(
            u32,
            tree1,
            parsed.value.tree1_non_candidate_log_sizes,
        );
        try std.testing.expectEqual(
            degree5.residency.staged_peak_lower_bound_bytes,
            parsed.value.candidate_degree5.residency
                .staged_peak_lower_bound_bytes,
        );
        try std.testing.expectEqual(
            degree6.residency.staged_peak_lower_bound_bytes,
            parsed.value.candidate_degree6.residency
                .staged_peak_lower_bound_bytes,
        );
    }
};
