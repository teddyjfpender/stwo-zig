//! Ordered leaf-request wires for the non-production matched A/B corpus.
//!
//! Baseline entries retain the already-established ordinary leaf request.
//! Candidate entries are a distinct typed schema: they bind the execution-only
//! segment custody and all program/admission identities needed by a future
//! candidate producer, but make no proof or fresh-verification claim.  Neither
//! manifest is valid until both execution arms and the full legacy geometry
//! audit have closed.

const std = @import("std");

const base = @import("ethereum_block_leaf_contract.zig");
const authority =
    @import("ethereum_matched_ab_rematerialization_authority_v1.zig");

pub const baseline_manifest_schema =
    "stwo.ethereum.matched-ab-baseline-leaf-request-manifest.v1";
pub const candidate_request_schema =
    "stwo.ethereum.matched-ab-candidate-leaf-request.v1";
pub const candidate_manifest_schema =
    "stwo.ethereum.matched-ab-candidate-leaf-request-manifest.v1";
pub const status = "minted-after-both-captures-and-legacy-geometry-audit";
pub const production_active = false;
pub const proof_or_fresh_verification = false;
pub const statement_authority =
    "candidate-producer-reconstructed-from-cold-segment-custody-v1";

pub const CandidateLeafRequest = struct {
    admission_receipt_identity_sha256: []const u8,
    arm: []const u8,
    candidate_authority_identity_sha256: []const u8,
    capability_identity_sha256: []const u8,
    capture_result: base.Identity,
    content_sha256: []const u8,
    expected_output: base.Identity,
    expected_statement_sha256: []const u8,
    geometry_audit: base.Identity,
    input: base.Identity,
    production_active: bool,
    program_commitment_identity_sha256: []const u8,
    program_root: u32,
    proof_or_fresh_verification: bool,
    schema: []const u8,
    segment_count: u32,
    segment_execution_receipt: base.Identity,
    segment_index: u32,
    segment_step_budget: u64,
    statement_authority: []const u8,
    status: []const u8,
    target_provider_log_size: u32,

    pub fn validate(self: CandidateLeafRequest) !void {
        if (!std.mem.eql(u8, self.arm, "candidate") or
            !std.mem.eql(u8, self.schema, candidate_request_schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(
                u8,
                self.statement_authority,
                statement_authority,
            ) or self.production_active or self.proof_or_fresh_verification or
            self.segment_count < 2 or self.segment_index >= self.segment_count or
            self.segment_step_budget != authority.segment_step_budget or
            self.target_provider_log_size != authority.target_provider_log_size)
        {
            return error.InvalidMatchedAbCandidateLeafRequest;
        }
        inline for (.{
            self.admission_receipt_identity_sha256,
            self.candidate_authority_identity_sha256,
            self.capability_identity_sha256,
            self.content_sha256,
            self.expected_statement_sha256,
            self.program_commitment_identity_sha256,
        }) |digest| _ = try base.parseSha256(digest);
        inline for (.{
            self.capture_result,
            self.expected_output,
            self.geometry_audit,
            self.input,
            self.segment_execution_receipt,
        }) |file| try file.validate(false);
    }
};

pub const OrderedEntry = struct {
    expected_statement_sha256: []const u8,
    request: base.TypedIdentity,
    segment_index: u32,

    pub fn validate(
        self: OrderedEntry,
        expected_index: usize,
        expected_schema: []const u8,
    ) !void {
        const index = std.math.cast(u32, expected_index) orelse
            return error.InvalidMatchedAbLeafRequestEntry;
        if (self.segment_index != index or
            !std.mem.eql(u8, self.request.schema, expected_schema))
        {
            return error.InvalidMatchedAbLeafRequestEntry;
        }
        _ = try base.parseSha256(self.expected_statement_sha256);
        try self.request.validate();
    }
};

pub const OrderedManifest = struct {
    arm: []const u8,
    both_captures_closed: bool,
    content_sha256: []const u8,
    expected_output: base.Identity,
    geometry_audit: base.Identity,
    geometry_audit_closed: bool,
    input: base.Identity,
    production_active: bool,
    proof_or_fresh_verification: bool,
    requests: []const OrderedEntry,
    schema: []const u8,
    segment_count: u32,
    segment_step_budget: u64,
    source_capture_result: base.Identity,
    status: []const u8,

    pub fn validate(self: OrderedManifest) !void {
        const is_baseline = std.mem.eql(u8, self.arm, "baseline");
        const is_candidate = std.mem.eql(u8, self.arm, "candidate");
        const expected_manifest_schema = if (is_baseline)
            baseline_manifest_schema
        else if (is_candidate)
            candidate_manifest_schema
        else
            return error.InvalidMatchedAbLeafRequestManifest;
        const expected_request_schema = if (is_baseline)
            base.task_request_schema
        else
            candidate_request_schema;
        if (!std.mem.eql(u8, self.schema, expected_manifest_schema) or
            !std.mem.eql(u8, self.status, status) or
            self.production_active or self.proof_or_fresh_verification or
            !self.both_captures_closed or !self.geometry_audit_closed or
            self.segment_count < 2 or self.requests.len != self.segment_count or
            self.segment_step_budget != authority.segment_step_budget)
        {
            return error.InvalidMatchedAbLeafRequestManifest;
        }
        _ = try base.parseSha256(self.content_sha256);
        inline for (.{
            self.expected_output,
            self.geometry_audit,
            self.input,
            self.source_capture_result,
        }) |file| try file.validate(false);
        for (self.requests, 0..) |request, index|
            try request.validate(index, expected_request_schema);
    }

    pub fn validateMatched(left: OrderedManifest, right: OrderedManifest) !void {
        try left.validate();
        try right.validate();
        if (!std.mem.eql(u8, left.arm, "baseline") or
            !std.mem.eql(u8, right.arm, "candidate") or
            left.segment_step_budget != right.segment_step_budget or
            !identityEql(left.input, right.input) or
            !identityEql(left.expected_output, right.expected_output) or
            !identityEql(left.geometry_audit, right.geometry_audit))
        {
            return error.MatchedAbLeafRequestManifestMismatch;
        }
    }
};

fn identityEql(left: base.Identity, right: base.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        authority.segment_step_budget != 1_048_576 or
        authority.target_provider_log_size != 22)
    {
        @compileError("matched A/B leaf-request policy drifted");
    }
}

test "ordered manifests reject request order and common input drift" {
    const baseline_entries = [_]OrderedEntry{
        entry(0, base.task_request_schema, "/private/tmp/baseline-0.json"),
        entry(1, base.task_request_schema, "/private/tmp/baseline-1.json"),
    };
    const candidate_entries = [_]OrderedEntry{
        entry(0, candidate_request_schema, "/private/tmp/candidate-0.json"),
        entry(1, candidate_request_schema, "/private/tmp/candidate-1.json"),
    };
    const baseline = manifest("baseline", &baseline_entries, sharedIdentity(
        "/private/tmp/common-input.bin",
    ));
    var candidate = manifest("candidate", &candidate_entries, sharedIdentity(
        "/private/tmp/common-input.bin",
    ));
    try OrderedManifest.validateMatched(baseline, candidate);

    var reordered = candidate_entries;
    reordered[0].segment_index = 1;
    candidate.requests = &reordered;
    try std.testing.expectError(
        error.InvalidMatchedAbLeafRequestEntry,
        candidate.validate(),
    );
    candidate.requests = &candidate_entries;
    candidate.input = sharedIdentity("/private/tmp/drifted-input.bin");
    try std.testing.expectError(
        error.MatchedAbLeafRequestManifestMismatch,
        OrderedManifest.validateMatched(baseline, candidate),
    );
}

fn manifest(
    arm: []const u8,
    requests: []const OrderedEntry,
    input: base.Identity,
) OrderedManifest {
    return .{
        .arm = arm,
        .both_captures_closed = true,
        .content_sha256 = zero_sha256,
        .expected_output = sharedIdentity("/private/tmp/common-output.bin"),
        .geometry_audit = sharedIdentity("/private/tmp/geometry.json"),
        .geometry_audit_closed = true,
        .input = input,
        .production_active = false,
        .proof_or_fresh_verification = false,
        .requests = requests,
        .schema = if (std.mem.eql(u8, arm, "baseline"))
            baseline_manifest_schema
        else
            candidate_manifest_schema,
        .segment_count = 2,
        .segment_step_budget = authority.segment_step_budget,
        .source_capture_result = sharedIdentity("/private/tmp/capture.json"),
        .status = status,
    };
}

fn entry(
    segment_index: u32,
    request_schema: []const u8,
    path: []const u8,
) OrderedEntry {
    return .{
        .expected_statement_sha256 = zero_sha256,
        .request = .{
            .bytes = 1,
            .path = path,
            .schema = request_schema,
            .sha256 = zero_sha256,
        },
        .segment_index = segment_index,
    };
}

fn sharedIdentity(path: []const u8) base.Identity {
    return .{ .bytes = 1, .path = path, .sha256 = zero_sha256 };
}

const zero_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
