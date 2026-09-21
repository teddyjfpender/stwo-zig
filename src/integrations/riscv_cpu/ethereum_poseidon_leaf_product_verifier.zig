//! Genuinely fresh-process verifier for one expected Poseidon v4 leaf.

const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const parsed_options = try Options.parse(arguments);
    var options = try parsed_options.resolve(allocator);
    defer options.deinit(allocator);
    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        options.request,
        contract.max_json_bytes,
    );
    defer allocator.free(request_bytes);
    var parsed_request = try product.parseRequest(allocator, request_bytes);
    defer parsed_request.deinit();
    const request = &parsed_request.value;
    const executable_sha = try support.executableSha256(allocator);
    if (!std.meta.eql(
        executable_sha,
        try contract.parseSha256(request.verifier_sha256),
    )) return error.VerifierIdentityMismatch;

    var authority = try product_support.openAuthority(allocator, request);
    defer authority.deinit();
    const proof = try artifact_io.readFileBounded(
        allocator,
        options.proof,
        support.artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(proof);
    var verify_clock: ?evidence.Clock = if (options.timing_receipt != null)
        try evidence.Clock.start()
    else
        null;
    var verified = try support.verifyPoseidonArtifactWithCapture(
        allocator,
        proof,
        &authority.expected,
    );
    defer verified.deinit(allocator);
    const verify_timing: ?product.Timing = if (verify_clock) |*clock|
        try finishVerificationTiming(clock)
    else
        null;

    const proof_digest = support.sha256(proof);
    const proof_hex = product_support.digestHex(proof_digest);
    const verifier_hex = product_support.digestHex(executable_sha);
    const request_hex = product_support.digestHex(
        try contract.parseSha256(request.content_sha256),
    );
    const recursive_statement = product_support.digestHex(
        verified.recursive_statement_sha256,
    );
    const root = product_support.digestHex(verified.root_sha256);
    const security = product_support.digestHex(support.recursive_security_identity);
    const source_statement = product_support.digestHex(
        verified.source_public_statement_sha256,
    );
    const transcript = product_support.digestHex(
        verified.transcript_state_sha256,
    );
    const capture = product_support.digestHex(verified.capture.identity_digest);
    const link = product_support.fieldDigestHex(
        verified.capture.verified_link.identity,
    );
    const result = try product.encodeVerifierResult(allocator, .{
        .proof_bytes = proof.len,
        .proof_sha256 = &proof_hex,
        .recursive_statement_sha256 = &recursive_statement,
        .request_sha256 = &request_hex,
        .root_sha256 = &root,
        .security_identity_sha256 = &security,
        .segment_index = request.segment_index,
        .source_public_statement_sha256 = &source_statement,
        .transcript_state_sha256 = &transcript,
        .verified_capture_sha256 = &capture,
        .verified_link_id_m31_le = &link,
        .verifier_sha256 = &verifier_hex,
    });
    defer allocator.free(result);
    var timing_receipt: ?[]u8 = null;
    defer if (timing_receipt) |bytes| allocator.free(bytes);
    if (options.timing_receipt != null) {
        const request_file_hex = product_support.digestHex(
            support.sha256(request_bytes),
        );
        const result_hex = product_support.digestHex(support.sha256(result));
        timing_receipt = try product.encodeVerifierTimingReceipt(allocator, .{
            .proof = .{
                .bytes = proof.len,
                .path = options.proof,
                .sha256 = &proof_hex,
            },
            .request = .{
                .bytes = request_bytes.len,
                .path = options.request,
                .sha256 = &request_file_hex,
            },
            .request_content_sha256 = request.content_sha256,
            .segment_index = request.segment_index,
            .verifier_result = .{
                .bytes = result.len,
                .path = options.result,
                .sha256 = &result_hex,
            },
            .verifier_sha256 = &verifier_hex,
            .verify_timing = verify_timing orelse
                return error.MissingVerificationTiming,
        });
        var parsed_result = try product.parseVerifierResult(allocator, result);
        defer parsed_result.deinit();
        var parsed_timing = try product.parseVerifierTimingReceipt(
            allocator,
            timing_receipt.?,
        );
        defer parsed_timing.deinit();
        try parsed_timing.value.validateAgainst(
            request.*,
            parsed_result.value,
            .{
                .bytes = request_bytes.len,
                .path = options.request,
                .sha256 = &request_file_hex,
            },
            .{
                .bytes = proof.len,
                .path = options.proof,
                .sha256 = &proof_hex,
            },
            .{
                .bytes = result.len,
                .path = options.result,
                .sha256 = &result_hex,
            },
        );
    }
    try publishEvidencePair(
        options.result,
        result,
        options.timing_receipt,
        timing_receipt,
    );
}

fn finishVerificationTiming(clock: anytype) !product.Timing {
    const timing = try clock.finish();
    if (timing.wall_ns == 0) return error.InvalidVerificationTiming;
    return .{
        .system_ns = timing.system_ns,
        .user_ns = timing.user_ns,
        .wall_ns = timing.wall_ns,
    };
}

fn publishEvidencePair(
    result_path: []const u8,
    result: []const u8,
    timing_path: ?[]const u8,
    timing_receipt: ?[]const u8,
) !void {
    if ((timing_path == null) != (timing_receipt == null))
        return error.InvalidTimingPublication;
    try artifact_io.publishCreateOnlyDurable(result_path, result);
    if (timing_path) |path|
        try artifact_io.publishCreateOnlyDurable(path, timing_receipt.?);
}

/// Narrow test surface for the evidence boundary. The product itself always
/// calls the same helpers; no proof or transcript behavior is replaced here.
pub const testing = struct {
    pub fn parseHasTimingReceipt(arguments: []const []const u8) !bool {
        return (try Options.parse(arguments)).timing_receipt != null;
    }

    pub fn finishTiming(clock: anytype) !product.Timing {
        return finishVerificationTiming(clock);
    }

    pub fn publishPair(
        result_path: []const u8,
        result: []const u8,
        timing_path: ?[]const u8,
        timing_receipt: ?[]const u8,
    ) !void {
        return publishEvidencePair(
            result_path,
            result,
            timing_path,
            timing_receipt,
        );
    }

    /// Pins the production ordering invariant: a failed monotonic/process
    /// clock read is selected before either create-only output is attempted.
    pub fn finishThenPublish(
        clock: anytype,
        result_path: []const u8,
        result: []const u8,
        timing_path: ?[]const u8,
        timing_receipt: ?[]const u8,
    ) !void {
        _ = try finishVerificationTiming(clock);
        return publishEvidencePair(
            result_path,
            result,
            timing_path,
            timing_receipt,
        );
    }
};

const Options = struct {
    proof: []const u8,
    request: []const u8,
    result: []const u8,
    timing_receipt: ?[]const u8 = null,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 6 and arguments.len != 8)
            return error.InvalidArguments;
        var result: Options = undefined;
        result.timing_receipt = null;
        var seen: u4 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len or arguments[index + 1].len == 0)
                return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, name, "--proof")) {
                if (seen & 1 != 0) return error.DuplicateArgument;
                seen |= 1;
                result.proof = value;
            } else if (std.mem.eql(u8, name, "--request")) {
                if (seen & 2 != 0) return error.DuplicateArgument;
                seen |= 2;
                result.request = value;
            } else if (std.mem.eql(u8, name, "--result")) {
                if (seen & 4 != 0) return error.DuplicateArgument;
                seen |= 4;
                result.result = value;
            } else if (std.mem.eql(u8, name, "--timing-receipt")) {
                if (seen & 8 != 0) return error.DuplicateArgument;
                seen |= 8;
                result.timing_receipt = value;
            } else return error.InvalidArguments;
        }
        if (seen != 7 and seen != 15) return error.InvalidArguments;
        return result;
    }

    fn resolve(self: Options, allocator: std.mem.Allocator) !Options {
        var result = self;
        result.proof = try artifact_io.resolveAbsolute(allocator, self.proof);
        errdefer allocator.free(result.proof);
        result.request = try artifact_io.resolveAbsolute(allocator, self.request);
        errdefer allocator.free(result.request);
        result.result = try artifact_io.resolveAbsolute(allocator, self.result);
        errdefer allocator.free(result.result);
        result.timing_receipt = if (self.timing_receipt) |path|
            try artifact_io.resolveAbsolute(allocator, path)
        else
            null;
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.proof);
        allocator.free(self.request);
        allocator.free(self.result);
        if (self.timing_receipt) |path| allocator.free(path);
        self.* = undefined;
    }
};
