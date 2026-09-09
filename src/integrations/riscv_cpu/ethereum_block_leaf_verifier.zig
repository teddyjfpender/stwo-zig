//! Fresh-process verifier for one serialized STWGETH3 segment artifact.

const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
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
    var parsed = try contract.parseRealLeafTask(allocator, request_bytes);
    defer parsed.deinit();
    const request = parsed.value;
    const proof = try artifact_io.readFileBounded(
        allocator,
        options.proof,
        support.artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(proof);
    const verified = try support.verifyArtifact(allocator, proof);
    if (verified.segment_index != request.node_index or
        !std.meta.eql(
            verified.statement_sha256,
            try contract.parseSha256(request.expected_statement_sha256),
        )) return error.VerifiedStatementMismatch;

    const encoded = try evidence.encodeVerifierResult(allocator, .{
        .level = request.level,
        .node_index = request.node_index,
        .proof_bytes = proof.len,
        .proof_sha256 = support.sha256(proof),
        .request_sha256 = try contract.parseSha256(request.content_sha256),
        .root_sha256 = verified.root_sha256,
        .scope = request.scope,
        .statement_sha256 = verified.statement_sha256,
        .verifier_sha256 = try support.executableSha256(allocator),
    });
    defer allocator.free(encoded);
    try artifact_io.publishCreateOnly(options.result, encoded);
}

const Options = struct {
    request: []const u8,
    proof: []const u8,
    result: []const u8,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 6) return error.InvalidArguments;
        var result: Options = undefined;
        var seen: u3 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len) return error.InvalidArguments;
            const value = arguments[index + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, arguments[index], "--request")) {
                if (seen & 1 != 0) return error.DuplicateArgument;
                seen |= 1;
                result.request = value;
            } else if (std.mem.eql(u8, arguments[index], "--proof")) {
                if (seen & 2 != 0) return error.DuplicateArgument;
                seen |= 2;
                result.proof = value;
            } else if (std.mem.eql(u8, arguments[index], "--result")) {
                if (seen & 4 != 0) return error.DuplicateArgument;
                seen |= 4;
                result.result = value;
            } else return error.InvalidArguments;
        }
        if (seen != 7) return error.InvalidArguments;
        return result;
    }

    fn resolve(self: Options, allocator: std.mem.Allocator) !Options {
        var result = self;
        result.request = try artifact_io.resolveAbsolute(allocator, self.request);
        errdefer allocator.free(result.request);
        result.proof = try artifact_io.resolveAbsolute(allocator, self.proof);
        errdefer allocator.free(result.proof);
        result.result = try artifact_io.resolveAbsolute(allocator, self.result);
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.request);
        allocator.free(self.proof);
        allocator.free(self.result);
        self.* = undefined;
    }
};
