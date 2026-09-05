//! Fail-closed CLI for one ordinary leaf proof under the matched A/B policy.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const base = @import("ethereum_block_leaf_contract.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const producer = @import("ethereum_poseidon_leaf_product_producer.zig");
const profile_receipt = @import("ethereum_poseidon_leaf_profile_receipt.zig");
const matched_result = @import("ethereum_poseidon_leaf_matched_ab_result_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const matched = frontend.prover_mod.guest_precompile
    .ethereum_leaf_matched_ab_execution_profile_v1;

pub const command_name =
    "ethereum-poseidon-v4-leaf-baseline-matched-ab-v1";

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var options = try Options.parseAndResolve(allocator, arguments);
    defer options.deinit(allocator);
    try options.requireFreshOutputs();

    const authority = matched.Authority.canonical();
    try authority.validate();
    // The baseline owns no detached provider job, but the result binds the
    // exact serial/4-worker provider policy required by the candidate arm.
    try authority.validateProviderExecution(.{
        .concurrent_owners = 1,
        .engine_workers_per_owner = 4,
    });
    const producer_arguments = [_][]const u8{
        "--profile-receipt",
        options.profile_receipt,
        "--proof",
        options.proof,
        "--request",
        options.request,
        "--result",
        options.producer_result,
    };
    try producer.runUsingExecution(
        allocator,
        &producer_arguments,
        .{ .cpu = try authority.leafCpuRequest() },
    );

    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        options.request,
        base.max_json_bytes,
    );
    defer allocator.free(request_bytes);
    var request = try product.parseRequest(allocator, request_bytes);
    defer request.deinit();
    const proof_bytes = try artifact_io.readFileBounded(
        allocator,
        options.proof,
        support.artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(proof_bytes);
    const producer_result_bytes = try artifact_io.readFileBounded(
        allocator,
        options.producer_result,
        base.max_json_bytes,
    );
    defer allocator.free(producer_result_bytes);
    var ordinary = try product.parseProducerResult(
        allocator,
        producer_result_bytes,
    );
    defer ordinary.deinit();
    const profile_bytes = try artifact_io.readFileBounded(
        allocator,
        options.profile_receipt,
        profile_receipt.max_receipt_bytes,
    );
    defer allocator.free(profile_bytes);
    var profile = try profile_receipt.parse(allocator, profile_bytes);
    defer profile.deinit();

    const executable_sha256 = try support.executableSha256(allocator);
    const authority_hex = std.fmt.bytesToHex(authority.identity, .lower);
    const executable_hex = std.fmt.bytesToHex(executable_sha256, .lower);
    const proof_hex = digestHex(proof_bytes);
    const request_hex = digestHex(request_bytes);
    const producer_result_hex = digestHex(producer_result_bytes);
    const profile_hex = digestHex(profile_bytes);
    const encoded = try matched_result.encode(allocator, .{
        .producer_result = identity(
            options.producer_result,
            producer_result_bytes,
            &producer_result_hex,
        ),
        .producer_sha256 = &executable_hex,
        .profile = try matched_result.profileAuthority(
            authority,
            &authority_hex,
        ),
        .profile_receipt = identity(
            options.profile_receipt,
            profile_bytes,
            &profile_hex,
        ),
        .proof = identity(options.proof, proof_bytes, &proof_hex),
        .request = identity(options.request, request_bytes, &request_hex),
        .request_content_sha256 = request.value.content_sha256,
        .segment_index = request.value.segment_index,
    });
    defer allocator.free(encoded);
    var reopened = try matched_result.parse(allocator, encoded);
    defer reopened.deinit();
    try reopened.value.validateAgainst(ordinary.value, profile.value);
    try artifact_io.publishCreateOnlyDurable(options.matched_result, encoded);
}

const Options = struct {
    matched_result: []u8,
    producer_result: []u8,
    profile_receipt: []u8,
    proof: []u8,
    request: []u8,

    fn parseAndResolve(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        if (arguments.len != 10) return error.InvalidArguments;
        var matched_result_path: ?[]const u8 = null;
        var producer_result_path: ?[]const u8 = null;
        var profile_receipt_path: ?[]const u8 = null;
        var proof_path: ?[]const u8 = null;
        var request_path: ?[]const u8 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--matched-result")) {
                if (matched_result_path != null) return error.DuplicateArgument;
                matched_result_path = value;
            } else if (std.mem.eql(u8, name, "--result")) {
                if (producer_result_path != null) return error.DuplicateArgument;
                producer_result_path = value;
            } else if (std.mem.eql(u8, name, "--profile-receipt")) {
                if (profile_receipt_path != null) return error.DuplicateArgument;
                profile_receipt_path = value;
            } else if (std.mem.eql(u8, name, "--proof")) {
                if (proof_path != null) return error.DuplicateArgument;
                proof_path = value;
            } else if (std.mem.eql(u8, name, "--request")) {
                if (request_path != null) return error.DuplicateArgument;
                request_path = value;
            } else return error.InvalidArguments;
        }

        var result = Options{
            .matched_result = try resolve(
                allocator,
                matched_result_path orelse return error.InvalidArguments,
            ),
            .producer_result = undefined,
            .profile_receipt = undefined,
            .proof = undefined,
            .request = undefined,
        };
        errdefer allocator.free(result.matched_result);
        result.producer_result = try resolve(
            allocator,
            producer_result_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(result.producer_result);
        result.profile_receipt = try resolve(
            allocator,
            profile_receipt_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(result.profile_receipt);
        result.proof = try resolve(
            allocator,
            proof_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(result.proof);
        result.request = try resolve(
            allocator,
            request_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(result.request);
        try result.validateDistinct();
        return result;
    }

    fn validateDistinct(self: Options) !void {
        const paths = [_][]const u8{
            self.matched_result,
            self.producer_result,
            self.profile_receipt,
            self.proof,
            self.request,
        };
        for (paths, 0..) |left, index|
            for (paths[index + 1 ..]) |right|
                if (std.mem.eql(u8, left, right))
                    return error.DuplicateMatchedAbLeafPath;
    }

    fn requireFreshOutputs(self: Options) !void {
        inline for (.{
            self.matched_result,
            self.producer_result,
            self.profile_receipt,
            self.proof,
        }) |path| try requireAbsent(path);
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.matched_result);
        allocator.free(self.producer_result);
        allocator.free(self.profile_receipt);
        allocator.free(self.proof);
        allocator.free(self.request);
        self.* = undefined;
    }
};

fn resolve(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return artifact_io.resolveAbsolute(allocator, path);
}

fn requireAbsent(path: []const u8) !void {
    if (std.fs.accessAbsolute(path, .{})) |_| {
        return error.MatchedAbLeafOutputAlreadyExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
}

fn digestHex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn identity(
    path: []const u8,
    bytes: []const u8,
    sha256: *const [64]u8,
) base.Identity {
    return .{
        .bytes = bytes.len,
        .path = path,
        .sha256 = sha256,
    };
}

pub const testing = struct {
    pub fn parse(arguments: []const []const u8) !void {
        var options = try Options.parseAndResolve(
            std.testing.allocator,
            arguments,
        );
        defer options.deinit(std.testing.allocator);
    }
};

test "matched A/B baseline CLI is separate and requires its final result" {
    try testing.parse(&.{
        "--matched-result",  "/retained/matched.json",
        "--profile-receipt", "/retained/profile.json",
        "--proof",           "/retained/proof.stw",
        "--request",         "/retained/request.json",
        "--result",          "/retained/result.json",
    });
    try std.testing.expectError(
        error.InvalidArguments,
        testing.parse(&.{
            "--profile-receipt", "/retained/profile.json",
            "--proof",           "/retained/proof.stw",
            "--request",         "/retained/request.json",
            "--result",          "/retained/result.json",
        }),
    );
}
