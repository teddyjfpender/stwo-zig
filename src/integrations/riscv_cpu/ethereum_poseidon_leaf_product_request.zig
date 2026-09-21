//! Create-only request materializer for one expected Poseidon v4 leaf.

const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const parsed_options = try Options.parse(arguments);
    var options = try parsed_options.resolve(allocator);
    defer options.deinit(allocator);
    const source_bytes = try artifact_io.readFileBounded(
        allocator,
        options.source_request,
        contract.max_json_bytes,
    );
    defer allocator.free(source_bytes);
    var source = try contract.parseRecursiveSource(allocator, source_bytes);
    defer source.deinit();
    if (options.segment_index >= source.value.segment_count)
        return error.SegmentIndexOutOfBounds;
    const segment_bytes = try artifact_io.readFileBounded(
        allocator,
        options.source_segment,
        support.source_wire.encoded_size,
    );
    defer allocator.free(segment_bytes);
    const segment = try support.source_wire.decode(segment_bytes);
    if (segment.metadata.segment_index != options.segment_index or
        segment.metadata.segment_count != source.value.segment_count)
    {
        return error.ExpectedSourceMismatch;
    }
    const producer_bytes = try artifact_io.readFileBounded(
        allocator,
        options.producer,
        512 * 1024 * 1024,
    );
    defer allocator.free(producer_bytes);
    const verifier_bytes = try artifact_io.readFileBounded(
        allocator,
        options.verifier,
        512 * 1024 * 1024,
    );
    defer allocator.free(verifier_bytes);

    const source_sha = product_support.digestHex(support.sha256(source_bytes));
    const segment_sha = product_support.digestHex(support.sha256(segment_bytes));
    const producer_sha = product_support.digestHex(support.sha256(producer_bytes));
    const verifier_sha = product_support.digestHex(support.sha256(verifier_bytes));
    const source_statement = product_support.digestHex(
        try segment.statementSha256(),
    );
    const recursive_statement = product_support.digestHex(
        statement_plan.statementSha256(
            &segment.metadata.base_statement_words,
        ),
    );
    const encoded = try product.encodeRequest(allocator, .{
        .expected_recursive_statement_sha256 = &recursive_statement,
        .expected_source_public_statement_sha256 = &source_statement,
        .producer_sha256 = &producer_sha,
        .segment_index = options.segment_index,
        .session_id = options.session_id,
        .source_request = .{
            .bytes = source_bytes.len,
            .path = options.source_request,
            .schema = contract.recursive_source_schema,
            .sha256 = &source_sha,
        },
        .source_segment = .{
            .bytes = segment_bytes.len,
            .path = options.source_segment,
            .sha256 = &segment_sha,
        },
        .verifier_sha256 = &verifier_sha,
    });
    defer allocator.free(encoded);
    var parsed = try product.parseRequest(allocator, encoded);
    defer parsed.deinit();
    var authority = try product_support.openAuthority(
        allocator,
        &parsed.value,
    );
    authority.deinit();
    try artifact_io.publishCreateOnlyDurable(options.result, encoded);
}

const Options = struct {
    producer: []const u8,
    result: []const u8,
    segment_index: u32,
    session_id: []const u8,
    source_request: []const u8,
    source_segment: []const u8,
    verifier: []const u8,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 14) return error.InvalidArguments;
        var result: Options = undefined;
        var seen: u8 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len or arguments[index + 1].len == 0)
                return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, name, "--producer")) {
                try take(&seen, 1);
                result.producer = value;
            } else if (std.mem.eql(u8, name, "--result")) {
                try take(&seen, 2);
                result.result = value;
            } else if (std.mem.eql(u8, name, "--segment-index")) {
                try take(&seen, 4);
                result.segment_index = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, name, "--session-id")) {
                try take(&seen, 8);
                result.session_id = value;
            } else if (std.mem.eql(u8, name, "--source-request")) {
                try take(&seen, 16);
                result.source_request = value;
            } else if (std.mem.eql(u8, name, "--source-segment")) {
                try take(&seen, 32);
                result.source_segment = value;
            } else if (std.mem.eql(u8, name, "--verifier")) {
                try take(&seen, 64);
                result.verifier = value;
            } else return error.InvalidArguments;
        }
        if (seen != 127) return error.InvalidArguments;
        return result;
    }

    fn resolve(self: Options, allocator: std.mem.Allocator) !Options {
        _ = try contract.parseSha256(self.session_id);
        var result = self;
        result.producer = try artifact_io.resolveAbsolute(allocator, self.producer);
        errdefer allocator.free(result.producer);
        result.result = try artifact_io.resolveAbsolute(allocator, self.result);
        errdefer allocator.free(result.result);
        result.source_request = try artifact_io.resolveAbsolute(
            allocator,
            self.source_request,
        );
        errdefer allocator.free(result.source_request);
        result.source_segment = try artifact_io.resolveAbsolute(
            allocator,
            self.source_segment,
        );
        errdefer allocator.free(result.source_segment);
        result.verifier = try artifact_io.resolveAbsolute(allocator, self.verifier);
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.producer);
        allocator.free(self.result);
        allocator.free(self.source_request);
        allocator.free(self.source_segment);
        allocator.free(self.verifier);
        self.* = undefined;
    }
};

fn take(seen: *u8, bit: u8) !void {
    if (seen.* & bit != 0) return error.DuplicateArgument;
    seen.* |= bit;
}
