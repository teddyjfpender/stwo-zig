//! Capture canonical compact input once, then parse and bind those owned bytes.
//! A compact transport has a unique encoding (reserved bits and padding are
//! checked by the frontend), so re-encoding it adds copies without normalization.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");

pub const Capture = struct {
    input: cairo.adapter.ProverInput,
    encoded: []align(64) u8,
    file_sha256: [32]u8,
    encoded_sha256: [32]u8,
};

pub fn read(allocator: std.mem.Allocator, path: []const u8) !Capture {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    const limits = cairo.adapter.official_input.Limits{};
    if (stat.kind != .file) return error.InputNotRegularFile;
    if (stat.size == 0) return error.EmptyInput;
    if (stat.size > limits.max_file_bytes) return error.InputTooLarge;
    var header: [cairo.adapter.adapted_input.MAGIC.len]u8 = undefined;
    const header_len = try file.readAll(&header);
    try file.seekTo(0);
    if (std.mem.eql(u8, header[0..header_len], &cairo.adapter.adapted_input.MAGIC)) {
        const bytes = try allocator.alignedAlloc(u8, .@"64", @intCast(stat.size));
        errdefer allocator.free(bytes);
        if (try file.readAll(bytes) != bytes.len) return error.Truncated;
        var trailing: [1]u8 = undefined;
        if (try file.read(&trailing) != 0) return error.CanonicalInputChanged;
        var input = try cairo.adapter.input.parseSlice(allocator, bytes, limits);
        errdefer input.deinit(allocator);
        const digest = sha(bytes);
        if (!std.mem.eql(u8, &digest, &try fileSha(path))) return error.CanonicalInputChanged;
        return .{ .input = input, .encoded = bytes, .file_sha256 = digest, .encoded_sha256 = digest };
    }
    // Capture the JSON bytes once. Parsing the slice avoids a second file
    // read and the streaming token source; the final digest still detects a
    // path replacement or mutation before the request is admitted.
    // `allocator` is often the request arena; use a reclaimable temporary
    // allocation so the large JSON capture does not survive the parse.
    const json_bytes = try std.heap.page_allocator.alloc(u8, @intCast(stat.size));
    defer std.heap.page_allocator.free(json_bytes);
    if (try file.readAll(json_bytes) != json_bytes.len) return error.Truncated;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.CanonicalInputChanged;
    const file_digest = sha(json_bytes);
    var input = try cairo.adapter.input.parseSlice(allocator, json_bytes, limits);
    errdefer input.deinit(allocator);
    const encoded = try cairo.adapter.compact_writer.encode(allocator, &input);
    errdefer allocator.free(encoded);
    if (!std.mem.eql(u8, &file_digest, &try fileSha(path))) return error.CanonicalInputChanged;
    return .{ .input = input, .encoded = encoded, .file_sha256 = file_digest, .encoded_sha256 = sha(encoded) };
}

fn sha(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn fileSha(path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    return hash.finalResult();
}

test "canonical input capture preserves normalized transport and digest" {
    const allocator = std.testing.allocator;
    var captured = try read(allocator, "vectors/cairo/official/all_opcodes.prover_input.cpi");
    defer captured.input.deinit(allocator);
    defer allocator.free(captured.encoded);
    var json = try read(allocator, "vectors/cairo/official/all_opcodes.prover_input.json");
    defer json.input.deinit(allocator);
    defer allocator.free(json.encoded);
    const encoded = try cairo.adapter.compact_writer.encode(allocator, &captured.input);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, encoded, captured.encoded);
    try std.testing.expectEqualSlices(u8, json.encoded, captured.encoded);
    try std.testing.expectEqualSlices(u8, &captured.file_sha256, &captured.encoded_sha256);
    try std.testing.expectEqualSlices(u8, &json.encoded_sha256, &captured.encoded_sha256);
    // Captured bytes remain the authority even if a caller changes the path
    // afterward; noncanonical compact data is still rejected by the parser.
    const old = captured.encoded[12];
    captured.encoded[12] = 1;
    defer captured.encoded[12] = old;
    try std.testing.expectError(error.NonCanonicalEncoding, cairo.adapter.input.parseSlice(allocator, captured.encoded, .{}));
}

test "Rust oracle compact inputs match normalized JSON for continuous PIEs" {
    const directory = std.process.getEnvVarOwned(std.testing.allocator, "STWO_CAIRO_CUDA_CONTINUOUS_INPUT_DIR") catch return error.SkipZigTest;
    defer std.testing.allocator.free(directory);
    for ([_][]const u8{ "15627902-15627904", "15627905-15627907" }) |name| {
        const json_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/{s}.prover_input.json", .{ directory, name });
        defer std.testing.allocator.free(json_path);
        const compact_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/{s}.prover_input.cpi", .{ directory, name });
        defer std.testing.allocator.free(compact_path);
        var json = try read(std.testing.allocator, json_path);
        defer json.input.deinit(std.testing.allocator);
        defer std.testing.allocator.free(json.encoded);
        var compact = try read(std.testing.allocator, compact_path);
        defer compact.input.deinit(std.testing.allocator);
        defer std.testing.allocator.free(compact.encoded);
        try std.testing.expectEqualSlices(u8, json.encoded, compact.encoded);
        try std.testing.expectEqualSlices(u8, &json.encoded_sha256, &compact.encoded_sha256);
    }
}
