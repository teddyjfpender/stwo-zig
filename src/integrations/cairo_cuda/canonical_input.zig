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
    timings: Timings,
};

pub const Timings = struct {
    read_ns: u64,
    parse_and_encode_ns: u64,
    digest_wait_ns: u64,
    identity_check_ns: u64,
};

pub fn read(allocator: std.mem.Allocator, path: []const u8) !Capture {
    return readExpected(allocator, path, null);
}

/// A service can supply the authenticated digest of its immutable CAS object.
/// The digest of the captured bytes must match it; no second pathname read is
/// needed because every subsequent operation uses the owned capture.
pub fn readExpected(allocator: std.mem.Allocator, path: []const u8, expected: ?[32]u8) !Capture {
    var timer = try std.time.Timer.start();
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
        const read_ns = timer.lap();
        var check = BytesHashJob{ .bytes = bytes };
        check.start();
        defer check.deinit();
        var input = try cairo.adapter.input.parseSlice(allocator, bytes, limits);
        errdefer input.deinit(allocator);
        const parse_ns = timer.lap();
        const digest = check.wait();
        const digest_wait_ns = timer.lap();
        if (expected) |identity| {
            if (!std.mem.eql(u8, &digest, &identity)) return error.CanonicalInputChanged;
        } else if (!std.mem.eql(u8, &digest, &try fileSha(path))) return error.CanonicalInputChanged;
        return .{ .input = input, .encoded = bytes, .file_sha256 = digest, .encoded_sha256 = digest, .timings = .{ .read_ns = read_ns, .parse_and_encode_ns = parse_ns, .digest_wait_ns = digest_wait_ns, .identity_check_ns = timer.lap() } };
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
    const read_ns = timer.lap();
    var check = BytesHashJob{ .bytes = json_bytes };
    check.start();
    defer check.deinit();
    var input = try cairo.adapter.input.parseSlice(allocator, json_bytes, limits);
    errdefer input.deinit(allocator);
    const encoded = try cairo.adapter.compact_writer.encode(allocator, &input);
    errdefer allocator.free(encoded);
    const parse_ns = timer.lap();
    const file_digest = check.wait();
    const digest_wait_ns = timer.lap();
    if (expected) |identity| {
        if (!std.mem.eql(u8, &file_digest, &identity)) return error.CanonicalInputChanged;
    } else if (!std.mem.eql(u8, &file_digest, &try fileSha(path))) return error.CanonicalInputChanged;
    const encoded_digest = sha(encoded);
    return .{ .input = input, .encoded = encoded, .file_sha256 = file_digest, .encoded_sha256 = encoded_digest, .timings = .{ .read_ns = read_ns, .parse_and_encode_ns = parse_ns, .digest_wait_ns = digest_wait_ns, .identity_check_ns = timer.lap() } };
}

/// Hash captured immutable bytes while they are parsed. The second path hash
/// still runs after parsing, so the replacement check retains its timing.
const BytesHashJob = struct {
    bytes: []const u8,
    thread: ?std.Thread = null,
    started: bool = false,
    digest: [32]u8 = undefined,

    fn start(self: *BytesHashJob) void {
        self.thread = std.Thread.spawn(.{}, run, .{self}) catch return;
        self.started = true;
    }

    fn run(self: *BytesHashJob) void {
        self.digest = sha(self.bytes);
    }

    fn wait(self: *BytesHashJob) [32]u8 {
        if (!self.started) return sha(self.bytes);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        return self.digest;
    }

    fn deinit(self: *BytesHashJob) void {
        if (self.thread) |thread| thread.join();
    }
};

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

test "authenticated capture checks owned bytes without rereading the path" {
    const allocator = std.testing.allocator;
    const path = "vectors/cairo/official/all_opcodes.prover_input.cpi";
    const expected = try fileSha(path);
    var captured = try readExpected(allocator, path, expected);
    defer captured.input.deinit(allocator);
    defer allocator.free(captured.encoded);
    try std.testing.expectEqual(expected, captured.file_sha256);
    try std.testing.expectError(error.CanonicalInputChanged, readExpected(allocator, path, [_]u8{0} ** 32));
}

test "large compact capture keeps identical authority with expected digest" {
    const allocator = std.testing.allocator;
    const path = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_LARGE_INPUT") catch return error.SkipZigTest;
    defer allocator.free(path);
    var legacy = try read(allocator, path);
    const expected = legacy.file_sha256;
    const encoded = legacy.encoded_sha256;
    std.debug.print("cairo-cuda capture legacy_ns={} identity_check_ns={}\n", .{
        legacy.timings.read_ns + legacy.timings.parse_and_encode_ns + legacy.timings.digest_wait_ns + legacy.timings.identity_check_ns,
        legacy.timings.identity_check_ns,
    });
    legacy.input.deinit(allocator);
    allocator.free(legacy.encoded);
    var authenticated = try readExpected(allocator, path, expected);
    defer authenticated.input.deinit(allocator);
    defer allocator.free(authenticated.encoded);
    try std.testing.expectEqual(expected, authenticated.file_sha256);
    try std.testing.expectEqual(encoded, authenticated.encoded_sha256);
    std.debug.print("cairo-cuda capture authenticated_ns={} identity_check_ns={}\n", .{
        authenticated.timings.read_ns + authenticated.timings.parse_and_encode_ns + authenticated.timings.digest_wait_ns + authenticated.timings.identity_check_ns,
        authenticated.timings.identity_check_ns,
    });
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
