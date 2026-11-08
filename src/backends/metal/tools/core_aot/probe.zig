const std = @import("std");
const host_transcript = @import("host_transcript");
const shader_manifest = @import("shader_manifest");

const core_aot = shader_manifest.core_aot;
const kernel_abi = shader_manifest.abi_contract.native_kernel_abi;

const usage =
    "usage: metal-core-aot-probe --bundle-dir <path> --trust-anchor <path>\n";

extern fn stwo_zig_metal_core_probe(
    metallib_bytes: [*]const u8,
    metallib_len: usize,
    source_bytes: [*]const u8,
    source_len: usize,
    transcript_source: [*]const u32,
    transcript_source_len: usize,
    expected_secure: [*]const u32,
    expected_secure_len: usize,
    expected_queries: [*]const u32,
    expected_queries_len: usize,
    expected_names: [*]const [*:0]const u8,
    expected_count: usize,
    error_message: [*]u8,
    error_message_len: usize,
) bool;

pub fn main() void {
    run() catch |err| {
        std.debug.print("metal-core-aot-probe failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 5 or !std.mem.eql(u8, args[1], "--bundle-dir") or
        !std.mem.eql(u8, args[3], "--trust-anchor"))
    {
        std.debug.print("{s}", .{usage});
        return error.InvalidArguments;
    }

    const expected_manifest_sha256 = try readTrustAnchor(allocator, args[4]);
    var admission = try core_aot.admit(allocator, args[2], expected_manifest_sha256);
    defer admission.deinit();

    var owned_names: [kernel_abi.len][:0]u8 = undefined;
    var name_pointers: [kernel_abi.len][*:0]const u8 = undefined;
    var initialized: usize = 0;
    defer for (owned_names[0..initialized]) |name| allocator.free(name);
    for (kernel_abi, 0..) |entry, index| {
        owned_names[index] = try allocator.dupeZ(u8, entry.name);
        initialized += 1;
        name_pointers[index] = owned_names[index].ptr;
    }

    const transcript = host_transcript.canonical;

    var error_buffer: [1024]u8 = @splat(0);
    if (!stwo_zig_metal_core_probe(
        admission.metallib_bytes.ptr,
        admission.metallib_bytes.len,
        shader_manifest.native_amalgamated_source.ptr,
        shader_manifest.native_amalgamated_source.len - 1,
        &transcript.source,
        transcript.source.len,
        &transcript.secure,
        transcript.secure.len,
        &transcript.queries,
        transcript.queries.len,
        name_pointers[0..].ptr,
        name_pointers.len,
        &error_buffer,
        error_buffer.len,
    )) {
        const end = std.mem.indexOfScalar(u8, &error_buffer, 0) orelse error_buffer.len;
        std.log.err("Native core metallib rejected: {s}", .{error_buffer[0..end]});
        return error.CompiledMetalLibraryRejected;
    }
    std.debug.print(
        "Native core metallib accepted: {d} exact kernel exports, zero function constants, AOT/JIT kernel parity\n",
        .{kernel_abi.len},
    );
}

fn readTrustAnchor(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const encoded = try std.fs.cwd().readFileAlloc(
        allocator,
        path,
        256,
    );
    defer allocator.free(encoded);
    return parseTrustAnchor(encoded);
}

fn parseTrustAnchor(encoded: []const u8) ![32]u8 {
    const suffix = "  " ++ core_aot.manifest_filename ++ "\n";
    if (encoded.len != 64 + suffix.len or !std.mem.eql(u8, encoded[64..], suffix))
        return error.InvalidManifestTrustAnchor;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded[0..64]) catch
        return error.InvalidManifestTrustAnchor;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded[0..64], &canonical))
        return error.InvalidManifestTrustAnchor;
    return digest;
}

test "probe authority is the exact Native ABI with no function constants" {
    try std.testing.expectEqual(shader_manifest.native_exports.len, kernel_abi.len);
    for (kernel_abi) |entry|
        try std.testing.expectEqual(@as(usize, 0), entry.function_constants.len);
}

test "manifest trust anchor parser is canonical and fail closed" {
    const encoded = "ab" ** 32 ++ "  " ++ core_aot.manifest_filename ++ "\n";
    try std.testing.expectEqual([_]u8{0xab} ** 32, try parseTrustAnchor(encoded));
    try std.testing.expectError(
        error.InvalidManifestTrustAnchor,
        parseTrustAnchor("AB" ** 32 ++ "  " ++ core_aot.manifest_filename ++ "\n"),
    );
    try std.testing.expectError(
        error.InvalidManifestTrustAnchor,
        parseTrustAnchor("ab" ** 32 ++ " " ++ core_aot.manifest_filename ++ "\n"),
    );
}
