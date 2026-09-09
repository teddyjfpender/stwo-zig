//! Create-only cold checker for one actual combined bulk4+SWAP5 guest ELF.

const std = @import("std");

const receipt_mod = @import(
    "runner/guest_precompile/ethereum_candidate_combined_elf_receipt_v1.zig",
);

const maximum_elf_bytes: usize = 64 << 20;
const maximum_checker_bytes: usize = 256 << 20;

pub fn main() void {
    run() catch |err| {
        std.debug.print("combined candidate ELF check failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 6 or
        !std.fs.path.isAbsolute(args[1]) or
        !std.fs.path.isAbsolute(args[3]) or
        !std.fs.path.isAbsolute(args[4]))
    {
        std.debug.print(
            "usage: check-ethereum-combined-candidate-elf-v1 " ++
                "<absolute-candidate.elf> <expected-lowercase-sha256> " ++
                "<absolute-source-root> <absolute-create-only-receipt.json> " ++
                "<relative-source-path>...\n",
            .{},
        );
        return error.InvalidArguments;
    }

    const elf_path = args[1];
    const expected_elf_sha256 = try receipt_mod.parseDigest(args[2]);
    const source_root = args[3];
    const receipt_path = args[4];
    const elf_bytes = try readAbsoluteAlloc(allocator, elf_path, maximum_elf_bytes);
    defer allocator.free(elf_bytes);
    const source_closure = try receipt_mod.collectSourceClosure(source_root, args[5..]);
    const checker = try checkerIdentity(allocator);
    defer allocator.free(checker.path);
    const receipt = try receipt_mod.createFromReopened(
        allocator,
        elf_path,
        elf_bytes,
        expected_elf_sha256,
        checker,
        source_root,
        source_closure,
        true,
    );
    const encoded = try receipt_mod.encodeAlloc(allocator, receipt);
    defer allocator.free(encoded);

    // Reopen and reconstruct every authority before the final path exists.
    try coldValidateBeforePublish(
        allocator,
        encoded,
        elf_path,
        expected_elf_sha256,
        source_root,
    );
    var output = try std.fs.createFileAbsolute(receipt_path, .{
        .exclusive = true,
        .mode = 0o600,
    });
    defer output.close();
    try output.writeAll(encoded);
    try output.writeAll("\n");
    try output.sync();
}

fn coldValidateBeforePublish(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    elf_path: []const u8,
    expected_elf_sha256: receipt_mod.Digest,
    source_root: []const u8,
) !void {
    var parsed = try receipt_mod.decodeAlloc(allocator, encoded);
    defer parsed.deinit();
    const receipt = try receipt_mod.fromWire(parsed.value);
    if (!receipt.final_candidate_executable or
        !std.mem.eql(u8, receipt.elf.path, elf_path) or
        !std.mem.eql(u8, receipt.source_root, source_root) or
        !std.mem.eql(u8, &receipt.elf.sha256, &expected_elf_sha256))
    {
        return error.InvalidCombinedCandidateElfReceipt;
    }
    const canonical = try receipt_mod.encodeAlloc(allocator, receipt);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, encoded, canonical))
        return error.NonCanonicalCombinedCandidateElfReceipt;

    const reopened_elf = try readAbsoluteAlloc(allocator, elf_path, maximum_elf_bytes);
    defer allocator.free(reopened_elf);
    var source_paths: [receipt_mod.source_file_capacity][]const u8 = undefined;
    const source_count: usize = receipt.source_closure.count;
    for (receipt.source_closure.files[0..source_count], 0..) |maybe_file, index|
        source_paths[index] = maybe_file.?.path;
    const reopened_source_closure = try receipt_mod.collectSourceClosure(
        source_root,
        source_paths[0..source_count],
    );
    const reopened_checker = try checkerIdentity(allocator);
    defer allocator.free(reopened_checker.path);
    if (reopened_checker.bytes != receipt.checker.bytes or
        !std.mem.eql(u8, reopened_checker.path, receipt.checker.path) or
        !std.mem.eql(u8, &reopened_checker.sha256, &receipt.checker.sha256))
    {
        return error.CombinedCandidateCheckerIdentityMismatch;
    }
    try receipt_mod.validateReopened(
        allocator,
        receipt,
        reopened_elf,
        reopened_source_closure,
    );
}

fn checkerIdentity(allocator: std.mem.Allocator) !receipt_mod.FileIdentity {
    const path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(path);
    const bytes = try readAbsoluteAlloc(allocator, path, maximum_checker_bytes);
    defer allocator.free(bytes);
    return .{
        .path = try allocator.dupe(u8, path),
        .bytes = @intCast(bytes.len),
        .sha256 = receipt_mod.hashBytes(bytes),
    };
}

fn readAbsoluteAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, maximum_bytes);
}

comptime {
    if (receipt_mod.production_active or receipt_mod.proof_or_fresh_verification)
        @compileError("combined candidate ELF checker became production-active");
}
