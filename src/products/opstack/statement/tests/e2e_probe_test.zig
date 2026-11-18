//! ReleaseFast probe checks against the golden ABI probe guest in
//! `vectors/opstack` (paths arrive through the `opstack_fixture_paths` build
//! options module; no environment variable is read).
const std = @import("std");
const paths = @import("opstack_fixture_paths");
const frontend = @import("opstack_frontend_component");
const elf = @import("stwo_riscv_rv64").execution.elf;

const a = std.testing.allocator;

fn readVector(name: []const u8, limit: usize) ![]u8 {
    var dir = try std.fs.cwd().openDir(paths.vectors_root, .{});
    defer dir.close();
    return dir.readFileAlloc(a, name, limit);
}

fn manifest() !std.json.Parsed(std.json.Value) {
    const bytes = try readVector("abi-probe.json", 1 << 20);
    defer a.free(bytes);
    return std.json.parseFromSlice(std.json.Value, a, bytes, .{});
}

test "e2e probe: golden ELF matches its pinned sha256" {
    const bytes = try readVector("abi-probe.elf", 64 << 20);
    defer a.free(bytes);
    var parsed = try manifest();
    defer parsed.deinit();
    const pinned = parsed.value.object.get("elf_sha256") orelse return error.MissingProbeSha256;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualStrings(pinned.string, &actual);
}

test "e2e probe: golden ELF is an immutable RV64 executable" {
    const bytes = try readVector("abi-probe.elf", 64 << 20);
    defer a.free(bytes);
    const image = try elf.inspect(bytes, .{});
    try std.testing.expect(image.load_segments > 0);
    var loaded = try elf.loadImmutableImage(a, bytes, .{});
    loaded.deinit();
}

test "e2e probe: one flipped ELF byte breaks the pin" {
    const bytes = try readVector("abi-probe.elf", 64 << 20);
    defer a.free(bytes);
    var parsed = try manifest();
    defer parsed.deinit();
    bytes[bytes.len / 2] ^= 1;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expect(!std.mem.eql(u8, parsed.value.object.get("elf_sha256").?.string, &actual));
}

test "e2e probe: pinned expected output, when present, is a well-formed statement" {
    var parsed = try manifest();
    defer parsed.deinit();
    const request = parsed.value.object.get("request") orelse return;
    const expected = request.object.get("expected_output") orelse return;
    const bytes = try frontend.statement.expectedFromHex(expected.string);
    var corrupted = bytes;
    corrupted[0] ^= 1;
    try std.testing.expect(!(try frontend.statement.binds(&corrupted, &bytes)));
}
