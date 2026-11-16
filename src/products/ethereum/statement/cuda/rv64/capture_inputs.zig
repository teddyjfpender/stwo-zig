//! Producer-only diagnostic identity; hashes actual input files against request pins.
const std = @import("std");
pub const Metadata = struct { program: [32]u8, input: [32]u8, config: [32]u8 };
pub fn configForArgs(args: []const [:0]const u8) ?[]const u8 {
    const at: usize = if (args.len > 1 and std.mem.eql(u8, args[1], "--security-profile")) 3 else 1;
    if (args.len <= at + 1) return null;
    const mode = args[at];
    if (!std.mem.eql(u8, mode, "produce-candidate") and !std.mem.eql(u8, mode, "produce-control") and !std.mem.eql(u8, mode, "produce-and-recurse-candidate") and !std.mem.eql(u8, mode, "recurse-candidate") and !std.mem.eql(u8, mode, "resume-recursion-candidate")) return null;
    return args[at + 1];
}
pub fn read(a: std.mem.Allocator, path: []const u8) !Metadata {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 16384);
    defer a.free(bytes);
    const Config = struct { elf: []const u8, input: []const u8, elf_sha256: []const u8, input_sha256: []const u8 };
    const config = try std.json.parseFromSlice(Config, a, bytes, .{ .ignore_unknown_fields = true });
    defer config.deinit();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .program = try pinned(config.value.elf, config.value.elf_sha256), .input = try pinned(config.value.input, config.value.input_sha256), .config = digest };
}
fn pinned(path: []const u8, pin: []const u8) ![32]u8 {
    if (pin.len != 64) return error.InvalidCaptureInputPin;
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, pin);
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [32768]u8 = undefined;
    while (true) {
        const n = try file.read(&buffer);
        if (n == 0) break;
        hash.update(buffer[0..n]);
    }
    const actual = hash.finalResult();
    if (!std.mem.eql(u8, &actual, &expected)) return error.CaptureInputPinMismatch;
    return actual;
}
test {
    _ = @import("capture_inputs_test.zig");
}
