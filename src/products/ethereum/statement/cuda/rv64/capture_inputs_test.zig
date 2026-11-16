const std = @import("std");
const owner = @import("capture_inputs.zig");
const a = std.testing.allocator;
test "capture identity hashes both actual files and refuses stale declared pins" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "guest", .data = "guest bytes" });
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "block bytes" });
    const elf = try tmp.dir.realpathAlloc(a, "guest");
    defer a.free(elf);
    const input = try tmp.dir.realpathAlloc(a, "input");
    defer a.free(input);
    var program: [32]u8 = undefined;
    var data: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("guest bytes", &program, .{});
    std.crypto.hash.sha2.Sha256.hash("block bytes", &data, .{});
    const text = try std.json.Stringify.valueAlloc(a, .{ .elf = elf, .input = input, .elf_sha256 = std.fmt.bytesToHex(program, .lower), .input_sha256 = std.fmt.bytesToHex(data, .lower), .other = "original product owns other fields" }, .{});
    defer a.free(text);
    try tmp.dir.writeFile(.{ .sub_path = "request.json", .data = text });
    const path = try tmp.dir.realpathAlloc(a, "request.json");
    defer a.free(path);
    const identity = try owner.read(a, path);
    try std.testing.expectEqualSlices(u8, &program, &identity.program);
    try std.testing.expectEqualSlices(u8, &data, &identity.input);
    try tmp.dir.writeFile(.{ .sub_path = "guest", .data = "changed guest" });
    try std.testing.expectError(error.CaptureInputPinMismatch, owner.read(a, path));
    try tmp.dir.writeFile(.{ .sub_path = "guest", .data = "guest bytes" });
    try tmp.dir.writeFile(.{ .sub_path = "input", .data = "changed block" });
    try std.testing.expectError(error.CaptureInputPinMismatch, owner.read(a, path));
}
test "capture identity selects existing producer arguments only" {
    inline for (.{ "recurse-candidate", "resume-recursion-candidate" }) |mode| try std.testing.expectEqualStrings("request", owner.configForArgs(&.{ "p", mode, "request" }).?);
    try std.testing.expectEqual(@as(?[]const u8, null), owner.configForArgs(&.{ "p", "verify-recursion-candidate", "request" }));
    try std.testing.expectEqualStrings("request", owner.configForArgs(&.{ "p", "produce-candidate", "request" }).?);
    try std.testing.expectEqualStrings("request", owner.configForArgs(&.{ "p", "--security-profile", "profile", "produce-and-recurse-candidate", "request" }).?);
    try std.testing.expectEqual(@as(?[]const u8, null), owner.configForArgs(&.{ "p", "verify-candidate", "request" }));
    try std.testing.expectEqual(@as(?[]const u8, null), owner.configForArgs(&.{ "p", "--security-profile" }));
}
