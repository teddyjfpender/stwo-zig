//! Actual integration consumer; real Session and Native.Context slot, no GPU initialization.
const std = @import("std");
const Native = @import("stwo_riscv_cuda_integration").rv64.execution.pcs.pcs_native;
const Session = @import("capture_execution.zig").Session;
extern "c" fn setenv([*:0]const u8, [*:0]const u8, c_int) c_int;
extern "c" fn unsetenv([*:0]const u8) c_int;

test "capture execution consumer: real request hashes native slot and diagnostic failure stay request owned" {
    const a = std.testing.allocator;
    const key = "STWO_RV64_LEAN_ARTIFACT_DIR";
    const previous = std.process.getEnvVarOwned(a, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (previous) |value| a.free(value);
    defer {
        if (previous) |value| {
            const text = a.dupeZ(u8, value) catch unreachable;
            defer a.free(text);
            std.debug.assert(setenv(key, text, 1) == 0);
        } else std.debug.assert(unsetenv(key) == 0);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const root_z = try a.dupeZ(u8, root);
    defer a.free(root_z);
    try std.testing.expectEqual(@as(c_int, 0), setenv(key, root_z, 1));
    try tmp.dir.writeFile(.{ .sub_path = "image", .data = "host diagnostic image fixture" });
    const image = try tmp.dir.realpathAlloc(a, "image");
    defer a.free(image);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("host diagnostic image fixture", &hash, .{});
    const pin = std.fmt.bytesToHex(hash, .lower);
    const config = try std.json.Stringify.valueAlloc(a, .{ .elf = image, .input = image, .elf_sha256 = pin, .input_sha256 = pin }, .{});
    defer a.free(config);
    try tmp.dir.writeFile(.{ .sub_path = "request", .data = config });
    const request = try tmp.dir.realpathAlloc(a, "request");
    defer a.free(request);
    var session = Session.config(a, request, @splat(9), .execution);
    const dataset = session.dataset orelse return error.MissingActualCaptureOwner;
    const dataset_path = try a.dupe(u8, dataset.path);
    defer a.free(dataset_path);
    var native: Native.Context = undefined;
    native.recording = .{}; // No other Native fields participate in attachment.
    session.attach(&native.recording);
    try native.recording.requireExecution(@splat(9));
    native.active_block = @splat(7);
    native.cache = .empty;
    // This actual admission branch returns before setup, submit or any GPU API.
    try std.testing.expectError(error.ResidentBlockStillActive, native.beginBlock(@splat(9), .{ .device_bytes = 0, .immutable_bytes = 0, .max_scopes = 1 }));
    _ = try dataset.write(.nodes, "node-0.gnr", "host capture bytes");
    dataset.fail(error.NoSpaceLeft);
    native.recording.detach();
    session.success = true;
    session.deinit();
    try std.testing.expectError(error.RecordingIncomplete, Native.Recording.verify(a, dataset_path));
    const request_z = try a.dupeZ(u8, request);
    defer a.free(request_z);
    var arguments = Session.args(a, &.{ "capture-consumer", "recurse-candidate", request_z });
    try std.testing.expect(arguments.dataset != null);
    arguments.deinit();
}
