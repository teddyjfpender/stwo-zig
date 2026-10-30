const std = @import("std");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Continue = @import("../block_v7_real_window_continuation_v2.zig");
fn digest(key: [:0]const u8) !Capture.Digest {
    var out: Capture.Digest = undefined;
    if ((try std.fmt.hexToBytes(&out, std.posix.getenv(key) orelse return error.MissingCapsulePin)).len != 32) return error.InvalidCapsulePin;
    return out;
}
test "export bounded retained Ethereum continuation capsule without prefix replay" {
    const elf_path = std.posix.getenv("STWO_WINDOW_CONTINUE_ELF") orelse return error.SkipZigTest;
    const Engine = @import("stwo_prover_engine");
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 8 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(a, elf_path, 32 << 20);
    defer a.free(elf);
    const bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_WINDOW_CONTINUE_INCOMING") orelse return error.MissingIncoming, 64 << 20);
    defer a.free(bytes);
    const elf_pin = try digest("STWO_WINDOW_CONTINUE_ELF_SHA256");
    const incoming_pin = try digest("STWO_WINDOW_CONTINUE_INCOMING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    const cycles = try std.fmt.parseInt(u32, std.posix.getenv("STWO_WINDOW_CONTINUE_CYCLES") orelse return error.MissingWindowSize, 10);
    const skip = try std.fmt.parseInt(u64, std.posix.getenv("STWO_WINDOW_CONTINUE_SKIP") orelse return error.MissingWindowOffset, 10);
    // Explicit corpus-export envelope; production continuation defaults stay
    // bounded at 1M. This does not qualify any proof or recursive geometry.
    var actual = try Continue.capture(a, elf, elf_pin, incoming, incoming_pin, cycles, .{ .max_cycles = 1 << 23 });
    defer actual.deinit(a);
    const outgoing_bytes = try actual.outgoing.encode(a);
    defer a.free(outgoing_bytes);
    var dir = try std.fs.cwd().openDir(std.posix.getenv("STWO_WINDOW_CONTINUE_OUTPUT") orelse return error.MissingOutput, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "incoming.b7win", .data = bytes });
    try dir.writeFile(.{ .sub_path = "outgoing.b7win", .data = outgoing_bytes });
    const report = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-v7-explicit-window-continuation-input-v2",
        .scope = "actual guest continuation from independently selected incoming snapshot; no prefix replay or proof authority",
        .proof_verified = false,
        .execution_completed = true,
        .window = .{ .skip_cycles = skip, .cycles = cycles },
        .elf_sha256 = std.fmt.bytesToHex(elf_pin, .lower),
        .incoming_sha256 = std.fmt.bytesToHex(incoming_pin, .lower),
        .outgoing_sha256 = std.fmt.bytesToHex(actual.outgoing.identity(), .lower),
        .stats = actual.stats,
        .incoming_words = incoming.words.len,
        .outgoing_words = actual.outgoing.words.len,
        .logical_source_bytes_read = elf.len + bytes.len,
        .logical_snapshot_bytes_written = bytes.len + outgoing_bytes.len,
        .physical_disk_bytes = @as(?u64, null),
        .charged_peak_bytes = budget.snapshot().peak_live_bytes,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try dir.writeFile(.{ .sub_path = "capture.json", .data = report });
}
