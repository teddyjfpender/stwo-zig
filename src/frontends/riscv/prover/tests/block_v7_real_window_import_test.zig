//! Opt-in capture executable. Paths are supplied by the hash-checking Python
//! importer; source hashes are still checked independently here.
const std = @import("std");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
test "capture pinned retained Ethereum benchmark window" {
    const a = std.testing.allocator;
    const elf_path = std.posix.getenv("STWO_REAL_WINDOW_ELF") orelse return error.SkipZigTest;
    const input_path = std.posix.getenv("STWO_REAL_WINDOW_INPUT") orelse return error.MissingRealWindowInput;
    const output_path = std.posix.getenv("STWO_REAL_WINDOW_OUTPUT_DIR") orelse return error.MissingRealWindowOutput;
    var pins: Capture.Pins = undefined;
    _ = try std.fmt.hexToBytes(&pins.elf, "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688");
    _ = try std.fmt.hexToBytes(&pins.input, "737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82");
    const window: Capture.Window = .{
        .skip_cycles = try std.fmt.parseInt(u64, std.posix.getenv("STWO_REAL_WINDOW_SKIP") orelse "0", 10),
        .cycles = try std.fmt.parseInt(u32, std.posix.getenv("STWO_REAL_WINDOW_CYCLES") orelse "32768", 10),
    };
    const elf = try std.fs.cwd().readFileAlloc(a, elf_path, 32 << 20);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, input_path, 4 << 20);
    defer a.free(input);
    var captured = try Capture.capture(a, elf, input, pins, window, .{});
    defer captured.deinit();
    try Capture.replay(a, elf, input, &captured, captured.incoming.identity(), .{});
    const json = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-v7-explicit-window-benchmark-input-v1",
        .scope = "real RV32 window replay; incoming state is explicit benchmark input; no prefix, original-STARK, recursive or Ethereum-block proof",
        .proof_verified = false,
        .replay_verified = true,
        .elf_sha256 = std.fmt.bytesToHex(pins.elf, .lower),
        .input_sha256 = std.fmt.bytesToHex(pins.input, .lower),
        .window = window,
        .stats = captured.stats,
        .incoming_sha256 = std.fmt.bytesToHex(captured.incoming.identity(), .lower),
        .outgoing_sha256 = std.fmt.bytesToHex(captured.outgoing.identity(), .lower),
        .behavior_sha256 = std.fmt.bytesToHex(captured.behavior, .lower),
        .incoming_file = "incoming.b7win",
        .outgoing_file = "outgoing.b7win",
    }, .{ .whitespace = .indent_2 });
    defer a.free(json);
    var dir = try std.fs.cwd().openDir(output_path, .{});
    defer dir.close();
    inline for (.{ "incoming", "outgoing" }) |name| {
        const bytes = try @field(captured, name).encode(a);
        defer a.free(bytes);
        var snapshot_file = try dir.createFile(name ++ ".b7win", .{ .exclusive = true });
        defer snapshot_file.close();
        try snapshot_file.writeAll(bytes);
    }
    var file = try dir.createFile("capture.json", .{ .exclusive = true });
    defer file.close();
    try file.writeAll(json);
    std.debug.print("V7_REAL_WINDOW_CAPTURE stats={f} replay_verified=true proof_verified=false\n", .{std.json.fmt(captured.stats, .{})});
}
