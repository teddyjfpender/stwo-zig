//! Small terminal-only qualification runner. The executable policy root passes
//! ITS builtin.test_functions; a separately compiled runner module has none.
//! Unsupported server/fuzz modes fail explicitly instead of silently skipping.
const std = @import("std");
const testing = std.testing;
pub const std_options: std.Options = .{ .logFn = log };
var log_err_count: usize = 0;
var argument_buffer: [8192]u8 = undefined;
pub fn main(test_functions: []const std.builtin.TestFn) void {
    @disableInstrumentation();
    if (test_functions.len == 0) {
        std.debug.print("Qualification runner rejected zero discovered tests.\n", .{});
        std.process.exit(1);
    }
    var arguments = std.heap.FixedBufferAllocator.init(&argument_buffer);
    const args = std.process.argsAlloc(arguments.allocator()) catch @panic("unable to parse test runner arguments");
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            testing.random_seed = std.fmt.parseUnsigned(u32, arg["--seed=".len..], 0) catch @panic("unable to parse --seed argument");
        } else if (std.mem.startsWith(u8, arg, "--cache-dir=")) {
            // Accepted for compatibility with direct compiler invocation. This
            // terminal runner does not enter fuzz mode or use the cache path.
        } else if (std.mem.eql(u8, arg, "--listen=-")) {
            @panic("policy qualification requires the terminal runner, not --listen");
        } else @panic("unrecognized test runner argument");
    }
    if (@import("builtin").fuzz) @panic("policy qualification runner does not execute fuzz jobs");
    var passed: usize = 0;
    var skipped: usize = 0;
    var failed: usize = 0;
    var leaks: usize = 0;
    for (test_functions, 0..) |test_fn, i| {
        testing.allocator_instance = .{};
        testing.log_level = .warn;
        std.debug.print("{d}/{d} {s}...", .{ i + 1, test_functions.len, test_fn.name });
        if (test_fn.func()) |_| {
            passed += 1;
            std.debug.print("OK\n", .{});
        } else |err| switch (err) {
            error.SkipZigTest => {
                skipped += 1;
                std.debug.print("SKIP\n", .{});
            },
            else => {
                failed += 1;
                std.debug.print("FAIL ({s})\n", .{@errorName(err)});
                if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
            },
        }
        if (testing.allocator_instance.deinit() == .leak) leaks += 1;
    }
    if (passed == test_functions.len) {
        std.debug.print("All {d} tests passed.\n", .{passed});
    } else std.debug.print("{d} passed; {d} skipped; {d} failed.\n", .{ passed, skipped, failed });
    if (log_err_count != 0) std.debug.print("{d} errors were logged.\n", .{log_err_count});
    if (leaks != 0) std.debug.print("{d} tests leaked memory.\n", .{leaks});
    if (failed != 0 or log_err_count != 0 or leaks != 0) std.process.exit(1);
}
pub fn log(comptime level: std.log.Level, comptime scope: @Type(.enum_literal), comptime format: []const u8, args: anytype) void {
    @disableInstrumentation();
    if (@intFromEnum(level) <= @intFromEnum(std.log.Level.err)) log_err_count +|= 1;
    if (@intFromEnum(level) <= @intFromEnum(testing.log_level)) std.debug.print("[" ++ @tagName(scope) ++ "] (" ++ @tagName(level) ++ "): " ++ format ++ "\n", args);
}
