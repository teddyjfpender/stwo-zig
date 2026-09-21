const std = @import("std");
const artifact = @import("artifact.zig");
const toolchain = @import("toolchain.zig");

const usage =
    \\usage: metal-core-aot <emit|build> --output-dir <path> [--profile ethereum-fixed-program-narrow-v1|recursive-framework-v1]
    \\
    \\  emit   Write the canonical core MSL and authenticated JSON manifest.
    \\  build  Require full Xcode, emit the inputs, and run metal + metallib.
;

pub fn main() void {
    run() catch |err| {
        if (err == error.FullXcodeRequired)
            std.debug.print("{s}\n", .{toolchain.full_xcode_message})
        else
            std.debug.print("metal-core-aot failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if ((args.len != 4 and args.len != 6) or !std.mem.eql(u8, args[2], "--output-dir")) {
        std.debug.print("{s}", .{usage});
        return error.InvalidArguments;
    }
    const profile: artifact.Profile = if (args.len == 4) .core_v2 else if (std.mem.eql(u8, args[4], "--profile") and std.mem.eql(u8, args[5], "ethereum-fixed-program-narrow-v1")) .ethereum_fixed_program_narrow_v1 else if (std.mem.eql(u8, args[4], "--profile") and std.mem.eql(u8, args[5], "recursive-framework-v1")) .recursive_framework_v1 else return error.InvalidArguments;
    if (std.mem.eql(u8, args[1], "emit")) {
        try artifact.emitForProfile(allocator, args[3], profile);
    } else if (std.mem.eql(u8, args[1], "build")) {
        try toolchain.buildForProfile(allocator, args[3], profile);
    } else {
        std.debug.print("{s}", .{usage});
        return error.InvalidArguments;
    }
}

test {
    _ = artifact;
    _ = toolchain;
}
