//! Package-root binding for RISC-V frontend focused suites.
//! A suite lives at `<package>/tests/focused/<name>.zig`, but Zig confines a
//! module's imports to its root file's directory. The module therefore roots
//! at `<package>/focused_test_root.zig`, which analyses only the suite named
//! by the `focused_suite` option and fails to compile on any other name.
const std = @import("std");

pub const Selection = struct { root: []const u8, name: []const u8 };

const PREFIX = "src/frontends/riscv/";
const SUITES = "tests/focused/";

pub fn select(b: *std.Build, source: []const u8) ?Selection {
    if (!std.mem.startsWith(u8, source, PREFIX)) return null;
    const at = std.mem.indexOf(u8, source, SUITES) orelse return null;
    if (source[at - 1] != '/') std.debug.panic("focused suite outside a package tests/ directory: {s}", .{source});
    const file = source[at + SUITES.len ..];
    if (!std.mem.endsWith(u8, file, ".zig") or std.mem.indexOfScalar(u8, file, '/') != null)
        std.debug.panic("focused suite must be a direct tests/focused/*.zig file: {s}", .{source});
    return .{
        .root = b.fmt("{s}focused_test_root.zig", .{source[0..at]}),
        .name = file[0 .. file.len - ".zig".len],
    };
}

pub fn bind(b: *std.Build, module: *std.Build.Module, selection: Selection) void {
    const options = b.addOptions();
    options.addOption([]const u8, "name", selection.name);
    module.addOptions("focused_suite", options);
}
