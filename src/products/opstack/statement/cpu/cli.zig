//! `stwo-opstack-native` command surface (design/opstack/integration.md §6.1)
//! translated onto the neutral pipeline command line. Flags may follow the
//! positional arguments; the pipeline wants setup flags first, then
//! `--security-profile`, then the mode. Options the S1 pipeline does not have
//! are rejected by name instead of being silently ignored.
const std = @import("std");

pub const Error = error{
    MissingSubcommand,
    MissingFlagValue,
    UnknownFlag,
    /// `batch-candidate`, `verify-batch-candidate`, `execute`: not in S1.
    SubcommandNotInPipeline,
    /// `--gkr-storage` other than `default` (RFC-4b, pending owner decision).
    GkrStorageNotInPipeline,
    /// `--receiver-setup` other than `committed`, or more than one worker (RFC-4b).
    ReceiverSetupNotInPipeline,
    OutOfMemory,
};

const renames = .{
    .{ "prove", "produce-candidate" },
    .{ "verify", "verify-candidate" },
    .{ "plan-candidate", "plan" },
};
const native_modes = [_][]const u8{ "describe", "describe-candidate", "plan", "produce-candidate", "verify-candidate", "verify-prefix-candidate" };
const missing_modes = [_][]const u8{ "batch-candidate", "verify-batch-candidate", "execute" };

fn pipelineMode(mode: []const u8) Error![]const u8 {
    inline for (renames) |r| if (std.mem.eql(u8, mode, r[0])) return r[1];
    for (native_modes) |m| if (std.mem.eql(u8, mode, m)) return m;
    for (missing_modes) |m| if (std.mem.eql(u8, mode, m)) return error.SubcommandNotInPipeline;
    return error.MissingSubcommand;
}

/// Returns the pipeline argv (`argv[0]` first). Strings are owned by `a`.
pub fn translate(a: std.mem.Allocator, argv: []const []const u8) Error![]const [:0]u8 {
    var setup: std.ArrayList([:0]u8) = .empty;
    var positional: std.ArrayList([:0]u8) = .empty;
    var profile: ?[]const u8 = null;
    var mode: ?[]const u8 = null;
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (!std.mem.startsWith(u8, arg, "--")) {
            if (mode == null) mode = try pipelineMode(arg) else try positional.append(a, try a.dupeZ(u8, arg));
            continue;
        }
        if (i + 1 >= argv.len) return error.MissingFlagValue;
        i += 1;
        const value = argv[i];
        if (std.mem.eql(u8, arg, "--security-profile")) {
            profile = value;
        } else if (std.mem.eql(u8, arg, "--setup-build-threads") or std.mem.eql(u8, arg, "--setup-identity-only") or std.mem.eql(u8, arg, "--setup-cache")) {
            // `ephemeral` = shared in-memory setup, nothing persisted (empty DIR).
            const v = if (std.mem.eql(u8, arg, "--setup-cache") and std.mem.eql(u8, value, "ephemeral")) "" else value;
            try setup.appendSlice(a, &.{ try a.dupeZ(u8, arg), try a.dupeZ(u8, v) });
        } else if (std.mem.eql(u8, arg, "--gkr-storage")) {
            if (!std.mem.eql(u8, value, "default")) return error.GkrStorageNotInPipeline;
        } else if (std.mem.eql(u8, arg, "--receiver-setup")) {
            if (!std.mem.eql(u8, value, "committed")) return error.ReceiverSetupNotInPipeline;
        } else if (std.mem.eql(u8, arg, "--receiver-setup-workers")) {
            if (!std.mem.eql(u8, value, "1")) return error.ReceiverSetupNotInPipeline;
        } else return error.UnknownFlag;
    }
    const selected = mode orelse return error.MissingSubcommand;
    const plan = std.mem.eql(u8, selected, "plan");
    // `plan` is geometry advice: it takes no profile and no resources file.
    if (plan and positional.items.len == 4) _ = positional.pop();
    var out: std.ArrayList([:0]u8) = .empty;
    try out.append(a, try a.dupeZ(u8, if (argv.len > 0) argv[0] else "stwo-opstack-native"));
    try out.appendSlice(a, setup.items);
    if (profile) |p| if (!plan) try out.appendSlice(a, &.{ try a.dupeZ(u8, "--security-profile"), try a.dupeZ(u8, p) });
    try out.append(a, try a.dupeZ(u8, selected));
    try out.appendSlice(a, positional.items);
    return out.items;
}

fn expectTranslation(expected: []const []const u8, argv: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const got = try translate(arena.allocator(), argv);
    try std.testing.expectEqual(expected.len, got.len);
    for (expected, got) |e, g| try std.testing.expectEqualStrings(e, g);
}

test "cli: prove moves trailing setup flags and the profile ahead of produce-candidate" {
    try expectTranslation(
        &.{ "op", "--setup-build-threads", "2", "--setup-cache", "", "--security-profile", "P", "produce-candidate", "req.json", "-", "out", "0", "res.json" },
        &.{ "op", "--security-profile", "P", "prove", "req.json", "-", "out", "0", "res.json", "--setup-build-threads", "2", "--setup-cache", "ephemeral" },
    );
}

test "cli: verify accepts only the committed single-worker receiver setup" {
    try expectTranslation(
        &.{ "op", "verify-candidate", "req.json", "out", "64", "128" },
        &.{ "op", "verify", "req.json", "out", "64", "128", "--receiver-setup", "committed" },
    );
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ReceiverSetupNotInPipeline, translate(arena.allocator(), &.{ "op", "verify", "r", "--receiver-setup", "identity-only" }));
    try std.testing.expectError(error.GkrStorageNotInPipeline, translate(arena.allocator(), &.{ "op", "prove", "r", "--gkr-storage", "streamed-dense" }));
}

test "cli: plan-candidate drops the profile and resources; S2 subcommands are rejected" {
    try expectTranslation(&.{ "op", "plan", "req.json", "-", "0" }, &.{ "op", "--security-profile", "P", "plan-candidate", "req.json", "-", "0", "res.json" });
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ "batch-candidate", "verify-batch-candidate", "execute" }) |mode|
        try std.testing.expectError(error.SubcommandNotInPipeline, translate(arena.allocator(), &.{ "op", mode, "x" }));
    try std.testing.expectError(error.UnknownFlag, translate(arena.allocator(), &.{ "op", "prove", "--outer-profile", "x" }));
}
