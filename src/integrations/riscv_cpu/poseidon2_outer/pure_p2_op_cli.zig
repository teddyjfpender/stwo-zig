//! Explicit native selector. Resource/config files do not select proof authority.
const std = @import("std");
pub const Command = struct { mode: []const u8, config: []const u8, directory: []const u8, resources: ?[]const u8 = null, truth_local_gkr: bool = false, miller_local_gkr: bool = false, detached_sponge: bool = false };
pub fn parse(args: []const []const u8) !Command {
    if (args.len < 4 or args.len > 7) return error.ExpectedOpNativeModeConfigDirectoryAndOptionalResources;
    const mode = args[1];
    if (!std.mem.eql(u8, mode, "prove") and !std.mem.eql(u8, mode, "verify") and !std.mem.eql(u8, mode, "capture") and !std.mem.eql(u8, mode, "prepare")) return error.ExpectedOpNativeModeConfigDirectoryAndOptionalResources;
    var out = Command{ .mode = mode, .config = args[2], .directory = args[3] };
    for (args[4..]) |arg| {
        if (std.mem.eql(u8, arg, "--truth-local-gkr")) {
            if (out.truth_local_gkr) return error.DuplicateOpNativeSelector;
            out.truth_local_gkr = true;
        } else if (std.mem.eql(u8, arg, "--miller-local-gkr")) {
            if (out.miller_local_gkr) return error.DuplicateOpNativeSelector;
            out.miller_local_gkr = true;
        } else if (std.mem.eql(u8, arg, "--detached-sponge")) {
            if (out.detached_sponge) return error.DuplicateOpNativeSelector;
            out.detached_sponge = true;
        } else {
            if (std.mem.startsWith(u8, arg, "--")) return error.UnknownOpNativeSelector;
            if (out.resources != null) return error.MultipleOpNativeResourceFiles;
            out.resources = arg;
        }
    }
    // Capture/prepare currently report classic upper-bound cells. Keep the
    // unqualified mode combination closed rather than silently mislabel costs.
    if (out.detached_sponge and (out.truth_local_gkr or out.miller_local_gkr)) return error.ConflictingOpNativeSourceRoute;
    if ((out.truth_local_gkr or out.miller_local_gkr or out.detached_sponge) and !std.mem.eql(u8, mode, "prove") and !std.mem.eql(u8, mode, "verify")) return error.UnsupportedOpNativeModeCombination;
    return out;
}
test "OP native CLI selector is explicit and classic stays the default" {
    try std.testing.expect(!(try parse(&.{ "native", "prove", "config", "out" })).truth_local_gkr);
    const flagged = try parse(&.{ "native", "verify", "config", "out", "caps", "--truth-local-gkr" });
    try std.testing.expect(flagged.truth_local_gkr and std.mem.eql(u8, flagged.resources.?, "caps"));
    try std.testing.expect((try parse(&.{ "native", "prove", "config", "out", "--truth-local-gkr", "caps" })).truth_local_gkr);
    try std.testing.expectError(error.UnsupportedOpNativeModeCombination, parse(&.{ "native", "capture", "config", "out", "--truth-local-gkr" }));
    try std.testing.expectError(error.UnsupportedOpNativeModeCombination, parse(&.{ "native", "prepare", "config", "out", "--truth-local-gkr" }));
    try std.testing.expectError(error.UnknownOpNativeSelector, parse(&.{ "native", "prove", "config", "out", "--r6" }));
    try std.testing.expectError(error.DuplicateOpNativeSelector, parse(&.{ "native", "prove", "config", "out", "--truth-local-gkr", "--truth-local-gkr" }));
    try std.testing.expectError(error.MultipleOpNativeResourceFiles, parse(&.{ "native", "prove", "config", "out", "caps0", "caps1" }));
}

test "OP native Miller suite selector is explicit and bounded" {
    const command = try parse(&.{ "native", "prove", "config", "out", "caps", "--truth-local-gkr", "--miller-local-gkr" });
    try std.testing.expect(command.truth_local_gkr and command.miller_local_gkr);
    try std.testing.expectError(error.DuplicateOpNativeSelector, parse(&.{ "native", "prove", "config", "out", "--miller-local-gkr", "--miller-local-gkr" }));
    try std.testing.expectError(error.UnsupportedOpNativeModeCombination, parse(&.{ "native", "prepare", "config", "out", "--miller-local-gkr" }));
}

test "OP detached native selector is explicit with no source family inference" {
    try std.testing.expect(!(try parse(&.{ "native", "prove", "cfg", "out" })).detached_sponge);
    const selected = try parse(&.{ "native", "verify", "cfg", "out", "caps", "--detached-sponge" });
    try std.testing.expect(selected.detached_sponge and !selected.truth_local_gkr and !selected.miller_local_gkr);
    try std.testing.expectEqualStrings("caps", selected.resources.?);
    try std.testing.expectError(error.DuplicateOpNativeSelector, parse(&.{ "native", "prove", "cfg", "out", "--detached-sponge", "--detached-sponge" }));
    for ([_][]const u8{ "--truth-local-gkr", "--miller-local-gkr" }) |other| try std.testing.expectError(error.ConflictingOpNativeSourceRoute, parse(&.{ "native", "verify", "cfg", "out", other, "--detached-sponge" }));
    for ([_][]const u8{ "capture", "prepare" }) |mode| try std.testing.expectError(error.UnsupportedOpNativeModeCombination, parse(&.{ "native", mode, "cfg", "out", "--detached-sponge" }));
}
