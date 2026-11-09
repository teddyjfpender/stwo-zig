//! Explicit experimental root protocol selection. No bundle-selected fallback.
const std = @import("std");
pub const Command = struct {
    mode: enum { prove, verify },
    config: []const u8,
    source: []const u8,
    root: []const u8,
    resources: ?[]const u8,
    r6: bool,
    truth_local_gkr: bool,
};
/// Arguments exclude the executable name. Historical positional commands keep
/// their exact R5/classic selection; both new protocol choices are explicit.
pub fn parse(args: []const []const u8) !Command {
    var positional: [5][]const u8 = undefined;
    var count: usize = 0;
    var r6 = false;
    var local = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--r6")) {
            if (r6) return error.DuplicateOpRootOption;
            r6 = true;
        } else if (std.mem.eql(u8, arg, "--truth-local-gkr")) {
            if (local) return error.DuplicateOpRootOption;
            local = true;
        } else {
            if (std.mem.startsWith(u8, arg, "--")) return error.UnknownOpRootOption;
            if (count == positional.len) return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
            positional[count] = arg;
            count += 1;
        }
    }
    if (count < 4) return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
    const mode: @FieldType(Command, "mode") = if (std.mem.eql(u8, positional[0], "prove")) .prove else if (std.mem.eql(u8, positional[0], "verify")) .verify else return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
    if (local and !r6) return error.OpRootLocalGkrRequiresR6;
    return .{ .mode = mode, .config = positional[1], .source = positional[2], .root = positional[3], .resources = if (count == 5) positional[4] else null, .r6 = r6, .truth_local_gkr = local };
}
test "OP root CLI defaults preserve classic authority and require explicit R6 local admission" {
    const classic = try parse(&.{ "prove", "config.json", "native", "root" });
    try std.testing.expect(!classic.r6 and !classic.truth_local_gkr and classic.resources == null);
    const next = try parse(&.{ "--r6", "verify", "config.json", "native", "root", "resources.json", "--truth-local-gkr" });
    try std.testing.expect(next.mode == .verify and next.r6 and next.truth_local_gkr);
    try std.testing.expectEqualStrings("resources.json", next.resources.?);
    try std.testing.expectEqualStrings("config.json", next.config);
    try std.testing.expectEqualStrings("native", next.source);
    try std.testing.expectEqualStrings("root", next.root);
    try std.testing.expectError(error.OpRootLocalGkrRequiresR6, parse(&.{ "prove", "c", "s", "r", "--truth-local-gkr" }));
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&.{ "prove", "c", "s", "r", "--r6", "--r6" }));
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&.{ "verify", "c", "s", "r", "--r6", "--truth-local-gkr", "--truth-local-gkr" }));
    try std.testing.expectError(error.UnknownOpRootOption, parse(&.{ "prove", "c", "s", "r", "--r7" }));
    try std.testing.expectError(error.ExpectedOpRootModeConfigSourceAndRootDirectory, parse(&.{"verify"}));
    try std.testing.expectError(error.ExpectedOpRootModeConfigSourceAndRootDirectory, parse(&.{ "verify", "c", "s", "r", "resources", "extra" }));
}
