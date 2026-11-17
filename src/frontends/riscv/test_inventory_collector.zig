const std = @import("std");

// An import-only focused collector adds no assertion to the default suite when
// each subject is already collected there directly. Parse conservatively.
// Collectors live in `<package>/tests/focused/`; the inventory is the
// package's `tests/root.zig`, so a subject `../../air/x.zig` must appear there
// as `../air/x.zig` and a sibling suite `x.zig` as `focused/x.zig`.
pub fn coveredCollector(allocator: std.mem.Allocator, source: []const u8, inventory: []const u8) !bool {
    const text = try allocator.dupeZ(u8, source);
    defer allocator.free(text);
    var tokens = std.zig.Tokenizer.init(text);
    var first = tokens.next();
    while (first.tag == .doc_comment or first.tag == .container_doc_comment) first = tokens.next();
    if (first.tag != .keyword_test or tokens.next().tag != .l_brace) return false;
    var count: usize = 0;
    while (true) {
        const lhs = tokens.next();
        if (lhs.tag == .r_brace) return count != 0 and tokens.next().tag == .eof;
        if (lhs.tag != .identifier or !std.mem.eql(u8, text[lhs.loc.start..lhs.loc.end], "_") or tokens.next().tag != .equal) return false;
        const builtin = tokens.next();
        if (builtin.tag != .builtin or !std.mem.eql(u8, text[builtin.loc.start..builtin.loc.end], "@import") or tokens.next().tag != .l_paren) return false;
        const path = tokens.next();
        if (path.tag != .string_literal) return false;
        const literal = text[path.loc.start + 1 .. path.loc.end - 1];
        const parent = "../../";
        const in_package = std.mem.startsWith(u8, literal, parent);
        const subject = if (in_package) literal[parent.len..] else literal;
        if (!std.mem.endsWith(u8, subject, ".zig") or std.mem.indexOf(u8, subject, "..") != null or std.mem.indexOfScalar(u8, subject, '\\') != null or std.fs.path.isAbsolute(subject)) return false;
        var buffer: [512]u8 = undefined;
        const statement = (if (!in_package)
            std.fmt.bufPrint(&buffer, "_ = @import(\"focused/{s}\");", .{subject})
        else if (std.mem.startsWith(u8, subject, "tests/"))
            std.fmt.bufPrint(&buffer, "_ = @import(\"{s}\");", .{subject["tests/".len..]})
        else
            std.fmt.bufPrint(&buffer, "_ = @import(\"../{s}\");", .{subject})) catch return false;
        var lines = std.mem.tokenizeAny(u8, inventory, "\r\n");
        var covered = false;
        while (lines.next()) |line| covered = covered or std.mem.eql(u8, std.mem.trim(u8, line, " \t"), statement);
        if (!covered or tokens.next().tag != .r_paren or tokens.next().tag != .semicolon) return false;
        count += 1;
    }
}

test "test inventory: redundant collectors cannot hide assertions or absent subjects" {
    const allocator = std.testing.allocator;
    const source = "test { _ = @import(\"../../air/example.zig\"); }";
    const inventory = "    _ = @import(\"../air/example.zig\");";
    try std.testing.expect(try coveredCollector(allocator, source, inventory));
    try std.testing.expect(!try coveredCollector(allocator, source, "// " ++ inventory));
    try std.testing.expect(!try coveredCollector(allocator, source, ""));
    try std.testing.expect(!try coveredCollector(allocator, "test { _ = @import(\"../../air/example.zig\"); unreachable; }", inventory));
    try std.testing.expect(!try coveredCollector(allocator, "test { _ = @import(\"../outside.zig\"); }", inventory));
    try std.testing.expect(!try coveredCollector(allocator, "test { _ = @import(\"../../../outside.zig\"); }", inventory));
    try std.testing.expect(!try coveredCollector(allocator, "test { _ = @import(\"air/example.zig\"); }", inventory));
    try std.testing.expect(try coveredCollector(allocator, "test { _ = @import(\"sibling.zig\"); }", "_ = @import(\"focused/sibling.zig\");"));
    try std.testing.expect(try coveredCollector(allocator, "test { _ = @import(\"../../tests/shared.zig\"); }", "_ = @import(\"shared.zig\");"));
}
