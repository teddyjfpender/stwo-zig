//! Explicit experimental root protocol selection. No bundle-selected fallback.
const std = @import("std");
pub const Command = struct {
    mode: enum { prove, verify },
    config: []const u8,
    source: []const u8,
    root: []const u8,
    resources: ?[]const u8,
    r6: bool,
    r7: bool = false,
    truth_local_gkr: bool,
    miller_local_gkr: bool,
    miller_cache_bytes: usize = 0,
    miller_prover_cache_bytes: usize = 0,
};
/// Arguments exclude the executable name. Historical positional commands keep
/// their exact R5/classic selection; every new protocol choice is explicit.
pub fn parse(args: []const []const u8) !Command {
    var positional: [5][]const u8 = undefined;
    var count: usize = 0;
    var r6 = false;
    var r7 = false;
    var local = false;
    var miller = false;
    var cache_bytes: ?usize = null;
    var prover_cache_bytes: ?usize = null;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--r6")) {
            if (r6) return error.DuplicateOpRootOption;
            r6 = true;
        } else if (std.mem.eql(u8, arg, "--r7")) {
            if (r7) return error.DuplicateOpRootOption;
            r7 = true;
        } else if (std.mem.eql(u8, arg, "--truth-local-gkr")) {
            if (local) return error.DuplicateOpRootOption;
            local = true;
        } else if (std.mem.eql(u8, arg, "--miller-local-gkr")) {
            if (miller) return error.DuplicateOpRootOption;
            miller = true;
        } else if (std.mem.startsWith(u8, arg, "--miller-cache-mib=")) {
            if (cache_bytes != null) return error.DuplicateOpRootOption;
            cache_bytes = try cacheBytes(arg["--miller-cache-mib=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--miller-prover-cache-mib=")) {
            if (prover_cache_bytes != null) return error.DuplicateOpRootOption;
            prover_cache_bytes = try cacheBytes(arg["--miller-prover-cache-mib=".len..]);
        } else {
            if (std.mem.startsWith(u8, arg, "--")) return error.UnknownOpRootOption;
            if (count == positional.len) return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
            positional[count] = arg;
            count += 1;
        }
    }
    if (count < 4) return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
    const mode: @FieldType(Command, "mode") = if (std.mem.eql(u8, positional[0], "prove")) .prove else if (std.mem.eql(u8, positional[0], "verify")) .verify else return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
    if (r6 and r7) return error.ConflictingOpRootProtocol;
    if (r7 and (cache_bytes != null or prover_cache_bytes != null)) return error.OpRootR7CacheUnsupported;
    if ((local or miller) and !r6 and !r7) return error.OpRootLocalGkrRequiresR6;
    if (cache_bytes != null and prover_cache_bytes != null) return error.ConflictingOpRootCacheModes;
    if (cache_bytes != null and (mode != .verify or !r6 or !miller)) return error.OpRootMillerCacheRequiresLocalVerification;
    if (prover_cache_bytes != null and (mode != .prove or !r6 or !miller)) return error.OpRootMillerCacheRequiresLocalProving;
    return .{ .mode = mode, .config = positional[1], .source = positional[2], .root = positional[3], .resources = if (count == 5) positional[4] else null, .r6 = r6, .r7 = r7, .truth_local_gkr = local, .miller_local_gkr = miller, .miller_cache_bytes = cache_bytes orelse 0, .miller_prover_cache_bytes = prover_cache_bytes orelse 0 };
}
fn cacheBytes(value: []const u8) !usize {
    if (value.len == 0) return error.InvalidOpRootMillerCache;
    for (value) |digit| if (digit < '0' or digit > '9') return error.InvalidOpRootMillerCache;
    const mib = std.fmt.parseInt(usize, value, 10) catch return error.InvalidOpRootMillerCache;
    if (mib > 8192) return error.InvalidOpRootMillerCache;
    return mib * (1 << 20);
}
test "OP root CLI defaults preserve classic authority and require explicit R6 local admission" {
    const classic = try parse(&.{ "prove", "config.json", "native", "root" });
    try std.testing.expect(!classic.r6 and !classic.truth_local_gkr and !classic.miller_local_gkr and classic.resources == null);
    const next = try parse(&.{ "--r6", "verify", "config.json", "native", "root", "resources.json", "--truth-local-gkr" });
    try std.testing.expect(next.mode == .verify and next.r6 and next.truth_local_gkr);
    try std.testing.expectEqualStrings("resources.json", next.resources.?);
    try std.testing.expectEqualStrings("config.json", next.config);
    try std.testing.expectEqualStrings("native", next.source);
    try std.testing.expectEqualStrings("root", next.root);
    try std.testing.expectError(error.OpRootLocalGkrRequiresR6, parse(&.{ "prove", "c", "s", "r", "--truth-local-gkr" }));
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&.{ "prove", "c", "s", "r", "--r6", "--r6" }));
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&.{ "verify", "c", "s", "r", "--r6", "--truth-local-gkr", "--truth-local-gkr" }));
    try std.testing.expectError(error.UnknownOpRootOption, parse(&.{ "prove", "c", "s", "r", "--r8" }));
    try std.testing.expectError(error.ExpectedOpRootModeConfigSourceAndRootDirectory, parse(&.{"verify"}));
    try std.testing.expectError(error.ExpectedOpRootModeConfigSourceAndRootDirectory, parse(&.{ "verify", "c", "s", "r", "resources", "extra" }));
}

test "OP root CLI Miller suite requires R6 and keeps truth mode independent" {
    const mixed = try parse(&.{ "--r6", "--miller-local-gkr", "prove", "c", "s", "r" });
    try std.testing.expect(mixed.r6 and mixed.miller_local_gkr and !mixed.truth_local_gkr);
    const both = try parse(&.{ "--r6", "--miller-local-gkr", "--truth-local-gkr", "verify", "c", "s", "r", "resources" });
    try std.testing.expect(both.miller_local_gkr and both.truth_local_gkr);
    try std.testing.expectEqualStrings("resources", both.resources.?);
    try std.testing.expectError(error.OpRootLocalGkrRequiresR6, parse(&.{ "--miller-local-gkr", "verify", "c", "s", "r" }));
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&.{ "--r6", "--miller-local-gkr", "--miller-local-gkr", "prove", "c", "s", "r" }));
}

test "OP root CLI bounded Miller cache is an explicit verifier-only resource choice" {
    const prefix = .{ "--r6", "--miller-local-gkr", "verify", "c", "s", "r" };
    try std.testing.expectEqual(@as(usize, 0), (try parse(&prefix)).miller_cache_bytes);
    try std.testing.expectEqual(@as(usize, 1 << 30), (try parse(&(prefix ++ .{"--miller-cache-mib=1024"}))).miller_cache_bytes);
    try std.testing.expectEqual(@as(usize, 8 << 30), (try parse(&(prefix ++ .{"--miller-cache-mib=8192"}))).miller_cache_bytes);
    try std.testing.expectEqual(@as(usize, 0), (try parse(&(prefix ++ .{"--miller-cache-mib=0"}))).miller_cache_bytes);
    inline for (.{ "", "-1", "+1", "1.5", "8193", "0x10", "184467440737095516160" }) |bad| {
        try std.testing.expectError(error.InvalidOpRootMillerCache, parse(&(prefix ++ .{"--miller-cache-mib=" ++ bad})));
    }
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&(prefix ++ .{ "--miller-cache-mib=0", "--miller-cache-mib=0" })));
    try std.testing.expectError(error.OpRootMillerCacheRequiresLocalVerification, parse(&.{ "--r6", "--miller-local-gkr", "prove", "c", "s", "r", "--miller-cache-mib=1024" }));
    try std.testing.expectError(error.OpRootMillerCacheRequiresLocalVerification, parse(&.{ "--r6", "verify", "c", "s", "r", "--miller-cache-mib=1024" }));
}

test "OP root CLI producer cache is independently bounded and cannot select verification policy" {
    const prefix = .{ "--r6", "--miller-local-gkr", "prove", "c", "s", "r" };
    const selected = try parse(&(prefix ++ .{"--miller-prover-cache-mib=1024"}));
    try std.testing.expectEqual(@as(usize, 1 << 30), selected.miller_prover_cache_bytes);
    try std.testing.expectEqual(@as(usize, 0), selected.miller_cache_bytes);
    try std.testing.expectEqual(@as(usize, 0), (try parse(&prefix)).miller_prover_cache_bytes);
    try std.testing.expectError(error.InvalidOpRootMillerCache, parse(&(prefix ++ .{"--miller-prover-cache-mib=8193"})));
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&(prefix ++ .{ "--miller-prover-cache-mib=1", "--miller-prover-cache-mib=2" })));
    try std.testing.expectError(error.ConflictingOpRootCacheModes, parse(&(prefix ++ .{ "--miller-prover-cache-mib=0", "--miller-cache-mib=0" })));
    try std.testing.expectError(error.OpRootMillerCacheRequiresLocalProving, parse(&.{ "--r6", "--miller-local-gkr", "verify", "c", "s", "r", "--miller-prover-cache-mib=1" }));
    try std.testing.expectError(error.OpRootMillerCacheRequiresLocalProving, parse(&.{ "--r6", "prove", "c", "s", "r", "--miller-prover-cache-mib=1" }));
}

test "OP root CLI R7 is explicit and cannot override R6 or cache policy" {
    const old = try parse(&.{ "verify", "c", "s", "r" });
    try std.testing.expect(!old.r6 and !old.r7);
    const r7 = try parse(&.{ "--r7", "verify", "c", "s", "r" });
    try std.testing.expect(r7.r7 and !r7.r6);
    const local = try parse(&.{ "--r7", "--truth-local-gkr", "--miller-local-gkr", "prove", "c", "s", "r" });
    try std.testing.expect(local.r7 and local.truth_local_gkr and local.miller_local_gkr);
    try std.testing.expectError(error.ConflictingOpRootProtocol, parse(&.{ "--r6", "--r7", "verify", "c", "s", "r" }));
    try std.testing.expectError(error.DuplicateOpRootOption, parse(&.{ "--r7", "--r7", "verify", "c", "s", "r" }));
    try std.testing.expectError(error.OpRootR7CacheUnsupported, parse(&.{ "--r7", "--miller-local-gkr", "--miller-cache-mib=1", "verify", "c", "s", "r" }));
}
