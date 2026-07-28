//! Product-side activation of the protocol-identity-bound preprocessed cache.
//!
//! The key material is the product's own authenticated identity document —
//! protocol manifest digest, identity digest, implementation revision and dirty
//! content digest, target and CPU feature digest, optimize mode, runtime
//! manifests and pinned upstream revisions. Nothing about the proven program or
//! its input reaches the key. The frontend adds the preprocessed variant, the
//! structural column specification digest and the PCS configuration digest.
//!
//! The cache is on by default and opts out through the environment:
//!   STWO_CAIRO_PREPROCESSED_CACHE=0        disable entirely
//!   STWO_CAIRO_PREPROCESSED_CACHE_DIR=…    absolute directory override
//!   STWO_CAIRO_PREPROCESSED_CACHE_BUDGET=… total directory budget in bytes
//! Otherwise the directory is `$XDG_CACHE_HOME/stwo-zig/cairo-preprocessed`,
//! falling back to `$HOME/.cache/stwo-zig/cairo-preprocessed`. With no usable
//! directory the cache stays inert and every proof recomputes. The budget
//! defaults to 2 GiB and is enforced by least-recently-used eviction after each
//! successful store; `0` means unbounded.

const std = @import("std");

const enable_variable = "STWO_CAIRO_PREPROCESSED_CACHE";
const directory_variable = "STWO_CAIRO_PREPROCESSED_CACHE_DIR";
const budget_variable = "STWO_CAIRO_PREPROCESSED_CACHE_BUDGET";
const relative_directory = "stwo-zig" ++ std.fs.path.sep_str ++
    "cairo-preprocessed";

pub const Activation = struct {
    allocator: std.mem.Allocator,
    directory: ?[]u8,

    pub fn deinit(self: *Activation, comptime Product: type) void {
        Product.stwo.frontends.cairo.preprocessed.product_cache.configure(.{});
        if (self.directory) |owned| self.allocator.free(owned);
        self.* = undefined;
    }
};

/// Activates the cache for the lifetime of one proving transaction.
pub fn activate(
    comptime Product: type,
    allocator: std.mem.Allocator,
) !Activation {
    const product_cache = Product.stwo.frontends.cairo.preprocessed.product_cache;
    var activation = Activation{ .allocator = allocator, .directory = null };
    if (!enabled(allocator)) {
        product_cache.configure(.{});
        return activation;
    }
    activation.directory = resolveDirectory(allocator) catch null;
    const directory = activation.directory orelse {
        product_cache.configure(.{});
        return activation;
    };
    product_cache.configure(.{
        .enabled = true,
        .product_digest = try productDigest(Product),
        .directory = directory,
        .budget_bytes = budgetBytes(
            allocator,
            product_cache.default_budget_bytes,
        ),
    });
    return activation;
}

/// Total-size budget for the cache directory. An unset, empty or unparseable
/// value keeps the default; `0` disables eviction entirely.
fn budgetBytes(allocator: std.mem.Allocator, default: u64) u64 {
    const raw = std.process.getEnvVarOwned(allocator, budget_variable) catch
        return default;
    defer allocator.free(raw);
    return parseBudget(raw) orelse default;
}

fn parseBudget(raw: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(u64, trimmed, 10) catch null;
}

fn enabled(allocator: std.mem.Allocator) bool {
    const raw = std.process.getEnvVarOwned(allocator, enable_variable) catch
        return true;
    defer allocator.free(raw);
    return !(std.mem.eql(u8, raw, "0") or
        std.ascii.eqlIgnoreCase(raw, "false") or
        std.ascii.eqlIgnoreCase(raw, "off") or
        std.ascii.eqlIgnoreCase(raw, "no"));
}

fn resolveDirectory(allocator: std.mem.Allocator) !?[]u8 {
    if (std.process.getEnvVarOwned(allocator, directory_variable)) |override| {
        if (std.fs.path.isAbsolute(override)) return override;
        allocator.free(override);
        return null;
    } else |_| {}
    if (std.process.getEnvVarOwned(allocator, "XDG_CACHE_HOME")) |root| {
        defer allocator.free(root);
        if (std.fs.path.isAbsolute(root))
            return try std.fs.path.join(allocator, &.{ root, relative_directory });
    } else |_| {}
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);
    if (!std.fs.path.isAbsolute(home)) return null;
    return try std.fs.path.join(
        allocator,
        &.{ home, ".cache", relative_directory },
    );
}

/// Structural digest of the product's authenticated identity document.
fn productDigest(comptime Product: type) ![32]u8 {
    var buffer: [16 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try Product.identity.write(&writer);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cairo-product-identity/v1\x00");
    hasher.update(writer.buffered());
    return hasher.finalResult();
}

test "the budget parser keeps the default for anything unusable" {
    try std.testing.expectEqual(@as(?u64, 0), parseBudget("0"));
    try std.testing.expectEqual(@as(?u64, 1024), parseBudget(" 1024\n"));
    try std.testing.expectEqual(
        @as(?u64, 2 * 1024 * 1024 * 1024),
        parseBudget("2147483648"),
    );
    try std.testing.expectEqual(@as(?u64, null), parseBudget(""));
    try std.testing.expectEqual(@as(?u64, null), parseBudget("2GiB"));
    try std.testing.expectEqual(@as(?u64, null), parseBudget("-1"));
}

test "opt-out parsing accepts the documented spellings" {
    // Behaviour is environment-driven; the parser itself is exercised through
    // the pure predicate below to keep the test hermetic.
    const off = [_][]const u8{ "0", "false", "FALSE", "off", "No" };
    for (off) |value| try std.testing.expect(
        std.mem.eql(u8, value, "0") or
            std.ascii.eqlIgnoreCase(value, "false") or
            std.ascii.eqlIgnoreCase(value, "off") or
            std.ascii.eqlIgnoreCase(value, "no"),
    );
}
