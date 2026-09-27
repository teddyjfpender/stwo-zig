//! Typed proof transport. Expected scope comes from the admitted roster; this
//! module always invokes the real pair verifier and never accepts Open receipts.
const std = @import("std");
const Files = @import("block_v5_readonly_provider_files_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Join = @import("block_v5_readonly_input_global_join_v2.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
pub const Loader = struct {
    context: *anyopaque,
    count: usize,
    limits: Table.Limits = .{},
    take_pair: *const fn (*anyopaque, std.mem.Allocator, *const Roster.Authority, Seal.Sealed, u32) anyerror!Files.Loaded,
    pub fn require(self: Loader, authority: *const Roster.Authority) !void {
        if (self.count != authority.providers().len) return error.IncompleteGlobalReadonlyProviderFiles;
    }
};
pub fn require(loader: ?Loader, authority: *const Roster.Authority) !void {
    if (loader) |actual| try actual.require(authority) else if (authority.providers().len != 0) return error.MissingGlobalReadonlyProviderLoader;
}
pub fn verifyAll(comptime Backend: type, a: std.mem.Allocator, loader: ?Loader, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, joined: *Join.Owned) !void {
    try require(loader, authority);
    try authority.requireEpoch(sealed);
    if (joined.authority != authority or !std.meta.eql(joined.sealed, sealed)) return error.UntrustedGlobalReadonlyJoinSession;
    const actual = loader orelse return;
    for (authority.providers(), 0..) |_, index| {
        var loaded = try actual.take_pair(actual.context, a, authority, sealed, @intCast(index));
        defer loaded.deinit();
        const expected = try Files.Expected.fromAuthority(authority, @intCast(index), sealed);
        if (loaded.authority != authority or !std.meta.eql(loaded.sealed, sealed) or !std.meta.eql(loaded.expected, expected) or !loaded.proofs_live) return error.UntrustedGlobalReadonlyProviderFileScope;
        // Both original proofs are consumed on success AND verifier failure.
        // Transport scope/SHA alone never reaches joined.provider.
        const fresh = try loaded.verifyPair(Backend, pins, entries, actual.limits);
        try joined.provider(fresh);
    }
}
/// Independently expected ordinal vector and original decoder admission remain
/// in Files.load; only filenames/SHA/lengths are transported by this borrowed view.
pub const Directory = struct {
    dir: std.fs.Dir,
    files: []const Files.FileSet,
    limits: Files.Limits = .{},
    provider_limits: Table.Limits = .{},
    pub fn loader(self: *Directory) Loader {
        return .{ .context = self, .count = self.files.len, .limits = self.provider_limits, .take_pair = take };
    }
    fn take(raw: *anyopaque, a: std.mem.Allocator, authority: *const Roster.Authority, sealed: Seal.Sealed, index: u32) !Files.Loaded {
        const self: *const Directory = @ptrCast(@alignCast(raw));
        if (index >= self.files.len) return error.IncompleteGlobalReadonlyProviderFiles;
        const expected = try Files.Expected.fromAuthority(authority, index, sealed);
        return Files.load(a, self.dir, expected, authority, sealed, self.files[index], self.limits);
    }
};
