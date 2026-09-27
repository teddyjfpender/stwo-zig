//! Independently owned roster/Plan authority supplies every fragment ordinal
//! and geometry; no received proof or private witness chooses provider setup.
const std = @import("std");
const core = @import("stwo_core");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Limits = struct { max_capture_bytes: usize = 128 * 1024 * 1024, max_preparation_bytes: usize = 512 * 1024 * 1024, max_public_wires: usize = 1 << 20, table: Table.Limits = .{} };
pub const Prepared = struct {
    a: std.mem.Allocator,
    authority: *const Roster.Authority,
    pin: Provider.Pin,
    ordinals: []u32,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    roots: [2][32]u8,
    template_id: [32]u8,
    logs: [3][]u32,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, authority: *const Roster.Authority, index: u32, ordinals: []const u32, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        if (limits.max_capture_bytes == 0 or limits.max_preparation_bytes == 0 or limits.max_public_wires == 0) return error.InvalidReadonlyProviderRecursiveLimits;
        const pin = try authority.provider(index);
        try Provider.require(authority, pin, sealed, pins, entries);
        if (!std.meta.eql(try Table.ordinalDigest(pin.shape, pin.plan_digest, ordinals), pin.ordinal_digest)) return error.UntrustedReadonlyProviderOrdinals;
        for (ordinals, 0..) |ordinal, i| if (ordinal >= authority.intervals().len or (i != 0 and ordinal < ordinals[i - 1])) return error.UntrustedReadonlyProviderOrdinals;
        const copied = try a.dupe(u32, ordinals);
        errdefer a.free(copied);
        var logs: [3][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |values| a.free(values);
        for ([_]usize{ 10, 18, 44 }, &logs) |count, *values| {
            values.* = try a.alloc(u32, count);
            @memset(values.*, pin.shape.row_log);
            initialized += 1;
        }
        return .{ .a = a, .authority = authority, .pin = pin, .ordinals = copied, .sealed = sealed, .pins = pins, .entries = entries, .config = authority.config(), .roots = pin.roots, .template_id = templateId(pin), .logs = logs, .limits = limits };
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |values| self.a.free(values);
        self.a.free(self.ordinals);
        self.* = undefined;
    }
    pub fn validateAuthority(self: *const Prepared) !void {
        try Provider.require(self.authority, self.pin, self.sealed, self.pins, self.entries);
        if (!std.meta.eql(self.config, self.authority.config()) or !std.meta.eql(self.roots, self.pin.roots) or !std.meta.eql(self.template_id, templateId(self.pin)) or
            !std.meta.eql(try Table.ordinalDigest(self.pin.shape, self.pin.plan_digest, self.ordinals), self.pin.ordinal_digest)) return error.StaleReadonlyProviderRecursiveAdmission;
        for (self.logs, [_]usize{ 10, 18, 44 }) |values, count| {
            if (values.len != count) return error.StaleReadonlyProviderRecursiveAdmission;
            for (values) |log| if (log != self.pin.shape.row_log) return error.StaleReadonlyProviderRecursiveAdmission;
        }
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority();
        if (!std.meta.eql(expected, self.template_id)) return error.StaleReadonlyProviderRecursiveTemplate;
    }
};
fn recipe() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/readonly-provider/recursive/v2\x00");
    hash.update(@embedFile("block_v5_readonly_input_provider_proof_v2.zig"));
    hash.update(@embedFile("block_v5_readonly_input_provider_component_v2.zig"));
    hash.update("original48/fixed10/main18/inter44;shared54/group-shift/11claims/8integerlimbs;range+source-joins-open\x00");
    return hash.finalResult();
}
fn templateId(pin: Provider.Pin) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixRoot(@import("../recursion/source_authority_cache_v1.zig").For(recipe).get());
    channel.mixU32s(&.{ Provider.TAG, Provider.VERSION, pin.shape.fragment_count, pin.shape.row_log });
    pin.config.mixInto(&channel);
    return channel.digestBytes();
}
