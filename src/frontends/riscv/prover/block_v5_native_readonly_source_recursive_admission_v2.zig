//! Genuine group/source admission. Borrows one independently admitted job
//! Authority; never clones/traverses the complete interval Plan per source.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_native_readonly_source_proof_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Original = @import("block_v5_readonly_input_proof_v1.zig");
pub const Limits = struct { max_capture_bytes: usize = 128 * 1024 * 1024, max_preparation_bytes: usize = 512 * 1024 * 1024, max_public_wires: usize = 1 << 20, proof: Original.Limits = .{} };
pub const Prepared = struct {
    a: std.mem.Allocator,
    authority: *const Roster.Authority,
    pin: Native.Pin,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    /// Compatibility with original field-safe source methods; no per-call seal
    /// rebuild uses these borrowed entries after the owned Authority admission.
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    roots: [2][32]u8,
    template_id: [32]u8,
    logs: [3][]u32,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, authority: *const Roster.Authority, ordinal: u32, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        if (limits.max_capture_bytes == 0 or limits.max_preparation_bytes == 0 or limits.max_public_wires == 0) return error.InvalidNativeReadonlyV2RecursiveLimits;
        const pin = try Native.Pin.fromAuthority(authority, ordinal, authority.config(), limits.proof);
        try pin.require(authority, sealed, pins, entries);
        var logs: [3][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |values| a.free(values);
        for ([_]usize{ 1, 103, 20 }, &logs) |count, *values| {
            values.* = try a.alloc(u32, count);
            @memset(values.*, pin.classifier.row_log);
            initialized += 1;
        }
        return .{ .a = a, .authority = authority, .pin = pin, .sealed = sealed, .pins = pins, .entries = entries, .config = authority.config(), .roots = pin.classifier.roots, .template_id = templateId(pin), .logs = logs, .limits = limits };
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |values| self.a.free(values);
        self.* = undefined;
    }
    pub fn validateAuthority(self: *const Prepared) !void {
        try self.pin.require(self.authority, self.sealed, self.pins, self.entries);
        if (!std.meta.eql(self.config, self.authority.config()) or !std.meta.eql(self.roots, self.pin.classifier.roots) or !std.meta.eql(self.template_id, templateId(self.pin))) return error.StaleNativeReadonlyV2RecursiveAdmission;
        for (self.logs, [_]usize{ 1, 103, 20 }) |values, count| {
            if (values.len != count) return error.StaleNativeReadonlyV2RecursiveAdmission;
            for (values) |log| if (log != self.pin.classifier.row_log) return error.StaleNativeReadonlyV2RecursiveAdmission;
        }
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority();
        if (!std.meta.eql(expected, self.template_id)) return error.StaleNativeReadonlyV2RecursiveTemplate;
    }
};
fn recipe() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/native-readonly-source/recursive/v2\x00");
    hash.update(@embedFile("block_v5_native_readonly_source_proof_v2.zig"));
    hash.update(@embedFile("block_v5_readonly_input_component_v1.zig"));
    hash.update("original205/fixed1/main103/inter20;shared54/unshifted-public-draws/group-shift-graph;compactclaims5;provider+source-joins-open\x00");
    return hash.finalResult();
}
fn templateId(pin: Native.Pin) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixRoot(@import("../recursion/source_authority_cache_v1.zig").For(recipe).get());
    channel.mixU32s(&.{ Native.TAG, Native.VERSION, pin.classifier.events, pin.classifier.row_log });
    pin.classifier.config.mixInto(&channel);
    return channel.digestBytes();
}
