//! Independent physical strict-RAM recursive verifier policy. No virtual
//! event log or received proof metadata selects masks, roots or security.
const std = @import("std");
const core = @import("stwo_core");
const Lane = @import("block_v5_ram_lanes_proof_v1.zig");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Spec = @import("block_v5_ram_lanes_component_v1.zig").Spec;
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { proof: Lane.Limits = .{}, max_capture_bytes: usize = 256 << 20, max_preparation_bytes: usize = 2 << 30 };
pub fn templateId(config: core.pcs.PcsConfig, row_log: u32) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354c4b, VERSION, row_log, Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT, Spec.CONSTRAINT_COUNT, Spec.DEGREE, Spec.EXPANSION_BITS }); // B5LK
    channel.mixRoot(Protocol.abiId());
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@embedFile("../air/block/word_memory_v5.zig"));
    hash.update(@embedFile("../air/block/word_memory_lanes_v1.zig"));
    hash.update(@embedFile("block_v5_ram_lanes_interaction_v1.zig"));
    hash.update(@embedFile("block_v5_ram_lanes_component_v1.zig"));
    hash.update(@embedFile("block_v5_word_quotient_adapter_v1.zig"));
    channel.mixRoot(hash.finalResult());
    config.mixInto(&channel);
    return channel.digestBytes();
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    pin: Lane.Pin,
    roots: [2][32]u8,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    template_id: [32]u8,
    logs: [3][]u32,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, pin: Lane.Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        var self = Prepared{ .allocator = a, .pin = pin, .roots = pin.roots, .sealed = sealed, .pins = pins, .entries = entries, .config = pins.config, .template_id = templateId(pins.config, pin.claim.row_log), .logs = undefined, .limits = limits };
        try self.validateAuthority(self.template_id);
        self.logs[0] = try a.alloc(u32, Spec.FIXED_COUNT);
        @memset(self.logs[0], pin.claim.row_log);
        errdefer a.free(self.logs[0]);
        self.logs[1] = try a.alloc(u32, Spec.MAIN_COUNT);
        @memset(self.logs[1], pin.claim.row_log);
        errdefer a.free(self.logs[1]);
        self.logs[2] = try a.alloc(u32, Spec.INTERACTION_COUNT);
        @memset(self.logs[2], pin.claim.row_log);
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority(expected);
        for (self.logs, [_]usize{ Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT }) |logs, width| {
            if (logs.len != width) return error.UntrustedRamRecursiveGeometry;
            for (logs) |log| if (log != self.pin.claim.row_log) return error.UntrustedRamRecursiveGeometry;
        }
    }
    fn validateAuthority(self: *const Prepared, expected: [32]u8) !void {
        try self.limits.proof.require(self.pin.claim);
        try Lane.admit(self.pin, self.sealed, self.pins, self.entries);
        if (!std.meta.eql(self.config, self.pin.config) or !std.meta.eql(self.config, self.pins.config) or
            !std.meta.eql(self.roots, self.pin.roots) or !std.meta.eql(self.template_id, expected) or
            !std.meta.eql(expected, templateId(self.config, self.pin.claim.row_log)) or
            self.pin.index >= core.fields.m31.Modulus or self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0)
            return error.UntrustedRamRecursiveAdmission;
    }
};
