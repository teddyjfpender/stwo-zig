//! Independent range16 recursive policy. Layout/domain/security are fixed by
//! the actual provider ABI; first roots and exact shard come from trusted plans.
const std = @import("std");
const core = @import("stwo_core");
const Range = @import("block_v5_range16_v1.zig");
const Native = @import("block_v5_range16_proof_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { max_capture_bytes: usize = 128 << 20, max_preparation_bytes: usize = 512 << 20 };
pub fn templateId(config: core.pcs.PcsConfig, fixed_root: [32]u8) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x4235524b, VERSION, Range.TABLE_LOG, 1, 1, 8, 2, 2, 1 }); // B5RK
    channel.mixRoot(Word.abiId());
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@embedFile("block_v5_range16_algebra_v1.zig"));
    hash.update(@embedFile("block_v5_range16_component_v1.zig"));
    hash.update(@embedFile("block_v5_word_quotient_adapter_v1.zig"));
    channel.mixRoot(hash.finalResult());
    channel.mixRoot(fixed_root);
    config.mixInto(&channel);
    return channel.digestBytes();
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    shard: Range.Shard,
    plan_digest: [32]u8,
    roots: [2][32]u8,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    template_id: [32]u8,
    logs: [3][]u32,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, shard: Range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        var self = Prepared{ .allocator = a, .shard = shard, .plan_digest = plan_digest, .roots = roots, .sealed = sealed, .pins = pins, .entries = entries, .config = pins.config, .template_id = templateId(pins.config, roots[0]), .logs = undefined, .limits = limits };
        try self.validateAuthority(self.template_id);
        self.logs[0] = try a.dupe(u32, &.{Range.TABLE_LOG});
        errdefer a.free(self.logs[0]);
        self.logs[1] = try a.dupe(u32, &.{Range.TABLE_LOG});
        errdefer a.free(self.logs[1]);
        self.logs[2] = try a.dupe(u32, &([_]u32{Range.TABLE_LOG} ** 8));
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority(expected);
        for (self.logs, [_]usize{ 1, 1, 8 }) |logs, width| {
            if (logs.len != width) return error.UntrustedRangeRecursiveGeometry;
            for (logs) |log| if (log != Range.TABLE_LOG) return error.UntrustedRangeRecursiveGeometry;
        }
    }
    fn validateAuthority(self: *const Prepared, expected: [32]u8) !void {
        try Native.admit(self.shard, self.plan_digest, self.roots, self.sealed, self.pins, self.entries);
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        if (!std.meta.eql(self.config, self.pins.config) or !std.meta.eql(self.template_id, expected) or
            !std.meta.eql(expected, templateId(self.config, self.roots[0])) or
            self.shard.index >= self.pins.counts[@intFromEnum(Seal.Family.memory_range) - 1] or
            self.shard.index >= core.fields.m31.Modulus or self.shard.first_instance >= core.fields.m31.Modulus or
            self.shard.instance_count >= core.fields.m31.Modulus or
            try std.math.add(u32, self.shard.first_instance, self.shard.instance_count) > self.sealed.memory_instance_count or
            std.mem.allEqual(u8, &self.plan_digest, 0) or self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0)
            return error.UntrustedRangeRecursiveAdmission;
        for (self.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedRangeRecursiveAdmission;
    }
};
