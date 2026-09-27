//! Actual external RangePin authority, no fabricated memory_range entries.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v5_range16_recursive_admission_v1.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Range = @import("block_v5_range16_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 2;
pub const Limits = Original.Limits;
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    authority: *const Roster.Authority,
    pin: Roster.RangePin,
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
    pub fn init(a: std.mem.Allocator, authority: *const Roster.Authority, index: u32, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        const pin = try authority.range(index);
        var self = Prepared{ .allocator = a, .authority = authority, .pin = pin, .shard = pin.shard, .plan_digest = pin.plan_digest, .roots = pin.roots, .sealed = sealed, .pins = pins, .entries = entries, .config = authority.config(), .template_id = Original.templateId(authority.config(), pin.roots[0]), .logs = undefined, .limits = limits };
        try self.validateAuthority(self.template_id);
        var initialized: usize = 0;
        errdefer for (self.logs[0..initialized]) |values| a.free(values);
        for ([_]usize{ 1, 1, 8 }, &self.logs) |width, *values| {
            values.* = try a.alloc(u32, width);
            @memset(values.*, Range.TABLE_LOG);
            initialized += 1;
        }
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |values| self.allocator.free(values);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority(expected);
        for (self.logs, [_]usize{ 1, 1, 8 }) |values, width| {
            if (values.len != width) return error.StaleReadonlyRangeRecursiveGeometry;
            for (values) |log| if (log != Range.TABLE_LOG) return error.StaleReadonlyRangeRecursiveGeometry;
        }
    }
    fn validateAuthority(self: *const Prepared, expected: [32]u8) !void {
        try (Provider.RangeAdmission{ .authority = self.authority, .pin = self.pin }).require(self.shard, self.plan_digest, self.roots, self.sealed, self.pins, self.entries);
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        const provider = try self.authority.provider(self.pin.provider_index);
        if (!std.meta.eql(self.config, self.authority.config()) or self.pin.group_id != provider.shape.group_id or provider.range_index != self.pin.index or
            self.shard.request_count != provider.shape.counts.range_requests or self.shard.instance_count != 1 or self.shard.first_instance != self.pin.provider_index or
            !std.meta.eql(self.template_id, expected) or !std.meta.eql(expected, Original.templateId(self.config, self.roots[0])) or
            self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0) return error.StaleReadonlyRangeRecursiveAdmission;
    }
};
