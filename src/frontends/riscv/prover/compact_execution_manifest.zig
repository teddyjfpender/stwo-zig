//! Caller-authenticated compact geometry plus native source/commitment admission.
//! The outer expected identity authenticates the geometry ID before it is used.
const std = @import("std");
const core = @import("stwo_core");
const base = @import("blake3_execution_manifest.zig");
const geometry = @import("../recursion/air/compact_range_geometry.zig");
const wire = @import("compact_range_codec.zig");
const contract = @import("compact_execution_contract.zig");
const Statement = @import("../air/statement.zig").Blake3ExecutionStatement;
const Admission = @import("blake3_commitment_plan.zig").Admission;
pub const MAGIC = "B3CRADM1";
pub const PREFIX_BYTES = 12 + 32 + wire.ENCODED_BYTES;
const Context = struct {
    ranges: geometry.Plan,
    pub fn validate(self: Context, shape: *const Statement) !void {
        try (contract.Contract{ .native = shape, .ranges = self.ranges }).validate(0);
    }
    pub fn mix(self: Context, _: std.mem.Allocator, channel: anytype, config: core.pcs.PcsConfig, shape: *const Statement, pin: Admission) !void {
        try (contract.Contract{ .native = shape, .ranges = self.ranges }).mix(channel, config, pin, 0);
    }
};
pub fn hasMagic(raw: []const u8) bool {
    return raw.len >= 8 and std.mem.eql(u8, raw[0..8], MAGIC);
}
pub fn encode(a: std.mem.Allocator, shape: *const Statement, pin: Admission, config: core.pcs.PcsConfig, source: base.Source, limits: base.Limits, ranges: geometry.Plan) ![]u8 {
    const encoded_ranges = try wire.encode(ranges);
    const id = try ranges.identity();
    const inner = try base.encodeWithContext(a, shape, pin, config, source, limits, Context{ .ranges = ranges });
    defer a.free(inner);
    const count = try std.math.add(usize, PREFIX_BYTES, inner.len);
    if (count > limits.max_bytes) return error.ExecutionManifestResourceLimit;
    const raw = try a.alloc(u8, count);
    @memcpy(raw[0..8], MAGIC);
    std.mem.writeInt(u32, raw[8..12], 1, .little);
    @memcpy(raw[12..44], &id);
    @memcpy(raw[44..PREFIX_BYTES], &encoded_ranges);
    @memcpy(raw[PREFIX_BYTES..], inner);
    return raw;
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: [32]u8, source: base.Source, config: core.pcs.PcsConfig, limits: base.Limits) !base.Owned {
    if (raw.len > limits.max_bytes) return error.ExecutionManifestResourceLimit;
    if (raw.len < PREFIX_BYTES + base.HEADER_BYTES) return error.TruncatedExecutionManifest;
    if (!hasMagic(raw) or std.mem.readInt(u32, raw[8..12], .little) != 1) return error.InvalidExecutionManifestVersion;
    if (!std.mem.eql(u8, &base.identity(raw), &expected)) return error.UntrustedExecutionManifest;
    const ranges = try wire.decode(raw[44..PREFIX_BYTES], raw[12..44].*);
    const inner = raw[PREFIX_BYTES..];
    var owned = try base.decodeWithContext(a, inner, base.identity(inner), source, config, limits, Context{ .ranges = ranges });
    owned.ranges = ranges;
    return owned;
}
