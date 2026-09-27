//! Independently pinned ordered B5CT capacity roster. This distinct catalog
//! binds reusable capacities, not proof-selected keys or logical row counts.
const std = @import("std");
const core = @import("stwo_core");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const TAG: u32 = 0x42354343; // B5CC; never the exact-row B5NC catalog.
pub const VERSION: u32 = 1;
pub const Record = struct {
    index: u32,
    template_id: Protocol.Digest,
    capacity_digest: Protocol.Digest,
    fixed_root: Protocol.Digest,

    pub fn fromTemplate(index: u32, template: Protocol.Template) !Record {
        return .{ .index = index, .template_id = try template.identity(), .capacity_digest = template.capacity_digest, .fixed_root = template.fixed_root };
    }
};
pub const Limits = struct {
    max_records: usize = 1 << 16,
    max_metadata_bytes: usize = 16 << 20,
    pub fn require(self: Limits, count: usize) !void {
        if (self.max_records == 0 or self.max_records > std.math.maxInt(u32) or count == 0 or count > self.max_records or
            try std.math.mul(usize, count, @sizeOf(Record)) > self.max_metadata_bytes) return error.NativeCapacityCatalogResourceLimit;
    }
};
pub const Admission = struct {
    records: []const Record,
    limits: Limits = .{},

    pub fn digest(self: Admission) !Protocol.Digest {
        try self.limits.require(self.records.len);
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ TAG, VERSION, @intCast(self.records.len) });
        for (self.records, 0..) |record, index| {
            if (record.index != index or zero(record.template_id) or zero(record.capacity_digest) or zero(record.fixed_root)) return error.InvalidNativeCapacityCatalog;
            channel.mixU32s(&.{record.index});
            channel.mixRoot(record.template_id);
            channel.mixRoot(record.capacity_digest);
            channel.mixRoot(record.fixed_root);
        }
        return channel.digestBytes();
    }
    pub fn admit(self: Admission, pins: Seal.Pins, sealed: Seal.Sealed, index: u32, template: Protocol.Template, template_id: Protocol.Digest) !void {
        if (!zero(pins.native_template_id) or zero(pins.native_template_catalog_digest) or
            self.records.len != sealed.execution_instance_count or index >= self.records.len or
            !std.meta.eql(try self.digest(), pins.native_template_catalog_digest) or
            !std.meta.eql(sealed.native_template_catalog_digest, pins.native_template_catalog_digest) or
            !std.meta.eql(template.config, pins.config)) return error.UntrustedNativeCapacityCatalog;
        const expected = try Record.fromTemplate(index, template);
        if (!std.meta.eql(expected, self.records[index]) or !std.meta.eql(template_id, expected.template_id)) return error.UntrustedNativeCapacityCatalog;
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    records: []Record,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, records: []const Record, limits: Limits) !Owned {
        _ = try (Admission{ .records = records, .limits = limits }).digest();
        return .{ .allocator = a, .records = try a.dupe(Record, records), .limits = limits };
    }
    pub fn admission(self: *const Owned) Admission {
        return .{ .records = self.records, .limits = self.limits };
    }
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.records);
        self.records = &.{};
    }
};
fn zero(value: Protocol.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}
