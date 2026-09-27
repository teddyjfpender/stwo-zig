//! Independently admitted, ordered native-template roster for blocks whose
//! execution leaves have different exact row geometries. This commits to
//! each leaf's fixed root and template identity before B5SS is sealed.
const std = @import("std");
const core = @import("stwo_core");
const template_mod = @import("block_v5_native_template_protocol.zig");
const seal_mod = @import("block_v5_source_seal_v1.zig");

pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42354e43; // B5NC
pub const Digest = [32]u8;

pub const Record = struct {
    index: u32,
    template_id: Digest,
    geometry_digest: Digest,
    fixed_root: Digest,
};

pub const Admission = struct {
    /// These records come from trusted policy or a separately hash-pinned
    /// candidate roster. Proof bytes never select an entry or its key.
    records: []const Record,

    pub fn digest(self: Admission) !Digest {
        if (self.records.len == 0 or self.records.len > std.math.maxInt(u32))
            return error.InvalidNativeV5TemplateCatalog;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ TAG, VERSION, @intCast(self.records.len) });
        for (self.records, 0..) |record, index| {
            if (@as(usize, record.index) != index or zero(record.template_id) or
                zero(record.geometry_digest) or zero(record.fixed_root))
                return error.InvalidNativeV5TemplateCatalog;
            channel.mixU32s(&.{record.index});
            channel.mixRoot(record.template_id);
            channel.mixRoot(record.geometry_digest);
            channel.mixRoot(record.fixed_root);
        }
        return channel.digestBytes();
    }

    pub fn admit(self: Admission, pins: seal_mod.Pins, sealed: seal_mod.Sealed, index: u32, template: anytype, template_id: Digest) !void {
        if (zero(pins.native_template_catalog_digest) or
            !zero(pins.native_template_id) or
            self.records.len != @as(usize, sealed.execution_instance_count) or
            !std.meta.eql(try self.digest(), pins.native_template_catalog_digest) or
            !std.meta.eql(sealed.native_template_catalog_digest, pins.native_template_catalog_digest) or
            @as(usize, index) >= self.records.len)
            return error.UntrustedNativeV5TemplateCatalog;
        const record = self.records[@as(usize, index)];
        if (!std.meta.eql(record.template_id, template_id) or
            !std.meta.eql(record.geometry_digest, template.geometry_digest) or
            !std.meta.eql(record.fixed_root, template.fixed_root) or
            !std.meta.eql(try template.identity(), template_id))
            return error.UntrustedNativeV5TemplateCatalog;
    }
};

fn zero(value: Digest) bool {
    return std.meta.eql(value, @as(Digest, @splat(0)));
}

test "native-v5 catalog rejects reordered and changed leaf records" {
    const first = Record{ .index = 0, .template_id = @splat(1), .geometry_digest = @splat(2), .fixed_root = @splat(3) };
    const second = Record{ .index = 1, .template_id = @splat(4), .geometry_digest = @splat(5), .fixed_root = @splat(6) };
    const records = [_]Record{ first, second };
    const expected = try (Admission{ .records = &records }).digest();
    var changed = records;
    changed[1].fixed_root = @splat(7);
    try std.testing.expect(!std.meta.eql(expected, try (Admission{ .records = &changed }).digest()));
    changed = .{ second, first };
    try std.testing.expectError(error.InvalidNativeV5TemplateCatalog, (Admission{ .records = &changed }).digest());
}
