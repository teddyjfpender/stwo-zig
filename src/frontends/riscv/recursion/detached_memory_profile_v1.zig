//! Independently admitted address topology for the two sparse byte trees.
//! Every byte slot is retained, including zeros, so values cannot select the
//! circuit or its Poseidon request count. No candidate-derived admission API.
const recursion = struct {
    const segment_statement_v2 = @import("segment_statement_v2.zig");
};
const std = @import("std");
const wire = recursion.segment_statement_v2;
const SectionProfileV1 = @import("detached_section_profile_v1.zig").SectionProfileV1;

pub const MemoryProfileV1 = struct {
    version: u16 = 1,
    entry_addresses: []const u32,
    exit_addresses: []const u32,

    pub fn validate(self: MemoryProfileV1, sections: SectionProfileV1) !void {
        if (self.version != 1) return error.InvalidBoundaryMemoryProfile;
        for ([_][]const u32{ self.entry_addresses, self.exit_addresses }, sections.counts[0..2]) |addresses, count| {
            if (addresses.len != count) return error.InvalidBoundaryMemoryProfile;
            for (addresses, 0..) |address, index| {
                if ((address & 3) != 0 or address > wire.MAX_RW_ADDRESS_EXCLUSIVE - 4 or (index != 0 and address <= addresses[index - 1]))
                    return error.InvalidBoundaryMemoryProfile;
            }
        }
    }
};

/// Supplies the existing canonical traversal with fixed addresses and generic
/// byte values. This iterator deliberately does not remove zero-value leaves.
pub fn ByteIterator(comptime F: type) type {
    return struct {
        const Self = @This();
        const Leaf = struct { index: u32, value: F };
        addresses: []const u32,
        bytes: []const [4]F,
        at: usize = 0,
        current: ?Leaf,
        pub fn init(addresses: []const u32, bytes: []const [4]F) Self {
            std.debug.assert(addresses.len == bytes.len);
            return .{ .addresses = addresses, .bytes = bytes, .current = if (addresses.len == 0) null else .{ .index = addresses[0], .value = bytes[0][0] } };
        }
        pub fn consume(self: *Self) Leaf {
            const value = self.current.?;
            self.at += 1;
            self.current = if (self.at == self.addresses.len * 4) null else .{ .index = self.addresses[self.at / 4] + @as(u32, @intCast(self.at % 4)), .value = self.bytes[self.at / 4][self.at % 4] };
            return value;
        }
    };
}
