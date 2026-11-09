//! Original fixed metadata guard, shared by default and scoped admission plans.
//! These hashes supplement the actually admitted fixed commitment. They never
//! nominate expected proof keys or authenticate proposed public values.
const std = @import("std");
pub fn fixedDigest(rows: anytype) [32]u8 {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("stwo.parent.fixed-metadata.v1");
    hasher.update(std.mem.sliceAsBytes(rows));
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}
pub fn ForAirs(comptime Airs: anytype) type {
    return struct {
        pub fn require(prepared: anytype, logs: *const [Airs.len]u32, fixed_counts: *const [Airs.len]usize, digests: *const [Airs.len][32]u8) !void {
            inline for (Airs, 0..) |Air, i| {
                if (prepared.fixed[i].len != fixed_counts[i]) return error.InvalidBlake3ParentRows;
                if (prepared.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidBlake3ParentRows;
                const log = logs[i];
                const size = @as(usize, 1) << @intCast(log);
                for (prepared.main[i]) |column| if (column.log_size != log or column.values.len != size) return error.InvalidBlake3ParentRows;
                const digest = fixedDigest(prepared.fixed[i]);
                if (!std.mem.eql(u8, &digest, &digests[i])) return error.InvalidBlake3ParentRows;
            }
        }
    };
}
