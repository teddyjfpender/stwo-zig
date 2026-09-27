//! Bounded exact schedule custody, sharing the actual family's canonical
//! digest. Copies are storage, never proof authority or key reconstruction.
const std = @import("std");
pub fn ForWire(comptime Wire: type, comptime digest: anytype) type {
    return struct {
        pub fn copy(a: std.mem.Allocator, proposed: []const Wire, independently_expected: [32]u8, max_terms: usize) ![]Wire {
            if (proposed.len > max_terms) return error.InputRequestScheduleResourceLimit;
            if (!std.meta.eql(try digest(proposed), independently_expected)) return error.UntrustedInputRequestSchedule;
            const owned = try a.dupe(Wire, proposed);
            errdefer a.free(owned);
            if (!std.meta.eql(try digest(owned), independently_expected)) return error.UntrustedInputRequestSchedule;
            return owned;
        }
    };
}
