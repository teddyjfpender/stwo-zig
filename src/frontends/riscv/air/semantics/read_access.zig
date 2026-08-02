//! Compact read-only access columns shared by high-volume opcode families.
//!
//! A read cannot change its value. Committing one limb group makes that
//! invariant structural instead of asking the prover for a duplicate group
//! and four equality constraints. `asAccess` reconstructs the unchanged bus
//! protocol, including tuple order and clocks.

const std = @import("std");

pub fn Ops(comptime S: type, comptime Access: type) type {
    return struct {
        pub const ReadAccess = struct {
            addr: S,
            value: [4]S,
            previous_clock: S,

            pub fn asAccess(self: ReadAccess) Access {
                return .{
                    .addr = self.addr,
                    .previous = self.value,
                    .previous_clock = self.previous_clock,
                    .next = self.value,
                };
            }
        };

        pub fn fromColumns(columns: []const S) ReadAccess {
            std.debug.assert(columns.len == 6);
            return .{
                .addr = columns[0],
                .value = columns[1..5].*,
                .previous_clock = columns[5],
            };
        }
    };
}
