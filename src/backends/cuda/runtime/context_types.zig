//! Context capability value types and failure-atomic construction ownership.
const std = @import("std");
const native_api = @import("../abi/runtime.zig");
const runtime_error = @import("error.zig");

pub fn ForContext(comptime Self: type) type {
    return struct {
        pub const Construction = union(enum) {
            ready: Self,
            released: void,
            failed: struct { cause: runtime_error.Error, teardown: ?Self = null },

            /// A failed cleanup still owns its native control node. On another
            /// teardown error the outcome remains intact for explicit retry.
            pub fn deinit(self: *Construction) runtime_error.Error!void {
                switch (self.*) {
                    .ready => |*owner| {
                        try owner.abort();
                        self.* = .released;
                    },
                    .released => {},
                    .failed => |*failure| if (failure.teardown) |*owner| {
                        try owner.abort();
                        failure.teardown = null;
                    },
                }
            }
        };

        pub const DependencySlot = struct {
            generation: u64 = 0,
            producer_lane: u32 = 0,
            active: bool = false,
        };
        pub const Lane = struct {
            owner: usize,
            context_identity: u64,
            index: u32,
            stream: *anyopaque,
        };
        pub const Dependency = struct {
            owner: usize,
            token: native_api.DependencyToken,
        };

        pub const Buffer = struct {
            pointer: [*]u32,
            words: usize,
            owner: usize,
            generation: u64,

            pub fn bytes(self: Buffer) runtime_error.Error!usize {
                return std.math.mul(usize, self.words, @sizeOf(u32)) catch
                    error.SizeOverflow;
            }
        };
    };
}
