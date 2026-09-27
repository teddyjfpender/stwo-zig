//! Success-only scoped file rollback. Transport ownership is not proof authority.
//! The exclusive original publisher never replaces an existing destination.
const std = @import("std");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const Recipe = @import("../recursion/block_v5_heterogeneous_scoped_plan_v1.zig").Recipe;

pub fn path(comptime recipe: Recipe, buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, switch (recipe) {
        .complete => "block-v5-cpu-scoped-node-{d}.proof",
        .requesters => "block-v5-cpu-requester-node-{d}.proof",
    }, .{index});
}

pub fn ForRecipe(comptime recipe: Recipe) type {
    return struct {
        pub const Tracker = struct {
            dir: std.fs.Dir,
            planned: usize,
            created: usize = 0,
            active: bool = true,

            /// No allocation or filesystem access before bounded admission.
            pub fn init(dir: std.fs.Dir, planned: usize, maximum: usize) !@This() {
                if (maximum == 0 or planned > maximum or planned > std.math.maxInt(u32))
                    return error.CpuScopedPublicationResourceLimit;
                return .{ .dir = dir, .planned = planned };
            }

            /// Advance ONLY after successful publication, before any callback.
            /// Files.publish removes its own partial destination on I/O error.
            pub fn publish(self: *@This(), index: u32, raw: []const u8) !void {
                if (!self.active) return error.ClosedCpuScopedPublication;
                if (index != self.created or self.created >= self.planned)
                    return error.InvalidCpuScopedPublicationOrder;
                var buffer: [128]u8 = undefined;
                try Files.publish(self.dir, try path(recipe, &buffer, index), raw);
                self.created += 1;
            }

            /// Best-effort cleanup preserves the original failure. Only this
            /// transaction's successfully created prefix is eligible; original
            /// inputs, collisions and the other recipe's artifacts are untouched.
            /// The caller must not rename/replace tracked files while live.
            pub fn rollback(self: *@This()) void {
                if (!self.active) return;
                self.active = false;
                var remaining = self.created;
                while (remaining != 0) {
                    remaining -= 1;
                    var buffer: [128]u8 = undefined;
                    const filename = path(recipe, &buffer, @intCast(remaining)) catch continue;
                    self.dir.deleteFile(filename) catch {};
                }
            }

            /// Transfer successful file ownership only after the fold's final
            /// normative owner construction has succeeded.
            pub fn commit(self: *@This()) void {
                self.active = false;
            }
        };
    };
}
