//! Decode producer-cache blocks on the caller's bounded, existing proof pool.
const std = @import("std");
const Pack = @import("cache_pack.zig");
const Rows = @import("stwo_prover_engine").lookups.row_work;
pub fn unpack(encoded: Pack.Packed, output: []u32) !void {
    const Context = struct {
        encoded: Pack.Packed,
        output: []u32,
        errors: [Rows.MAX_SHARDS]?anyerror = @splat(null),
        pub fn runRange(self: *@This(), shard: usize, begin: usize, end: usize) void {
            self.encoded.unpackRange(self.output, begin, end) catch |err| {
                self.errors[shard] = err;
            };
        }
    };
    var context = Context{ .encoded = encoded, .output = output };
    const shards = Rows.forEachRange(encoded.workItems(), &context, .{ .min_rows_per_shard = 1 });
    for (context.errors[0..shards]) |failure| if (failure) |err| return err;
}
