//! Opt-in v5 encoding: one committed copy of each sorted predecessor. The
//! full logical AIR row is reconstructed from authenticated ordering cells;
//! the v2 eighty-three-column encoding remains independently selectable.
const std = @import("std");
const memory = @import("../air/block/memory_component.zig");
const trace = @import("../air/block/memory_component_trace.zig");
const batch = @import("block_v5_memory_batch_receiver_v1.zig");
const shards = @import("block_memory_range_shard_v2.zig");
pub const Trace = trace.CompactTrace;
pub const MAIN_COLUMNS = 66;
pub const SAVED_MAIN_COLUMNS = trace.main_column_count - MAIN_COLUMNS;
pub const SAVED_MAIN_BYTES_PER_ROW = SAVED_MAIN_COLUMNS * @sizeOf(@import("stwo_core").fields.m31.M31);
pub fn planDigest(claims: []const memory.Claim, roots: []const [2][32]u8, range_roots: []const [2][32]u8, plan: *const shards.Plan) ![32]u8 {
    const original = try batch.memoryPlanDigest(claims, roots, range_roots, plan);
    return bind("stwo-zig/block-v5/compact-memory-plan/v1\x00", original);
}
pub fn instanceId(claim: memory.Claim, index: u32) [32]u8 {
    return bind("stwo-zig/block-v5/compact-memory-instance/v1\x00", batch.memoryInstanceId(claim, index));
}
fn bind(domain: []const u8, original: [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    var width: [4]u8 = undefined;
    std.mem.writeInt(u32, &width, MAIN_COLUMNS, .little);
    hash.update(&width);
    hash.update(&original);
    return hash.finalResult();
}
