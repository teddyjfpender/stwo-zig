//! Bounded common original envelope writer. Only an independent proof receiver
//! may turn these transported bytes into a verified relation.
const std = @import("std");
const core = @import("stwo_core");
const Fields = @import("block_v7_union_claim_wire_v1.zig");
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, magic: *const [8]u8, stark: core.proof_suites.Blake3.Proof, claims: anytype, maximum: usize) !usize {
    var out = @import("bounded_artifact_writer_v1.zig").Writer.init(a, maximum);
    defer out.deinit();
    try out.writeAll(magic);
    try out.writeAll(&Fields.schemaId(@TypeOf(claims)));
    var remaining: usize = 1 << 20;
    try Fields.encode(@TypeOf(claims), &out, claims, &remaining);
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &out, stark);
    try dir.writeFile(.{ .sub_path = name, .data = out.bytes.items });
    return out.bytes.items.len;
}
