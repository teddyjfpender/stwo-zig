//! Explicit retained-root qualification only. Reuses one fresh source authority
//! and the immutable physical proof; none of these checks run in normal verify.
const std = @import("std");
const A = @import("../sponge_cpu/root_admission.zig");
const Topology = @import("topology.zig").Topology;
const C = @import("../full_p2_common.zig");
fn refuse(topology: *const Topology, authority: A.Authority, prepared: *const A.Prepared, bytes: []const u8) !void {
    if (topology.verify(authority.inventory, prepared, bytes)) |_| return error.NativeGroupAcceptedForgedRoot else |_| {}
}
fn metadataRefused(a: std.mem.Allocator, topology: *const Topology, authority: A.Authority, metadata: A.Metadata, bytes: []const u8) !void {
    var changed = A.prepare(a, authority, metadata) catch return;
    defer changed.deinit();
    try refuse(topology, authority, &changed, bytes);
}
pub fn run(a: std.mem.Allocator, topology: *const Topology, authority: A.Authority, prepared: *const A.Prepared, metadata: A.Metadata, bytes: []const u8) !u32 {
    // Every negative is bracketed by the original positive control, so an
    // unavailable/broken verifier cannot make this corpus pass vacuously.
    try topology.verify(authority.inventory, prepared, bytes);
    var controls: u32 = 0;
    const output = try a.dupe(@import("../native_omul/fold.zig").Digest, prepared.outputs);
    defer a.free(output);
    var altered = prepared.*;
    altered.outputs = output;
    output[0][8] = output[0][8].add(C.Q.one());
    try refuse(topology, authority, &altered, bytes);
    controls += 1;
    const corrupt = try a.dupe(u8, bytes);
    defer a.free(corrupt);
    corrupt[corrupt.len / 2] ^= 1;
    try refuse(topology, authority, prepared, corrupt);
    controls += 1;
    const leaves = try a.dupe(@import("native_adapter.zig").Leaf, metadata.leaves);
    defer a.free(leaves);
    var proposal = metadata;
    proposal.leaves = leaves;
    proposal.execution[0] ^= 1;
    try metadataRefused(a, topology, authority, proposal, bytes);
    controls += 1;
    proposal = metadata;
    proposal.leaves = leaves;
    proposal.leaves = leaves[0 .. leaves.len - 1];
    try metadataRefused(a, topology, authority, proposal, bytes);
    controls += 1;
    proposal.leaves = leaves;
    leaves[0].ordinal += 1;
    try metadataRefused(a, topology, authority, proposal, bytes);
    leaves[0] = metadata.leaves[0];
    controls += 1;
    if (leaves.len > 1) {
        std.mem.swap(@import("native_adapter.zig").Leaf, &leaves[0], &leaves[1]);
        try metadataRefused(a, topology, authority, proposal, bytes);
        std.mem.swap(@import("native_adapter.zig").Leaf, &leaves[0], &leaves[1]);
        controls += 1;
    }
    // These are opposite REAL Wire slots; their sum is unchanged. This tests
    // frame authentication rather than relying only on a zero-sum check.
    if (authority.detached.len != 0) {
        const cpu = try a.dupe(C.O, leaves[0].claims);
        defer a.free(cpu);
        const di = authority.cpus.len;
        const detached = try a.dupe(C.O, leaves[di].claims);
        defer a.free(detached);
        cpu[cpu.len - 1] = cpu[cpu.len - 1].add(C.O.one());
        detached[2] = detached[2].sub(C.O.one());
        leaves[0].claims = cpu;
        leaves[di].claims = detached;
        try metadataRefused(a, topology, authority, proposal, bytes);
        leaves[0] = metadata.leaves[0];
        leaves[di] = metadata.leaves[di];
        controls += 1;
    }
    // A missing late local receipt cannot change the selected proof family.
    for (leaves, 0..) |leaf, i| if (leaf.receipt != null) {
        leaves[i].receipt = null;
        try metadataRefused(a, topology, authority, proposal, bytes);
        leaves[i] = metadata.leaves[i];
        controls += 1;
        break;
    };
    if (comptime @import("builtin").is_test) if (std.posix.getenv("STWO_OP_GROUP_CROSS_FORMAT_PROOF")) |path| {
        const other = try std.fs.cwd().readFileAlloc(a, path, 2 << 20);
        defer a.free(other);
        try refuse(topology, authority, prepared, other);
        controls += 1;
    };
    try topology.verify(authority.inventory, prepared, bytes);
    return controls;
}
