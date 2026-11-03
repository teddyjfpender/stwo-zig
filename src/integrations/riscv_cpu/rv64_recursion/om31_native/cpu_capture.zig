//! Native authority and shape capture for CPU recursion qualification.
//! A capture follows independent native CPU verification; it never converts a
//! producer-declared shape directly into accepted recursive topology.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("mod.zig");
const Oods = @import("cpu_oods.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const Worker = @import("../../word16_global_execution/services/gkr_local/cpu_worker.zig");
const Components = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
pub fn geometry(a: std.mem.Allocator, setup: *const R.CpuSetup, config: W.PcsConfig) !V.Shape {
    var plan = try Components.Plan.init(a, setup);
    defer plan.deinit();
    var global_log: u32 = 0;
    for (plan.slots) |slot| global_log = @max(global_log, slot.log);
    const logs = try a.alloc([]const u32, 4);
    logs[0] = try setup.logs(a, 0);
    logs[1] = try setup.logs(a, 1);
    logs[2] = try plan.interLogs(a);
    const comp = try a.alloc(u32, 16);
    @memset(comp, global_log);
    logs[3] = comp;
    const offsets = try a.alloc([]const []const i32, 4);
    for (offsets, logs) |*tree, sizes| {
        const columns = try a.alloc([]const i32, sizes.len);
        @memset(columns, &.{});
        tree.* = columns;
    }
    // Copy immutable offsets to arena-owned slices; array literals are static.
    for (plan.slots) |slot| {
        const descriptor = Oods.Authority.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = setup.materials.geometry.cpu_compact_decode };
        const shape = try Oods.Authority.shape(descriptor);
        const f = @constCast(offsets[0]);
        const main = @constCast(offsets[1]);
        const inter = @constCast(offsets[2]);
        for (0..shape.fixed) |c| f[slot.fixed_offset + c] = &.{0};
        for (0..shape.main) |c| main[slot.main_offset + c] = if (Oods.Authority.previousMain(descriptor, c)) &.{ 0, -1 } else &.{0};
        const local: usize = if (slot.binding_index != null) 16 else 0;
        if (local != 0) for (0..16) |c| {
            inter[slot.inter_offset + c] = if (c < 8) &.{ 0, 2 } else &.{ 0, -1 };
        };
        const global = Oods.Authority.Global.layout(slot.origin);
        for (0..global.width()) |c| inter[slot.inter_offset + local + c] = if (global.previous(c)) &.{ 0, -1 } else &.{0};
    }
    for (@constCast(offsets[3])) |*column| column.* = &.{0};
    const out = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = offsets, .global_log = global_log, .composition_log_split = 1, .pcs = config };
    try out.validate();
    return out;
}
pub const Verified = struct {
    proof: W.Proof,
    capture: V.proof.NativeCapture,
    channel: W.Channel,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.capture.deinit(a);
        self.proof.deinit(a);
    }
};
pub fn verify(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: M.ExpectedWorker, first: anytype, manifest: *const M.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const Worker.CpuEncoded, fixed: ?*const Fixed.Binding) !Verified {
    _ = try Worker.verifyCpuWithAuthority(a, setup, request, expected, first, manifest, index, config, encoded, fixed);
    var proof = try W.decodePhysical(a, encoded.bytes);
    errdefer proof.deinit(a);
    var plan = try Components.Plan.init(a, setup);
    defer plan.deinit();
    var set = try Components.Set.init(a, setup, request, first, &plan, &manifest.entries[index].local.?, manifest.shared, encoded.claims);
    defer set.deinit();
    const handles = try set.verifiers(a);
    defer a.free(handles);
    var channel = if (fixed) |binding| binding.begin(config, expected) else W.begin(config, expected);
    var receiver = try core.pcs.ForField(W.O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, config);
    defer receiver.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    for (0..2) |tree| {
        const logs = try setup.logs(a, @intCast(tree));
        defer a.free(logs);
        try receiver.commit(a, roots[tree], logs, &channel);
    }
    W.mixManifestAndClaims(&channel, manifest.digest, encoded.claims);
    const logs = try plan.interLogs(a);
    defer a.free(logs);
    try receiver.commit(a, roots[2], logs, &channel);
    var capture: V.proof.NativeCapture = undefined;
    try core.verifier.ForField(W.O).verifyBorrowedWithProofCapture(W.H, W.MC, a, handles, &channel, &receiver, &proof, &capture);
    return .{ .proof = proof, .capture = capture, .channel = channel };
}
