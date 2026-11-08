//! M8 GPU-native request driver (stream: driver). Contract: gpu_native.zig;
//! design: design/riscv-proving-stack/rv64-m8-gpu-native.md §3, §6.
//!
//! GPU-native is the default; `STWO_RV64_M8_GPU_NATIVE=0` is the temporary reference control.
//! and the pieces of the JOBS=1 GPU-native request driver:
//!   driver_install.zig  installed class cache, memory plans, slabs and events
//!   driver_request.zig  request: DAG batches per GPU, ONE host wait, one
//!                       slab D2H per GPU, publication from status words
//!   driver_dag.zig      request DAG + static placement (+ two-phase marks)
//!   driver_memory.zig   one two-phase memory plan per GPU
//!   driver_peer.zig     PeerExchange over peer_ops.cu
//!   ../m8_capture_stream.zig  capture -> CaptureSink -> Stage1 release
//! plus a host model of the peer exchange (`HostExchange`) for tests.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

/// GPU-native is selected without opt-in flags. An explicit
/// STWO_RV64_M8_GPU_NATIVE=0 keeps the temporary reference control. Missing
/// installed classes and factory hooks fail closed on the selected path.
pub const env_select = "STWO_RV64_M8_GPU_NATIVE";

pub fn selected(env: *const fn ([]const u8) ?[]const u8) !bool {
    const v = env(env_select) orelse "1";
    if (std.mem.eql(u8, v, "0")) return false;
    if (!std.mem.eql(u8, v, "1")) return error.InvalidM8GpuNativeSelection;
    const jobs = env("STWO_RV64_M8_JOBS") orelse "1";
    if (!std.mem.eql(u8, jobs, "1")) return error.M8GpuNativeRequiresJobs;
    return true;
}

pub const request = @import("driver_request.zig");
pub const dag = @import("driver_dag.zig");
pub const memory = @import("driver_memory.zig");
pub const peer = @import("driver_peer.zig");
pub const capture = @import("../m8_capture_stream.zig");
pub const Driver = request.Driver;

/// Host model of `PeerExchange` (tests and the fake device): replicas are
/// host slices; publish copies the slot and sets its flag word to `tag`
/// (the request's gpu_native.Exchange.flagTag).
pub const HostExchange = struct {
    replicas: []const []u32,
    tag: u32 = 1,
    pub fn peer(self: *HostExchange) G.PeerExchange {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = G.PeerExchange.VTable{ .publish = publish, .await_slot = awaitSlot };
    fn of(raw: *anyopaque) *HostExchange {
        return @ptrCast(@alignCast(raw));
    }
    fn publish(raw: *anyopaque, src: u32, slot: G.Exchange.Slot) anyerror!void {
        const self = of(raw);
        if (src >= self.replicas.len) return error.GpuNativeExchangeSlot;
        const from = self.replicas[src];
        for (self.replicas, 0..) |r, d| {
            if (d == src) continue;
            @memcpy(r[slot.offset..][0..slot.words], from[slot.offset..][0..slot.words]);
            r[slot.flag] = self.tag;
        }
        from[slot.flag] = self.tag;
    }
    fn awaitSlot(raw: *anyopaque, device: u32, _: u32, slot: G.Exchange.Slot) anyerror!void {
        const self = of(raw);
        if (device >= self.replicas.len) return error.GpuNativeExchangeSlot;
        if (self.replicas[device][slot.flag] != self.tag) return error.GpuNativeExchangeNotPublished;
    }
};

const testing = std.testing;

test {
    _ = request;
    _ = dag;
    _ = memory;
    _ = capture;
    // The D3 pod probe compiles with the host tests (it needs real GPUs to run).
    _ = &@import("driver_probe.zig").run;
    _ = &@import("driver_serve.zig").serveSpool;
}

test "probe topology: one leaf per artifact, binary folds, root last" {
    const P = @import("driver_probe.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const topo = try P.topology(arena.allocator(), 7, 2);
    try std.testing.expectEqual(@as(usize, 9 + 8), topo.len);
    var d = try dag.build(std.testing.allocator, .{ .devices = 2, .segments = &(.{dag.Segment{}} ** 7), .truths = &(.{dag.Truth{}} ** 2), .recursion = topo, .root = @intCast(topo.len - 1) });
    defer d.deinit();
    try std.testing.expectEqual(G.ProofKind.root, d.nodes[d.recursion[topo.len - 1]].proof.?.kind);
}

test "selection: native default, explicit reference, contradictions fail closed" {
    const E = struct {
        var gpu: ?[]const u8 = null;
        var jobs: ?[]const u8 = null;
        fn get(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, env_select)) return gpu;
            if (std.mem.eql(u8, name, "STWO_RV64_M8_JOBS")) return jobs;
            return null;
        }
    };
    E.gpu = null;
    try testing.expect(try selected(E.get));
    E.gpu = "1";
    try testing.expect(try selected(E.get));
    E.jobs = "0";
    try testing.expectError(error.M8GpuNativeRequiresJobs, selected(E.get));
    E.jobs = "1";
    try testing.expect(try selected(E.get));
    E.gpu = "0";
    try testing.expect(!try selected(E.get));
    E.gpu = "yes";
    try testing.expectError(error.InvalidM8GpuNativeSelection, selected(E.get));
}

test "host exchange: a root published on GPU 0 lands in GPU 1's replica" {
    const x = G.Exchange{ .segments = 3, .claims_per_segment = 2, .devices = 2 };
    const r0 = try testing.allocator.alloc(u32, x.words());
    defer testing.allocator.free(r0);
    const r1 = try testing.allocator.alloc(u32, x.words());
    defer testing.allocator.free(r1);
    @memset(r0, 0);
    @memset(r1, 0);
    var h = HostExchange{ .replicas = &.{ r0, r1 } };
    const p = h.peer();
    const slot = try x.root(1);
    for (r0[slot.offset..][0..8], 0..) |*w, i| w.* = @intCast(100 + i);
    try testing.expectError(error.GpuNativeExchangeNotPublished, p.awaitSlot(1, 0, slot));
    try p.publish(0, slot);
    try p.awaitSlot(1, 0, slot);
    try testing.expectEqualSlices(u32, r0[slot.offset..][0..8], r1[slot.offset..][0..8]);
}
