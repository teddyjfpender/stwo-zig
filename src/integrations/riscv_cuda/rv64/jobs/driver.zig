//! M8 GPU-native request driver (stream: driver). Contract: gpu_native.zig;
//! design: design/riscv-proving-stack/rv64-m8-gpu-native.md §3, §6.
//!
//! STUB (contract landing): selection + a host model of the peer exchange.
//! The driver stream replaces this with the JOBS=1 request driver: scheduler
//! DAG over NativeFactory/RecursionFactory jobs, placement, device seal
//! barrier + peer exchange, per-GPU memory plan, single wait + single slab
//! readback per GPU, publication from status words.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

/// STWO_RV64_M8_GPU_NATIVE=1 (requires STWO_RV64_M8_JOBS=1) selects the GPU-native
/// driver; unset = today's feeder path, unchanged. Until the driver lands,
/// selecting it fails closed.
pub const env_select = "STWO_RV64_M8_GPU_NATIVE";

pub fn selected(env: *const fn ([]const u8) ?[]const u8) !bool {
    const v = env(env_select) orelse return false;
    if (std.mem.eql(u8, v, "0")) return false;
    if (!std.mem.eql(u8, v, "1")) return error.InvalidM8GpuNativeSelection;
    const jobs = env("STWO_RV64_M8_JOBS") orelse return error.M8GpuNativeRequiresJobs;
    if (!std.mem.eql(u8, jobs, "1")) return error.M8GpuNativeRequiresJobs;
    return true;
}

pub const Driver = struct {
    native: G.NativeFactory,
    recursion: G.RecursionFactory,
    pub fn serveRequest(_: *Driver, _: u64) !void {
        return error.M8GpuNativeDriverNotLanded;
    }
};

/// Host model of `PeerExchange` (tests and the fake device): replicas are
/// host slices; publish copies the slot and sets its flag word to 1.
pub const HostExchange = struct {
    replicas: []const []u32,
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
            r[slot.flag] = 1;
        }
        from[slot.flag] = 1;
    }
    fn awaitSlot(raw: *anyopaque, device: u32, _: u32, slot: G.Exchange.Slot) anyerror!void {
        const self = of(raw);
        if (device >= self.replicas.len) return error.GpuNativeExchangeSlot;
        if (self.replicas[device][slot.flag] != 1) return error.GpuNativeExchangeNotPublished;
    }
};

const testing = std.testing;

test "selection: default off, requires JOBS=1, strict values" {
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
    try testing.expect(!try selected(E.get));
    E.gpu = "1";
    try testing.expectError(error.M8GpuNativeRequiresJobs, selected(E.get));
    E.jobs = "1";
    try testing.expect(try selected(E.get));
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
