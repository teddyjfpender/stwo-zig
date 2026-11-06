//! `gpu_native.PeerExchange` over cudaMemcpyPeerAsync + cross-GPU events
//! (rv64-m8-gpu-native.md §3.6; addon NAT/rv64/jobs/peer_ops.cu).
//!
//!   publish(src, slot)       on src's exec stream: flag := 1 locally, then for
//!                            every other GPU peer-copy the slot words and the
//!                            flag word into its replica, then record the
//!                            slot's event. Called from the producer job's
//!                            `enqueue` on src's worker thread.
//!   awaitSlot(dev, src, slot) dev's exec stream waits (on the device) for that
//!                            event. Called from the consumer's `enqueue` on
//!                            dev's worker thread.
//!
//! The host never reads an exchanged value. Its only check is protocol: a
//! slot must have been published in THIS request (generation) before anyone
//! awaits it, else error.GpuNativeExchangeNotPublished (the DAG makes every
//! consumer's enqueue follow its producers' records, so a miss is a bug, and
//! a wait on an unrecorded event would silently not wait).
const std = @import("std");
const G = @import("gpu_native.zig");
const O = @import("ops.zig");

pub const max_slots = 4 * 256 + G.max_devices + 1;

pub const Peer = struct {
    exec: *const O.Exec,
    peer: *const O.Peer,
    devices: u32,
    /// CUDA ordinals by driver device index.
    ordinals: [G.max_devices]u32 = @splat(0),
    /// Exec stream per device (the workers' lane 0).
    streams: [G.max_devices]?*anyopaque = @splat(null),
    /// One event per (src device, slot index), created on src's worker thread.
    events: [G.max_devices][]?*anyopaque = @splat(&.{}),
    published: [G.max_devices][]std.atomic.Value(u64) = @splat(&.{}),
    // request state
    exchange: G.Exchange = .{ .segments = 0, .claims_per_segment = 0, .devices = 0 },
    replicas: [G.max_devices]?[*]u32 = @splat(null),
    generation: u64 = 0,
    publishes: std.atomic.Value(u64) = .init(0),
    peer_copies: std.atomic.Value(u64) = .init(0),
    awaits: std.atomic.Value(u64) = .init(0),

    pub fn deinitHost(self: *Peer, a: std.mem.Allocator) void {
        for (0..self.devices) |d| {
            a.free(self.events[d]);
            a.free(self.published[d]);
        }
    }

    /// Install: host tables for `slots` slot indices per device.
    pub fn reserve(self: *Peer, a: std.mem.Allocator, slots: usize) !void {
        if (slots > max_slots) return error.GpuNativeExchangeTooLarge;
        for (0..self.devices) |d| {
            self.events[d] = try a.alloc(?*anyopaque, slots);
            @memset(self.events[d], null);
            self.published[d] = try a.alloc(std.atomic.Value(u64), slots);
            for (self.published[d]) |*p| p.* = .init(0);
        }
    }

    /// Request start (driver thread, before any batch runs).
    pub fn begin(self: *Peer, generation: u64, exchange: G.Exchange, replicas: []const [*]u32) !void {
        if (generation == 0) return error.GpuNativeExchangeGeneration;
        if (replicas.len != self.devices) return error.GpuNativeMirrorCount;
        if (exchange.flagWords() > self.events[0].len) return error.GpuNativeExchangeTooLarge;
        self.exchange = exchange;
        for (replicas, 0..) |r, d| self.replicas[d] = r;
        self.generation = generation;
        self.publishes.store(0, .monotonic);
        self.peer_copies.store(0, .monotonic);
        self.awaits.store(0, .monotonic);
    }

    pub fn exchangeOf(self: *Peer) G.PeerExchange {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = G.PeerExchange.VTable{ .publish = publish, .await_slot = awaitSlot };

    fn of(raw: *anyopaque) *Peer {
        return @ptrCast(@alignCast(raw));
    }
    pub fn slotIndex(self: *const Peer, slot: G.Exchange.Slot) !usize {
        const base = self.exchange.words() - self.exchange.flagWords();
        if (slot.flag < base or slot.flag >= self.exchange.words()) return error.GpuNativeExchangeSlot;
        if (slot.offset + slot.words > base) return error.GpuNativeExchangeSlot;
        return slot.flag - base;
    }

    fn publish(raw: *anyopaque, src: u32, slot: G.Exchange.Slot) anyerror!void {
        const self = of(raw);
        if (src >= self.devices) return error.GpuNativeExchangeSlot;
        const idx = try self.slotIndex(slot);
        const stream = self.streams[src] orelse return error.GpuNativePeerNotInstalled;
        const event = self.events[src][idx] orelse return error.GpuNativePeerNotInstalled;
        const from = self.replicas[src] orelse return error.GpuNativePeerNotInstalled;
        try O.check(self.peer.fill_u32(from + slot.flag, 1, 1, stream));
        for (0..self.devices) |d| {
            if (d == src) continue;
            const to = self.replicas[d] orelse return error.GpuNativePeerNotInstalled;
            try O.check(self.peer.peer_copy_async(to + slot.offset, self.ordinals[d], from + slot.offset, self.ordinals[src], slot.words * 4, stream));
            try O.check(self.peer.peer_copy_async(to + slot.flag, self.ordinals[d], from + slot.flag, self.ordinals[src], 4, stream));
            _ = self.peer_copies.fetchAdd(2, .monotonic);
        }
        try O.check(self.exec.event_record(event, stream));
        self.published[src][idx].store(self.generation, .release);
        _ = self.publishes.fetchAdd(1, .monotonic);
    }

    fn awaitSlot(raw: *anyopaque, device: u32, src: u32, slot: G.Exchange.Slot) anyerror!void {
        const self = of(raw);
        if (device >= self.devices or src >= self.devices) return error.GpuNativeExchangeSlot;
        const idx = try self.slotIndex(slot);
        if (self.published[src][idx].load(.acquire) != self.generation) return error.GpuNativeExchangeNotPublished;
        _ = self.awaits.fetchAdd(1, .monotonic);
        // Same GPU: the producer ran earlier on this exec stream.
        if (device == src) return;
        const stream = self.streams[device] orelse return error.GpuNativePeerNotInstalled;
        try O.check(self.exec.stream_wait(stream, self.events[src][idx].?));
    }
};
