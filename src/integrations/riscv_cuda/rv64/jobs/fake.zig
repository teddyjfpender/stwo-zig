//! Host model of the job runtime's device operations, for tests without a GPU.
//! "Device" memory is host memory, every enqueue executes immediately in
//! program order (a legal schedule of one in-order exec stream), and the
//! channel kernels re-implement NAT/rv64/channel.cu + transcript/state.cuh
//! word for word. Counters let tests assert host waits, copies and ordering.
const std = @import("std");
const O = @import("ops.zig");

pub const Counters = struct {
    contexts: usize = 0,
    allocations: usize = 0,
    frees: usize = 0,
    h2d: usize = 0,
    d2h: usize = 0,
    d2d: usize = 0,
    h2d_bytes: usize = 0,
    d2h_bytes: usize = 0,
    host_waits: usize = 0,
    stream_waits: usize = 0,
    host_fns: usize = 0,
    kernels: usize = 0,
    fail_alloc_after: ?usize = null,
    fail_event_sync: bool = false,
    /// Frees (device or host) after this many succeed fail with code 4 and
    /// leave the block allocated (a CUDA error: the state is unknown).
    fail_free_after: ?usize = null,
    /// Frees of a pointer that is not allocated (double frees).
    bad_frees: usize = 0,
    // GPU-native driver ops (peer_ops.cu model)
    peer_enables: usize = 0,
    peer_copies: usize = 0,
    peer_bytes: usize = 0,
    fills: usize = 0,
    verdicts: usize = 0,
    timed_events: usize = 0,
    event_records: usize = 0,
};
pub var counters: Counters = .{};
var mutex: std.Thread.Mutex = .{};
const page = std.heap.page_allocator;
const Block = struct { ptr: [*]align(256) u8, bytes: usize };
var blocks: std.ArrayListUnmanaged(Block) = .empty;

pub fn reset() void {
    mutex.lock();
    defer mutex.unlock();
    counters = .{};
}

const M31: u32 = 0x7fffffff;

fn bump(comptime field: []const u8, n: usize) void {
    mutex.lock();
    defer mutex.unlock();
    @field(counters, field) += n;
}

fn contextCreate(options: *const O.ContextOptions, out: *?*anyopaque) callconv(.c) c_int {
    if (options.lane_count != 1) return 1;
    bump("contexts", 1);
    out.* = @ptrFromInt(0x1000 + @as(usize, options.device_ordinal) * 0x100);
    return 0;
}
fn contextDestroy(_: *anyopaque) callconv(.c) c_int {
    return 0;
}
fn laneStream(ctx: *anyopaque, lane: u32, out: *?*anyopaque) callconv(.c) c_int {
    if (lane != 0) return 1;
    out.* = @ptrFromInt(@intFromPtr(ctx) + 8);
    return 0;
}
fn allocU32(_: *anyopaque, count: usize, out: *?[*]u32) callconv(.c) c_int {
    mutex.lock();
    defer mutex.unlock();
    if (counters.fail_alloc_after) |n| if (counters.allocations >= n) return 2;
    const mem = page.alignedAlloc(u8, .fromByteUnits(256), count * 4) catch return 2;
    @memset(mem, 0xa5);
    blocks.append(page, .{ .ptr = mem.ptr, .bytes = mem.len }) catch return 2;
    counters.allocations += 1;
    out.* = @ptrCast(@alignCast(mem.ptr));
    return 0;
}
fn freeU32(_: *anyopaque, p: [*]u32) callconv(.c) c_int {
    mutex.lock();
    defer mutex.unlock();
    if (counters.fail_free_after) |n| if (counters.frees >= n) {
        counters.fail_free_after = null; // one injected failure
        return 4;
    };
    for (blocks.items, 0..) |b, i| if (@intFromPtr(b.ptr) == @intFromPtr(p)) {
        page.free(b.ptr[0..b.bytes]);
        _ = blocks.swapRemove(i);
        counters.frees += 1;
        return 0;
    };
    counters.bad_frees += 1;
    return 3;
}
fn streamCreate(device: u32, out: *?*anyopaque) callconv(.c) c_int {
    out.* = @ptrFromInt(0x9000 + @as(usize, device) * 0x100);
    return 0;
}
fn streamDestroy(_: *anyopaque) callconv(.c) c_int {
    return 0;
}
var next_event: usize = 0x20000;
fn eventCreate(out: *?*anyopaque) callconv(.c) c_int {
    mutex.lock();
    defer mutex.unlock();
    next_event += 16;
    out.* = @ptrFromInt(next_event);
    return 0;
}
fn eventDestroy(_: *anyopaque) callconv(.c) c_int {
    return 0;
}
fn eventRecord(_: *anyopaque, _: *anyopaque) callconv(.c) c_int {
    bump("event_records", 1);
    return 0;
}
fn streamWait(_: *anyopaque, _: *anyopaque) callconv(.c) c_int {
    bump("stream_waits", 1);
    return 0;
}
fn eventSync(_: *anyopaque) callconv(.c) c_int {
    bump("host_waits", 1);
    return if (counters.fail_event_sync) 700 else 0;
}
fn hostAlloc(bytes: usize, out: *?*anyopaque) callconv(.c) c_int {
    const mem = page.alignedAlloc(u8, .fromByteUnits(4096), @max(bytes, 4)) catch return 2;
    mutex.lock();
    defer mutex.unlock();
    blocks.append(page, .{ .ptr = mem.ptr, .bytes = mem.len }) catch return 2;
    out.* = mem.ptr;
    return 0;
}
fn hostFree(p: *anyopaque) callconv(.c) c_int {
    return freeU32(undefined, @ptrCast(@alignCast(p)));
}
fn copyAsync(dst: *anyopaque, src: *const anyopaque, bytes: usize, kind: u32, _: *anyopaque) callconv(.c) c_int {
    const d: [*]u8 = @ptrCast(dst);
    const s: [*]const u8 = @ptrCast(src);
    @memmove(d[0..bytes], s[0..bytes]);
    switch (kind) {
        1 => {
            bump("h2d", 1);
            bump("h2d_bytes", bytes);
        },
        2 => {
            bump("d2h", 1);
            bump("d2h_bytes", bytes);
        },
        3 => bump("d2d", 1),
        else => return 1,
    }
    return 0;
}
fn hostFn(_: *anyopaque, f: O.HostCall, user: ?*anyopaque) callconv(.c) c_int {
    bump("host_fns", 1);
    f(user);
    return 0;
}

// ---------------- channel kernels (transcript::State, raw digest) ----------------
const S = struct {
    const digest = 0;
    const draws = 8;
    const cursor = 9;
    const status = 10;
    const reserved = 11;
    const chain = 12;
};
fn getChain(s: [*]u32) u64 {
    return @as(u64, s[S.chain]) | @as(u64, s[S.chain + 1]) << 32;
}
fn setChain(s: [*]u32, v: u64) void {
    s[S.chain] = @truncate(v);
    s[S.chain + 1] = @truncate(v >> 32);
}
fn beginStep(s: [*]u32, step: u32, chain: u64) bool {
    if (s[S.status] != 0) return false;
    if (s[S.cursor] != step or getChain(s) != chain) {
        s[S.status] = 1;
        return false;
    }
    return true;
}
fn finishStep(s: [*]u32, next: u64, boundary: [*]u32) void {
    if (s[S.status] == 0) {
        s[S.cursor] += 1;
        setChain(s, next);
    }
    @memcpy(boundary[0..16], s[0..16]);
}
fn hashDigestWords(s: [*]u32, words: []const u32) void {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update(std.mem.sliceAsBytes(s[0..8]));
    h.update(std.mem.sliceAsBytes(words));
    var out: [32]u8 = undefined;
    h.final(&out);
    for (0..8) |i| s[i] = std.mem.readInt(u32, out[4 * i ..][0..4], .little);
    s[S.draws] = 0;
}
fn hashDraw(s: [*]const u32, counter: u32) [8]u32 {
    var input: [37]u8 = undefined;
    @memcpy(input[0..32], std.mem.sliceAsBytes(s[0..8]));
    std.mem.writeInt(u32, input[32..36], counter, .little);
    input[36] = 0;
    var out: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&input, &out, .{});
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, out[4 * i ..][0..4], .little);
    return words;
}
fn reduce(w: u32) u32 {
    const folded = (w & M31) + (w >> 31);
    return if (folded >= M31) folded - M31 else folded;
}
fn channelInit(_: *anyopaque, _: u32, s: [*]u32, seed: [*]const u32, chain: u64) callconv(.c) c_int {
    bump("kernels", 1);
    @memcpy(s[0..8], seed[0..8]);
    s[S.draws] = seed[8];
    s[S.cursor] = 0;
    s[S.status] = if (seed[8] <= 1 << 20) 0 else 5;
    s[S.reserved] = 0;
    setChain(s, chain);
    s[14] = 0;
    s[15] = 0;
    return 0;
}
fn channelMix(_: *anyopaque, _: u32, s: [*]u32, step: u32, chain: u64, next: u64, input: ?[*]const u32, count: u32, field: u32, boundary: [*]u32) callconv(.c) c_int {
    bump("kernels", 1);
    if (beginStep(s, step, chain)) {
        if (s[S.reserved] != 0 or step == std.math.maxInt(u32)) s[S.status] = 1;
        const words: []const u32 = if (count == 0) &.{} else input.?[0..count];
        if (field != 0) for (words) |w| if (w >= M31) {
            s[S.status] = 4;
        };
        if (s[S.status] == 0) hashDigestWords(s, words);
    }
    finishStep(s, next, boundary);
    return 0;
}
fn channelDraw(_: *anyopaque, _: u32, s: [*]u32, step: u32, chain: u64, next: u64, count: u32, out: [*]u32, boundary: [*]u32) callconv(.c) c_int {
    bump("kernels", 1);
    var valid = beginStep(s, step, chain);
    if (valid and (s[S.reserved] != 0 or step == std.math.maxInt(u32) or s[S.draws] > std.math.maxInt(u32) - count)) {
        s[S.status] = 1;
        valid = false;
    }
    const first = s[S.draws];
    for (0..count) |i| {
        const raw = if (valid) hashDraw(s, first + @as(u32, @intCast(i))) else @as([8]u32, @splat(0));
        for (0..8) |c| out[8 * i + c] = if (valid) reduce(raw[c]) else 0;
    }
    if (valid) s[S.draws] += count;
    finishStep(s, next, boundary);
    return 0;
}
fn channelQueries(_: *anyopaque, _: u32, s: [*]u32, step: u32, chain: u64, next: u64, log: u32, count: u32, out: [*]u32, boundary: [*]u32) callconv(.c) c_int {
    bump("kernels", 1);
    const nblocks = (count + 7) / 8;
    var valid = beginStep(s, step, chain);
    if (valid and (s[S.reserved] != 0 or step == std.math.maxInt(u32) or s[S.draws] > std.math.maxInt(u32) - nblocks)) {
        valid = false;
        s[S.status] = 1;
    }
    const first = s[S.draws];
    for (0..nblocks) |b| {
        const raw = if (valid) hashDraw(s, first + @as(u32, @intCast(b))) else @as([8]u32, @splat(0));
        for (0..8) |i| if (b * 8 + i < count) {
            out[b * 8 + i] = if (valid) raw[i] & ((@as(u32, 1) << @intCast(log)) - 1) else 0;
        };
    }
    if (valid) s[S.draws] += nblocks;
    finishStep(s, next, boundary);
    return 0;
}
fn drawRaw(_: *anyopaque, _: u32, s: [*]u32, step: u32, chain: u64, next: u64, out: [*]u32, boundary: [*]u32) callconv(.c) c_int {
    bump("kernels", 1);
    if (beginStep(s, step, chain)) {
        if (s[S.reserved] != 0 or step == std.math.maxInt(u32) or s[S.draws] == std.math.maxInt(u32)) {
            s[S.status] = 1;
        } else {
            const raw = hashDraw(s, s[S.draws]);
            s[S.draws] += 1;
            @memcpy(out[0..8], &raw);
        }
    }
    if (s[S.status] != 0) @memset(out[0..8], 0);
    finishStep(s, next, boundary);
    return 0;
}
fn powUnsupported(_: [*]const u32, _: u32, _: c_ulonglong, _: [*]u32, _: [*]c_ulonglong, _: [*]u32, _: [*]u32, _: *anyopaque) callconv(.c) c_int {
    return 98; // the host model does not grind; PoW parity runs on the pod.
}

pub const ops = O.Ops{
    .exec = .{
        .alloc_u32 = allocU32,
        .alloc_u32_long = allocU32,
        .free_u32 = freeU32,
        .channel_init_on = channelInit,
        .channel_mix_on = channelMix,
        .channel_draw_on = channelDraw,
        .channel_queries_on = channelQueries,
        .channel_draw_raw_on = drawRaw,
        .pow_persistent_on = powUnsupported,
        .copy_async = copyAsync,
        .event_record = eventRecord,
        .stream_wait = streamWait,
        .host_fn = hostFn,
    },
    .wait = .{
        .context_create = contextCreate,
        .context_destroy = contextDestroy,
        .lane_stream = laneStream,
        .stream_create = streamCreate,
        .stream_destroy = streamDestroy,
        .event_create = eventCreate,
        .event_destroy = eventDestroy,
        .event_sync = eventSync,
        .host_alloc = hostAlloc,
        .host_free = hostFree,
    },
};

// ---------------- GPU-native driver ops (peer_ops.cu model) ----------------
pub var peer_direct: u32 = 1;
fn peerEnable(_: [*]const u32, _: u32, direct: *u32) callconv(.c) c_int {
    direct.* = peer_direct;
    bump("peer_enables", 1);
    return 0;
}
fn peerCopy(dst: *anyopaque, _: u32, src: *const anyopaque, _: u32, bytes: usize, _: *anyopaque) callconv(.c) c_int {
    const d: [*]u8 = @ptrCast(dst);
    const s: [*]const u8 = @ptrCast(src);
    @memmove(d[0..bytes], s[0..bytes]);
    bump("peer_copies", 1);
    bump("peer_bytes", bytes);
    return 0;
}
fn fillU32(dst: [*]u32, value: u32, words: usize, _: *anyopaque) callconv(.c) c_int {
    @memset(dst[0..words], value);
    bump("fills", 1);
    bump("kernels", 1);
    return 0;
}
fn flagsVerdict(flags: [*]const u32, count: u32, verdict: [*]u32, reject_code: u32, _: *anyopaque) callconv(.c) c_int {
    bump("verdicts", 1);
    bump("kernels", 1);
    for (flags[0..count], 0..) |f, i| if (f != 1) {
        verdict[0] = (reject_code & 0xffff0000) | @as(u32, @intCast(@min(i + 1, 0xffff)));
        return 0;
    };
    verdict[0] = 0;
    return 0;
}
fn eventCreateTimed(out: *?*anyopaque) callconv(.c) c_int {
    bump("timed_events", 1);
    return eventCreate(out);
}
fn eventElapsed(_: *anyopaque, _: *anyopaque, out: *u64) callconv(.c) c_int {
    out.* = 0;
    return 0;
}

pub const peer = O.Peer{
    .peer_enable = peerEnable,
    .peer_copy_async = peerCopy,
    .fill_u32 = fillU32,
    .flags_verdict = flagsVerdict,
    .event_create_timed = eventCreateTimed,
    .event_elapsed_us = eventElapsed,
};
