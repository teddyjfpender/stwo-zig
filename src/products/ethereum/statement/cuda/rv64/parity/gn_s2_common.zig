//! Parity completion, peer copying and canonical scalar conversions.
const M31 = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const W = jobs.worker;
const api = jobs.api;
const core = @import("stwo_core");
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const std = @import("std");

pub fn env(name: []const u8) ?[]const u8 {
    return std.posix.getenv(name);
}
pub fn envBytes(name: []const u8, default: usize) !usize {
    const text = env(name) orelse return default;
    return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidParityEnvironment;
}
pub fn words8(x: O) [8]u32 {
    var w: [8]u32 = undefined;
    for (x.toM31Array(), &w) |m, *o| o.* = m.toU32();
    return w;
}
pub fn feltOf(w: []const u32) !O {
    var limbs: [8]M31 = undefined;
    for (&limbs, w[0..8]) |*l, x| {
        if (x >= core.fields.m31.Modulus) return error.NoncanonicalFelt;
        l.* = M31.fromCanonical(x);
    }
    return O.fromM31Array(limbs);
}

// ---------------------------------------------------------------------------
// Legacy device inputs live on the legacy GPU: mirror them (peer copy).
// ---------------------------------------------------------------------------
pub const PeerCopy = *const fn (*anyopaque, c_int, *const anyopaque, c_int, usize, *anyopaque) callconv(.c) c_int;
pub const Peer = struct {
    copy: PeerCopy,
    source_device: c_int,
    pub fn mirror(self: Peer, e: *api.Enqueue, dst: [*]u32, src: [*]const u32, words: usize) !void {
        if (self.copy(dst, @intCast(e.device()), src, self.source_device, words * 4, e.stream()) != 0) return error.ParityPeerCopyFailed;
    }
    /// Same-device D2D (staged buffer -> slab).
    pub fn local(self: Peer, e: *api.Enqueue, dst: [*]u32, src: [*]const u32, words: usize) !void {
        if (self.copy(dst, @intCast(e.device()), src, @intCast(e.device()), words * 4, e.stream()) != 0) return error.ParityPeerCopyFailed;
    }
};

pub const Done = struct {
    done: bool = false,
    result: anyerror!void = {},
    receipt: api.Receipt = .{},
    pub fn call(raw: *anyopaque, c: api.Completion) void {
        const d: *@This() = @ptrCast(@alignCast(raw));
        d.receipt = c.receipt;
        d.result = c.result;
        @atomicStore(bool, &d.done, true, .release);
    }
};
pub fn run(worker: *W.Worker, job: api.Job) !api.Receipt {
    var done = Done{};
    try worker.submit(job, .{ .ctx = &done, .done = Done.call });
    while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
    try done.result;
    return done.receipt;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------
