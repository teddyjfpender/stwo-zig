//! DeviceChannel (spec §3.3): the proof's Fiat–Shamir transcript, resident on
//! the device. State is the 16-word `NAT/rv64/channel.h` / transcript::State
//! (raw digest: `reserved` = 0). Every operation enqueues one existing kernel
//! on the exec stream and advances the host-side step/chain ordering guard;
//! no value ever returns to the host. The host only mirrors (step, chain) so
//! a later checkpoint can be validated.
//!
//! Byte equality with the host `raw_mod_m31.Om31Channel`:
//!   mixU32s / mixU64 / mixRoot → mixWords (blake2s(digest ‖ words), draws = 0)
//!   mixFelts(OM31)           → mixFelts (same bytes, field-checked)
//!   drawSecureFelt(s)        → drawSecureFelts (blake2s(digest ‖ draws ‖ 0), reduce_m31 per word)
//!   drawU32s                 → drawRaw (raw words)
//!   queries.drawQueries      → drawQueries (8 raw words per draw, masked)
//!   PoW                      → pow (device grind + mix of the 2 nonce words; = legacy device PCS)
const std = @import("std");
const api = @import("api.zig");
const O = @import("ops.zig");

/// Channel words the worker reserves per job: 16 state + 16 boundary scratch.
pub const state_words: usize = 32;
pub const snapshot_words: usize = 16;
const chain_tag: u64 = 0x4a4f4253 << 32; // "JOBS"

pub const Snapshot = extern struct {
    digest: [8]u32,
    draws: u32,
    cursor: u32,
    status: u32,
    reserved: u32,
    chain: u64,
    padding: [2]u32,
    pub fn fromWords(words: []const u32) Snapshot {
        std.debug.assert(words.len >= snapshot_words);
        var out: Snapshot = undefined;
        @memcpy(std.mem.asBytes(&out), std.mem.sliceAsBytes(words[0..snapshot_words]));
        return out;
    }
};
comptime {
    if (@sizeOf(Snapshot) != 64 or @offsetOf(Snapshot, "chain") != 48) @compileError("OM31 channel snapshot ABI mismatch");
}

pub const DeviceChannel = struct {
    worker: *api.DeviceWorker,
    exec: *const O.Exec,
    ctx: *anyopaque,
    stream: *anyopaque,
    state: [*]u32,
    boundary: [*]u32,
    chain_base: u64,
    step: u32 = 0,
    initialized: bool = false,
    poisoned: bool = false,

    pub fn init(worker: *api.DeviceWorker, exec: *const O.Exec, ctx: *anyopaque, stream: *anyopaque, words: api.DeviceBuffer, sequence: u64) DeviceChannel {
        std.debug.assert(words.words >= state_words);
        return .{ .worker = worker, .exec = exec, .ctx = ctx, .stream = stream, .state = words.ptr, .boundary = words.ptr + snapshot_words, .chain_base = chain_tag | (sequence & 0xffff_ffff) << 0 };
    }

    fn chain(self: *const DeviceChannel) u64 {
        return self.chain_base +% (@as(u64, self.step) << 0);
    }
    fn begin(self: *DeviceChannel) !void {
        if (self.poisoned) return error.DeviceChannelPoisoned;
        if (!self.initialized) return error.DeviceChannelNotInitialized;
        if (self.step == std.math.maxInt(u32) - 1) return error.TranscriptStepOverflow;
    }
    fn done(self: *DeviceChannel, code: c_int) !void {
        if (code != 0) {
            self.poisoned = true;
            return error.CudaEnqueueFailed;
        }
        self.step += 1;
    }
    fn need(b: api.DeviceBuffer, words: usize) !void {
        if (b.words < words) return error.DeviceBufferTooSmall;
    }

    /// Seed = digest[8] ‖ draws (9 words, device resident; usually staged or a
    /// previous job's slab snapshot).
    pub fn initFromCheckpoint(self: *DeviceChannel, seed: api.DeviceBuffer) !void {
        if (self.initialized) return error.DeviceChannelAlreadyInitialized;
        try need(seed, 9);
        if (self.exec.channel_init_on(self.ctx, 0, self.state, seed.ptr, self.chain()) != 0) {
            self.poisoned = true;
            return error.CudaEnqueueFailed;
        }
        self.initialized = true;
    }
    pub fn mixWords(self: *DeviceChannel, words: api.DeviceBuffer) !void {
        return self.mix(words, false);
    }
    /// OM31 felts (8 canonical M31 words each); rejects non-canonical words on device.
    pub fn mixFelts(self: *DeviceChannel, felts: api.DeviceBuffer) !void {
        if (felts.words % 8 != 0) return error.InvalidFeltWords;
        return self.mix(felts, true);
    }
    /// Merkle root straight from a device tree buffer (8 words). Never read back.
    pub fn mixRootFromTree(self: *DeviceChannel, root: api.DeviceBuffer) !void {
        try need(root, 8);
        return self.mix(.{ .ptr = root.ptr, .words = 8 }, false);
    }
    fn mix(self: *DeviceChannel, input: api.DeviceBuffer, field: bool) !void {
        try self.begin();
        if (input.words > (std.math.maxInt(u32) - 32) / 4) return error.InvalidGeometry;
        const source: ?[*]const u32 = if (input.words == 0) null else input.ptr;
        try self.done(self.exec.channel_mix_on(self.ctx, 0, self.state, self.step, self.chain(), self.chain() +% 1, source, @intCast(input.words), @intFromBool(field), self.boundary));
    }
    /// `n` OM31 felts (8 words each) into `out`. One step regardless of n.
    pub fn drawSecureFelts(self: *DeviceChannel, n: u32, out: api.DeviceBuffer) !void {
        if (n == 0 or n > 1 << 20) return error.InvalidGeometry;
        try need(out, @as(usize, n) * 8);
        try self.begin();
        try self.done(self.exec.channel_draw_on(self.ctx, 0, self.state, self.step, self.chain(), self.chain() +% 1, n, out.ptr, self.boundary));
    }
    /// Host `drawU32s`: one raw 8-word draw. `out` needs 16 words (8 output + 8 snapshot).
    pub fn drawRaw(self: *DeviceChannel, out: api.DeviceBuffer) !void {
        try need(out, 16);
        try self.begin();
        try self.done(self.exec.transcript_draw_u32s_on(self.state, self.step, self.chain(), self.chain() +% 1, out.ptr, out.ptr + 8, self.boundary, self.stream));
    }
    pub fn drawQueries(self: *DeviceChannel, log: u32, count: u32, out: api.DeviceBuffer) !void {
        if (log == 0 or log > 28 or count == 0 or count > 1024) return error.InvalidGeometry;
        try need(out, count);
        try self.begin();
        try self.done(self.exec.channel_queries_on(self.ctx, 0, self.state, self.step, self.chain(), self.chain() +% 1, log, count, out.ptr, self.boundary));
    }
    /// Words of device workspace `pow` needs (prefix 8, best u64 2, blocks 1, nonce 2; 8-byte aligned).
    pub const pow_workspace_words: usize = 16;
    /// Device grind then mix of the two nonce words — the exact legacy device
    /// PCS sequence (pcs_pipeline.cuh). `workspace` from Enqueue.alloc; the
    /// nonce stays at workspace[10..12] for the slab.
    pub fn pow(self: *DeviceChannel, bits: u32, workspace: api.DeviceBuffer) !void {
        if (bits == 0 or bits > 32) return error.InvalidGeometry;
        try need(workspace, pow_workspace_words);
        if (@intFromPtr(workspace.ptr) % 8 != 0) return error.InvalidDeviceAddress;
        try self.begin();
        const w = workspace.ptr;
        if (self.exec.pow_persistent_on(self.state, bits, 1 << 40, w, @ptrCast(@alignCast(w + 8)), w + 12, w + 10, self.stream) != 0) {
            self.poisoned = true;
            return error.CudaEnqueueFailed;
        }
        try self.mix(.{ .ptr = w + 10, .words = 2 }, false);
    }
    pub fn powNonce(workspace: api.DeviceBuffer) api.DeviceBuffer {
        return .{ .ptr = workspace.ptr + 10, .words = 2 };
    }
    /// Copy the current 16-word state into the slab at `offset` words (D2D, exec stream).
    pub fn snapshot(self: *DeviceChannel, slab: *const @import("slab.zig").ProofSlab, offset: usize) !void {
        if (!self.initialized or self.poisoned) return error.DeviceChannelPoisoned;
        const dst = try slab.device.slice(offset, snapshot_words);
        try O.check(self.exec.copy_async(dst.ptr, self.state, snapshot_words * 4, @intFromEnum(O.CopyKind.d2d), self.stream));
    }
    /// Device pointer to the live state (e.g. digest for a following job's seed).
    pub fn stateBuffer(self: *const DeviceChannel) api.DeviceBuffer {
        return .{ .ptr = self.state, .words = snapshot_words };
    }
    /// Host-side expectation for a completed snapshot taken after `steps` ops.
    pub fn validate(self: *const DeviceChannel, s: Snapshot) !void {
        if (self.poisoned or !self.initialized) return error.DeviceChannelPoisoned;
        if (s.status != 0 or s.reserved != 0 or s.cursor != self.step or s.chain != self.chain() or s.padding[0] != 0 or s.padding[1] != 0) return error.InvalidDeviceTranscript;
    }
    pub fn expectedChain(self: *const DeviceChannel, steps: u32) u64 {
        return self.chain_base +% steps;
    }
};
