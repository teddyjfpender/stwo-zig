//! M8 GPU-native native Stage 2 and the device global seal (stream native,
//! piece n-stage2; rv64-m8-gpu-native.md §3.2, §3.5, §3.6; inventory H8-H13).
//! native_device.zig's `stage2` / `seal` vtable entries come here.
//!
//! Seal (one job on the seal GPU, after every segment's MAIN root slot and
//! every two-stage truth's stage-1 MAIN root slot (Exchange.truthRoot, r-truth)
//! has landed in its exchange replica): the manifest chi chain over the roster
//! (native_seal_chi.cu: MAIN-only rho, chain step, chi) -> the 16-word seal
//! slot (chi = the manifest digest, then 0; Exchange.seal_digest_words)
//! peer-published to the other GPUs; Check.global_seal. A truth entry's root is
//! read from its truthRoot slot exactly like a segment's root slot (same flag
//! tag test), so the seal frames truths without a host-known root.
//! The host never reads a root, a digest or a challenge.
//!
//! Stage 2 (per segment, on the segment's GPU, after the seal slot landed):
//!   channel <- the segment's Stage-1 checkpoint (handoff region)
//!   shared  <- drawShared(seal chi) on device (native_seal_chi.cu)
//!   patch   global projection parameters and the composition table's
//!           shared / local / binding / hc / public parameters on device from
//!           the shared draws, the Stage-1 semantic handoff and the segment's
//!           public statement input (class tables, validated at warm)
//!   globals -> claims; mixManifestAndClaims(chi, claims) on the device channel
//!   INTER commit, alpha, composition, OODS, enqueue-only PCS (job arena)
//!   checks  global_status, composition_accept, public_claims, root_match,
//!           pcs_status, channel_order, encode_bounds -> request slab words
//!   encode  the exact WP.encodePhysical bytes into the slab (native_encode)
//! with the class framing (globals/INTER/composition plans, PcsJob framing,
//! encode program, patch tables) from the class cache only (`Classes`).
//!
//! Check.oods_constraint (gn-s2): native_encode_oods.zig, the point
//! evaluation of every role's composition program at the device OODS point
//! from the PCS image samples and the patched composition table, compared
//! with the composition samples' reconstruction. It runs when the class
//! carries an OODS program (ClassFraming.oods, built at warm by
//! native_encode_oods.fromPlan) and the addon kernel is loaded
//! (Symbols.oods); otherwise its status word stays `unset` (fails closed).
const std = @import("std");
const LF = @import("native_leaf_wire.zig");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const NE = @import("native_encode.zig");
const MW = @import("native_manifest_wire.zig");
const C = @import("native_commit.zig");
const N = @import("native_pcs.zig");
const NComp = @import("native_composition.zig");
const Gl = @import("native_global.zig");
const B = @import("native_binding.zig");
const JP = @import("../joined_parameters.zig");
pub const NO = @import("native_encode_oods.zig");

// ---------------------------------------------------------------------------
// Seal: constants and roster
// ---------------------------------------------------------------------------

pub const SealEntry = extern struct {
    k: u32,
    family: u32,
    rung: u32,
    root_offset: u32 = std.math.maxInt(u32),
    flag_offset: u32 = std.math.maxInt(u32),
    reserved: [3]u32 = @splat(0),
    vkhash: [8]u32,
    stmt: [8]u32,
    s_in: [8]u32,
    s_out: [8]u32,
    main_const: [8]u32 = @splat(0),
};
pub const SealConstants = extern struct {
    rho_tag: [8]u32,
    seg_tag: [8]u32,
    chi_tag: [8]u32,
    m0: [8]u32,
    execution: [8]u32,
    channel_init: [8]u32,
    ram_header: u32 = 14,
    kio_header: u32 = 11,
    wire_header: u32 = 35,
    ram_draws: u32 = JP.ram_count,
    kio_draws: u32 = JP.kio_count,
    wire_draws: u32 = JP.wire_count,
    entries: u32,
    tag: u32,
    /// secp256k1 equations WireFor.draw mixes this word before drawing.
    wire_pre: u32 = 0x53575031,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(SealEntry) != 48 * 4 or @sizeOf(SealConstants) != 58 * 4) @compileError("seal ABI changed");
}
/// Shared felts drawn per request, in the joined-parameter shared namespace
/// order (RAM offset+14, KIO offset+arity, Wire offset+arity) = JP.ram..JP.claims.
pub const shared_felts: u32 = JP.ram_count + JP.kio_count + JP.wire_count;

pub fn words8(d: [32]u8) [8]u32 {
    var w: [8]u32 = undefined;
    for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, d[4 * i ..][0..4], .little);
    return w;
}
const Blake = std.crypto.hash.blake2.Blake2s256;
/// canon_native Tag.digest: Blake2s-256(tag name).
pub fn tagDigest(name: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Blake.hash(name, &out, .{});
    return out;
}
/// canon_native.chainIv(identity) = H(iv, identity).
pub fn chainIv(identity: [32]u8) [32]u8 {
    var h = Blake.init(.{});
    h.update(&tagDigest("rv64-m5-chain-iv/v1"));
    h.update(&identity);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
/// Om31Channel.init() digest (the shared-draw channel's initial state).
pub fn om31InitDigest() [32]u8 {
    const Ch = @import("stwo_core").channel.raw_mod_m31.Om31Channel;
    return Ch.init().inner.digest;
}

/// `identity`: chain.versionIdentity(version) of the service policy (a
/// constant of the service); `execution`: the request statement digest (chi
/// input); `tag`: the request's exchange flag tag.
pub fn sealConstants(identity: [32]u8, execution: [32]u8, entries: u32, tag: u32) SealConstants {
    return .{
        .rho_tag = words8(tagDigest("rv64-m5-rho/v1")),
        .seg_tag = words8(tagDigest("rv64-m5-seg")),
        .chi_tag = words8(tagDigest("rv64-m5-chi")),
        .m0 = words8(chainIv(identity)),
        .execution = words8(execution),
        .channel_init = words8(om31InitDigest()),
        .entries = entries,
        .tag = tag,
    };
}

/// One roster entry (Manifest.ExpectedWorker chain fields, in roster order).
/// The entry's MAIN root comes from exactly one place:
///   `segment`  the native segment's MAIN root slot (Exchange.root);
///   `truth`    two-stage truth t's stage-1 MAIN root slot
///              (Exchange.truthRoot(t), r-truth; manifest ordinal = cpu
///              count + t), produced on GPU `truth_device`;
///   neither    `root`, a constant known before the request.
pub const RosterEntry = struct {
    family: u32,
    rung: u32,
    vkhash: [32]u8,
    stmt: [32]u8,
    s_in: [32]u8,
    s_out: [32]u8,
    segment: ?u32 = null,
    truth: ?u32 = null,
    /// GPU whose truth stage 1 publishes the truthRoot slot (seal awaitSlot).
    truth_device: u32 = 0,
    root: [32]u8 = @splat(0),
};
pub fn sealEntries(a: std.mem.Allocator, roster: []const RosterEntry, exchange: G.Exchange) ![]SealEntry {
    const out = try a.alloc(SealEntry, roster.len);
    errdefer a.free(out);
    for (roster, out, 0..) |r, *e, k| {
        e.* = .{ .k = @intCast(k), .family = r.family, .rung = r.rung, .vkhash = words8(r.vkhash), .stmt = words8(r.stmt), .s_in = words8(r.s_in), .s_out = words8(r.s_out), .main_const = words8(r.root) };
        if (r.segment != null and r.truth != null) return error.NativeSealRosterRootAmbiguous;
        const slot: ?G.Exchange.Slot = if (r.segment) |s| try exchange.root(s) else if (r.truth) |t| try exchange.truthRoot(t) else null;
        if (slot) |sl| {
            e.root_offset = @intCast(sl.offset);
            e.flag_offset = @intCast(sl.flag);
        }
    }
    return out;
}
/// The truth root slots the seal awaits (slot + producing GPU), roster order.
pub const TruthAwait = struct { slot: G.Exchange.Slot, device: u32 };
pub fn truthAwaits(a: std.mem.Allocator, roster: []const RosterEntry, exchange: G.Exchange, devices: usize) ![]TruthAwait {
    var n: usize = 0;
    for (roster) |r| n += @intFromBool(r.truth != null);
    const out = try a.alloc(TruthAwait, n);
    errdefer a.free(out);
    var i: usize = 0;
    for (roster) |r| if (r.truth) |t| {
        if (r.truth_device >= devices) return error.GpuNativeSealDeviceOutOfRange;
        out[i] = .{ .slot = try exchange.truthRoot(t), .device = r.truth_device };
        i += 1;
    };
    return out;
}

pub const SealFn = *const fn (*anyopaque, u32, [*]const SealEntry, [*]const u32, u64, *const SealConstants, [*]u32, [*]u32, [*]const SealEntry) callconv(.c) c_int;
pub const SharedFn = *const fn (*anyopaque, u32, [*]const u32, *const SealConstants, [*]u32, u64) callconv(.c) c_int;
pub const SealSymbols = struct {
    seal: SealFn,
    shared: SharedFn,
    /// Flat (v1-flat) manifest digest; null on an addon without it.
    flat: ?*const anyopaque = null,
    manifest: ?MW.EncodeFn = null,
    pub fn load(addon: *std.DynLib) !SealSymbols {
        return .{
            .seal = addon.lookup(SealFn, "stwo_rv64_native_seal_chi_v1_on") orelse return error.MissingNativeSealSymbol,
            .shared = addon.lookup(SharedFn, "stwo_rv64_native_seal_shared_v1_on") orelse return error.MissingNativeSealSymbol,
            .flat = addon.lookup(*const anyopaque, "stwo_rv64_native_seal_flat_v1_on"),
            .manifest = MW.load(addon) catch null,
        };
    }
    pub fn flatFn(self: *const SealSymbols) !FlatFn {
        return @ptrCast(@alignCast(self.flat orelse return error.MissingNativeSealFlatSymbol));
    }
};

pub fn rcOf(code: c_int) !void {
    return rc(code);
}
fn rc(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

/// Replica of the exchange region on `device` (inside its slab segment).
pub fn replica(ctx: *const G.RequestContext, device: u32) !api.DeviceBuffer {
    return ctx.layout.segments[device].exchangeBuffer(ctx.segments[device]);
}

// ---------------------------------------------------------------------------
// Flat manifest digest (STWO_RV64_NATIVE_VERSION=v1-flat: the D2 profile)
// ---------------------------------------------------------------------------

/// Under the flat policy the manifest digest is NOT the chi chain above but
/// manifest.emitCanonical hashed with one Blake2s-256 (manifest.zig Writer):
///   PROFILE || execution || u64 8 || u64 n || per entry:
///     u64 kind, u64 relation bits, u64 mass ram/kio/wire, u64 ordinal,
///     statement, fixed, MAIN root, u64 local?;
///     local: receipt digest, u64 instances, per instance u64 2 + 2 felts
///            (claims_to_verify_by_instance, canonical coordinates)
/// Everything but the MAIN roots, the local receipt digests and the terminal
/// marginals is request public data known before proving; those three are
/// device values in the exchange replica (root / truthRoot, receipt, claims
/// slots). The host turns the roster into a "digest script" once per request
/// (`FlatScript.build`): byte runs from a constant pool and exchange reads,
/// plus the flag-tag tests of every slot read; the device streams it into
/// one Blake2s (native_seal_chi.cu stwo_rv64_native_seal_flat_v1_on) and
/// writes the seal slot (digest, then 0) and Check.global_seal.
pub const FlatOp = enum(u32) { bytes = 0, words = 1, felts = 2, flag = 3 };
pub const FlatEntry = struct {
    kind: u32,
    relations: u32,
    mass: [3]u64,
    ordinal: u32,
    statement: [32]u8,
    fixed: [32]u8,
    /// Root source as RosterEntry (segment / truth slot, or `main`).
    segment: ?u32 = null,
    truth: ?u32 = null,
    truth_device: u32 = 0,
    main: [32]u8 = @splat(0),
    /// Local child present: number of GKR instances (marginals: 2 felts each,
    /// the segment's claims slot) and the receipt digest from the segment's
    /// receipt slot (Exchange.receipts). null: u64 0, no local block.
    local_instances: ?u32 = null,
};
pub const FlatScript = struct {
    a: std.mem.Allocator,
    /// [op, a, b] triples: bytes (pool byte offset, length), words (exchange
    /// word offset, count), felts (exchange word offset, felts), flag
    /// (exchange word offset of a slot flag; must equal the request tag).
    ops: []u32,
    /// Constant bytes (little-endian words; `pool_bytes` valid).
    pool: []u32,
    pool_bytes: u32,
    pub fn deinit(self: *FlatScript) void {
        self.a.free(self.ops);
        self.a.free(self.pool);
    }
    pub fn build(a: std.mem.Allocator, profile: []const u8, execution: [32]u8, entries: []const FlatEntry, exchange: G.Exchange) !FlatScript {
        var ops: std.ArrayListUnmanaged(u32) = .empty;
        errdefer ops.deinit(a);
        var pool: std.ArrayListUnmanaged(u8) = .empty;
        defer pool.deinit(a);
        var run_at: ?usize = null; // pool offset of the open bytes run
        const Emit = struct {
            fn bytes(al: std.mem.Allocator, o: *std.ArrayListUnmanaged(u32), p: *std.ArrayListUnmanaged(u8), open: *?usize, v: []const u8) !void {
                _ = o;
                if (open.* == null) open.* = p.items.len;
                try p.appendSlice(al, v);
            }
            fn int(al: std.mem.Allocator, o: *std.ArrayListUnmanaged(u32), p: *std.ArrayListUnmanaged(u8), open: *?usize, v: u64) !void {
                var e: [8]u8 = undefined;
                std.mem.writeInt(u64, &e, v, .little);
                try bytes(al, o, p, open, &e);
            }
            fn close(al: std.mem.Allocator, o: *std.ArrayListUnmanaged(u32), p: *std.ArrayListUnmanaged(u8), open: *?usize) !void {
                const at = open.* orelse return;
                try o.appendSlice(al, &.{ @intFromEnum(FlatOp.bytes), @intCast(at), @intCast(p.items.len - at) });
                open.* = null;
            }
            fn read(al: std.mem.Allocator, o: *std.ArrayListUnmanaged(u32), p: *std.ArrayListUnmanaged(u8), open: *?usize, op: FlatOp, slot: G.Exchange.Slot, n: usize) !void {
                try close(al, o, p, open);
                try o.appendSlice(al, &.{ @intFromEnum(FlatOp.flag), @intCast(slot.flag), 0, @intFromEnum(op), @intCast(slot.offset), @intCast(n) });
            }
        };
        if (entries.len == 0) return error.NativeSealFlatRoster;
        try Emit.bytes(a, &ops, &pool, &run_at, profile);
        try Emit.bytes(a, &ops, &pool, &run_at, &execution);
        try Emit.int(a, &ops, &pool, &run_at, 8);
        try Emit.int(a, &ops, &pool, &run_at, entries.len);
        for (entries) |e| {
            for ([_]u64{ e.kind, e.relations, e.mass[0], e.mass[1], e.mass[2], e.ordinal }) |v| try Emit.int(a, &ops, &pool, &run_at, v);
            try Emit.bytes(a, &ops, &pool, &run_at, &e.statement);
            try Emit.bytes(a, &ops, &pool, &run_at, &e.fixed);
            if (e.segment != null and e.truth != null) return error.NativeSealRosterRootAmbiguous;
            if (e.segment) |sg| try Emit.read(a, &ops, &pool, &run_at, .words, try exchange.root(sg), 8) else if (e.truth) |t| try Emit.read(a, &ops, &pool, &run_at, .words, try exchange.truthRoot(t), 8) else try Emit.bytes(a, &ops, &pool, &run_at, &e.main);
            try Emit.int(a, &ops, &pool, &run_at, @intFromBool(e.local_instances != null));
            if (e.local_instances) |n| {
                const sg = e.segment orelse return error.NativeSealFlatLocalWithoutSegment;
                try Emit.read(a, &ops, &pool, &run_at, .words, try exchange.receipt(sg), 8);
                try Emit.int(a, &ops, &pool, &run_at, n);
                const claims = try exchange.claims(sg);
                if (claims.words < 16 * @as(usize, n)) return error.NativeSealFlatClaimsShape;
                for (0..n) |i| {
                    try Emit.int(a, &ops, &pool, &run_at, 2);
                    // One flag test per slot is enough; repeat it per read (cheap, uniform).
                    try Emit.read(a, &ops, &pool, &run_at, .felts, .{ .offset = claims.offset + 16 * i, .words = 16, .flag = claims.flag }, 2);
                }
            }
        }
        try Emit.close(a, &ops, &pool, &run_at);
        const words = try a.alloc(u32, (pool.items.len + 3) / 4);
        errdefer a.free(words);
        @memset(words, 0);
        @memcpy(std.mem.sliceAsBytes(words)[0..pool.items.len], pool.items);
        return .{ .a = a, .ops = try ops.toOwnedSlice(a), .pool = words, .pool_bytes = @intCast(pool.items.len) };
    }
    /// Host mirror of the kernel over a host copy of the exchange replica:
    /// the digest, or the global_seal detail it refuses with.
    pub fn hostDigest(self: *const FlatScript, exchange: []const u32, tag: u32) union(enum) { digest: [32]u8, refuse: u16 } {
        var h = Blake.init(.{});
        const pool = std.mem.sliceAsBytes(self.pool)[0..self.pool_bytes];
        var i: usize = 0;
        var detail: u16 = 0;
        while (i + 3 <= self.ops.len) : (i += 3) {
            const op: FlatOp = @enumFromInt(self.ops[i]);
            const x = self.ops[i + 1];
            const n = self.ops[i + 2];
            switch (op) {
                .bytes => h.update(pool[x..][0..n]),
                .words => h.update(std.mem.sliceAsBytes(exchange[x..][0..n])),
                .felts => {
                    for (exchange[x..][0 .. 8 * n]) |w| if (w >= m31_modulus and detail == 0) {
                        detail = flat_noncanonical;
                    };
                    h.update(std.mem.sliceAsBytes(exchange[x..][0 .. 8 * n]));
                },
                .flag => if (exchange[x] != tag and detail == 0) {
                    detail = 1; // kRootNotLanded
                },
            }
        }
        if (detail != 0) return .{ .refuse = detail };
        var out: [32]u8 = undefined;
        h.final(&out);
        return .{ .digest = out };
    }
};
/// global_seal detail of a non-canonical marginal coordinate (flat mode).
pub const flat_noncanonical: u16 = 3;

pub const FlatFn = *const fn (*anyopaque, u32, [*]const u32, u64, [*]const u32, u64, u32, [*]const u32, u64, u32, [*]u32, [*]u32, [*]const u32) callconv(.c) c_int;
pub fn sealFlat(f: FlatFn, ctx: *anyopaque, ops: api.DeviceBuffer, pool: api.DeviceBuffer, pool_bytes: u32, exchange: api.DeviceBuffer, tag: u32, slot: api.DeviceBuffer, verdict: api.DeviceBuffer, ops_host: []const u32) !void {
    if (ops.words != ops_host.len or pool.words * 4 < pool_bytes or slot.words < 16) return error.NativeSealFlatShape;
    return rc(f(ctx, 0, ops.ptr, ops.words, pool.ptr, pool.words, pool_bytes, exchange.ptr, exchange.words, tag, slot.ptr, verdict.ptr, ops_host.ptr));
}

/// The seal job (NativeFactory.seal). Footprint: the entries (staged) only.
pub const SealJob = struct {
    a: std.mem.Allocator,
    sym: *const SealSymbols,
    ctx: *const G.RequestContext,
    device: u32,
    entries: []const SealEntry,
    constants: SealConstants,
    /// Two-stage truth roots the chain reads (Exchange.truthRoot slots).
    truth_awaits: []const TruthAwait = &.{},
    /// Flat policy (v1-flat, D2): the digest script replaces the chi chain;
    /// `entries` is then unused (may be empty).
    flat: ?*const FlatScript = null,
    manifest: ?*MW.Program = null,
    staged: ?api.DeviceBuffer = null,
    staged_ops: ?api.DeviceBuffer = null,
    staged_pool: ?api.DeviceBuffer = null,
    staged_manifest: ?api.DeviceBuffer = null,

    pub fn classKey(_: *SealJob) [32]u8 {
        return tagDigest("rv64-m8-gpu-native-seal/v1");
    }
    pub fn footprint(self: *SealJob) api.Footprint {
        var w = std.mem.alignForward(usize, self.entries.len * 48, 64);
        if (self.flat) |f| w += std.mem.alignForward(usize, f.ops.len, 64) + std.mem.alignForward(usize, f.pool.len, 64);
        if (self.manifest) |m| w += std.mem.alignForward(usize, m.words.len, 64);
        return .{ .device_words = w, .staged_words = w, .pinned_words = w };
    }
    pub fn stage(self: *SealJob, s: *api.Stager) !void {
        if (self.manifest) |m| {
            const b = try s.alloc(m.words.len);
            try s.upload(b, m.words);
            self.staged_manifest = b;
        }
        if (self.flat) |f| {
            const o = try s.alloc(f.ops.len);
            try s.upload(o, f.ops);
            self.staged_ops = o;
            const p = try s.alloc(@max(1, f.pool.len));
            try s.upload(try p.slice(0, f.pool.len), f.pool);
            self.staged_pool = p;
            return;
        }
        const b = try s.alloc(self.entries.len * 48);
        try s.upload(b, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(self.entries)));
        self.staged = b;
    }
    pub fn enqueue(self: *SealJob, e: *api.Enqueue) !void {
        var trace_label: [80]u8 = undefined;
        var trace_range = try e.trace(.seal, 0, &trace_label);
        defer trace_range.deinit();
        if (self.flat != null) {
            try self.enqueueFlat(e);
            try self.encodeManifest(e);
            return;
        }
        const ctx = self.ctx;
        const staged = self.staged orelse return error.NativeSealNotStaged;
        // Every segment's MAIN root slot, from whichever GPU produced it.
        for (ctx.segment_device, 0..) |src, s| try ctx.peer.awaitSlot(self.device, src, try ctx.exchange.root(@intCast(s)));
        // Every two-stage truth's stage-1 MAIN root, from its truth GPU.
        for (self.truth_awaits) |t| try ctx.peer.awaitSlot(self.device, t.device, t.slot);
        const x = try replica(ctx, self.device);
        const seal = ctx.exchange.seal();
        const slot = try x.slice(seal.offset, seal.words);
        const verdict = try ctx.layout.segments[self.device].statusBuffer(ctx.segments[self.device], .{ .kind = .request, .ordinal = 0 }, .global_seal);
        try rc(self.sym.seal(e.ctx(), 0, @ptrCast(staged.ptr), x.ptr, x.words, &self.constants, slot.ptr, verdict.ptr, self.entries.ptr));
        try ctx.peer.publish(self.device, seal);
        try self.encodeManifest(e);
    }
    fn encodeManifest(self: *SealJob, e: *api.Enqueue) !void {
        const m = self.manifest orelse return;
        const ctx = self.ctx;
        for (ctx.segment_device, 0..) |src, segment| try ctx.peer.awaitSlot(self.device, src, try ctx.exchange.childWire(@intCast(segment)));
        const sl = &ctx.layout.segments[self.device];
        const out = try sl.encodedBuffer(ctx.segments[self.device], .{ .kind = .request, .ordinal = 0 });
        if ((out.words - 1) * 4 < m.max_bytes) return error.GlobalGkrManifestLimit;
        const program = self.staged_manifest orelse return error.NativeSealNotStaged;
        const exchange = try replica(ctx, self.device);
        const args = MW.Run{ .program = program.ptr, .program_words = program.words, .exchange = exchange.ptr, .exchange_words = exchange.words, .tag = G.Exchange.flagTag(ctx.generation), .encoded = out.ptr, .encoded_words = out.words, .verdict = (try sl.statusBuffer(ctx.segments[self.device], .{ .kind = .request, .ordinal = 0 }, .global_seal)).ptr, .reject_code = @as(u32, @intFromEnum(G.Check.global_seal)) << 16 };
        try rc((self.sym.manifest orelse return error.MissingManifestEncoder)(e.ctx(), 0, &args));
    }
    /// Flat digest: every root, receipt and claims slot of every segment and
    /// every truth root, then the script.
    fn enqueueFlat(self: *SealJob, e: *api.Enqueue) !void {
        const ctx = self.ctx;
        const f = self.flat.?;
        for (ctx.segment_device, 0..) |src, sg| {
            const seg: u32 = @intCast(sg);
            try ctx.peer.awaitSlot(self.device, src, try ctx.exchange.root(seg));
            try ctx.peer.awaitSlot(self.device, src, try ctx.exchange.claims(seg));
            if (ctx.exchange.receipts) try ctx.peer.awaitSlot(self.device, src, try ctx.exchange.receipt(seg));
        }
        for (self.truth_awaits) |t| try ctx.peer.awaitSlot(self.device, t.device, t.slot);
        const x = try replica(ctx, self.device);
        const seal = ctx.exchange.seal();
        const verdict = try ctx.layout.segments[self.device].statusBuffer(ctx.segments[self.device], .{ .kind = .request, .ordinal = 0 }, .global_seal);
        try sealFlat(try self.sym.flatFn(), e.ctx(), self.staged_ops orelse return error.NativeSealNotStaged, try self.staged_pool.?.slice(0, f.pool.len), f.pool_bytes, x, self.constants.tag, try x.slice(seal.offset, seal.words), verdict, f.ops);
        try ctx.peer.publish(self.device, seal);
    }
    pub fn finish(_: *SealJob, _: api.SlabView) !void {}
    pub fn abort(_: *SealJob) void {}
};

// ---------------------------------------------------------------------------
// Stage-1 -> Stage-2 handoff (contract with piece n-stage1; INTERFACES)
// ---------------------------------------------------------------------------

/// Request-retained regions Stage1 creates (Stager/Enqueue.retain) and Stage2
/// finds (Stager.retained), keyed by segment:
///   checkpoint  9 words: the post-MAIN/GKR channel digest[8], draws
///               (CpuWorker.channel before mixManifestAndClaims)
///   binding     the binding plan's output words (16 coefficient columns per
///               binding instance, native_binding.Plan layout)
///   semantic    felts (8 words each): the joined-parameter local + binding
///               namespaces (JP.local .. JP.eta + 4), then every role's hc
///               rows (16 * trace_log words per hc role, role order)
pub const Handoff = enum(u8) { checkpoint = 1, binding = 2, semantic = 3 };
pub fn handoffName(kind: Handoff, segment: u32) [32]u8 {
    var n: [32]u8 = @splat(0);
    @memcpy(n[0..16], "rv64-gn-s1-hand.");
    n[16] = @intFromEnum(kind);
    std.mem.writeInt(u32, n[20..24], segment, .little);
    return n;
}
pub const checkpoint_words: usize = 9;
/// Felts of the semantic handoff before the hc rows.
pub const semantic_felts: u32 = JP.eta + 4 - JP.local;

// ---------------------------------------------------------------------------
// Device parameter patches (class tables)
// ---------------------------------------------------------------------------

/// A patch table: out[dst[i] .. +8] = src[8 * index[i] .. +8].
pub const Patch = struct {
    dst: []u32 = &.{},
    index: []u32 = &.{},
    pub fn deinit(self: *Patch, a: std.mem.Allocator) void {
        a.free(self.dst);
        a.free(self.index);
    }
    pub fn len(self: Patch) usize {
        return self.dst.len;
    }
    /// Fail closed at warm on a table the patch kernel would skip or that
    /// writes outside its target (the kernel's bounds guard only keeps a bad
    /// table in memory; a skipped entry would leave a warm-time value in a
    /// per-request parameter, i.e. a wrong proof with every check accepting).
    pub fn check(self: Patch, src_felts: usize, target_words: usize) !void {
        if (self.dst.len != self.index.len) return error.NativeStage2PatchTable;
        for (self.dst, self.index) |d, i| if (i >= src_felts or @as(usize, d) + 8 > target_words) return error.NativeStage2PatchTable;
    }
};
/// Device sources of per-request parameter values:
///   shared    drawShared(chi) on device (JP.ram .. JP.claims)
///   semantic  the Stage-1 semantic handoff (JP.local .. JP.eta + 4, then hc rows)
///   public    the segment's public namespace (JP slots < JP.local: cpu_steps,
///             pcs, epoch, rows, calls, first ids, source public such as the
///             sponge first id), request statement data uploaded with the job
pub const Source = enum { shared, semantic, public };
pub const sources = [_]Source{ .shared, .semantic, .public };
/// Felts of the public request input (JP slots [0, JP.local)).
pub const public_felts: u32 = JP.local;
const m31_modulus: u32 = 0x7fff_ffff;
/// Which parameter slots come from which device source. Every slot of a
/// per-request namespace maps to a source; only the claims namespace (mixed,
/// never a parameter value here) returns null.
pub fn sourceOf(slot: u32) ?struct { source: Source, index: u32 } {
    if (slot < JP.local) return .{ .source = .public, .index = slot };
    if (slot >= JP.ram and slot < JP.claims) return .{ .source = .shared, .index = slot - JP.ram };
    if (slot >= JP.local and slot < JP.eta + 4) return .{ .source = .semantic, .index = slot - JP.local };
    return null;
}
/// The patch tables of one parameter vector, one per source.
pub const PatchSet = struct {
    shared: Patch = .{},
    semantic: Patch = .{},
    public: Patch = .{},
    pub fn get(self: PatchSet, source: Source) Patch {
        return switch (source) {
            .shared => self.shared,
            .semantic => self.semantic,
            .public => self.public,
        };
    }
    pub fn words(self: PatchSet) usize {
        return 2 * (self.shared.len() + self.semantic.len() + self.public.len());
    }
    pub fn deinit(self: *PatchSet, a: std.mem.Allocator) void {
        self.shared.deinit(a);
        self.semantic.deinit(a);
        self.public.deinit(a);
    }
    pub fn check(self: PatchSet, semantic_words: usize, target_words: usize) !void {
        return self.checkWithPublic(semantic_words, target_words, public_felts);
    }
    pub fn checkWithPublic(self: PatchSet, semantic_words: usize, target_words: usize, count: usize) !void {
        try self.shared.check(shared_felts, target_words);
        try self.semantic.check(semantic_words / 8, target_words);
        try self.public.check(count, target_words);
    }
};
/// Patches of one packed parameter vector (`slots` = artifact parameter
/// slots, 8 words per slot starting at `base`), for one source.
pub fn appendSlots(a: std.mem.Allocator, dst: *std.ArrayListUnmanaged(u32), index: *std.ArrayListUnmanaged(u32), slots: []const u32, base: u32, source: Source) !void {
    for (slots, 0..) |slot, i| if (sourceOf(slot)) |s| if (s.source == source) {
        try dst.append(a, base + 8 * @as(u32, @intCast(i)));
        try index.append(a, s.index);
    };
}
pub fn patchOf(a: std.mem.Allocator, dst: *std.ArrayListUnmanaged(u32), index: *std.ArrayListUnmanaged(u32)) !Patch {
    return .{ .dst = try dst.toOwnedSlice(a), .index = try index.toOwnedSlice(a) };
}

// ---------------------------------------------------------------------------
// Class framing (built once per class at warm; never per request)
// ---------------------------------------------------------------------------

/// Everything Stage 2 of one segment class needs, owned by the class cache
/// entry (ClassEntry.plan). Built at warm by the native factory from the
/// class geometry (the framing cache's builders: native_framing_cache.zig);
/// the per-request values it held on the hybrid path are device patches here.
pub const ClassFraming = struct {
    a: std.mem.Allocator,
    key: G.ClassKey,
    claim_count: u32,
    slots: []const Gl.Slot,
    inter: *C.CommitPlan,
    composition: *NComp.Plan,
    pcs: *N.PcsJob,
    program: NE.Program,
    fixed_root: [32]u8,
    fixed_key: [32]u8,
    fixed_host: []const []const u32,
    fixed_offsets: []const usize,
    fixed_words: usize,
    /// Complete Stage-1 persistent allocation, including its root/authority.
    fixed_region_words: usize = 0,
    resident_handoff: ?struct { checkpoint: usize, binding: usize, semantic: usize, section: usize = 0, section_words: usize = 0 } = null,
    resources_warmed: bool = false,
    /// Installed only when every worker reclaims stream-ordered non-LIFO
    /// frees. Otherwise footprint retains the conservative sum of phases.
    reuse_frees: bool = false,
    /// PCS image, leaf statement seed tape and public outputs following the
    /// physical proof bytes in its request-slab child region.
    leaf_suffix_words: usize = 0,
    main_offsets: []const usize,
    main_words: usize,
    bind_plan: *const B.Plan,
    /// Per global plan (slot order of `slots` with a global), the patches of
    /// its parameter vector (shared draws, public request values).
    global_patches: []PatchSet,
    /// Composition table patches (shared draws, Stage-1 semantic incl. hc
    /// rows, public request values).
    comp_patches: PatchSet,
    /// Words of the Stage-1 semantic handoff region of this class: the
    /// `semantic_felts` namespace felts, then every hc role's rows.
    semantic_words: usize = 8 * @as(usize, semantic_felts),
    /// Flattened role-local public values, avoiding collisions between e.g.
    /// two roles' different call counts. Default preserves the old namespace.
    public_input_felts: u32 = public_felts,
    /// RAM boundary claim slots (core initial / terminal), or null.
    initial_claim: ?u32 = null,
    terminal_claim: ?u32 = null,
    /// Check.oods_constraint program of the class (native_encode_oods.fromPlan
    /// over `composition` and the PCS shape, at warm); null: the check does
    /// not run and its word stays unset (publication refuses).
    oods: ?[]const u32 = null,
    /// Class-cache device tables (per GPU) holding program + patch tables;
    /// see `deviceWords` / `writeDevice`.
    destroy_fn: ?*const fn (*ClassFraming) void = null,

    /// The resident Stage-1 commits store columns in log-sorted order.
    /// Install framing also supports legacy original-order images, so adopt
    /// the actual producer's original-index -> physical-offset views when
    /// the binding shares its resident buffers. Borrowed for class lifetime.
    pub fn adoptResidentColumns(self: *ClassFraming, fixed: *const C.CommitPlan, main: *const C.CommitPlan) !void {
        if (self.fixed_offsets.len != fixed.offsets.len or self.main_offsets.len != main.offsets.len or self.fixed_words != fixed.coefficient_cells or self.main_words != main.coefficient_cells) return error.NativeStage2ResidentColumnsShape;
        self.fixed_offsets = fixed.offsets;
        self.main_offsets = main.offsets;
    }

    /// Every patch table in bounds of its source and target (warm, once).
    pub fn validate(self: *const ClassFraming) !void {
        if (self.semantic_words < 8 * @as(usize, semantic_felts) or self.semantic_words % 8 != 0) return error.NativeStage2PatchTable;
        var k: usize = 0;
        for (self.slots) |s| if (s.global) |g| {
            if (k >= self.global_patches.len) return error.NativeStage2PatchTable;
            try self.global_patches[k].checkWithPublic(self.semantic_words, g.plan.parameters.len, self.public_input_felts);
            k += 1;
        };
        if (k != self.global_patches.len) return error.NativeStage2PatchTable;
        try self.comp_patches.checkWithPublic(self.semantic_words, self.composition.table.len, self.public_input_felts);
        if (self.oods) |d| try checkOods(d, &self.program, self.composition.table.len);
    }
    pub fn uses(self: *const ClassFraming, source: Source) bool {
        if (self.comp_patches.get(source).len() != 0) return true;
        for (self.global_patches) |p| if (p.get(source).len() != 0) return true;
        return false;
    }
    pub fn deviceWords(self: *const ClassFraming) usize {
        var n = self.program.words.len;
        for (self.global_patches) |p| n += p.words();
        return n + self.comp_patches.words() + if (self.oods) |d| d.len else 0;
    }
    /// The class-cache image: program, then per patch set (globals in order,
    /// then the composition) per source (`sources` order) the dst and index
    /// tables.
    pub fn image(self: *const ClassFraming, a: std.mem.Allocator) ![]u32 {
        const out = try a.alloc(u32, self.deviceWords());
        var at: usize = 0;
        @memcpy(out[0..self.program.words.len], self.program.words);
        at += self.program.words.len;
        const all = [_][]const PatchSet{ self.global_patches, &.{self.comp_patches} };
        for (all) |group| for (group) |set| for (sources) |source| {
            const p = set.get(source);
            @memcpy(out[at..][0..p.len()], p.dst);
            at += p.len();
            @memcpy(out[at..][0..p.len()], p.index);
            at += p.len();
        };
        if (self.oods) |d| {
            @memcpy(out[at..][0..d.len], d);
            at += d.len;
        }
        std.debug.assert(at == out.len);
        return out;
    }
    pub const PatchView = struct { dst: api.DeviceBuffer, index: api.DeviceBuffer };
    pub const SetView = [sources.len]PatchView;
    pub const Views = struct {
        program: api.DeviceBuffer,
        globals: []SetView,
        composition: SetView,
        oods: ?api.DeviceBuffer = null,
    };
    pub fn views(self: *const ClassFraming, a: std.mem.Allocator, device: api.DeviceBuffer) !Views {
        if (device.words < self.deviceWords()) return error.NativeStage2ClassImage;
        var at: usize = self.program.words.len;
        const g = try a.alloc(SetView, self.global_patches.len);
        errdefer a.free(g);
        const take = struct {
            fn f(d: api.DeviceBuffer, cursor: *usize, set: PatchSet) !SetView {
                var v: SetView = undefined;
                for (sources, &v) |source, *pv| {
                    const n = set.get(source).len();
                    pv.* = .{ .dst = try d.slice(cursor.*, n), .index = try d.slice(cursor.* + n, n) };
                    cursor.* += 2 * n;
                }
                return v;
            }
        }.f;
        for (self.global_patches, g) |p, *v| v.* = try take(device, &at, p);
        const comp = try take(device, &at, self.comp_patches);
        const oods: ?api.DeviceBuffer = if (self.oods) |d| try device.slice(at, d.len) else null;
        return .{ .program = try device.slice(0, self.program.words.len), .globals = g, .composition = comp, .oods = oods };
    }
};

/// A class OODS program fits its PCS image (sample count of the encode
/// program) and its composition table (warm, once).
pub fn checkOods(d: []const u32, program: *const NE.Program, table_words: usize) !void {
    try NO.validate(d);
    if (d[NO.H.samples] != program.get(.sample_count) or d[NO.H.table_words] > table_words) return error.NativeStage2OodsProgram;
}

/// Per-request inputs Stage 2 reads that are request public data (known on
/// the host before proving, uploaded with the job): the RAM boundary tuples
/// (capture output: 14 canonical words per cell).
pub const RequestInputs = struct {
    leaf_program: ?*const LF.Program = null,
    /// Explicit diagnostic run only: append the OODS inputs to the existing
    /// request readback. Never changes proof bytes or any acceptance check.
    oods_diagnostic: bool = false,
    initial_tuples: []const u32 = &.{},
    terminal_tuples: []const u32 = &.{},
    /// The segment's public parameter namespace (`public_felts` x 8 canonical
    /// words, JP slot order): its statement values from capture. Required
    /// when the class patches any public slot (ClassFraming.uses(.public)).
    public: []const u32 = &.{},
};

pub fn oodsDiagnosticWords(c: *const ClassFraming) usize {
    return 57 + c.composition.table.len + 8 * @as(usize, c.program.get(.sample_count));
}

pub fn requestPinnedWords(c: *const ClassFraming, inputs: RequestInputs) usize {
    var words = @as(usize, @intCast(c.pcs.ingressWords())) + c.composition.table.len + 8 * c.inter.logs.len + inputs.initial_tuples.len + inputs.terminal_tuples.len + inputs.public.len + 64 * 64;
    for (c.slots) |slot| if (slot.global) |g| {
        words += g.plan.parameters.len;
    };
    return words;
}

pub const Symbols = struct {
    encode: NE.Symbols,
    seal: SealSymbols,
    commit: C.Symbols,
    pcs: N.Symbols,
    composition: NComp.Symbols,
    global: Gl.Symbols,
    /// Check.oods_constraint kernel (addon); null leaves the word unset.
    oods: ?NO.Symbols = null,
    leaf: ?LF.EncodeFn = null,
};

/// Stage 2 of one segment (NativeFactory.stage2), fully enqueued: no host
/// wait, no readback, writes only device memory and the request slab.
pub const Stage2Job = @import("native_stage2_job.zig").Stage2Job;

pub const Hooks = @import("native_device.zig").Stage2Hooks;

pub fn imageKey(class: G.ClassKey) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gn-stage2-image/v1");
    h.update(&class);
    return h.finalResult();
}

// ---------------------------------------------------------------------------
// Factory: class registry (warm) + per-request inputs -> jobs
// ---------------------------------------------------------------------------

/// What native_device.zig delegates `warm` (Stage-2 classes), `seal` and
/// `stage2` to. Classes are registered by the warm path (one ClassFraming per
/// segment class, built from the class geometry) and inserted into the
/// ClassCache; after `ClassCache.seal` an unknown class fails closed
/// (GpuNativeClassNotWarmed). Per request, the driver hands the roster and
/// the request public inputs (`beginRequest`) before submitting jobs.
/// Domain-separated Stage-2 cache key of a native class. Shared by the
/// install builder and request-local resolver (never keyed by ordinal alone).
pub fn framingKey(key: G.ClassKey) G.ClassKey {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gn-shape-framing/v1");
    h.update(&key);
    return h.finalResult();
}

pub const Factory = @import("native_stage2_factory.zig").Factory;

// ---------------------------------------------------------------------------
// Host tests (no GPU)
// ---------------------------------------------------------------------------

pub const hostChi = @import("native_device_stage2_test.zig").hostChi;
pub const testRoster = @import("native_device_stage2_test.zig").testRoster;
test {
    _ = @import("native_device_stage2_test.zig");
    _ = @import("native_stage2_factory.zig");
}
