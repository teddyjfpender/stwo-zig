//! M8 GPU-native request contract (design/riscv-proving-stack/rv64-m8-gpu-native.md).
//!
//! Under STWO_RV64_M8_JOBS=1 the end-state request is: capture streams trace
//! chunks (the only CPU compute on the request path, overlapping proving) ->
//! everything else is enqueued device work on the two GPUs -> ONE host wait
//! per request -> one readback of the finished request slab per GPU -> the
//! host checks status words and publishes. This file is the shared contract
//! the three streams (driver, native, recursion) build against without
//! touching each other's files:
//!
//!   Check / Verdict      status-word ids and the accept/reject encoding
//!   ProofKind / ProofId  every proof a request publishes
//!   RequestLayout        the request slab: header, directory, status words,
//!                        peer-exchange region, encoded proof regions
//!   Exchange / PeerExchange  roots/claims/chi partials swapped between GPUs
//!   ClassCache           per-class setup built at install/warm time only
//!   DeviceCheck          an acceptance check as an enqueued kernel
//!   ProofEncoder         device proof encoding into a slab region
//!   MemoryPlan           one static plan per GPU (no request-path cudaMalloc)
//!   CaptureSink          streaming capture -> device witness hand-off
//!   NativeFactory / RecursionFactory  what the driver asks the other streams
//!   Publication          the host's only job: check the words, slice bytes
//!
//! Ownership: the contract steward is the driver stream. Changes are additive
//! and announced in /workspace/m3/M8-INTERFACES.md; streams never edit it to
//! suit themselves. No proof byte depends on this file (layout only).
const std = @import("std");
const api = @import("api.zig");

pub const contract_version: u32 = 1;
// Contract additions (driver, M8-INTERFACES "m8-gpu-driver"), all defaulted so
// existing initializers compile unchanged:
//   ClassEntry.main_resident_words / arena_peak_words / claims_per_segment /
//   cost_us  (the driver plans placement, the memory plan and the exchange
//   from class constants); RequestContext.main_resident / segment_device /
//   generation (the plan's per-segment MAIN views; where each segment runs).
pub const slab_magic: u32 = 0x4e475652; // "RVGN" little-endian

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

/// A status word is written by exactly one device check. It starts as
/// `Verdict.unset` (the driver's slab-init memset), so a check that never ran
/// rejects. `accepted` is 0; any other value is a reject code
/// (`Verdict.reject(check, detail)`).
pub const Verdict = struct {
    pub const unset: u32 = 0xffff_ffff;
    pub const accepted: u32 = 0;
    /// Reject code: high half = check id, low half = check-specific detail
    /// (nonzero). Never equals `accepted` or `unset`.
    pub fn reject(check: Check, detail: u16) u32 {
        const d: u32 = if (detail == 0) 1 else detail;
        return (@as(u32, @intFromEnum(check)) << 16) | d;
    }
    pub fn checkOf(word: u32) ?Check {
        if (word == unset or word == accepted) return null;
        return std.meta.intToEnum(Check, @as(u16, @truncate(word >> 16))) catch null;
    }
};

/// Status-word ids. Ranges: 0x01xx driver, 0x02xx native, 0x03xx recursion,
/// so a stream adds ids inside its range without colliding (append only;
/// values are stable, they appear in receipts).
pub const Check = enum(u16) {
    // driver (0x01xx): transcript and request-level
    channel_order = 0x0101, // device channel step/chain protocol latch
    exchange_complete = 0x0102, // every peer root/claim slot written once
    global_seal = 0x0103, // global chi / manifest closure over all segments
    encode_bounds = 0x0104, // every encoder wrote <= its region capacity
    // native (0x02xx): one set per native segment proof
    witness_status = 0x0201, // device witness generation (range/shape flags)
    binding_authority = 0x0202, // GKR terminal state == binding authority (was NB.checkAuthority)
    global_status = 0x0203, // global interaction witness status (was job.global_status loop)
    composition_accept = 0x0204, // composition role status (was native_stage2.accept)
    oods_constraint = 0x0205, // composition(OODS) == extracted eval (was host evalCompositionPolynomialAtPoint)
    public_claims = 0x0206, // device publicClaims reduction (was CW.publicClaims)
    pcs_status = 0x0207, // enqueue-only PCS pipeline status plane
    root_match = 0x0208, // FIXED/MAIN roots equal the class/statement roots
    // recursion (0x03xx): truth proofs and outer nodes
    truth_status = 0x0301, // truth_source / truth_composition / truth_pcs
    lookup_sum = 0x0302, // outer node LogUp sum == 0 (was host lookup status)
    node_oods_constraint = 0x0303, // outer node composition at OODS (was assemble's host check)
    node_pcs_status = 0x0304,
    seed_tape = 0x0305, // device seed fill from child slab matches class template
    child_binding = 0x0306, // node statement binds its children's encoded proofs
};

/// Status checks every proof of a kind must carry (the driver reserves these
/// words in the directory entry; extra checks may be appended by the owner).
pub fn requiredChecks(kind: ProofKind) []const Check {
    return switch (kind) {
        .native_segment => &.{ .channel_order, .witness_status, .binding_authority, .global_status, .composition_accept, .oods_constraint, .public_claims, .pcs_status, .root_match, .encode_bounds },
        .truth => &.{ .channel_order, .truth_status, .pcs_status, .encode_bounds },
        .leaf, .fold, .root => &.{ .channel_order, .seed_tape, .child_binding, .lookup_sum, .node_oods_constraint, .node_pcs_status, .encode_bounds },
        .request => &.{ .global_seal, .exchange_complete },
    };
}

// ---------------------------------------------------------------------------
// Proofs of a request
// ---------------------------------------------------------------------------

pub const ProofKind = enum(u8) {
    /// Request-level pseudo-proof: carries the request status words only.
    request = 0,
    native_segment = 1,
    truth = 2,
    leaf = 3,
    fold = 4,
    root = 5,
};

pub const ProofId = struct {
    kind: ProofKind,
    ordinal: u32,
    pub fn eql(a: ProofId, b: ProofId) bool {
        return a.kind == b.kind and a.ordinal == b.ordinal;
    }
};

/// What a stream declares per proof class (from its ClassCache entry):
/// the worst-case encoded size and any status words beyond `requiredChecks`.
pub const ProofSpec = struct {
    id: ProofId,
    /// GPU that produces (and whose slab segment holds) this proof.
    device: u32,
    /// Upper bound of the encoded proof bytes (class constant).
    max_encoded_bytes: usize,
    extra_checks: []const Check = &.{},
};

// ---------------------------------------------------------------------------
// Request slab layout
// ---------------------------------------------------------------------------
//
// One slab segment per GPU, pinned host mirror of the same size. Word layout
// of a segment (all offsets in u32 words, regions 64-word aligned):
//
//   header      16 words   magic, version, request, device, n_entries,
//                          status_words, exchange_offset, exchange_words,
//                          encoded_offset, encoded_words, segment_words, 0...
//   directory   n_entries * 8 words (Entry, below)
//   status      sum of entry status counts (Verdict words)
//   exchange    Exchange.words() (peer-copied roots/claims/chi partials)
//   encoded     per entry: 1 length word (bytes written by the encoder) +
//               ceil(max_encoded_bytes / 4) words of proof bytes
//
// The directory is written by the host at plan time (it is class geometry,
// identical every request of a class mix); status/length words are written
// by device kernels; the host reads them after the single wait.

pub const header_words: usize = 16;
pub const entry_words: usize = 8;
pub const region_align: usize = 64;

pub const Entry = extern struct {
    kind: u32,
    ordinal: u32,
    status_first: u32, // word offset of the first status word (segment relative)
    status_count: u32,
    encoded_offset: u32, // word offset of the length word; bytes follow
    encoded_capacity_words: u32,
    first_check: u32, // index into the segment's check-id table (host side)
    reserved: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != entry_words * 4) @compileError("Entry must be 8 words");
}

pub const SegmentLayout = struct {
    device: u32,
    entries: []Entry,
    /// Check id of each status word, in status order (host side, for decoding).
    checks: []Check,
    ids: []ProofId,
    status_offset: usize,
    status_words: usize,
    exchange_offset: usize,
    exchange_words: usize,
    encoded_offset: usize,
    encoded_words: usize,
    words: usize,

    pub fn find(self: *const SegmentLayout, id: ProofId) ?usize {
        for (self.ids, 0..) |x, i| if (x.eql(id)) return i;
        return null;
    }
    /// Segment-relative word offset of a proof's status word for `check`.
    pub fn statusWord(self: *const SegmentLayout, id: ProofId, check: Check) !usize {
        const i = self.find(id) orelse return error.GpuNativeUnknownProof;
        const e = self.entries[i];
        const first = e.first_check;
        for (self.checks[first..][0..e.status_count], 0..) |c, k| if (c == check) return e.status_first + k;
        return error.GpuNativeUnknownCheck;
    }
    /// Device view of a status word inside the segment buffer.
    pub fn statusBuffer(self: *const SegmentLayout, segment: api.DeviceBuffer, id: ProofId, check: Check) !api.DeviceBuffer {
        return segment.slice(try self.statusWord(id, check), 1);
    }
    /// Device view of an encoded region: length word followed by the bytes.
    pub fn encodedBuffer(self: *const SegmentLayout, segment: api.DeviceBuffer, id: ProofId) !api.DeviceBuffer {
        const i = self.find(id) orelse return error.GpuNativeUnknownProof;
        const e = self.entries[i];
        return segment.slice(e.encoded_offset, 1 + e.encoded_capacity_words);
    }
    pub fn exchangeBuffer(self: *const SegmentLayout, segment: api.DeviceBuffer) !api.DeviceBuffer {
        return segment.slice(self.exchange_offset, self.exchange_words);
    }
    /// The host-written prefix (header + directory), uploaded once per class
    /// mix and re-used across requests.
    pub fn prefix(self: *const SegmentLayout, out: []u32, request: u64) !void {
        if (out.len < self.status_offset) return error.GpuNativeSlabTooSmall;
        @memset(out[0..self.status_offset], 0);
        const h = [header_words]u32{ slab_magic, contract_version, @truncate(request), self.device, @intCast(self.entries.len), @intCast(self.status_words), @intCast(self.exchange_offset), @intCast(self.exchange_words), @intCast(self.encoded_offset), @intCast(self.encoded_words), @intCast(self.words), 0, 0, 0, 0, 0 };
        @memcpy(out[0..header_words], &h);
        const dir = std.mem.bytesAsSlice(Entry, std.mem.sliceAsBytes(out[header_words..][0 .. self.entries.len * entry_words]));
        for (dir, self.entries) |*d, e| d.* = e;
    }
};

pub const RequestLayout = struct {
    a: std.mem.Allocator,
    segments: []SegmentLayout,

    /// Plan the request slab from the proofs' class specs (host, at request
    /// plan time from cached class constants: no device work, no waits).
    pub fn build(a: std.mem.Allocator, devices: u32, proofs: []const ProofSpec, exchange: Exchange) !RequestLayout {
        if (devices == 0) return error.GpuNativeNoDevices;
        const segments = try a.alloc(SegmentLayout, devices);
        var built: usize = 0;
        errdefer {
            for (segments[0..built]) |s| freeSegment(a, s);
            a.free(segments);
        }
        for (segments, 0..) |*s, d| {
            s.* = try buildSegment(a, @intCast(d), proofs, exchange);
            built += 1;
        }
        // Every proof id appears exactly once across the request.
        for (proofs, 0..) |p, i| {
            if (p.device >= devices) return error.GpuNativeProofDeviceOutOfRange;
            for (proofs[0..i]) |q| if (q.id.eql(p.id)) return error.GpuNativeDuplicateProof;
        }
        return .{ .a = a, .segments = segments };
    }
    pub fn deinit(self: *RequestLayout) void {
        for (self.segments) |s| freeSegment(self.a, s);
        self.a.free(self.segments);
    }
    pub fn totalWords(self: *const RequestLayout) usize {
        var n: usize = 0;
        for (self.segments) |s| n += s.words;
        return n;
    }

    fn freeSegment(a: std.mem.Allocator, s: SegmentLayout) void {
        a.free(s.entries);
        a.free(s.checks);
        a.free(s.ids);
    }
    fn alignUp(x: usize) usize {
        return std.mem.alignForward(usize, x, region_align);
    }
    fn buildSegment(a: std.mem.Allocator, device: u32, proofs: []const ProofSpec, exchange: Exchange) !SegmentLayout {
        var n: usize = 0;
        var n_checks: usize = 0;
        for (proofs) |p| if (p.device == device) {
            n += 1;
            n_checks += requiredChecks(p.id.kind).len + p.extra_checks.len;
        };
        const entries = try a.alloc(Entry, n);
        errdefer a.free(entries);
        const checks = try a.alloc(Check, n_checks);
        errdefer a.free(checks);
        const ids = try a.alloc(ProofId, n);
        errdefer a.free(ids);
        const status_offset = alignUp(header_words + n * entry_words);
        const exchange_offset = alignUp(status_offset + n_checks);
        const exchange_words = exchange.words();
        const encoded_offset = alignUp(exchange_offset + exchange_words);
        var at_check: usize = 0;
        var at_encoded = encoded_offset;
        var i: usize = 0;
        for (proofs) |p| if (p.device == device) {
            const req = requiredChecks(p.id.kind);
            const count = req.len + p.extra_checks.len;
            @memcpy(checks[at_check..][0..req.len], req);
            @memcpy(checks[at_check + req.len ..][0..p.extra_checks.len], p.extra_checks);
            for (checks[at_check..][0..count], 0..) |c, k| for (checks[at_check..][0..k]) |prev| if (prev == c) return error.GpuNativeDuplicateCheck;
            const cap = std.math.divCeil(usize, p.max_encoded_bytes, 4) catch unreachable;
            entries[i] = .{ .kind = @intFromEnum(p.id.kind), .ordinal = p.id.ordinal, .status_first = @intCast(status_offset + at_check), .status_count = @intCast(count), .encoded_offset = @intCast(at_encoded), .encoded_capacity_words = @intCast(cap), .first_check = @intCast(at_check) };
            ids[i] = p.id;
            at_check += count;
            at_encoded = alignUp(at_encoded + 1 + cap);
            i += 1;
        };
        if (at_encoded > std.math.maxInt(u32)) return error.GpuNativeSlabTooLarge;
        return .{ .device = device, .entries = entries, .checks = checks, .ids = ids, .status_offset = status_offset, .status_words = n_checks, .exchange_offset = exchange_offset, .exchange_words = exchange_words, .encoded_offset = encoded_offset, .encoded_words = at_encoded - encoded_offset, .words = at_encoded };
    }
};

// ---------------------------------------------------------------------------
// Peer exchange (the only cross-GPU traffic of a request)
// ---------------------------------------------------------------------------

/// The exchange region is replicated in every GPU's segment. Each segment
/// writes its own slots locally, then peer-copies them into the other GPUs'
/// replicas; a consumer waits (on device) for the producer's event. Slots:
///   roots    per native segment: stage-1 MAIN root (8 words)
///   claims   per native segment: `claims_per_segment` secure felts (8 words each)
///   partials per device: the device's global chi / LogUp partial (8 words)
///   seal     one 16-word channel checkpoint after the global seal (written
///            by the seal device, peer-copied to the others)
/// Every slot has one "written" flag word (set by the producer's copy, checked
/// by `Check.exchange_complete`). The flag value is the request's
/// `flagTag(generation)`, not a constant: replicas are never zeroed per
/// request (a consumer GPU's zero fill is not ordered against a producer
/// GPU's peer copy, so it could erase a slot that already landed), and a
/// stale flag of an earlier request in the same slab parity carries another
/// tag, so it can never satisfy this request's check.
pub const Exchange = struct {
    /// Flag value of request `generation`: never 0 (install zeroes the slabs)
    /// nor `Verdict.unset`; repeats only after 2^32 - 2 requests.
    pub fn flagTag(generation: u64) u32 {
        return @as(u32, @intCast(generation % 0xffff_fffe)) + 1;
    }

    segments: u32,
    claims_per_segment: u32,
    devices: u32,
    pub fn rootWords(self: Exchange) usize {
        return @as(usize, self.segments) * 8;
    }
    pub fn claimWords(self: Exchange) usize {
        return @as(usize, self.segments) * self.claims_per_segment * 8;
    }
    pub fn partialWords(self: Exchange) usize {
        return @as(usize, self.devices) * 8;
    }
    pub const seal_words: usize = 16;
    pub fn flagWords(self: Exchange) usize {
        return @as(usize, self.segments) * 2 + self.devices + 1;
    }
    pub fn words(self: Exchange) usize {
        return self.rootWords() + self.claimWords() + self.partialWords() + seal_words + self.flagWords();
    }
    pub const Slot = struct { offset: usize, words: usize, flag: usize };
    pub fn root(self: Exchange, segment: u32) !Slot {
        if (segment >= self.segments) return error.GpuNativeExchangeSlot;
        return .{ .offset = @as(usize, segment) * 8, .words = 8, .flag = self.flagBase() + segment };
    }
    pub fn claims(self: Exchange, segment: u32) !Slot {
        if (segment >= self.segments) return error.GpuNativeExchangeSlot;
        const per = @as(usize, self.claims_per_segment) * 8;
        return .{ .offset = self.rootWords() + segment * per, .words = per, .flag = self.flagBase() + self.segments + segment };
    }
    pub fn partial(self: Exchange, device: u32) !Slot {
        if (device >= self.devices) return error.GpuNativeExchangeSlot;
        return .{ .offset = self.rootWords() + self.claimWords() + @as(usize, device) * 8, .words = 8, .flag = self.flagBase() + 2 * self.segments + device };
    }
    pub fn seal(self: Exchange) Slot {
        return .{ .offset = self.rootWords() + self.claimWords() + self.partialWords(), .words = seal_words, .flag = self.flagBase() + 2 * self.segments + self.devices };
    }
    fn flagBase(self: Exchange) usize {
        return self.rootWords() + self.claimWords() + self.partialWords() + seal_words;
    }
};

/// Enqueue-only peer copies between the GPUs' exchange replicas. Driver
/// implements it over cudaMemcpyPeerAsync + cross-device events (addon
/// `NAT/rv64/jobs/peer_ops.cu`); the host never reads an exchanged value.
pub const PeerExchange = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        /// Copy `slot` of `src_device`'s replica into every other replica on
        /// `src_device`'s exec stream; records the slot's ready event.
        publish: *const fn (*anyopaque, src_device: u32, slot: Exchange.Slot) anyerror!void,
        /// Make `device`'s exec stream wait (on device) until `slot` from
        /// `src_device` has landed in `device`'s replica.
        await_slot: *const fn (*anyopaque, device: u32, src_device: u32, slot: Exchange.Slot) anyerror!void,
    };
    pub fn publish(self: PeerExchange, src_device: u32, slot: Exchange.Slot) !void {
        return self.vtable.publish(self.ctx, src_device, slot);
    }
    pub fn awaitSlot(self: PeerExchange, device: u32, src_device: u32, slot: Exchange.Slot) !void {
        return self.vtable.await_slot(self.ctx, device, src_device, slot);
    }
};

// ---------------------------------------------------------------------------
// Per-class setup cache (built at install/warm time, never per request)
// ---------------------------------------------------------------------------

pub const ClassKey = [32]u8;

pub const Phase = enum { warm, request };

/// One cached class: host plan (opaque, owned by the stream that built it)
/// plus device-resident regions on each GPU that kernels read.
pub const ClassEntry = struct {
    key: ClassKey,
    /// Stream-owned host plan (component Sets, mask points, PcsJob framing,
    /// composition/INTER plans, outer node tapes, ...). Never mutated after warm.
    plan: *anyopaque,
    destroy: *const fn (*anyopaque) void,
    /// Device-resident constants per GPU (twiddles, FIXED trees, class tapes,
    /// directory prefixes); `null` on a GPU the class never runs on.
    device: [max_devices]?api.DeviceBuffer = @splat(null),
    /// Proof spec constants the driver plans the slab from.
    max_encoded_bytes: usize = 0,
    extra_checks: []const Check = &.{},
    /// Captured whole-job CUDA graph executable per GPU (opaque; null = direct
    /// enqueue). A graph that bakes arena or main_resident addresses is
    /// captured in the factory's `installed` hook, never in `warm`.
    graph: [max_devices]?*anyopaque = @splat(null),
    /// Native segment classes: MAIN words kept resident witness -> PCS (the
    /// driver carves them from the main_resident region; 0 = none).
    main_resident_words: usize = 0,
    /// Measured arena peak of one job of this class (plan.zig sweep).
    arena_peak_words: usize = 0,
    /// Native segment classes: secure-felt claim blocks this segment publishes.
    claims_per_segment: u32 = 0,
    /// Estimated device time of one job of this class (placement weight only).
    cost_us: u64 = 1,
};

pub const max_devices = 4;

/// Thread-safe map from class key to entry. In `.request` phase a miss is an
/// error (a class must be warmed at install time): that is how "never per
/// request" is enforced rather than hoped for.
pub const ClassCache = struct {
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    map: std.AutoHashMapUnmanaged(ClassKey, *ClassEntry) = .empty,
    phase: Phase = .warm,
    builds: u64 = 0,
    request_misses: u64 = 0,

    pub const Builder = struct {
        ctx: *anyopaque,
        build: *const fn (*anyopaque, std.mem.Allocator, ClassKey) anyerror!ClassEntry,
    };

    pub fn init(a: std.mem.Allocator) ClassCache {
        return .{ .a = a };
    }
    pub fn deinit(self: *ClassCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            e.*.destroy(e.*.plan);
            self.a.destroy(e.*);
        }
        self.map.deinit(self.a);
    }
    /// Close the warm phase: from now on every lookup must hit.
    pub fn seal(self: *ClassCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.phase = .request;
    }
    /// Re-open warm (a new class mix discovered at install, never mid-request).
    pub fn reopen(self: *ClassCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.phase = .warm;
    }
    pub fn get(self: *ClassCache, key: ClassKey) !*const ClassEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.map.get(key)) |e| return e;
        self.request_misses += 1;
        return error.GpuNativeClassNotWarmed;
    }
    /// Warm phase only: build (once) and insert.
    pub fn warm(self: *ClassCache, key: ClassKey, builder: Builder) !*const ClassEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.map.get(key)) |e| return e;
        if (self.phase != .warm) {
            self.request_misses += 1;
            return error.GpuNativeClassBuildOnRequestPath;
        }
        const entry = try self.a.create(ClassEntry);
        errdefer self.a.destroy(entry);
        entry.* = try builder.build(builder.ctx, self.a, key);
        if (!std.mem.eql(u8, &entry.key, &key)) {
            entry.destroy(entry.plan);
            return error.GpuNativeClassKeyMismatch;
        }
        try self.map.put(self.a, key, entry);
        self.builds += 1;
        return entry;
    }
    pub fn count(self: *ClassCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.count();
    }
};

// ---------------------------------------------------------------------------
// Device acceptance checks and encoders
// ---------------------------------------------------------------------------

/// An acceptance check as an enqueued kernel: reads device inputs, writes
/// exactly one Verdict word. Never reads back, never branches the host.
pub const DeviceCheck = struct {
    check: Check,
    ctx: *anyopaque,
    enqueue: *const fn (*anyopaque, *api.Enqueue, status: api.DeviceBuffer) anyerror!void,
    pub fn run(self: DeviceCheck, e: *api.Enqueue, layout: *const SegmentLayout, segment: api.DeviceBuffer, id: ProofId) !void {
        const word = try layout.statusBuffer(segment, id, self.check);
        return self.enqueue(self.ctx, e, word);
    }
};

/// Device proof encoding: writes today's exact proof bytes (the
/// `WP.encodePhysical` / om31 wrapped encoding) into `region[1..]` and the
/// byte length into `region[0]`. Bounds failure writes `encode_bounds`.
pub const ProofEncoder = struct {
    ctx: *anyopaque,
    enqueue: *const fn (*anyopaque, *api.Enqueue, region: api.DeviceBuffer, status: api.DeviceBuffer) anyerror!void,
    pub fn run(self: ProofEncoder, e: *api.Enqueue, layout: *const SegmentLayout, segment: api.DeviceBuffer, id: ProofId) !void {
        return self.enqueue(self.ctx, e, try layout.encodedBuffer(segment, id), try layout.statusBuffer(segment, id, .encode_bounds));
    }
};

// ---------------------------------------------------------------------------
// Memory plan (one per GPU)
// ---------------------------------------------------------------------------

pub const RegionKind = enum(u8) {
    class_cache, // per-class constants (twiddles, FIXED trees, tapes): install-time
    graph_exec, // captured graph executables (driver budget)
    main_resident, // MAIN coefficients/trees of every segment on this GPU, witness -> PCS
    arena, // two-sided job arena (worker): one job in flight + one staged
    truth, // truth-job working set (inside the plan, never a lease)
    exchange_slab, // request slab segment + its pinned mirror size
    reserve, // driver/CUDA headroom
};

pub const Region = struct { kind: RegionKind, words: u64 };

/// Every request-path allocation comes from one of these regions; nothing on
/// the request path calls cudaMalloc outside them (`outside_words` == 0 is a
/// plan invariant the worker enforces).
pub const MemoryPlan = struct {
    device: u32,
    capacity_words: u64,
    regions: [std.meta.fields(RegionKind).len]u64 = @splat(0),

    pub fn set(self: *MemoryPlan, kind: RegionKind, words: u64) void {
        self.regions[@intFromEnum(kind)] = words;
    }
    pub fn get(self: *const MemoryPlan, kind: RegionKind) u64 {
        return self.regions[@intFromEnum(kind)];
    }
    pub fn total(self: *const MemoryPlan) u64 {
        var n: u64 = 0;
        for (self.regions) |w| n += w;
        return n;
    }
    pub fn validate(self: *const MemoryPlan) !void {
        if (self.total() > self.capacity_words) return error.GpuNativeMemoryPlanExceedsDevice;
        if (self.get(.arena) == 0) return error.GpuNativeMemoryPlanNoArena;
        if (self.get(.exchange_slab) == 0) return error.GpuNativeMemoryPlanNoSlab;
    }
    /// Region base offsets in a fixed order (class cache lowest: it outlives
    /// requests; arena last: it may grow into the reserve at install).
    pub fn offset(self: *const MemoryPlan, kind: RegionKind) u64 {
        var at: u64 = 0;
        for (0..@intFromEnum(kind)) |k| at += self.regions[k];
        return at;
    }
};

// ---------------------------------------------------------------------------
// Streaming capture -> device witness hand-off
// ---------------------------------------------------------------------------

/// One chunk of captured trace for a native segment, in pinned host memory
/// owned by the capture ring. The driver uploads it on the h2d stream and
/// hands the device view to the segment's witness job; `release` returns the
/// ring slot once the upload event has fired (host-fn, no host wait).
pub const TraceChunk = struct {
    segment: u32,
    sequence: u32,
    first_row: u64,
    rows: u32,
    last: bool,
    words: []const u32,
};

pub const CaptureSink = struct {
    ctx: *anyopaque,
    /// Called on the capture thread; must not block on the GPU.
    chunk: *const fn (*anyopaque, TraceChunk) anyerror!void,
    /// Segment geometry is final (row count, log): stage-1 may be released.
    sealed_segment: *const fn (*anyopaque, segment: u32, rows: u64) anyerror!void,
    /// Capture finished (segment count final).
    done: *const fn (*anyopaque, segments: u32) anyerror!void,
};

// ---------------------------------------------------------------------------
// What the driver asks of the native and recursion streams
// ---------------------------------------------------------------------------

/// Request-scoped context every factory call receives.
pub const RequestContext = struct {
    request: u64,
    layout: *const RequestLayout,
    exchange: Exchange,
    peer: PeerExchange,
    classes: *ClassCache,
    /// Device segment buffers of the request slab, indexed by device.
    segments: []const api.DeviceBuffer,
    /// Per native segment: its MAIN view inside its GPU's main_resident
    /// region (resident witness -> PCS; never allocated per request).
    main_resident: []const api.DeviceBuffer = &.{},
    /// Per native segment: the GPU its Stage1 and Stage2 run on.
    segment_device: []const u32 = &.{},
    /// Request generation (1-based, unique per driver; peer-slot protocol).
    generation: u64 = 0,
};

/// Handed to the factories' `installed` hook. `warm` runs BEFORE the plan
/// exists (the plan is sized from the warmed classes), and installing the
/// plan frees the worker's previous arena: a graph captured in `warm` that
/// bakes arena addresses would dangle. Such graphs are captured in
/// `installed` instead (the class cache is sealed only after it). Per device:
/// the main_resident region and the worker's arena epoch of plan phase A and
/// phase B (stable for the service's life; key graph executables on them).
pub const Installed = struct {
    devices: u32,
    main_resident: [max_devices]api.DeviceBuffer = undefined,
    arena_epochs: [max_devices][2]u64 = @splat(.{ 0, 0 }),
};

/// Stream native implements this (jobs/native_device.zig).
pub const NativeFactory = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        /// Install time: warm every class of the manifest's class mix.
        warm: *const fn (*anyopaque, *ClassCache) anyerror!void,
        /// Install time, after the memory plan is installed (see `Installed`):
        /// capture every graph that bakes arena / main_resident addresses.
        installed: ?*const fn (*anyopaque, *ClassCache, *const Installed) anyerror!void = null,
        /// Class of a native segment (from capture geometry).
        class_of: *const fn (*anyopaque, segment: u32, rows: u64) anyerror!ClassKey,
        /// Stage 1 (witness from trace chunks, FIXED adoption, MAIN commit into
        /// main_resident, local GKR, binding): publishes root + claims slots.
        stage1: *const fn (*anyopaque, *const RequestContext, segment: u32, device: u32) anyerror!api.Job,
        /// Stage 2 (after the device seal): globals, INTER, composition, OODS,
        /// PCS, checks, encoding into the segment's encoded region.
        stage2: *const fn (*anyopaque, *const RequestContext, segment: u32, device: u32) anyerror!api.Job,
        /// Device-side global seal over all segments (on `device`, after every
        /// root/claims slot landed): writes the seal checkpoint slot.
        seal: *const fn (*anyopaque, *const RequestContext, device: u32) anyerror!api.Job,
        /// Hand-off of captured trace chunks (driver calls it from the sink).
        chunk: *const fn (*anyopaque, *const RequestContext, TraceChunk, device: u32) anyerror!void,
    };
};

/// Stream recursion implements this (jobs/outer_device.zig, jobs/truth_job.zig).
pub const RecursionFactory = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        warm: *const fn (*anyopaque, *ClassCache) anyerror!void,
        /// See NativeFactory.VTable.installed.
        installed: ?*const fn (*anyopaque, *ClassCache, *const Installed) anyerror!void = null,
        class_of: *const fn (*anyopaque, ProofId) anyerror!ClassKey,
        truth: *const fn (*anyopaque, *const RequestContext, ordinal: u32, device: u32) anyerror!api.Job,
        /// Leaf/fold/root node: reads its children's encoded regions (device,
        /// own segment or peer replica) and writes its own.
        node: *const fn (*anyopaque, *const RequestContext, id: ProofId, children: []const ProofId, device: u32) anyerror!api.Job,
    };
};

// ---------------------------------------------------------------------------
// Publication (the host's only per-request computation besides capture)
// ---------------------------------------------------------------------------

pub const Rejection = struct { id: ProofId, check: Check, word: u32 };

pub const Published = struct {
    id: ProofId,
    bytes: []const u8, // view into the pinned mirror: copy before the slot is reused
};

/// Check every status word of every segment and slice the encoded proofs.
/// `mirrors[d]` is device d's pinned segment after the request's single wait.
/// Fails closed: an unset word, a reject code, a header mismatch, or a length
/// beyond capacity refuses the whole request (`first` names the culprit).
pub fn publish(a: std.mem.Allocator, layout: *const RequestLayout, request: u64, mirrors: []const []const u32, first: ?*Rejection) ![]Published {
    if (mirrors.len != layout.segments.len) return error.GpuNativeMirrorCount;
    var n: usize = 0;
    for (layout.segments, mirrors) |s, m| {
        if (m.len < s.words) return error.GpuNativeMirrorTruncated;
        if (m[0] != slab_magic or m[1] != contract_version or m[2] != @as(u32, @truncate(request)) or m[3] != s.device) return error.GpuNativeSlabHeaderMismatch;
        for (s.entries, 0..) |e, i| {
            for (0..e.status_count) |k| {
                const word = m[e.status_first + k];
                if (word != Verdict.accepted) {
                    if (first) |f| f.* = .{ .id = s.ids[i], .check = s.checks[e.first_check + k], .word = word };
                    return error.GpuNativeProofRejected;
                }
            }
            const len = m[e.encoded_offset];
            if (len > @as(usize, e.encoded_capacity_words) * 4) return error.GpuNativeEncodedOverrun;
            n += 1;
        }
    }
    const out = try a.alloc(Published, n);
    var i: usize = 0;
    for (layout.segments, mirrors) |s, m| for (s.entries, s.ids) |e, id| {
        const len = m[e.encoded_offset];
        out[i] = .{ .id = id, .bytes = std.mem.sliceAsBytes(m[e.encoded_offset + 1 ..][0..e.encoded_capacity_words])[0..len] };
        i += 1;
    };
    return out;
}

test {
    _ = @import("gpu_native_test.zig");
}
