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
const Protocol = @import("gpu_native_protocol.zig");
const Classes = @import("gpu_native_classes.zig");

pub const contract_version = Protocol.contract_version;
// Contract additions (driver, M8-INTERFACES "m8-gpu-driver"), all defaulted so
// existing initializers compile unchanged:
//   ClassEntry.main_resident_words / arena_peak_words / claims_per_segment /
//   cost_us  (the driver plans placement, the memory plan and the exchange
//   from class constants); RequestContext.main_resident / segment_device /
//   generation (the plan's per-segment MAIN views; where each segment runs).
// Version 2 (driver review fixes): the exchange region sits at a fixed
//   offset right after the header and is laid out from install capacities
//   (flags first), so a flag word only ever holds flags; the directory
//   follows it; header word `header_completion_word` is device-written by
//   each GPU's batch tail (publish requires it); Exchange.partial_mask (only
//   GPUs hosting segments own a partial); ClassEntry.phase_b / held_words /
//   capture_words; RecursionFactory.class_of takes the node's authority
//   (children's class keys), never a topology ordinal; publish refuses an
//   empty proof.
// API additions (d-wire, M8-INTERFACES "m8-gpu-d-wire"; no slab layout
//   change, version stays 2, every hook optional and defaulted):
//   ClassEntry.stage_one_bytes (the request pseudo-proof's encoded region
//   carries the stage-one bytes the native seal job encodes);
//   ClassEntry.needs_capture_end (truth classes whose inputs are final only
//   when capture ends: the driver gates the job on the capture's end);
//   CapturedSegment / CaptureEnd / ChunkWriter + NativeFactory.pack /
//   .captured and RecursionFactory.captured (streaming capture hand-off);
//   WarmBlock / BlockShape + NativeFactory.shape / RecursionFactory.shape
//   (install-time class mix per block, from one warm capture);
//   Publication + NativeFactory.publish / RecursionFactory.publish (each
//   stream writes its own legacy-format artifacts from the published bytes
//   after the single wait).
// gn-shape addition (M8-INTERFACES "m8-gn-shape", defaulted, no layout
//   change): NativeFactory.VTable.class_of_block (block-qualified class_of).
// r-truth additions (M8-INTERFACES "m8-gpu-r-truth", all defaulted): Check
//   truth_root; Exchange.truths/capacity_truths + truthRoot slot (after the
//   seal; 0 truths = the version-2 layout word for word); the seal slot's
//   digest convention (seal_digest_words); RecursionFactory.truth_stage2.
// gn-s2 addition (M8-INTERFACES "m8-gn-s2", defaulted): Exchange.receipts +
//   receipt(segment) slot (each segment's local-GKR receipt digest, 8 words +
//   flag, appended after the truth roots; receipts=false = the previous layout
//   word for word). The flat (v1-flat, the D2 profile) manifest digest frames
//   it per CPU entry; Stage 1 publishes it, the device seal reads it.
pub const slab_magic = Protocol.slab_magic;

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

/// A status word is written by exactly one device check. It starts as
/// `Verdict.unset` (the driver's slab-init memset), so a check that never ran
/// rejects. `accepted` is 0; any other value is a reject code
/// (`Verdict.reject(check, detail)`).
pub const Verdict = Protocol.Verdict;
pub const Check = Protocol.Check;
pub const requiredChecks = Protocol.requiredChecks;
pub const ProofKind = Protocol.ProofKind;
pub const ProofId = Protocol.ProofId;
pub const ProofSpec = Protocol.ProofSpec;

// ---------------------------------------------------------------------------
// Request slab layout
// ---------------------------------------------------------------------------
//
// One slab segment per GPU, pinned host mirror of the same size. Word layout
// of a segment (all offsets in u32 words, regions 64-word aligned):
//
//   header      16 words   magic, version, request, device, n_entries,
//                          status_words, exchange_offset, exchange_words,
//                          encoded_offset, encoded_words, segment_words,
//                          directory_offset, completion tag (device), 0...
//   exchange    Exchange.words() at a FIXED offset (64): peer-copied flags,
//               roots, claims, chi partials, seal; laid out from install
//               capacities so every request of a service puts each flag
//               word at the same address (a flag word only ever holds a
//               flag tag or 0, never a stale directory/status/data word)
//   directory   n_entries * 8 words (Entry, below)
//   status      sum of entry status counts (Verdict words)
//   encoded     per entry: 1 length word (bytes written by the encoder) +
//               ceil(max_encoded_bytes / 4) words of proof bytes
//
// The header and directory are written by the host at plan time (class
// geometry) and uploaded as two copies (the exchange between them is never
// touched by the host: other GPUs peer-copy into it with no order against
// this GPU's preamble). Status/length words and the completion tag are
// written by device work; the host reads them after the single wait.

pub const header_words = Protocol.header_words;
pub const header_completion_word = Protocol.header_completion_word;
pub const entry_words = Protocol.entry_words;
pub const region_align = Protocol.region_align;
pub const Entry = Protocol.Entry;

pub const SegmentLayout = struct {
    device: u32,
    entries: []Entry,
    /// Check id of each status word, in status order (host side, for decoding).
    checks: []Check,
    ids: []ProofId,
    directory_offset: usize,
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
    /// The host-written prefix: header (`[0, header_words)`) and directory
    /// (`[directory_offset, status_offset)`). The exchange region between
    /// them is left untouched (two uploads, see the layout comment). The
    /// completion word stays 0 (only the device writes the request's tag).
    pub fn prefix(self: *const SegmentLayout, out: []u32, request: u64) !void {
        if (out.len < self.status_offset) return error.GpuNativeSlabTooSmall;
        @memset(out[0..header_words], 0);
        @memset(out[self.directory_offset..self.status_offset], 0);
        const h = [header_words]u32{ slab_magic, contract_version, @truncate(request), self.device, @intCast(self.entries.len), @intCast(self.status_words), @intCast(self.exchange_offset), @intCast(self.exchange_words), @intCast(self.encoded_offset), @intCast(self.encoded_words), @intCast(self.words), @intCast(self.directory_offset), 0, 0, 0, 0 };
        @memcpy(out[0..header_words], &h);
        const dir = std.mem.bytesAsSlice(Entry, std.mem.sliceAsBytes(out[self.directory_offset..][0 .. self.entries.len * entry_words]));
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
        try exchange.validate();
        // Fixed exchange offset (install capacities make its size fixed too).
        const exchange_offset = alignUp(header_words);
        const exchange_words = exchange.words();
        const directory_offset = alignUp(exchange_offset + exchange_words);
        const status_offset = alignUp(directory_offset + n * entry_words);
        const encoded_offset = alignUp(status_offset + n_checks);
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
        return .{ .device = device, .entries = entries, .checks = checks, .ids = ids, .directory_offset = directory_offset, .status_offset = status_offset, .status_words = n_checks, .exchange_offset = exchange_offset, .exchange_words = exchange_words, .encoded_offset = encoded_offset, .encoded_words = at_encoded - encoded_offset, .words = at_encoded };
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
///   partials per GPU that hosts segments (`partial_mask`): the GPU's global
///            chi / LogUp partial (8 words). A GPU without segments owns no
///            partial slot (nobody could publish it), so the seal reads and
///            `Check.exchange_complete` requires only the hosting GPUs'.
///   seal     one 16-word channel checkpoint after the global seal (written
///            by the seal device, peer-copied to the others)
/// Every slot has one "written" flag word (set by the producer's copy, checked
/// by `Check.exchange_complete`). The flag value is the request's
/// `flagTag(generation)`, not a constant: replicas are never zeroed per
/// request (a consumer GPU's zero fill is not ordered against a producer
/// GPU's peer copy, so it could erase a slot that already landed), and a
/// stale flag of an earlier request in the same slab parity carries another
/// tag, so it can never satisfy this request's check.
///
/// Word layout (from the install capacities, identical for every request of
/// a service, so a flag word only ever holds a flag):
///   [0, flagCapacity)  flags: seal, partials (dense by hosting GPU), then
///                      (root, claims) per segment. The flags of one request
///                      are the contiguous prefix [0, flagWords()).
///   then roots (capacity_segments x 8), claims (capacity_segments x
///   capacity_claims x 8), partials (devices x 8), seal (16).
pub const Exchange = struct {
    /// Flag value of request `generation`: never 0 (install zeroes the slabs)
    /// nor `Verdict.unset`; repeats only after 2^32 - 2 requests.
    pub fn flagTag(generation: u64) u32 {
        return @as(u32, @intCast(generation % 0xffff_fffe)) + 1;
    }

    segments: u32,
    claims_per_segment: u32,
    devices: u32,
    /// Install capacities (0 = this request's value): fix every offset.
    capacity_segments: u32 = 0,
    capacity_claims: u32 = 0,
    /// GPUs that host segments, bit d = device d (0 = every device).
    partial_mask: u8 = 0,
    /// The flat-manifest protocol consumes roots, receipts and marginals
    /// directly and has no per-GPU partial producer or consumer. Chained
    /// protocols retain their partial slots and completion requirements.
    partials_enabled: bool = true,
    /// Two-stage truths (r-truth): each truth's stage-1 MAIN root (8 words +
    /// flag), framed by the seal. Appended after every other slot, so layouts
    /// without truths are unchanged.
    truths: u32 = 0,
    capacity_truths: u32 = 0,
    /// Per-segment local-GKR receipt digest slots (gn-s2): 8 words + flag per
    /// segment, after the truth roots. false: no slot, layout unchanged.
    receipts: bool = false,
    /// Capacity of each segment's length-prefixed local child wire. Zero
    /// preserves the previous exchange layout.
    child_wire_words: usize = 0,

    fn capS(self: Exchange) usize {
        return if (self.capacity_segments == 0) self.segments else self.capacity_segments;
    }
    fn capT(self: Exchange) usize {
        return if (self.capacity_truths == 0) self.truths else self.capacity_truths;
    }
    fn capC(self: Exchange) usize {
        return if (self.capacity_claims == 0) self.claims_per_segment else self.capacity_claims;
    }
    pub fn mask(self: Exchange) u8 {
        if (!self.partials_enabled) return 0;
        if (self.partial_mask != 0) return self.partial_mask;
        return @truncate((@as(u16, 1) << @intCast(@min(self.devices, 8))) - 1);
    }
    pub fn hasPartial(self: Exchange, device: u32) bool {
        return device < self.devices and device < 8 and (self.mask() >> @intCast(device)) & 1 == 1;
    }
    pub fn partials(self: Exchange) usize {
        return @popCount(self.mask());
    }
    pub fn validate(self: Exchange) !void {
        if (self.segments > self.capS() or self.claims_per_segment > self.capC() or self.truths > self.capT()) return error.GpuNativeExchangeExceedsCapacity;
        if (self.devices == 0 or self.devices > max_devices) return error.GpuNativeExchangeDevices;
        const all: u8 = @truncate((@as(u16, 1) << @intCast(self.devices)) - 1);
        if (self.mask() & ~all != 0) return error.GpuNativeExchangeDevices;
    }
    /// Flag words reserved at install (slot events are indexed by flag).
    pub fn flagCapacity(self: Exchange) usize {
        return 1 + @as(usize, self.devices) + 2 * self.capS() + self.capT() + self.capR() + (if (self.child_wire_words != 0) self.capS() else 0);
    }
    /// This request's flags: the contiguous prefix [flagOffset, +flagWords).
    pub fn flagWords(self: Exchange) usize {
        return 1 + self.partials() + 2 * @as(usize, self.segments) + self.truths + (if (self.receipts) @as(usize, self.segments) else 0) + (if (self.child_wire_words != 0) @as(usize, self.segments) else 0);
    }
    fn capR(self: Exchange) usize {
        return if (self.receipts) self.capS() else 0;
    }
    pub const flag_offset: usize = 0;
    pub fn rootWords(self: Exchange) usize {
        return self.capS() * 8;
    }
    pub fn claimWords(self: Exchange) usize {
        return self.capS() * self.capC() * 8;
    }
    pub fn partialWords(self: Exchange) usize {
        return @as(usize, self.devices) * 8;
    }
    pub const seal_words: usize = 16;
    /// Seal slot convention (r-truth reads it; the native seal writes it):
    /// words [0, 8) are the manifest digest (little-endian words, the bytes
    /// worker_protocol.mixManifestAndClaims digests). Stage-2 consumers mix
    /// these words and derive the shared challenges (manifest.drawShared)
    /// from them on device.
    pub const seal_digest_words: usize = 8;
    pub fn truthRootWords(self: Exchange) usize {
        return self.capT() * 8;
    }
    pub fn words(self: Exchange) usize {
        return std.mem.alignForward(usize, self.flagCapacity(), 8) + self.rootWords() + self.claimWords() + self.partialWords() + seal_words + self.capT() * 8 + self.capR() * 8 + self.capS() * self.child_wire_words;
    }
    fn dataBase(self: Exchange) usize {
        return std.mem.alignForward(usize, self.flagCapacity(), 8);
    }
    pub const Slot = struct { offset: usize, words: usize, flag: usize };
    pub fn root(self: Exchange, segment: u32) !Slot {
        if (segment >= self.segments) return error.GpuNativeExchangeSlot;
        return .{ .offset = self.dataBase() + @as(usize, segment) * 8, .words = 8, .flag = 1 + self.partials() + 2 * @as(usize, segment) };
    }
    pub fn claims(self: Exchange, segment: u32) !Slot {
        if (segment >= self.segments) return error.GpuNativeExchangeSlot;
        const per = self.capC() * 8;
        return .{ .offset = self.dataBase() + self.rootWords() + segment * per, .words = @as(usize, self.claims_per_segment) * 8, .flag = 2 + self.partials() + 2 * @as(usize, segment) };
    }
    /// error.GpuNativeExchangeNoPartial: `device` hosts no segment.
    pub fn partial(self: Exchange, device: u32) !Slot {
        if (device >= self.devices) return error.GpuNativeExchangeSlot;
        if (!self.hasPartial(device)) return error.GpuNativeExchangeNoPartial;
        const rank = @popCount(self.mask() & ((@as(u8, 1) << @intCast(device)) - 1));
        return .{ .offset = self.dataBase() + self.rootWords() + self.claimWords() + @as(usize, device) * 8, .words = 8, .flag = 1 + @as(usize, rank) };
    }
    pub fn seal(self: Exchange) Slot {
        return .{ .offset = self.dataBase() + self.rootWords() + self.claimWords() + self.partialWords(), .words = seal_words, .flag = 0 };
    }
    /// Truth `t`'s stage-1 MAIN root (two-stage truths).
    pub fn truthRoot(self: Exchange, t: u32) !Slot {
        if (t >= self.truths) return error.GpuNativeExchangeSlot;
        return .{ .offset = self.seal().offset + seal_words + @as(usize, t) * 8, .words = 8, .flag = 1 + self.partials() + 2 * @as(usize, self.segments) + t };
    }
    /// Segment `segment`'s local-GKR receipt digest (receipts only).
    pub fn receipt(self: Exchange, segment: u32) !Slot {
        if (!self.receipts or segment >= self.segments) return error.GpuNativeExchangeSlot;
        return .{ .offset = self.seal().offset + seal_words + self.capT() * 8 + @as(usize, segment) * 8, .words = 8, .flag = 1 + self.partials() + 2 * @as(usize, self.segments) + self.truths + segment };
    }
    pub fn childWire(self: Exchange, segment: u32) !Slot {
        if (self.child_wire_words == 0 or segment >= self.segments) return error.GpuNativeExchangeSlot;
        return .{ .offset = self.seal().offset + seal_words + self.capT() * 8 + self.capR() * 8 + @as(usize, segment) * self.child_wire_words, .words = self.child_wire_words, .flag = 1 + self.partials() + 2 * @as(usize, self.segments) + self.truths + (if (self.receipts) self.segments else 0) + segment };
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

pub const ClassKey = Classes.ClassKey;
pub const Phase = Classes.Phase;
pub const ClassEntry = Classes.ClassEntry;
pub const stage_one_base_bytes = Classes.stage_one_base_bytes;
pub const max_devices = Classes.max_devices;
pub const ClassCache = Classes.ClassCache;

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

pub const RegionKind = @import("memory_plan.zig").RegionKind;
pub const Region = @import("memory_plan.zig").Region;
pub const MemoryPlan = @import("memory_plan.zig").MemoryPlan;

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

/// One captured segment as the capture's per-segment readiness hook sees it
/// (GE `ethereum/capture.zig Ready.native_segment`, on the ordered owner's
/// thread, strictly in index order). Opaque on purpose: this contract never
/// imports the CPU integration. Types (stwo_riscv_cpu_integration):
///   native  *const word16_execution/prepared.zig Prepared
///   events  *const []const load_store_v2.native.Event (ledger shard events)
///   shard   *const services/collector.zig Shard (null if the capture has none)
/// The pointers themselves are valid during `pack` only (GE hands the shard by
/// value); the data they reference (Prepared, the event array) stays owned by
/// the capture and immutable until the request detaches.
pub const CapturedSegment = struct {
    segment: u32,
    native: *const anyopaque,
    events: *const anyopaque,
    shard: ?*const anyopaque = null,
    /// Capture clock (ns since the ordered owner started); report only.
    at_ns: u64 = 0,
};

/// The finished capture (after the last segment, before `done`). Types:
///   owner    *const ethereum/capture.zig Owner (advice, totals, terminal)
///   image    *const word16_execution/expected_image.zig Owner
///   program  *const word16_execution/program.zig Program
///   config   *const rv64_ethereum_request.zig Config
/// Valid until the request detaches its capture stream (after publication).
pub const CaptureEnd = struct {
    segments: u32,
    owner: *const anyopaque,
    image: *const anyopaque,
    program: *const anyopaque,
    config: *const anyopaque,
};

/// What `NativeFactory.pack` writes a captured segment through: pinned ring
/// buffers of the capture stream. `buffer` hands out the next free buffer
/// (blocks only on ring backpressure); `emit` publishes the first `words` of
/// the buffer last handed out as the segment's next TraceChunk of `rows`
/// rows (forwarded to `NativeFactory.chunk` on the same thread).
pub const ChunkWriter = struct {
    ctx: *anyopaque,
    buffer: *const fn (*anyopaque) anyerror![]u32,
    emit: *const fn (*anyopaque, words: usize, rows: u32, last: bool) anyerror!void,
    pub fn next(self: ChunkWriter) ![]u32 {
        return self.buffer(self.ctx);
    }
    pub fn put(self: ChunkWriter, words: usize, rows: u32, last: bool) !void {
        return self.emit(self.ctx, words, rows, last);
    }
};

/// A block's install-time warm capture, handed to the factories' `shape`
/// hooks so they derive (and warm) the block's class mix from real data.
pub const WarmBlock = struct {
    block: u64,
    capture: CaptureEnd,
};

/// The per-block geometry a request is planned from (fixed for the
/// service's life; a request whose capture differs fails closed).
pub const BlockShape = struct {
    block: u64,
    /// Rows per native segment (NativeFactory.shape).
    segment_rows: []const u64,
    /// Truth/service proofs (RecursionFactory.shape).
    truths: u32 = 0,
    /// Fold arity of the recursion tree (ready_dag policy; 2..4).
    fold_arity: u32 = 2,
};

/// Recursion's answer for one block (`RecursionFactory.shape`).
pub const RecursionShape = struct { truths: u32, fold_arity: u32 };

/// After the single wait: what each factory's `publish` hook writes from.
/// `proofs` are the request's published views INCLUDING the request
/// pseudo-proof (`.request`, ordinal 0) whose bytes are the stage-one bytes;
/// `exchange` is the final GPU's exchange replica (every root/claims slot,
/// laid out by `RequestContext.exchange`); `dir` is the request's output
/// directory (new and empty; the native stream writes its bundle files, the
/// recursion stream `recursion-om31/`).
pub const Publication = struct {
    block: u64,
    proofs: []const Published,
    exchange: []const u32,
    dir: std.fs.Dir,
};

// ---------------------------------------------------------------------------
// What the driver asks of the native and recursion streams
// ---------------------------------------------------------------------------

/// Request-scoped context every factory call receives.
pub const RequestContext = struct {
    request: u64,
    /// Actual driver slot, independent of generation and request id.
    parity: u1 = 0,
    block: u64 = 0,
    /// Native class keys resolved during planning; immutable for this request.
    native_classes: []const ClassKey = &.{},
    truth_devices: []const u32 = &.{},
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
        /// Request metadata before class selection, and device placement
        /// after planning but before any jobs are constructed.
        begin_request: ?*const fn (*anyopaque, block: u64, request: u64, generation: u64) anyerror!void = null,
        planned: ?*const fn (*anyopaque, *const RequestContext) anyerror!void = null,
        batch_pinned_words: ?*const fn (*anyopaque) anyerror!usize = null,
        /// Install time: warm every class of the manifest's class mix.
        warm: *const fn (*anyopaque, *ClassCache) anyerror!void,
        /// Address-independent immutable resources, before the final arena.
        resources: ?*const fn (*anyopaque, *ClassCache, u32) anyerror!void = null,
        /// Install time, after the memory plan is installed (see `Installed`):
        /// capture every graph that bakes arena / main_resident addresses.
        installed: ?*const fn (*anyopaque, *ClassCache, *const Installed) anyerror!void = null,
        /// Class of a native segment (from capture geometry).
        class_of: *const fn (*anyopaque, segment: u32, rows: u64) anyerror!ClassKey,
        /// gn-shape addition (optional): the class of segment `segment` of
        /// `block` (Request.block / the install loop's block). `class_of`
        /// alone is ambiguous when two blocks (or two segments) share a row
        /// count but not a class; callers that know the block prefer this.
        class_of_block: ?*const fn (*anyopaque, block: u64, segment: u32, rows: u64) anyerror!ClassKey = null,
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
        /// Install, before `warm`: the segment rows of `block` from its warm
        /// capture; the factory registers the block's classes for `warm`.
        shape: ?*const fn (*anyopaque, std.mem.Allocator, WarmBlock) anyerror![]u64 = null,
        /// Capture thread: pack one captured segment into trace chunks
        /// through `writer` (pinned ring); returns the segment's rows (must
        /// equal the planned rows; the driver then seals the segment).
        pack: ?*const fn (*anyopaque, *const RequestContext, CapturedSegment, ChunkWriter) anyerror!u64 = null,
        /// Capture thread, after the last segment and before `done`.
        captured: ?*const fn (*anyopaque, *const RequestContext, CaptureEnd) anyerror!void = null,
        /// Host, after the request's single wait: write the native artifacts
        /// (cpu-N.bin, stage-one.bin, cells.bin, bundle.json, ...).
        publish: ?*const fn (*anyopaque, *const RequestContext, Publication) anyerror!void = null,
    };
};

/// Stream recursion implements this (jobs/outer_device.zig, jobs/truth_job.zig).
pub const RecursionFactory = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        warm: *const fn (*anyopaque, *ClassCache) anyerror!void,
        resources: ?*const fn (*anyopaque, *ClassCache, u32) anyerror!void = null,
        /// See NativeFactory.VTable.installed.
        installed: ?*const fn (*anyopaque, *ClassCache, *const Installed) anyerror!void = null,
        /// Class of a recursion proof from its AUTHORITY, never from its
        /// position in one request's topology: `children` are the class keys
        /// of what the node verifies (a leaf: its native segments' then its
        /// truths' classes, in topology order; a fold/root: its children
        /// nodes' classes). A truth has no children; its ordinal names the
        /// truth statement kind (fixed per service).
        class_of: *const fn (*anyopaque, id: ProofId, children: []const ClassKey) anyerror!ClassKey,
        /// The truth job; with `truth_stage2` set it is truth STAGE 1
        /// (witness -> MAIN root -> Exchange.truthRoot, before the seal).
        truth: *const fn (*anyopaque, *const RequestContext, ordinal: u32, device: u32) anyerror!api.Job,
        /// Two-stage truths (r-truth): stage 2 after the seal, on the stage-1
        /// GPU; it publishes the truth proof. Null: `truth` is the whole proof.
        truth_stage2: ?*const fn (*anyopaque, *const RequestContext, ordinal: u32, device: u32) anyerror!api.Job = null,
        /// Leaf/fold/root node: reads its children's encoded regions (device,
        /// own segment or peer replica) and writes its own.
        node: *const fn (*anyopaque, *const RequestContext, id: ProofId, children: []const ProofId, device: u32) anyerror!api.Job,
        /// Install, after NativeFactory.shape: the block's truth count and
        /// fold arity; the factory registers the block's recursion classes
        /// (authorities over `native_keys`, the segments' class keys).
        shape: ?*const fn (*anyopaque, WarmBlock, native_keys: []const ClassKey) anyerror!RecursionShape = null,
        /// Capture thread, after the last segment and before `done` (truth
        /// inputs are final here; `needs_capture_end` truths are gated on it).
        captured: ?*const fn (*anyopaque, *const RequestContext, CaptureEnd) anyerror!void = null,
        /// Host, after the request's single wait and native's publish: write
        /// truth-N.bin and recursion-om31/ (leaf/fold/root proofs, tree.json).
        publish: ?*const fn (*anyopaque, *const RequestContext, Publication) anyerror!void = null,
    };
};

// ---------------------------------------------------------------------------
// Publication (the host's only per-request computation besides capture)
// ---------------------------------------------------------------------------

pub const Rejection = struct { id: ProofId, check: Check, word: u32 };

pub const Published = struct {
    id: ProofId,
    bytes: []const u8, // view into the pinned mirror: copy before the slot is reused
    /// Full encoded region, including device-only child image/frame suffixes.
    region: []const u32 = &.{},
};

/// Check every status word of every segment and slice the encoded proofs.
/// `mirrors[d]` is device d's pinned segment after the request's single wait.
/// Fails closed: an unset word, a reject code, a header mismatch, or a length
/// beyond capacity refuses the whole request (`first` names the culprit).
/// `completion` is the request's `Exchange.flagTag(generation)`: every
/// segment's device-written completion word must carry it (the host-written
/// header alone cannot tell a landed D2H from a stale mirror).
pub fn publish(a: std.mem.Allocator, layout: *const RequestLayout, request: u64, completion: u32, mirrors: []const []const u32, first: ?*Rejection) ![]Published {
    if (mirrors.len != layout.segments.len) return error.GpuNativeMirrorCount;
    var n: usize = 0;
    for (layout.segments, mirrors) |s, m| {
        if (m.len < s.words) return error.GpuNativeMirrorTruncated;
        if (m[0] != slab_magic or m[1] != contract_version or m[2] != @as(u32, @truncate(request)) or m[3] != s.device) return error.GpuNativeSlabHeaderMismatch;
        if (m[header_completion_word] != completion) return error.GpuNativeSlabNotCompleted;
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
            // Only a request pseudo-proof without a stage-one region carries
            // no bytes: an encoder that accepted its bounds but wrote no
            // length published nothing.
            if (len == 0 and (e.kind != @intFromEnum(ProofKind.request) or e.encoded_capacity_words != 0)) {
                if (first) |f| f.* = .{ .id = s.ids[i], .check = .encode_bounds, .word = 0 };
                return error.GpuNativeEncodedEmpty;
            }
            n += 1;
        }
    }
    const out = try a.alloc(Published, n);
    var i: usize = 0;
    for (layout.segments, mirrors) |s, m| for (s.entries, s.ids) |e, id| {
        const len = m[e.encoded_offset];
        out[i] = .{ .id = id, .bytes = std.mem.sliceAsBytes(m[e.encoded_offset + 1 ..][0..e.encoded_capacity_words])[0..len], .region = m[e.encoded_offset..][0 .. 1 + e.encoded_capacity_words] };
        i += 1;
    };
    return out;
}

test {
    _ = @import("gpu_native_test.zig");
}
