//! M8 GPU-native native Stage 1 (piece n-stage1; design rv64-m8-gpu-native.md
//! §3.2 items 1-4, inventory H4-H7, H12; contract gpu_native.zig).
//!
//! Per native segment, enqueue-only on the segment's GPU, inside the driver's
//! per-GPU batch (no per-job host wait, no per-job readback):
//!
//!   seed      9-word worker checkpoint (request words, staged)
//!   witness   MAIN evaluation image from the segment's TraceChunks (h2d of the
//!             pinned ring buffers on the exec stream + scatter kernel, no
//!             contributor joins) or from caller device columns
//!   FIXED     ADOPTED: the class tree (coefficients + root) lives in a
//!             worker-persistent region filled once per (class, GPU) by
//!             `WarmJob` at install; the request job only mixes the device
//!             root (legacy appendFixed -> appendCommittedTree). No host SHA,
//!             no FIXED upload, no host plan per request. A region that is not
//!             warm fails closed (GpuNativeFixedNotWarmed).
//!   MAIN      native_commit into the segment's `main_resident` view (MAIN
//!             stays resident witness -> PCS; no legacy replay, no copy job);
//!             the root is written straight into this GPU's exchange root
//!             slot, mixed on device and peer-published.
//!   GKR       native_gkr on its own device child channel; the GKR section
//!             (status, header, snapshot, roots, MAIN root, records/masks) is
//!             written into the segment's resident section region (the
//!             Stage-2 encoder reads it: `Class.section`).
//!   binding   native_binding into the resident binding region (Stage 2's
//!             INTER commit reads it), authority words into the resident
//!             authority region; the GKR terminal claims are copied into the
//!             exchange claims slot and peer-published (the device seal reads
//!             every segment's slot).
//!   checkpoint the post-MAIN main-channel snapshot (16 words) into the
//!             segment's resident checkpoint region: the transcript Stage 2
//!             continues from (legacy `seedOf(worker.channel)` at stage two,
//!             before `mixManifestAndClaims`).
//!   checks    witness_status, binding_authority, root_match: one Verdict word
//!             each in the request slab (stwo_rv64_n1_check_v2_on):
//!               witness_status    scatter status word (every run in range);
//!                                 full image coverage is refused on the host
//!                                 at job init (validateCoverage), before any
//!                                 enqueue;
//!               binding_authority GKR closure status, binding verdict, the
//!                                 traversal header guard (legacy
//!                                 gkr.Header.validate) and the child channel
//!                                 snapshot guard (legacy Section.verify
//!                                 cursor/chain/status/draws);
//!               root_match        device FIXED root == class authority root,
//!                                 exchanged MAIN root == GKR-bound MAIN root,
//!                                 post-MAIN main-channel guard (cursor, chain,
//!                                 status latch: seed -> FIXED -> MAIN order).
//!             NOT on device (no device GKR verifier exists): the legacy
//!             `NB.checkAuthority` replay of the GKR proof (claims, OOD point,
//!             eta vs a host partial verification) and the host replay of the
//!             child digest. binding_authority covers only the guards above;
//!             see the n-stage1 receipt.
//!
//! Resident layout of one segment (`ResidentLayout`, offsets 64-word aligned):
//!   [MAIN coefficients | binding output | GKR section | authority words | checkpoint 16]
//! `ClassEntry.main_resident_words` = `ResidentLayout.words`.
//!
//! Per-request host work that remains here (listed in the receipt): the two
//! challenge-free checkpoints (`RequestWords.seed`, `.prefix`: a few Blake2s
//! compressions over the statement) and the GKR public words, both supplied by
//! the service from the capture result.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const C = @import("native_commit.zig");
const NG = @import("native_gkr.zig");
const Wire = @import("native_gkr_wire.zig");
const Semantic = @import("native_semantic.zig");
const NB = @import("native_binding.zig");
/// addon stwo_rv64_jobs_copy_async(dst, src, bytes, kind, stream) (kind 3 = d2d).
pub const CopyAsync = *const fn (*anyopaque, *const anyopaque, usize, u32, *anyopaque) callconv(.c) c_int;
const Slab = @import("slab.zig");
const Sources = @import("../gkr_sources.zig");
/// gn-pack: compact TraceChunk v2 + the device witness program.
pub const NP = @import("native_pack.zig");

pub const granule: usize = 64;
const up = @import("native_stage1_job.zig").up;

// ---------------------------------------------------------------------------
// Addon ABI (NAT/rv64/jobs/native_witness_stage1.cu)
// ---------------------------------------------------------------------------

pub const Pair = extern struct { a: [*]const u32, b: [*]const u32, words: u32, reserved: u32 = 0 };
/// A device run compared with constants carried in the launch parameters.
pub const Const = extern struct { a: [*]const u32, words: u32, reserved: u32 = 0, values: [16]u32 = @splat(0) };
pub const CheckSpec = extern struct {
    zero: [8][*]const u32 = undefined,
    pairs: [4]Pair = undefined,
    consts: [4]Const = undefined,
    n_zero: u32 = 0,
    n_pairs: u32 = 0,
    n_consts: u32 = 0,
    check: u32,

    pub fn mustBeZero(self: *CheckSpec, word: api.DeviceBuffer) !void {
        if (self.n_zero == 8 or word.words < 1) return error.NativeStage1CheckShape;
        self.zero[self.n_zero] = word.ptr;
        self.n_zero += 1;
    }
    pub fn mustEqual(self: *CheckSpec, a: api.DeviceBuffer, b: api.DeviceBuffer) !void {
        if (self.n_pairs == 4 or a.words != b.words or a.words == 0 or a.words > 4096) return error.NativeStage1CheckShape;
        self.pairs[self.n_pairs] = .{ .a = a.ptr, .b = b.ptr, .words = @intCast(a.words) };
        self.n_pairs += 1;
    }
    /// `a[0..values.len) == values` on device (values travel by value).
    pub fn mustMatch(self: *CheckSpec, a: api.DeviceBuffer, values: []const u32) !void {
        if (self.n_consts == 4 or values.len == 0 or values.len > 16 or a.words != values.len) return error.NativeStage1CheckShape;
        var c = Const{ .a = a.ptr, .words = @intCast(values.len) };
        @memcpy(c.values[0..values.len], values);
        self.consts[self.n_consts] = c;
        self.n_consts += 1;
    }
};
comptime {
    if (@sizeOf(Pair) != 24 or @sizeOf(Const) != 80 or @sizeOf(CheckSpec) != 8 * 8 + 4 * 24 + 4 * 80 + 16) @compileError("n1 check ABI changed");
}

/// Words [8, 16) of a completed device channel snapshot (channel.zig
/// Snapshot: draws, cursor, status, reserved, chain lo/hi, padding 2): the
/// legacy host `Snapshot.validate(cursor, chain)` plus the draw counter.
pub fn snapshotGuard(draws: u32, cursor: u32, chain: u64) [8]u32 {
    return .{ draws, cursor, 0, 0, @truncate(chain), @truncate(chain >> 32), 0, 0 };
}
/// Words [8, 20) of a completed GKR traversal header (gkr.zig Header): the
/// legacy host `Header.validate` (channel cursor 2L, chain, draws 1, layers,
/// count, next_layer = layers, phase 2).
pub fn headerGuard(layers: u32, count: u32, chain: u64) [12]u32 {
    return snapshotGuard(1, 2 * layers, chain) ++ [4]u32{ layers, count, layers, 2 };
}
pub const Run = extern struct { dst: u64, src: u64, words: u64 };
comptime {
    if (@sizeOf(Run) != 24) @compileError("n1 run ABI changed");
}

pub const CheckFn = *const fn (*anyopaque, u32, *const CheckSpec, [*]u32) callconv(.c) c_int;
pub const ScatterFn = *const fn (*anyopaque, u32, [*]const Run, u32, [*]const u32, u64, [*]u32, u64, [*]u32) callconv(.c) c_int;

pub const Symbols = struct {
    check: CheckFn,
    scatter: ScatterFn,
    copy: CopyAsync,
    memset: *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int,
    commit: C.Symbols,
    /// Local GKR symbols (native_gkr.Symbols.load); required by the GKR half
    /// (Stage1Job, WarmJob), not by the prologue.
    gkr: ?*const NG.Symbols,
    binding: NB.Symbols,
    /// v2 compact ingress kernels (base-library *_witness_on; null = v2 refused).
    pack: ?NP.Symbols = null,
    receipt_encode: ?Wire.EncodeFn = null,
    pub fn load(base: *std.DynLib, addon: *std.DynLib, gkr: ?*const NG.Symbols) !Symbols {
        return .{
            .pack = NP.Symbols.load(base, addon) catch null,
            .receipt_encode = Wire.load(addon) catch null,
            .check = addon.lookup(CheckFn, "stwo_rv64_n1_check_v2_on") orelse return error.MissingNativeStage1Kernel,
            .scatter = addon.lookup(ScatterFn, "stwo_rv64_n1_scatter_v1_on") orelse return error.MissingNativeStage1Kernel,
            .copy = addon.lookup(CopyAsync, "stwo_rv64_jobs_copy_async") orelse return error.MissingNativeStage1Kernel,
            .memset = base.lookup(*const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int, "stwo_exec_context_memset_async") orelse return error.MissingNativeStage1Kernel,
            .commit = try C.Symbols.load(base),
            .gkr = gkr,
            .binding = try NB.Symbols.load(base),
        };
    }
};

const cuda = @import("native_stage1_job.zig").cuda;

// ---------------------------------------------------------------------------
// Class (built once per class at warm; immutable afterwards)
// ---------------------------------------------------------------------------

/// What the service registers per native segment class (from setup, never
/// from a request). `gkr` and `instances` are borrowed for the class's life.
pub const Spec = struct {
    key: G.ClassKey,
    /// Challenge-free local GKR plan of the class (native_gkr.Plan.init on the
    /// class geometry). Its `prefix` and item `public` words are per request
    /// and rebound per job (`RequestWords`); the plan itself is never mutated.
    gkr: *const NG.Plan,
    instances: []const NG.Instance,
    fixed_shapes: []const C.Shape,
    /// FIXED coefficient columns (original order); read only by `WarmJob`.
    fixed_host: []const []const u32,
    /// Class FIXED authority root (setup key root, little-endian words).
    fixed_root: [8]u32,
    main_shapes: []const C.Shape,
    /// Trace commitment blowup parameter (native_commit beta; D2 = 2).
    beta: u32,
    cost_us: u64 = 1,
    /// Pinned capture words one segment holds in the ring (driver ring check).
    capture_words: u64 = 0,
    /// gn-pack: arena words of the class's largest v2 witness program (its
    /// compact inputs, CPU scratch and ledgers), planned on top of jobWords.
    compact_words: u64 = 0,
    /// Compact witness ROM, uploaded at install so request jobs only adopt it.
    compact_rom: ?struct { key: [8]u32, words: []const u32 } = null,
};

pub const ResidentLayout = struct {
    main: usize = 0,
    main_words: usize,
    binding: usize,
    binding_words: usize,
    section: usize,
    section_words: usize,
    authority: usize,
    authority_words: usize,
    /// Post-MAIN main-channel snapshot (16 words; Stage 2 seeds from [0, 9)).
    checkpoint: usize,
    receipt: usize = 0,
    local_wire: usize = 0,
    scope: usize = 0,
    wire_words: usize = 0,
    semantic: usize = 0,
    semantic_words: usize = 0,
    words: usize,

    pub const checkpoint_words: usize = 16;
    pub fn withSemantic(self: ResidentLayout, n: usize) ResidentLayout {
        var out = self;
        out.semantic = self.words;
        out.semantic_words = n;
        out.words += up(n);
        return out;
    }
    pub fn withWire(self: ResidentLayout, wire_words: usize) ResidentLayout {
        var out = self;
        out.receipt = self.words;
        out.local_wire = out.receipt + granule;
        out.scope = out.local_wire + up(wire_words);
        out.wire_words = wire_words;
        out.words = out.scope + granule;
        return out;
    }
    pub fn of(main_words: usize, binding_words: usize, section_words: usize, authority_words: usize) ResidentLayout {
        const binding = up(main_words);
        const section = binding + up(binding_words);
        const authority = section + up(section_words);
        const checkpoint = authority + up(authority_words);
        return .{ .main_words = main_words, .binding = binding, .binding_words = binding_words, .section = section, .section_words = section_words, .authority = authority, .authority_words = authority_words, .checkpoint = checkpoint, .words = checkpoint + up(checkpoint_words) };
    }
    pub fn checkpointView(self: ResidentLayout, resident: api.DeviceBuffer) !api.DeviceBuffer {
        if (resident.words < self.words) return error.GpuNativeMainResidentTooSmall;
        return resident.slice(self.checkpoint, checkpoint_words);
    }
    pub fn mainView(self: ResidentLayout, resident: api.DeviceBuffer) !api.DeviceBuffer {
        if (resident.words < self.words) return error.GpuNativeMainResidentTooSmall;
        return resident.slice(self.main, self.main_words);
    }
    pub fn bindingView(self: ResidentLayout, resident: api.DeviceBuffer) !api.DeviceBuffer {
        if (resident.words < self.words) return error.GpuNativeMainResidentTooSmall;
        return resident.slice(self.binding, self.binding_words);
    }
    pub fn sectionView(self: ResidentLayout, resident: api.DeviceBuffer) !api.DeviceBuffer {
        if (resident.words < self.words) return error.GpuNativeMainResidentTooSmall;
        return resident.slice(self.section, self.section_words);
    }
    pub fn authorityView(self: ResidentLayout, resident: api.DeviceBuffer) !api.DeviceBuffer {
        if (resident.words < self.words) return error.GpuNativeMainResidentTooSmall;
        return resident.slice(self.authority, self.authority_words);
    }
};

pub const Class = struct {
    a: std.mem.Allocator,
    spec: Spec,
    fixed: C.CommitPlan,
    main: C.CommitPlan,
    bind: NB.Plan,
    /// GKR section fields (native_gkr Plan.addFields at base 0), relative to
    /// the resident section region. The Stage-2 encoder decodes it.
    section: Slab.ProofLayout,
    resident: ResidentLayout,
    /// Worker-persistent FIXED region: [coefficients | device root 8 | class root 8].
    fixed_key: [32]u8,
    /// MAIN evaluation image: column offsets (original order) and size.
    image_offsets: []usize,
    image_words: usize,
    /// Draw counter of the GKR child channel at its snapshot (data
    /// independent: the op sequence is class geometry; host replay once).
    child_draws: u32 = 0,
    wire: ?Wire.Program = null,
    wire_key: [32]u8 = @splat(0),

    pub fn init(a: std.mem.Allocator, spec: Spec) !*Class {
        if (spec.gkr.fixed_count != spec.fixed_shapes.len or spec.gkr.logs.len != spec.fixed_shapes.len + spec.main_shapes.len) return error.NativeStage1ClassShape;
        if (spec.fixed_host.len != spec.fixed_shapes.len) return error.NativeStage1ClassShape;
        for (spec.fixed_host, spec.fixed_shapes) |h, s| if (h.len != @as(usize, 1) << @intCast(s.log_size)) return error.NativeStage1ClassShape;
        for (spec.main_shapes, spec.gkr.logs[spec.fixed_shapes.len..]) |s, l| if (s.log_size != l) return error.NativeStage1ClassShape;
        const self = try a.create(Class);
        errdefer a.destroy(self);
        var fixed = try C.CommitPlan.init(a, spec.fixed_shapes, spec.beta);
        errdefer fixed.deinit();
        var main = try C.CommitPlan.init(a, spec.main_shapes, spec.beta);
        errdefer main.deinit();
        var bind = try NB.Plan.init(a, spec.instances, spec.gkr.traversal.layers);
        errdefer bind.deinit();
        var section: Slab.ProofLayout = .{};
        try spec.gkr.addFields(&section);
        var wire = try Wire.build(a, spec.instances, spec.gkr.variables, spec.gkr.fields, &section);
        errdefer wire.deinit();
        const image_offsets = try a.alloc(usize, spec.main_shapes.len);
        errdefer a.free(image_offsets);
        var at: usize = 0;
        for (spec.main_shapes, image_offsets) |s, *o| {
            o.* = at;
            at += @as(usize, 1) << @intCast(s.log_size);
        }
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-n1-fixed-v1");
        h.update(&spec.key);
        const fixed_key = h.finalResult();
        h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-local-gkr-wire-v1");
        h.update(&spec.key);
        self.* = .{ .a = a, .spec = spec, .fixed = fixed, .main = main, .bind = bind, .section = section, .resident = ResidentLayout.of(main.coefficient_cells, bind.output_words, section.words, bind.authorityWords()).withWire(wire.wireWords()).withSemantic(Semantic.words(bind.row_logs)), .fixed_key = fixed_key, .image_offsets = image_offsets, .image_words = at, .child_draws = NG.expectedChild(spec.gkr, @splat(0))[8], .wire = wire, .wire_key = h.finalResult() };
        return self;
    }
    pub fn deinit(self: *Class) void {
        if (self.wire) |*wire| wire.deinit();
        self.a.free(self.image_offsets);
        self.bind.deinit();
        self.main.deinit();
        self.fixed.deinit();
        self.a.destroy(self);
    }
    pub fn instances(self: *const Class) u32 {
        return @intCast(self.bind.row_logs.len);
    }
    /// Secure-felt claim blocks published per segment: the GKR terminal
    /// claims, 2 per instance (claims_to_verify_by_instance).
    pub fn claimsPerSegment(self: *const Class) u32 {
        return 2 * self.instances();
    }
    pub fn requestPinnedWords(self: *const Class) usize {
        // Committed device inputs; ROM and twiddles were installed.
        return self.spec.gkr.staged_words + 8 * self.main.logs.len + 9 + 25 + 4 * granule;
    }
    pub fn fixedRegionWords(self: *const Class) usize {
        return self.fixed.coefficient_cells + 16;
    }
    /// Words this class holds per GPU in worker-persistent regions (FIXED tree,
    /// the MAIN/GKR/binding twiddle towers; shared across classes of equal
    /// logs, counted per class: an over-estimate the plan can absorb).
    pub fn heldWords(self: *const Class) u64 {
        return self.fixedRegionWords() + twiddleWords(&self.main) + twiddleWords(&self.fixed) + self.spec.gkr.twiddle_words + self.bind.persistentWords() + (if (self.spec.compact_rom) |rom| up(rom.words.len) else 0) + (if (self.wire) |wire| up(wire.words.len) else 0);
    }
    /// Static arena peak of one request job (stream-ordered allocations).
    /// The MAIN commit's work (evaluations + tree, freed LIFO inside
    /// CommitPlan.enqueueInto) is dead before the local GKR + binding
    /// allocate, so the two phases share one window: max, not sum. The
    /// witness image and compact program stay counted for the whole job (the
    /// image free after the commit is not LIFO when the v2 program allocated
    /// status words above it). gn-bind [M] 26235156: 8519d3b3 6.365G -> ~4.15G
    /// words [D]; the sum overflowed phase A (GpuNativeMemoryPlanPhaseA, r7).
    pub fn jobWords(self: *const Class) usize {
        const commit = @max(self.main.deviceWords(), self.main.coefficient_cells + self.main.eval_cells) + 8 * granule;
        // v2 writes MAIN directly into main_resident. It has compact input
        // buffers instead of a second v1 expanded MAIN/scatter image.
        const witness = if (self.spec.compact_words == 0 or self.spec.beta == 1) up(self.image_words) + up(max_chunk_runs * 6) + granule else 0;
        const tail = self.spec.gkr.enqueueWords() + self.bind.enqueueWords() + granule;
        return up(9) + granule + self.spec.gkr.stagedWords(true) + up(self.main.stagedWords(0)) + witness + @as(usize, @intCast(self.spec.compact_words)) + @max(commit, tail) + 8 * granule;
    }
    /// Stage-1 fields of the class's ClassEntry (Stage 2 adds its own).
    pub fn fill(self: *const Class, entry: *G.ClassEntry, devices: u32) void {
        entry.main_resident_words = @max(entry.main_resident_words, self.resident.words);
        entry.claims_per_segment = self.claimsPerSegment();
        entry.arena_peak_words = @max(entry.arena_peak_words, self.jobWords());
        entry.capture_words = self.spec.capture_words;
        if (self.wire) |wire| {
            entry.stage_one_bytes = @max(entry.stage_one_bytes, 76 + wire.max_wire_bytes);
            entry.local_gkr_wire_words = wire.wireWords();
            entry.extra_checks = &.{.local_receipt};
        }
        entry.cost_us = @max(entry.cost_us, self.spec.cost_us);
        for (0..@min(devices, G.max_devices)) |d| entry.held_words[d] += self.heldWords();
    }
};

/// native_commit's persistent twiddle tower words (CommitPlan.twiddleWords).
fn twiddleWords(p: *const C.CommitPlan) usize {
    return p.tw.twiddles.len + p.tw.itwiddles.len;
}

/// The largest run table one chunk may carry (scatter kernel input).
pub const max_chunk_runs: usize = 4096;

// ---------------------------------------------------------------------------
// Request words (challenge-free, per request, from the capture result)
// ---------------------------------------------------------------------------

pub const PublicWords = @FieldType(Sources.Item, "public");

pub const RequestWords = struct {
    statement: [32]u8 = @splat(0),
    /// worker_protocol.begin(config, expected) checkpoint (digest 8, draws 1).
    seed: [9]u32,
    /// native_gkr.childPrefix(scope, instances) checkpoint.
    prefix: [9]u32,
    /// Per GKR source item: its public words (epoch, pc, registers, clocks).
    publics: []const PublicWords,
};

/// The exchange stride covers the largest class in the request. A smaller
/// segment publishes its own terminal claims in that slot's prefix; only
/// those claims enter its receipt and the manifest's instance roster.
pub fn claimPayloadSlot(exchange: G.Exchange, segment: u32, claims: u32) !G.Exchange.Slot {
    const slot = try exchange.claims(segment);
    const words = 8 * @as(usize, claims);
    if (claims == 0 or words > slot.words) return error.GpuNativeExchangeClaimsShape;
    return .{ .offset = slot.offset, .words = words, .flag = slot.flag };
}

// ---------------------------------------------------------------------------
// Witness ingress
// ---------------------------------------------------------------------------

/// Chunk ingress format v1 (`TraceChunk.words`): [n_runs, 0, runs (n_runs x 6
/// words, `Run` little-endian: dst/src/words as u64), data...]; `Run.src` is
/// relative to the data start, `Run.dst` a word offset in the segment's MAIN
/// evaluation image (`Class.image_offsets`, original column order).
pub const chunk_header_words: usize = 2;
pub fn chunkRuns(words: []const u32) ![]align(4) const Run {
    if (words.len < chunk_header_words) return error.NativeStage1ChunkFormat;
    const n = words[0];
    if (n == 0 or n > max_chunk_runs or words[1] != 0 or words.len < chunk_header_words + 6 * @as(usize, n)) return error.NativeStage1ChunkFormat;
    const raw = std.mem.sliceAsBytes(words[chunk_header_words..][0 .. 6 * @as(usize, n)]);
    return @as([*]align(4) const Run, @ptrCast(raw.ptr))[0..n];
}
pub fn chunkData(words: []const u32) ![]const u32 {
    const runs = try chunkRuns(words);
    return words[chunk_header_words + 6 * runs.len ..];
}
/// Host-side preflight of a chunk (capture thread, O(runs)): the device check
/// repeats it, so this only rejects early with a precise error.
pub fn validateChunk(words: []const u32, image_words: usize) !void {
    const runs = try chunkRuns(words);
    const data = words.len - chunk_header_words - 6 * runs.len;
    for (runs) |r| {
        if (r.words == 0 or r.words > data or r.src > data - r.words or r.words > image_words or r.dst > image_words - r.words) return error.NativeStage1ChunkRunOutOfRange;
    }
}

/// The runs of a segment's chunks must tile its MAIN evaluation image
/// exactly (no gap: the arena image is not zeroed, a gap would commit stale
/// words; no overlap: the result would depend on scatter order). Host, O(R
/// log R) over the run tables only, at job init: a refusal enqueues nothing.
pub fn validateCoverage(a: std.mem.Allocator, chunks: []const G.TraceChunk, image_words: usize) !void {
    var spans: std.ArrayListUnmanaged([2]u64) = .empty;
    defer spans.deinit(a);
    for (chunks) |ch| for (try chunkRuns(ch.words)) |r| try spans.append(a, .{ r.dst, r.words });
    std.mem.sort([2]u64, spans.items, {}, struct {
        fn lt(_: void, x: [2]u64, y: [2]u64) bool {
            return x[0] < y[0];
        }
    }.lt);
    var at: u64 = 0;
    for (spans.items) |sp| {
        if (sp[0] != at) return error.NativeStage1WitnessCoverage;
        at += sp[1];
    }
    if (at != image_words) return error.NativeStage1WitnessCoverage;
}

/// Where Stage 1 gets its MAIN evaluations from.
pub const Witness = union(enum) {
    /// Captured chunks (pinned ring memory, valid until the job's `after`
    /// host function releases the segment's ring buffers).
    chunks: []const G.TraceChunk,
    /// MAIN columns already on device (original order, evaluation or
    /// coefficient encoding as the class shapes declare): parity harnesses and
    /// a device witness producer upstream of this job.
    device: []const [*]const u32,
    /// gn-pack: compact TraceChunk v2 (native_pack.zig): compact facts/events
    /// + a launch program of the base-library witness kernels, run into the
    /// MAIN image on the exec stream. `program`/`bound` are the job's own
    /// (set by Stage1Job.init/stage); harnesses may set them directly.
    compact: Compact,
};

pub const Compact = struct {
    chunks: []const G.TraceChunk,
    roms: ?*NP.Roms = null,
    program: ?*const NP.Program = null,
    bound: ?*const NP.Bound = null,
};

/// True when a segment's chunks are format v2 (all or none).
pub fn chunksAreV2(chunks: []const G.TraceChunk) !bool {
    if (chunks.len == 0) return false;
    const v2 = NP.isV2(chunks[0].words);
    for (chunks[1..]) |ch| if (NP.isV2(ch.words) != v2) return error.NativeStage1ChunkFormat;
    return v2;
}

// ---------------------------------------------------------------------------
// Warm job: one per (class, GPU), at install, outside any request batch
// ---------------------------------------------------------------------------

/// Fills the class's worker-persistent regions on one GPU: commits FIXED once
/// (coefficients + device root), stores the class authority root next to it,
/// and stages the MAIN/GKR/binding twiddle towers. `finish` compares the
/// device FIXED root with the class authority root (install-time host check,
/// once per class and GPU; on the request path it is `Check.root_match`).
pub const WarmJob = struct {
    a: std.mem.Allocator,
    class: *const Class,
    sym: *const Symbols,
    fixed: C.CommitPlan = undefined,
    main: C.CommitPlan = undefined,
    gkr: NG.Gkr = undefined,
    binding: NB.Binding = undefined,
    region: ?api.DeviceBuffer = null,
    fresh: bool = false,
    layout: Slab.ProofLayout = .{},
    device_root: [8]u32 = @splat(0),
    inputs: []C.Input = &.{},

    pub fn init(self: *WarmJob) !void {
        self.fixed = self.class.fixed;
        self.main = self.class.main;
        self.gkr = try NG.Gkr.init(self.a, self.class.spec.gkr, self.sym.gkr orelse return error.NativeStage1SymbolsNotBound);
        errdefer self.gkr.deinit();
        self.binding = .{ .plan = &self.class.bind, .sym = self.sym.binding };
        self.inputs = try self.a.alloc(C.Input, self.class.spec.fixed_host.len);
        for (self.inputs, self.class.spec.fixed_host) |*i, h| i.* = .{ .host = h };
        _ = try self.layout.add(.root, 0, 8);
    }
    pub fn deinit(self: *WarmJob) void {
        self.gkr.deinit();
        self.a.free(self.inputs);
    }
    pub fn classKey(self: *WarmJob) [32]u8 {
        return self.class.fixed_key;
    }
    pub fn footprint(self: *WarmJob) api.Footprint {
        const c = self.class;
        const staged = c.fixed.stagedWords(c.fixed.coefficient_cells) + c.main.stagedWords(0) + c.spec.gkr.stagedWords(true) + 8 * granule;
        const pinned = c.fixed.coefficient_cells + twiddleWords(&c.fixed) + twiddleWords(&c.main) + c.spec.gkr.pinnedWords() + c.bind.pinnedWords() + 16 + 8 * granule + (if (c.spec.compact_rom) |rom| rom.words.len else 0) + (if (c.wire) |wire| wire.words.len else 0);
        return .{ .device_words = staged + @max(c.fixed.deviceWords(), c.fixed.coefficient_cells + c.fixed.eval_cells) + 8 * granule, .staged_words = staged, .slab_words = self.layout.words, .pinned_words = pinned };
    }
    pub fn stage(self: *WarmJob, s: *api.Stager) !void {
        const c = self.class;
        const p = try s.persistent(c.fixed_key, c.fixedRegionWords());
        self.region = p.buffer;
        self.fresh = p.fresh;
        if (c.wire) |wire| {
            const region = try s.persistent(c.wire_key, wire.words.len);
            if (region.fresh) try s.upload(region.buffer, wire.words);
        }
        if (c.spec.compact_rom) |rom| {
            const region = try s.persistent(NP.persistentKey(rom.key), rom.words.len);
            if (region.fresh) try s.upload(region.buffer, rom.words);
        }
        if (p.fresh) {
            try self.fixed.stage(s, self.inputs);
            try s.upload(try p.buffer.slice(c.fixed.coefficient_cells + 8, 8), &c.spec.fixed_root);
        }
        // Twiddle towers (persistent, keyed by log inside each stage call).
        const placeholders = try self.a.alloc(C.Input, c.main.shapes.len);
        defer self.a.free(placeholders);
        for (placeholders) |*i| i.* = .{ .device = @ptrFromInt(@alignOf(u32)) };
        try self.main.stage(s, placeholders);
        try self.gkr.stageCommitted(s);
        try self.binding.stage(self.a, s);
    }
    pub fn enqueue(self: *WarmJob, e: *api.Enqueue) !void {
        const c = self.class;
        try e.slab.bind(&self.layout);
        const region = self.region orelse return error.NativeStage1NotStaged;
        const coefficients = try region.slice(0, c.fixed.coefficient_cells);
        const root = try region.slice(c.fixed.coefficient_cells, 8);
        if (self.fresh) _ = try self.fixed.enqueueInto(self.sym.commit, e, self.inputs, coefficients, root, false);
        try cuda(self.sym.commit.copy_d2d(e.ctx(), (try e.slab.field(.root, 0)).ptr, root.ptr, 32));
    }
    pub fn finish(self: *WarmJob, view: api.SlabView) !void {
        @memcpy(&self.device_root, try Slab.read(view, .root, 0));
        if (!std.mem.eql(u32, &self.device_root, &self.class.spec.fixed_root)) return error.NativeStage1FixedRootMismatch;
    }
    pub fn abort(_: *WarmJob) void {}
};

// ---------------------------------------------------------------------------
// Request job
// ---------------------------------------------------------------------------

/// CUDA-event span over a job's enqueued work. Production requests borrow
/// installed worker events; component harnesses may own their diagnostics.
pub const Span = @import("job_timing.zig").Timing.Span;

pub const Stage1Job = @import("native_stage1_job.zig").Stage1Job;

pub const Prologue = struct {
    fixed: C.Committed,
    main: C.Committed,
    fixed_root: api.DeviceBuffer,
    class_root: api.DeviceBuffer,
    /// Witness ingress status (0 = every chunk run in range), job arena.
    witness_status: api.DeviceBuffer,
    /// gn-pack v2: the program's device status words (CPU witness verdict,
    /// shared ledger status); every one must be 0 (`witness_status`).
    compact_status: [NP.max_status]api.DeviceBuffer = undefined,
    compact_status_len: usize = 0,
};

/// Stage 1 up to the MAIN root, on `e`'s exec stream and device channel:
/// channel := seed; witness -> MAIN evaluation image (chunks: h2d of each
/// staged run table + scatter; device: caller columns); mix the adopted FIXED
/// root; commit MAIN into `main_view` with its root written to `root_out`
/// and mixed. `main` is the job's staged CommitPlan copy; `runs[i]` the
/// staged device buffer of chunk i. The image is freed after the commit.
pub fn enqueuePrologue(c: *const Class, sym: *const Symbols, e: *api.Enqueue, seed: api.DeviceBuffer, fixed_region: api.DeviceBuffer, witness: Witness, runs: []const ?api.DeviceBuffer, main: *const C.CommitPlan, inputs: []C.Input, main_view: api.DeviceBuffer, root_out: api.DeviceBuffer) !Prologue {
    const ectx = e.ctx();
    const stream = e.stream();
    if (fixed_region.words < c.fixedRegionWords() or inputs.len != c.main.shapes.len or root_out.words < 8 or main_view.words < c.main.coefficient_cells) return error.NativeStage1PrologueShape;
    try e.channel.initFromCheckpoint(seed);
    const wstatus = try e.alloc(1);
    try cuda(sym.memset(ectx, wstatus.ptr, 0, 4));
    var image: ?api.DeviceBuffer = null;
    var compact_status: [NP.max_status]api.DeviceBuffer = undefined;
    var compact_len: usize = 0;
    switch (witness) {
        .chunks => |chunks| {
            if (runs.len != chunks.len) return error.NativeStage1NotStaged;
            const img = try e.alloc(c.image_words);
            image = img;
            for (chunks, runs) |ch, r| {
                const dev = r orelse return error.NativeStage1NotStaged;
                try cuda(sym.copy(@ptrCast(dev.ptr), @ptrCast(ch.words.ptr), ch.words.len * 4, 1, stream));
                const table = try chunkRuns(ch.words);
                const head = chunk_header_words + 6 * table.len;
                try cuda(sym.scatter(ectx, 0, @ptrCast(@alignCast(dev.ptr + chunk_header_words)), @intCast(table.len), dev.ptr + head, ch.words.len - head, img.ptr, img.words, wstatus.ptr));
            }
            for (inputs, c.image_offsets) |*i, off| i.* = .{ .device = img.ptr + off };
        },
        .device => |cols| {
            if (cols.len != inputs.len) return error.NativeStage1WitnessShape;
            for (inputs, cols) |*i, col| i.* = .{ .device = col };
        },
        .compact => |cw| {
            const psym = &(sym.pack orelse return error.MissingGnPackKernel);
            const program = cw.program orelse return error.NativeStage1NotStaged;
            const bound = cw.bound orelse return error.NativeStage1NotStaged;
            // Witness evaluations live in the eventual coefficient region.
            // The beta >= 2 CommitPlan stages them into its private commit
            // scratch before writing coefficients back, so they may alias
            // the output. This removes the v1 expanded-image arena term.
            if (main_view.words < c.image_words) return error.NativeStage1PrologueShape;
            const img = if (c.spec.beta != 1) try main_view.slice(0, c.image_words) else blk: {
                const allocated = try e.alloc(c.image_words);
                image = allocated;
                break :blk allocated;
            };
            // Zero first: a kernel that leaves padding rows untouched commits
            // zeros exactly as the legacy fresh MAIN leases did.
            try cuda(sym.memset(ectx, @ptrCast(img.ptr), 0, img.words * 4));
            try bound.enqueue(program, psym, e, img, c.image_offsets);
            for (inputs, c.image_offsets) |*i, off| i.* = .{ .device = img.ptr + off };
            compact_len = (try bound.statusWords(program, &compact_status)).len;
        },
    }
    const fixed_root = try fixed_region.slice(c.fixed.coefficient_cells, 8);
    try e.channel.mixRootFromTree(fixed_root);
    const fixed = C.Committed{ .coefficients = try fixed_region.slice(0, c.fixed.coefficient_cells), .root = fixed_root.ptr };
    const committed = try main.enqueueInto(sym.commit, e, inputs, main_view, root_out, true);
    if (image) |img| e.free(img);
    return .{ .fixed = fixed, .main = committed, .fixed_root = fixed_root, .class_root = try fixed_region.slice(c.fixed.coefficient_cells + 8, 8), .witness_status = wstatus, .compact_status = compact_status, .compact_status_len = compact_len };
}

// ---------------------------------------------------------------------------
// Registry: the Stage-1 half of native_device.Native
// ---------------------------------------------------------------------------

pub const Registry = @import("native_stage1_registry.zig").Registry;

test {
    _ = @import("native_device_stage1_test.zig");
    _ = @import("native_pack.zig");
    _ = @import("native_pack_capture.zig");
    _ = @import("native_pack_gpu_test.zig");
}
