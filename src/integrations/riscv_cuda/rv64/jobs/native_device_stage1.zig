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
const Timing = @import("job_timing.zig").Timing;
const Slab = @import("slab.zig");
const Sources = @import("../gkr_sources.zig");
const W = @import("worker.zig");
const ND = @import("native_device.zig");
/// gn-pack: compact TraceChunk v2 + the device witness program.
pub const NP = @import("native_pack.zig");

pub const granule: usize = 64;
fn up(x: usize) usize {
    return std.mem.alignForward(usize, x, granule);
}

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
    copy: @FieldType(@import("ops.zig").Exec, "copy_async"),
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
            .copy = addon.lookup(@FieldType(Symbols, "copy"), "stwo_rv64_jobs_copy_async") orelse return error.MissingNativeStage1Kernel,
            .memset = base.lookup(*const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int, "stwo_exec_context_memset_async") orelse return error.MissingNativeStage1Kernel,
            .commit = try C.Symbols.load(base),
            .gkr = gkr,
            .binding = try NB.Symbols.load(base),
        };
    }
};

fn cuda(status: c_int) !void {
    if (status != 0) return error.CudaEnqueueFailed;
}

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

pub const Stage1Job = struct {
    a: std.mem.Allocator,
    class: *const Class,
    sym: *const Symbols,
    ctx: *const G.RequestContext,
    segment: u32,
    device: u32,
    words: RequestWords,
    witness: Witness,
    timing: ?*const Timing = null,
    timing_storage: enum { owned, installed } = .owned,
    // per-job shallow copies of the class plans (stage writes device views
    // into them; the class plans stay immutable and shareable across GPUs)
    main: C.CommitPlan = undefined,
    gplan: NG.Plan = undefined,
    items: []Sources.Item = &.{},
    gkr: NG.Gkr = undefined,
    binding: NB.Binding = undefined,
    inputs: []C.Input = &.{},
    // staged
    seed: ?api.DeviceBuffer = null,
    fixed: ?api.DeviceBuffer = null,
    wire_program: ?api.DeviceBuffer = null,
    wire_scope: ?api.DeviceBuffer = null,
    runs: []?api.DeviceBuffer = &.{},
    /// gn-pack v2 witness program (parsed at init) and its device buffers.
    program: ?NP.Program = null,
    bound: NP.Bound = .{},
    span: Span = .{},
    initialized: bool = false,

    pub fn init(self: *Stage1Job) !void {
        const c = self.class;
        if (self.words.publics.len != c.spec.gkr.source.items.len) return error.NativeStage1RequestWords;
        if (self.segment >= self.ctx.main_resident.len or self.segment >= self.ctx.segment_device.len) return error.GpuNativeSegmentOutOfRange;
        if (self.ctx.segment_device[self.segment] != self.device) return error.GpuNativeSegmentDeviceMismatch;
        switch (self.witness) {
            .chunks => |chunks| {
                for (chunks) |ch| {
                    if (ch.segment != self.segment) return error.NativeStage1ChunkSegment;
                    try validateChunk(ch.words, c.image_words);
                }
                try validateCoverage(self.a, chunks, c.image_words);
            },
            .device => |cols| if (cols.len != c.main.shapes.len) return error.NativeStage1WitnessShape,
            .compact => |cw| {
                if (self.sym.pack == null) return error.MissingGnPackKernel;
                for (cw.chunks) |ch| if (ch.segment != self.segment) return error.NativeStage1ChunkSegment;
                self.program = try NP.Program.parse(self.a, cw.chunks, c.main.shapes.len);
            },
        }
        errdefer if (self.program) |*p| p.deinit();
        if (self.program) |*p| {
            try p.checkMainLogs(c.spec.gkr.logs[c.spec.gkr.fixed_count..]);
            // The plan bound (arena_peak_words via jobWords) must hold the program.
            if (c.spec.compact_words != 0 and p.arenaWords() > c.spec.compact_words) return error.GnPackArenaExceedsPlan;
        }
        self.main = try C.jobCopy(self.a, &c.main);
        errdefer C.freeJobCopy(self.a, &self.main);
        self.gplan = c.spec.gkr.*;
        self.gplan.prefix = self.words.prefix;
        self.items = try self.a.dupe(Sources.Item, c.spec.gkr.source.items);
        errdefer self.a.free(self.items);
        for (self.items, self.words.publics) |*it, pw| it.public = pw;
        self.gplan.source.items = self.items;
        self.gkr = try NG.Gkr.init(self.a, &self.gplan, self.sym.gkr orelse return error.NativeStage1SymbolsNotBound);
        errdefer self.gkr.deinit();
        self.binding = .{ .plan = &c.bind, .sym = self.sym.binding };
        self.inputs = try self.a.alloc(C.Input, c.main.shapes.len);
        errdefer self.a.free(self.inputs);
        self.runs = try self.a.alloc(?api.DeviceBuffer, switch (self.witness) {
            .chunks => |chunks| chunks.len,
            .device, .compact => 0,
        });
        @memset(self.runs, null);
        self.initialized = true;
    }
    pub fn deinit(self: *Stage1Job) void {
        if (!self.initialized) return;
        self.span.close(self.timing);
        self.a.free(self.runs);
        if (self.program) |*p| p.deinit();
        self.program = null;
        self.a.free(self.inputs);
        self.gkr.deinit();
        self.a.free(self.items);
        C.freeJobCopy(self.a, &self.main);
        self.initialized = false;
    }
    pub fn id(self: *const Stage1Job) G.ProofId {
        return .{ .kind = .native_segment, .ordinal = self.segment };
    }
    pub fn classKey(self: *Stage1Job) [32]u8 {
        var k = self.class.spec.key;
        k[0] ^= 0x51; // Stage-1 job class (distinct from the Stage-2 job of the same segment class)
        return k;
    }
    pub fn footprint(self: *Stage1Job) api.Footprint {
        const c = self.class;
        var chunk_words: usize = 0;
        switch (self.witness) {
            .chunks => |chunks| for (chunks) |ch| {
                chunk_words += up(ch.words.len);
            },
            .device => {},
            .compact => if (self.program) |*p| {
                chunk_words += p.arenaWords();
            },
        }
        // jobWords() already carries Spec.compact_words (the class's planned
        // v2 program bound, checked >= this program's arena at init): only an
        // unplanned program (compact_words 0) adds its arena on top.
        const planned: usize = if (self.witness == .compact and c.spec.compact_words != 0) chunk_words else 0;
        const staged = up(9) + granule + c.spec.gkr.stagedWords(true) + up(c.main.stagedWords(0)) + chunk_words;
        return .{ .device_words = c.jobWords() + chunk_words - planned, .staged_words = staged, .slab_words = 0, .pinned_words = c.requestPinnedWords() };
    }
    pub fn stage(self: *Stage1Job, s: *api.Stager) !void {
        if (self.timing != null and self.timing_storage == .installed) self.span = Span.borrow(try s.timingPair(self.ctx.parity, self.segment));
        const c = self.class;
        // FIXED adoption: the class region must already be warm on this GPU.
        const p = try s.persistent(c.fixed_key, c.fixedRegionWords());
        if (p.fresh) return error.GpuNativeFixedNotWarmed;
        self.fixed = p.buffer;
        if (c.wire) |wire| {
            const region = try s.persistent(c.wire_key, wire.words.len);
            if (region.fresh) return error.GpuNativeReceiptNotWarmed;
            self.wire_program = region.buffer;
            var scope: [25]u32 = @splat(0);
            for (scope[0..8], 0..) |*word, i| word.* = std.mem.readInt(u32, self.words.statement[4 * i ..][0..4], .little);
            @memcpy(scope[8..16], &c.spec.fixed_root);
            scope[24] = self.segment;
            self.wire_scope = try s.alloc(25);
            try s.upload(self.wire_scope.?, &scope);
        }
        const seed = try s.alloc(9);
        try s.upload(seed, &self.words.seed);
        self.seed = seed;
        for (self.inputs) |*i| i.* = .{ .device = @ptrFromInt(@alignOf(u32)) };
        try self.main.stage(s, self.inputs);
        try self.gkr.stageCommitted(s);
        try self.binding.stage(self.a, s);
        switch (self.witness) {
            // One arena buffer per chunk (run table + data); the h2d from
            // the pinned ring is enqueued on the exec stream at enqueue.
            .chunks => |chunks| for (chunks, self.runs) |ch, *r| {
                r.* = try s.alloc(ch.words.len);
            },
            .device => {},
            .compact => |*cw| {
                const prog = if (self.program) |*pp| pp else return error.NativeStage1NotStaged;
                try self.bound.stage(prog, s, cw.roms);
                cw.program = prog;
                cw.bound = &self.bound;
            },
        }
        try self.span.open(self.timing);
    }
    fn statusWord(self: *Stage1Job, check: G.Check) !api.DeviceBuffer {
        const d = self.device;
        if (d >= self.ctx.layout.segments.len or d >= self.ctx.segments.len) return error.GpuNativeProofDeviceOutOfRange;
        return self.ctx.layout.segments[d].statusBuffer(self.ctx.segments[d], self.id(), check);
    }
    fn exchangeSlot(self: *Stage1Job, slot: G.Exchange.Slot) !api.DeviceBuffer {
        const d = self.device;
        const ex = try self.ctx.layout.segments[d].exchangeBuffer(self.ctx.segments[d]);
        return ex.slice(slot.offset, slot.words);
    }
    pub fn enqueue(self: *Stage1Job, e: *api.Enqueue) !void {
        var trace_label: [80]u8 = undefined;
        var trace_range = try e.trace(.native_stage1, self.segment, &trace_label);
        defer trace_range.deinit();
        const c = self.class;
        const sym = self.sym;
        const ectx = e.ctx();
        const stream = e.stream();
        // Every precondition before the first enqueued op.
        const seed = self.seed orelse return error.NativeStage1NotStaged;
        const fixed_region = self.fixed orelse return error.NativeStage1NotStaged;
        const resident = self.ctx.main_resident[self.segment];
        const main_view = try c.resident.mainView(resident);
        const bind_view = try c.resident.bindingView(resident);
        const section_view = try c.resident.sectionView(resident);
        const authority_view = try c.resident.authorityView(resident);
        const checkpoint_view = try c.resident.checkpointView(resident);
        const root_slot = try self.ctx.exchange.root(self.segment);
        const claims_slot = try self.ctx.exchange.claims(self.segment);
        const claims_payload = try claimPayloadSlot(self.ctx.exchange, self.segment, c.claimsPerSegment());
        const root_out = try self.exchangeSlot(root_slot);
        const claims_out = try self.exchangeSlot(claims_payload);
        const st_witness = try self.statusWord(.witness_status);
        const st_binding = try self.statusWord(.binding_authority);
        const st_root = try self.statusWord(.root_match);

        try self.span.mark(self.timing, .begin, stream);
        // The GKR writes its section through e.slab: point it at the resident
        // section region for this job (the batch job slab is empty).
        const saved = e.slab.*;
        defer e.slab.* = saved;
        e.slab.* = .{ .device = section_view };
        try e.slab.bind(&c.section);

        const pro = try enqueuePrologue(c, sym, e, seed, fixed_region, self.witness, self.runs, &self.main, self.inputs, main_view, root_out);
        const fixed_root = pro.fixed_root;
        const class_root = pro.class_root;
        const fixed = pro.fixed;
        const main = pro.main;
        const wstatus = pro.witness_status;
        // The transcript Stage 2 continues from (seed -> FIXED -> MAIN).
        const main_cursor = e.channel.step;
        const main_chain = e.channel.expectedChain(main_cursor);
        const checkpoint_slab = Slab.ProofSlab{ .device = checkpoint_view };
        try e.channel.snapshot(&checkpoint_slab, 0);
        try self.ctx.peer.publish(self.device, root_slot);

        // Local GKR + binding.
        try self.gkr.enqueueCommitted(e, &c.fixed, fixed, &self.main, main, root_out);
        const bverdict = try e.alloc(1);
        try cuda(sym.memset(ectx, bverdict.ptr, 0, 4));
        const semantic = try resident.slice(c.resident.semantic, c.resident.semantic_words);
        const draws = self.gkr.reservoir orelse return error.NativeGkrNotEnqueued;
        if (draws.words != Semantic.local_words) return error.NativeSemanticShape;
        try cuda(sym.commit.copy_d2d(ectx, semantic.ptr, draws.ptr, draws.bytes()));
        try self.binding.enqueueComplete(e, &self.gkr, bind_view, bverdict, authority_view, semantic);
        // Terminal claims (authority words [9, 9 + 16n)) -> exchange claims slot.
        const claims = try authority_view.slice(9, claims_out.words);
        // The full slot is peer-published. Clear its unused suffix so it
        // never transports stale words from another class/request.
        if (claims_payload.words < claims_slot.words) {
            const full = try self.exchangeSlot(claims_slot);
            try cuda(sym.memset(ectx, full.ptr + claims_payload.words, 0, (claims_slot.words - claims_payload.words) * 4));
        }
        try cuda(sym.commit.copy_d2d(ectx, claims_out.ptr, claims.ptr, claims_out.words * 4));
        try self.ctx.peer.publish(self.device, claims_slot);
        if (c.wire) |wire| {
            const encode = sym.receipt_encode orelse return error.MissingLocalGkrReceiptEncoder;
            const program = self.wire_program orelse return error.NativeStage1NotStaged;
            const scope = self.wire_scope orelse return error.NativeStage1NotStaged;
            const receipt = try resident.slice(c.resident.receipt, 16);
            const child_wire = try resident.slice(c.resident.local_wire, wire.wireWords());
            try cuda(sym.commit.copy_d2d(ectx, scope.ptr + 16, root_out.ptr, 32));
            const args = Wire.Run{ .program = program.ptr, .program_words = program.words, .section = section_view.ptr, .section_words = section_view.words, .scope = scope.ptr, .marginals = claims.ptr, .marginal_words = claims.words, .receipt = receipt.ptr, .wire = child_wire.ptr, .wire_words = child_wire.words, .verdict = (try self.statusWord(.local_receipt)).ptr, .reject_code = @as(u32, @intFromEnum(G.Check.local_receipt)) << 16 };
            try cuda(encode(ectx, 0, &args));
            const rs = try self.ctx.exchange.receipt(self.segment);
            const ws = try self.ctx.exchange.childWire(self.segment);
            if (ws.words < child_wire.words) return error.GpuNativeExchangeSlot;
            try cuda(sym.commit.copy_d2d(ectx, (try self.exchangeSlot(rs)).ptr, receipt.ptr, 32));
            try cuda(sym.commit.copy_d2d(ectx, (try self.exchangeSlot(ws)).ptr, child_wire.ptr, child_wire.bytes()));
            try self.ctx.peer.publish(self.device, rs);
            try self.ctx.peer.publish(self.device, ws);
        }

        // Device acceptance checks (one Verdict word each).
        const traversal = (self.gkr.traversal orelse return error.NativeGkrNotEnqueued).traversal;
        const header = try e.slab.field(.gkr_section, c.spec.gkr.fields.header());
        const child = try e.slab.field(.snapshot, c.spec.gkr.fields.base);
        var w = CheckSpec{ .check = @intFromEnum(G.Check.witness_status) };
        try w.mustBeZero(wstatus);
        for (pro.compact_status[0..pro.compact_status_len]) |st| try w.mustBeZero(st);
        try cuda(sym.check(ectx, 0, &w, st_witness.ptr));
        var b = CheckSpec{ .check = @intFromEnum(G.Check.binding_authority) };
        try b.mustBeZero(try e.slab.field(.status, c.spec.gkr.fields.status()));
        try b.mustBeZero(bverdict);
        try b.mustMatch(try header.slice(8, 12), &headerGuard(traversal.layers, traversal.count, traversal.chain));
        try b.mustMatch(try child.slice(8, 8), &snapshotGuard(c.child_draws, self.gkr.child_steps, self.gkr.child_chain));
        try cuda(sym.check(ectx, 0, &b, st_binding.ptr));
        var r = CheckSpec{ .check = @intFromEnum(G.Check.root_match) };
        try r.mustEqual(fixed_root, class_root);
        try r.mustEqual(root_out, try e.slab.field(.gkr_section, c.spec.gkr.fields.mainRoot()));
        try r.mustMatch(try checkpoint_view.slice(8, 8), &snapshotGuard(0, main_cursor, main_chain));
        try cuda(sym.check(ectx, 0, &r, st_root.ptr));
        try self.span.mark(self.timing, .end, stream);
    }
    /// After the request's single wait: only the CUDA-event span (the
    /// verdict words are read by `gpu_native.publish`).
    pub fn finish(self: *Stage1Job, _: api.SlabView) !void {
        self.span.read(self.timing);
    }
    pub fn abort(_: *Stage1Job) void {}
};

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

const Done = struct {
    event: std.Thread.ResetEvent = .{},
    result: anyerror!void = {},
    fn call(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        self.result = c.result;
        self.event.set();
    }
};

/// ClassCache builder of a Stage-1 entry: the plan is the registry's Class
/// (borrowed; the registry destroys it), Stage-1 constants filled in.
const EntryBuilder = struct {
    class: *Class,
    devices: u32,
    fn build(raw: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
        const self: *EntryBuilder = @ptrCast(@alignCast(raw));
        var entry = G.ClassEntry{ .key = key, .plan = self.class, .destroy = noop };
        self.class.fill(&entry, self.devices);
        return entry;
    }
    fn noop(_: *anyopaque) void {}
};

pub const Registry = struct {
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    specs: std.AutoArrayHashMapUnmanaged(G.ClassKey, Spec) = .empty,
    classes: std.AutoArrayHashMapUnmanaged(G.ClassKey, *Class) = .empty,
    /// Segment rows -> class (class_of from capture geometry).
    by_rows: std.AutoHashMapUnmanaged(u64, G.ClassKey) = .empty,
    /// Per (request generation, segment): the request words and the chunks.
    requests: std.AutoHashMapUnmanaged(u64, *Pending) = .empty,
    sym: ?*const Symbols = null,
    timing: ?*const Timing = null,
    /// gn-pack: host ROM words for the v2 programs' persistent ROM regions
    /// (filled by native_pack_capture.pack on the capture thread).
    roms: ?*NP.Roms = null,
    /// Workers by driver device index (WarmJob per class and GPU at install).
    workers: []const *W.Worker = &.{},
    /// GPUs the service runs (set before warm): `held_words` is reserved on
    /// each of them. 0 = `workers.len`; a class registered with neither set
    /// refuses to warm (it would budget only GPU 0).
    devices: u32 = 0,
    /// Devices the warmed entries reserved held words on.
    warmed_devices: u32 = 0,
    sealed: bool = false,

    /// native_device.Native.stage1_hooks of this registry.
    pub fn hooks(self: *Registry) ND.Stage1Hooks {
        return .{ .ctx = self, .warm = hWarm, .installed = hInstalled, .class_of = hClassOf, .stage1 = hStage1, .chunk = hChunk };
    }
    fn reg(raw: *anyopaque) *Registry {
        return @ptrCast(@alignCast(raw));
    }
    fn hWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const self = reg(raw);
        return self.warm(cache, if (self.devices != 0) self.devices else @intCast(self.workers.len));
    }
    fn hInstalled(raw: *anyopaque, info: *const G.Installed) anyerror!void {
        const self = reg(raw);
        if (self.workers.len < info.devices) return error.NativeStage1WorkersNotBound;
        if (self.classes.count() != 0 and info.devices > self.warmed_devices) return error.NativeStage1DevicesNotWarmed;
        try self.warmDevices(self.workers[0..info.devices]);
        self.seal();
    }
    fn hClassOf(raw: *anyopaque, rows: u64) anyerror!G.ClassKey {
        return reg(raw).classOf(rows);
    }
    fn hStage1(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        if (ctx.native_classes.len != 0) return reg(raw).deferred(ctx, segment, device);
        return reg(raw).stage1(ctx, segment, device);
    }
    fn hChunk(raw: *anyopaque, ctx: *const G.RequestContext, c: G.TraceChunk) anyerror!void {
        return reg(raw).chunk(ctx, c);
    }

    pub const Pending = struct {
        key: ?G.ClassKey = null,
        words: ?RequestWords = null,
        publics: []PublicWords = &.{},
        chunks: std.ArrayListUnmanaged(G.TraceChunk) = .empty,
        device: ?[]const [*]const u32 = null,
        job: ?*Stage1Job = null,
        deferred_job: ?*Deferred = null,
    };

    pub fn init(a: std.mem.Allocator) Registry {
        return .{ .a = a };
    }
    pub fn deinit(self: *Registry) void {
        var it = self.requests.valueIterator();
        while (it.next()) |p| self.dropPending(p.*);
        self.requests.deinit(self.a);
        for (self.classes.values()) |c| c.deinit();
        self.classes.deinit(self.a);
        self.specs.deinit(self.a);
        self.by_rows.deinit(self.a);
    }
    fn dropPending(self: *Registry, p: *Pending) void {
        if (p.deferred_job) |j| self.a.destroy(j);
        if (p.job) |j| {
            j.deinit();
            self.a.destroy(j);
        }
        p.chunks.deinit(self.a);
        self.a.free(p.publics);
        self.a.destroy(p);
    }
    fn pendingKey(generation: u64, segment: u32) u64 {
        return (generation << 16) | segment;
    }

    /// Install time: register a class (same key twice must be the same spec).
    pub fn register(self: *Registry, spec: Spec, rows: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sealed) return error.GpuNativeClassBuildOnRequestPath;
        if (self.specs.get(spec.key)) |old| {
            if (old.gkr != spec.gkr or old.fixed_shapes.ptr != spec.fixed_shapes.ptr or old.main_shapes.ptr != spec.main_shapes.ptr) return error.GpuNativeClassKeyMismatch;
        } else try self.specs.put(self.a, spec.key, spec);
        if (self.by_rows.get(rows)) |k| {
            if (!std.mem.eql(u8, &k, &spec.key)) return error.GpuNativeClassKeyMismatch;
        } else try self.by_rows.put(self.a, rows, spec.key);
    }
    /// Warm: build every registered class (host plans) and fill its entry.
    pub fn warm(self: *Registry, cache: *G.ClassCache, devices: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.specs.count() != 0 and devices == 0) return error.NativeStage1DevicesNotBound;
        self.warmed_devices = @min(devices, G.max_devices);
        for (self.specs.values()) |spec| {
            const cl = if (self.classes.get(spec.key)) |c| c else blk: {
                const c = try Class.init(self.a, spec);
                errdefer c.deinit();
                try self.classes.put(self.a, spec.key, c);
                break :blk c;
            };
            // Another admitted block may need a larger compact staging span
            // for the same immutable class. Replan from the complete bound.
            cl.spec.capture_words = @max(cl.spec.capture_words, spec.capture_words);
            cl.spec.compact_words = @max(cl.spec.compact_words, spec.compact_words);
            if (spec.compact_rom) |rom| cl.spec.compact_rom = rom;
            var builder = EntryBuilder{ .class = cl, .devices = devices };
            _ = try cache.warm(spec.key, .{ .ctx = &builder, .build = EntryBuilder.build });
        }
    }
    /// Install (after the memory plan, before the cache seals): one WarmJob
    /// per (class, GPU) on that GPU's worker, waited here (install time).
    pub fn warmDevices(self: *Registry, workers: []const *W.Worker) !void {
        const sym = self.sym orelse return error.NativeStage1SymbolsNotBound;
        for (self.classes.values()) |cl| for (workers) |w| {
            var job = WarmJob{ .a = self.a, .class = cl, .sym = sym };
            try job.init();
            defer job.deinit();
            var done = Done{};
            while (true) {
                w.submit(api.Job.from(WarmJob, &job), .{ .ctx = &done, .done = Done.call }) catch |err| switch (err) {
                    error.WorkerBusy => {
                        std.Thread.sleep(20 * std.time.ns_per_us);
                        continue;
                    },
                    else => return err,
                };
                break;
            }
            done.event.wait();
            try done.result;
        };
    }
    pub fn seal(self: *Registry) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.sealed = true;
    }
    pub fn classOf(self: *Registry, rows: u64) !G.ClassKey {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_rows.get(rows) orelse error.GpuNativeClassNotWarmed;
    }
    pub fn class(self: *Registry, key: G.ClassKey) !*const Class {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.classes.get(key) orelse error.GpuNativeClassNotWarmed;
    }
    fn pending(self: *Registry, generation: u64, segment: u32) !*Pending {
        const gop = try self.requests.getOrPut(self.a, pendingKey(generation, segment));
        if (!gop.found_existing) {
            const p = try self.a.create(Pending);
            p.* = .{};
            gop.value_ptr.* = p;
        }
        return gop.value_ptr.*;
    }
    /// Service, per request and segment: the challenge-free request words.
    pub fn setRequest(self: *Registry, generation: u64, segment: u32, key: G.ClassKey, words: RequestWords) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.classes.contains(key)) return error.GpuNativeClassNotWarmed;
        const p = try self.pending(generation, segment);
        if (p.key) |expected| if (!std.mem.eql(u8, &expected, &key)) return error.GpuNativeClassKeyMismatch;
        if (p.words != null) return error.NativeStage1RequestWordsTwice;
        p.key = key;
        p.publics = try self.a.dupe(PublicWords, words.publics);
        p.words = .{ .statement = words.statement, .seed = words.seed, .prefix = words.prefix, .publics = p.publics };
    }
    /// Parity/upstream producers: MAIN columns already on device.
    pub fn setDeviceWitness(self: *Registry, generation: u64, segment: u32, columns: []const [*]const u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = try self.pending(generation, segment);
        if (p.chunks.items.len != 0 or p.device != null) return error.NativeStage1WitnessTwice;
        p.device = columns;
    }
    /// Capture thread (NativeFactory.chunk): record the chunk (no GPU work).
    pub fn chunk(self: *Registry, ctx: *const G.RequestContext, c: G.TraceChunk) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = try self.pending(ctx.generation, c.segment);
        if (p.device != null) return error.NativeStage1WitnessTwice;
        if (p.job != null) return error.GpuNativeCaptureChunkAfterSeal;
        if (c.sequence != p.chunks.items.len) return error.GpuNativeCaptureGeometryMismatch;
        if (NP.isV2(c.words)) {
            if (c.words[1] != NP.version) return error.NativeStage1ChunkFormat;
        } else _ = try chunkRuns(c.words);
        try p.chunks.append(self.a, c);
    }
    /// NativeFactory.stage1: the job (owned by the registry until `release`).
    /// Construction precedes capture. The worker's segment-ready gate fires
    /// before `stage`, so only then may the job consume chunks/public words.
    pub fn deferred(self: *Registry, ctx: *const G.RequestContext, segment: u32, device: u32) !api.Job {
        if (segment >= ctx.native_classes.len) return error.GpuNativeSegmentOutOfRange;
        const key = ctx.native_classes[segment];
        self.mutex.lock();
        defer self.mutex.unlock();
        const cl = self.classes.get(key) orelse return error.GpuNativeClassNotWarmed;
        const p = try self.pending(ctx.generation, segment);
        if (p.deferred_job != null or p.job != null) return error.NativeStage1JobTwice;
        if (p.key) |expected| if (!std.mem.eql(u8, &expected, &key)) return error.GpuNativeClassKeyMismatch;
        const j = try self.a.create(Deferred);
        j.* = .{ .registry = self, .ctx = ctx, .segment = segment, .device = device, .class = cl };
        p.key = key;
        p.deferred_job = j;
        return api.Job.from(Deferred, j);
    }

    pub const Deferred = struct {
        registry: *Registry,
        ctx: *const G.RequestContext,
        segment: u32,
        device: u32,
        class: *const Class,
        inner: ?api.Job = null,
        pub fn classKey(self: *Deferred) [32]u8 {
            var k = self.class.spec.key;
            k[0] ^= 0x51;
            return k;
        }
        pub fn footprint(self: *Deferred) api.Footprint {
            const c = self.class;
            return .{ .device_words = c.jobWords(), .staged_words = up(9) + granule + c.spec.gkr.stagedWords(true) + up(c.main.stagedWords(0)) + @as(usize, @intCast(c.spec.compact_words)), .pinned_words = c.requestPinnedWords() };
        }
        pub fn stage(self: *Deferred, s: *api.Stager) !void {
            const job = try self.registry.stage1(self.ctx, self.segment, self.device);
            self.inner = job;
            // The class budget is fixed before capture, never enlarged on a
            // request. An unexpectedly large witness fails before upload.
            if (job.footprint().device_words > self.footprint().device_words) return error.NativeStage1CompactExceedsPlan;
            try job.vtable.stage(job.ctx, s);
        }
        pub fn enqueue(self: *Deferred, e: *api.Enqueue) !void {
            const j = self.inner orelse return error.NativeStage1WitnessMissing;
            try j.vtable.enqueue(j.ctx, e);
        }
        pub fn finish(self: *Deferred, v: api.SlabView) !void {
            const j = self.inner orelse return error.NativeStage1WitnessMissing;
            try j.vtable.finish(j.ctx, v);
        }
        pub fn abort(self: *Deferred) void {
            if (self.inner) |j| j.vtable.abort(j.ctx);
        }
    };

    pub fn stage1(self: *Registry, ctx: *const G.RequestContext, segment: u32, device: u32) !api.Job {
        const sym = self.sym orelse return error.NativeStage1SymbolsNotBound;
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = try self.pending(ctx.generation, segment);
        if (p.job != null) return error.NativeStage1JobTwice;
        const words = p.words orelse return error.NativeStage1RequestWordsMissing;
        const cl = self.classes.get(p.key.?) orelse return error.GpuNativeClassNotWarmed;
        const witness: Witness = if (p.device) |d| .{ .device = d } else if (p.chunks.items.len != 0)
            (if (try chunksAreV2(p.chunks.items)) .{ .compact = .{ .chunks = p.chunks.items, .roms = self.roms } } else .{ .chunks = p.chunks.items })
        else
            return error.NativeStage1WitnessMissing;
        const job = try self.a.create(Stage1Job);
        errdefer self.a.destroy(job);
        job.* = .{ .a = self.a, .class = cl, .sym = sym, .ctx = ctx, .segment = segment, .device = device, .words = words, .witness = witness, .timing = self.timing, .timing_storage = .installed };
        try job.init();
        p.job = job;
        return api.Job.from(Stage1Job, job);
    }
    /// GPU span of a segment's Stage 1 [M] (after the request's wait), or -1.
    pub fn gpuMs(self: *Registry, generation: u64, segment: u32) f32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = self.requests.get(pendingKey(generation, segment)) orelse return -1;
        return if (p.job) |j| j.span.gpu_ms else -1;
    }
    /// Request end (success or abort): drop every pending record of it.
    pub fn release(self: *Registry, generation: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var doomed: std.ArrayListUnmanaged(u64) = .empty;
        defer doomed.deinit(self.a);
        var it = self.requests.iterator();
        while (it.next()) |kv| if (kv.key_ptr.* >> 16 == generation) doomed.append(self.a, kv.key_ptr.*) catch {};
        for (doomed.items) |k| if (self.requests.fetchRemove(k)) |kv| self.dropPending(kv.value);
    }
};

test {
    _ = @import("native_device_stage1_test.zig");
    _ = @import("native_pack.zig");
    _ = @import("native_pack_capture.zig");
    _ = @import("native_pack_gpu_test.zig");
}
