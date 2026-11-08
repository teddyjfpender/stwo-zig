//! OuterNodeJob (spec §3.5 item 4): one recursion node (leaf, fold or root)
//! as an api.Job. Host preparation already happened in the pre-stage
//! (rv64/outer_job_prestage.zig, on a host pool); this file is the three
//! phases:
//!   stage   - upload the node region; the class and twiddle regions only when
//!             this worker has not seen the class (Stager.persistent);
//!   enqueue - outer_node.zig on the exec stream, captured per (class,
//!             placement) once warm and rebound per node (outer_graph_cache);
//!   finish  - decode the outer slab section: status latches, canonical
//!             claims, lookupSum == 0, then the tail's proof fields.
const std = @import("std");
const api = @import("api.zig");
const Slab = @import("slab.zig");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");
const St = @import("outer_staged.zig");
const N = @import("outer_node.zig");
const Graphs = @import("outer_graph_cache.zig");
const Heap = @import("outer_heap.zig");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Pcs = @import("native_pcs.zig");
const Comp = @import("outer_composition.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const core = @import("stwo_core");
const TC = @import("outer_trace_commit.zig");
const Env = @import("outer_env.zig");
const CP = @import("outer_class_plan.zig");
const Checks = @import("outer_checks.zig");
const Packed = @import("outer_packed_class.zig");

/// Slab field indices (`Slab.Kind.opaque_words`): the outer section, the
/// native PCS result image and the OODS points (native_pcs.zig).
pub const section_index: u32 = 0x4f55_5452; // "OUTR"
pub const pcs_index: u32 = 0x5043_5331; // "PCS1"
pub const oods_index: u32 = 0x4f4f_4453; // "OODS"

/// Whole-node bindings (composition kernels, enqueue-only PCS symbols).
pub const Whole = struct {
    composition: *const Comp.Kernels,
    pcs: Pcs.Symbols,
    /// Base image PCS framing version >= 3 (pcs_native.zig wide_pcs_framing).
    wide: bool,
    /// Device acceptance checks (outer_checks.zig); null: host checks only.
    checks: ?Checks.Symbols = null,
};

/// Node buffers that live through PCS, allocated before the body so the PCS
/// framing names real addresses. Only what the PCS opens (coefficients) and
/// what composition reads lives this long; trees are transient (streamed) or,
/// on the full-LDE path, held as before.
const Held = struct {
    long: N.Long,
    composition: K.Buffer,
    composition_tree: ?K.Buffer,
    rc_parameters: K.Buffer,
};

pub const Decoded = @import("outer_result.zig").Decoded;
pub const decode = @import("outer_result.zig").decode;
const root = @import("outer_result.zig").root;

pub const Timing = K.Timing;

pub const Report = struct {
    outcome: Graphs.Outcome = .direct,
    /// Host launch calls, including graph recording and fallback attempts.
    launches: u32 = 0,
    recording_launches: u32 = 0,
    /// Launches the body issued when recorded (graph kernel nodes, if captured).
    body_launches: u32 = 0,
    kernel_nodes: u64 = 0,
    staged_words: [3]u64 = .{ 0, 0, 0 },
    receipt: api.Receipt = .{},
    /// Work heap (outer_heap.zig): region words, peak live words, allocations.
    heap_words: u64 = 0,
    heap_peak_words: u64 = 0,
    heap_allocations: u64 = 0,
    /// Highest heap offset used (region the schedule needs) and per-phase
    /// live peaks / high-waters (outer_heap.Phase order).
    heap_high_words: u64 = 0,
    phase_peak_words: [Heap.Heap.n_phases]u64 = @splat(0),
    phase_high_words: [Heap.Heap.n_phases]u64 = @splat(0),
    /// Largest single heap allocation (words) of the outer kernels (against
    /// the 2^31 index guard) and of the native PCS (unguarded).
    max_alloc_words: u64 = 0,
    max_unguarded_alloc_words: u64 = 0,
    streamed: bool = false,
    /// Region.fixed came from the lane's FIXED precommit (no in-node commit).
    fixed_handoff: bool = false,
    /// Worker-thread time inside finish (slab decode, root checks and, unless
    /// deferred, the PCS proof decode).
    finish_ns: u64 = 0,
    /// Lane-thread time of decodeProof (deferred PCS proof decode).
    decode_ns: u64 = 0,
};

/// FIXED coefficients a FixedJob of the same lane left in worker-persistent
/// memory (outer_job_factory.zig Lane.precommitFixed): `key`/`words` name the
/// Stager.persistent region. The factory sets it only when the precommit's
/// root equals this node's `staged.fixed_root` (same evaluations, same
/// commit plan, so the same coefficients); stage() still recommits in the
/// node when the region turns out fresh (e.g. released). Either way the PCS
/// rebuilds the FIXED tree from Region.fixed and decode checks its root
/// against `staged.fixed_root` (native_pcs.checkRoots): a wrong handoff fails
/// closed (NativePcsTreeRootMismatch), it cannot change a proof byte.
pub const FixedHandoff = struct { key: [32]u8, words: usize };

pub const OuterNodeJob = struct {
    staged: *St.Staged,
    kernels: *const K.Kernels,
    mode: N.Mode = .full,
    tail: ?N.Tail = null,
    /// Per-worker graph cache (the integration layer keeps one per device).
    graphs: ?*Graphs.Cache = null,
    /// Steps of the device channel snapshotted into the slab (parity only).
    snapshots: bool = false,
    layout: Slab.ProofLayout = .{},
    bases: St.Bases = undefined,
    decoded: ?Decoded = null,
    report: Report = .{},
    finished: bool = false,
    /// Slab words retained by finish for the parity harness (caller-owned copy).
    keep_slab: ?[]u32 = null,
    whole: ?Whole = null,
    pcs: ?Pcs.PcsJob = null,
    pcs_plan: Pcs.Plan = .{},
    pcs_pinned: []u32 = &.{},
    held: ?Held = null,
    /// finish() output of a whole node: PCS proof containers (caller deinit).
    pcs_proof: ?@import("../hybrid_pcs.zig").Decoded = null,
    composition_root: [32]u8 = @splat(0),
    oods: [16]u32 = @splat(0),
    /// Job-internal host containers (stream schedules, PCS framing).
    allocator: std.mem.Allocator = std.heap.c_allocator,
    /// Allocator of `pcs_proof`. assemble MOVES the decoded proof into the
    /// caller's om31 Produced, which the request layer frees with ITS
    /// allocator: the two must be the same allocator (outer_job_factory
    /// sets it to the prove() allocator). A mismatch freed malloc memory
    /// through the legacy budgeted recycler: "host budget heap underflow"
    /// at teardown, smp free-list corruption, corrupted later proofs.
    proof_allocator: std.mem.Allocator = std.heap.c_allocator,
    timing: ?Timing = null,
    fixed_commit: ?N.FixedCommit = null,
    /// Streamed commit schedules (null: full-LDE path; STWO_RV64_M8_OUTER_STREAM=0).
    streams: ?N.Streams = null,
    composition_stream: ?Comp.CommitStream = null,
    /// Fold classes keep their class region in worker-persistent memory
    /// (outside the arena). The hybrid window clears this: its workers park
    /// between requests, and class regions outside the arena would grow with
    /// every fold class the service sees; each node stages its class region
    /// inside its own arena window instead.
    persistent_classes: bool = true,
    /// Native service requests may only bind class resources warmed at install.
    require_warm: bool = false,
    packed_class: ?*const Packed.Class = null,
    packed_launch: ?Packed.Launch = null,
    packed_program: api.DeviceBuffer = undefined,
    packed_output: api.DeviceBuffer = undefined,
    packed_scratch: api.DeviceBuffer = undefined,
    packed_verdict: ?api.DeviceBuffer = null,
    /// See FixedHandoff (whole nodes only).
    fixed_handoff: ?FixedHandoff = null,
    /// PCS proof decode left to the caller (decodeProof after the completion),
    /// so the worker thread returns to staging the next job at once.
    defer_decode: bool = false,
    pcs_words: []u32 = &.{},
    /// Environment knobs, parsed strictly once in init (outer_env.zig).
    pcs_reserve_trees: u64 = 11,
    declare_words: ?u64 = null,
    leaf_persistent: bool = false,
    /// `streams` / `composition_stream` are shallow copies of the class's
    /// WholePlan (outer_class_plan.zig slot): read only, never freed here.
    borrowed: bool = false,
    /// Device lookup_sum check enqueued at the end of the body (whole nodes
    /// with `whole.checks`); `check_fault`: negative-test corruption.
    device_checks: bool = false,
    check_fault: bool = false,
    check_tag: u32 = 0,

    /// `staged` stays owned by the caller (deinit after finish/abort).
    /// `snapshots`: also copy the channel state into the slab after every
    /// prefix step (parity harness; adds one D2D copy per step).
    pub fn init(staged: *St.Staged, kernels: *const K.Kernels, snapshots: bool) !OuterNodeJob {
        return initBase(staged, kernels, snapshots, true);
    }
    fn initBase(staged: *St.Staged, kernels: *const K.Kernels, snapshots: bool, build_streams: bool) !OuterNodeJob {
        var out = OuterNodeJob{ .staged = staged, .kernels = kernels, .snapshots = snapshots, .mode = .prefix };
        out.pcs_reserve_trees = try Env.unsigned(u64, "STWO_RV64_M8_OUTER_PCS_RESERVE_TREES", out.pcs_reserve_trees);
        out.declare_words = try Env.optionalUnsigned(u64, "STWO_RV64_M8_OUTER_DECLARE_WORDS");
        out.leaf_persistent = try Env.flag("STWO_RV64_M8_OUTER_LEAF_PERSISTENT", false);
        if (build_streams and try TC.streamSelected(kernels)) {
            const fp: ?*const Plan.TreePlan = if (staged.statics.fixed_plan) |*f| f else null;
            out.streams = try N.Streams.init(out.allocator, staged.plan(), fp, try TC.streamChunkWords(), kernels.compact_eager);
        }
        errdefer if (out.streams) |*st| st.deinit(out.allocator);
        _ = try out.layout.add(.opaque_words, section_index, Plan.Section.words);
        if (snapshots) for (0..N.prefix_steps) |step| {
            _ = try out.layout.add(.snapshot, @intCast(step), 16);
        };
        return out;
    }
    /// A whole node through PCS. The PCS framing is shape-only, so its exact
    /// output and pinned-ingress sizes are planned here at placeholder
    /// addresses; stage() frames it again at the real ones. A cached class
    /// (Statics.class_plan) builds that plan once and every node borrows it.
    pub fn initWhole(staged: *St.Staged, kernels: *const K.Kernels, whole: Whole) !OuterNodeJob {
        if (staged.statics.class_plan) |raw| {
            const slot: *CP.Slot = @ptrCast(@alignCast(raw));
            var ctx = WholeBuild{ .staged = staged, .kernels = kernels, .whole = whole };
            const builder = CP.Slot.Builder{ .ctx = &ctx, .build = WholeBuild.build, .destroy = WholePlan.destroy };
            if (try slot.acquire(try wholeSignature(kernels, whole), builder)) |plan| return initBorrowed(staged, kernels, whole, @ptrCast(@alignCast(plan)));
        }
        return initWholeFresh(staged, kernels, whole);
    }
    /// The class products of initWhole, borrowed (never rebuilt): stream
    /// schedules and composition commit stream by shallow copy, the PCS framing
    /// as a clone sharing the template's immutable sections (only the column
    /// table is per node: bindColumn writes it in holdBuffers).
    fn initBorrowed(staged: *St.Staged, kernels: *const K.Kernels, whole: Whole, plan: *const WholePlan) !OuterNodeJob {
        var out = try initBase(staged, kernels, false, false);
        out.borrowed = true;
        errdefer out.deinit();
        out.mode = .full;
        out.whole = whole;
        if (staged.statics.composition == null or staged.pcs_points == null) return error.OuterJobWholeStagingMissing;
        out.streams = plan.streams;
        out.composition_stream = plan.composition_stream;
        out.pcs = try clonePcs(out.allocator, &plan.pcs);
        out.pcs_plan = out.pcs.?.plan;
        _ = try out.layout.add(.opaque_words, pcs_index, @intCast(out.pcs.?.outputWords()));
        _ = try out.layout.add(.opaque_words, oods_index, Pcs.oods_field_words);
        try out.initChecks();
        return out;
    }
    fn initWholeFresh(staged: *St.Staged, kernels: *const K.Kernels, whole: Whole) !OuterNodeJob {
        var out = try init(staged, kernels, false);
        errdefer out.deinit();
        out.mode = .full;
        out.whole = whole;
        if (staged.statics.composition == null or staged.pcs_points == null) return error.OuterJobWholeStagingMissing;
        if (out.streams != null) out.composition_stream = try Comp.CommitStream.init(out.allocator, &staged.statics.composition.?, try TC.streamChunkWords(), kernels.compact_eager);
        var placeholder = try out.request(null);
        defer out.freeRequest(&placeholder);
        // Framed once, here on the caller's thread (pre-stage side); stage()
        // only binds the real coefficient addresses (native_pcs.bindColumn).
        out.pcs = try Pcs.PcsJob.prepare(out.allocator, whole.pcs, placeholder, try Pcs.placeholderPoint(), whole.wide);
        out.pcs_plan = out.pcs.?.plan;
        _ = try out.layout.add(.opaque_words, pcs_index, @intCast(out.pcs.?.outputWords()));
        _ = try out.layout.add(.opaque_words, oods_index, Pcs.oods_field_words);
        try out.initChecks();
        return out;
    }
    /// STWO_RV64_M8_OUTER_DEVICE_CHECKS=1: the node carries its device checks
    /// (fail closed when the addon lacks them or the pre-stage did not stage
    /// the expected outputs and circuit constants).
    fn initChecks(self: *OuterNodeJob) !void {
        if (!try Checks.selected()) return;
        return self.requireDeviceChecks();
    }
    /// Native node jobs always validate the device-derived outputs and lookup
    /// relation, independently of the legacy diagnostic environment switch.
    pub fn requireDeviceChecks(self: *OuterNodeJob) !void {
        if (self.device_checks) return;
        if (self.whole.?.checks == null) return error.MissingOuterCheckKernel;
        if (self.staged.lookup == null or self.staged.image.expected.words != self.staged.expected.len) return error.OuterCheckInputsNotStaged;
        self.device_checks = true;
        self.check_fault = if (try Checks.faultOrdinal()) |n| n == self.staged.ordinal else false;
        self.check_tag = Checks.tagOf(&self.staged.checkpoint, self.staged.ordinal);
        _ = try self.layout.add(.opaque_words, Checks.field_index, Checks.field_words);
    }
    pub fn deinit(self: *OuterNodeJob) void {
        if (!self.borrowed) {
            if (self.streams) |*st| st.deinit(self.allocator);
            if (self.composition_stream) |*c| c.deinit(self.allocator);
        }
        self.streams = null;
        self.composition_stream = null;
        if (self.pcs) |*j| j.deinit(self.allocator);
        self.pcs = null;
        if (self.pcs_proof) |*d| d.proof.deinit(self.proof_allocator);
        self.pcs_proof = null;
        if (self.pcs_words.len != 0) self.allocator.free(self.pcs_words);
        self.pcs_words = &.{};
    }

    /// The PCS request of this node: FIXED (class region), MAIN, INTER and
    /// composition coefficients, all device resident; roots are placeholders
    /// (the PCS echoes them; finish checks them against the committed roots).
    fn request(self: *OuterNodeJob, held: ?Held) !D.Request {
        const a = self.allocator;
        const p = self.staged.plan();
        const cs = &self.staged.statics.composition.?;
        const fake: [*]u32 = @ptrFromInt(1 << 20);
        const trees = try a.alloc(D.Tree, 4);
        errdefer a.free(trees);
        var made: usize = 0;
        errdefer for (trees[0..made]) |t| a.free(t.columns);
        const Col = struct {
            fn col(log: u32, ptr: [*]const u32) D.Column {
                return .{ .log_size = log, .device = .{ .words = ptr, .count = @as(u64, 1) << @intCast(log), .context_token = 1, .generation = 1 } };
            }
        };
        const fixed_base: [*]const u32 = if (held != null) self.bases.at(cs.fixed) else fake;
        trees[0] = .{ .root = self.staged.fixed_root, .columns = &.{} };
        const cols0 = try a.alloc(D.Column, cs.fixed_offsets.len);
        trees[0].columns = cols0;
        made += 1;
        for (cols0, cs.fixed_offsets, self.staged.fixed_logs) |*c, off, log| c.* = Col.col(log, fixed_base + @as(usize, @intCast(off)));
        const main: [*]const u32 = if (held) |h| h.long.main_coef.ptr else fake;
        trees[1] = .{ .root = @splat(0), .columns = &.{} };
        const cols1 = try a.alloc(D.Column, p.main.logs.len);
        trees[1].columns = cols1;
        made += 1;
        for (cols1, p.main.logs, p.main.offsets) |*c, log, off| c.* = Col.col(log, main + @as(usize, @intCast(off)));
        const inter: [*]const u32 = if (held) |h| h.long.inter_coef.ptr else fake;
        trees[2] = .{ .root = @splat(0), .columns = &.{} };
        const cols2 = try a.alloc(D.Column, p.inter.logs.len);
        trees[2].columns = cols2;
        made += 1;
        for (cols2, p.inter.logs, p.inter.offsets) |*c, log, off| c.* = Col.col(log, inter + @as(usize, @intCast(off)));
        const comp: [*]const u32 = if (held) |h| h.composition.ptr else fake;
        trees[3] = .{ .root = @splat(0), .columns = &.{} };
        const cols3 = try a.alloc(D.Column, cs.outputColumns());
        trees[3].columns = cols3;
        made += 1;
        for (cols3, 0..) |*c, i| c.* = Col.col(cs.chunkLog(), comp + i * (@as(usize, 1) << @intCast(cs.chunkLog())));
        const points: *const core.pcs.TreeVec([][]D.Point) = @ptrCast(@alignCast(self.staged.pcs_points.?));
        return .{ .scope = null, .config = try Outer.protocol.targetConfig(), .lifting_log_size = cs.commitLog(), .trees = trees, .points = points.* };
    }
    fn freeRequest(self: *OuterNodeJob, r: *D.Request) void {
        for (r.trees) |t| self.allocator.free(t.columns);
        self.allocator.free(r.trees);
    }
    pub fn job(self: *OuterNodeJob) api.Job {
        return api.Job.from(OuterNodeJob, self);
    }
    pub fn classKey(self: *OuterNodeJob) [32]u8 {
        return self.staged.class_key;
    }
    /// PCS working set beyond the held coefficients, in words: fitted to the
    /// measured heap peaks of whole nodes (the PCS rebuilds every tree it
    /// opens, rolling and streamed; its scratch scales with the lifting
    /// height, not the column count) [M wire-outer-p2, 26235156 leaves at
    /// lifting 2^24: 4.920e9 heap peak - 2.05e9 held = 2.87e9 = 10.7 x the
    /// lifting-height tree]. STWO_RV64_M8_OUTER_PCS_RESERVE_TREES overrides
    /// the multiplier (measurement sweeps).
    pub fn pcsReserveWords(self: *const OuterNodeJob, cs: *const Comp.Static) u64 {
        return self.pcs_reserve_trees * cs.treeWords();
    }

    /// Whole nodes own Region.fixed (the FIXED coefficients RC and the PCS
    /// read). It is committed in the node from the staged raw evaluations,
    /// unless a warm worker-persistent region holds it (stage(): a
    /// persistent fold class seen before on this worker, or the lane's
    /// FIXED precommit handoff). Prefix/parity nodes have no Region.fixed.
    fn nodeFixed(self: *const OuterNodeJob) bool {
        return self.whole != null;
    }

    /// Static per-node peak from the class plan, in the worker's 64-word
    /// granules: staged inputs + buffers held through PCS + the largest phase
    /// transient (FIXED recommit, MAIN, INTER, composition, PCS). With
    /// streamed commits no phase holds an LDE image or a tree: the commit
    /// transient is one chunk + two state banks.
    /// One ordered schedule for both declaration and holdBuffers allocation.
    /// Zero-sized tree slots are omitted on the streamed path.
    fn heldBufferWords(self: *const OuterNodeJob) [9]usize {
        const streamed = self.streams != null;
        const w = N.Long.words(self.staged.plan(), streamed);
        var sizes = [_]usize{ w[0], w[1], w[2], w[3], w[4], w[5], 0, 0, 0 };
        if (self.whole != null) if (self.staged.statics.composition) |*cs| {
            sizes[6] = @intCast(cs.coefficientWords());
            sizes[7] = if (streamed) 0 else @intCast(cs.treeWords());
            sizes[8] = @as(usize, cs.param_total) * 8;
        };
        return sizes;
    }

    pub fn footprint(self: *OuterNodeJob) api.Footprint {
        const p = self.staged.plan();
        const g = struct {
            fn r(words: u64) u64 {
                return std.mem.alignForward(u64, @max(words, 1), 64);
            }
        }.r;
        var held: u64 = 0;
        for (self.heldBufferWords()) |w| if (w != 0) {
            held += g(w);
        };
        var widest_inter: u64 = 0;
        for (p.geometry.components) |c| {
            const prefix = (@import("../prefix_plan.zig").Plan.init(c.log) catch unreachable).scratch_words;
            widest_inter = @max(widest_inter, g(8 * @as(u64, c.pairs) << @intCast(c.log)) + g(prefix));
        }
        const eval = g(p.main.coefficient_words);
        const main_commit: u64 = if (self.streams) |*st| st.main.scratchWords() else g(p.main.evaluation_words);
        const inter_commit: u64 = if (self.streams) |*st| st.inter.scratchWords() else g(p.inter.evaluation_words);
        var phase = @max(@max(eval + g(self.staged.assignment.count * 4), eval + main_commit), @max(eval + widest_inter, inter_commit));
        const node = self.staged.image.words[@intFromEnum(St.Region.node)];
        const class = self.staged.image.words[@intFromEnum(St.Region.class)];
        var staged: u64 = g(node);
        if (self.packed_class) |compressed| {
            staged += g(compressed.outputWords()) + g(12);
        } else if (!self.persistentClass()) staged += g(class);
        var pinned_extra: u64 = 0;
        if (self.staged.statics.composition) |*cs| if (self.whole != null) {
            var widest: u64 = 0;
            var buckets: u64 = 0;
            var seen: [29]bool = @splat(false);
            for (cs.roles) |r| {
                const cols: u64 = r.widths[0] + r.widths[1] + r.widths[2];
                widest = @max(widest, g(cols << @intCast(r.eval_log)));
                if (!seen[r.eval_log]) buckets += g(@as(u64, 8) << @intCast(r.eval_log));
                seen[r.eval_log] = true;
            }
            const commit: u64 = if (self.composition_stream) |*c| c.stream.scratchWords() else g(@as(u64, cs.outputColumns()) << @intCast(cs.commitLog()));
            phase = @max(phase, buckets + @max(widest, g(cs.coefficientWords()) + commit));
            phase = @max(phase, self.pcsReserveWords(cs));
            pinned_extra = self.pcs_plan.ingress_words;
            if (self.nodeFixed()) if (self.staged.statics.fixed_plan) |*fp| {
                // Coefficient buffer staged (raw evaluations interpolated in
                // place) unless worker-persistent (class region or the FIXED
                // precommit handoff); commit scratch as a phase either way (a
                // fresh persistent region is still committed in the node).
                if (self.packed_class == null and !self.persistentClass() and self.fixed_handoff == null) staged += g(fp.coefficient_words);
                const fixed_commit: u64 = if (self.streams) |*st| (if (st.fixed) |*f| f.scratchWords() else 0) else g(fp.evaluation_words) + g(fp.tree_words + fp.prefix_words);
                phase = @max(phase, fixed_commit);
                if (!self.require_warm and self.packed_class == null) pinned_extra += fp.coefficient_words;
            };
        };
        // Diagnostic (measurement sweeps only): STWO_RV64_M8_OUTER_DECLARE_WORDS
        // caps the declared device peak so a node can run in an arena smaller
        // than this bound; the worker still fails the job closed
        // (JobWorkExceedsArena) if its real allocations do not fit.
        var device: u64 = staged + held + phase;
        if (self.declare_words) |cap| device = @min(device, cap);
        return .{
            .device_words = @intCast(device),
            .staged_words = @intCast(staged),
            .slab_words = self.layout.words,
            .pinned_words = @intCast(node + (if (self.require_warm) 0 else (if (self.packed_class) |compressed| compressed.words.len else class) + self.staged.image.words[@intFromEnum(St.Region.twiddles)]) + pinned_extra),
        };
    }

    /// Fold classes keep their class region (and, with the in-node FIXED
    /// recommit, FIXED coefficients) in worker-persistent memory shared by
    /// every node of the class; a leaf stages them per node. The hybrid
    /// window clears `persistent_classes` (STWO_RV64_M8_OUTER_PERSISTENT_CLASSES=1
    /// restores it), so persistent memory outside the arena does not grow
    /// with each fold class. STWO_RV64_M8_OUTER_LEAF_PERSISTENT=1 makes leaves
    /// persistent too (parity fixtures).
    fn persistentClass(self: *const OuterNodeJob) bool {
        if (self.staged.assignment.reusable) return self.persistent_classes;
        return self.leaf_persistent;
    }

    pub fn stage(self: *OuterNodeJob, s: *api.Stager) !void {
        if (self.mode == .full and self.tail == null and self.whole == null) return error.OuterJobTailUnbound;
        if (self.staged.plan().geometry.beta != 1) return error.UnsupportedOuterJobBlowup;
        const words = self.staged.image.words;
        var regions: [4][*]const u32 = undefined;
        regions[@intFromEnum(St.Region.fixed)] = undefined;
        if (self.packed_class) |compressed| {
            const program = try s.persistent(compressed.key, compressed.words.len);
            if (self.require_warm and program.fresh) return error.GpuNativeRecursionClassCold;
            self.packed_program = program.buffer;
            if (program.fresh) {
                const pinned = try s.pinned(compressed.words.len);
                @memcpy(pinned, compressed.words);
                try s.upload(program.buffer, pinned);
            }
            self.packed_output = try s.alloc(compressed.outputWords());
            self.packed_scratch = try s.alloc(12);
            regions[@intFromEnum(St.Region.fixed)] = self.packed_output.ptr + compressed.class_words;
        }
        for (St.uploaded) |region| {
            const n = words[@intFromEnum(region)];
            const buffer: api.DeviceBuffer, const fresh = switch (region) {
                .node => .{ try s.alloc(@intCast(@max(n, 1))), true },
                .class => blk: {
                    if (self.packed_class) |compressed| break :blk .{ try self.packed_output.slice(0, compressed.class_words), false };
                    if (!self.persistentClass()) break :blk .{ try s.alloc(@intCast(@max(n, 1))), true };
                    const p = try s.persistent(self.staged.classRegionKey(), @intCast(@max(n, 1)));
                    break :blk .{ p.buffer, p.fresh };
                },
                .twiddles => blk: {
                    const p = try s.persistent(self.staged.twiddleRegionKey(), @intCast(@max(n, 1)));
                    break :blk .{ p.buffer, p.fresh };
                },
                .fixed => unreachable,
            };
            regions[@intFromEnum(region)] = buffer.ptr;
            if (self.require_warm and fresh and region != .node) return error.GpuNativeRecursionClassCold;
            if (fresh and n != 0) {
                const pinned = try s.pinned(@intCast(n));
                try self.staged.pack(region, pinned);
                try s.upload(buffer, pinned);
                self.report.staged_words[@intFromEnum(region)] = n;
            }
        }
        if (self.nodeFixed() and self.packed_class == null) {
            // FIXED coefficients: the lane's precommit handoff, else
            // worker-persistent per FIXED root (persistent classes), else in
            // the node's own staging. A fresh region is committed on device
            // from the raw evaluations (and its root checked in finish).
            const fp = &(self.staged.statics.fixed_plan orelse return error.OuterJobWholeStagingMissing);
            const fixed: api.Persistent = if (self.fixed_handoff) |h| blk: {
                if (h.words < fp.coefficient_words) return error.OuterFixedHandoffTooSmall;
                break :blk try s.persistent(h.key, h.words);
            } else if (self.persistentClass()) try s.persistent(self.staged.fixedRegionKey(), @intCast(fp.coefficient_words)) else .{ .buffer = try s.alloc(@intCast(fp.coefficient_words)), .fresh = true };
            regions[@intFromEnum(St.Region.fixed)] = fixed.buffer.ptr;
            self.report.fixed_handoff = self.fixed_handoff != null and !fixed.fresh;
            if (self.require_warm and fixed.fresh) return error.GpuNativeRecursionFixedCold;
            if (fixed.fresh) {
                // Raw evaluations are uploaded straight into the coefficient
                // buffer and interpolated in place (B2N with exactly aliased
                // strides, as TC INTER does): no separate raw buffer.
                const pinned = try s.pinned(@intCast(fp.coefficient_words));
                try self.staged.packFixed(pinned);
                try s.upload(fixed.buffer, pinned);
                self.fixed_commit = .{ .evaluations = fixed.buffer.ptr, .coefficients = fixed.buffer.ptr };
            }
        }
        self.bases = .{ .regions = regions };
        if (self.whole != null) self.pcs_pinned = try s.pinned(@intCast(self.pcs.?.ingressWords()));
    }

    /// Node buffers that live through PCS. Allocated in the job's work window
    /// (enqueue, before the body), not as staged inputs: they are the largest
    /// part of a real node, and staged inputs of two jobs coexist in the
    /// two-sided arena. The PCS framing only names their addresses (host
    /// writes into pinned ingress, read by the PCS upload inside the body).
    fn holdBuffers(self: *OuterNodeJob, e: *Heap.Heap) !void {
        const p = self.staged.plan();
        const cs = &self.staged.statics.composition.?;
        var b: [9]?K.Buffer = @splat(null);
        const sizes = self.heldBufferWords();
        for (sizes) |n| try Plan.requireIndexable(&.{n});
        // Refuse before the body: every commit transient of this node. The
        // heap also checks each allocation (outer_heap.zig); this names the
        // node up front, including the full-LDE images (STREAM=0 or a base
        // image without the mixed-leaf kernels).
        if (self.streams) |*st| {
            for ([_]?*const TC.Stream{ &st.main, &st.inter, if (st.fixed) |*f| f else null }) |maybe| if (maybe) |s| {
                try Plan.requireIndexable(&.{ s.plan.chunk_words, s.plan.bank_words[0], s.plan.bank_words[1] });
            };
        } else {
            try Plan.requireIndexable(&.{ p.main.evaluation_words, p.inter.evaluation_words });
            if (self.staged.statics.fixed_plan) |*fp| try Plan.requireIndexable(&.{ fp.evaluation_words, fp.tree_words + fp.prefix_words });
        }
        if (self.composition_stream) |*c| {
            try Plan.requireIndexable(&.{ c.stream.plan.chunk_words, c.stream.plan.bank_words[0], c.stream.plan.bank_words[1] });
        } else try Plan.requireIndexable(&.{@as(u64, cs.outputColumns()) << @intCast(cs.commitLog())});
        for (&b, sizes) |*out, n| if (n != 0) {
            const d = try e.alloc(n);
            out.* = .{ .ptr = d.ptr, .words = d.words };
        };
        self.held = .{ .long = .{ .main_coef = b[0].?, .inter_coef = b[1].?, .main_tree = b[2], .inter_tree = b[3], .parameters = b[4].?, .powers = b[5].? }, .composition = b[6].?, .composition_tree = b[7], .rc_parameters = b[8].? };
        var r = try self.request(self.held.?);
        defer self.freeRequest(&r);
        for (r.trees, 0..) |tree, t| for (tree.columns, 0..) |column, c| try self.pcs.?.bindColumn(t, c, column.device.?.words);
    }

    const TailState = struct {
        job: *OuterNodeJob,
        e: *api.Enqueue,
        heap: *Heap.Heap,
        fn enqueue(raw: *anyopaque, device: *K.Device, in: *const N.TailInputs) anyerror!void {
            const self: *TailState = @ptrCast(@alignCast(raw));
            const nj = self.job;
            const whole = nj.whole.?;
            const held = nj.held.?;
            const cs = &nj.staged.statics.composition.?;
            const p = nj.staged.plan();
            try Comp.enqueue(device, whole.composition, cs, &.{
                .bases = in.bases,
                .twiddles = &nj.staged.image.twiddles,
                .itwiddles = &nj.staged.image.itwiddles,
                .main = in.main_coefficients,
                .main_offsets = p.main.offsets,
                .inter = in.inter_coefficients,
                .inter_offsets = p.inter.offsets.ptr,
                .lookup = in.lookup,
                .claims = in.claims,
                .powers = in.powers,
                .parameters = held.rc_parameters.ptr,
                .output = held.composition,
                .tree = held.composition_tree,
                .commit = if (nj.composition_stream) |*c| c else null,
                .root_out = in.section + Plan.Section.composition_root,
                .status = in.section + Plan.Section.status + 2,
            });
            try device.mix(in.section + Plan.Section.composition_root, 8, false);
            device.phase(.pcs);
            const oods = try self.e.slab.field(.opaque_words, oods_index);
            const pcs = try self.e.slab.field(.opaque_words, pcs_index);
            var pe = Heap.PcsEnqueue.init(self.e, self.heap);
            try nj.pcs.?.enqueueOpening(whole.pcs, &pe, nj.pcs_pinned, oods, pcs);
            device.counters.api += 3;
        }
    };

    const Body = struct {
        job: *OuterNodeJob,
        e: *api.Enqueue,
        device: *K.Device,
        node: *N.Node,
        saved: api.DeviceChannel,
        /// Launches of the last enqueue (recorded or issued).
        last: u32 = 0,
        pub fn enqueue(self: *Body) !u32 {
            try self.e.channel.initFromCheckpoint(.{ .ptr = @constCast(self.job.bases.at(self.job.staged.image.channel_seed)), .words = 9 });
            // Check words := unset before any body work: a check that never
            // runs is refused whatever the (arena-reused) slab held.
            if (self.job.device_checks) try self.device.unset((try self.e.slab.field(.opaque_words, Checks.field_index)).ptr, Checks.field_words);
            self.last = try self.node.enqueue(self.device);
            if (self.job.device_checks) self.last += try self.job.enqueueChecks(self.e, self.device);
            return self.last;
        }
        pub fn reset(self: *Body) void {
            // A discarded capture advanced only the host mirror of the channel.
            self.e.channel.* = self.saved;
        }
        fn snapshot(raw: *anyopaque, step: u32) anyerror!void {
            const self: *Body = @ptrCast(@alignCast(raw));
            const f = try self.e.slab.layout.?.get(.snapshot, step);
            try self.e.channel.snapshot(self.e.slab, f.offset);
        }
    };

    pub fn enqueue(self: *OuterNodeJob, e: *api.Enqueue) !void {
        try e.waitStaged();
        try e.slab.bind(&self.layout);
        // One work-heap region per node: the declared work peak (footprint
        // less staged inputs), or as much as the window holds.
        // The worker's planned footprint: the memory policy's measured class
        // peak when the class is planned, else exactly self.footprint().
        const fp = e.footprint();
        const region_words = fp.device_words -| fp.staged_words;
        var heap = Heap.Heap.init(try e.alloc(@max(region_words, Heap.granule)));
        if (self.whole != null) try self.holdBuffers(&heap);
        const section = try e.slab.field(.opaque_words, section_index);
        var view = Heap.DeviceEnqueue{ .e = e, .heap = &heap };
        var device = K.Device{ .ctx = e.ctx(), .stream = e.stream(), .impl = &view, .vtable = &Heap.DeviceEnqueue.vtable, .kernels = self.kernels, .phase_hook = Heap.DeviceEnqueue.phase };
        var materialize_launches: u32 = 0;
        if (self.packed_class) |compressed| {
            const before = device.counters.total();
            const status = self.packed_verdict orelse try e.slab.field(.opaque_words, Packed.field_index);
            try Packed.enqueue(self.packed_launch orelse return error.PackedClassDecoderMissing, e.ctx(), compressed, self.packed_program, self.packed_output, self.packed_scratch, status, api.gpu_native.Verdict.reject(.class_unpack, 0) & 0xffff0000);
            const plan = &(self.staged.statics.fixed_plan orelse return error.OuterJobWholeStagingMissing);
            const raw = @constCast(self.bases.regions[@intFromEnum(St.Region.fixed)]);
            const tw = self.staged.image.twiddles[plan.eval_log];
            const itw = self.staged.image.itwiddles[plan.eval_log];
            try TC.interpolate(&device, plan, raw, raw, .{ .sorted_logs = self.bases.at(self.staged.image.fixed_logs), .twiddles = self.bases.at(tw), .twiddle_words = @intCast(tw.words), .itwiddles = self.bases.at(itw), .itwiddle_words = @intCast(itw.words) });
            // Four decoder kernels plus the interpolation wrappers' counts.
            materialize_launches = 4 + device.counters.total() - before;
        }
        self.report.streamed = self.streams != null;
        if (self.timing) |t| t.mark(t.ctx, false, e.stream());
        defer if (self.timing) |t| t.mark(t.ctx, true, e.stream());
        defer {
            self.report.heap_words = heap.words;
            self.report.heap_peak_words = heap.peak;
            self.report.heap_allocations = heap.allocations;
            self.report.heap_high_words = heap.high;
            self.report.max_alloc_words = heap.max_alloc;
            self.report.max_unguarded_alloc_words = heap.max_unguarded_alloc;
            for (&self.report.phase_peak_words, heap.phase_peak) |*o, v| o.* = v;
            for (&self.report.phase_high_words, heap.phase_high) |*o, v| o.* = v;
        }
        var tail_state = TailState{ .job = self, .e = e, .heap = &heap };
        var node = N.Node{ .staged = self.staged, .bases = self.bases, .section = section.ptr, .mode = self.mode, .tail = self.tail, .long = if (self.held) |h| h.long else null, .fixed = self.fixed_commit, .streams = if (self.streams) |*st| st else null };
        if (self.whole != null) node.tail = .{ .context = &tail_state, .enqueue = TailState.enqueue };
        var body = Body{ .job = self, .e = e, .device = &device, .node = &node, .saved = e.channel.* };
        if (self.snapshots) {
            node.after_step = Body.snapshot;
            node.after_step_context = &body;
        }
        if (self.graphs) |cache| {
            const r = try cache.run(.{ .class = self.staged.graph_key, .placement = @intFromEnum(e.placement) | (@as(u8, @intFromBool(self.whole != null)) << 1) | (@as(u8, @intFromBool(self.fixed_commit != null)) << 2) | (@as(u8, @intFromBool(self.streams != null)) << 3) }, e.stream(), &body);
            self.report.outcome = r.outcome;
            self.report.launches = r.launches;
            self.report.recording_launches = r.recording_launches;
            self.report.kernel_nodes = r.kernel_nodes;
        } else {
            self.report.launches = try body.enqueue();
        }
        // body_launches describes one body's shape. launches above counts
        // every host attempt, including a discarded recording and fallback.
        self.report.launches += materialize_launches;
        self.report.body_launches = body.last + materialize_launches;
    }

    /// Device checks after the body (inside the captured graph): lookup_sum
    /// over the section the body wrote and the staged expected outputs.
    fn enqueueChecks(self: *OuterNodeJob, e: *api.Enqueue, device: *K.Device) !u32 {
        const section = try e.slab.field(.opaque_words, section_index);
        const out = try e.slab.field(.opaque_words, Checks.field_index);
        const S = Plan.Section;
        const n: u32 = @intCast(self.staged.expected.len / 4);
        const c = Checks.constants(self.staged.lookup.?, n, Plan.n_components, self.check_tag, self.check_fault);
        const expected: ?[*]const u32 = if (n != 0) self.bases.at(self.staged.image.expected) else null;
        try device.check(self.whole.?.checks.?.lookup(e.ctx(), K.lane, section.ptr + S.claims, section.ptr + S.challenges, expected, &c, out.ptr));
        return 1;
    }

    pub fn finish(self: *OuterNodeJob, view: api.SlabView) !void {
        self.finished = true;
        var timer = std.time.Timer.start() catch null;
        defer if (timer) |*t| {
            self.report.finish_ns = t.read();
        };
        if (self.timing) |t| t.resolve(t.ctx);
        self.report.receipt = view.receipt;
        if (self.keep_slab) |copy| @memcpy(copy[0..@min(copy.len, view.words.len)], view.words[0..@min(copy.len, view.words.len)]);
        const section = try Slab.read(view, .opaque_words, section_index);
        // Device verdict first (the authority under device checks), then the
        // host reference: both must accept, so a disagreement fails closed.
        if (self.device_checks) if (try Checks.verdict(try Slab.read(view, .opaque_words, Checks.field_index), self.check_tag)) |r| {
            std.log.err("OUTER_JOB device check rejected ordinal={d} check={s} detail={d}", .{ self.staged.ordinal, @tagName(r.check), r.detail });
            return error.OuterDeviceLookupSumRejected;
        };
        self.decoded = try decode(section, self.staged.expected);
        if (self.whole != null) {
            const d = self.decoded.?;
            if (self.fixed_commit != null and !std.mem.eql(u8, &root(section[Plan.Section.fixed_root..]), &self.staged.fixed_root)) return error.InvalidOm31DeviceFixedRoot;
            self.composition_root = root(section[Plan.Section.composition_root..]);
            const oods = try Slab.read(view, .opaque_words, oods_index);
            if (oods[32] != 0) return error.InvalidOuterOodsPoint;
            @memcpy(&self.oods, oods[0..16]);
            const words = try Slab.read(view, .opaque_words, pcs_index);
            if (self.defer_decode) {
                // The slab is recycled after finish: keep a copy for decodeProof.
                self.pcs_words = try self.allocator.dupe(u32, words);
            } else {
                const roots = [_][32]u8{ self.staged.fixed_root, d.main_root, d.inter_root, self.composition_root };
                self.pcs_proof = try self.pcs.?.decode(self.proof_allocator, words, &roots);
            }
        }
    }
    /// Deferred PCS proof decode (`defer_decode`), on the caller's thread
    /// after a successful completion; the roots are those finish checked.
    pub fn decodeProof(self: *OuterNodeJob) !void {
        if (self.pcs_proof != null) return;
        if (!self.defer_decode or self.pcs_words.len == 0) return error.OuterJobNotDecoded;
        var timer = try std.time.Timer.start();
        const d = self.decoded orelse return error.OuterJobNotDecoded;
        const roots = [_][32]u8{ self.staged.fixed_root, d.main_root, d.inter_root, self.composition_root };
        self.pcs_proof = try self.pcs.?.decode(self.proof_allocator, self.pcs_words, &roots);
        self.allocator.free(self.pcs_words);
        self.pcs_words = &.{};
        self.report.decode_ns = timer.read();
    }
    pub fn abort(self: *OuterNodeJob) void {
        self.finished = true;
    }
    /// Channel snapshot after prefix step `step` (parity mode), from the slab view.
    pub fn snapshotWords(view: api.SlabView, step: u32) ![]const u32 {
        return Slab.read(view, .snapshot, step);
    }
};

/// Class products of initWhole (H20), shared read only by every node of one
/// cached class: owned by the class's outer_class_plan.Slot (process
/// allocator), destroyed only with the class statics.
pub const WholePlan = struct {
    streams: ?N.Streams,
    composition_stream: ?Comp.CommitStream,
    /// Framing template at placeholder addresses (never bound or enqueued).
    pcs: Pcs.PcsJob,
    fn destroy(raw: *anyopaque) void {
        const self: *WholePlan = @ptrCast(@alignCast(raw));
        const a = std.heap.c_allocator;
        if (self.streams) |*st| st.deinit(a);
        if (self.composition_stream) |*c| c.deinit(a);
        self.pcs.deinit(a);
        a.destroy(self);
    }
};

/// Process constants a WholePlan depends on beyond the class authority.
fn wholeSignature(kernels: *const K.Kernels, whole: Whole) !CP.Signature {
    const streamed = try TC.streamSelected(kernels);
    const chunk: u64 = if (streamed) try TC.streamChunkWords() else 0;
    return CP.signatureOf(&.{ @intFromBool(streamed), chunk, @intFromBool(kernels.compact_eager), @intFromBool(whole.wide), @intFromPtr(whole.pcs.plan), @intFromPtr(whole.composition) });
}

const WholeBuild = struct {
    staged: *St.Staged,
    kernels: *const K.Kernels,
    whole: Whole,
    /// Exactly the per-node initWhole, then its products move into the plan.
    fn build(raw: *anyopaque) anyerror!*anyopaque {
        const self: *WholeBuild = @ptrCast(@alignCast(raw));
        var fresh = try OuterNodeJob.initWholeFresh(self.staged, self.kernels, self.whole);
        defer fresh.deinit();
        const a = std.heap.c_allocator;
        if (!St.sameAllocator(fresh.allocator, a)) return error.OuterClassPlanAllocatorMismatch;
        const plan = try a.create(WholePlan);
        plan.* = .{ .streams = fresh.streams, .composition_stream = fresh.composition_stream, .pcs = fresh.pcs.? };
        fresh.streams = null;
        fresh.composition_stream = null;
        fresh.pcs = null;
        return plan;
    }
};

/// A per-node PcsJob over the template's framing: the 17 sections and the
/// metadata stay the template's (immutable after prepare: the device
/// substitutes seed, point and roots), only the coefficient column table is
/// the node's own. Its deinit frees only that table.
fn clonePcs(a: std.mem.Allocator, template: *const Pcs.PcsJob) !Pcs.PcsJob {
    var job = template.*;
    job.prepared.coefficients = try a.dupe(@TypeOf(template.prepared.coefficients[0]), template.prepared.coefficients);
    job.prepared.section_owned = @splat(false);
    job.prepared.owns_metadata = false;
    job.prepared.geometry = null;
    job.descriptor = job.prepared.descriptor();
    return job;
}
