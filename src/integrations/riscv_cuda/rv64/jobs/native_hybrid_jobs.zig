//! Native-hybrid jobs (STWO_RV64_M8_NATIVE_JOBS=1): the two per-segment jobs
//! the legacy orchestration runs on the persistent per-GPU workers. Glue
//! (legacy types, plans, proof assembly) is rv64/native_hybrid.zig; this file
//! is enqueue-only and lint-clean.
//!
//! Stage1Job  (at the legacy local-GKR call, before the global-chi barrier):
//!   copy the segment's committed MAIN coefficients into a REQUEST-RETAINED
//!   region (retained.zig: they must survive the barrier; the legacy replay
//!   frees its own MAIN right after stage one), then the local GKR on the
//!   job's device channel and the local Eq/prefix binding into a second
//!   retained region. One host wait.
//! Stage2Job  (replaces CpuWorker.complete after the barrier): the global
//!   interaction of every slot (claims straight into the slab's claims
//!   field), then NativeStage2: mixManifestAndClaims, INTER commit, device
//!   composition coefficient, composition with device claim slots, OODS and
//!   the enqueue-only PCS, all on one device transcript seeded from the
//!   worker's post-MAIN checkpoint. Reads both retained regions. One host wait.
const std = @import("std");
const api = @import("api.zig");
const Slab = @import("slab.zig");
const R = @import("retained.zig");
const G = @import("native_gkr.zig");
const B = @import("native_binding.zig");
const C = @import("native_commit.zig");
const Gl = @import("native_global.zig");
const N = @import("native_pcs.zig");
const S2 = @import("native_stage2.zig");
const NComp = @import("native_composition.zig");

/// addon stwo_rv64_jobs_copy_async(dst, src, bytes, kind, stream) (kind 3 = d2d):
/// a raw stream copy; the legacy MAIN columns are not in the worker's ledger.
pub const CopyAsync = *const fn (*anyopaque, *const anyopaque, usize, u32, *anyopaque) callconv(.c) c_int;

/// Optional CUDA-event span around a job's enqueued work (glue supplies the
/// base image's event entry points; events are created in `stage`, on the
/// worker thread, and read in `finish` after the job's single wait).
pub const Timing = struct {
    ctx: ?*anyopaque = null,
    create: *const fn (?*anyopaque, *?*anyopaque) c_int,
    record: *const fn (?*anyopaque, *anyopaque, *anyopaque) c_int,
    elapsed: *const fn (?*anyopaque, *f32, *anyopaque, *anyopaque) c_int,
    destroy: *const fn (?*anyopaque, *anyopaque) void,
    pub const Span = struct {
        begin: ?*anyopaque = null,
        end: ?*anyopaque = null,
        gpu_ms: f32 = -1,
        fn open(self: *Span, t: ?*const Timing) !void {
            const tm = t orelse return;
            if (tm.create(tm.ctx, &self.begin) != 0 or tm.create(tm.ctx, &self.end) != 0 or self.begin == null or self.end == null) return error.CudaTimingFailed;
        }
        fn mark(self: *Span, t: ?*const Timing, which: enum { begin, end }, stream: *anyopaque) !void {
            const tm = t orelse return;
            const ev = (if (which == .begin) self.begin else self.end) orelse return;
            if (tm.record(tm.ctx, ev, stream) != 0) return error.CudaTimingFailed;
        }
        fn read(self: *Span, t: ?*const Timing) void {
            const tm = t orelse return;
            if (self.begin == null or self.end == null or tm.elapsed(tm.ctx, &self.gpu_ms, self.begin.?, self.end.?) != 0) self.gpu_ms = -1;
        }
        pub fn close(self: *Span, t: ?*const Timing) void {
            const tm = t orelse return;
            if (self.begin) |e| tm.destroy(tm.ctx, e);
            if (self.end) |e| tm.destroy(tm.ctx, e);
            self.begin = null;
            self.end = null;
        }
    };
};

pub fn mainName(ordinal: u32) [32]u8 {
    return R.name("hy.s1.main", ordinal);
}
pub fn bindName(ordinal: u32) [32]u8 {
    return R.name("hy.s1.bind", ordinal);
}
/// Stage-two PCS inputs moved out of the arena window before the PCS.
pub fn interName(ordinal: u32) [32]u8 {
    return R.name("hy.s2.inter", ordinal);
}
pub fn compName(ordinal: u32) [32]u8 {
    return R.name("hy.s2.comp", ordinal);
}

/// Copy runs of adjacent legacy columns (one copy per contiguous run).
fn copyColumns(copy: CopyAsync, stream: *anyopaque, dst: [*]u32, offsets: []const usize, logs: []const u32, legacy: []const [*]const u32) !void {
    var c: usize = 0;
    while (c < legacy.len) {
        var end = c + 1;
        var words: usize = @as(usize, 1) << @intCast(logs[c]);
        while (end < legacy.len and legacy[end] == legacy[c] + words and offsets[end] == offsets[c] + words) : (end += 1) words += @as(usize, 1) << @intCast(logs[end]);
        if (copy(@ptrCast(dst + offsets[c]), @ptrCast(legacy[c]), words * 4, 3, stream) != 0) return error.CudaEnqueueFailed;
        c = end;
    }
}

pub const Stage1Job = struct {
    a: std.mem.Allocator,
    request: u64,
    ordinal: u32,
    gkr: *G.Gkr,
    binding: *B.Binding,
    copy: CopyAsync,
    /// FIXED coefficient columns (host, original order).
    fixed_host: []const []const u32,
    /// MAIN columns: the legacy device pointers, logs, offsets in the retained region.
    legacy_main: []const [*]const u32,
    main_logs: []const u32,
    main_offsets: []const usize,
    main_words: usize,
    /// The legacy MAIN root (the child transcript mixes it from device).
    main_root: [8]u32,
    /// Keep the MAIN copy in a request-retained region for stage two (not
    /// selected by the service: see native_hybrid.zig); false = a window copy,
    /// and stage two takes MAIN from the legacy owner (replay restore).
    retain_main: bool = false,
    timing: ?*const Timing = null,
    /// Input views (fixed host + main device inside the retained region).
    inputs: []G.Input,
    layout: Slab.ProofLayout = .{},
    // phase outputs
    main_region: ?api.DeviceBuffer = null,
    bind_region: ?api.DeviceBuffer = null,
    staged_root: ?api.DeviceBuffer = null,
    section: ?G.Section = null,
    verdict: u32 = 0xffff_ffff,
    authority: []u32 = &.{},
    span: Timing.Span = .{},
    /// The arena window the job runs in (set by its submitter); caps device_words.
    window_words: usize = std.math.maxInt(usize),

    pub fn init(self: *Stage1Job) !void {
        try self.gkr.plan.addFields(&self.layout);
        _ = try self.layout.add(.opaque_words, 0, 1);
        _ = try self.layout.add(.opaque_words, 1, self.binding.plan.authorityWords());
        self.authority = try self.a.alloc(u32, self.binding.plan.authorityWords());
    }
    pub fn deinit(self: *Stage1Job) void {
        if (self.section) |*s| s.deinit();
        if (self.authority.len != 0) self.a.free(self.authority);
        self.span.close(self.timing);
    }
    /// Device words this job allocates OUTSIDE its arena window (retained
    /// regions, fresh persistent regions): the window must leave them room.
    pub fn outsideWords(self: *Stage1Job) usize {
        return (if (self.retain_main) self.main_words else 0) + self.binding.plan.output_words + self.gkr.plan.host_column_words + self.gkr.plan.twiddle_words + self.binding.plan.persistentWords();
    }
    pub fn classKey(self: *Stage1Job) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-hybrid-stage1-v1");
        h.update(&G.classKeyOf(self.gkr.plan));
        return h.finalResult();
    }
    pub fn footprint(self: *Stage1Job) api.Footprint {
        const p = self.gkr.plan;
        const g = 64;
        const staged = p.stagedWords(self.gkr.host_key != null) + 2 * g;
        const bind = self.binding.plan.enqueueWords() + 4 * g;
        const main = if (self.retain_main) 0 else std.mem.alignForward(usize, self.main_words, g);
        return .{ .device_words = @min(self.window_words, staged + main + p.enqueueWords() + bind + 8 * g), .staged_words = staged, .slab_words = self.layout.words, .pinned_words = p.pinnedWords() + self.binding.plan.pinnedWords() + 4 * g };
    }
    pub fn stage(self: *Stage1Job, s: *api.Stager) !void {
        const bind = try s.retain(self.request, bindName(self.ordinal), self.binding.plan.output_words);
        if (!bind.fresh) return error.HybridStage1RegionNotFresh;
        self.bind_region = bind.buffer;
        if (self.retain_main) {
            const main = try s.retain(self.request, mainName(self.ordinal), self.main_words);
            if (!main.fresh) return error.HybridStage1RegionNotFresh;
            self.main_region = main.buffer;
        }
        const nf = self.fixed_host.len;
        for (self.inputs[0..nf], self.fixed_host) |*i, h| i.* = .{ .host = h };
        // Device MAIN views are set at enqueue (window copy) or here (retained).
        for (self.inputs[nf..], self.main_offsets) |*i, off| i.* = .{ .device = if (self.main_region) |m| m.ptr + off else @ptrFromInt(@alignOf(u32)) };
        try self.gkr.stage(s, self.inputs);
        try self.binding.stage(self.a, s);
        const root = try s.alloc(8);
        try s.upload(root, &self.main_root);
        self.staged_root = root;
        try self.span.open(self.timing);
    }
    pub fn enqueue(self: *Stage1Job, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const main = self.main_region orelse try e.alloc(self.main_words);
        const nf = self.fixed_host.len;
        for (self.inputs[nf..], self.main_offsets) |*i, off| i.* = .{ .device = main.ptr + off };
        try self.span.mark(self.timing, .begin, e.stream());
        try copyColumns(self.copy, e.stream(), main.ptr, self.main_offsets, self.main_logs, self.legacy_main);
        try self.gkr.enqueue(e, self.inputs, self.staged_root.?);
        const verdict = try e.slab.field(.opaque_words, 0);
        if (self.gkr.sym.memset(e.ctx(), verdict.ptr, 0, 4) != 0) return error.CudaEnqueueFailed;
        try self.binding.enqueueWithAuthority(e, self.gkr, self.bind_region.?, verdict, try e.slab.field(.opaque_words, 1));
        try self.span.mark(self.timing, .end, e.stream());
    }
    pub fn finish(self: *Stage1Job, view: api.SlabView) !void {
        self.section = try G.Section.read(self.a, self.gkr, view);
        self.verdict = (try Slab.read(view, .opaque_words, 0))[0];
        @memcpy(self.authority, try Slab.read(view, .opaque_words, 1));
        self.span.read(self.timing);
    }
    pub fn abort(_: *Stage1Job) void {}
};

/// One cpu_components.Plan slot as Stage2 consumes it.
pub const Slot = struct {
    log: u32,
    inter_offset: usize,
    /// Binding instance whose 16 coefficient columns open the slot's INTER range.
    binding_index: ?usize = null,
    /// The slot's global interaction (claims), or null (claimCount == 0).
    global: ?Global = null,
    pub const Global = struct {
        plan: *const Gl.Plan,
        claim_offset: u32,
        /// First FIXED / MAIN column of the slot (original order).
        fixed_first: usize,
        main_first: usize,
    };
};

pub const Stage2Job = struct {
    a: std.mem.Allocator,
    request: u64,
    ordinal: u32,
    /// Post-MAIN host checkpoint (CpuWorker.channel before mixManifestAndClaims).
    seed: [9]u32,
    manifest: [32]u8,
    /// FIXED coefficients: the worker-persistent region Stage1's GKR filled
    /// (same key and layout); refilled from `fixed_host` when evicted.
    fixed_key: [32]u8,
    fixed_host: []const []const u32,
    fixed_offsets: []const usize,
    fixed_words: usize,
    main_offsets: []const usize,
    main_words: usize,
    /// Non-empty: MAIN comes from the legacy owner's device tree (copied into
    /// the window at enqueue); empty: the stage-one retained region.
    legacy_main: []const [*]const u32 = &.{},
    main_logs: []const u32 = &.{},
    bind_plan: *const B.Plan,
    slots: []const Slot,
    stage2: S2.Stage2,
    composition: *NComp.Plan,
    comp_sym: NComp.Symbols,
    gsym: *const Gl.Symbols,
    /// INTER inputs: placeholders at stage (all device), real views at enqueue.
    inter_inputs: []C.Input,
    timing: ?*const Timing = null,
    layout: Slab.ProofLayout = .{},
    globals: []Gl.Global = &.{},
    global_count: usize = 0,
    // phase outputs
    staged_seed: ?api.DeviceBuffer = null,
    fixed: ?api.DeviceBuffer = null,
    main: ?api.DeviceBuffer = null,
    bind: ?api.DeviceBuffer = null,
    inter_out: ?api.DeviceBuffer = null,
    comp_out: ?api.DeviceBuffer = null,
    copy: CopyAsync,
    span: Timing.Span = .{},
    /// finish: host copies of the slab fields the glue assembles from.
    roots: [32]u32 = undefined,
    alpha: [8]u32 = undefined,
    composition_status: u32 = 0xffff_ffff,
    global_status: []u32 = &.{},
    claims: []u32 = &.{},
    oods: [N.oods_field_words]u32 = undefined,
    pcs_words: []u32 = &.{},
    /// The arena window the job runs in (set by its submitter); caps device_words.
    window_words: usize = std.math.maxInt(usize),

    pub fn init(self: *Stage2Job) !void {
        for (self.slots) |s| self.global_count += @intFromBool(s.global != null);
        self.globals = try self.a.alloc(Gl.Global, self.global_count);
        var k: usize = 0;
        for (self.slots) |s| if (s.global) |g| {
            self.globals[k] = .{ .plan = g.plan, .sym = self.gsym };
            k += 1;
        };
        self.global_status = try self.a.alloc(u32, self.global_count);
        self.claims = try self.a.alloc(u32, @as(usize, self.stage2.claim_count) * 8);
        self.pcs_words = try self.a.alloc(u32, @intCast(self.stage2.pcs.outputWords()));
        _ = try self.layout.add(.root, 0, 32);
        _ = try self.layout.add(.opaque_words, 0, 8);
        _ = try self.layout.add(.status, 0, 1);
        for (0..self.global_count) |i| _ = try self.layout.add(.status, @intCast(1 + i), 1);
        _ = try self.layout.add(.claims, 0, @max(1, self.claims.len));
        _ = try self.layout.add(.opaque_words, 1, N.oods_field_words);
        _ = try self.layout.add(.opaque_words, 2, self.pcs_words.len);
    }
    pub fn deinit(self: *Stage2Job) void {
        self.a.free(self.globals);
        self.a.free(self.global_status);
        self.a.free(self.claims);
        self.a.free(self.pcs_words);
        self.span.close(self.timing);
    }
    /// Device words allocated OUTSIDE the window (retained PCS inputs, fresh
    /// persistent twiddles / FIXED / composition tables).
    pub fn outsideWords(self: *Stage2Job) usize {
        var words: usize = self.stage2.inter.coefficient_cells + self.composition.coefficientWords() + self.composition.persistentWords() + self.fixed_words + 2 * (@as(usize, 1) << @intCast(self.stage2.inter.eval_log));
        for (self.globals) |gl| words += gl.plan.rows;
        return words;
    }
    pub fn classKey(self: *Stage2Job) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-hybrid-stage2-v1");
        h.update(&self.composition.classKey());
        h.update(std.mem.sliceAsBytes(self.stage2.inter.logs));
        h.update(std.mem.asBytes(&self.stage2.pcs.outputWords()));
        return h.finalResult();
    }
    pub fn footprint(self: *Stage2Job) api.Footprint {
        const g = 64;
        var staged: usize = 4 * g + self.stage2.inter.stagedWords(0) + self.composition.stagedWords();
        const main_window = if (self.legacy_main.len != 0) std.mem.alignForward(usize, self.main_words, g) else 0;
        var globals: usize = 0;
        for (self.globals) |gl| {
            staged += gl.plan.stagedWords(false) + g;
            globals += std.mem.alignForward(usize, gl.plan.outputWords(), g) + gl.plan.enqueueWords();
        }
        // The PCS peak is not declared by the producer: the native PCS
        // segment-scale class measured 2.14e9 words [M] memory-plan-p2 (the
        // parity harness declared 5 << 29 = 2.68e9). Declare the measured
        // peak + 7%: the stage-two window must fit beside the legacy truths
        // (a 5.2e9-word window failed to map next to 6-10 GB live [M] h3).
        const pcs: usize = 2_300_000_000;
        const work = main_window + globals + self.stage2.inter.deviceWords() + self.composition.coefficientWords() + self.composition.enqueueWords() + pcs;
        // Pinned: the PCS ingress, the composition tables, and every upload a
        // FRESH persistent region may need (Stager.upload copies non-pinned
        // sources into the job's pinned memory): FIXED (if evicted), the
        // INTER trace twiddles, one twiddle tower per global log.
        var fresh: usize = self.fixed_words + 2 * (@as(usize, 1) << @intCast(self.stage2.inter.eval_log)) + self.composition.persistentWords() + 8 * self.stage2.inter.logs.len;
        for (self.globals) |gl| fresh += gl.plan.rows + gl.plan.parameters.len;
        return .{ .device_words = @min(self.window_words, staged + work + 16 * g), .staged_words = staged, .slab_words = self.layout.words, .pinned_words = @as(usize, @intCast(self.stage2.pcs.ingressWords())) + self.composition.pinnedWords() + fresh + 64 * g };
    }
    pub fn stage(self: *Stage2Job, s: *api.Stager) !void {
        const seed = try s.alloc(9);
        try s.upload(seed, &self.seed);
        self.staged_seed = seed;
        const fixed = try s.persistent(self.fixed_key, self.fixed_words);
        if (fixed.fresh) for (self.fixed_host, self.fixed_offsets) |h, off| try s.upload(try fixed.buffer.slice(off, h.len), h);
        self.fixed = fixed.buffer;
        if (self.legacy_main.len == 0) self.main = try s.retained(self.request, mainName(self.ordinal), self.main_words);
        self.bind = try s.retained(self.request, bindName(self.ordinal), self.bind_plan.output_words);
        self.inter_out = (try s.retain(self.request, interName(self.ordinal), self.stage2.inter.coefficient_cells)).buffer;
        self.comp_out = (try s.retain(self.request, compName(self.ordinal), self.composition.coefficientWords())).buffer;
        for (self.globals) |*gl| try gl.stage(self.a, s, &.{});
        try self.composition.stage(s);
        try self.stage2.stage(s, self.manifest, self.inter_inputs);
        try self.span.open(self.timing);
    }
    pub fn enqueue(self: *Stage2Job, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const fixed = self.fixed orelse return error.HybridStage2NotStaged;
        const main = self.main orelse blk: {
            const m = try e.alloc(self.main_words);
            try copyColumns(self.copy, e.stream(), m.ptr, self.main_offsets, self.main_logs, self.legacy_main);
            break :blk m;
        };
        const bind = self.bind.?;
        try self.span.mark(self.timing, .begin, e.stream());
        try e.channel.initFromCheckpoint(self.staged_seed.?);
        const claims = try e.slab.field(.claims, 0);
        const outputs = try self.a.alloc(?api.DeviceBuffer, self.slots.len);
        defer self.a.free(outputs);
        @memset(outputs, null);
        var pointers: std.ArrayListUnmanaged([*]const u32) = .empty;
        defer pointers.deinit(self.a);
        var k: usize = 0;
        for (self.slots, outputs) |slot, *out| if (slot.global) |g| {
            const p = g.plan;
            pointers.clearRetainingCapacity();
            for (0..p.fixed_count) |i| try pointers.append(self.a, fixed.ptr + self.fixed_offsets[g.fixed_first + i]);
            for (0..p.main_count) |i| try pointers.append(self.a, main.ptr + self.main_offsets[g.main_first + i]);
            const output = try e.alloc(p.outputWords());
            out.* = output;
            try self.globals[k].enqueue(e, pointers.items[0..p.fixed_count], pointers.items[p.fixed_count..], .{ .output = output, .claims = try p.claimsIn(claims, g.claim_offset), .status = try e.slab.field(.status, @intCast(1 + k)) });
            k += 1;
        };
        // INTER views: per slot [binding 16 | global witness], at inter_offset.
        for (self.slots, outputs) |slot, out| {
            var at = slot.inter_offset;
            const rows = @as(usize, 1) << @intCast(slot.log);
            if (slot.binding_index) |bi| {
                const cols = try self.bind_plan.columns(bind, bi);
                if (cols.words != 16 * rows) return error.HybridBindingShape;
                for (0..16) |c| self.inter_inputs[at + c] = .{ .device = cols.ptr + c * rows };
                at += 16;
            }
            if (slot.global) |g| {
                const output = out.?;
                for (0..g.plan.width) |c| self.inter_inputs[at + c] = .{ .device = try g.plan.columnPointer(output, c) };
            }
        }
        // NativeStage2.enqueue's sequence (native_stage2.zig), inlined so the
        // global witness outputs are freed right after the INTER commit (their
        // last reader copies them), before the composition and the PCS: the
        // whole-sequence peak otherwise overran a 4.8e9-word window [M] h9.
        const st = &self.stage2;
        const staged = st.staged orelse return error.Stage2NotStaged;
        const roots = try e.slab.field(.root, 0);
        const alpha = try e.slab.field(.opaque_words, 0);
        const mixed = try claims.slice(0, @as(usize, st.claim_count) * 8);
        try e.channel.mixWords(.{ .ptr = staged.ptr, .words = 3 });
        try e.channel.mixWords(.{ .ptr = staged.ptr + 3, .words = 8 });
        try e.channel.mixFelts(mixed);
        const inter = try st.inter.enqueue(st.csym, e, self.inter_inputs, try roots.slice(16, 8), true);
        var i = outputs.len;
        while (i > 0) {
            i -= 1;
            if (outputs[i]) |o| e.free(o);
        }
        try e.channel.drawSecureFelts(1, alpha);
        const inter_views = S2.Composition.Committed.of(st.inter, inter);
        const fixed_view = S2.Composition.Committed{ .offsets = self.fixed_offsets, .tree = .{ .coefficients = fixed, .root = fixed.ptr } };
        const main_view = S2.Composition.Committed{ .offsets = self.main_offsets, .tree = .{ .coefficients = main, .root = main.ptr } };
        var producer = S2.NativeComposition{ .plan = self.composition, .sym = self.comp_sym };
        const seam = producer.producer();
        const comp = try seam.enqueue(seam.ctx, e, .{ .alpha = alpha, .claims = mixed, .status = try e.slab.field(.status, 0), .root_out = try roots.slice(24, 8), .trees = .{ fixed_view, main_view, inter_views } });
        try e.channel.mixRootFromTree(try roots.slice(24, 8));
        // Move the INTER and composition coefficients out of the window (two
        // stream copies into retained regions) and free them: the PCS then
        // runs in the whole emptied window (its peak ~2.1e9 words [M] is not
        // added to the commit/composition peak; together they overran 4.8e9 [M] h11).
        const inter_out = self.inter_out.?;
        const comp_out = self.comp_out.?;
        if (comp.tree.coefficients.words < comp_out.words or inter.coefficients.words < inter_out.words) return error.HybridStage2Shape;
        if (self.copy(@ptrCast(inter_out.ptr), @ptrCast(inter.coefficients.ptr), inter_out.words * 4, 3, e.stream()) != 0) return error.CudaEnqueueFailed;
        if (self.copy(@ptrCast(comp_out.ptr), @ptrCast(comp.tree.coefficients.ptr), comp_out.words * 4, 3, e.stream()) != 0) return error.CudaEnqueueFailed;
        e.free(comp.tree.coefficients);
        e.free(inter.coefficients);
        const inter_moved = S2.Composition.Committed{ .offsets = inter_views.offsets, .tree = .{ .coefficients = inter_out, .root = inter_out.ptr } };
        const comp_moved = S2.Composition.Committed{ .offsets = comp.offsets, .tree = .{ .coefficients = comp_out, .root = comp_out.ptr } };
        const trees = [4]S2.Composition.Committed{ fixed_view, main_view, inter_moved, comp_moved };
        for (trees, 0..) |t, index| for (t.offsets, 0..) |offset, original| try st.pcs.bindColumn(index, original, t.tree.coefficients.ptr + offset);
        try st.pcs.enqueueOpening(st.nsym, e, st.pinned, try e.slab.field(.opaque_words, 1), try e.slab.field(.opaque_words, 2));
        try self.span.mark(self.timing, .end, e.stream());
    }
    pub fn finish(self: *Stage2Job, view: api.SlabView) !void {
        @memcpy(&self.roots, try Slab.read(view, .root, 0));
        @memcpy(&self.alpha, try Slab.read(view, .opaque_words, 0));
        self.composition_status = (try Slab.read(view, .status, 0))[0];
        for (self.global_status, 0..) |*st, i| st.* = (try Slab.read(view, .status, @intCast(1 + i)))[0];
        if (self.claims.len != 0) @memcpy(self.claims, (try Slab.read(view, .claims, 0))[0..self.claims.len]);
        @memcpy(&self.oods, try Slab.read(view, .opaque_words, 1));
        @memcpy(self.pcs_words, try Slab.read(view, .opaque_words, 2));
        self.span.read(self.timing);
    }
    pub fn abort(_: *Stage2Job) void {}
};

test "hybrid jobs type-check against the api" {
    _ = api.Job.from(Stage1Job, undefined);
    _ = api.Job.from(Stage2Job, undefined);
    try std.testing.expect(!std.mem.eql(u8, &mainName(1), &bindName(1)));
    try std.testing.expect(!std.mem.eql(u8, &mainName(1), &mainName(2)));
}
