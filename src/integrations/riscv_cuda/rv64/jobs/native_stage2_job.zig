//! Request Stage-2 owner: exclusive framing lease, enqueue and terminal cleanup.
const Schema = @import("native_device_stage2.zig");
const std = @import("std");
const LF = @import("native_leaf_wire.zig");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const NE = @import("native_encode.zig");
const C = @import("native_commit.zig");
const N = @import("native_pcs.zig");
const S2 = @import("native_stage2.zig");
const Gl = @import("native_global.zig");
const NO = @import("native_encode_oods.zig");
const m31_modulus = @import("stwo_core").fields.m31.Modulus;
pub const Stage2Job = struct {
    a: std.mem.Allocator,
    sym: *const Schema.Symbols,
    ctx: *const G.RequestContext,
    /// The class prototype: read-only class constants (footprint, key).
    class: *Schema.ClassFraming,
    /// The instance this job stages and enqueues with, held EXCLUSIVELY from
    /// `stage` to the end of `enqueue` (CommitPlan.stage, Plan.stage and
    /// PcsJob.bindColumn write per-job state into it; the worker stages job
    /// N+1 before it enqueues job N, and both GPUs run the same classes).
    /// From the owner's pool; `class` itself when there is no owner.
    lease: ?*Schema.ClassFraming = null,
    /// The class image on this GPU (worker-persistent, keyed by class: filled
    /// by the first job of the class on the GPU, never per request).
    class_device: api.DeviceBuffer = undefined,
    /// Owner to release this job to after finish/abort (null: caller owns).
    owner: ?*Schema.Factory = null,
    segment: u32,
    device: u32,
    /// GPU that ran the seal job (publishes the seal slot).
    seal_device: u32 = 0,
    constants: Schema.SealConstants,
    inputs: Schema.RequestInputs = .{},
    // staged
    staged_header: ?api.DeviceBuffer = null,
    checkpoint: ?api.DeviceBuffer = null,
    bind: ?api.DeviceBuffer = null,
    semantic: ?api.DeviceBuffer = null,
    fixed: ?api.DeviceBuffer = null,
    leaf_device: ?api.DeviceBuffer = null,
    tuples: [2]?api.DeviceBuffer = .{ null, null },
    public: ?api.DeviceBuffer = null,
    globals: []Gl.Global = &.{},
    inter_inputs: []C.Input = &.{},
    pinned: []u32 = &.{},

    pub fn id(self: *const Stage2Job) G.ProofId {
        return .{ .kind = .native_segment, .ordinal = self.segment };
    }
    pub fn classKey(self: *Stage2Job) [32]u8 {
        return self.class.key;
    }
    fn globalCount(self: *const Stage2Job) usize {
        var n: usize = 0;
        for (self.class.slots) |s| n += @intFromBool(s.global != null);
        return n;
    }
    pub fn footprint(self: *Stage2Job) api.Footprint {
        const g = 64;
        const c = self.class;
        var staged: usize = 4 * g + c.inter.stagedWords(0) + c.composition.stagedWords() + std.mem.alignForward(usize, self.inputs.initial_tuples.len, g) + std.mem.alignForward(usize, self.inputs.terminal_tuples.len, g) + std.mem.alignForward(usize, self.inputs.public.len, g);
        var globals: usize = 0;
        var global_outputs: usize = 0;
        var global_scratch: usize = 0;
        for (c.slots) |s| if (s.global) |gs| {
            staged += gs.plan.stagedWords(false) + g;
            globals += std.mem.alignForward(usize, gs.plan.outputWords(), g) + gs.plan.enqueueWords();
            global_outputs += std.mem.alignForward(usize, gs.plan.outputWords(), g);
            global_scratch = @max(global_scratch, gs.plan.enqueueWords());
        };
        // PCS peak: measured segment-scale class 2.14e9 words [M]
        // (memory-plan-p2) + 7%, as the retired native-hybrid Stage2Job.
        const pcs: usize = 2_300_000_000;
        // public_claims scratch grows with the boundary cells (8 + 8 per
        // 256-cell block, up to 4104 words): sized here, not in the slack.
        const pscratch = std.mem.alignForward(usize, @intCast(self.sym.encode.public_scratch(@intCast(self.inputs.initial_tuples.len / 14), @intCast(self.inputs.terminal_tuples.len / 14))), g);
        const oods_scratch: usize = if (c.oods) |d| std.mem.alignForward(usize, NO.scratchWords(d), g) else 0;
        const fields = 8 * g + @as(usize, c.claim_count) * 8 + @as(usize, @intCast(c.pcs.outputWords())) + NE.scratch_words + 8 * Schema.shared_felts + 8 * (1 + self.globalCount()) + pscratch + oods_scratch + 4096;
        const work = if (c.reuse_frees) blk: {
            // Each global's scratch is freed in reverse allocation order
            // before the next global. INTER consumes all global outputs;
            // they retire before composition/PCS. Retain their entire size
            // in later bounds as a conservative fragmentation allowance.
            // composition.enqueueWords already includes its kept output.
            const inter_peak = global_outputs + global_scratch + c.inter.deviceWords();
            const kept = global_outputs + c.inter.coefficient_cells;
            const composition_peak = kept + c.composition.enqueueWords();
            const pcs_peak = kept + c.composition.coefficientWords() + pcs;
            break :blk @max(inter_peak, @max(composition_peak, pcs_peak)) + fields;
        } else globals + c.inter.deviceWords() + c.composition.coefficientWords() + c.composition.enqueueWords() + pcs + fields;
        const fresh = c.fixed_words + c.composition.persistentWords();
        return .{ .device_words = staged + work + 16 * g, .staged_words = staged, .slab_words = 0, .pinned_words = if (c.resources_warmed) Schema.requestPinnedWords(c, self.inputs) else @as(usize, @intCast(c.pcs.ingressWords())) + c.composition.pinnedWords() + fresh + 64 * g + self.inputs.initial_tuples.len + self.inputs.terminal_tuples.len + self.inputs.public.len };
    }

    fn acquire(self: *Stage2Job) !*Schema.ClassFraming {
        if (self.lease) |l| return l;
        const l = if (self.owner) |f| try f.acquire(self.class) else self.class;
        self.lease = l;
        return l;
    }
    fn releaseLease(self: *Stage2Job) void {
        const l = self.lease orelse return;
        self.lease = null;
        if (self.owner) |f| f.releaseFraming(l);
    }

    pub fn stage(self: *Stage2Job, s: *api.Stager) !void {
        const c = try self.acquire();
        const ctx = self.ctx;
        const req = ctx.request;
        if (c.resident_handoff) |h| {
            const resident = ctx.main_resident[self.segment];
            self.checkpoint = try resident.slice(h.checkpoint, Schema.checkpoint_words);
            self.bind = try resident.slice(h.binding, c.bind_plan.output_words);
            if (c.uses(.semantic)) self.semantic = try resident.slice(h.semantic, c.semantic_words);
        } else {
            self.checkpoint = try s.retained(req, Schema.handoffName(.checkpoint, self.segment), Schema.checkpoint_words);
            self.bind = try s.retained(req, Schema.handoffName(.binding, self.segment), c.bind_plan.output_words);
            if (c.uses(.semantic)) self.semantic = try s.retained(req, Schema.handoffName(.semantic, self.segment), c.semantic_words);
        }
        if (c.uses(.public)) {
            if (self.inputs.public.len != 8 * @as(usize, c.public_input_felts)) return error.NativeStage2NoPublic;
            for (self.inputs.public) |w| if (w >= m31_modulus) return error.NativeStage2NoncanonicalPublic;
            const b = try s.alloc(self.inputs.public.len);
            try s.upload(b, self.inputs.public);
            self.public = b;
        }
        const image = try s.persistent(Schema.imageKey(c.key), c.deviceWords());
        if (image.fresh and c.resources_warmed) return error.GpuNativeStage2NotWarmed;
        if (image.fresh) {
            const words = try c.image(self.a);
            defer self.a.free(words);
            try s.upload(image.buffer, words);
        }
        self.class_device = image.buffer;
        if (self.inputs.leaf_program) |program| {
            const p = try s.persistent(program.key(), program.words.len);
            if (p.fresh) return error.NativeLeafProgramNotWarmed;
            self.leaf_device = p.buffer;
        }
        const fixed = try s.persistent(c.fixed_key, if (c.fixed_region_words != 0) c.fixed_region_words else c.fixed_words);
        if (fixed.fresh and c.resident_handoff != null) return error.GpuNativeFixedNotWarmed;
        if (fixed.fresh) for (c.fixed_host, c.fixed_offsets) |h, off| try s.upload(try fixed.buffer.slice(off, h.len), h);
        self.fixed = fixed.buffer;
        // [0,3) mixManifestAndClaims header (the digest comes from the seal
        // slot), [3,11) the class FIXED root (root_match), [11] a zero word.
        const hdr = try s.alloc(12);
        var words: [12]u32 = undefined;
        words[0..3].* = .{ S2.manifest_header[0], S2.manifest_header[1], c.claim_count };
        words[3..11].* = Schema.words8(c.fixed_root);
        words[11] = 0;
        try s.upload(hdr, &words);
        self.staged_header = hdr;
        for ([2][]const u32{ self.inputs.initial_tuples, self.inputs.terminal_tuples }, &self.tuples) |t, *out| {
            if (t.len % 14 != 0) return error.NativeStage2BoundaryShape;
            if (t.len == 0) {
                // A declared boundary relation over an empty cell list still
                // has a claim: public_claims must check that it is zero.
                // The kernel does not read tuples when cells == 0.
                out.* = try hdr.slice(0, 0);
            } else {
                const b = try s.alloc(t.len);
                try s.upload(b, t);
                out.* = b;
            }
        }
        self.globals = try self.a.alloc(Gl.Global, self.globalCount());
        var k: usize = 0;
        for (c.slots) |slot| if (slot.global) |gs| {
            self.globals[k] = .{ .plan = gs.plan, .sym = &self.sym.global };
            try self.globals[k].stage(self.a, s, &.{});
            k += 1;
        };
        try c.composition.stage(s);
        self.inter_inputs = try self.a.alloc(C.Input, c.inter.shapes.len);
        @memset(self.inter_inputs, .{ .device = @ptrFromInt(@alignOf(u32)) });
        try c.inter.stage(s, self.inter_inputs);
        self.pinned = try s.pinned(@intCast(c.pcs.ingressWords()));
    }

    fn status(self: *const Stage2Job, check: G.Check) !api.DeviceBuffer {
        const ctx = self.ctx;
        return ctx.layout.segments[self.device].statusBuffer(ctx.segments[self.device], self.id(), check);
    }

    /// out <- every source's patch of one parameter vector (stream order).
    fn applyPatches(self: *const Stage2Job, e: *api.Enqueue, set: Schema.ClassFraming.SetView, shared: api.DeviceBuffer, out: api.DeviceBuffer) !void {
        for (Schema.sources, set) |source, v| {
            if (v.dst.words == 0) continue;
            const src = switch (source) {
                .shared => shared,
                .semantic => self.semantic orelse return error.NativeStage2NoSemantic,
                .public => self.public orelse return error.NativeStage2NoPublic,
            };
            try NE.patchFelts(&self.sym.encode, e.ctx(), src, v.index, v.dst, out);
        }
    }

    pub fn enqueue(self: *Stage2Job, e: *api.Enqueue) !void {
        var trace_label: [80]u8 = undefined;
        var trace_range = try e.trace(.native_stage2, self.segment, &trace_label);
        defer trace_range.deinit();
        // The lease ends with the enqueue: everything below reads the
        // instance's host state at call time only (device work captured the
        // pointers it staged), so the next job may restage the instance.
        defer self.releaseLease();
        const c = self.lease orelse return error.NativeStage2NotStaged;
        const ctx = self.ctx;
        const sym = self.sym;
        const fixed = self.fixed orelse return error.NativeStage2NotStaged;
        if (self.segment >= ctx.main_resident.len) return error.NativeStage2NoResidentMain;
        const main = ctx.main_resident[self.segment];
        if (main.words < c.main_words) return error.NativeStage2ResidentMainShape;
        const bind = self.bind.?;
        const views = try c.views(self.a, self.class_device);
        defer self.a.free(views.globals);
        // ---- seal slot (chi) on this GPU, then the shared draws
        const seal = ctx.exchange.seal();
        try ctx.peer.awaitSlot(self.device, self.seal_device, seal);
        const x = try Schema.replica(ctx, self.device);
        const chi = try x.slice(seal.offset, 8);
        const shared = try e.alloc(8 * Schema.shared_felts);
        try Schema.rcOf(sym.seal.shared(e.ctx(), 0, chi.ptr, &self.constants, shared.ptr, shared.words));
        // ---- device parameters: globals and composition table, from the
        // shared draws, the Stage-1 semantic handoff and the public inputs
        if (views.globals.len != self.globals.len) return error.NativeStage2PatchTable;
        for (self.globals, views.globals) |*gl, set| try self.applyPatches(e, set, shared, gl.staged.?);
        const table = c.composition.table_device orelse return error.NativeStage2NotStaged;
        try self.applyPatches(e, views.composition, shared, table);
        var k: usize = 0;
        // ---- transcript from the Stage-1 checkpoint
        try e.channel.initFromCheckpoint(self.checkpoint.?);
        const claims = try e.alloc(@max(1, @as(usize, c.claim_count) * 8));
        const gstatus = try e.alloc(@max(1, self.globals.len));
        const roots = try e.alloc(32);
        const alpha = try e.alloc(8);
        const comp_status = try e.alloc(1);
        const oods = try e.alloc(N.oods_field_words);
        const pcs_out = try e.alloc(@intCast(c.pcs.outputWords()));
        // ---- global interaction of every slot
        const outputs = try self.a.alloc(?api.DeviceBuffer, c.slots.len);
        defer self.a.free(outputs);
        @memset(outputs, null);
        var pointers: std.ArrayListUnmanaged([*]const u32) = .empty;
        defer pointers.deinit(self.a);
        k = 0;
        for (c.slots, outputs) |slot, *out| if (slot.global) |g| {
            const p = g.plan;
            pointers.clearRetainingCapacity();
            for (0..p.fixed_count) |i| try pointers.append(self.a, fixed.ptr + c.fixed_offsets[g.fixed_first + i]);
            for (0..p.main_count) |i| try pointers.append(self.a, main.ptr + c.main_offsets[g.main_first + i]);
            const output = try e.alloc(p.outputWords());
            out.* = output;
            try self.globals[k].enqueue(e, pointers.items[0..p.fixed_count], pointers.items[p.fixed_count..], .{ .output = output, .claims = try p.claimsIn(claims, g.claim_offset), .status = try gstatus.slice(k, 1) });
            k += 1;
        };
        for (c.slots, outputs) |slot, out| {
            var at = slot.inter_offset;
            const rows = @as(usize, 1) << @intCast(slot.log);
            if (slot.binding_index) |bi| {
                const cols = try c.bind_plan.columns(bind, bi);
                if (cols.words != 16 * rows) return error.NativeStage2BindingShape;
                for (0..16) |col| self.inter_inputs[at + col] = .{ .device = cols.ptr + col * rows };
                at += 16;
            }
            if (slot.global) |g| for (0..g.plan.width) |col| {
                self.inter_inputs[at + col] = .{ .device = try g.plan.columnPointer(out.?, col) };
            };
        }
        // ---- mixManifestAndClaims (chi from the seal slot), INTER, alpha
        const mixed = try claims.slice(0, @as(usize, c.claim_count) * 8);
        const hdr = self.staged_header orelse return error.NativeStage2NotStaged;
        try e.channel.mixWords(try hdr.slice(0, 3));
        try e.channel.mixWords(chi);
        try e.channel.mixFelts(mixed);
        const inter = try c.inter.enqueue(sym.commit, e, self.inter_inputs, try roots.slice(16, 8), true);
        var i = outputs.len;
        while (i > 0) {
            i -= 1;
            if (outputs[i]) |o| e.free(o);
        }
        try e.channel.drawSecureFelts(1, alpha);
        // ---- composition, OODS, PCS
        const inter_views = S2.Composition.Committed.of(c.inter, inter);
        const fixed_view = S2.Composition.Committed{ .offsets = c.fixed_offsets, .tree = .{ .coefficients = fixed, .root = fixed.ptr } };
        const main_view = S2.Composition.Committed{ .offsets = c.main_offsets, .tree = .{ .coefficients = main, .root = main.ptr } };
        var producer = S2.NativeComposition{ .plan = c.composition, .sym = sym.composition };
        const seam = producer.producer();
        const comp = try seam.enqueue(seam.ctx, e, .{ .alpha = alpha, .claims = mixed, .status = comp_status, .root_out = try roots.slice(24, 8), .trees = .{ fixed_view, main_view, inter_views } });
        try e.channel.mixRootFromTree(try roots.slice(24, 8));
        const trees = [4]S2.Composition.Committed{ fixed_view, main_view, inter_views, comp };
        for (trees, 0..) |t, index| for (t.offsets, 0..) |offset, original| try c.pcs.bindColumn(index, original, t.tree.coefficients.ptr + offset);
        try c.pcs.enqueueOpening(sym.pcs, e, self.pinned, oods, pcs_out);
        e.free(comp.tree.coefficients);
        e.free(inter.coefficients);
        // ---- device acceptance checks -> request slab status words
        // No global slot: nothing can reject; the check reads the staged zero word.
        try NE.wordsZero(&sym.encode, e.ctx(), if (self.globals.len != 0) gstatus else try hdr.slice(11, 1), .global_status, try self.status(.global_status));
        try NE.wordsZero(&sym.encode, e.ctx(), comp_status, .composition_accept, try self.status(.composition_accept));
        try NE.wordsZero(&sym.encode, e.ctx(), try e.channel.stateBuffer().slice(10, 1), .channel_order, try self.status(.channel_order));
        // root_match: FIXED vs the class authority; MAIN vs this segment's exchange root slot.
        const main_root = try x.slice((try ctx.exchange.root(self.segment)).offset, 8);
        // The committed FIXED tree is the class tree (persistent), so its
        // committed root is the class root staged above; MAIN is the root
        // Stage 1 published; INTER / composition are this job's commits.
        try NE.rootMatch(&sym.encode, e.ctx(), pcs_out, &.{ try hdr.slice(3, 8), main_root, try roots.slice(16, 8), try roots.slice(24, 8) }, c.fixed_root, try self.status(.root_match));
        // public_claims (device RAM boundary reduction)
        const bi: ?NE.BoundaryInput = if (c.initial_claim) |cl| .{ .claim = cl, .tuples = self.tuples[0] orelse return error.NativeStage2NoBoundary, .cells = @intCast(self.inputs.initial_tuples.len / 14) } else null;
        const bt: ?NE.BoundaryInput = if (c.terminal_claim) |cl| .{ .claim = cl, .tuples = self.tuples[1] orelse return error.NativeStage2NoBoundary, .cells = @intCast(self.inputs.terminal_tuples.len / 14) } else null;
        const pscratch = try e.alloc(NE.publicClaimsScratch(&sym.encode, bi, bt));
        try NE.publicClaims(&sym.encode, e.ctx(), mixed, c.claim_count, try shared.slice(0, 15 * 8), bi, bt, pscratch, try self.status(.public_claims));
        // oods_constraint: the composition programs at the device OODS point
        // from the PCS image samples and the patched composition table
        // (after the claim slots: the composition enqueue copied them in).
        var oods_scratch: ?api.DeviceBuffer = null;
        if (views.oods) |od| if (sym.oods) |*osym| {
            const d = c.oods.?;
            const samples = try pcs_out.slice(c.program.get(.off_samples), 8 * @as(usize, c.program.get(.sample_count)));
            const os = try e.alloc(NO.scratchWords(d));
            oods_scratch = os;
            const diagnostic: ?api.DeviceBuffer = if (self.inputs.oods_diagnostic) blk: {
                const program = self.inputs.leaf_program orelse return error.NativeLeafProgramNotWarmed;
                const region = try ctx.layout.segments[self.device].encodedBuffer(ctx.segments[self.device], self.id());
                // Relayout leaves all extra capacity in wire padding, ahead
                // of the PCS/leaf suffix. Never extend past that suffix.
                const count = Schema.oodsDiagnosticWords(c);
                if (program.words[10] < count) return error.NativeStage2OodsProgram;
                const out = try region.slice(program.words[10] - count, count);
                var at: usize = 16;
                for ([_]api.DeviceBuffer{ alpha, oods, table, samples }) |src| {
                    try Schema.rcOf(sym.commit.copy_d2d(e.ctx(), (try out.slice(at, src.words)).ptr, src.ptr, src.bytes()));
                    at += src.words;
                }
                if (at != out.words) return error.NativeStage2OodsProgram;
                break :blk try out.slice(0, 16);
            } else null;
            try NO.enqueue(osym, e.ctx(), od, samples, table, alpha, oods, os, try self.status(.oods_constraint), diagnostic);
        };
        // ---- device encoding into the slab region (+ pcs_status, encode_bounds)
        const scratch = try e.alloc(NE.scratch_words);
        var enc = NE.Encoder{ .sym = &sym.encode, .program = views.program, .host = &c.program, .pcs = pcs_out, .scratch = scratch, .pcs_status = try self.status(.pcs_status) };
        try enc.encoder().run(e, &ctx.layout.segments[self.device], ctx.segments[self.device], self.id());
        if (self.inputs.leaf_program) |program| {
            const handoff = c.resident_handoff orelse return error.NativeStage2NoSemantic;
            const section = try main.slice(handoff.section, handoff.section_words);
            const receipt = try x.slice((try ctx.exchange.receipt(self.segment)).offset, 8);
            const region = try ctx.layout.segments[self.device].encodedBuffer(ctx.segments[self.device], self.id());
            const leaf_device = self.leaf_device orelse return error.NativeLeafProgramNotWarmed;
            const sources_: [6]?LF.Buffer = .{ null, .{ .ptr = section.ptr, .words = section.words }, .{ .ptr = chi.ptr, .words = chi.words }, .{ .ptr = receipt.ptr, .words = receipt.words }, .{ .ptr = claims.ptr, .words = claims.words }, .{ .ptr = pcs_out.ptr, .words = pcs_out.words } };
            try LF.enqueue(sym.leaf orelse return error.MissingNativeLeafEncoder, sym.commit.copy_d2d, e.ctx(), program, .{ .ptr = leaf_device.ptr, .words = leaf_device.words }, sources_, .{ .ptr = region.ptr, .words = region.words }, (try self.status(.encode_bounds)).ptr, @as(u32, @intFromEnum(G.Check.encode_bounds)) << 16);
        }
        // Stream-ordered frees after the last readers.
        if (oods_scratch) |b| e.free(b);
        for ([_]api.DeviceBuffer{ scratch, pscratch, pcs_out, oods, comp_status, alpha, roots, gstatus, claims, shared }) |b| e.free(b);
    }

    pub fn finish(self: *Stage2Job, _: api.SlabView) !void {
        self.release();
    }
    pub fn abort(self: *Stage2Job) void {
        self.release();
    }
    fn release(self: *Stage2Job) void {
        const owner = self.owner;
        self.releaseLease(); // abort between stage and enqueue
        self.deinit();
        if (owner) |f| f.releaseStage2(self);
    }
    pub fn deinit(self: *Stage2Job) void {
        self.a.free(self.globals);
        self.a.free(self.inter_inputs);
        self.globals = &.{};
        self.inter_inputs = &.{};
    }
};
