//! Request Stage-1 lifecycle owner: initialization, staging, enqueue and completion.
const Schema = @import("native_device_stage1.zig");
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
const NP = @import("native_pack.zig");
const Span = @import("job_timing.zig").Timing.Span;
pub fn up(x: usize) usize {
    return std.mem.alignForward(usize, x, Schema.granule);
}

pub fn cuda(status: c_int) !void {
    if (status != 0) return error.CudaEnqueueFailed;
}

pub const Stage1Job = struct {
    a: std.mem.Allocator,
    class: *const Schema.Class,
    sym: *const Schema.Symbols,
    ctx: *const G.RequestContext,
    segment: u32,
    device: u32,
    words: Schema.RequestWords,
    witness: Schema.Witness,
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
                    try Schema.validateChunk(ch.words, c.image_words);
                }
                try Schema.validateCoverage(self.a, chunks, c.image_words);
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
        const staged = up(9) + Schema.granule + c.spec.gkr.stagedWords(true) + up(c.main.stagedWords(0)) + chunk_words;
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
        const claims_payload = try Schema.claimPayloadSlot(self.ctx.exchange, self.segment, c.claimsPerSegment());
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

        const pro = try Schema.enqueuePrologue(c, sym, e, seed, fixed_region, self.witness, self.runs, &self.main, self.inputs, main_view, root_out);
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
        var w = Schema.CheckSpec{ .check = @intFromEnum(G.Check.witness_status) };
        try w.mustBeZero(wstatus);
        for (pro.compact_status[0..pro.compact_status_len]) |st| try w.mustBeZero(st);
        try cuda(sym.check(ectx, 0, &w, st_witness.ptr));
        var b = Schema.CheckSpec{ .check = @intFromEnum(G.Check.binding_authority) };
        try b.mustBeZero(try e.slab.field(.status, c.spec.gkr.fields.status()));
        try b.mustBeZero(bverdict);
        try b.mustMatch(try header.slice(8, 12), &Schema.headerGuard(traversal.layers, traversal.count, traversal.chain));
        try b.mustMatch(try child.slice(8, 8), &Schema.snapshotGuard(c.child_draws, self.gkr.child_steps, self.gkr.child_chain));
        try cuda(sym.check(ectx, 0, &b, st_binding.ptr));
        var r = Schema.CheckSpec{ .check = @intFromEnum(G.Check.root_match) };
        try r.mustEqual(fixed_root, class_root);
        try r.mustEqual(root_out, try e.slab.field(.gkr_section, c.spec.gkr.fields.mainRoot()));
        try r.mustMatch(try checkpoint_view.slice(8, 8), &Schema.snapshotGuard(0, main_cursor, main_chain));
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
