//! Truth Stage-2 request owner: shared draws, interaction, composition, proof encoding and terminal custody.
const Schema = @import("truth_job.zig");
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const Slab = @import("slab.zig");
const C = @import("native_commit.zig");
const NC = @import("native_composition.zig");
const NP = @import("native_pcs.zig");
const S1 = @import("native_stage1.zig");
const X = @import("truth_challenges.zig");
const P = @import("truth_params.zig");
const I = @import("truth_interaction.zig");
const K = @import("truth_class.zig");
const T = @import("../truth_codegen.zig");
const TO = @import("truth_oods.zig");
const NE = @import("native_encode.zig");
const LF = @import("native_leaf_wire.zig");
const D = CPU.rv64_device_pcs;
const WP = CPU.rv64_gkr_worker_protocol;
const O = D.O;
const CP = engine.air.component_prover.ForField(O);
const verdict_names = [_][]const u8{ "truth_status", "root_match", "channel_order", "pcs_status", "truth_oods", "encode_bounds" };
const Events = @import("../cuda_events.zig");
const CPU = @import("stwo_riscv_cpu_integration");
pub const Table = struct {
    local: usize = 0,
    shared: usize = 0,
    consts: usize = 0,
    header: usize = 0,
    programs: [6]usize = @splat(0),
    roots: usize = 0, // 16 words: class FIXED root, then the expected MAIN root (filled on device)
    expect: usize = 0,
    host_digest: usize = 0, // 8 words (Stage2.digest_words)
    host_root: usize = 0, // 8 words (Stage2.stage1_root_words)
    words: usize = 0,
};

pub const Stage2 = struct {
    leaf_program: ?*const LF.Program = null,
    leaf_device: ?api.DeviceBuffer = null,
    a: std.mem.Allocator,
    class: *const K.Class,
    sym: *const Schema.Symbols,
    ordinal: u32,
    calls: u32,
    first_id: u32,
    compact: []const u32,
    /// worker_protocol.begin(config, expected) [+ binding] (K.seed).
    seed: [9]u32,
    /// Device manifest digest (8 words: the seal slot's first words), or
    /// null with `digest_words` (host words staged with the job: harnesses
    /// and the hybrid driver, where the seal ran on the host).
    digest: ?api.DeviceBuffer = null,
    digest_words: ?[8]u32 = null,
    /// Device stage-1 MAIN root (8 words) the replay must reproduce; null =
    /// compared on the host instead (parity harness vs the legacy root).
    stage1_root: ?api.DeviceBuffer = null,
    /// As `stage1_root`, from host words (staged).
    stage1_root_words: ?[8]u32 = null,
    /// CUDA-event GPU span of the job's enqueue (begin..end on the exec stream).
    timing: ?*const Events.Api = null,
    /// Negative tests: corrupt exactly one check input (each must fire its check).
    fault: Schema.Fault = .none,
    verdicts: Schema.Verdicts = .{},
    /// Skip the host assembly in finish (timing runs of the host path).
    assemble_on_finish: bool = true,
    /// gn-truth: device OODS + device encoder (`.device`), or both paths
    /// compared (`.check`). `.host` is the r-truth path unchanged.
    encode: Schema.Encode = .host,
    /// Request-slab encoded region of this truth (length word + bytes);
    /// null = a job-slab field (finish copies the bytes: harnesses).
    encoded: ?api.DeviceBuffer = null,
    request_slab_only: bool = false,
    // per-job plan copies
    fixed_plan: C.CommitPlan = undefined,
    main_plan: C.CommitPlan = undefined,
    inter_plan: C.CommitPlan = undefined,
    composition: NC.Plan = undefined,
    pcs: NP.PcsJob = undefined,
    fixed_tree: S1.FixedTree = undefined,
    live: bool = false,
    layout: Slab.ProofLayout = .{},
    table: Table = .{},
    // staged
    staged: ?api.DeviceBuffer = null,
    staged_seed: ?api.DeviceBuffer = null,
    staged_compact: ?api.DeviceBuffer = null,
    pinned: []u32 = &.{},
    twiddles: [3]?api.DeviceBuffer = @splat(null),
    /// Class-persistent device programs (device modes).
    oods_program: ?api.DeviceBuffer = null,
    encode_program: ?api.DeviceBuffer = null,
    // finish copies
    roots: [32]u32 = undefined,
    alpha: [8]u32 = undefined,
    status_words: [8]u32 = @splat(0),
    claims: [40]u32 = @splat(0),
    oods: [NP.oods_field_words]u32 = undefined,
    local_felts: [X.classic_felts * 8]u32 = @splat(0),
    shared_felts: [X.shared_felts * 8]u32 = undefined,
    pcs_words: []u32 = &.{},
    verdict_words: [verdict_names.len]u32 = @splat(G.Verdict.unset),
    /// Device OODS diagnostic [evaluated(8) | extracted(8)] (device modes).
    oods_diag: [16]u32 = @splat(0),
    /// Host OODS values (`.check`): evaluated, extracted.
    host_oods: [16]u32 = @splat(0),
    /// Device-encoded bytes copied from the job slab (`encoded == null`;
    /// caller frees) and whether they equal the host bytes (`.check`).
    device_bytes: []u8 = &.{},
    device_equal: bool = false,
    /// CUDA-event GPU span of the device OODS check + encoder.
    device_span: Schema.Span = .{},
    /// CUDA-event GPU span of the device OODS check alone (inside device_span).
    oods_span: Schema.Span = .{},
    /// Host time of finish (verdict reads + copies; + assembly on the host path).
    finish_ns: u64 = 0,
    channel_steps: u32 = 0,
    /// finish output: the legacy proof bytes and claims (caller frees).
    bytes: []u8 = &.{},
    out_claims: []O = &.{},
    span: Schema.Span = .{},
    /// pcs_status expectation (host struct; the launcher copies it by value).
    expect: Schema.PcsExpect = undefined,
    /// Host finish (assembly) time of the last finish.
    assemble_ns: u64 = 0,

    pub fn init(self: *Stage2) !void {
        if (self.request_slab_only) {
            if (self.encode != .device or self.encoded == null) return error.TruthRequestVerdictsMissing;
            inline for (verdict_names) |name| if (@field(self.verdicts, name) == null) return error.TruthRequestVerdictsMissing;
        }
        const c = self.class;
        if (self.compact.len != c.compactWords(self.calls) or self.calls == 0) return error.TruthCompactShape;
        // `.check` compares the device bytes it copies out of the job slab;
        // a request-slab region would leave nothing to compare.
        if (self.encode == .check and self.encoded != null) return error.TruthCheckNeedsJobSlabRegion;
        if (self.encoded) |r| if (r.words < c.encode.regionWords()) {
            // A region below the class capacity: the encoder fails closed
            // (encode_bounds); `.encode_capacity` negatives exercise it.
            if (self.fault != .encode_capacity) return error.TruthEncodedRegionTooSmall;
        };
        if (self.digest) |d| {
            if (d.words < G.Exchange.seal_digest_words) return error.TruthDigestShape;
        } else if (self.digest_words == null) return error.TruthDigestRequired;
        if (self.stage1_root != null and self.stage1_root_words != null) return error.TruthStage1RootAmbiguous;
        self.fixed_plan = try K.jobPlan(self.a, &c.fixed_plan);
        errdefer K.freeJobPlan(self.a, &self.fixed_plan);
        self.main_plan = try K.jobPlan(self.a, &c.main_plan);
        errdefer K.freeJobPlan(self.a, &self.main_plan);
        self.inter_plan = try K.jobPlan(self.a, &c.inter_plan);
        errdefer K.freeJobPlan(self.a, &self.inter_plan);
        self.main_plan.require_warm = self.request_slab_only;
        self.inter_plan.require_warm = self.request_slab_only;
        self.composition = c.composition;
        self.composition.table_device = null;
        self.composition.tw_device = null;
        self.pcs = try K.clonePcs(self.a, c);
        errdefer self.a.free(self.pcs.prepared.coefficients);
        self.pcs_words = try self.a.alloc(u32, @intCast(self.pcs.outputWords()));
        errdefer self.a.free(self.pcs_words);
        self.fixed_tree = .{ .plan = &self.fixed_plan, .key = c.fixed_key };
        self.table = tableOf(c);
        self.live = true;
        const n_status: u32 = Schema.StatusIndex.first_role + @as(u32, @intCast(c.roles.len));
        _ = try self.layout.add(.root, 0, 32);
        _ = try self.layout.add(.opaque_words, 0, 8); // alpha
        _ = try self.layout.add(.status, 0, n_status);
        _ = try self.layout.add(.status, 1, Schema.Own.words); // own verdicts + raw PCS words
        _ = try self.layout.add(.claims, 0, feltWords(c.claim_count));
        _ = try self.layout.add(.claims, 1, @max(8, feltWords(c.zero_count)));
        _ = try self.layout.add(.opaque_words, 1, NP.oods_field_words);
        if (self.encode != .host) {
            const sym = self.sym;
            if (sym.oods == null or sym.encode == null or sym.merge == null) return error.TruthDeviceEncodeSymbolsMissing;
            _ = try self.layout.add(.opaque_words, 5, 16); // OODS diagnostic
            if (self.encoded == null) _ = try self.layout.add(.opaque_words, 6, c.encode.regionWords());
        }
        // The PCS image enters the job slab only for host decoding.
        if (self.encode != .device) _ = try self.layout.add(.opaque_words, 2, self.pcs_words.len);
        _ = try self.layout.add(.opaque_words, 3, feltWords(c.localScript().felts));
        _ = try self.layout.add(.opaque_words, 4, feltWords(X.shared_felts));
        _ = try self.layout.add(.channel_state, 0, @import("channel.zig").snapshot_words);
    }
    pub fn deinit(self: *Stage2) void {
        self.span.close(self.timing);
        self.device_span.close(self.timing);
        self.oods_span.close(self.timing);
        if (!self.live) return;
        K.freeJobPlan(self.a, &self.fixed_plan);
        K.freeJobPlan(self.a, &self.main_plan);
        K.freeJobPlan(self.a, &self.inter_plan);
        self.a.free(self.pcs.prepared.coefficients);
        self.a.free(self.pcs_words);
        self.live = false;
    }
    pub fn classKey(self: *Stage2) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gpu-truth-stage2/v1\x00");
        h.update(&self.class.key);
        return h.finalResult();
    }
    pub fn footprint(self: *Stage2) api.Footprint {
        var fp = if (self.request_slab_only) Schema.stage2RequestFootprint(self.class, self.calls, @intCast(self.pcs.outputWords()), @intCast(self.pcs.ingressWords())) else Schema.stage2Footprint(self.class, self.calls, self.layout.words, @intCast(self.pcs.outputWords()), @intCast(self.pcs.ingressWords()));
        if (self.request_slab_only) fp.device_words += self.layout.words;
        return fp;
    }

    pub fn stage(self: *Stage2, s: *api.Stager) !void {
        const c = self.class;
        if (self.leaf_program) |program| {
            const p = try s.persistent(program.key(), program.words.len);
            if (p.fresh) return error.NativeLeafProgramNotWarmed;
            self.leaf_device = p.buffer;
        }
        const t = self.table;
        const table = try s.pinned(t.words);
        try fillTable(c, &self.pcs, t, self.calls, self.first_id, table);
        if (self.digest_words) |w| @memcpy(table[t.host_digest..][0..8], &w);
        if (self.stage1_root_words) |w| @memcpy(table[t.host_root..][0..8], &w);
        switch (self.fault) {
            .none, .absent_claim, .channel_cursor => {},
            .parameter_program => table[t.programs[0] + 1] = c.bounds().staged + 1000, // out-of-range gather entry
            .class_root => table[t.roots] ^= 1,
            .stage1_root => table[t.host_root] ^= 1,
            .pcs_header => {},
            .oods_sample, .oods_composition, .encode_capacity, .encode_value => if (self.encode == .host) return error.TruthFaultNeedsDeviceEncode,
        }
        self.expect = Schema.pcsExpect(&self.pcs);
        if (self.fault == .pcs_header) self.expect.header[0] ^= 1;
        if (self.fault == .stage1_root and self.stage1_root_words == null) return error.TruthFaultNeedsStage1Root;
        try self.span.open(self.timing);
        const staged = try s.alloc(t.words);
        try s.upload(staged, table);
        self.staged = staged;
        const seed = try s.alloc(9);
        try s.upload(seed, &self.seed);
        self.staged_seed = seed;
        const compact = try s.alloc(self.compact.len);
        try s.upload(compact, self.compact);
        self.staged_compact = compact;
        // FIXED: class-persistent, filled by the first job of the class.
        const fixed_inputs = try self.a.alloc(C.Input, c.fixed_host.len);
        defer self.a.free(fixed_inputs);
        for (fixed_inputs, c.fixed_host) |*i, h| i.* = .{ .host = h };
        if (self.request_slab_only) {
            const region = try s.persistent(c.fixed_key, self.fixed_tree.words());
            if (region.fresh) return error.TruthClassNotWarmed;
            self.fixed_tree.persistent = region;
        } else try self.fixed_tree.stage(s, fixed_inputs);
        const inputs = try placeholders(self.a, @max(c.main_logs.len, c.inter_logs.len));
        defer self.a.free(inputs);
        try self.main_plan.stage(s, inputs[0..c.main_logs.len]);
        try self.inter_plan.stage(s, inputs[0..c.inter_logs.len]);
        for (c.roles, 0..) |r, i| self.twiddles[i] = try I.stageTwiddles(self.a, s, r.interaction.log);
        try self.composition.stage(s);
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
        if (self.encode != .host) {
            // Class-persistent per worker: uploaded by the first job of the class.
            const od = try s.persistent(c.oods.key(c.key), c.oods.words.len);
            if (od.fresh and self.request_slab_only) return error.TruthClassNotWarmed;
            if (od.fresh) try s.upload(od.buffer, c.oods.words);
            self.oods_program = od.buffer;
            const ep = try s.persistent(Schema.encodeKey(c), c.encode.words.len);
            if (ep.fresh and self.request_slab_only) return error.TruthClassNotWarmed;
            if (ep.fresh) try s.upload(ep.buffer, c.encode.words);
            self.encode_program = ep.buffer;
            try self.device_span.open(self.timing);
            try self.oods_span.open(self.timing);
        }
    }

    pub fn enqueue(self: *Stage2, e: *api.Enqueue) !void {
        var trace_label: [80]u8 = undefined;
        var trace_range = try e.trace(.truth_stage2, self.ordinal, &trace_label);
        defer trace_range.deinit();
        const saved = e.slab.*;
        defer e.slab.* = saved;
        if (self.request_slab_only) e.slab.* = .{ .device = try e.alloc(self.layout.words) };
        const c = self.class;
        const sym = self.sym;
        const ctx = e.ctx();
        const t = self.table;
        try e.slab.bind(&self.layout);
        trace("s2.begin", self.ordinal);
        const staged = self.staged orelse return error.TruthJobNotStaged;
        const compact = self.staged_compact.?;
        const roots = try e.slab.field(.root, 0);
        const status = try e.slab.field(.status, 0);
        const own = try e.slab.field(.status, 1);
        const claims = try e.slab.field(.claims, 0);
        const zero = try e.slab.field(.claims, 1);
        const local = try e.slab.field(.opaque_words, 3);
        const shared = try e.slab.field(.opaque_words, 4);
        try check(sym.memset(ctx, status.ptr, 0, status.words * 4));
        try check(sym.memset(ctx, claims.ptr, 0, claims.words * 4));
        try check(sym.memset(ctx, zero.ptr, 0, zero.words * 4));
        // Transcript prefix: begin [+ binding] (host seed), FIXED root, MAIN root.
        const digest = self.digest orelse try staged.slice(t.host_digest, 8);
        const stage1_root: ?api.DeviceBuffer = self.stage1_root orelse if (self.stage1_root_words != null) try staged.slice(t.host_root, 8) else null;
        try self.span.mark(self.timing, false, e.stream());
        try e.channel.initFromCheckpoint(self.staged_seed.?);
        const fixed_inputs = try self.a.alloc(C.Input, c.fixed_host.len);
        defer self.a.free(fixed_inputs);
        for (fixed_inputs, c.fixed_host) |*i, h| i.* = .{ .host = h };
        const fixed = try self.fixed_tree.enqueue(sym.commit, e, fixed_inputs, try roots.slice(0, 8));
        trace("s2.fixed", self.ordinal);
        const main_eval = try e.alloc(c.mainEvalWords());
        const bytes = try enqueueWitness(c, sym, e, compact, main_eval, status.ptr + Schema.StatusIndex.witness, self.calls, self.first_id);
        const main_inputs = try self.a.alloc(C.Input, c.main_logs.len);
        defer self.a.free(main_inputs);
        try mainInputs(c, main_eval, main_inputs);
        const main = try self.main_plan.enqueue(sym.commit, e, main_inputs, try roots.slice(8, 8), true);
        trace("s2.main", self.ordinal);
        if (bytes) |b| e.free(b);
        e.free(main_eval);
        // Local challenges (proof channel), shared challenges (fresh channel over the digest).
        try X.run(c.localScript(), e.channel, try staged.slice(t.local, X.stagedWords(c.localScript())), null, local);
        trace("s2.local", self.ordinal);
        const state = try e.alloc(@import("channel.zig").state_words);
        var fresh = api.DeviceChannel.init(e.channel.worker, e.channel.exec, ctx, e.stream(), state, 0);
        try X.run(X.shared, &fresh, try staged.slice(t.shared, X.stagedWords(X.shared)), digest, shared);
        e.free(state);
        trace("s2.shared", self.ordinal);
        // Interaction witnesses.
        const consts = try staged.slice(t.consts, feltWords(c.stagedFelts()));
        const b = c.bounds();
        const bounds = [4]u32{ b.staged, b.local, b.shared, b.claim };
        var outputs: [3]api.DeviceBuffer = undefined;
        var max_fixed: usize = 0;
        var max_main: usize = 0;
        for (c.roles) |r| {
            max_fixed = @max(max_fixed, r.interaction.fixed_count);
            max_main = @max(max_main, r.interaction.main_count);
        }
        const fixed_ptrs = try self.a.alloc([*]const u32, max_fixed);
        defer self.a.free(fixed_ptrs);
        const main_ptrs = try self.a.alloc([*]const u32, max_main);
        defer self.a.free(main_ptrs);
        for (c.roles, 0..) |*r, i| {
            const p = &r.interaction;
            const params = try e.alloc(p.program.len * 8);
            try check(sym.gather(ctx, 0, consts.ptr, local.ptr, shared.ptr, null, @ptrCast(staged.ptr + t.programs[2 * i]), @intCast(p.program.len), &bounds, params.ptr, status.ptr + Schema.StatusIndex.params));
            for (0..p.fixed_count) |k| fixed_ptrs[k] = fixed.coefficients.ptr + c.fixed_offsets[p.fixed_first + k];
            for (0..p.main_count) |k| main_ptrs[k] = main.coefficients.ptr + self.main_plan.offsets[p.main_first + k];
            outputs[i] = try e.alloc(p.outputWords());
            try I.enqueue(p, &sym.interaction, e, .{ .fixed = fixed_ptrs[0..p.fixed_count], .main = main_ptrs[0..p.main_count], .parameters = params, .twiddles = self.twiddles[i].? }, .{ .output = outputs[i], .claims = claims, .zero = zero, .status = try status.slice(Schema.StatusIndex.first_role + i, 1) });
            e.free(params);
            trace("s2.role", self.ordinal);
        }
        // mixManifestAndClaims (worker_protocol): header, digest, claims.
        try e.channel.mixWords(try staged.slice(t.header, 3));
        try e.channel.mixWords(try digest.slice(0, 8));
        try e.channel.mixFelts(claims);
        trace("s2.mixed", self.ordinal);
        // INTER commit over the roles' published columns; the witnesses die after it.
        const inter_inputs = try self.a.alloc(C.Input, c.inter_logs.len);
        defer self.a.free(inter_inputs);
        {
            var at: usize = 0;
            for (c.roles, 0..) |*r, i| for (0..r.interaction.width()) |col| {
                inter_inputs[at] = .{ .device = try r.interaction.columnPointer(outputs[i].ptr, col) };
                at += 1;
            };
        }
        const inter = try self.inter_plan.enqueue(sym.commit, e, inter_inputs, try roots.slice(16, 8), true);
        trace("s2.inter", self.ordinal);
        var k = c.roles.len;
        while (k > 0) {
            k -= 1;
            e.free(outputs[k]);
        }
        // Composition: coefficient drawn on device, role parameters gathered on device.
        const alpha = try e.slab.field(.opaque_words, 0);
        try e.channel.drawSecureFelts(1, alpha);
        const table = (self.composition.table_device orelse return error.NativeCompositionNotStaged).ptr;
        for (c.roles, self.composition.roles, 0..) |*r, rp, i| {
            if (rp.spec.parameters.len != r.composition_program.len * 8) return error.TruthCompositionShape;
            try check(sym.gather(ctx, 0, consts.ptr, local.ptr, shared.ptr, claims.ptr, @ptrCast(staged.ptr + t.programs[2 * i + 1]), @intCast(r.composition_program.len), &bounds, table + rp.t_params, status.ptr + Schema.StatusIndex.params));
        }
        const fixed_cols = NC.Columns{ .base = fixed.coefficients.ptr, .offsets = c.fixed_offsets };
        const main_cols = NC.Columns{ .base = main.coefficients.ptr, .offsets = self.main_plan.offsets };
        const inter_cols = NC.Columns{ .base = inter.coefficients.ptr, .offsets = self.inter_plan.offsets };
        const comp = try self.composition.enqueueWithClaims(sym.composition, e, .{ fixed_cols, main_cols, inter_cols }, alpha.ptr, null, try roots.slice(24, 8), status.ptr + Schema.StatusIndex.composition);
        try e.channel.mixRootFromTree(try roots.slice(24, 8));
        trace("s2.composition", self.ordinal);
        // OODS + enqueue-only PCS over the four trees.
        const trees = [4]struct { base: [*]const u32, offsets: []const usize }{
            .{ .base = fixed.coefficients.ptr, .offsets = c.fixed_offsets },
            .{ .base = main.coefficients.ptr, .offsets = self.main_plan.offsets },
            .{ .base = inter.coefficients.ptr, .offsets = self.inter_plan.offsets },
            .{ .base = comp.coefficients.ptr, .offsets = self.composition.offsets },
        };
        for (trees, 0..) |tree, index| for (tree.offsets, 0..) |offset, original| try self.pcs.bindColumn(index, original, tree.base + offset);
        const pcs_out = if (self.encode == .device) try e.alloc(self.pcs_words.len) else try e.slab.field(.opaque_words, 2);
        try self.pcs.enqueueOpening(sym.pcs, e, self.pinned, try e.slab.field(.opaque_words, 1), pcs_out);
        trace("s2.pcs", self.ordinal);
        e.free(comp.coefficients);
        e.free(inter.coefficients);
        e.free(main.coefficients);
        if (self.fault == .absent_claim) {
            // A nonzero word in the absent claim (classic) / the local closing
            // group (delegated): truth_status must reject it.
            const target = if (c.kind == .classic) try claims.slice(32, 1) else try zero.slice(0, 1);
            try check(sym.memset(ctx, target.ptr, 1, 1));
        }
        // Device acceptance checks (one Verdict word each).
        try statusVerdict(sym, e, status, claims, if (c.zero_count != 0) zero else null, .{ .n_status = @intCast(status.words), .n_claims = c.claim_count, .n_zero = c.zero_count, .classic = @intFromBool(c.kind == .classic), .check = @intFromEnum(G.Check.truth_status) }, self.verdicts.truth_status orelse try own.slice(0, 1));
        // Expected roots: the class FIXED root (staged), then the stage-1 MAIN
        // root (device) or, without one, the replay itself (host-compared).
        const expected = try staged.slice(t.roots, 16);
        try check(sym.copy_d2d(ctx, expected.ptr + 8, (stage1_root orelse try roots.slice(8, 8)).ptr, 32));
        try check(sym.root_match(ctx, 0, roots.ptr, expected.ptr, 2, @intFromEnum(G.Check.root_match), (self.verdicts.root_match orelse try own.slice(1, 1)).ptr));
        self.channel_steps = e.channel.step;
        try e.channel.snapshot(e.slab, (try self.layout.get(.channel_state, 0)).offset);
        const cursor = e.channel.step + @intFromBool(self.fault == .channel_cursor);
        try check(sym.order(ctx, 0, e.channel.stateBuffer().ptr, cursor, e.channel.expectedChain(e.channel.step), (self.verdicts.channel_order orelse try own.slice(2, 1)).ptr));
        // The launcher reads the expectation on the host (by value into the kernel).
        const pcs_verdict = if (self.encode == .host) self.verdicts.pcs_status orelse try own.slice(Schema.Own.pcs_status, 1) else try own.slice(Schema.Own.pcs_truth, 1);
        try check(sym.pcs_status(ctx, 0, pcs_out.ptr, pcs_out.words, roots.ptr, &self.expect, pcs_verdict.ptr));
        trace("s2.checks", self.ordinal);
        if (self.encode != .host) try self.enqueueDevice(e, pcs_out, own);
        if (self.leaf_program) |program| {
            const region = self.encoded orelse return error.NativeLeafRegionBounds;
            const leaf_device = self.leaf_device orelse return error.NativeLeafProgramNotWarmed;
            const sources_: [6]?LF.Buffer = .{ null, null, .{ .ptr = digest.ptr, .words = digest.words }, null, .{ .ptr = claims.ptr, .words = claims.words }, .{ .ptr = pcs_out.ptr, .words = pcs_out.words } };
            const verdict = self.verdicts.encode_bounds orelse return error.NativeLeafRegionBounds;
            try LF.enqueue(sym.leaf orelse return error.MissingNativeLeafEncoder, sym.copy_d2d, ctx, program, .{ .ptr = leaf_device.ptr, .words = leaf_device.words }, sources_, .{ .ptr = region.ptr, .words = region.words }, verdict.ptr, @as(u32, @intFromEnum(G.Check.encode_bounds)) << 16);
        }
        trace("s2.device_encode", self.ordinal);
        if (self.encode == .device) e.free(pcs_out);
        try self.span.mark(self.timing, true, e.stream());
    }

    /// Device OODS constraint check + device encoder (gn-truth), after the
    /// PCS and its status check. Verdicts: truth_oods, encode_bounds, and
    /// pcs_status = merge(truth_pcs_status, encoder pcs_status).
    fn enqueueDevice(self: *Stage2, e: *api.Enqueue, pcs_out: api.DeviceBuffer, own: api.DeviceBuffer) !void {
        const c = self.class;
        const sym = self.sym;
        const ctx = e.ctx();
        const osym = sym.oods.?;
        const esym = sym.encode.?;
        try self.device_span.mark(self.timing, false, e.stream());
        switch (self.fault) {
            .oods_sample, .oods_composition, .encode_value => {
                const word = try self.faultWord();
                try check(sym.memset(ctx, pcs_out.ptr + word, if (self.fault == .encode_value) 0xff else 0x01, 4));
            },
            else => {},
        }
        // OODS constraint check over the PCS samples and the gathered parameters.
        const scratch = try e.alloc(c.oods.scratch_words);
        try check(sym.memset(ctx, scratch.ptr + c.oods.words[TO.H.partials_at], 0, TO.partial_words * TO.max_roles * 4));
        const table = (self.composition.table_device orelse return error.NativeCompositionNotStaged);
        var params: [TO.max_roles]?api.DeviceBuffer = @splat(null);
        for (self.composition.roles, 0..) |rp, i| params[i] = try table.slice(rp.t_params, rp.spec.parameters.len);
        try self.oods_span.mark(self.timing, false, e.stream());
        try TO.enqueue(&osym, ctx, &c.oods, .{
            .desc = self.oods_program orelse return error.TruthJobNotStaged,
            .pcs = pcs_out,
            .trees = 4,
            .params = params,
            .alpha = try e.slab.field(.opaque_words, 0),
            .point = try e.slab.field(.opaque_words, 1),
            .scratch = scratch,
            .verdict = self.verdicts.truth_oods orelse try own.slice(Schema.Own.truth_oods, 1),
            .diag = try e.slab.field(.opaque_words, 5),
        });
        try self.oods_span.mark(self.timing, true, e.stream());
        e.free(scratch);
        // Encoder: WP.encodePhysical bytes into the encoded region.
        const escratch = try e.alloc(NE.scratch_words);
        var region = self.encoded orelse try e.slab.field(.opaque_words, 6);
        if (self.fault == .encode_capacity) region = try region.slice(0, 2);
        var enc = NE.Encoder{ .sym = &esym, .program = self.encode_program orelse return error.TruthJobNotStaged, .host = &c.encode, .pcs = pcs_out, .scratch = escratch, .pcs_status = try own.slice(Schema.Own.pcs_encoder, 1) };
        try enc.enqueue(ctx, region, self.verdicts.encode_bounds orelse try own.slice(Schema.Own.encode_bounds, 1));
        e.free(escratch);
        try check(sym.merge.?(ctx, 0, (try own.slice(Schema.Own.pcs_truth, 2)).ptr, 2, @intFromEnum(G.Check.pcs_status), (self.verdicts.pcs_status orelse try own.slice(Schema.Own.pcs_status, 1)).ptr));
        try self.device_span.mark(self.timing, true, e.stream());
    }

    /// The PCS-image word a device-encode fault corrupts.
    fn faultWord(self: *const Stage2) !usize {
        const d = self.class.oods.words;
        return switch (self.fault) {
            .oods_sample => blk: {
                const row = d[TO.H.header_words..][0..TO.R.words];
                for (0..row[TO.R.n_nodes]) |i| {
                    const w = d[row[TO.R.nodes_at] + TO.node_words * i ..][0..TO.node_words];
                    if (w[0] == @intFromEnum(TO.Op.input)) break :blk TO.samplesOffset(4) + 8 * @as(usize, w[1]);
                }
                return error.TruthFaultNoInput;
            },
            .oods_composition => TO.samplesOffset(4) + 8 * (@as(usize, d[TO.H.composition_sample]) + 9),
            .encode_value => blk: {
                // native_encode Program tree table, tree 0 record word 4: the
                // PCS offset of tree 0's queried values.
                const p = self.class.encode.words;
                break :blk p[p[@intFromEnum(NE.H.tree_table)] + 4];
            },
            else => error.TruthFaultNotDevice,
        };
    }

    pub fn finish(self: *Stage2, view: api.SlabView) !void {
        var finish_timer = try std.time.Timer.start();
        defer self.finish_ns = finish_timer.read();
        self.span.read(self.timing);
        self.device_span.read(self.timing);
        self.oods_span.read(self.timing);
        if (self.request_slab_only) return;
        @memcpy(&self.roots, try Slab.read(view, .root, 0));
        @memcpy(&self.alpha, try Slab.read(view, .opaque_words, 0));
        const st = try Slab.read(view, .status, 0);
        @memcpy(self.status_words[0..st.len], st);
        const cl = try Slab.read(view, .claims, 0);
        @memcpy(self.claims[0..cl.len], cl);
        @memcpy(&self.oods, try Slab.read(view, .opaque_words, 1));
        if (self.encode != .device) @memcpy(self.pcs_words, try Slab.read(view, .opaque_words, 2));
        const lf = try Slab.read(view, .opaque_words, 3);
        @memcpy(self.local_felts[0..lf.len], lf);
        @memcpy(&self.shared_felts, try Slab.read(view, .opaque_words, 4));
        @memcpy(&self.verdict_words, (try Slab.read(view, .status, 1))[0..verdict_names.len]);
        if (self.encode != .host) {
            @memcpy(&self.oods_diag, try Slab.read(view, .opaque_words, 5));
            if (self.encoded == null) {
                const region = try Slab.read(view, .opaque_words, 6);
                const len: usize = region[0];
                if (len > 4 * (region.len - 1)) return error.TruthEncodedLengthOverrun;
                self.device_bytes = try self.a.dupe(u8, std.mem.sliceAsBytes(region[1..])[0..len]);
            }
        }
        // Own verdict words (request-slab ones are gpu_native.publish's); the
        // device-encode words exist only in the device modes.
        const ran = if (self.encode == .host) 4 else verdict_names.len;
        inline for (verdict_names, 0..) |name, i| {
            if (i < ran and @field(self.verdicts, name) == null and self.verdict_words[i] != G.Verdict.accepted) {
                std.debug.print("GPU_M8_TRUTH_JOB event=rejected ordinal={} check={s} word=0x{x}\n", .{ self.ordinal, name, self.verdict_words[i] });
                return error.DeviceTruthCheckRejected;
            }
        }
        if (self.encode != .device and self.assemble_on_finish) {
            var timer = try std.time.Timer.start();
            try self.assemble();
            self.assemble_ns = timer.read();
            if (self.encode == .check) self.device_equal = std.mem.eql(u8, self.device_bytes, self.bytes) and std.mem.eql(u32, &self.oods_diag, &self.host_oods);
        }
    }

    /// Host assembly (the legacy W.Prover tail): PCS decode, the engine's
    /// OODS constraint check with the device claims/challenges, encodePhysical.
    pub fn assemble(self: *Stage2) !void {
        const c = self.class;
        const a = self.a;
        var root_bytes: [4][32]u8 = undefined;
        for (&root_bytes, 0..) |*r, tr| for (0..8) |i| std.mem.writeInt(u32, r[4 * i ..][0..4], self.roots[8 * tr + i], .little);
        var decoded = try self.pcs.decode(a, self.pcs_words, &root_bytes);
        defer decoded.proof.deinit(a);
        const claims = try a.alloc(O, c.claim_count);
        errdefer a.free(claims);
        for (claims, 0..) |*v, i| v.* = try felt(self.claims[8 * i ..][0..8]);
        const shared_values = try felts(X.shared_felts, &self.shared_felts);
        const shared = try X.sharedFrom(&shared_values);
        var classic: [3]T.Role.Component = undefined;
        var delegated: T.V3Role.Component = undefined;
        var handles: [3]CP.ComponentProver = undefined;
        const provers_slice: []const CP.ComponentProver = if (c.kind == .classic) blk: {
            const local_values = try felts(X.classic_felts, &self.local_felts);
            const local = try X.classicFrom(&local_values);
            const kinds = [3]T.Role.Kind{ .keccak, .chi, .xor5 };
            var offsets: [3]usize = .{ 0, 0, 0 };
            for (&classic, kinds, 0..) |*comp, kd, i| {
                const r = c.roles[i];
                comp.* = .{ .kind = kd, .log_size = r.interaction.log, .calls = if (i == 0) self.calls else 0, .first_id = if (i == 0) self.first_id else 1, .keccak_policy = c.keccakPolicy(), .local = local, .shared = shared, .claim = claims[i], .global_claim = if (i == 0) claims[3] else O.zero(), .split = 2 };
                comp.offsets = offsets;
                for (comp.widths(), 0..) |w, tr| offsets[tr] += w;
                handles[i] = comp.asProverComponent();
            }
            break :blk handles[0..3];
        } else blk: {
            delegated = .{ .truth = K.withSpan(c.truth, self.calls, self.first_id), .wire = shared.wire, .bytes = try felt(self.local_felts[0..8]), .claim = claims[0] };
            handles[0] = delegated.asProverComponent();
            break :blk handles[0..1];
        };
        const provers = CP.ComponentProvers{ .components = provers_slice, .n_preprocessed_columns = c.fixed_logs.len };
        var view = try provers.componentsView(a);
        defer view.deinit(a);
        const oods = D.Point{ .x = try felt(self.oods[0..8]), .y = try felt(self.oods[8..16]) };
        const proof = WP.Proof{ .commitment_scheme_proof = decoded.proof };
        const extracted = proof.extractCompositionOodsEvalWithSplit(oods, c.mask_log + c.split, c.split) orelse return error.InvalidStructure;
        const expected_eval = try view.evalCompositionPolynomialAtPointWithWorkCapture(a, oods, &decoded.proof.sampled_values, try felt(&self.alpha), c.mask_log, c.mask_log + c.split, c.split, null);
        @memcpy(self.host_oods[0..8], &X.words(expected_eval));
        @memcpy(self.host_oods[8..16], &X.words(extracted));
        if (!extracted.eql(expected_eval)) return error.ConstraintsNotSatisfied;
        self.bytes = try WP.encodePhysical(a, .{ .commitment_scheme_proof = decoded.proof });
        self.out_claims = claims;
    }
    pub fn abort(_: *Stage2) void {}
    pub fn job(self: *Stage2) api.Job {
        return api.Job.from(Stage2, self);
    }
};

/// Persistent-region key of a class's encode program on a worker.
pub fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

pub fn trace(comptime what: []const u8, ordinal: u32) void {
    const on = struct {
        var value: ?bool = null;
    };
    if (on.value == null) on.value = false;
    if (on.value.?) std.debug.print("GPU_M8_TRUTH_TRACE ordinal={} at={s} host_ns={}\n", .{ ordinal, what, std.time.nanoTimestamp() });
}

pub fn feltWords(n: u32) usize {
    return @as(usize, n) * 8;
}

pub fn mainInputs(class: *const K.Class, buffer: api.DeviceBuffer, out: []C.Input) !void {
    if (out.len != class.main_logs.len or buffer.words < class.mainEvalWords()) return error.TruthMainShape;
    var at: usize = 0;
    for (class.main_logs, out) |l, *input| {
        input.* = .{ .device = buffer.ptr + at };
        at += @as(usize, 1) << @intCast(l);
    }
}

pub fn statusVerdict(sym: *const Schema.Symbols, e: *api.Enqueue, status: api.DeviceBuffer, claims: ?api.DeviceBuffer, zero: ?api.DeviceBuffer, c: Schema.StatusConstants, verdict: api.DeviceBuffer) !void {
    try check(sym.status(e.ctx(), 0, status.ptr, if (claims) |b| b.ptr else null, if (zero) |b| b.ptr else null, &c, verdict.ptr));
}

pub fn placeholders(a: std.mem.Allocator, n: usize) ![]C.Input {
    const inputs = try a.alloc(C.Input, n);
    @memset(inputs, .{ .device = @ptrFromInt(@alignOf(u32)) });
    return inputs;
}

pub fn tableOf(c: *const K.Class) Table {
    var t = Table{};
    var n: usize = 0;
    t.local = n;
    n += X.stagedWords(c.localScript());
    t.shared = n;
    n += X.stagedWords(X.shared);
    n = std.mem.alignForward(usize, n, 8);
    t.consts = n;
    n += feltWords(c.stagedFelts());
    t.header = n;
    n += 3;
    for (c.roles, 0..) |r, i| {
        t.programs[2 * i] = n;
        n += 2 * r.interaction.program.len;
        t.programs[2 * i + 1] = n;
        n += 2 * r.composition_program.len;
    }
    t.roots = n;
    n += 16;
    t.expect = n;
    n += @sizeOf(Schema.PcsExpect) / 4;
    t.host_digest = n;
    n += 8;
    t.host_root = n;
    n += 8;
    t.words = n;
    return t;
}

pub fn fillTable(c: *const K.Class, pcs: *const NP.PcsJob, t: Table, calls: u32, first_id: u32, out: []u32) !void {
    if (out.len < t.words) return error.TruthStageTableTooSmall;
    @memset(out[0..t.words], 0);
    try X.stageWords(c.localScript(), out[t.local..]);
    try X.stageWords(X.shared, out[t.shared..]);
    var spans: [3]P.Span = undefined;
    for (c.roles, 0..) |r, i| spans[i] = r.span;
    spans[0] = .{ .calls = calls, .first_id = first_id }; // the crypto role carries the request span
    try P.stageConstants(spans[0..c.roles.len], out[t.consts..]);
    const H = @import("native_stage2.zig").manifest_header;
    out[t.header] = H[0];
    out[t.header + 1] = H[1];
    out[t.header + 2] = c.claim_count;
    for (c.roles, 0..) |r, i| for ([2][]const P.Entry{ r.interaction.program, r.composition_program }, 0..) |prog, j| {
        try P.validate(prog, c.bounds());
        for (prog, 0..) |entry, k| {
            out[t.programs[2 * i + j] + 2 * k] = entry.source;
            out[t.programs[2 * i + j] + 2 * k + 1] = entry.index;
        }
    };
    for (0..8) |i| out[t.roots + i] = std.mem.readInt(u32, c.fixed_root[4 * i ..][0..4], .little);
    const expect = Schema.pcsExpect(pcs);
    @memcpy(out[t.expect..][0 .. @sizeOf(Schema.PcsExpect) / 4], std.mem.bytesAsSlice(u32, std.mem.asBytes(&expect)));
}

pub fn felt(words: []const u32) !O {
    if (words.len < 8) return error.InvalidFelt;
    var limbs: [8]core.fields.m31.M31 = undefined;
    for (&limbs, words[0..8]) |*l, w| {
        if (w >= core.fields.m31.Modulus) return error.NoncanonicalFelt;
        l.* = core.fields.m31.M31.fromCanonical(w);
    }
    return O.fromM31Array(limbs);
}

pub fn felts(comptime n: usize, words: []const u32) ![n]O {
    var out: [n]O = undefined;
    for (&out, 0..) |*v, i| v.* = try felt(words[8 * i ..][0..8]);
    return out;
}

pub fn enqueueWitness(class: *const K.Class, sym: *const Schema.Symbols, e: *api.Enqueue, compact: api.DeviceBuffer, main: api.DeviceBuffer, status: [*]u32, calls: u32, first_id: u32) !?api.DeviceBuffer {
    const ctx = e.ctx();
    const rows = @as(usize, 1) << @intCast(class.log);
    const main_words = class.main_width * rows;
    var bytes: ?api.DeviceBuffer = null;
    switch (class.witness) {
        .keccak => |k| {
            const chi = main.ptr + main_words;
            const xor5 = chi + (@as(usize, 1) << @intCast(k.chi_log));
            const packet = Schema.KeccakPacket{ .inputs = compact.ptr, .main = main.ptr, .chi = chi, .xor5 = xor5, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log, .policy = k.policy };
            try check((sym.keccak orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
        .sha256 => {
            const packet = Schema.ShaPacket{ .inputs = compact.ptr, .main = main.ptr, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log };
            try check((sym.sha orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
        .arith256_mod => {
            const b = try e.alloc(256);
            bytes = b;
            const packet = Schema.ArithPacket{ .inputs = compact.ptr, .main = main.ptr, .byte_counts = b.ptr, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log };
            try check((sym.arith orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
        .secp => |s| {
            const b = try e.alloc(256);
            bytes = b;
            const packet = Schema.SecpPacket{ .inputs = compact.ptr, .main = main.ptr, .byte_counts = b.ptr, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log, .kind = s.kind };
            try check(((if (s.curve) sym.curve else sym.secp) orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
    }
    return bytes;
}
