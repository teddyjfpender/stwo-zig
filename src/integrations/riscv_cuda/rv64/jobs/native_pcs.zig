//! Enqueue-only native PCS for the M8 job runtime (shared by native and outer jobs).
//!
//! Phase split (spec §3.1/§3.5):
//!   prepare (pre-stage/stage, host): the unchanged legacy 17-section framing,
//!     built with a PLACEHOLDER OODS point and seed. Every section except the
//!     seed (1), the imported point (2) and the expected roots (15) is a pure
//!     function of the class geometry and mask offsets (tested below), so it is
//!     challenge independent and can be built before the proof's transcript.
//!   enqueue (exec stream): `stwo_rv64_pcs_job_enqueue_v1` reads the seed and
//!     the OODS base point from device memory and writes the legacy
//!     Result.words layout into a slab span. No sync, no D2H.
//!   finish (after the worker's single wait): `decode` is the existing
//!     hybrid_pcs.decodeWords (status/step/chain checks) plus the root check
//!     the legacy pipeline did on the host. Proof bytes are therefore produced
//!     by the same assembler as today.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Export = @import("../pcs_request_export.zig");
const Decode = @import("../hybrid_pcs.zig");
const Native = @import("../pcs_native_abi.zig");

/// Mirrors NAT/rv64/jobs/pcs_enqueue.h.
pub const Plan = extern struct {
    output_words: u64 = 0,
    ingress_words: u64 = 0,
    trees: u32 = 0,
    layers: u32 = 0,
    queries: u32 = 0,
    steps: u32 = 0,
    samples: u32 = 0,
    rolling: u32 = 0,
    reserved: [2]u32 = @splat(0),
};
pub const Memory = extern struct {
    user: ?*anyopaque,
    alloc: *const fn (?*anyopaque, u64) callconv(.c) ?[*]u32,
    release: *const fn (?*anyopaque, [*]u32, u64) callconv(.c) void,
    pinned: ?[*]u32,
    pinned_words: u64,
};
pub const Io = extern struct {
    /// Device digest[8], draws: the first nine words of a 16-word channel state.
    seed: [*]const u32,
    /// Device OODS BASE point x[8], y[8] (see `Prepared.base_shift`), imported requests only.
    point: ?[*]const u32 = null,
    /// Optional cached device domain (2 << lifting_log words); null builds it in the job arena.
    domain: ?[*]const u32 = null,
    output: [*]u32,
    output_words: u64,
};
comptime {
    if (@sizeOf(Plan) != 48 or @sizeOf(Memory) != 40 or @sizeOf(Io) != 40) @compileError("PCS job ABI changed");
}
pub const PlanFn = *const fn (*const Native.Request, *Plan) callconv(.c) c_int;
pub const EnqueueFn = *const fn (*anyopaque, u32, *const Native.Request, *const Memory, *const Io) callconv(.c) c_int;
pub const ErrorFn = *const fn () callconv(.c) [*:0]const u8;
/// NAT/rv64/jobs/oods_points.h
pub const OodsFn = *const fn (*anyopaque, u32, [*]const u32, u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
pub const Symbols = struct {
    plan: PlanFn,
    enqueue: EnqueueFn,
    last_error: ErrorFn,
    oods: OodsFn,
    pub fn load(addon: *std.DynLib) !Symbols {
        return .{
            .plan = addon.lookup(PlanFn, "stwo_rv64_pcs_job_plan_v1") orelse return error.MissingPcsJobSymbol,
            .enqueue = addon.lookup(EnqueueFn, "stwo_rv64_pcs_job_enqueue_v1") orelse return error.MissingPcsJobSymbol,
            .last_error = addon.lookup(ErrorFn, "stwo_rv64_pcs_job_error_v1") orelse return error.MissingPcsJobSymbol,
            .oods = addon.lookup(OodsFn, "stwo_rv64_job_oods_points_v1") orelse return error.MissingPcsJobSymbol,
        };
    }
};
/// Words of the OODS slab field written by `enqueueOpening`: oods x[8] y[8],
/// base x[8] y[8], status (0 = ok).
pub const oods_field_words = 33;

/// Placeholder device column for `prepare` (bound at enqueue by `bindColumn`).
pub fn placeholderColumn(log_size: u32) D.Column {
    return .{ .log_size = log_size, .device = .{ .words = @ptrFromInt(0x1000), .count = @as(u64, 1) << @intCast(log_size), .context_token = 1, .generation = 1 } };
}

/// Generic, non-degenerate placeholder OODS point used only to build the
/// challenge-independent framing; never sampled, never mixed.
pub fn placeholderPoint() !D.Point {
    var limbs: [8]D.M = undefined;
    for (&limbs, 0..) |*limb, i| limb.* = D.M.fromCanonical(@intCast(0x1234567 + 7919 * i));
    return core.circle.secureFieldPointFromRandomSeedCheckedFor(D.O, D.O.fromM31Array(limbs));
}

/// The OODS base point the PCS imports is the FIRST sample point of the
/// request (pcs_request_export: `base = first ps[0]`), i.e. oods + base_shift
/// with an M31 shift fixed by the mask offsets. On device: draw t, then one
/// `stwo_rv64_sample_points_on` recipe {shift.x, shift.y, folds 0, log 1}
/// yields points[0] = oods and points[1] = base (the existing kernel).
pub fn baseShift(request: D.Request, oods: D.Point) !core.circle.CirclePointM31 {
    for (request.points.items) |tree| for (tree) |column| if (column.len != 0) {
        const p = column[0].sub(oods);
        const x = p.x.toM31Array();
        const y = p.y.toM31Array();
        for (x[1..]) |v| if (!v.isZero()) return error.UnsupportedDevicePcsPointOffset;
        for (y[1..]) |v| if (!v.isZero()) return error.UnsupportedDevicePcsPointOffset;
        return .{ .x = x[0], .y = y[0] };
    };
    return error.EmptyDevicePcsSamples;
}

pub const PcsJob = struct {
    prepared: Export.Prepared,
    descriptor: Native.Request,
    plan: Plan,
    base_shift: core.circle.CirclePointM31,

    /// Host framing for one proof. `request.points` are mask points at
    /// `oods_placeholder`; `request.trees[].root` may be placeholders.
    pub fn prepare(a: std.mem.Allocator, symbols: Symbols, request: D.Request, oods_placeholder: D.Point, wide_framing: bool) !PcsJob {
        var prepared = try Export.prepareRequestWithFraming(a, request, D.Channel.init(), null, wide_framing);
        errdefer prepared.deinit(a);
        if (prepared.section_storage[0].len < 22 or prepared.section_storage[0][21] != 1) return error.PcsJobRequiresImportedPoint;
        var self = PcsJob{ .prepared = prepared, .descriptor = undefined, .plan = .{}, .base_shift = try baseShift(request, oods_placeholder) };
        self.descriptor = self.prepared.descriptor();
        if (symbols.plan(&self.descriptor, &self.plan) != 0) {
            std.debug.print("GPU_PCS_JOB_PLAN error={s}\n", .{symbols.last_error()});
            return error.PcsJobPlanFailed;
        }
        return self;
    }
    /// Bind tree `tree`, ORIGINAL column `original` to its device coefficient
    /// words (a job-arena view, e.g. native_commit.Committed.column). The
    /// request given to `prepare` carries placeholder device columns: their
    /// addresses exist only at enqueue. An unbound placeholder fails the PCS's
    /// context-custody check (fail closed).
    pub fn bindColumn(self: *PcsJob, tree: usize, original: usize, words: [*]const u32) !void {
        const trees = self.prepared.metadata.shape.trees;
        if (tree >= trees.len) return error.InvalidPcsColumn;
        var base: usize = 0;
        for (trees[0..tree]) |t| base += t.sorted_to_original.len;
        for (trees[tree].sorted_to_original, 0..) |o, k| if (o == original) {
            self.prepared.coefficients[base + k].kind = 1;
            self.prepared.coefficients[base + k].words = words;
            return;
        };
        return error.InvalidPcsColumn;
    }
    pub fn deinit(self: *PcsJob, a: std.mem.Allocator) void {
        self.prepared.deinit(a);
        self.* = undefined;
    }
    pub fn outputWords(self: *const PcsJob) u64 {
        return self.plan.output_words;
    }
    pub fn ingressWords(self: *const PcsJob) u64 {
        return self.plan.ingress_words;
    }
    /// Constructors must model each tree's planned contiguous arena view.
    /// init checks that geometry promise; C++ checks actual CUDA custody when
    /// binding and borrowing. Retired blocks remain charged in this upper bound.
    pub fn borrowedWorkBound(self: *const PcsJob, a: std.mem.Allocator) !struct { words: u64, requested_words: u64 } {
        const Cost = @import("../pcs_allocation_cost.zig");
        var options = try Cost.optionsFromEnv();
        options.phase_retirement = false;
        options.domain_cached = false;
        options.borrowed_trees = @splat(true);
        var allocation = try Cost.init(a, &self.descriptor, options);
        defer allocation.deinit(a);
        return .{ .words = try allocation.jobWords(a), .requested_words = allocation.requested_upper_bytes / 4 };
    }
    /// `e` is the job's api.Enqueue: only ctx(), alloc(words) and free(buffer)
    /// are used. `pinned` is job-lifetime pinned memory from Stager.pinned.
    pub fn enqueue(self: *PcsJob, symbols: Symbols, e: anytype, pinned: []u32, io: Io) !void {
        if (pinned.len < self.plan.ingress_words or io.output_words != self.plan.output_words or io.point == null) return error.InvalidPcsJobSpan;
        const B = Bridge(@TypeOf(e));
        const memory = Memory{ .user = @ptrCast(e), .alloc = B.alloc, .release = B.release, .pinned = pinned.ptr, .pinned_words = pinned.len };
        // Worker exec contexts have one lane; lane 0 is the job's exec stream.
        if (symbols.enqueue(e.ctx(), 0, &self.descriptor, &memory, &io) != 0) {
            std.debug.print("GPU_PCS_JOB_ENQUEUE error={s}\n", .{symbols.last_error()});
            return error.PcsJobEnqueueFailed;
        }
    }
    /// The native opening tail on the job's device transcript, after the
    /// composition root was mixed: draw the OODS felt (one channel step, as
    /// host randomSecureFieldPointFor), build the OODS and base points on
    /// device, then the PCS seeded from the channel state. `oods_out` is a slab
    /// field of `oods_field_words` (finish's constraint check needs the point);
    /// `pcs_out` a slab field of `outputWords()`. The PCS keeps its own
    /// transcript state (as today); the proof ends after it, so `e.channel` is
    /// not advanced past the OODS draw.
    pub fn enqueueOpening(self: *PcsJob, symbols: Symbols, e: anytype, pinned: []u32, oods_out: anytype, pcs_out: anytype) !void {
        if (oods_out.words < oods_field_words) return error.InvalidPcsJobSpan;
        const t = try e.alloc(8);
        defer e.free(t);
        try e.channel.drawSecureFelts(1, t);
        if (symbols.oods(e.ctx(), 0, t.ptr, self.base_shift.x.v, self.base_shift.y.v, oods_out.ptr, oods_out.ptr + 32) != 0) return error.CudaEnqueueFailed;
        const state = e.channel.stateBuffer();
        try self.enqueue(symbols, e, pinned, .{ .seed = state.ptr, .point = oods_out.ptr + 16, .output = pcs_out.ptr, .output_words = pcs_out.words });
    }
    /// finish(): slab words → native proof containers + post-PCS channel.
    /// `expected_roots` are the tree roots committed earlier in this proof
    /// (FIXED, MAIN, INTER, composition), read from the slab.
    pub fn decode(self: *const PcsJob, a: std.mem.Allocator, words: []const u32, expected_roots: []const [32]u8) !Decode.Decoded {
        try checkRoots(words, expected_roots);
        return Decode.decodeWords(a, self.prepared.metadata.shape, words);
    }
};

/// The legacy pipeline compared PCS-rebuilt tree roots against section 15 on
/// the host; the job path compares them against the committed roots in finish.
pub fn checkRoots(words: []const u32, expected_roots: []const [32]u8) !void {
    if (words.len < 31 + expected_roots.len * 8 or words[7] != expected_roots.len) return error.InvalidGpuPcsProof;
    for (expected_roots, 0..) |root, t| for (0..8) |i| {
        if (words[31 + t * 8 + i] != std.mem.readInt(u32, root[i * 4 ..][0..4], .little)) return error.NativePcsTreeRootMismatch;
    };
}

fn Bridge(comptime EnqueuePtr: type) type {
    const E = @typeInfo(EnqueuePtr).pointer.child;
    const Buffer = @typeInfo(@TypeOf(E.free)).@"fn".params[1].type.?;
    return struct {
        fn alloc(user: ?*anyopaque, words: u64) callconv(.c) ?[*]u32 {
            const e: *E = @ptrCast(@alignCast(user orelse return null));
            const buffer = e.alloc(@intCast(words)) catch |err| {
                std.debug.print("GPU_PCS_JOB_ALLOC_FAILED words={} error={s}\n", .{ words, @errorName(err) });
                return null;
            };
            return buffer.ptr;
        }
        fn release(user: ?*anyopaque, ptr: [*]u32, words: u64) callconv(.c) void {
            const e: *E = @ptrCast(@alignCast(user orelse return));
            e.free(Buffer{ .ptr = ptr, .words = @intCast(words) });
        }
    };
}

// ---------------------------------------------------------------------------
// Pure-host tests (no GPU, no addon).

const M = D.M;
const Point = D.Point;
fn testRequest(trees: []D.Tree, forest: [][][]Point, beta: u32) D.Request {
    return .{ .config = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = beta, .log_last_layer_degree_bound = 0, .n_queries = 2, .fold_step = 2 } }, .lifting_log_size = 4 + beta, .trees = trees, .points = core.pcs.TreeVec([][]Point).initOwned(forest) };
}
test "PCS framing is challenge independent except seed, imported point and roots" {
    const a = std.testing.allocator;
    var coeff8 = [_]M{M.zero()} ** 8;
    var coeff16 = [_]M{M.zero()} ** 16;
    const step = core.poly.circle.canonic.CanonicCoset.new(4).coset().step;
    const shift = Point{ .x = D.O.fromBase(step.x), .y = D.O.fromBase(step.y) };
    var oods_points: [2]Point = .{ try placeholderPoint(), try core.circle.secureFieldPointFromRandomSeedCheckedFor(D.O, D.O.fromBase(M.fromCanonical(7))) };
    var prepared: [2]Export.Prepared = undefined;
    var shifts: [2]core.circle.CirclePointM31 = undefined;
    for (&oods_points, &prepared, &shifts) |oods, *out, *base_shift| {
        // Column masks: none, {0}, {-1, 0}: the first sample is shifted, so the
        // imported base point is NOT the OODS point itself.
        var samples0 = [_]Point{};
        var samples1 = [_]Point{ oods.sub(shift), oods };
        var samples2 = [_]Point{oods};
        var points = [_][]Point{ &samples0, &samples1, &samples2 };
        var forest = [_][][]Point{&points};
        var columns = [_]D.Column{ .{ .log_size = 3, .coefficients = &coeff8 }, .{ .log_size = 4, .coefficients = &coeff16 }, .{ .log_size = 4, .coefficients = &coeff16 } };
        var trees = [_]D.Tree{.{ .root = @splat(0), .columns = &columns }};
        const request = testRequest(&trees, &forest, 1);
        out.* = try Export.prepareRequestWithFraming(a, request, D.Channel.init(), null, true);
        base_shift.* = try baseShift(request, oods);
        var offset: usize = 0;
        for (out.coefficients) |*col| {
            col.kind = 1;
            col.words = @as([*]const u32, @ptrFromInt(0x1000)) + offset;
            col.context_token = 1;
            col.generation = 1;
            offset += @intCast(col.count);
        }
        const before = try a.dupe(Native.Column, out.coefficients);
        defer a.free(before);
        const probe = PcsJob{ .prepared = undefined, .descriptor = out.descriptor(), .plan = .{}, .base_shift = base_shift.* };
        try std.testing.expect((try probe.borrowedWorkBound(a)).words > 0);
        try std.testing.expectEqualSlices(Native.Column, before, out.coefficients);
        out.coefficients[out.coefficients.len - 1].words = out.coefficients[out.coefficients.len - 1].words.? + 1;
        try std.testing.expectError(error.InvalidPcsBorrowPromise, probe.borrowedWorkBound(a));
    }
    defer for (&prepared) |*p| p.deinit(a);
    try std.testing.expect(shifts[0].eql(shifts[1]));
    try std.testing.expect(!shifts[0].eql(core.circle.CirclePointM31.zero()));
    for (prepared[0].section_storage, prepared[1].section_storage, 0..) |x, y, i| {
        if (i == 1 or i == 2 or i == 15) continue;
        try std.testing.expectEqualSlices(u32, x, y);
    }
    try std.testing.expect(!std.mem.eql(u32, prepared[0].section_storage[2], prepared[1].section_storage[2]));
    try std.testing.expectEqual(@as(u32, 1), prepared[0].section_storage[0][21]);
}
test "finish root check matches the legacy section-15 comparison" {
    var words = [_]u32{0} ** (31 + 16);
    words[7] = 2;
    var roots = [_][32]u8{ @splat(0), @splat(0) };
    roots[1][4] = 9;
    words[31 + 8 + 1] = 9;
    try checkRoots(&words, &roots);
    words[31] = 1;
    try std.testing.expectError(error.NativePcsTreeRootMismatch, checkRoots(&words, &roots));
    words[7] = 3;
    try std.testing.expectError(error.InvalidGpuPcsProof, checkRoots(&words, &roots));
}
test "enqueue bridge maps api.Enqueue alloc/free onto the C memory callbacks" {
    const Fake = struct {
        pub const Buffer = struct { ptr: [*]u32, words: usize };
        storage: [64]u32 = undefined,
        used: usize = 0,
        freed: usize = 0,
        pub fn alloc(self: *@This(), words: usize) !Buffer {
            if (self.used + words > self.storage.len) return error.OutOfMemory;
            defer self.used += words;
            return .{ .ptr = self.storage[self.used..].ptr, .words = words };
        }
        pub fn free(self: *@This(), b: Buffer) void {
            self.freed += b.words;
        }
    };
    var fake = Fake{};
    const B = Bridge(*Fake);
    const p = B.alloc(&fake, 16) orelse return error.TestUnexpectedResult;
    try std.testing.expect(B.alloc(&fake, 1000) == null);
    B.release(&fake, p, 16);
    try std.testing.expectEqual(@as(usize, 16), fake.freed);
}
