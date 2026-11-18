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
    reserve_words: ?u64 = null,
    require_borrowed_trees: bool = false,

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
        // Unsupported geometry retains the caller's historical reservation.
        self.reserve_words = try reserveForSections(a, self.prepared.section_storage, false);
        return self;
    }
    /// Outer-only contract: checked again against REAL bound pointers before
    /// enqueue; one contiguous kind1 transfer/tree is borrowed by JobOwner.
    pub fn requireBorrowedTrees(self: *PcsJob, a: std.mem.Allocator) !void {
        self.reserve_words = try reserveForSections(a, self.prepared.section_storage, true);
        self.require_borrowed_trees = self.reserve_words != null;
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
    /// `e` is the job's api.Enqueue: only ctx(), alloc(words) and free(buffer)
    /// are used. `pinned` is job-lifetime pinned memory from Stager.pinned.
    pub fn enqueue(self: *PcsJob, symbols: Symbols, e: anytype, pinned: []u32, io: Io) !void {
        if (pinned.len < self.plan.ingress_words or io.output_words != self.plan.output_words or io.point == null) return error.InvalidPcsJobSpan;
        if (self.require_borrowed_trees) try checkBorrowedTrees(self.prepared.coefficients, self.prepared.section_storage[7]);
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

fn checkBorrowedTrees(columns: []const Native.Column, trees: []const u32) !void {
    if (trees.len % 6 != 0) return error.PcsJobRequiresContiguousTrees;
    for (0..trees.len / 6) |t| {
        const d = trees[t * 6 ..][0..6];
        if (d[1] == 0 or @as(u64, d[0]) + d[1] > columns.len) return error.PcsJobRequiresContiguousTrees;
        const first = columns[d[0]];
        var address = @intFromPtr(first.words orelse return error.PcsJobRequiresContiguousTrees);
        for (columns[d[0]..][0..d[1]]) |c| {
            if (c.kind != 1 or c.context_token != first.context_token or c.generation != first.generation or @intFromPtr(c.words orelse return error.PcsJobRequiresContiguousTrees) != address) return error.PcsJobRequiresContiguousTrees;
            address = std.math.add(usize, address, std.math.mul(usize, @intCast(c.count), 4) catch return error.PcsJobRequiresContiguousTrees) catch return error.PcsJobRequiresContiguousTrees;
        }
    }
}

// Upper bound on EVERY JobOwner::plane allocation in jobs/pcs_enqueue.cu.
// Count retired blocks again: its best-fit cache retains reservations until exit.
// No reuse credit; coefficient borrowing requires the checked outer contract.
// Only the fixed imported beta1 outer schedule is admitted here.
fn reserveForSections(a: std.mem.Allocator, s: [17][]const u32, borrowed_trees: bool) !?u64 {
    const h = s[0];
    if ((h.len != 24 and h.len != 28) or h[0] != 0x52564d53 or h[21] != 1 or h[5] != 1 or h[4] > 28) return null;
    const sc: u64 = h[8];
    const tc: u64 = h[9];
    const gc: u64 = h[10];
    const nt: usize = h[12];
    const layers: usize = h[14];
    const queries: u64 = h[6];
    if (sc == 0 or sc > 65536 or tc == 0 or tc > 65536 or gc == 0 or gc > 1024 or nt == 0 or nt > 4 or layers > 28 or s[3].len != sc * 4 or s[5].len != gc * 8 or s[6].len != @as(u64, h[11]) * 8 or s[7].len != nt * 6 or s[13].len != layers * 8) return null;
    const Bound = struct {
        words: u64 = 64, // enqueueOpening's separately live OODS draw plane.
        fn add(b: *@This(), n: u64) void {
            if (n != 0) b.words += std.mem.alignForward(u64, n, 64);
        }
    };
    var b = Bound{};
    var counts: [4]u64 = undefined;
    for (&counts, 0..) |*v, i| v.* = h[15 + i] | (if (h.len == 28) @as(u64, h[24 + i]) << 32 else 0);
    for (counts) |n| if (n > @as(u64, 1) << 48) return null;
    // Possible per-tree coefficient copies (even though contiguous device
    // sources are borrowed), then combined DEEP arena + descriptor packets.
    for (0..nt) |t| {
        const d = s[7][t * 6 ..][0..6];
        if (@as(u64, d[0]) + d[1] > sc or d[4] > h[4]) return null;
        var words: u64 = 0;
        for (d[0]..d[0] + d[1]) |c| {
            const log = s[3][4 * c + 3];
            if (log > 28) return null;
            words += @as(u64, 1) << @intCast(log);
        }
        if (!borrowed_trees) b.add(words);
        b.add(@as(u64, d[1]) * queries);
        b.add(queries * d[4] * 8);
    }
    b.add(counts[2] + counts[3] + 6 * sc + 48 * gc);
    var scratch: u64 = 0;
    var max_terms: u64 = 0;
    for (0..@intCast(gc)) |g| {
        const d = s[5][g * 8 ..][0..8];
        if (d[2] > 28 or d[1] <= d[0]) return null;
        const terms: u64 = d[1] - d[0];
        scratch = @max(scratch, (((@as(u64, 1) << @intCast(d[2])) + 1023) / 1024) * terms * 8);
        max_terms = @max(max_terms, terms);
    }
    const rows = @as(u64, 1) << @intCast(h[4]);
    // Every standalone upload/plane at lines408,490–512 and544–545.
    for ([_]u64{ h[19], nt * 8, h[13], @as(u64, h[13]) * 8, sc, 4 * sc, 4 * tc, 8 * gc, 4 * gc, 2 * rows, h[20], 16, 16, (gc + 1) * 16, gc * 224, gc + 1, scratch, scratch, max_terms, tc * 8, 8, tc * 8, gc * 16, 2, rows * 8, 8, queries, 2, 1, 8, 2, 1, 16, layers * 8 }) |n| b.add(n);
    for (0..layers) |i| {
        const d = s[13][i * 8 ..][0..8];
        if (d[0] == 0 or !std.math.isPowerOfTwo(d[0]) or d[1] > 4 or d[2] > d[1] or d[2] > std.math.log2_int(u32, d[0])) return null;
        if (i != 0) b.add(@as(u64, d[0]) * 8);
        b.add((2 * (@as(u64, d[0]) >> @intCast(d[2])) - 1) * 8);
        b.add(8);
        b.add((queries << @intCast(d[1])) * 8);
        b.add((queries << @intCast(d[1] - d[2])) * (std.math.log2_int(u32, d[0]) - d[2]) * 8);
    }
    // Same shared streaming planner as the C++ port; always use legacy
    // 24-word banks, which also upper-bound the compact-eager variant.
    const Stream = @import("../trace_stream_plan.zig");
    var stream_words: u64 = 0;
    const column_rows = try a.alloc(u32, @intCast(sc));
    defer a.free(column_rows);
    for (0..nt) |t| {
        const d = s[7][t * 6 ..][0..6];
        if (d[1] == 0) return null;
        var n: usize = 0;
        for (d[2]..d[2] + d[3]) |g| {
            if (g >= h[11]) return null;
            const v = s[6][g * 8 ..][0..8];
            if (v[3] > 28 or n + v[5] > column_rows.len) return null;
            @memset(column_rows[n..][0..v[5]], @as(u32, 1) << @intCast(v[3]));
            n += v[5];
        }
        if (n != d[1]) return null;
        var plan = try Stream.plan(a, column_rows[0..n], Stream.default_chunk_words);
        defer plan.deinit(a);
        const final_bank = plan.calls[plan.calls.len - 1].out_bank;
        plan.bank_words[final_bank] = @max(plan.bank_words[final_bank], Stream.treeWords(@as(u32, 1) << @intCast(d[4])));
        stream_words = @max(stream_words, plan.scratchWords());
    }
    b.add(stream_words);
    return b.words;
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

test "PCS reserve derives rounded allocation upper bound from imported geometry" {
    const a = std.testing.allocator;
    var h = [_]u32{0} ** 24;
    h[0] = 0x52564d53;
    h[1] = 2;
    h[4] = 5;
    h[5] = 1;
    h[6] = 2;
    h[8] = 1;
    h[9] = 1;
    h[10] = 1;
    h[11] = 1;
    h[12] = 1;
    h[13] = 1;
    h[15] = 16;
    h[17] = 128;
    h[18] = 256;
    h[14] = 1;
    h[19] = 16;
    h[20] = 16;
    h[21] = 1;
    var sections: [17][]const u32 = @splat(&.{});
    sections[0] = &h;
    sections[3] = &.{ 0, 0, 0, 4 };
    sections[5] = &.{ 0, 1, 4, 5, 0, 0, 0, 0 };
    sections[6] = &.{ 0, 0, 4, 5, 0, 1, 0, 16 };
    sections[7] = &.{ 0, 1, 0, 1, 5, 0 };
    sections[13] = &.{ 32, 4, 4, 0, 0, 0, 0, 0 };
    const words = (try reserveForSections(a, sections, false)).?;
    // Independent sum of rounded C++ plane calls for this tiny geometry.
    try std.testing.expectEqual(@as(u64, 4352), words);
    try std.testing.expectEqual(@as(?u64, 4288), try reserveForSections(a, sections, true));
    try std.testing.expectEqual(@as(u64, 0), words % 64);
    try std.testing.checkAllAllocationFailures(a, struct {
        fn check(alloc: std.mem.Allocator, descriptors: [17][]const u32) !void {
            _ = try reserveForSections(alloc, descriptors, false);
        }
    }.check, .{sections});
    h[5] = 2;
    try std.testing.expectEqual(@as(?u64, null), try reserveForSections(a, sections, false));
    h[5] = 1;
    h[1] = 3;
    var wide = [_]u32{0} ** 28;
    @memcpy(wide[0..24], &h);
    wide[24] = 1 << 17;
    sections[0] = &wide;
    try std.testing.expectEqual(@as(?u64, null), try reserveForSections(a, sections, false));
}

test "PCS reserve refuses an absent descriptor" {
    const sections: [17][]const u32 = @splat(&.{});
    try std.testing.expectEqual(@as(?u64, null), try reserveForSections(std.testing.allocator, sections, false));
}

test "PCS borrowed tree contract rejects gaps host columns and address overflow" {
    var storage: [32]u32 = undefined;
    var columns = [_]Native.Column{
        .{ .kind = 1, .coefficient_log = 4, .words = &storage, .count = 16 },
        .{ .kind = 1, .coefficient_log = 4, .words = storage[16..].ptr, .count = 16 },
    };
    const trees = [_]u32{ 0, 2, 0, 0, 5, 0 };
    try checkBorrowedTrees(&columns, &trees);
    columns[1].words = storage[17..].ptr;
    try std.testing.expectError(error.PcsJobRequiresContiguousTrees, checkBorrowedTrees(&columns, &trees));
    columns[1].words = storage[16..].ptr;
    columns[1].kind = 0;
    try std.testing.expectError(error.PcsJobRequiresContiguousTrees, checkBorrowedTrees(&columns, &trees));
    columns[1].kind = 1;
    columns[0].count = std.math.maxInt(u64);
    try std.testing.expectError(error.PcsJobRequiresContiguousTrees, checkBorrowedTrees(&columns, &trees));
}
