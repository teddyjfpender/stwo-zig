//! Enqueue-only truth interaction witness (GPU-native TruthJob stage 2).
//!
//! A port of the legacy resident stage the truth source calls
//! (rv64/global_stage.zig Context.generateRational / Job.run) for ONE truth
//! role, both layouts (classic keccak roles: inverse_prefix; delegated v3
//! roles: cumulative_batches). Same kernels, inputs and arithmetic:
//!
//!   FIXED/MAIN coefficient ingress (D2D) -> one N2B (forward twiddles)
//!   -> the role's AOT projection stwo_rv64_truth_projection_<id>
//!   -> per group: stwo_rv64_global_pairs_on (+ stwo_rv64_global_cumulative_on)
//!
//! Differences (custody only): no lease, no join, no claim/verdict readback,
//! lane 0 of the job's exec context instead of lane 1 of the owner's, and the
//! projection parameters are a DEVICE buffer (truth_params gather from the
//! device-drawn challenges), never host values. Group claims are copied into
//! the job's claims buffer at the legacy claim positions; the verdict word is
//! the device input of Check.truth_status (truth_ops.cu).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");
const Abi = @import("../abi.zig");
const Prefix = @import("../prefix_plan.zig");
const P = @import("truth_params.zig");

pub const Launch = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, [*]const u32, [*]u32, [*]u32, [*]u32, u32) callconv(.c) c_int;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const CopyD2d = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
const Pairs = *const @TypeOf(Abi.stwo_rv64_global_pairs_on);
pub const Cumulative = extern struct { output: [*]u32, contributions: [*]const u32, stride: u64, row_log: u32, pairs: u32 };
const CumulativeFn = *const fn (*anyopaque, u32, *const Cumulative) callconv(.c) c_int;

pub const Layout = enum { inverse_prefix, cumulative_batches };

pub const Symbols = struct {
    copy_d2d: CopyD2d,
    memset: Memset,
    n2b: N2b,
    pairs: Pairs,
    cumulative: ?CumulativeFn,
    pub fn load(base: *std.DynLib) !Symbols {
        return .{
            .copy_d2d = base.lookup(CopyD2d, "stwo_exec_context_memcpy_d2d_async") orelse return error.MissingTruthInteractionSymbol,
            .memset = base.lookup(Memset, "stwo_exec_context_memset_async") orelse return error.MissingTruthInteractionSymbol,
            .n2b = base.lookup(N2b, "stwo_ntt_n2b_columns_on") orelse return error.MissingTruthInteractionSymbol,
            .pairs = base.lookup(Pairs, "stwo_rv64_global_pairs_on") orelse return error.MissingTruthInteractionSymbol,
            .cumulative = base.lookup(CumulativeFn, "stwo_rv64_global_cumulative_on"),
        };
    }
};

/// Where a group's claim goes: a claim index of the job's claims buffer, or
/// the role's "must be zero" word (legacy zero_claim_groups: a local group
/// that closes inside the truth, checked by Check.truth_status).
pub const ClaimTarget = union(enum) { claim: u32, zero_check: u32 };

/// Static plan of one role (class geometry; built once per class).
pub const Plan = struct {
    id: u32,
    log: u32,
    rows: usize,
    fixed_count: usize,
    main_count: usize,
    /// First FIXED / MAIN column of the role (original order of the trees).
    fixed_first: usize,
    main_first: usize,
    groups: [2]u32,
    layout: Layout,
    targets: [2]ClaimTarget,
    pairs: usize,
    group_count: usize,
    scan_words: usize,
    /// Projection parameter gather program (artifact.parameter_slots order).
    program: []const P.Entry,
    launch: Launch,

    pub const Spec = struct {
        id: u32,
        log: u32,
        fixed_count: usize,
        main_count: usize,
        fixed_first: usize,
        main_first: usize,
        groups: [2]u32,
        layout: Layout,
        targets: [2]ClaimTarget,
        program: []const P.Entry,
        launch: Launch,
    };
    pub fn init(spec: Spec) !Plan {
        const log = spec.log;
        // global_stage.generateRationalLocked geometry checks.
        if (log < 5 or log > 22 or spec.fixed_count == 0 or spec.main_count == 0 or spec.program.len == 0 or spec.program.len > 65536) return error.InvalidTruthInteractionGeometry;
        if (spec.groups[0] == 0 or spec.groups[0] > 640 or spec.groups[1] > 640) return error.InvalidTruthInteractionGeometry;
        const group_count: usize = 1 + @as(usize, @intFromBool(spec.groups[1] != 0));
        return .{ .id = spec.id, .log = log, .rows = @as(usize, 1) << @intCast(log), .fixed_count = spec.fixed_count, .main_count = spec.main_count, .fixed_first = spec.fixed_first, .main_first = spec.main_first, .groups = spec.groups, .layout = spec.layout, .targets = spec.targets, .pairs = @as(usize, spec.groups[0]) + spec.groups[1], .group_count = group_count, .scan_words = (try Prefix.Plan.init(log)).scratch_words, .program = spec.program, .launch = spec.launch };
    }
    /// Physical output columns (8 per pair + 8 per group).
    pub fn physicalWidth(self: *const Plan) usize {
        return 8 * (self.pairs + self.group_count);
    }
    pub fn outputWords(self: *const Plan) usize {
        return self.physicalWidth() * self.rows;
    }
    /// Published INTER columns (legacy `width`): every physical column for
    /// inverse_prefix, the pair columns only for cumulative_batches.
    pub fn width(self: *const Plan) usize {
        return if (self.layout == .inverse_prefix) self.physicalWidth() else 8 * self.pairs;
    }
    /// Published column `column` of `output`, in the legacy order.
    pub fn columnPointer(self: *const Plan, output: [*]const u32, column: usize) ![*]const u32 {
        if (column >= self.width()) return error.InvalidTruthInteractionGeometry;
        var physical: usize = 0;
        var published: usize = 0;
        for (self.groups) |count| {
            if (count == 0) continue;
            const n = 8 * (@as(usize, count) + @intFromBool(self.layout == .inverse_prefix));
            if (column < published + n) return output + (physical + column - published) * self.rows;
            published += n;
            physical += 8 * (@as(usize, count) + 1);
        }
        return error.InvalidTruthInteractionGeometry;
    }
    pub fn claimWords(self: *const Plan) usize {
        return 8 * self.group_count;
    }
    /// Enqueue-time arena words besides the caller-owned output (64-word granules).
    pub fn enqueueWords(self: *const Plan) usize {
        const g = 64;
        return std.mem.alignForward(usize, (self.fixed_count + self.main_count) * self.rows, g) + std.mem.alignForward(usize, self.pairs * 8 * self.rows, g) + std.mem.alignForward(usize, self.scan_words + self.claimWords() + 1, g) + std.mem.alignForward(usize, self.program.len * 8, g) + g;
    }
    /// The forward twiddle tower words (class persistent; shared key with
    /// native_global: identical content per log).
    pub fn twiddleWords(self: *const Plan) usize {
        return @as(usize, 1) << @intCast(self.log - 1);
    }
};

pub fn twiddleKey(log: u32) [32]u8 {
    var key: [32]u8 = @splat(0);
    @memcpy(key[0..16], "rv64-m8-glob-twd");
    key[16] = @intCast(log);
    return key;
}

/// Phase 1: the role's class twiddle tower (persistent; host-built only when fresh).
pub fn stageTwiddles(a: std.mem.Allocator, s: *api.Stager, log: u32) !api.DeviceBuffer {
    const tw_len = @as(usize, 1) << @intCast(log - 1);
    const region = try s.persistent(twiddleKey(log), tw_len);
    if (region.fresh) {
        var tw = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        defer engine.poly.twiddles.deinitM31(a, &tw);
        if (tw.twiddles.len != tw_len) return error.InvalidTruthInteractionGeometry;
        try s.upload(region.buffer, @as([*]const u32, @ptrCast(tw.twiddles.ptr))[0..tw.twiddles.len]);
    }
    return region.buffer;
}

fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

pub const Inputs = struct {
    /// FIXED / MAIN coefficient column pointers (device, role column order).
    fixed: []const [*]const u32,
    main: []const [*]const u32,
    /// Gathered projection parameters (program.len * 8 device words).
    parameters: api.DeviceBuffer,
    twiddles: api.DeviceBuffer,
};
pub const Outputs = struct {
    /// Caller-owned physical witness (Plan.outputWords), kept for the INTER commit.
    output: api.DeviceBuffer,
    /// The job's claims buffer (8 words per claim).
    claims: api.DeviceBuffer,
    /// The job's zero-check words (8 per index; ClaimTarget.zero_check).
    zero: api.DeviceBuffer,
    /// 1-word sticky verdict (0 = accepted).
    status: api.DeviceBuffer,
};

/// Phase 2 (exec stream, no host wait).
pub fn enqueue(plan: *const Plan, sym: *const Symbols, e: anytype, in: Inputs, out: Outputs) !void {
    const p = plan;
    if (in.fixed.len != p.fixed_count or in.main.len != p.main_count or in.parameters.words < p.program.len * 8 or in.twiddles.words < p.twiddleWords()) return error.InvalidTruthInteractionGeometry;
    if (out.output.words < p.outputWords() or out.status.words < 1) return error.InvalidTruthInteractionGeometry;
    if (p.layout == .cumulative_batches and sym.cumulative == null) return error.MissingResidentCumulativeCapability;
    const ctx = e.ctx();
    const stream = e.stream();
    const rows = p.rows;
    const source = try e.alloc((p.fixed_count + p.main_count) * rows);
    for (in.fixed, 0..) |from, i| try check(sym.copy_d2d(ctx, source.ptr + i * rows, from, rows * 4));
    for (in.main, 0..) |from, i| try check(sym.copy_d2d(ctx, source.ptr + (p.fixed_count + i) * rows, from, rows * 4));
    var launches: u32 = 0;
    const tw_count: u32 = @intCast(p.twiddleWords());
    try check(sym.n2b(source.ptr, rows, p.log, @intCast(p.fixed_count + p.main_count), in.twiddles.ptr + in.twiddles.words - tw_count, tw_count, tw_count, stream, &launches));
    const numerator = try e.alloc(p.pairs * 8 * rows);
    const scratch = try e.alloc(p.scan_words + p.claimWords() + 1);
    const claim = scratch.ptr + p.scan_words;
    const status = claim + p.claimWords();
    try check(sym.memset(ctx, status, 0, 4));
    try check(p.launch(ctx, 0, source.ptr, source.ptr + p.fixed_count * rows, in.parameters.ptr, numerator.ptr, out.output.ptr, status, p.log));
    var group_offset: usize = 0;
    var pair_offset: usize = 0;
    var k: usize = 0;
    for (p.groups, 0..) |count, group| {
        if (count == 0) continue;
        const job = Abi.GlobalPairs{ .output = out.output.ptr + group_offset * rows, .contributions = numerator.ptr + pair_offset * 8 * rows, .scan_scratch = scratch.ptr, .claim = claim + group * 8, .status = status, .stride = rows, .scan_words = p.scan_words, .row_log = p.log, .pairs = count };
        try check(sym.pairs(ctx, 0, &job));
        if (p.layout == .cumulative_batches) {
            const cumulative = Cumulative{ .output = job.output, .contributions = job.contributions, .stride = rows, .row_log = p.log, .pairs = count };
            try check(sym.cumulative.?(ctx, 0, &cumulative));
        }
        // Claim k of the role (legacy witness.claims[k]) to its target.
        const dst: [*]u32 = switch (p.targets[k]) {
            .claim => |i| blk: {
                if ((@as(usize, i) + 1) * 8 > out.claims.words) return error.InvalidTruthInteractionGeometry;
                break :blk out.claims.ptr + 8 * @as(usize, i);
            },
            .zero_check => |i| blk: {
                if ((@as(usize, i) + 1) * 8 > out.zero.words) return error.InvalidTruthInteractionGeometry;
                break :blk out.zero.ptr + 8 * @as(usize, i);
            },
        };
        try check(sym.copy_d2d(ctx, dst, claim + group * 8, 32));
        group_offset += 8 * (@as(usize, count) + 1);
        pair_offset += count;
        k += 1;
    }
    try check(sym.copy_d2d(ctx, out.status.ptr, status, 4));
    e.free(scratch);
    e.free(numerator);
    e.free(source);
}

const testing = std.testing;
fn noLaunch(_: *anyopaque, _: u32, _: [*]const u32, _: [*]const u32, _: [*]const u32, _: [*]u32, _: [*]u32, _: [*]u32, _: u32) callconv(.c) c_int {
    return 1;
}
const one_entry = [_]P.Entry{.{ .source = 0, .index = 0 }};

test "published INTER columns follow the legacy order for both layouts" {
    const base = Plan.Spec{ .id = 7, .log = 6, .fixed_count = 1, .main_count = 1, .fixed_first = 0, .main_first = 0, .groups = .{ 2, 1 }, .layout = .inverse_prefix, .targets = .{ .{ .claim = 0 }, .{ .claim = 3 } }, .program = &one_entry, .launch = noLaunch };
    const inv = try Plan.init(base);
    try testing.expectEqual(@as(usize, 8 * 5), inv.physicalWidth());
    try testing.expectEqual(inv.physicalWidth(), inv.width());
    const out: [*]const u32 = @ptrFromInt(0x10000);
    // inverse_prefix publishes every physical column in place.
    for (0..inv.width()) |c| try testing.expectEqual(@intFromPtr(out) + c * 64 * 4, @intFromPtr(try inv.columnPointer(out, c)));
    var cum_spec = base;
    cum_spec.layout = .cumulative_batches;
    cum_spec.id = 5;
    const cum = try Plan.init(cum_spec);
    try testing.expectEqual(@as(usize, 8 * 3), cum.width());
    // cumulative skips each group's 8 claim columns: group 0 = physical 0..16, group 1 = physical 24..32.
    try testing.expectEqual(@intFromPtr(out) + 15 * 64 * 4, @intFromPtr(try cum.columnPointer(out, 15)));
    try testing.expectEqual(@intFromPtr(out) + 24 * 64 * 4, @intFromPtr(try cum.columnPointer(out, 16)));
    try testing.expectError(error.InvalidTruthInteractionGeometry, cum.columnPointer(out, 24));
}

test "plan refuses the legacy-invalid geometries" {
    var s = Plan.Spec{ .id = 0, .log = 4, .fixed_count = 1, .main_count = 1, .fixed_first = 0, .main_first = 0, .groups = .{ 1, 0 }, .layout = .inverse_prefix, .targets = .{ .{ .claim = 0 }, .{ .claim = 0 } }, .program = &one_entry, .launch = noLaunch };
    try testing.expectError(error.InvalidTruthInteractionGeometry, Plan.init(s));
    s.log = 23;
    try testing.expectError(error.InvalidTruthInteractionGeometry, Plan.init(s));
    s.log = 10;
    s.groups = .{ 0, 1 };
    try testing.expectError(error.InvalidTruthInteractionGeometry, Plan.init(s));
    s.groups = .{ 1, 641 };
    try testing.expectError(error.InvalidTruthInteractionGeometry, Plan.init(s));
    s.groups = .{ 1, 0 };
    s.program = &.{};
    try testing.expectError(error.InvalidTruthInteractionGeometry, Plan.init(s));
}
