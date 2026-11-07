//! Device Check.oods_constraint of a native segment (M8 GPU-native,
//! rv64-m8-gpu-native.md §3.5, inventory H11; stream native, piece gn-s2).
//! Kernel: NAT/rv64/jobs/native_encode_oods.cu (stwo_rv64_native_oods_check_v1_on).
//!
//! The hybrid host assembly's last proof-level check (native_hybrid.zig
//! stageTwoInner: a second Components.Set with the real claims, then
//! evalCompositionPolynomialAtPointWithWorkCapture) evaluates the composition
//! polynomial at the OODS point from the sampled mask values and requires it
//! to equal what the composition tree's samples reconstruct
//! (extractCompositionOodsEvalWithSplit). Per role (component, Horner order)
//! the host computes
//!
//!   denominator  1 / cosetVanishing(CanonicCoset(trace_log), p_local),
//!                p_local = OODS point doubled (global_log - trace_log) times
//!   residuals    the role's AIR at the sampled masks (role_oods.zig and the
//!                other gkr_local roles), plus for roles with local binding the
//!                succinct auxiliaries is_first / is_second (mle_point
//!                evalAnchorsFor) and the carry quotient (evalCarryQuotientFor)
//!                at p_local
//!   accumulate   acc = acc * alpha + residual * denominator (root order)
//!
//! On the device the residuals come from the SAME symbolic program the AOT
//! composition kernels are generated from (joined_codegen.record: the
//! secure_polynomial_program_v2 DAG of each role, whose evaluation equals the
//! AIR's residuals, joined_fixture_support.nativeResiduals), interpreted at
//! the point instead of compiled per domain row. Everything from the class
//! geometry (node tables, mask reads resolved to PCS-image sample indices,
//! coset constants, table offsets of every role's parameters and hc rows) is
//! one per-class program built once at warm (`build` / `fromPlan`); per
//! segment the kernel reads only device data: the enqueue-only PCS image's
//! sampled values, the composition table AFTER its device patches (shared
//! draws, Stage-1 semantic + hc rows, public values, claim slots), the device
//! alpha and the device OODS field. It writes the Verdict word and an optional
//! 16-word diagnostic [evaluated(8) | extracted(8)]. Exact OM31 arithmetic
//! (om31.cuh is the host basis), so the verdict is the host's verdict.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v2;
pub const OM = core.fields.om31.OM31;
pub const Program = ir.ProgramFor(OM);
const M = core.fields.m31.M31;
const canonic = core.poly.circle.canonic;
const CirclePointM31 = core.circle.CirclePointM31;

pub const magic: u32 = 0x3144_4f4e; // "NOD1"
pub const version: u32 = 1;
/// Header word indices (native_encode_oods.cu, same order).
pub const H = struct {
    pub const magic = 0;
    pub const version = 1;
    pub const words = 2;
    pub const roles = 3;
    pub const global_log = 4;
    pub const split = 5;
    pub const composition_sample = 6; // sample index of composition column 0
    pub const samples = 7; // samples of the PCS image (8 words each)
    pub const scratch_words = 8;
    pub const table_words = 9; // minimum composition table size
    pub const header_words = 16;
};
/// One row per role (composition order).
pub const Role = struct {
    pub const words = 32;
    pub const trace_log = 0;
    pub const n_nodes = 1;
    pub const nodes_at = 2;
    pub const n_inputs = 3;
    pub const inputs_at = 4;
    pub const n_constants = 5;
    pub const constants_at = 6;
    pub const n_params = 7;
    pub const params_at = 8; // composition table word offset of parameter 0
    pub const n_roots = 9;
    pub const roots_at = 10;
    pub const regs_at = 11; // scratch word offset (8 words per node)
    pub const hc_at = 12; // table word offset of hc0[0] (hc1[i] at + 8 * (trace_log + i))
    pub const flags = 13;
    pub const half_step = 14; // M31 x, y of CanonicCoset(trace_log).coset().half_step
    pub const n_points = 16;
    pub const points_at = 17; // M31 (x, y) shift constants, see `points`
};
pub const node_words = 4; // op, lhs, rhs, value
pub const input_words = 2; // kind, sample index
pub const flag_aux: u32 = 1; // role has local binding: first / second / carry
pub const no_table: u32 = 0xffff_ffff;
pub const max_trace_log: u32 = 30;

/// How a program input is read at the OODS point.
pub const InputKind = enum(u32) { sample = 0, first = 1, second = 2, carry = 3, zero = 4 };
/// Verdict details (Check.oods_constraint).
pub const Detail = enum(u16) { descriptor = 1, noncanonical = 2, zero_inverse = 3, mismatch = 4, point = 5 };

/// The class geometry of one role.
pub const RoleInput = struct {
    program: *const Program,
    trace_log: u32,
    /// Widths per tree (FIXED, MAIN, INTER) without auxiliary columns, and the
    /// role's column offsets in those trees (native_composition.RoleSpec).
    widths: [3]u32,
    offsets: [3]u32,
    fixed_indices: ?[]const u32 = null,
    /// Local binding (RoleSpec.aux == .hc): the program's tree-2 inputs past
    /// widths[2] are is_first, is_second and the 8 carry coordinates.
    aux: bool = false,
    /// Composition-table word offsets of this role's parameters and hc rows.
    params_at: u32,
    hc_at: u32 = no_table,
};
pub const Geometry = struct {
    /// max_log_degree_bound of the host check (compositionMaskLogSize).
    global_log: u32,
    split: u32,
    /// PCS shape sample counts per tree (FIXED, MAIN, INTER, composition), in
    /// original column order (the PCS image samples order).
    sample_counts: []const []const u32,
    /// Words of the composition table the parameters / hc rows live in.
    table_words: usize,
};

/// Shift constants of a role (M31 points c, read as h = p_local - c):
///   [0] coset initial                   (denominator, is_first)
///   aux only:
///   [1] initial + step                  is_second   = is_first(p - step)
///   [2] initial - 2 step                last0       = is_first(p + 2 step)
///   [3] initial - step                  first1      = is_first(p + step)
///   [4 + 2 v], [5 + 2 v], v < log - 1:  initial + step * offset_v (+1),
///                                       offset_v = 2^(v + 1) - 2 (step selectors)
pub fn points(a: std.mem.Allocator, trace_log: u32, aux: bool) ![]CirclePointM31 {
    const coset = canonic.CanonicCoset.new(trace_log).coset();
    const n: usize = if (aux) 4 + 2 * @as(usize, trace_log - 1) else 1;
    const out = try a.alloc(CirclePointM31, n);
    out[0] = coset.initial;
    if (!aux) return out;
    out[1] = coset.initial.add(coset.step);
    out[2] = coset.initial.sub(coset.step.double());
    out[3] = coset.initial.sub(coset.step);
    for (0..trace_log - 1) |v| {
        const offset = (@as(u128, 1) << @intCast(v + 1)) - 2;
        out[4 + 2 * v] = coset.initial.add(coset.step.mul(offset));
        out[5 + 2 * v] = coset.initial.add(coset.step.mul(offset + 1));
    }
    return out;
}

fn sampleBase(counts: []const []const u32, tree: usize) usize {
    var n: usize = 0;
    for (counts[0..tree]) |t| for (t) |c| {
        n += c;
    };
    return n;
}
fn sampleIndex(counts: []const []const u32, tree: usize, column: usize, k: usize) !u32 {
    if (tree >= counts.len or column >= counts[tree].len) return error.InvalidNativeOodsProgram;
    if (k >= counts[tree][column]) return error.InvalidNativeOodsProgram;
    var n = sampleBase(counts, tree);
    for (counts[tree][0..column]) |c| n += c;
    return @intCast(n + k);
}

/// The per-class program (header, role rows, body). Fails closed on any
/// geometry the kernel could not read exactly as the host check does.
pub fn build(a: std.mem.Allocator, roles: []const RoleInput, g: Geometry) ![]u32 {
    if (roles.len == 0 or g.sample_counts.len != 4 or g.split == 0 or g.split > 4 or g.global_log == 0 or g.global_log >= 31) return error.InvalidNativeOodsProgram;
    // Composition tree: 8 << split columns, one sample each.
    const comp = g.sample_counts[3];
    if (comp.len != (@as(usize, 8) << @intCast(g.split))) return error.InvalidNativeOodsProgram;
    for (comp) |c| if (c != 1) return error.InvalidNativeOodsProgram;
    const samples = sampleBase(g.sample_counts, 4);
    var body: std.ArrayListUnmanaged(u32) = .empty;
    defer body.deinit(a);
    const rows = try a.alloc([Role.words]u32, roles.len);
    defer a.free(rows);
    var scratch: u64 = 0;
    for (roles, rows) |r, *row| {
        const p = r.program;
        try p.validate();
        if (r.trace_log == 0 or r.trace_log > g.global_log or r.trace_log > max_trace_log or (r.aux and r.trace_log < 2)) return error.InvalidNativeOodsProgram;
        if (@as(u64, r.params_at) + 8 * @as(u64, p.parameters.len) > g.table_words) return error.InvalidNativeOodsProgram;
        if (r.aux and (r.hc_at == no_table or @as(u64, r.hc_at) + 16 * @as(u64, r.trace_log) > g.table_words)) return error.InvalidNativeOodsProgram;
        row.* = @splat(0);
        row[Role.trace_log] = r.trace_log;
        row[Role.flags] = if (r.aux) flag_aux else 0;
        row[Role.params_at] = r.params_at;
        row[Role.n_params] = @intCast(p.parameters.len);
        row[Role.hc_at] = if (r.aux) r.hc_at else no_table;
        // Nodes.
        row[Role.n_nodes] = @intCast(p.nodes.len);
        row[Role.nodes_at] = @intCast(body.items.len);
        for (p.nodes) |node| {
            switch (node.op) {
                .constant, .input, .parameter, .add, .sub, .mul, .neg => {},
                .fraction, .range_fraction => return error.InvalidNativeOodsProgram,
            }
            try body.appendSlice(a, &.{ @intFromEnum(node.op), node.lhs, node.rhs, node.value });
        }
        // Inputs: every mask read resolved to its PCS-image sample.
        row[Role.n_inputs] = @intCast(p.inputs.len);
        row[Role.inputs_at] = @intCast(body.items.len);
        for (p.inputs) |input| {
            const t = input.tree;
            if (t > 2) return error.InvalidNativeOodsProgram;
            const k: usize = @intFromBool(input.offset != 0);
            if (t == 2 and input.column >= r.widths[2]) {
                // Uncommitted auxiliaries (joined_codegen: first, second, carry[8]).
                if (!r.aux or input.offset != 0) return error.InvalidNativeOodsProgram;
                const kind: InputKind = switch (input.column - r.widths[2]) {
                    0 => .first,
                    1 => .second,
                    2 => .carry,
                    3...9 => .zero,
                    else => return error.InvalidNativeOodsProgram,
                };
                try body.appendSlice(a, &.{ @intFromEnum(kind), 0 });
                continue;
            }
            if (input.column >= r.widths[t]) return error.InvalidNativeOodsProgram;
            const column: usize = if (t == 0 and r.fixed_indices != null) blk: {
                const idx = r.fixed_indices.?;
                if (input.column >= idx.len) return error.InvalidNativeOodsProgram;
                break :blk idx[input.column];
            } else @as(usize, r.offsets[t]) + input.column;
            // A shifted read is the column's second mask point
            // (role_geometry.masks: {point, next2 | prior}).
            if (k == 1 and g.sample_counts[t].len > column and g.sample_counts[t][column] != 2) return error.InvalidNativeOodsProgram;
            try body.appendSlice(a, &.{ @intFromEnum(InputKind.sample), try sampleIndex(g.sample_counts, t, column, k) });
        }
        row[Role.n_constants] = @intCast(p.constants.len);
        row[Role.constants_at] = @intCast(body.items.len);
        for (p.constants) |c| try body.appendSlice(a, &c);
        row[Role.n_roots] = @intCast(p.roots.len);
        row[Role.roots_at] = @intCast(body.items.len);
        try body.appendSlice(a, p.roots);
        // Coset constants.
        const coset = canonic.CanonicCoset.new(r.trace_log).coset();
        row[Role.half_step] = coset.half_step.x.toU32();
        row[Role.half_step + 1] = coset.half_step.y.toU32();
        const pts = try points(a, r.trace_log, r.aux);
        defer a.free(pts);
        row[Role.n_points] = @intCast(pts.len);
        row[Role.points_at] = @intCast(body.items.len);
        for (pts) |pt| try body.appendSlice(a, &.{ pt.x.toU32(), pt.y.toU32() });
        row[Role.regs_at] = @intCast(scratch);
        scratch += 8 * @as(u64, p.nodes.len);
        if (scratch > std.math.maxInt(u32)) return error.InvalidNativeOodsProgram;
    }
    const body_at = H.header_words + roles.len * Role.words;
    const total = body_at + body.items.len;
    if (total > std.math.maxInt(u32)) return error.InvalidNativeOodsProgram;
    const out = try a.alloc(u32, total);
    errdefer a.free(out);
    @memset(out[0..H.header_words], 0);
    out[H.magic] = magic;
    out[H.version] = version;
    out[H.words] = @intCast(total);
    out[H.roles] = @intCast(roles.len);
    out[H.global_log] = g.global_log;
    out[H.split] = g.split;
    out[H.composition_sample] = @intCast(sampleBase(g.sample_counts, 3));
    out[H.samples] = @intCast(samples);
    out[H.scratch_words] = @intCast(scratch + 9 * roles.len);
    out[H.table_words] = @intCast(g.table_words);
    for (rows, 0..) |row, i| {
        var x = row;
        for ([_]usize{ Role.nodes_at, Role.inputs_at, Role.constants_at, Role.roots_at, Role.points_at }) |k| x[k] += @intCast(body_at);
        @memcpy(out[H.header_words + i * Role.words ..][0..Role.words], &x);
    }
    @memcpy(out[body_at..], body.items);
    try validate(out);
    return out;
}

/// Header and table bounds (host side, before upload; the kernel re-checks).
pub fn validate(d: []const u32) !void {
    if (d.len < H.header_words or d[H.magic] != magic or d[H.version] != version or d[H.words] != d.len or d[H.roles] == 0) return error.InvalidNativeOodsProgram;
    const roles = d[H.roles];
    if (@as(u64, H.header_words) + @as(u64, roles) * Role.words > d.len) return error.InvalidNativeOodsProgram;
    var regs: u64 = 0;
    for (0..roles) |i| {
        const r = d[H.header_words + i * Role.words ..][0..Role.words];
        const spans = [_][2]u64{
            .{ r[Role.nodes_at], node_words * @as(u64, r[Role.n_nodes]) },
            .{ r[Role.inputs_at], input_words * @as(u64, r[Role.n_inputs]) },
            .{ r[Role.constants_at], 8 * @as(u64, r[Role.n_constants]) },
            .{ r[Role.roots_at], r[Role.n_roots] },
            .{ r[Role.points_at], 2 * @as(u64, r[Role.n_points]) },
        };
        for (spans) |s| if (s[0] + s[1] > d.len) return error.InvalidNativeOodsProgram;
        if (r[Role.trace_log] == 0 or r[Role.trace_log] > d[H.global_log] or r[Role.n_points] == 0) return error.InvalidNativeOodsProgram;
        if (@as(u64, r[Role.regs_at]) + 8 * @as(u64, r[Role.n_nodes]) > d[H.scratch_words]) return error.InvalidNativeOodsProgram;
        regs = @max(regs, @as(u64, r[Role.regs_at]) + 8 * @as(u64, r[Role.n_nodes]));
    }
    if (regs + 9 * @as(u64, roles) > d[H.scratch_words]) return error.InvalidNativeOodsProgram;
}
/// Scratch words of the kernel (registers + 9 per role partial).
pub fn scratchWords(d: []const u32) usize {
    return d[H.scratch_words];
}
/// Base of the per-role partials inside the scratch.
pub fn partialsAt(d: []const u32) usize {
    return d[H.scratch_words] - 9 * @as(usize, d[H.roles]);
}

// ---------------------------------------------------------------------------
// Device ABI
// ---------------------------------------------------------------------------

pub const Io = extern struct {
    desc: [*]const u32,
    desc_words: u64,
    /// PCS image samples section (8 words per sample, image order).
    samples: [*]const u32,
    sample_words: u64,
    /// Composition table (parameters + hc rows, after the device patches).
    table: [*]const u32,
    table_words: u64,
    /// Composition coefficient (8 words, the device alpha).
    alpha: [*]const u32,
    /// native_pcs OODS field (oods_field_words = 33): point x[8], y[8],
    /// base x[8], y[8], status. A nonzero status refuses (detail point).
    point: [*]const u32,
    scratch: [*]u32,
    scratch_words: u64,
    verdict: [*]u32,
    /// [evaluated(8) | extracted(8)], written whenever both were computed.
    diag: ?[*]u32,
};
comptime {
    if (@sizeOf(Io) != 96) @compileError("native OODS Io ABI changed");
}
pub const CheckFn = *const fn (*anyopaque, u32, *const Io) callconv(.c) c_int;
pub const Symbols = struct {
    check: CheckFn,
    pub fn load(addon: *std.DynLib) !Symbols {
        const V = *const fn () callconv(.c) u32;
        const v = addon.lookup(V, "stwo_rv64_native_oods_check_version") orelse return error.MissingNativeOodsKernel;
        if (v() != version) return error.NativeOodsKernelVersion;
        return .{ .check = addon.lookup(CheckFn, "stwo_rv64_native_oods_check_v1_on") orelse return error.MissingNativeOodsKernel };
    }
};
pub fn check(sym: *const Symbols, ctx: *anyopaque, io: Io) !void {
    if (sym.check(ctx, 0, &io) != 0) return error.CudaEnqueueFailed;
}
/// Enqueue the check from device views (Stage2Job / harness): `samples` is
/// the PCS image samples section, `scratch` at least scratchWords(desc).
pub fn enqueue(sym: *const Symbols, ctx: *anyopaque, desc: api.DeviceBuffer, samples: api.DeviceBuffer, table: api.DeviceBuffer, alpha: api.DeviceBuffer, point: api.DeviceBuffer, scratch: api.DeviceBuffer, verdict: api.DeviceBuffer, diag: ?api.DeviceBuffer) !void {
    if (alpha.words < 8 or point.words < 33 or verdict.words < 1 or (diag != null and diag.?.words < 16)) return error.InvalidNativeOodsIo;
    return check(sym, ctx, .{ .desc = desc.ptr, .desc_words = desc.words, .samples = samples.ptr, .sample_words = samples.words, .table = table.ptr, .table_words = table.words, .alpha = alpha.ptr, .point = point.ptr, .scratch = scratch.ptr, .scratch_words = scratch.words, .verdict = verdict.ptr, .diag = if (diag) |b| b.ptr else null });
}

// ---------------------------------------------------------------------------
// Host mirror of the kernel (tests and the parity harness's cross-check)
// ---------------------------------------------------------------------------

pub const Result = struct { word: u32, evaluated: ?OM = null, extracted: ?OM = null };
const Pt = core.circle.CirclePoint(OM);
const Refuse = error{ Descriptor, Noncanonical, ZeroInverse };

fn felt(w: []const u32) Refuse!OM {
    var limbs: [8]M = undefined;
    for (&limbs, w[0..8]) |*l, x| {
        if (x >= core.fields.m31.Modulus) return error.Noncanonical;
        l.* = M.fromCanonical(x);
    }
    return OM.fromM31Array(limbs);
}
fn liftM(x: u32, y: u32) Pt {
    return .{ .x = OM.fromBase(M.fromCanonical(x)), .y = OM.fromBase(M.fromCanonical(y)) };
}
fn inv(x: OM) Refuse!OM {
    if (x.isZero()) return error.ZeroInverse;
    return x.inv() catch error.ZeroInverse;
}
fn pow2(k: u32) M {
    return M.fromU64(@as(u64, 1) << @intCast(k));
}
fn vanish(h: Pt, half: [2]u32, log: u32) OM {
    const q = h.add(liftM(half[0], half[1]));
    var x = q.x;
    for (1..log) |_| x = Pt.doubleX(x);
    return x;
}
fn isFirst(p: Pt, c: [2]u32, half: [2]u32, log: u32) Refuse!OM {
    const h = p.sub(liftM(c[0], c[1]));
    const num = vanish(h, half, log);
    const pv = h.y.mul(try inv(OM.one().add(h.x)));
    return num.mul(try inv(pv.mul(OM.fromBase(pow2(log)))));
}
fn stepSelector(p: Pt, c: [2]u32, log: u32, log_step: u32) Refuse!OM {
    var q = p.sub(liftM(c[0], c[1]));
    var ys: [max_trace_log + 1]OM = undefined;
    for (0..log) |i| {
        ys[i] = q.y;
        q = q.double();
    }
    var v: [max_trace_log + 1]OM = undefined;
    var iv: [max_trace_log + 1]OM = undefined;
    for (0..log_step) |i| {
        v[i] = ys[log - 1 - i];
        iv[i] = try inv(v[i]);
    }
    const t = v[0].mul(iv[1]);
    const dbl = t.mul(t);
    var sum = OM.zero();
    for (1..log_step) |i| sum = sum.add(iv[i]);
    const numer = dbl.add(v[0].mul(sum.add(sum)));
    const s = pow2(log_step + 1).inv() catch return error.ZeroInverse;
    return numer.mul(OM.fromBase(s));
}

/// Exactly the kernel's computation on host memory.
pub fn hostCheck(a: std.mem.Allocator, d: []const u32, samples: []const u32, table: []const u32, alpha_words: []const u32, point_words: []const u32) !Result {
    const reject = struct {
        fn f(detail: Detail) u32 {
            return G.Verdict.reject(.oods_constraint, @intFromEnum(detail));
        }
    }.f;
    validate(d) catch return .{ .word = reject(.descriptor) };
    if (@as(u64, d[H.samples]) * 8 > samples.len or table.len < d[H.table_words] or @as(u64, d[H.composition_sample]) + (@as(u64, 8) << @intCast(d[H.split])) > d[H.samples]) return .{ .word = reject(.descriptor) };
    if (point_words.len < 33 or point_words[32] != 0) return .{ .word = reject(.point) };
    const point = Pt{ .x = felt(point_words[0..8]) catch return .{ .word = reject(.noncanonical) }, .y = felt(point_words[8..16]) catch return .{ .word = reject(.noncanonical) } };
    const alpha = felt(alpha_words[0..8]) catch return .{ .word = reject(.noncanonical) };
    var acc = OM.zero();
    var regs: std.ArrayListUnmanaged(OM) = .empty;
    defer regs.deinit(a);
    for (0..d[H.roles]) |i| {
        const r = d[H.header_words + i * Role.words ..][0..Role.words];
        const partial = rolePartial(a, d, r, samples, table, point, alpha, &regs) catch |err| return .{ .word = reject(switch (err) {
            error.Descriptor => .descriptor,
            error.Noncanonical => .noncanonical,
            error.ZeroInverse => .zero_inverse,
            else => return err,
        }) };
        var pw = OM.one();
        for (0..r[Role.n_roots]) |_| pw = pw.mul(alpha);
        acc = acc.mul(pw).add(partial);
    }
    var chunks: [16]OM = undefined;
    const n_chunks = @as(usize, 1) << @intCast(d[H.split]);
    for (0..n_chunks) |c| {
        var e: [8]OM = undefined;
        for (&e, 0..) |*x, k| x.* = felt(samples[8 * (d[H.composition_sample] + c * 8 + k) ..][0..8]) catch return .{ .word = reject(.noncanonical) };
        chunks[c] = OM.fromPartialEvals(e);
    }
    var active = n_chunks;
    var parent_log = d[H.global_log] + 1;
    while (active > 1) {
        const factor = point.repeatedDouble(parent_log - 2).x;
        var o: usize = 0;
        var k: usize = 0;
        while (k < active) : (k += 2) {
            chunks[o] = chunks[k].add(factor.mul(chunks[k + 1]));
            o += 1;
        }
        active /= 2;
        parent_log += 1;
    }
    const word: u32 = if (acc.eql(chunks[0])) G.Verdict.accepted else reject(.mismatch);
    return .{ .word = word, .evaluated = acc, .extracted = chunks[0] };
}

fn rolePartial(a: std.mem.Allocator, d: []const u32, r: []const u32, samples: []const u32, table: []const u32, point: Pt, alpha: OM, regs: *std.ArrayListUnmanaged(OM)) !OM {
    const log = r[Role.trace_log];
    var local = point;
    for (log..d[H.global_log]) |_| local = local.double();
    const half = [2]u32{ r[Role.half_step], r[Role.half_step + 1] };
    const pts = d[r[Role.points_at]..][0 .. 2 * r[Role.n_points]];
    const den = vanish(local.sub(liftM(pts[0], pts[1])), half, log);
    const scale = try inv(den);
    var aux: [3]OM = .{ OM.zero(), OM.zero(), OM.zero() };
    if (r[Role.flags] & flag_aux != 0) {
        if (r[Role.n_points] != 4 + 2 * (log - 1) or r[Role.hc_at] == no_table or @as(u64, r[Role.hc_at]) + 16 * @as(u64, log) > table.len) return error.Descriptor;
        const P = struct {
            fn at(x: []const u32, k: usize) [2]u32 {
                return .{ x[2 * k], x[2 * k + 1] };
            }
        };
        aux[0] = try isFirst(local, P.at(pts, 0), half, log);
        aux[1] = try isFirst(local, P.at(pts, 1), half, log);
        const hc = table[r[Role.hc_at]..];
        var carry = OM.zero();
        for (0..log - 1) |v| {
            const s0 = try stepSelector(local, P.at(pts, 4 + 2 * v), log, @intCast(v + 2));
            const s1 = try stepSelector(local, P.at(pts, 5 + 2 * v), log, @intCast(v + 2));
            carry = carry.add(s0.mul(try felt(hc[8 * v ..][0..8]))).add(s1.mul(try felt(hc[8 * (log + v) ..][0..8])));
        }
        const last0 = try isFirst(local, P.at(pts, 2), half, log);
        const first1 = try isFirst(local, P.at(pts, 3), half, log);
        carry = carry.add((try felt(hc[8 * (log - 1) ..][0..8])).mul(last0)).add((try felt(hc[8 * (2 * log - 1) ..][0..8])).mul(first1));
        aux[2] = carry;
    }
    const n = r[Role.n_nodes];
    try regs.resize(a, n);
    const nodes = d[r[Role.nodes_at]..][0 .. node_words * n];
    const inputs = d[r[Role.inputs_at]..][0 .. input_words * r[Role.n_inputs]];
    const consts = d[r[Role.constants_at]..][0 .. 8 * r[Role.n_constants]];
    const n_samples = d[H.samples];
    for (0..n) |k| {
        const x = nodes[node_words * k ..][0..node_words];
        const op = std.meta.intToEnum(ir.Op, x[0]) catch return error.Descriptor;
        regs.items[k] = switch (op) {
            .constant => if (x[3] >= r[Role.n_constants]) return error.Descriptor else try felt(consts[8 * x[3] ..][0..8]),
            .parameter => if (x[3] >= r[Role.n_params] or @as(u64, r[Role.params_at]) + 8 * (@as(u64, x[3]) + 1) > table.len) return error.Descriptor else try felt(table[r[Role.params_at] + 8 * x[3] ..][0..8]),
            .input => blk: {
                if (x[3] >= r[Role.n_inputs]) return error.Descriptor;
                const kind = std.meta.intToEnum(InputKind, inputs[2 * x[3]]) catch return error.Descriptor;
                break :blk switch (kind) {
                    .sample => if (inputs[2 * x[3] + 1] >= n_samples) return error.Descriptor else try felt(samples[8 * @as(usize, inputs[2 * x[3] + 1]) ..][0..8]),
                    .first => aux[0],
                    .second => aux[1],
                    .carry => aux[2],
                    .zero => OM.zero(),
                };
            },
            .add, .sub, .mul => if (x[1] >= k or x[2] >= k) return error.Descriptor else switch (op) {
                .add => regs.items[x[1]].add(regs.items[x[2]]),
                .sub => regs.items[x[1]].sub(regs.items[x[2]]),
                else => regs.items[x[1]].mul(regs.items[x[2]]),
            },
            .neg => if (x[1] >= k) return error.Descriptor else regs.items[x[1]].neg(),
            .fraction, .range_fraction => return error.Descriptor,
        };
    }
    var h = OM.zero();
    for (d[r[Role.roots_at]..][0..r[Role.n_roots]]) |root| {
        if (root >= n) return error.Descriptor;
        h = h.mul(alpha).add(regs.items[root].mul(scale));
    }
    return h;
}

// ---------------------------------------------------------------------------
// Builder from a native composition plan (Stage2 class framing at warm)
// ---------------------------------------------------------------------------

const NComp = @import("native_composition.zig");

/// The program of a composition plan's roles, reading parameters / hc rows
/// at the plan's own table offsets (so the kernel reads the job's patched
/// `table_device`). `programs[i]`: role i's symbolic program (the
/// joined_codegen artifact of RoleSpec.id, recorded at warm).
pub fn fromPlan(a: std.mem.Allocator, plan: *const NComp.Plan, programs: []const *const Program, sample_counts: []const []const u32, global_log: u32) ![]u32 {
    if (programs.len != plan.roles.len) return error.InvalidNativeOodsProgram;
    const roles = try a.alloc(RoleInput, plan.roles.len);
    defer a.free(roles);
    for (plan.roles, programs, roles) |*r, p, *out| {
        const s = r.spec;
        if (s.kernel != .cpu or s.parameters.len != 8 * p.parameters.len or s.mask_columns.len != p.inputs.len or s.constraints != p.roots.len) return error.InvalidNativeOodsProgram;
        for (s.mask_columns, p.inputs) |m, input| if (m != input.column) return error.InvalidNativeOodsProgram;
        out.* = .{ .program = p, .trace_log = s.trace_log, .widths = s.widths, .offsets = s.offsets, .fixed_indices = s.fixed_indices, .aux = s.aux == .hc, .params_at = @intCast(r.t_params), .hc_at = if (s.aux == .hc) @intCast(r.t_hc) else no_table };
        if (s.aux == .last) return error.InvalidNativeOodsProgram;
    }
    return build(a, roles, .{ .global_log = global_log, .split = plan.split, .sample_counts = sample_counts, .table_words = plan.table.len });
}

// ---------------------------------------------------------------------------
// Host tests (no GPU)
// ---------------------------------------------------------------------------

const MP = @import("stwo_riscv_cpu_integration").rv64_outer_mle_point;

fn testFelt(rng: std.Random) OM {
    var limbs: [8]M = undefined;
    for (&limbs) |*l| l.* = M.fromCanonical(rng.uintLessThan(u32, core.fields.m31.Modulus));
    return OM.fromM31Array(limbs);
}
fn words8(x: OM) [8]u32 {
    var w: [8]u32 = undefined;
    for (x.toM31Array(), &w) |m, *o| o.* = m.toU32();
    return w;
}

test "native OODS host mirror: anchors and carry equal mle_point at a secure point" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rng = prng.random();
    for ([_]u32{ 2, 3, 5, 9 }) |log| {
        // A generic secure point on the circle (a channel draw).
        var ch = @import("stwo_core").channel.raw_mod_m31.Om31Channel.init();
        ch.mixU64(log);
        const point = try core.circle.randomSecureFieldPointFor(OM, &ch);
        const pts = try points(a, log, true);
        defer a.free(pts);
        const coset = canonic.CanonicCoset.new(log).coset();
        const half = [2]u32{ coset.half_step.x.toU32(), coset.half_step.y.toU32() };
        const anchors = try MP.evalAnchorsFor(OM, log, point);
        try std.testing.expect(anchors[0].eql(try isFirst(point, .{ pts[0].x.toU32(), pts[0].y.toU32() }, half, log)));
        try std.testing.expect(anchors[1].eql(try isFirst(point, .{ pts[1].x.toU32(), pts[1].y.toU32() }, half, log)));
        var r: [max_trace_log]OM = undefined;
        for (r[0..log]) |*v| v.* = testFelt(rng);
        const mle = try MP.MleEvalPointFor(OM).init(r[0..log]);
        var table: [16 * max_trace_log]u32 = undefined;
        for (0..log) |i| {
            table[8 * i ..][0..8].* = words8(mle.hc0[i]);
            table[8 * (log + i) ..][0..8].* = words8(mle.hc1[i]);
        }
        const expected = try MP.evalCarryQuotientFor(OM, &mle, point);
        // Carry through the role path: a one-node program reading the carry.
        var nodes = [_]ir.Node{.{ .op = .input, .value = 0 }};
        var inputs = [_]ir.Input{.{ .tree = 2, .column = 1 + 2 }};
        var roots = [_]u32{0};
        var prog = Program{ .a = a, .authority = @splat(1), .nodes = &nodes, .inputs = &inputs, .constants = &.{}, .parameters = &.{}, .roots = &roots, .identity = undefined };
        prog.identity = prog.identityDigest();
        const counts = [_][]const u32{ &.{1}, &.{1}, &.{1}, &([_]u32{1} ** 16) };
        const d = try build(a, &.{.{ .program = &prog, .trace_log = log, .widths = .{ 1, 1, 1 }, .offsets = .{ 0, 0, 0 }, .aux = true, .params_at = 0, .hc_at = 0 }}, .{ .global_log = log, .split = 1, .sample_counts = &counts, .table_words = 16 * log });
        defer a.free(d);
        var regs: std.ArrayListUnmanaged(OM) = .empty;
        defer regs.deinit(a);
        const samples = [_]u32{0} ** (8 * 19);
        const partial = try rolePartial(a, d, d[H.header_words..][0..Role.words], &samples, table[0 .. 16 * log], point, OM.one(), &regs);
        const den = try core.constraints.cosetVanishing(OM, coset, point).inv();
        try std.testing.expect(partial.eql(expected.mul(den)));
    }
}

test "native OODS program: mask reads resolve to image samples; geometry faults fail closed" {
    const a = std.testing.allocator;
    // x0 = MAIN col 1 (current), x1 = MAIN col 1 (previous), x2 = FIXED col 0,
    // x3 = INTER col 0, residual r = x0 * x1 - x2 + param0 * x3.
    var nodes = [_]ir.Node{
        .{ .op = .input, .value = 0 },
        .{ .op = .input, .value = 1 },
        .{ .op = .mul, .lhs = 0, .rhs = 1 },
        .{ .op = .input, .value = 2 },
        .{ .op = .sub, .lhs = 2, .rhs = 3 },
        .{ .op = .parameter, .value = 0 },
        .{ .op = .input, .value = 3 },
        .{ .op = .mul, .lhs = 5, .rhs = 6 },
        .{ .op = .add, .lhs = 4, .rhs = 7 },
        .{ .op = .constant, .value = 0 },
    };
    var inputs = [_]ir.Input{ .{ .tree = 1, .column = 1 }, .{ .tree = 1, .column = 1, .offset = -1 }, .{ .tree = 0, .column = 0 }, .{ .tree = 2, .column = 0 } };
    var constants = [_][8]u32{.{ 3, 0, 0, 0, 0, 0, 0, 0 }};
    var params = [_]OM{OM.one()};
    var roots = [_]u32{ 8, 9 };
    var prog = Program{ .a = a, .authority = @splat(2), .nodes = &nodes, .inputs = &inputs, .constants = &constants, .parameters = &params, .roots = &roots, .identity = undefined };
    prog.identity = prog.identityDigest();
    // Trees: FIXED 2 cols, MAIN 3 cols (col 2 of the role = global 2 has 2 samples), INTER 1, comp 16.
    const counts = [_][]const u32{ &.{ 1, 1 }, &.{ 1, 1, 2 }, &.{1}, &([_]u32{1} ** 16) };
    const role = RoleInput{ .program = &prog, .trace_log = 4, .widths = .{ 1, 2, 1 }, .offsets = .{ 1, 1, 0 }, .params_at = 8 };
    const d = try build(a, &.{role}, .{ .global_log = 6, .split = 1, .sample_counts = &counts, .table_words = 16 });
    defer a.free(d);
    const r = d[H.header_words..][0..Role.words];
    const ins = d[r[Role.inputs_at]..][0 .. 2 * 4];
    // MAIN global col 2 starts at sample 2 + 2 = 4; FIXED global col 1 = sample 1; INTER col 0 = 2 + 4 = 6.
    try std.testing.expectEqualSlices(u32, &.{ 0, 4, 0, 5, 0, 1, 0, 6 }, ins);
    try std.testing.expectEqual(@as(u32, 7), d[H.composition_sample]);
    try std.testing.expectEqual(@as(u32, 23), d[H.samples]);
    // Host mirror == direct evaluation of the residuals at random samples.
    var prng = std.Random.DefaultPrng.init(9);
    const rng = prng.random();
    var samples: [23 * 8]u32 = undefined;
    for (0..23) |i| samples[8 * i ..][0..8].* = words8(testFelt(rng));
    var table: [16]u32 = @splat(0);
    const pv = testFelt(rng);
    table[8..16].* = words8(pv);
    var ch = @import("stwo_core").channel.raw_mod_m31.Om31Channel.init();
    const point = try core.circle.randomSecureFieldPointFor(OM, &ch);
    const alpha = testFelt(rng);
    var pw: [33]u32 = @splat(0);
    pw[0..8].* = words8(point.x);
    pw[8..16].* = words8(point.y);
    const got = try hostCheck(a, d, &samples, &table, &words8(alpha), &pw);
    const s = struct {
        fn at(x: []const u32, i: usize) OM {
            return felt(x[8 * i ..][0..8]) catch unreachable;
        }
    };
    const residual = s.at(&samples, 4).mul(s.at(&samples, 5)).sub(s.at(&samples, 1)).add(pv.mul(s.at(&samples, 6)));
    const coset = canonic.CanonicCoset.new(4).coset();
    const den = try core.constraints.cosetVanishing(OM, coset, point.repeatedDouble(2)).inv();
    const expected = residual.mul(den).mul(alpha).add(OM.fromBase(M.fromCanonical(3)).mul(den));
    try std.testing.expect(got.evaluated.?.eql(expected));
    try std.testing.expect(got.word != G.Verdict.accepted); // random composition samples
    // Faults: a previous read of a single-sample column, a column past the
    // role width, an aux read on a role without binding, a short table.
    var bad = role;
    bad.offsets = .{ 1, 0, 0 };
    try std.testing.expectError(error.InvalidNativeOodsProgram, build(a, &.{bad}, .{ .global_log = 6, .split = 1, .sample_counts = &counts, .table_words = 16 }));
    var wide = inputs;
    wide[3].column = 1;
    var p2 = prog;
    p2.inputs = &wide;
    p2.identity = p2.identityDigest();
    var r2 = role;
    r2.program = &p2;
    try std.testing.expectError(error.InvalidNativeOodsProgram, build(a, &.{r2}, .{ .global_log = 6, .split = 1, .sample_counts = &counts, .table_words = 16 }));
    try std.testing.expectError(error.InvalidNativeOodsProgram, build(a, &.{role}, .{ .global_log = 6, .split = 1, .sample_counts = &counts, .table_words = 15 }));
    // Corrupted descriptor words are refused by the mirror (descriptor).
    const broken = try a.dupe(u32, d);
    defer a.free(broken);
    broken[H.header_words + Role.regs_at] = 1 << 30;
    try std.testing.expectEqual(G.Verdict.reject(.oods_constraint, @intFromEnum(Detail.descriptor)), (try hostCheck(a, broken, &samples, &table, &words8(alpha), &pw)).word);
    // Point status / noncanonical alpha.
    var pst = pw;
    pst[32] = 1;
    try std.testing.expectEqual(G.Verdict.reject(.oods_constraint, @intFromEnum(Detail.point)), (try hostCheck(a, d, &samples, &table, &words8(alpha), &pst)).word);
    var na = words8(alpha);
    na[3] = core.fields.m31.Modulus;
    try std.testing.expectEqual(G.Verdict.reject(.oods_constraint, @intFromEnum(Detail.noncanonical)), (try hostCheck(a, d, &samples, &table, &na, &pw)).word);
}

test "native OODS: an honest composition sample set is accepted, one flipped sample is a mismatch" {
    const a = std.testing.allocator;
    var nodes = [_]ir.Node{ .{ .op = .input, .value = 0 }, .{ .op = .input, .value = 0 }, .{ .op = .mul, .lhs = 0, .rhs = 1 } };
    var inputs = [_]ir.Input{.{ .tree = 1, .column = 0 }};
    var roots = [_]u32{ 2, 0 };
    var prog = Program{ .a = a, .authority = @splat(3), .nodes = &nodes, .inputs = &inputs, .constants = &.{}, .parameters = &.{}, .roots = &roots, .identity = undefined };
    prog.identity = prog.identityDigest();
    const counts = [_][]const u32{ &.{1}, &.{1}, &.{1}, &([_]u32{1} ** 16) };
    const d = try build(a, &.{.{ .program = &prog, .trace_log = 3, .widths = .{ 0, 1, 0 }, .offsets = .{ 0, 0, 0 }, .params_at = 0 }}, .{ .global_log = 5, .split = 1, .sample_counts = &counts, .table_words = 0 });
    defer a.free(d);
    var prng = std.Random.DefaultPrng.init(11);
    const rng = prng.random();
    var samples: [19 * 8]u32 = undefined;
    for (0..19) |i| samples[8 * i ..][0..8].* = words8(testFelt(rng));
    var ch = @import("stwo_core").channel.raw_mod_m31.Om31Channel.init();
    ch.mixU64(77);
    const point = try core.circle.randomSecureFieldPointFor(OM, &ch);
    var pw: [33]u32 = @splat(0);
    pw[0..8].* = words8(point.x);
    pw[8..16].* = words8(point.y);
    const alpha = testFelt(rng);
    const first = try hostCheck(a, d, &samples, &.{}, &words8(alpha), &pw);
    // Choose chunk 1 so that chunk0 + factor * chunk1 == evaluated: set chunk1
    // coordinates to 0 and chunk0 = evaluated (fromPartialEvals(e0, 0..) = e0).
    for (0..16) |k| samples[8 * (3 + k) ..][0..8].* = @splat(0);
    samples[8 * 3 ..][0..8].* = words8(first.evaluated.?);
    const ok = try hostCheck(a, d, &samples, &.{}, &words8(alpha), &pw);
    try std.testing.expectEqual(G.Verdict.accepted, ok.word);
    samples[8 * 3] ^= 1;
    try std.testing.expectEqual(G.Verdict.reject(.oods_constraint, @intFromEnum(Detail.mismatch)), (try hostCheck(a, d, &samples, &.{}, &words8(alpha), &pw)).word);
}

test "native OODS fromPlan reads parameters / hc rows at the composition plan's table offsets (== build on a compact table)" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x0d5);
    const rng = prng.random();
    // Role A: no binding; r = (MAIN0 * FIXED0 + p0) * p1, second root MAIN0 * FIXED0.
    var nodes_a = [_]ir.Node{
        .{ .op = .input, .value = 0 },
        .{ .op = .input, .value = 1 },
        .{ .op = .mul, .lhs = 0, .rhs = 1 },
        .{ .op = .parameter, .value = 0 },
        .{ .op = .add, .lhs = 2, .rhs = 3 },
        .{ .op = .parameter, .value = 1 },
        .{ .op = .mul, .lhs = 4, .rhs = 5 },
    };
    var inputs_a = [_]ir.Input{ .{ .tree = 1, .column = 0 }, .{ .tree = 0, .column = 0 } };
    var params_a = [_]OM{ OM.one(), OM.one() };
    var roots_a = [_]u32{ 6, 2 };
    var prog_a = Program{ .a = a, .authority = @splat(4), .nodes = &nodes_a, .inputs = &inputs_a, .constants = &.{}, .parameters = &params_a, .roots = &roots_a, .identity = undefined };
    prog_a.identity = prog_a.identityDigest();
    // Role B: local binding; r = MAIN1 * carry + is_first + p0 (reads hc rows).
    var nodes_b = [_]ir.Node{
        .{ .op = .input, .value = 0 },
        .{ .op = .input, .value = 1 },
        .{ .op = .input, .value = 2 },
        .{ .op = .mul, .lhs = 0, .rhs = 1 },
        .{ .op = .add, .lhs = 3, .rhs = 2 },
        .{ .op = .parameter, .value = 0 },
        .{ .op = .add, .lhs = 4, .rhs = 5 },
    };
    var inputs_b = [_]ir.Input{ .{ .tree = 1, .column = 0 }, .{ .tree = 2, .column = 2 }, .{ .tree = 2, .column = 0 } };
    var params_b = [_]OM{OM.one()};
    var roots_b = [_]u32{6};
    var prog_b = Program{ .a = a, .authority = @splat(5), .nodes = &nodes_b, .inputs = &inputs_b, .constants = &.{}, .parameters = &params_b, .roots = &roots_b, .identity = undefined };
    prog_b.identity = prog_b.identityDigest();
    var pa: [16]u32 = undefined;
    var pb: [8]u32 = undefined;
    var hc: [16 * 4]u32 = undefined;
    for ([_][]u32{ &pa, &pb, &hc }) |buf| for (0..buf.len / 8) |i| {
        buf[8 * i ..][0..8].* = words8(testFelt(rng));
    };
    const masks_a = [_]u32{ 0, 0 };
    const masks_b = [_]u32{ 0, 2, 0 };
    const specs = [_]NComp.RoleSpec{
        .{ .id = 1, .trace_log = 4, .eval_log = 5, .widths = .{ 1, 1, 0 }, .offsets = .{ 0, 0, 0 }, .parameters = &pa, .mask_columns = &masks_a, .constraints = 2 },
        .{ .id = 2, .trace_log = 4, .eval_log = 5, .widths = .{ 0, 1, 0 }, .offsets = .{ 0, 1, 0 }, .aux = .hc, .hc = &hc, .parameters = &pb, .mask_columns = &masks_b, .constraints = 1 },
    };
    const fixed_logs = [_]u32{4};
    const main_logs = [_]u32{ 4, 4 };
    var plan = try NComp.Plan.init(a, .{ .roles = &specs, .log = 6, .split = 1, .total = 3, .beta = 1, .tree_logs = .{ &fixed_logs, &main_logs, &.{} } });
    defer plan.deinit();
    const counts = [_][]const u32{ &.{1}, &.{ 1, 1 }, &.{}, &([_]u32{1} ** 16) };
    const progs = [_]*const Program{ &prog_a, &prog_b };
    const d = try fromPlan(a, &plan, &progs, &counts, 6);
    defer a.free(d);
    // The descriptor addresses the plan table (t_params / t_hc), not a compact one.
    try std.testing.expectEqual(@as(u32, @intCast(plan.roles[0].t_params)), d[H.header_words + Role.params_at]);
    try std.testing.expectEqual(@as(u32, @intCast(plan.roles[1].t_params)), d[H.header_words + Role.words + Role.params_at]);
    try std.testing.expectEqual(@as(u32, @intCast(plan.roles[1].t_hc)), d[H.header_words + Role.words + Role.hc_at]);
    try std.testing.expectEqual(@as(u32, @intCast(plan.table.len)), d[H.table_words]);
    // Reference: the same roles through `build` over a compact [pa | pb | hc] table.
    var compact: [16 + 8 + 64]u32 = undefined;
    @memcpy(compact[0..16], &pa);
    @memcpy(compact[16..24], &pb);
    @memcpy(compact[24..], &hc);
    const ref = try build(a, &.{
        .{ .program = &prog_a, .trace_log = 4, .widths = .{ 1, 1, 0 }, .offsets = .{ 0, 0, 0 }, .params_at = 0 },
        .{ .program = &prog_b, .trace_log = 4, .widths = .{ 0, 1, 0 }, .offsets = .{ 0, 1, 0 }, .aux = true, .params_at = 16, .hc_at = 24 },
    }, .{ .global_log = 6, .split = 1, .sample_counts = &counts, .table_words = compact.len });
    defer a.free(ref);
    var samples: [19 * 8]u32 = undefined;
    for (0..19) |i| samples[8 * i ..][0..8].* = words8(testFelt(rng));
    var ch = @import("stwo_core").channel.raw_mod_m31.Om31Channel.init();
    ch.mixU64(0xf0);
    const point = try core.circle.randomSecureFieldPointFor(OM, &ch);
    var pw: [33]u32 = @splat(0);
    pw[0..8].* = words8(point.x);
    pw[8..16].* = words8(point.y);
    const alpha = words8(testFelt(rng));
    const got = try hostCheck(a, d, &samples, plan.table, &alpha, &pw);
    const want = try hostCheck(a, ref, &samples, &compact, &alpha, &pw);
    try std.testing.expect(got.evaluated != null and want.evaluated != null and got.evaluated.?.eql(want.evaluated.?));
    // A patched plan-table parameter (what the device patches write) moves the evaluation.
    const table = try a.dupe(u32, plan.table);
    defer a.free(table);
    table[plan.roles[1].t_params] = (table[plan.roles[1].t_params] + 1) % core.fields.m31.Modulus;
    try std.testing.expect(!(try hostCheck(a, d, &samples, table, &alpha, &pw)).evaluated.?.eql(got.evaluated.?));
    // Shape faults fail closed: program count, mask columns, a last-anchor role.
    try std.testing.expectError(error.InvalidNativeOodsProgram, fromPlan(a, &plan, progs[0..1], &counts, 6));
    const swapped = [_]*const Program{ &prog_b, &prog_a };
    try std.testing.expectError(error.InvalidNativeOodsProgram, fromPlan(a, &plan, &swapped, &counts, 6));
}
