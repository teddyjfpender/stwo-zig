//! Device OODS constraint check of a truth proof (stream gn-truth; design
//! rv64-m8-gpu-native.md §3.5; kernel stwo_rv64_truth_oods_check_v1_on in
//! NAT/rv64/jobs/truth_oods.cu). Replaces the host check of
//! truth_job.Stage2.assemble:
//!
//!   view.evalCompositionPolynomialAtPoint(oods, sampled, alpha, mask_log)
//!     == proof.extractCompositionOodsEvalWithSplit(oods, mask_log + split, split)
//!
//! The per-class descriptor is built ONCE at warm from class geometry only:
//! every truth role's secure_polynomial_program_v2 (the very program the AOT
//! truth composition kernel is generated from: truth_domain_fixtures.record)
//! pruned to the nodes its constraints reach, reordered by DAG level, with
//! every mask read (tree, column, offset) resolved to an index of the PCS
//! image's samples section (hybrid_pcs.decodeWords layout: tree, original
//! column, mask order) and the classic last-anchor public polynomial marked.
//! No challenge or claim enters the descriptor: parameters are read per proof
//! from the device-gathered composition parameter table (the words the
//! composition kernel read), alpha and the OODS point from the job's device
//! fields. `evaluate` is the bit-exact host mirror of the kernel (parity and
//! unit tests); the unit tests compare it with the engine's
//! evalCompositionPolynomialAtPoint over the legacy truth components.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const CG = @import("../composition_codegen.zig");
const T = @import("../truth_codegen.zig");
const Fixtures = @import("../truth_domain_fixtures.zig");

const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);
const canonic = core.poly.circle.canonic;

pub const magic: u32 = 0x5344_4f54; // "TODS"
pub const version: u32 = 1;
/// Header word indices (truth_oods.cu, same order).
pub const H = struct {
    pub const magic = 0;
    pub const version = 1;
    pub const words = 2;
    pub const roles = 3;
    pub const global_log = 4;
    pub const composition_log = 5;
    pub const split = 6;
    pub const composition_sample = 7;
    pub const samples = 8;
    pub const consts_at = 9;
    pub const n_consts = 10;
    pub const scratch = 11;
    pub const partials_at = 12;
    pub const header_words = 16;
};
/// Role row word indices (16 words per role).
pub const R = struct {
    pub const trace_log = 0;
    pub const nodes_at = 1;
    pub const n_nodes = 2;
    pub const levels_at = 3;
    pub const n_levels = 4;
    pub const roots_at = 5;
    pub const n_roots = 6;
    pub const regs_at = 7;
    pub const n_params = 8;
    pub const anchor = 9;
    pub const initial = 10; // M31 x, y of the trace coset's initial point
    pub const half_step = 12; // M31 x, y
    pub const step = 14; // M31 x, y
    pub const words = 16;
};
pub const Op = enum(u32) { input = 0, anchor = 1, constant = 2, parameter = 3, add = 4, sub = 5, mul = 6, neg = 7 };
pub const node_words = 4;
pub const partial_words = 16;
pub const max_roles = 3;
/// Verdict details (Check.truth_oods).
pub const Detail = enum(u16) { descriptor = 1, noncanonical = 2, zero_inverse = 3, mismatch = 4, point = 5, params = 6 };

pub const Io = extern struct {
    desc: [*]const u32,
    desc_words: u64,
    samples: [*]const u32,
    sample_words: u64,
    params: [3]?[*]const u32 = @splat(null),
    param_words: [3]u64 = @splat(0),
    alpha: [*]const u32,
    point: [*]const u32,
    scratch: [*]u32,
    scratch_words: u64,
    verdict: [*]u32,
    diag: ?[*]u32 = null,
};
comptime {
    if (@sizeOf(Io) != 128) @compileError("truth OODS Io ABI");
}
pub const CheckFn = *const fn (*anyopaque, u32, *const Io) callconv(.c) c_int;
pub const VersionFn = *const fn () callconv(.c) u32;
pub const Symbols = struct {
    check: CheckFn,
    pub fn load(addon: *std.DynLib) !Symbols {
        const v = addon.lookup(VersionFn, "stwo_rv64_truth_oods_version") orelse return error.MissingTruthOodsSymbol;
        if (v() != version) return error.TruthOodsVersionMismatch;
        return .{ .check = addon.lookup(CheckFn, "stwo_rv64_truth_oods_check_v1_on") orelse return error.MissingTruthOodsSymbol };
    }
};

/// The samples section of an enqueue-only PCS image (hybrid_pcs.decodeWords:
/// header 14, status 1, channel 16, roots 8 per tree, then 8 words/sample).
pub fn samplesOffset(trees: usize) usize {
    return 14 + 1 + 16 + 8 * trees;
}

// ---------------------------------------------------------------------------
// Descriptor (per class, warm time)
// ---------------------------------------------------------------------------

/// Mask offsets of one (tree, component-local column), in the order the
/// component's maskPoints lists them (= the PCS sample order of that column).
pub const Shifts = union(enum) {
    classic: *const T.Role.Component,
    /// V3 delegated truths (role_geometry.zig): MAIN column 0 and the last
    /// byte/wire interaction batch carry [current, previous].
    v3: *const T.V3Role.Component,
    fn of(self: Shifts, tree: usize, column: usize) []const i32 {
        const current: []const i32 = &.{0};
        const with_previous: []const i32 = &.{ 0, -1 };
        return switch (self) {
            .classic => |c| c.shifts(tree, column),
            .v3 => |c| switch (tree) {
                0 => current,
                1 => if (c.previousMain(column)) with_previous else current,
                else => if (c.previousInter(column)) with_previous else current,
            },
        };
    }
};

pub const RoleSource = struct {
    program: *const CG.Program,
    trace_log: u32,
    /// Absolute column of local column 0 per tree (the component's offsets).
    offsets: [3]usize,
    /// Tree-2 local column of the last-anchor public auxiliary (classic).
    anchor_column: ?u32 = null,
    shifts: Shifts,
};

pub const Descriptor = struct {
    a: std.mem.Allocator,
    words: []u32,
    scratch_words: usize,
    roles: u32,
    n_params: [max_roles]u32 = @splat(0),
    nodes: usize,
    levels: usize,
    /// SHA-256 of the descriptor words (computed once by `build`).
    identity: [32]u8 = @splat(0),
    pub fn deinit(self: *Descriptor) void {
        self.a.free(self.words);
        self.* = undefined;
    }
    /// Persistent device region key of the descriptor of a class.
    pub fn key(self: *const Descriptor, class_key: [32]u8) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gn-truth-oods/v1\x00");
        h.update(&class_key);
        h.update(&self.identity);
        return h.finalResult();
    }
};

fn putPoint(out: []u32, p: core.circle.CirclePointM31) void {
    out[0] = p.x.toU32();
    out[1] = p.y.toU32();
}

/// Build the descriptor. `sample_counts`: the PCS shape's per-tree,
/// original-order sample counts (4 trees: FIXED, MAIN, INTER, composition).
pub fn build(a: std.mem.Allocator, roles: []const RoleSource, sample_counts: []const []const u32, global_log: u32, split: u32) !Descriptor {
    if (roles.len == 0 or roles.len > max_roles or sample_counts.len != 4 or split == 0 or split > 4 or global_log == 0 or global_log >= 31) return error.InvalidTruthOodsShape;
    // First sample index of every (tree, column).
    var first: [4][]u32 = undefined;
    var made: usize = 0;
    defer for (first[0..made]) |f| a.free(f);
    var total: u32 = 0;
    for (sample_counts, 0..) |counts, t| {
        first[t] = try a.alloc(u32, counts.len);
        made += 1;
        for (counts, first[t]) |c, *x| {
            x.* = total;
            total += c;
        }
    }
    const comp_columns = @as(usize, 8) << @intCast(split);
    if (sample_counts[3].len != comp_columns) return error.InvalidTruthOodsShape;
    for (sample_counts[3]) |c| if (c != 1) return error.InvalidTruthOodsShape;

    var out: std.ArrayListUnmanaged(u32) = .empty;
    errdefer out.deinit(a);
    try out.appendNTimes(a, 0, H.header_words + R.words * roles.len);
    var consts: std.ArrayListUnmanaged(u32) = .empty;
    defer consts.deinit(a);
    var n_consts: u32 = 0;
    var regs: usize = 0;
    var desc = Descriptor{ .a = a, .words = &.{}, .scratch_words = 0, .roles = @intCast(roles.len), .nodes = 0, .levels = 0 };
    for (roles, 0..) |role, r| {
        const p = role.program;
        try p.validate();
        if (role.trace_log == 0 or role.trace_log > global_log) return error.InvalidTruthOodsShape;
        const n = p.nodes.len;
        // Reachable from the roots (operands precede their node).
        const live = try a.alloc(bool, n);
        defer a.free(live);
        @memset(live, false);
        for (p.roots) |root| live[root] = true;
        var i = n;
        while (i > 0) {
            i -= 1;
            if (!live[i]) continue;
            switch (p.nodes[i].op) {
                .add, .sub, .mul => {
                    live[p.nodes[i].lhs] = true;
                    live[p.nodes[i].rhs] = true;
                },
                .neg => live[p.nodes[i].lhs] = true,
                else => {},
            }
        }
        // DAG level of every live node; order by (level, index).
        const level = try a.alloc(u32, n);
        defer a.free(level);
        var max_level: u32 = 0;
        for (p.nodes, 0..) |node, k| {
            if (!live[k]) continue;
            level[k] = switch (node.op) {
                .add, .sub, .mul => 1 + @max(level[node.lhs], level[node.rhs]),
                .neg => 1 + level[node.lhs],
                else => 0,
            };
            max_level = @max(max_level, level[k]);
        }
        const n_levels: usize = max_level + 1;
        const starts = try a.alloc(u32, n_levels + 1);
        defer a.free(starts);
        @memset(starts, 0);
        var count: u32 = 0;
        for (0..n) |k| if (live[k]) {
            starts[level[k] + 1] += 1;
            count += 1;
        };
        for (1..n_levels + 1) |l| starts[l] += starts[l - 1];
        const remap = try a.alloc(u32, n);
        defer a.free(remap);
        {
            const cursor = try a.dupe(u32, starts[0..n_levels]);
            defer a.free(cursor);
            for (0..n) |k| if (live[k]) {
                remap[k] = cursor[level[k]];
                cursor[level[k]] += 1;
            };
        }
        const order = try a.alloc(u32, count);
        defer a.free(order);
        for (0..n) |k| if (live[k]) {
            order[remap[k]] = @intCast(k);
        };
        // Nodes.
        const nodes_at = out.items.len;
        const const_base = n_consts;
        for (order) |k| {
            const node = p.nodes[k];
            var w = [node_words]u32{ 0, 0, 0, 0 };
            switch (node.op) {
                .input => {
                    const in = p.inputs[node.value];
                    if (in.tree >= 3) return error.InvalidTruthOodsShape;
                    if (in.tree == 2 and role.anchor_column != null and in.column == role.anchor_column.?) {
                        if (in.offset != 0) return error.InvalidTruthOodsMask;
                        w[0] = @intFromEnum(Op.anchor);
                    } else {
                        const column = role.offsets[in.tree] + in.column;
                        if (column >= sample_counts[in.tree].len) return error.InvalidTruthOodsMask;
                        const shifts = role.shifts.of(in.tree, in.column);
                        if (shifts.len != sample_counts[in.tree][column]) return error.InvalidTruthOodsMask;
                        const at = std.mem.indexOfScalar(i32, shifts, in.offset) orelse return error.InvalidTruthOodsMask;
                        w[0] = @intFromEnum(Op.input);
                        w[1] = first[in.tree][column] + @as(u32, @intCast(at));
                    }
                },
                .constant => {
                    w[0] = @intFromEnum(Op.constant);
                    w[1] = const_base + node.value;
                },
                .parameter => {
                    w[0] = @intFromEnum(Op.parameter);
                    w[1] = node.value;
                },
                .add, .sub, .mul => {
                    w[0] = @intFromEnum(@as(Op, switch (node.op) {
                        .add => .add,
                        .sub => .sub,
                        else => .mul,
                    }));
                    w[1] = remap[node.lhs];
                    w[2] = remap[node.rhs];
                },
                .neg => {
                    w[0] = @intFromEnum(Op.neg);
                    w[1] = remap[node.lhs];
                },
                .fraction, .range_fraction => return error.InvalidTruthOodsShape,
            }
            try out.appendSlice(a, &w);
        }
        for (p.constants) |c| try consts.appendSlice(a, &c);
        n_consts += @intCast(p.constants.len);
        const levels_at = out.items.len;
        try out.appendSlice(a, starts);
        const roots_at = out.items.len;
        for (p.roots) |root| try out.append(a, remap[root]);
        const coset = canonic.CanonicCoset.new(role.trace_log).coset();
        const row = out.items[H.header_words + R.words * r ..][0..R.words];
        row[R.trace_log] = role.trace_log;
        row[R.nodes_at] = @intCast(nodes_at);
        row[R.n_nodes] = count;
        row[R.levels_at] = @intCast(levels_at);
        row[R.n_levels] = @intCast(n_levels);
        row[R.roots_at] = @intCast(roots_at);
        row[R.n_roots] = @intCast(p.roots.len);
        row[R.regs_at] = @intCast(regs);
        row[R.n_params] = @intCast(p.parameters.len);
        row[R.anchor] = @intFromBool(role.anchor_column != null);
        putPoint(row[R.initial..][0..2], coset.initial);
        putPoint(row[R.half_step..][0..2], coset.half_step);
        putPoint(row[R.step..][0..2], coset.step);
        desc.n_params[r] = @intCast(p.parameters.len);
        regs += 8 * @as(usize, count);
        desc.nodes += count;
        desc.levels += n_levels;
    }
    const consts_at = out.items.len;
    try out.appendSlice(a, consts.items);
    const hdr = out.items[0..H.header_words];
    hdr[H.magic] = magic;
    hdr[H.version] = version;
    hdr[H.words] = @intCast(out.items.len);
    hdr[H.roles] = @intCast(roles.len);
    hdr[H.global_log] = global_log;
    hdr[H.composition_log] = global_log + split;
    hdr[H.split] = split;
    hdr[H.composition_sample] = first[3][0];
    hdr[H.samples] = total;
    hdr[H.consts_at] = @intCast(consts_at);
    hdr[H.n_consts] = n_consts;
    hdr[H.partials_at] = @intCast(regs);
    hdr[H.scratch] = @intCast(regs + partial_words * max_roles);
    desc.scratch_words = regs + partial_words * max_roles;
    desc.words = try out.toOwnedSlice(a);
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(desc.words), &desc.identity, .{});
    return desc;
}

/// A truth class's geometry (truth_class.build): the legacy component
/// geometry is rebuilt claim-free (only shifts, logs and offsets are read).
pub fn fromGeometry(a: std.mem.Allocator, g: anytype) !Descriptor {
    const shape = g.shape;
    if (shape.trees.len != 4) return error.InvalidTruthOodsShape;
    var counts: [4][]const u32 = undefined;
    for (shape.trees, 0..) |t, i| counts[i] = t.sample_counts;
    var recs: [max_roles]Fixtures.Record = undefined;
    var made: usize = 0;
    defer for (recs[0..made]) |*r| r.artifact.deinit();
    var roles: [max_roles]RoleSource = undefined;
    if (g.kind == .classic) {
        if (g.roles.len != 3) return error.InvalidTruthOodsShape;
        const policy = g.truth.keccak.setup.policy;
        const kinds = [3]T.Role.Kind{ .keccak, .chi, .xor5 };
        var comps: [3]T.Role.Component = undefined;
        var offsets: [3]usize = .{ 0, 0, 0 };
        for (&comps, kinds, 0..) |*c, k, i| {
            c.* = .{ .kind = k, .log_size = if (i == 0) g.log else policy.tableLog(if (i == 1) .chi else .xor5), .keccak_policy = policy, .local = std.mem.zeroes(@FieldType(T.Role.Component, "local")), .shared = std.mem.zeroes(@FieldType(T.Role.Component, "shared")), .claim = O.zero(), .global_claim = O.zero(), .split = 2 };
            c.offsets = offsets;
            for (c.widths(), 0..) |w, t| offsets[t] += w;
            recs[i] = try Fixtures.record(a, g.roles[i].interaction.id);
            made += 1;
            const anchor = recs[i].artifact.last_anchor_column;
            if (anchor == std.math.maxInt(usize)) return error.InvalidTruthOodsShape;
            roles[i] = .{ .program = &recs[i].artifact.program, .trace_log = c.log_size, .offsets = c.offsets, .anchor_column = @intCast(anchor), .shifts = .{ .classic = c } };
        }
        return build(a, roles[0..3], &counts, g.mask_log, g.split);
    }
    if (g.roles.len != 1) return error.InvalidTruthOodsShape;
    const v3 = T.V3Role.Component{ .truth = g.truth, .wire = std.mem.zeroes(@FieldType(T.V3Role.Component, "wire")) };
    recs[0] = try Fixtures.record(a, g.roles[0].interaction.id);
    made += 1;
    if (recs[0].artifact.last_anchor_column != std.math.maxInt(usize)) return error.InvalidTruthOodsShape;
    roles[0] = .{ .program = &recs[0].artifact.program, .trace_log = v3.logSize(), .offsets = .{ v3.offsets[0], v3.offsets[1], v3.inter_offset }, .shifts = .{ .v3 = &v3 } };
    return build(a, roles[0..1], &counts, g.mask_log, g.split);
}

// ---------------------------------------------------------------------------
// Host mirror (bit-exact with truth_oods.cu)
// ---------------------------------------------------------------------------

pub const Result = struct { verdict: u32, evaluated: [8]u32 = @splat(0), extracted: [8]u32 = @splat(0) };

fn felt(w: []const u32) O {
    var limbs: [8]M = undefined;
    for (&limbs, w[0..8]) |*l, x| l.* = M.fromU64(x);
    return O.fromM31Array(limbs);
}
fn canonicalWords(w: []const u32) bool {
    for (w[0..8]) |x| if (x >= core.fields.m31.Modulus) return false;
    return true;
}
fn words8(v: O) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, v.toM31Array()) |*o, m| o.* = m.toU32();
    return out;
}
fn mpoint(x: u32, y: u32) Point {
    return .{ .x = O.fromBase(M.fromCanonical(x)), .y = O.fromBase(M.fromCanonical(y)) };
}
fn cosetVanishing(row: []const u32, p_in: Point) O {
    const p = p_in.sub(mpoint(row[R.initial], row[R.initial + 1])).add(mpoint(row[R.half_step], row[R.half_step + 1]));
    var x = p.x;
    for (1..row[R.trace_log]) |_| {
        const s = x.mul(x);
        x = s.add(s).sub(O.one());
    }
    return x;
}
fn reject(d: Detail) Result {
    return .{ .verdict = G.Verdict.reject(.truth_oods, @intFromEnum(d)) };
}

/// The kernel's verdict and diagnostic on host words. `params[r]`: role r's
/// gathered parameters (8 words each); `point`: the 33-word OODS field.
pub fn evaluate(a: std.mem.Allocator, desc: []const u32, samples: []const u32, params: []const []const u32, alpha_words: []const u32, point_words: []const u32) !Result {
    const d = desc;
    if (d.len < H.header_words or d[H.magic] != magic or d[H.version] != version or d[H.words] != d.len or d[H.roles] == 0 or d[H.roles] > max_roles or H.header_words + R.words * @as(usize, d[H.roles]) > d.len or @as(usize, d[H.samples]) * 8 > samples.len) return reject(.descriptor);
    if (!canonicalWords(point_words[0..8]) or !canonicalWords(point_words[8..16]) or !canonicalWords(alpha_words)) return reject(.noncanonical);
    if (point_words[32] != 0) return reject(.point);
    const point = Point{ .x = felt(point_words[0..8]), .y = felt(point_words[8..16]) };
    const alpha = felt(alpha_words);
    var acc = O.zero();
    for (0..d[H.roles]) |r| {
        const row = d[H.header_words + R.words * r ..][0..R.words];
        if (r >= params.len or params[r].len < 8 * @as(usize, row[R.n_params])) return reject(.descriptor);
        for (0..row[R.n_params]) |i| if (!canonicalWords(params[r][8 * i ..][0..8])) return reject(.params);
        var local = point;
        for (row[R.trace_log]..d[H.global_log]) |_| local = local.double();
        var anchor = O.zero();
        if (row[R.anchor] != 0) {
            const p = local.add(mpoint(row[R.step], row[R.step + 1]));
            const num = cosetVanishing(row, p);
            const h = p.sub(mpoint(row[R.initial], row[R.initial + 1]));
            const hx1 = h.x.add(O.one());
            if (hx1.isZero() or h.y.isZero()) return reject(.zero_inverse);
            const pv = h.y.mul(try hx1.inv());
            const den = pv.mulBase(M.fromU64(@as(u64, 1) << @intCast(row[R.trace_log])));
            if (den.isZero()) return reject(.zero_inverse);
            anchor = num.mul(try den.inv());
        }
        const n: usize = row[R.n_nodes];
        const values = try a.alloc(O, n);
        defer a.free(values);
        const levels = d[row[R.levels_at]..][0 .. row[R.n_levels] + 1];
        for (0..row[R.n_levels]) |l| {
            const begin = levels[l];
            const end = levels[l + 1];
            if (begin > end or end > n) return reject(.descriptor);
            for (begin..end) |i| {
                const w = d[row[R.nodes_at] + node_words * i ..][0..node_words];
                values[i] = switch (w[0]) {
                    @intFromEnum(Op.input) => if (w[1] >= d[H.samples]) return reject(.descriptor) else felt(samples[8 * @as(usize, w[1]) ..]),
                    @intFromEnum(Op.anchor) => if (row[R.anchor] == 0) return reject(.descriptor) else anchor,
                    @intFromEnum(Op.constant) => if (w[1] >= d[H.n_consts]) return reject(.descriptor) else felt(d[d[H.consts_at] + 8 * @as(usize, w[1]) ..]),
                    @intFromEnum(Op.parameter) => if (w[1] >= row[R.n_params]) return reject(.descriptor) else felt(params[r][8 * @as(usize, w[1]) ..]),
                    @intFromEnum(Op.add), @intFromEnum(Op.sub), @intFromEnum(Op.mul) => blk: {
                        if (w[1] >= begin or w[2] >= begin) return reject(.descriptor);
                        const x = values[w[1]];
                        const y = values[w[2]];
                        break :blk if (w[0] == @intFromEnum(Op.add)) x.add(y) else if (w[0] == @intFromEnum(Op.sub)) x.sub(y) else x.mul(y);
                    },
                    @intFromEnum(Op.neg) => if (w[1] >= begin) return reject(.descriptor) else O.zero().sub(values[w[1]]),
                    else => return reject(.descriptor),
                };
            }
        }
        const vanishing = cosetVanishing(row, local);
        if (vanishing.isZero()) return reject(.zero_inverse);
        const inv = try vanishing.inv();
        var h = O.zero();
        for (d[row[R.roots_at]..][0..row[R.n_roots]]) |root| {
            if (root >= n) return reject(.descriptor);
            h = h.mul(alpha).add(values[root].mul(inv));
        }
        acc = acc.mul(alpha.pow(row[R.n_roots])).add(h);
    }
    const chunks = @as(usize, 1) << @intCast(d[H.split]);
    var chunk: [16]O = undefined;
    for (0..chunks) |c| {
        var e: [8]O = undefined;
        for (&e, 0..) |*v, k| v.* = felt(samples[8 * (d[H.composition_sample] + c * 8 + k) ..]);
        chunk[c] = O.fromPartialEvals(e);
    }
    var active = chunks;
    var parent_log: u32 = d[H.composition_log] - d[H.split] + 1;
    while (active > 1) {
        const f = point.repeatedDouble(parent_log - 2);
        var o: usize = 0;
        var i: usize = 0;
        while (i < active) : (i += 2) {
            chunk[o] = chunk[i].add(f.x.mul(chunk[i + 1]));
            o += 1;
        }
        active /= 2;
        parent_log += 1;
    }
    const res = Result{ .verdict = if (acc.eql(chunk[0])) G.Verdict.accepted else G.Verdict.reject(.truth_oods, @intFromEnum(Detail.mismatch)), .evaluated = words8(acc), .extracted = words8(chunk[0]) };
    return res;
}

// ---------------------------------------------------------------------------
// Device enqueue
// ---------------------------------------------------------------------------

pub const Inputs = struct {
    desc: api.DeviceBuffer,
    /// The PCS image (enqueue-only PcsJob output words) and its tree count.
    pcs: api.DeviceBuffer,
    trees: usize,
    params: [max_roles]?api.DeviceBuffer = @splat(null),
    alpha: api.DeviceBuffer,
    point: api.DeviceBuffer,
    scratch: api.DeviceBuffer,
    verdict: api.DeviceBuffer,
    diag: ?api.DeviceBuffer = null,
};

fn check(rc: c_int) !void {
    if (rc != 0) return error.CudaEnqueueFailed;
}

/// Enqueue the check (two launches, lane 0). `host` is the descriptor's host
/// copy (launch-time span validation only; the kernel re-validates).
pub fn enqueue(sym: *const Symbols, ctx: *anyopaque, host: *const Descriptor, in: Inputs) !void {
    const samples_at = samplesOffset(in.trees);
    const sample_words = 8 * @as(usize, host.words[H.samples]);
    if (in.desc.words != host.words.len or in.pcs.words < samples_at + sample_words or in.scratch.words < host.scratch_words or in.alpha.words < 8 or in.point.words < 33 or in.verdict.words < 1) return error.InvalidTruthOodsSpan;
    var io = Io{ .desc = in.desc.ptr, .desc_words = in.desc.words, .samples = in.pcs.ptr + samples_at, .sample_words = sample_words, .alpha = in.alpha.ptr, .point = in.point.ptr, .scratch = in.scratch.ptr, .scratch_words = host.scratch_words, .verdict = in.verdict.ptr, .diag = if (in.diag) |b| b.ptr else null };
    for (0..host.roles) |r| {
        const p = in.params[r] orelse return error.InvalidTruthOodsSpan;
        if (p.words < 8 * @as(usize, host.n_params[r])) return error.InvalidTruthOodsSpan;
        if (host.n_params[r] != 0) {
            io.params[r] = p.ptr;
            io.param_words[r] = 8 * @as(usize, host.n_params[r]);
        }
    }
    if (in.diag) |b| if (b.words < 16) return error.InvalidTruthOodsSpan;
    try check(sym.check(ctx, 0, &io));
}

// ---------------------------------------------------------------------------
// Tests (host): the descriptor + mirror equal the engine's point evaluation.
// ---------------------------------------------------------------------------

const testing = std.testing;
const engine = @import("stwo_prover_engine");
const CP = engine.air.component_prover.ForField(O);
const Air = core.air.components.ForField(O);

fn dense(seed: u64) O {
    var x = seed *% 0x9e37_79b9_7f4a_7c15 +% 1;
    var limbs: [8]M = undefined;
    for (&limbs) |*l| {
        x ^= x >> 29;
        x *%= 0xbf58_476d_1ce4_e5b9;
        x ^= x >> 32;
        l.* = M.fromU64(x % core.fields.m31.Modulus);
    }
    return O.fromM31Array(limbs);
}

/// Engine reference vs descriptor mirror on random masks over the given
/// components (in prover order) and their composition programs.
fn compareEngine(a: std.mem.Allocator, provers: []const CP.ComponentProver, roles: []const RoleSource, n_fixed: usize, params: []const []const u32, seed: u64) !void {
    const set = CP.ComponentProvers{ .components = provers, .n_preprocessed_columns = n_fixed };
    const comp_log: u32 = @intCast(set.compositionLogDegreeBound());
    const split: u32 = @intCast(try set.compositionLogSplit());
    const mask_log: u32 = @intCast(core.verifier_types.compositionMaskLogSize(comp_log, split) orelse return error.InvalidStructure);
    var view = try set.componentsView(a);
    defer view.deinit(a);
    const point = Point{ .x = dense(seed + 1), .y = dense(seed + 2) };
    var masks = try view.maskPointsWithWorkCapture(a, point, mask_log, false, null);
    defer masks.deinitDeep(a);
    // Random sampled values in the mask shape; composition tree appended.
    var counts: [4][]u32 = undefined;
    var values: [3][][]O = undefined;
    var k: u64 = 0;
    for (0..3) |t| {
        counts[t] = try a.alloc(u32, masks.items[t].len);
        values[t] = try a.alloc([]O, masks.items[t].len);
        for (masks.items[t], counts[t], values[t]) |col, *c, *v| {
            c.* = @intCast(col.len);
            v.* = try a.alloc(O, col.len);
            for (v.*) |*x| {
                x.* = dense(seed * 7919 + k);
                k += 1;
            }
        }
    }
    defer for (0..3) |t| {
        for (values[t]) |v| a.free(v);
        a.free(values[t]);
        a.free(counts[t]);
    };
    counts[3] = try a.alloc(u32, @as(usize, 8) << @intCast(split));
    defer a.free(counts[3]);
    @memset(counts[3], 1);
    var tree_values = [3][][]O{ values[0], values[1], values[2] };
    const mask_values = Air.MaskValues{ .items = &tree_values };
    const alpha = dense(seed + 3);
    const expected = try view.asCore().evalCompositionPolynomialAtPoint(point, &mask_values, alpha, mask_log);
    var desc = try build(a, roles, &.{ counts[0], counts[1], counts[2], counts[3] }, mask_log, split);
    defer desc.deinit();
    // Flat samples (tree, column, mask) + composition chunks of `expected`
    // split so that extraction reconstructs `expected` (chunk 0 = expected, rest 0).
    var samples: std.ArrayListUnmanaged(u32) = .empty;
    defer samples.deinit(a);
    for (0..3) |t| for (values[t]) |col| for (col) |v| try samples.appendSlice(a, &words8(v));
    const comp_at = samples.items.len / 8;
    try samples.appendNTimes(a, 0, 8 * counts[3].len);
    // chunk 0 coordinates: fromPartialEvals(e) with e[k] = coordinate k as base.
    const coords = expected.toM31Array();
    for (0..8) |c| samples.items[8 * (comp_at + c)] = coords[c].toU32();
    var point_words: [33]u32 = @splat(0);
    @memcpy(point_words[0..8], &words8(point.x));
    @memcpy(point_words[8..16], &words8(point.y));
    const res = try evaluate(a, desc.words, samples.items, params, &words8(alpha), &point_words);
    try testing.expectEqualSlices(u32, &words8(expected), &res.evaluated);
    try testing.expectEqual(G.Verdict.accepted, res.verdict);
    // One read trace sample changed, or one composition sample: the check fires (mismatch).
    const mismatch = G.Verdict.reject(.truth_oods, @intFromEnum(Detail.mismatch));
    const row = desc.words[H.header_words..][0..R.words];
    const read: usize = for (0..row[R.n_nodes]) |i| {
        const w = desc.words[row[R.nodes_at] + node_words * i ..][0..node_words];
        if (w[0] == @intFromEnum(Op.input)) break w[1];
    } else return error.TestNoInputNode;
    samples.items[8 * read] = (samples.items[8 * read] + 1) % core.fields.m31.Modulus;
    try testing.expectEqual(mismatch, (try evaluate(a, desc.words, samples.items, params, &words8(alpha), &point_words)).verdict);
    samples.items[8 * read] = (samples.items[8 * read] + core.fields.m31.Modulus - 1) % core.fields.m31.Modulus;
    try testing.expectEqual(G.Verdict.accepted, (try evaluate(a, desc.words, samples.items, params, &words8(alpha), &point_words)).verdict);
    samples.items[8 * (comp_at + 9)] ^= 1;
    try testing.expectEqual(mismatch, (try evaluate(a, desc.words, samples.items, params, &words8(alpha), &point_words)).verdict);
}

fn paramWords(a: std.mem.Allocator, artifact: *const T.Artifact, values: []const O) ![]u32 {
    const out = try a.alloc(u32, 8 * artifact.parameter_slots.len);
    for (artifact.parameter_slots, 0..) |slot, i| @memcpy(out[8 * i ..][0..8], &words8(values[slot]));
    return out;
}

test "classic truth: descriptor point evaluation equals the engine (keccak, chi, xor5; both policies)" {
    const a = testing.allocator;
    for ([_]@TypeOf(@as(T.Role.Component, undefined).keccak_policy){ .throughput_r27_v1, .triple_v2 }, 0..) |policy, pi| {
        var comps: [3]T.Role.Component = undefined;
        const kinds = [3]T.Role.Kind{ .keccak, .chi, .xor5 };
        var offsets: [3]usize = .{ 0, 0, 0 };
        var s: u64 = 100 * (pi + 1);
        for (&comps, kinds, 0..) |*c, kind, i| {
            c.* = .{ .kind = kind, .log_size = if (i == 0) 7 else policy.tableLog(if (i == 1) .chi else .xor5), .calls = if (i == 0) 5 else 0, .first_id = if (i == 0) 3 else 1, .keccak_policy = policy, .local = std.mem.zeroes(@FieldType(T.Role.Component, "local")), .shared = std.mem.zeroes(@FieldType(T.Role.Component, "shared")), .claim = dense(s), .global_claim = if (i == 0) dense(s + 1) else O.zero(), .split = 2 };
            c.local.polynomial = dense(s + 2);
            for (&c.local.offsets, 0..) |*v, j| v.* = dense(s + 10 + j);
            for (&c.local.coefficients, 0..) |*row, j| for (row, 0..) |*v, l| {
                v.* = dense(s + 100 + 6 * j + l);
            };
            inline for (.{ "ram", "kio", "wire" }) |name| {
                @field(c.shared, name).offset = dense(s + 200);
                for (&@field(c.shared, name).coefficients, 0..) |*v, j| v.* = dense(s + 300 + j);
            }
            c.offsets = offsets;
            for (c.widths(), 0..) |w, t| offsets[t] += w;
            s += 1000;
        }
        var recs: [3]Fixtures.Record = undefined;
        var made: usize = 0;
        defer for (recs[0..made]) |*r| r.artifact.deinit();
        var roles: [3]RoleSource = undefined;
        var params: [3][]u32 = undefined;
        var pmade: usize = 0;
        defer for (params[0..pmade]) |p| a.free(p);
        var provers: [3]CP.ComponentProver = undefined;
        for (&comps, 0..) |*c, i| {
            recs[i] = try Fixtures.record(a, try T.classicKernelId(policy, c.kind));
            made += 1;
            roles[i] = .{ .program = &recs[i].artifact.program, .trace_log = c.log_size, .offsets = c.offsets, .anchor_column = @intCast(recs[i].artifact.last_anchor_column), .shifts = .{ .classic = c } };
            params[i] = try paramWords(a, &recs[i].artifact, &T.nativeMetadata(c));
            pmade += 1;
            provers[i] = c.asProverComponent();
        }
        const n_fixed = offsets[0];
        try compareEngine(a, &provers, &roles, n_fixed, &.{ params[0], params[1], params[2] }, 17 + pi);
    }
}

test "descriptor refuses a corrupted header and a forward operand" {
    const a = testing.allocator;
    const policy: @TypeOf(@as(T.Role.Component, undefined).keccak_policy) = .triple_v2;
    var c = T.Role.Component{ .kind = .chi, .log_size = policy.tableLog(.chi), .keccak_policy = policy, .local = std.mem.zeroes(@FieldType(T.Role.Component, "local")), .shared = std.mem.zeroes(@FieldType(T.Role.Component, "shared")), .claim = O.zero(), .split = 2 };
    var rec = try Fixtures.record(a, try T.classicKernelId(policy, .chi));
    defer rec.artifact.deinit();
    const w = c.widths();
    var counts: [4][]u32 = undefined;
    for (0..3) |t| {
        counts[t] = try a.alloc(u32, w[t]);
        for (counts[t], 0..) |*x, col| x.* = @intCast(c.shifts(t, col).len);
    }
    counts[3] = try a.alloc(u32, 32);
    @memset(counts[3], 1);
    defer for (counts) |x| a.free(x);
    const role = RoleSource{ .program = &rec.artifact.program, .trace_log = c.log_size, .offsets = .{ 0, 0, 0 }, .anchor_column = @intCast(rec.artifact.last_anchor_column), .shifts = .{ .classic = &c } };
    var desc = try build(a, &.{role}, &.{ counts[0], counts[1], counts[2], counts[3] }, c.log_size + 1, 2);
    defer desc.deinit();
    var total: usize = 0;
    for (counts) |x| for (x) |v| {
        total += v;
    };
    const samples = try a.alloc(u32, 8 * total);
    defer a.free(samples);
    @memset(samples, 1);
    const params = try a.alloc(u32, 8 * rec.artifact.parameter_slots.len + 8);
    defer a.free(params);
    @memset(params, 2);
    var point: [33]u32 = @splat(3);
    point[32] = 0;
    const alpha: [8]u32 = @splat(5);
    // Accepted geometry evaluates (verdict is mismatch or accepted, never descriptor).
    const ok = try evaluate(a, desc.words, samples, &.{params}, &alpha, &point);
    try testing.expect(ok.verdict != G.Verdict.reject(.truth_oods, @intFromEnum(Detail.descriptor)));
    desc.words[H.magic] ^= 1;
    try testing.expectEqual(G.Verdict.reject(.truth_oods, @intFromEnum(Detail.descriptor)), (try evaluate(a, desc.words, samples, &.{params}, &alpha, &point)).verdict);
    desc.words[H.magic] ^= 1;
    point[32] = 1;
    try testing.expectEqual(G.Verdict.reject(.truth_oods, @intFromEnum(Detail.point)), (try evaluate(a, desc.words, samples, &.{params}, &alpha, &point)).verdict);
    point[32] = 0;
    // A binary node reading its own level is refused.
    const row = desc.words[H.header_words..][0..R.words];
    const last_level = desc.words[row[R.levels_at] + row[R.n_levels] - 1];
    const node = desc.words[row[R.nodes_at] + node_words * last_level ..][0..node_words];
    if (node[0] == @intFromEnum(Op.add) or node[0] == @intFromEnum(Op.mul) or node[0] == @intFromEnum(Op.sub)) {
        const lhs = node[1];
        node[1] = last_level;
        try testing.expectEqual(G.Verdict.reject(.truth_oods, @intFromEnum(Detail.descriptor)), (try evaluate(a, desc.words, samples, &.{params}, &alpha, &point)).verdict);
        node[1] = lhs;
    }
    // An anchor read in a role without the anchor flag is refused (the
    // kernel would otherwise read its never-written anchor value).
    const nodes = desc.words[row[R.nodes_at]..][0 .. node_words * row[R.n_nodes]];
    var anchored = false;
    var i: usize = 0;
    while (i < nodes.len) : (i += node_words) anchored = anchored or nodes[i] == @intFromEnum(Op.anchor);
    try testing.expect(anchored);
    try testing.expectEqual(@as(u32, 1), row[R.anchor]);
    try testing.expect((try evaluate(a, desc.words, samples, &.{params}, &alpha, &point)).verdict != G.Verdict.reject(.truth_oods, @intFromEnum(Detail.descriptor)));
    row[R.anchor] = 0;
    try testing.expectEqual(G.Verdict.reject(.truth_oods, @intFromEnum(Detail.descriptor)), (try evaluate(a, desc.words, samples, &.{params}, &alpha, &point)).verdict);
}
