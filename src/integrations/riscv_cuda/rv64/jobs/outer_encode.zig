//! Device proof encoding (GPU-native design rv64-m8-gpu-native.md §3.3-§3.5,
//! host work H22/H25; kernel NAT/rv64/jobs/outer_encode.cu).
//!
//! The enqueue-only PCS (`stwo_rv64_pcs_job_enqueue_v1`) leaves its compact
//! readback image (hybrid_pcs.decodeWords layout) in device memory. Today the
//! host decodes it (`hybrid_pcs.decodeWords` -> `pcs_assembly.assemble`: query
//! dedup, lifted-Merkle and FRI decommitment witnesses) and serialises the
//! proof (`stwo_proof_wire.encodeProofBytesBinary`, om31 `wire.encode`). This
//! file and its kernel do the same on the device: from the image, a per-class
//! descriptor (shape constants, built once per class at warm) and the node's
//! claims / expected outputs, one block writes the exact proof bytes into the
//! request slab's encoded region and two Verdict words:
//!   node_pcs_status  everything `decodeWords` + `checkRoots` + the outer
//!                    section decode refuse (header, numerical/channel
//!                    latches, roots, query range, canonical values,
//!                    duplicate-query consistency, section status latches,
//!                    canonical claims / outputs);
//!   encode_bounds    the bytes fit the region's capacity (else length 0).
//! No challenge, no arithmetic, no hashing: a pure re-layout, so equal inputs
//! give equal bytes by construction, and the receipts compare them with the
//! host bytes (STWO_RV64_M8_OUTER_DEVICE_ENCODE=check, outer_job_factory.zig).
//!
//! The physical part (`encodeProofBytesBinary`) is format generic: native
//! segments (WP.encodePhysical) use the same writer with `envelope = null`.
//!
//! `encodeHost` is the host mirror of the kernel: the same phases, the same
//! sorted-merge decommitment walk and the same bsearch consistency checks
//! (no hash maps), so a kernel/host difference is a port bug the parity run
//! names, and the reference-semantics tests below pin the mirror against a
//! transliteration of the host assembler (hash maps, like trace.zig/fri.zig).
const std = @import("std");
const G = @import("gpu_native.zig");

pub const modulus: u32 = 0x7fff_ffff;
pub const max_trees = 4;
pub const max_layers = 28;
pub const max_queries = 1024;
pub const max_columns = 65536;
pub const image_magic: u32 = 0x5256_4d4f; // pcs readback "OMVR"
pub const descriptor_magic: u32 = 0x434e_454f; // "OENC"
pub const descriptor_version: u32 = 1;

/// Descriptor header word indices (all u32).
pub const D = struct {
    pub const magic = 0;
    pub const version = 1;
    pub const words = 2;
    pub const flags = 3; // bit 0: om31 wire envelope
    pub const trees = 4;
    pub const queries = 5;
    pub const degree_log = 6;
    pub const layers = 7;
    pub const initial_log = 8;
    pub const blowup = 9;
    pub const samples = 10;
    pub const outputs = 11;
    pub const claims = 12;
    pub const latches = 13;
    pub const image_words = 14;
    pub const max_payload_words = 15;
    pub const scratch_words = 16;
    pub const max_ops = 17;
    pub const total_columns = 18;
    pub const config = 24; // 6: pow_bits, log_blowup, log_last_layer, n_queries, fold_step, lifting|0xffffffff
    pub const phys_magic = 30; // 2 words
    pub const envelope = 32; // 18 words: "STWOCOM1" + profile + authority
    pub const fixed_root = 50; // 8 words: class-constant expected root (outer FIXED)
    pub const fri = 64; // max_layers x 4: count, fold_step, leaf_log, shift
    pub const tree_table = fri + 4 * max_layers; // max_trees x 4: columns, tree_log, table offset, samples
    pub const tables = tree_table + 4 * max_trees; // per tree 4 x columns: logs_sorted, sorted_to_original, original_to_sorted, sample_counts
    pub const flag_envelope: u32 = 1;
};
comptime {
    if (D.envelope + 18 > D.fixed_root or D.fixed_root + 8 > D.fri) @compileError("descriptor header overlap");
}

/// node_pcs_status detail codes (kernel enum PcsDetail).
pub const PcsDetail = enum(u16) {
    descriptor = 1,
    image_length = 2,
    header = 3,
    numerical = 4,
    channel = 5,
    root = 6,
    query_range = 7,
    noncanonical = 8,
    trace_inconsistent = 9,
    fri_inconsistent = 10,
    section_latch = 11,
    noncanonical_public = 12,
    geometry = 13, // reserved
};
/// Check order of the details (host mirror order; the kernel keeps the
/// lowest rank when several threads fail, so both report the same detail).
pub const detail_order = [_]PcsDetail{ .descriptor, .image_length, .header, .numerical, .channel, .root, .section_latch, .noncanonical_public, .query_range, .noncanonical, .trace_inconsistent, .fri_inconsistent };
/// encode_bounds detail codes.
pub const BoundsDetail = enum(u16) { capacity = 1, input_rejected = 2 };

pub const FriLayer = struct { count: u32, fold_step: u32, leaf_log: u32, shift: u32 };
pub const Config = struct {
    pow_bits: u32,
    log_blowup: u32,
    log_last_layer: u32,
    n_queries: u32,
    fold_step: u32,
    lifting: ?u32,
};
pub const TreeShape = struct {
    /// Original PCS column order.
    coefficient_logs: []const u32,
    sorted_to_original: []const u32,
    sample_counts: []const u32,
};
/// Plain mirror of pcs_assembly.Shape (that file needs stwo_core; the
/// conversion lives in outer_job_factory.zig).
pub const Shape = struct { config: Config, degree_log: u32, trees: []const TreeShape };
pub const Envelope = struct {
    /// "STWOCOM1" + sha256(domain name) + authority identity.
    prefix: [72]u8,
    n_outputs: u32,
    n_claims: u32,
    /// Section words that must be zero (outer_plan.Section.status latches).
    latches: u32,
};

/// FRI plan (fri.zig Plan.init, same refusals).
pub fn friPlan(degree_log: u32, c: Config, out: *[max_layers]FriLayer) !u32 {
    if (c.log_last_layer != 0 or c.log_blowup < 1 or c.log_blowup > 16 or c.fold_step < 1 or c.fold_step > 4 or degree_log < c.fold_step or degree_log > 28 - c.log_blowup or c.n_queries == 0 or c.n_queries > max_queries) return error.UnsupportedFriGeometry;
    var n: u32 = 0;
    var remaining = degree_log;
    while (remaining > 0) {
        const step = @min(c.fold_step, remaining);
        out[n] = .{ .count = @as(u32, 1) << @intCast(remaining + c.log_blowup), .fold_step = step, .leaf_log = if (step > 1) 2 else 0, .shift = degree_log - remaining };
        n += 1;
        remaining -= step;
    }
    return n;
}
fn layerHeight(l: FriLayer) u32 {
    return std.math.log2_int(u32, l.count) - l.leaf_log;
}

/// Image word offsets (hybrid_pcs.decodeWords order).
pub const Image = struct {
    roots: u64,
    samples: u64,
    nonce: u64,
    terminal: u64,
    queries: u64,
    layer_root: [max_layers]u64 = @splat(0),
    layer_values: [max_layers]u64 = @splat(0),
    layer_paths: [max_layers]u64 = @splat(0),
    tree_values: [max_trees]u64 = @splat(0),
    tree_paths: [max_trees]u64 = @splat(0),
    words: u64,
    pub fn of(desc: []const u32) Image {
        const t = desc[D.trees];
        const q: u64 = desc[D.queries];
        var im = Image{ .roots = 31, .samples = 0, .nonce = 0, .terminal = 0, .queries = 0, .words = 0 };
        im.samples = im.roots + @as(u64, t) * 8;
        im.nonce = im.samples + @as(u64, desc[D.samples]) * 8;
        im.terminal = im.nonce + 2;
        im.queries = im.terminal + 8;
        var at = im.queries + q;
        for (0..desc[D.layers]) |l| {
            const f = layer(desc, @intCast(l));
            im.layer_root[l] = at;
            im.layer_values[l] = at + 8;
            im.layer_paths[l] = at + 8 + ((q << @intCast(f.fold_step)) * 8);
            at = im.layer_paths[l] + (q << @intCast(f.fold_step - f.leaf_log)) * layerHeight(f) * 8;
        }
        for (0..t) |ti| {
            const tr = tree(desc, @intCast(ti));
            im.tree_values[ti] = at;
            im.tree_paths[ti] = at + @as(u64, tr.columns) * q;
            at = im.tree_paths[ti] + q * tr.tree_log * 8;
        }
        im.words = at;
        return im;
    }
};

pub fn layer(desc: []const u32, l: u32) FriLayer {
    const b = D.fri + 4 * l;
    return .{ .count = desc[b], .fold_step = desc[b + 1], .leaf_log = desc[b + 2], .shift = desc[b + 3] };
}
pub const TreeRow = struct { columns: u32, tree_log: u32, table: u32, samples: u32 };
pub fn tree(desc: []const u32, t: u32) TreeRow {
    const b = D.tree_table + 4 * t;
    return .{ .columns = desc[b], .tree_log = desc[b + 1], .table = desc[b + 2], .samples = desc[b + 3] };
}

/// Lifted-Merkle row mapping (trace.zig position).
pub fn position(row: u64, from: u32, to: u32) u64 {
    return if (from >= to) ((row >> @intCast(from - to + 1)) << 1) | (row & 1) else ((row >> 1) << @intCast(to - from + 1)) | (row & 1);
}

/// Worst-case node count at a Merkle level when `q` leaves are queried in a
/// tree of 2^height leaves (every level holds at most min(q, 2^(height-l))).
fn levelBound(q: u64, height: u32, level: u32) u64 {
    return @min(q, @as(u64, 1) << @intCast(height - level));
}

pub const Bounds = struct { payload_words: u64, ops: u64, scratch_words: u64 };

/// Class bounds: the largest payload any image of this class can encode
/// (every query distinct, no paired siblings), the op list and scratch the
/// kernel needs. Exact formulas, mirrored by the kernel's refusals.
pub fn bounds(desc: []const u32) Bounds {
    const t = desc[D.trees];
    const q: u64 = desc[D.queries];
    var ops: u64 = 0;
    var scratch: u64 = 0;
    var payload: u64 = 2 + 6 + 1 + 8 * @as(u64, t); // magic, config, commitments
    payload += 1; // sampled count
    for (0..t) |ti| {
        const tr = tree(desc, @intCast(ti));
        payload += 1 + tr.columns + 8 * @as(u64, tr.samples);
        ops += tr.columns;
    }
    payload += 1 + 1; // decommitment count, queried count
    for (0..t) |ti| {
        const tr = tree(desc, @intCast(ti));
        var witness: u64 = 0;
        for (0..tr.tree_log) |lv| witness += levelBound(q, tr.tree_log, @intCast(lv));
        payload += 1 + 8 * witness;
        payload += 1 + @as(u64, tr.columns) * (1 + q);
        ops += witness;
        scratch += 2 * witness + 2 * q; // level lists (node, rep) incl. level 0
        scratch += (tr.tree_log + 1) * q; // canonical per distinct log
        scratch += q; // tree positions
    }
    payload += 2; // nonce
    for (0..desc[D.layers]) |l| {
        const f = layer(desc, @intCast(l));
        const h = layerHeight(f);
        const slots: u64 = @as(u64, 1) << @intCast(f.fold_step - f.leaf_log);
        const leaves = q * slots;
        var hw: u64 = 0;
        for (0..h) |lv| hw += levelBound(leaves, h, @intCast(lv));
        const fw = q << @intCast(f.fold_step);
        payload += 1 + 8 * fw + 1 + 8 * hw + 8;
        ops += fw + hw;
        scratch += 2 * (hw + leaves) + q; // level lists + group rep per raw query
    }
    payload += 1; // inner layer count
    payload += 1 + 8; // last layer poly
    if (desc[D.flags] & D.flag_envelope != 0) payload += 18 + 1 + 4 * @as(u64, desc[D.outputs]) + 8 * @as(u64, desc[D.claims]) + 1;
    scratch += 3 * ops;
    return .{ .payload_words = payload, .ops = ops, .scratch_words = scratch };
}

/// Per-class descriptor (host, at warm; uploaded once per GPU into the class
/// region). Refuses every shape the host assembler refuses.
pub fn buildDescriptor(a: std.mem.Allocator, shape: Shape, envelope: ?Envelope, fixed_root: ?[8]u32) ![]u32 {
    var fri: [max_layers]FriLayer = undefined;
    const layers = try friPlan(shape.degree_log, shape.config, &fri);
    if (shape.trees.len == 0 or shape.trees.len > max_trees) return error.InvalidPcsShape;
    var words: usize = D.tables;
    var samples: u64 = 0;
    var total: u64 = 0;
    for (shape.trees) |t| {
        const n = t.coefficient_logs.len;
        if (n == 0 or n > max_columns or t.sorted_to_original.len != n or t.sample_counts.len != n) return error.InvalidPcsShape;
        for (t.coefficient_logs, t.sample_counts) |log, count| {
            if (log < 1 or log > 28 - shape.config.log_blowup or count > 5 or (count != 0 and log > shape.degree_log)) return error.InvalidPcsShape;
            samples += count;
        }
        words += 4 * n;
        total += n;
    }
    const d = try a.alloc(u32, words);
    errdefer a.free(d);
    @memset(d, 0);
    d[D.magic] = descriptor_magic;
    d[D.version] = descriptor_version;
    d[D.words] = @intCast(words);
    d[D.trees] = @intCast(shape.trees.len);
    d[D.queries] = shape.config.n_queries;
    d[D.degree_log] = shape.degree_log;
    d[D.layers] = layers;
    d[D.initial_log] = shape.degree_log + shape.config.log_blowup;
    d[D.blowup] = shape.config.log_blowup;
    d[D.samples] = @intCast(samples);
    d[D.total_columns] = @intCast(total);
    d[D.config..][0..6].* = .{ shape.config.pow_bits, shape.config.log_blowup, shape.config.log_last_layer, shape.config.n_queries, shape.config.fold_step, shape.config.lifting orelse std.math.maxInt(u32) };
    d[D.phys_magic..][0..2].* = .{ std.mem.readInt(u32, "STWO", .little), std.mem.readInt(u32, "PRW8", .little) };
    if (envelope) |e| {
        d[D.flags] |= D.flag_envelope;
        for (0..18) |i| d[D.envelope + i] = std.mem.readInt(u32, e.prefix[4 * i ..][0..4], .little);
        if (e.n_outputs > 65536 or e.n_claims == 0 or e.n_claims > 64 or e.latches > 16) return error.InvalidPcsShape;
        d[D.outputs] = e.n_outputs;
        d[D.claims] = e.n_claims;
        d[D.latches] = e.latches;
    }
    if (fixed_root) |r| d[D.fixed_root..][0..8].* = r;
    for (fri[0..layers], 0..) |f, l| d[D.fri + 4 * l ..][0..4].* = .{ f.count, f.fold_step, f.leaf_log, f.shift };
    var at: u32 = D.tables;
    for (shape.trees, 0..) |t, ti| {
        const n: u32 = @intCast(t.coefficient_logs.len);
        const logs = d[at..][0..n];
        const s2o = d[at + n ..][0..n];
        const o2s = d[at + 2 * n ..][0..n];
        const counts = d[at + 3 * n ..][0..n];
        // trace.zig Geometry.validate: a permutation, ascending heights.
        const seen = try a.alloc(bool, n);
        defer a.free(seen);
        @memset(seen, false);
        var previous: u32 = 0;
        var tree_log: u32 = 0;
        var tree_samples: u32 = 0;
        for (t.sorted_to_original, 0..) |order, s| {
            if (order >= n or seen[order]) return error.InvalidPcsShape;
            seen[order] = true;
            const log = t.coefficient_logs[order] + shape.config.log_blowup;
            if (log < previous) return error.InvalidPcsShape;
            previous = log;
            logs[s] = log;
            s2o[s] = order;
            o2s[order] = @intCast(s);
            tree_log = @max(tree_log, log);
        }
        for (t.sample_counts, counts) |c, *out| {
            out.* = c;
            tree_samples += c;
        }
        if (tree_log < 1 or tree_log > 28) return error.InvalidPcsShape;
        d[D.tree_table + 4 * ti ..][0..4].* = .{ n, tree_log, at, tree_samples };
        at += 4 * n;
    }
    const im = Image.of(d);
    const b = bounds(d);
    if (im.words > std.math.maxInt(u32) or b.payload_words > std.math.maxInt(u32) / 4 or b.scratch_words > std.math.maxInt(u32)) return error.InvalidPcsShape;
    d[D.image_words] = @intCast(im.words);
    d[D.max_payload_words] = @intCast(b.payload_words);
    d[D.scratch_words] = @intCast(b.scratch_words);
    d[D.max_ops] = @intCast(b.ops);
    return d;
}

/// Encoded region capacity of a class (bytes of the slab Entry): payload
/// bound in bytes (the slab adds the length word itself).
pub fn maxEncodedBytes(desc: []const u32) usize {
    return @as(usize, desc[D.max_payload_words]) * 4;
}

/// Host inputs beside the image (device pointers in the kernel's Io).
pub const Inputs = struct {
    /// Expected root of each tree (8 words), null: not checked (native
    /// trees whose roots the stage checks elsewhere).
    roots: [max_trees]?[]const u32 = @splat(null),
    claims: []const u32 = &.{},
    latches: []const u32 = &.{},
    outputs: []const u32 = &.{},
};

pub const Verdicts = struct { pcs: u32, bounds: u32, bytes: u32 };

fn reject(check: G.Check, detail: anytype) u32 {
    return G.Verdict.reject(check, @intFromEnum(detail));
}

const Op = struct { dst: u32, src: u32, n: u32 };

/// Host mirror of the kernel (see the file comment). `out[0]` receives the
/// byte length (0 on any rejection), `out[1..]` the payload words.
pub fn encodeHost(a: std.mem.Allocator, desc: []const u32, image: []const u32, in: Inputs, out: []u32) !Verdicts {
    var m = try Mirror.init(a, desc, image, in, out);
    defer m.deinit();
    return m.run();
}

const Mirror = struct {
    a: std.mem.Allocator,
    desc: []const u32,
    image: []const u32,
    in: Inputs,
    out: []u32,
    im: Image = undefined,
    q: u32 = 0,
    sorted: []u32 = &.{}, // raw query indices in (raw, index) order
    reps: []u32 = &.{}, // first index of each distinct raw value, ascending raw
    ops: std.ArrayListUnmanaged(Op) = .empty,
    words: u32 = 0, // payload cursor
    detail: ?PcsDetail = null,
    // Planned sections (payload offsets fixed in emit()).
    trace_witness: [max_trees]std.ArrayListUnmanaged(Op) = @splat(.empty),
    fri_values: [max_layers]std.ArrayListUnmanaged(Op) = @splat(.empty),
    fri_hashes: [max_layers]std.ArrayListUnmanaged(Op) = @splat(.empty),

    fn init(a: std.mem.Allocator, desc: []const u32, image: []const u32, in: Inputs, out: []u32) !Mirror {
        return .{ .a = a, .desc = desc, .image = image, .in = in, .out = out };
    }
    fn deinit(self: *Mirror) void {
        self.a.free(self.sorted);
        self.a.free(self.reps);
        self.ops.deinit(self.a);
        for (&self.trace_witness) |*l| l.deinit(self.a);
        for (&self.fri_values) |*l| l.deinit(self.a);
        for (&self.fri_hashes) |*l| l.deinit(self.a);
    }
    fn fail(self: *Mirror, d: PcsDetail) void {
        if (self.detail == null) self.detail = d;
    }
    fn run(self: *Mirror) !Verdicts {
        if (self.out.len == 0) return error.OuterEncodeNoRegion;
        self.out[0] = 0;
        self.validate();
        if (self.detail == null) try self.plan();
        if (self.detail) |d| return .{ .pcs = reject(.node_pcs_status, d), .bounds = reject(.encode_bounds, BoundsDetail.input_rejected), .bytes = 0 };
        if (@as(u64, self.words) + 1 > self.out.len) return .{ .pcs = G.Verdict.accepted, .bounds = reject(.encode_bounds, BoundsDetail.capacity), .bytes = 0 };
        try self.emit();
        self.out[0] = self.words * 4;
        return .{ .pcs = G.Verdict.accepted, .bounds = G.Verdict.accepted, .bytes = self.words * 4 };
    }

    fn validate(self: *Mirror) void {
        const d = self.desc;
        if (d.len < D.tables or d[D.magic] != descriptor_magic or d[D.version] != descriptor_version or d[D.words] != d.len or d[D.trees] == 0 or d[D.trees] > max_trees or d[D.queries] == 0 or d[D.queries] > max_queries or d[D.layers] == 0 or d[D.layers] > max_layers) return self.fail(.descriptor);
        for (0..d[D.layers]) |l| {
            const f = layer(d, @intCast(l));
            if (f.fold_step == 0 or f.fold_step > 4 or f.leaf_log > f.fold_step or f.count < (@as(u32, 1) << @intCast(f.fold_step)) or !std.math.isPowerOfTwo(f.count) or f.count > 1 << 28) return self.fail(.descriptor);
        }
        for (0..d[D.trees]) |t| {
            const tr = tree(d, @intCast(t));
            if (tr.columns == 0 or tr.columns > max_columns or tr.tree_log < 1 or tr.tree_log > 28 or @as(u64, tr.table) + 4 * @as(u64, tr.columns) > d.len) return self.fail(.descriptor);
        }
        const env = d[D.flags] & D.flag_envelope != 0;
        if (self.in.outputs.len != (if (env) 4 * @as(usize, d[D.outputs]) else 0) or self.in.claims.len != (if (env) 8 * @as(usize, d[D.claims]) else 0) or self.in.latches.len != (if (env) @as(usize, d[D.latches]) else 0)) return self.fail(.descriptor);
        self.im = Image.of(d);
        self.q = d[D.queries];
        if (self.image.len != self.im.words or self.im.words != d[D.image_words]) return self.fail(.image_length);
        const h = self.image[0..14];
        if (h[0] != image_magic or h[1] != 2 or h[7] != d[D.trees] or h[8] != d[D.samples] or h[9] != d[D.layers] or h[10] != d[D.initial_log] or h[11] != self.q or h[12] != d[D.degree_log]) return self.fail(.header);
        if (self.image[14] != 0) return self.fail(.numerical);
        const s = self.image[15..31];
        if (s[9] != h[13] or s[10] != 0 or s[11] != 0 or s[12] != 17 +% h[13] or !std.mem.allEqual(u32, s[13..], 0)) return self.fail(.channel);
        for (0..d[D.trees]) |t| if (self.in.roots[t]) |r| {
            if (!std.mem.eql(u32, r[0..8], self.image[self.im.roots + 8 * t ..][0..8])) return self.fail(.root);
        };
        for (self.in.latches) |w| if (w != 0) return self.fail(.section_latch);
        for (self.in.claims) |w| if (w >= modulus) return self.fail(.noncanonical_public);
        for (self.in.outputs) |w| if (w >= modulus) return self.fail(.noncanonical_public);
        const raw = self.image[self.im.queries..][0..self.q];
        for (raw) |v| if (v >= @as(u64, 1) << @intCast(d[D.initial_log])) return self.fail(.query_range);
        // Every value the host decodes as a field element.
        const canonical = struct {
            fn all(ws: []const u32) bool {
                for (ws) |w| if (w >= modulus) return false;
                return true;
            }
        }.all;
        if (!canonical(self.image[self.im.samples..][0 .. d[D.samples] * 8]) or !canonical(self.image[self.im.terminal..][0..8])) return self.fail(.noncanonical);
        for (0..d[D.layers]) |l| {
            const f = layer(d, @intCast(l));
            if (!canonical(self.image[self.im.layer_values[l]..][0 .. (@as(u64, self.q) << @intCast(f.fold_step)) * 8])) return self.fail(.noncanonical);
        }
        for (0..d[D.trees]) |t| {
            const tr = tree(d, @intCast(t));
            if (!canonical(self.image[self.im.tree_values[t]..][0 .. @as(u64, tr.columns) * self.q])) return self.fail(.noncanonical);
        }
    }

    /// Rank sort of raw query indices by (value, index), then the first index
    /// of every distinct value (trace.zig representatives).
    fn sortQueries(self: *Mirror) !void {
        const raw = self.image[self.im.queries..][0..self.q];
        self.sorted = try self.a.alloc(u32, self.q);
        for (0..self.q) |i| {
            var rank: u32 = 0;
            for (0..self.q) |j| rank += @intFromBool(raw[j] < raw[i] or (raw[j] == raw[i] and j < i));
            self.sorted[rank] = @intCast(i);
        }
        var reps: std.ArrayListUnmanaged(u32) = .empty;
        errdefer reps.deinit(self.a);
        for (self.sorted) |i| if (reps.items.len == 0 or raw[reps.items[reps.items.len - 1]] != raw[i]) try reps.append(self.a, i);
        self.reps = try reps.toOwnedSlice(self.a);
    }

    /// Ordered (node, rep) list of one Merkle level.
    const Level = struct { nodes: []u64, reps: []u32 };
    fn find(nodes: []const u64, node: u64) ?usize {
        var lo: usize = 0;
        var hi: usize = nodes.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (nodes[mid] < node) lo = mid + 1 else hi = mid;
        }
        return if (lo < nodes.len and nodes[lo] == node) lo else null;
    }

    /// The lifted-Merkle witness walk shared by trace trees and FRI layers:
    /// `level0` = sorted unique leaves with a representative path index each;
    /// `hash(rep, level)` = image word offset of that path's sibling hash.
    /// Emits one 8-word op per unpaired node; returns the per-level lists.
    fn walk(self: *Mirror, level0: Level, height: u32, comptime Ctx: type, ctx: Ctx, witness: *std.ArrayListUnmanaged(Op)) ![]Level {
        const levels = try self.a.alloc(Level, height);
        var made: usize = 0;
        errdefer {
            for (levels[0..made]) |lv| {
                self.a.free(lv.nodes);
                self.a.free(lv.reps);
            }
            self.a.free(levels);
        }
        var cur = level0;
        for (0..height) |lv| {
            levels[lv] = cur;
            made += 1;
            var nodes: std.ArrayListUnmanaged(u64) = .empty;
            var reps: std.ArrayListUnmanaged(u32) = .empty;
            errdefer nodes.deinit(self.a);
            errdefer reps.deinit(self.a);
            var i: usize = 0;
            while (i < cur.nodes.len) {
                const first = cur.nodes[i];
                const paired = i + 1 < cur.nodes.len and cur.nodes[i + 1] == (first ^ 1);
                if (!paired) try witness.append(self.a, .{ .dst = 0, .src = ctx.hash(cur.reps[i], @intCast(lv)), .n = 8 });
                try nodes.append(self.a, first >> 1);
                try reps.append(self.a, cur.reps[i]);
                i += if (paired) 2 else 1;
            }
            cur = .{ .nodes = try nodes.toOwnedSlice(self.a), .reps = try reps.toOwnedSlice(self.a) };
        }
        self.a.free(cur.nodes);
        self.a.free(cur.reps);
        return levels;
    }
    fn freeLevels(self: *Mirror, levels: []Level) void {
        for (levels) |lv| {
            self.a.free(lv.nodes);
            self.a.free(lv.reps);
        }
        self.a.free(levels);
    }

    const TraceCtx = struct {
        paths: u64,
        tree_log: u32,
        fn hash(self: TraceCtx, qi: u32, level: u32) u32 {
            return @intCast(self.paths + (@as(u64, qi) * self.tree_log + level) * 8);
        }
    };
    const FriCtx = struct {
        paths: u64,
        slots: u32,
        height: u32,
        fn hash(self: FriCtx, path: u32, level: u32) u32 {
            return @intCast(self.paths + (@as(u64, path) * self.height + level) * 8);
        }
    };

    fn plan(self: *Mirror) !void {
        const d = self.desc;
        try self.sortQueries();
        const raw = self.image[self.im.queries..][0..self.q];
        // ---- trace trees
        for (0..d[D.trees]) |t| {
            const tr = tree(d, @intCast(t));
            const tl = tr.tree_log;
            const p = try self.a.alloc(u64, self.q);
            defer self.a.free(p);
            for (raw, p) |v, *out| out.* = position(v, d[D.initial_log], tl);
            // Sorted unique tree positions, each with its first query (rank sort by (p, index)).
            const order = try self.a.alloc(u32, self.q);
            defer self.a.free(order);
            for (0..self.q) |i| {
                var rank: u32 = 0;
                for (0..self.q) |j| rank += @intFromBool(p[j] < p[i] or (p[j] == p[i] and j < i));
                order[rank] = @intCast(i);
            }
            var nodes: std.ArrayListUnmanaged(u64) = .empty;
            var nreps: std.ArrayListUnmanaged(u32) = .empty;
            for (order) |i| if (nodes.items.len == 0 or nodes.items[nodes.items.len - 1] != p[i]) {
                try nodes.append(self.a, p[i]);
                try nreps.append(self.a, i);
            };
            const ctx = TraceCtx{ .paths = self.im.tree_paths[t], .tree_log = tl };
            const levels = try self.walk(.{ .nodes = try nodes.toOwnedSlice(self.a), .reps = try nreps.toOwnedSlice(self.a) }, tl, TraceCtx, ctx, &self.trace_witness[t]);
            defer self.freeLevels(levels);
            // Hash consistency: every query's sibling at every level equals its node's representative's.
            for (0..self.q) |qi| for (0..tl) |lv| {
                const lvl = levels[lv];
                const k = find(lvl.nodes, p[qi] >> @intCast(lv)) orelse return self.fail(.trace_inconsistent);
                const a0 = ctx.hash(@intCast(qi), @intCast(lv));
                const b0 = ctx.hash(lvl.reps[k], @intCast(lv));
                if (!std.mem.eql(u32, self.image[a0..][0..8], self.image[b0..][0..8])) return self.fail(.trace_inconsistent);
            };
            // Value consistency: queries sharing a column position share its value.
            const logs = d[tr.table..][0..tr.columns];
            const values = self.image[self.im.tree_values[t]..][0 .. @as(u64, tr.columns) * self.q];
            const canon = try self.a.alloc(u32, self.q);
            defer self.a.free(canon);
            var last_log: u32 = 0;
            for (logs, 0..) |log, s| {
                if (s == 0 or log != last_log) {
                    canonicalFor(p, order, tl, log, canon);
                    last_log = log;
                }
                for (0..self.q) |qi| if (canon[qi] != qi and values[s * self.q + qi] != values[s * self.q + canon[qi]]) return self.fail(.trace_inconsistent);
            }
        }
        // ---- FRI layers
        var positions: std.ArrayListUnmanaged(u64) = .empty;
        defer positions.deinit(self.a);
        var prep: std.ArrayListUnmanaged(u32) = .empty; // representative raw index per position
        defer prep.deinit(self.a);
        for (self.reps) |i| {
            try positions.append(self.a, raw[i]);
            try prep.append(self.a, i);
        }
        for (0..d[D.layers]) |l| {
            const f = layer(d, @intCast(l));
            const h = layerHeight(f);
            const subset: u64 = @as(u64, 1) << @intCast(f.fold_step);
            const slots: u32 = @as(u32, 1) << @intCast(f.fold_step - f.leaf_log);
            const vals = self.im.layer_values[l];
            // Group representative of every raw query: the position list holds
            // q >> shift for every raw q; groups are positions >> fold_step.
            const group_rep = try self.a.alloc(u32, self.q);
            defer self.a.free(group_rep);
            for (raw, 0..) |v, qi| {
                const pos = @as(u64, v) >> @intCast(f.shift);
                const k = find(positions.items, pos).?;
                // The first position of pos's group carries the group's rep.
                var g = k;
                while (g > 0 and positions.items[g - 1] >> @intCast(f.fold_step) == pos >> @intCast(f.fold_step)) g -= 1;
                group_rep[qi] = prep.items[g];
            }
            // Value consistency.
            for (0..self.q) |qi| if (group_rep[qi] != qi) for (0..subset) |off| {
                const x = vals + (qi * subset + off) * 8;
                const y = vals + (group_rep[qi] * subset + off) * 8;
                if (!std.mem.eql(u32, self.image[x..][0..8], self.image[y..][0..8])) return self.fail(.fri_inconsistent);
            };
            // Witness values and leaves (fri.zig layerProof walk).
            var leaves: std.ArrayListUnmanaged(u64) = .empty;
            var lreps: std.ArrayListUnmanaged(u32) = .empty;
            var cursor: usize = 0;
            while (cursor < positions.items.len) {
                const start = (positions.items[cursor] >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                const rep = prep.items[cursor];
                for (0..subset) |off| {
                    const pos = start + off;
                    if (cursor < positions.items.len and positions.items[cursor] == pos) cursor += 1 else try self.fri_values[l].append(self.a, .{ .dst = 0, .src = @intCast(vals + (rep * subset + off) * 8), .n = 8 });
                }
                for (0..slots) |slot| {
                    try leaves.append(self.a, (start >> @intCast(f.leaf_log)) + slot);
                    try lreps.append(self.a, rep * slots + @as(u32, @intCast(slot)));
                }
            }
            const ctx = FriCtx{ .paths = self.im.layer_paths[l], .slots = slots, .height = h };
            const levels = try self.walk(.{ .nodes = try leaves.toOwnedSlice(self.a), .reps = try lreps.toOwnedSlice(self.a) }, h, FriCtx, ctx, &self.fri_hashes[l]);
            defer self.freeLevels(levels);
            for (raw, 0..) |v, qi| {
                const start = ((@as(u64, v) >> @intCast(f.shift)) >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (0..slots) |slot| for (0..h) |lv| {
                    const leaf = (start >> @intCast(f.leaf_log)) + slot;
                    const lvl = levels[lv];
                    const k = find(lvl.nodes, leaf >> @intCast(lv)) orelse return self.fail(.fri_inconsistent);
                    const x = ctx.hash(@intCast(qi * slots + slot), @intCast(lv));
                    const y = ctx.hash(lvl.reps[k], @intCast(lv));
                    if (!std.mem.eql(u32, self.image[x..][0..8], self.image[y..][0..8])) return self.fail(.fri_inconsistent);
                };
            }
            // Fold the positions (Queries.fold), keeping the first rep.
            var w: usize = 0;
            for (0..positions.items.len) |i| {
                const folded = positions.items[i] >> @intCast(f.fold_step);
                if (w == 0 or positions.items[w - 1] != folded) {
                    positions.items[w] = folded;
                    prep.items[w] = prep.items[i];
                    w += 1;
                }
            }
            positions.shrinkRetainingCapacity(w);
            prep.shrinkRetainingCapacity(w);
        }
        // ---- size
        self.words = self.layoutWords();
    }

    /// Canonical query of every query for a column of height `log` in a tree
    /// of `tl`: the first query in (p, index) order with the same column
    /// position (positions are runs of equal p >> (d+1), split by p & 1).
    fn canonicalFor(p: []const u64, order: []const u32, tl: u32, log: u32, canon: []u32) void {
        var run_key: u64 = std.math.maxInt(u64);
        var first: [2]?u32 = .{ null, null };
        for (order) |i| {
            const cp = position(p[i], tl, log);
            const key = cp >> 1;
            if (key != run_key) {
                run_key = key;
                first = .{ null, null };
            }
            const bit: usize = @intCast(cp & 1);
            if (first[bit] == null) first[bit] = i;
            canon[i] = first[bit].?;
        }
    }

    fn layoutWords(self: *const Mirror) u32 {
        const d = self.desc;
        var n: u64 = 0;
        if (d[D.flags] & D.flag_envelope != 0) n += 18 + 1 + 4 * @as(u64, d[D.outputs]) + 8 * @as(u64, d[D.claims]) + 1;
        n += 2 + 6 + 1 + 8 * @as(u64, d[D.trees]) + 1;
        for (0..d[D.trees]) |t| {
            const tr = tree(d, @intCast(t));
            n += 1 + tr.columns + 8 * @as(u64, tr.samples);
        }
        n += 1;
        for (0..d[D.trees]) |t| n += 1 + 8 * @as(u64, self.trace_witness[t].items.len);
        n += 1;
        for (0..d[D.trees]) |t| n += 1 + @as(u64, tree(d, @intCast(t)).columns) * (1 + self.reps.len);
        n += 2;
        for (0..d[D.layers]) |l| n += 1 + 8 * @as(u64, self.fri_values[l].items.len) + 1 + 8 * @as(u64, self.fri_hashes[l].items.len) + 8;
        n += 1 + 1 + 8;
        return @intCast(n);
    }

    fn put(self: *Mirror, at: *u32, w: u32) void {
        self.out[1 + at.*] = w;
        at.* += 1;
    }
    fn copy(self: *Mirror, at: *u32, src: u64, n: u64) void {
        @memcpy(self.out[1 + at.* ..][0..n], self.image[src..][0..n]);
        at.* += @intCast(n);
    }
    fn emitOps(self: *Mirror, at: *u32, ops: []const Op) void {
        put(self, at, @intCast(ops.len));
        for (ops) |op| self.copy(at, op.src, op.n);
    }

    fn emit(self: *Mirror) !void {
        const d = self.desc;
        var at: u32 = 0;
        var phys_len_at: ?u32 = null;
        if (d[D.flags] & D.flag_envelope != 0) {
            for (0..18) |i| self.put(&at, d[D.envelope + i]);
            self.put(&at, d[D.outputs]);
            for (self.in.outputs) |w| self.put(&at, w);
            for (self.in.claims) |w| self.put(&at, w);
            phys_len_at = at;
            self.put(&at, 0);
        }
        const phys = at;
        self.put(&at, d[D.phys_magic]);
        self.put(&at, d[D.phys_magic + 1]);
        for (0..6) |i| self.put(&at, d[D.config + i]);
        self.put(&at, d[D.trees]);
        self.copy(&at, self.im.roots, 8 * @as(u64, d[D.trees]));
        // sampled values: tree, original column, value (pcs_assembly cursor order)
        self.put(&at, d[D.trees]);
        var cursor = self.im.samples;
        for (0..d[D.trees]) |t| {
            const tr = tree(d, @intCast(t));
            self.put(&at, tr.columns);
            const counts = d[tr.table + 3 * tr.columns ..][0..tr.columns];
            for (counts) |c| {
                self.put(&at, c);
                self.copy(&at, cursor, 8 * @as(u64, c));
                cursor += 8 * @as(u64, c);
            }
        }
        self.put(&at, d[D.trees]);
        for (0..d[D.trees]) |t| self.emitOps(&at, self.trace_witness[t].items);
        // queried values: tree, original column, distinct raw query (ascending)
        self.put(&at, d[D.trees]);
        for (0..d[D.trees]) |t| {
            const tr = tree(d, @intCast(t));
            const o2s = d[tr.table + 2 * tr.columns ..][0..tr.columns];
            const base = self.im.tree_values[t];
            self.put(&at, tr.columns);
            for (o2s) |s| {
                self.put(&at, @intCast(self.reps.len));
                for (self.reps) |qi| self.put(&at, self.image[base + @as(u64, s) * self.q + qi]);
            }
        }
        self.copy(&at, self.im.nonce, 2);
        for (0..d[D.layers]) |l| {
            if (l == 1) self.put(&at, d[D.layers] - 1);
            self.emitOps(&at, self.fri_values[l].items);
            self.emitOps(&at, self.fri_hashes[l].items);
            self.copy(&at, self.im.layer_root[l], 8);
        }
        if (d[D.layers] == 1) self.put(&at, 0);
        self.put(&at, 1);
        self.copy(&at, self.im.terminal, 8);
        if (phys_len_at) |p| self.out[1 + p] = (at - phys) * 4;
        if (at != self.words) return error.OuterEncodeLayoutDrift;
    }
};

// ---------------------------------------------------------------------------
// Kernel ABI (mirrors StwoRv64OuterEncodeIo in outer_encode.cu)

pub const Io = extern struct {
    desc: [*]const u32,
    desc_words: u64,
    image: [*]const u32,
    image_words: u64,
    roots: [max_trees]?[*]const u32,
    claims: ?[*]const u32,
    latches: ?[*]const u32,
    outputs: ?[*]const u32,
    claims_words: u32,
    latches_words: u32,
    outputs_words: u32,
    reserved: u32 = 0,
    /// region[0] = byte length, region[1..] = payload; capacity in words
    /// INCLUDING the length word.
    region: [*]u32,
    region_words: u64,
    pcs_status: [*]u32,
    encode_status: [*]u32,
    scratch: [*]u32,
    scratch_words: u64,
};
comptime {
    if (@sizeOf(Io) != 152) @compileError("outer encode Io ABI changed");
}
/// (context, lane, io) -> cudaError; enqueue only on the lane's exec stream.
pub const EncodeFn = *const fn (*anyopaque, u32, *const Io) callconv(.c) c_int;
pub const VersionFn = *const fn () callconv(.c) u32;
pub const kernel_version: u32 = 1;
pub const Symbols = struct {
    encode: EncodeFn,
    pub fn load(addon: *std.DynLib) !Symbols {
        const v = addon.lookup(VersionFn, "stwo_rv64_outer_encode_version") orelse return error.MissingOuterEncodeKernel;
        if (v() != kernel_version) return error.OuterEncodeKernelVersion;
        return .{ .encode = addon.lookup(EncodeFn, "stwo_rv64_outer_encode_v1_on") orelse return error.MissingOuterEncodeKernel };
    }
};

/// STWO_RV64_M8_OUTER_DEVICE_ENCODE: unset/"0" off; "check" encodes every
/// whole node on the device and requires byte equality with the host bytes
/// (fails the node closed otherwise); "1" encodes (GPU-native path).
pub const Mode = enum { off, check, on };
pub fn mode() !Mode {
    const v = std.posix.getenv("STWO_RV64_M8_OUTER_DEVICE_ENCODE") orelse return .off;
    if (std.mem.eql(u8, v, "0")) return .off;
    if (std.mem.eql(u8, v, "1")) return .on;
    if (std.mem.eql(u8, v, "check")) return .check;
    return error.InvalidOuterDeviceEncode;
}

/// STWO_RV64_M8_OUTER_ENCODE_FAULT_ORDINAL=n (negative test, two-key with
/// STWO_RV64_M8_FAULT_INJECTION=1): node n's PCS image gets one corrupted
/// word on the device before the encoder; its node_pcs_status must reject.
pub fn faultOrdinal() !?u32 {
    const v = std.posix.getenv("STWO_RV64_M8_OUTER_ENCODE_FAULT_ORDINAL") orelse return null;
    const n = std.fmt.parseUnsigned(u32, v, 10) catch return error.InvalidOuterEncodeFaultOrdinal;
    const armed = std.posix.getenv("STWO_RV64_M8_FAULT_INJECTION") orelse return error.M8FaultInjectionNotArmed;
    if (!std.mem.eql(u8, armed, "1")) return error.M8FaultInjectionNotArmed;
    return n;
}

// ---------------------------------------------------------------------------
// Tests: the mirror against a transliteration of the host assembler +
// stwo_proof_wire writer + om31 wire.encode (hash maps, its own sort), on
// synthetic images of random class shapes; negatives per detail.

const Ref = struct {
    // Transliteration of trace.zig assemble / fri.zig layerProof+assemble /
    // pcs_assembly.assemble / family.zig writeProofWireBinary / wire.encode.
    fn encode(a: std.mem.Allocator, desc: []const u32, image: []const u32, in: Inputs) ![]u32 {
        var out: std.ArrayListUnmanaged(u32) = .empty;
        errdefer out.deinit(a);
        const im = Image.of(desc);
        const q = desc[D.queries];
        const raw = image[im.queries..][0..q];
        const h = image[0..14];
        if (h[0] != image_magic or h[7] != desc[D.trees]) return error.InvalidGpuPcsProof;
        if (image[14] != 0) return error.GpuPcsNumericalFailure;
        for (0..desc[D.trees]) |t| if (in.roots[t]) |r| if (!std.mem.eql(u32, r, image[im.roots + 8 * t ..][0..8])) return error.NativePcsTreeRootMismatch;
        var physical: std.ArrayListUnmanaged(u32) = .empty;
        defer physical.deinit(a);
        const P = struct {
            list: *std.ArrayListUnmanaged(u32),
            a: std.mem.Allocator,
            fn w(self: @This(), v: u32) !void {
                try self.list.append(self.a, v);
            }
            fn ws(self: @This(), v: []const u32) !void {
                try self.list.appendSlice(self.a, v);
            }
        };
        const p = P{ .list = &physical, .a = a };
        try p.ws(desc[D.phys_magic..][0..2]);
        try p.ws(desc[D.config..][0..6]);
        try p.w(desc[D.trees]);
        try p.ws(image[im.roots..][0 .. 8 * desc[D.trees]]);
        try p.w(desc[D.trees]);
        var cur: usize = im.samples;
        for (0..desc[D.trees]) |t| {
            const tr = tree(desc, @intCast(t));
            try p.w(tr.columns);
            for (desc[tr.table + 3 * tr.columns ..][0..tr.columns]) |c| {
                try p.w(c);
                for (image[cur..][0 .. 8 * c]) |v| if (v >= modulus) return error.NoncanonicalPcsReadback;
                try p.ws(image[cur..][0 .. 8 * c]);
                cur += 8 * c;
            }
        }
        // trace openings
        var queried: std.ArrayListUnmanaged(u32) = .empty;
        defer queried.deinit(a);
        try queried.append(a, desc[D.trees]);
        try p.w(desc[D.trees]);
        for (0..desc[D.trees]) |t| {
            const tr = tree(desc, @intCast(t));
            const tl = tr.tree_log;
            const lift = desc[D.initial_log];
            const idx = try a.alloc(usize, q);
            defer a.free(idx);
            for (idx, 0..) |*x, i| x.* = i;
            const Order = struct {
                raw: []const u32,
                fn less(self: @This(), l: usize, r: usize) bool {
                    return self.raw[l] < self.raw[r] or (self.raw[l] == self.raw[r] and l < r);
                }
            };
            std.sort.heap(usize, idx, Order{ .raw = raw }, Order.less);
            var reps: std.ArrayListUnmanaged(usize) = .empty;
            defer reps.deinit(a);
            for (idx) |i| if (reps.items.len == 0 or raw[reps.items[reps.items.len - 1]] != raw[i]) try reps.append(a, i);
            const values = image[im.tree_values[t]..];
            var seen = std.AutoHashMap(u64, u32).init(a);
            defer seen.deinit();
            const logs = desc[tr.table..][0..tr.columns];
            for (logs, 0..) |log, ci| {
                seen.clearRetainingCapacity();
                for (raw, 0..) |v, qi| {
                    const value = values[ci * q + qi];
                    if (value >= modulus) return error.NoncanonicalTraceValue;
                    const pp = position(position(v, lift, tl), tl, log);
                    if (seen.get(pp)) |old| {
                        if (old != value) return error.InconsistentTraceReadback;
                    } else try seen.put(pp, value);
                }
            }
            var hashes = std.AutoHashMap(u64, [8]u32).init(a);
            defer hashes.deinit();
            const paths = image[im.tree_paths[t]..];
            var tp = try a.alloc(u64, q);
            defer a.free(tp);
            for (raw, 0..) |v, qi| tp[qi] = position(v, lift, tl);
            for (0..q) |qi| for (0..tl) |lv| {
                const key = (@as(u64, lv) << 40) | ((tp[qi] >> @intCast(lv)) ^ 1);
                const hh = paths[(qi * tl + lv) * 8 ..][0..8].*;
                if (hashes.get(key)) |old| {
                    if (!std.mem.eql(u32, &old, &hh)) return error.InconsistentTraceReadback;
                } else try hashes.put(key, hh);
            };
            std.mem.sort(u64, tp, {}, std.sort.asc(u64));
            var current: std.ArrayListUnmanaged(u64) = .empty;
            defer current.deinit(a);
            for (tp) |v| if (current.items.len == 0 or current.items[current.items.len - 1] != v) try current.append(a, v);
            var witness: std.ArrayListUnmanaged(u32) = .empty;
            defer witness.deinit(a);
            var n_witness: u32 = 0;
            for (0..tl) |lv| {
                var next: std.ArrayListUnmanaged(u64) = .empty;
                var i: usize = 0;
                while (i < current.items.len) {
                    const first = current.items[i];
                    const paired = i + 1 < current.items.len and current.items[i + 1] == (first ^ 1);
                    if (!paired) {
                        try witness.appendSlice(a, &(hashes.get((@as(u64, lv) << 40) | (first ^ 1)) orelse return error.MissingTraceReadback));
                        n_witness += 1;
                    }
                    try next.append(a, first >> 1);
                    i += if (paired) 2 else 1;
                }
                current.deinit(a);
                current = next;
            }
            try p.w(n_witness);
            try p.ws(witness.items);
            const s2o = desc[tr.table + tr.columns ..][0..tr.columns];
            const cols = try a.alloc([]u32, tr.columns);
            defer {
                for (cols) |c| a.free(c);
                a.free(cols);
            }
            for (0..tr.columns) |s| {
                const col = try a.alloc(u32, reps.items.len);
                for (reps.items, col) |qi, *v| v.* = values[s * q + qi];
                cols[s2o[s]] = col;
            }
            try queried.append(a, tr.columns);
            for (cols) |c| {
                try queried.append(a, @intCast(c.len));
                try queried.appendSlice(a, c);
            }
        }
        try p.ws(queried.items);
        try p.ws(image[im.nonce..][0..2]);
        // FRI
        var positions: std.ArrayListUnmanaged(u64) = .empty;
        defer positions.deinit(a);
        {
            const tmp = try a.alloc(u64, q);
            defer a.free(tmp);
            for (raw, tmp) |v, *x| x.* = v;
            std.mem.sort(u64, tmp, {}, std.sort.asc(u64));
            for (tmp) |v| if (positions.items.len == 0 or positions.items[positions.items.len - 1] != v) try positions.append(a, v);
        }
        for (0..desc[D.layers]) |l| {
            const f = layer(desc, @intCast(l));
            const hgt = layerHeight(f);
            const subset: usize = @as(usize, 1) << @intCast(f.fold_step);
            const slots: usize = @as(usize, 1) << @intCast(f.fold_step - f.leaf_log);
            const vals = image[im.layer_values[l]..];
            const paths = image[im.layer_paths[l]..];
            var values = std.AutoHashMap(u64, [8]u32).init(a);
            defer values.deinit();
            var hashes = std.AutoHashMap(u64, [8]u32).init(a);
            defer hashes.deinit();
            for (raw, 0..) |v, qi| {
                const start = ((@as(u64, v) >> @intCast(f.shift)) >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (0..subset) |off| {
                    const val = vals[(qi * subset + off) * 8 ..][0..8].*;
                    for (val) |x| if (x >= modulus) return error.NoncanonicalFriField;
                    if (values.get(start + off)) |old| {
                        if (!std.mem.eql(u32, &old, &val)) return error.InconsistentFriReadback;
                    } else try values.put(start + off, val);
                }
                for (0..slots) |slot| for (0..hgt) |lv| {
                    const leaf = (start >> @intCast(f.leaf_log)) + slot;
                    const key = (@as(u64, lv) << 40) | ((leaf >> @intCast(lv)) ^ 1);
                    const hh = paths[((qi * slots + slot) * hgt + lv) * 8 ..][0..8].*;
                    if (hashes.get(key)) |old| {
                        if (!std.mem.eql(u32, &old, &hh)) return error.InconsistentFriReadback;
                    } else try hashes.put(key, hh);
                };
            }
            var witness: std.ArrayListUnmanaged(u32) = .empty;
            defer witness.deinit(a);
            var n_fw: u32 = 0;
            var leaves: std.ArrayListUnmanaged(u64) = .empty;
            defer leaves.deinit(a);
            var cursor: usize = 0;
            while (cursor < positions.items.len) {
                const start = (positions.items[cursor] >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (start..start + subset) |pos| {
                    const value = values.get(pos) orelse return error.MissingFriReadback;
                    if (cursor < positions.items.len and positions.items[cursor] == pos) cursor += 1 else {
                        try witness.appendSlice(a, &value);
                        n_fw += 1;
                    }
                    const leaf = pos >> @intCast(f.leaf_log);
                    if (leaves.items.len == 0 or leaves.items[leaves.items.len - 1] != leaf) try leaves.append(a, leaf);
                }
            }
            var hw: std.ArrayListUnmanaged(u32) = .empty;
            defer hw.deinit(a);
            var n_hw: u32 = 0;
            var current = try leaves.clone(a);
            defer current.deinit(a);
            for (0..hgt) |lv| {
                var next: std.ArrayListUnmanaged(u64) = .empty;
                var i: usize = 0;
                while (i < current.items.len) {
                    const first = current.items[i];
                    const sib = i + 1 < current.items.len and current.items[i + 1] == (first ^ 1);
                    if (!sib) {
                        try hw.appendSlice(a, &(hashes.get((@as(u64, lv) << 40) | (first ^ 1)) orelse return error.MissingFriReadback));
                        n_hw += 1;
                    }
                    try next.append(a, first >> 1);
                    i += if (sib) 2 else 1;
                }
                current.deinit(a);
                current = next;
            }
            if (l == 1) try p.w(desc[D.layers] - 1);
            try p.w(n_fw);
            try p.ws(witness.items);
            try p.w(n_hw);
            try p.ws(hw.items);
            try p.ws(image[im.layer_root[l]..][0..8]);
            // fold
            var w: usize = 0;
            for (0..positions.items.len) |i| {
                const folded = positions.items[i] >> @intCast(f.fold_step);
                if (w == 0 or positions.items[w - 1] != folded) {
                    positions.items[w] = folded;
                    w += 1;
                }
            }
            positions.shrinkRetainingCapacity(w);
        }
        if (desc[D.layers] == 1) try p.w(0);
        try p.w(1);
        for (image[im.terminal..][0..8]) |x| if (x >= modulus) return error.NoncanonicalFriField;
        try p.ws(image[im.terminal..][0..8]);
        if (desc[D.flags] & D.flag_envelope != 0) {
            try out.appendSlice(a, desc[D.envelope..][0..18]);
            try out.append(a, @intCast(in.outputs.len / 4));
            try out.appendSlice(a, in.outputs);
            try out.appendSlice(a, in.claims);
            try out.append(a, @intCast(physical.items.len * 4));
        }
        try out.appendSlice(a, physical.items);
        return out.toOwnedSlice(a);
    }
};

const Synth = struct {
    // Deterministic, internally consistent PCS image of a class: every value
    // and sibling hash is a function of its tree position, so duplicated
    // queries read back equal words (as a correct PCS does).
    fn mix(x: u64) u32 {
        var z = x +% 0x9e37_79b9_7f4a_7c15;
        z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
        z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
        return @as(u32, @truncate(z ^ (z >> 31))) % modulus;
    }
    fn image(a: std.mem.Allocator, desc: []const u32, raw: []const u32, seed: u64) ![]u32 {
        const im = Image.of(desc);
        const w = try a.alloc(u32, im.words);
        for (w, 0..) |*x, i| x.* = mix(seed ^ (i *% 0x1234_5678_9abc));
        const q = desc[D.queries];
        w[0..14].* = .{ image_magic, 2, 0, 0, 0, 0, 0, desc[D.trees], desc[D.samples], desc[D.layers], desc[D.initial_log], q, desc[D.degree_log], 5 };
        w[14] = 0;
        @memset(w[15..31], 0);
        w[15 + 8] = 3;
        w[15 + 9] = 5;
        w[15 + 12] = 22;
        @memcpy(w[im.queries..][0..q], raw);
        for (0..desc[D.layers]) |l| {
            const f = layer(desc, @intCast(l));
            const hgt = layerHeight(f);
            const subset: u64 = @as(u64, 1) << @intCast(f.fold_step);
            const slots: u64 = @as(u64, 1) << @intCast(f.fold_step - f.leaf_log);
            for (raw, 0..) |v, qi| {
                const start = ((@as(u64, v) >> @intCast(f.shift)) >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (0..subset) |off| for (0..8) |k| {
                    w[im.layer_values[l] + (qi * subset + off) * 8 + k] = mix((l << 50) ^ ((start + off) << 4) ^ k ^ seed);
                };
                for (0..slots) |slot| for (0..hgt) |lv| {
                    const leaf = (start >> @intCast(f.leaf_log)) + slot;
                    const sib = (leaf >> @intCast(lv)) ^ 1;
                    for (0..8) |k| w[im.layer_paths[l] + ((qi * slots + slot) * hgt + lv) * 8 + k] = mix(0xf000_0000_0000 ^ (l << 44) ^ (lv << 38) ^ (sib << 4) ^ k ^ seed);
                };
            }
        }
        for (0..desc[D.trees]) |t| {
            const tr = tree(desc, @intCast(t));
            const logs = desc[tr.table..][0..tr.columns];
            for (raw, 0..) |v, qi| {
                const p = position(v, desc[D.initial_log], tr.tree_log);
                for (logs, 0..) |log, s| w[im.tree_values[t] + s * q + qi] = mix((t << 56) ^ (s << 30) ^ position(p, tr.tree_log, log) ^ seed);
                for (0..tr.tree_log) |lv| {
                    const sib = (p >> @intCast(lv)) ^ 1;
                    for (0..8) |k| w[im.tree_paths[t] + (qi * tr.tree_log + lv) * 8 + k] = mix(0xe000_0000_0000 ^ (t << 44) ^ (lv << 38) ^ (sib << 4) ^ k ^ seed);
                }
            }
        }
        return w;
    }
};

const TestClass = struct {
    trees: [max_trees]TreeShape,
    store: [max_trees][3][64]u32,
    n: usize,
    shape: Shape,
    fn random(self: *TestClass, r: std.Random, n_queries: u32, fold_step: u32) void {
        const degree_log: u32 = 5 + r.uintLessThan(u32, 5);
        self.n = 1 + r.uintLessThan(usize, max_trees);
        for (0..self.n) |t| {
            const cols = 1 + r.uintLessThan(usize, 12);
            const logs = self.store[t][0][0..cols];
            for (logs) |*l| l.* = 1 + r.uintLessThan(u32, degree_log);
            // sorted_to_original: argsort ascending by log (stable).
            const s2o = self.store[t][1][0..cols];
            for (s2o, 0..) |*x, i| x.* = @intCast(i);
            std.mem.sort(u32, s2o, logs, struct {
                fn less(ls: []u32, x: u32, y: u32) bool {
                    return ls[x] < ls[y] or (ls[x] == ls[y] and x < y);
                }
            }.less);
            const counts = self.store[t][2][0..cols];
            for (counts) |*c| c.* = r.uintLessThan(u32, 3);
            self.trees[t] = .{ .coefficient_logs = logs, .sorted_to_original = s2o, .sample_counts = counts };
        }
        self.shape = .{ .config = .{ .pow_bits = 20, .log_blowup = 1 + r.uintLessThan(u32, 2), .log_last_layer = 0, .n_queries = n_queries, .fold_step = fold_step, .lifting = degree_log + 2 }, .degree_log = degree_log, .trees = self.trees[0..self.n] };
    }
};

fn testEnvelope() Envelope {
    var e = Envelope{ .prefix = undefined, .n_outputs = 3, .n_claims = 11, .latches = 4 };
    @memcpy(e.prefix[0..8], "STWOCOM1");
    for (e.prefix[8..], 0..) |*b, i| b.* = @truncate(i *% 37);
    return e;
}

test "outer encode: host mirror equals the reference assembler + wire writer on random classes" {
    const t = std.testing;
    const a = t.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed_0e1c);
    const r = prng.random();
    var cases: usize = 0;
    while (cases < 160) : (cases += 1) {
        var tc: TestClass = undefined;
        const nq: u32 = 1 + r.uintLessThan(u32, 40);
        tc.random(r, nq, 1 + r.uintLessThan(u32, 4));
        const with_env = r.boolean();
        const env = testEnvelope();
        const root0: [8]u32 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
        const desc = buildDescriptor(a, tc.shape, if (with_env) env else null, root0) catch |err| switch (err) {
            error.UnsupportedFriGeometry => continue,
            else => return err,
        };
        defer a.free(desc);
        const raw = try a.alloc(u32, nq);
        defer a.free(raw);
        // Heavy duplication on purpose (few distinct rows).
        const span: u32 = @as(u32, 1) << @intCast(@min(desc[D.initial_log], 1 + r.uintLessThan(u32, desc[D.initial_log])));
        for (raw) |*x| x.* = r.uintLessThan(u32, span) << @intCast(desc[D.initial_log] - std.math.log2_int(u32, span));
        const img = try Synth.image(a, desc, raw, r.int(u64));
        defer a.free(img);
        var in = Inputs{};
        var claims: [88]u32 = undefined;
        for (&claims, 0..) |*c, i| c.* = @intCast(i * 7 + 1);
        const outputs = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12 };
        const latches = [_]u32{ 0, 0, 0, 0 };
        if (with_env) {
            in.claims = &claims;
            in.outputs = &outputs;
            in.latches = &latches;
        }
        in.roots[0] = img[Image.of(desc).roots..][0..8];
        const expected = try Ref.encode(a, desc, img, in);
        defer a.free(expected);
        const out = try a.alloc(u32, desc[D.max_payload_words] + 1);
        defer a.free(out);
        const v = try encodeHost(a, desc, img, in, out);
        try t.expectEqual(G.Verdict.accepted, v.pcs);
        try t.expectEqual(G.Verdict.accepted, v.bounds);
        try t.expectEqual(@as(u32, @intCast(expected.len * 4)), out[0]);
        try t.expectEqualSlices(u32, expected, out[1..][0..expected.len]);
        // Bound is an upper bound with distinct queries too.
        try t.expect(expected.len <= desc[D.max_payload_words]);
    }
}

test "outer encode: distinct queries reach but never exceed the class bound" {
    const t = std.testing;
    const a = t.allocator;
    var prng = std.Random.DefaultPrng.init(77);
    const r = prng.random();
    for (0..40) |_| {
        var tc: TestClass = undefined;
        tc.random(r, 1 + r.uintLessThan(u32, 30), 1 + r.uintLessThan(u32, 4));
        const desc = buildDescriptor(a, tc.shape, testEnvelope(), null) catch continue;
        defer a.free(desc);
        const nq = desc[D.queries];
        const raw = try a.alloc(u32, nq);
        defer a.free(raw);
        for (raw) |*x| x.* = r.uintLessThan(u32, @as(u32, 1) << @intCast(desc[D.initial_log]));
        const img = try Synth.image(a, desc, raw, 1);
        defer a.free(img);
        var claims: [88]u32 = @splat(1);
        const outputs = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
        const in = Inputs{ .claims = &claims, .outputs = &outputs, .latches = &.{ 0, 0, 0, 0 } };
        const out = try a.alloc(u32, desc[D.max_payload_words] + 1);
        defer a.free(out);
        const v = try encodeHost(a, desc, img, in, out);
        try t.expectEqual(G.Verdict.accepted, v.bounds);
        const exact = try Ref.encode(a, desc, img, in);
        defer a.free(exact);
        try t.expectEqualSlices(u32, exact, out[1..][0..exact.len]);
        // Too small a region: encode_bounds rejects, length stays 0.
        const small = try a.alloc(u32, exact.len);
        defer a.free(small);
        const s = try encodeHost(a, desc, img, in, small);
        try t.expectEqual(G.Verdict.accepted, s.pcs);
        try t.expectEqual(G.Verdict.reject(.encode_bounds, 1), s.bounds);
        try t.expectEqual(@as(u32, 0), small[0]);
    }
}

test "outer encode: every corrupted input class is refused with its detail (and the reference refuses too)" {
    const t = std.testing;
    const a = t.allocator;
    var prng = std.Random.DefaultPrng.init(4242);
    const r = prng.random();
    var tc: TestClass = undefined;
    while (true) {
        tc.random(r, 24, 2);
        if (buildDescriptor(a, tc.shape, testEnvelope(), null)) |d| {
            a.free(d);
            break;
        } else |_| {}
    }
    const desc = try buildDescriptor(a, tc.shape, testEnvelope(), null);
    defer a.free(desc);
    const im = Image.of(desc);
    const raw = try a.alloc(u32, 24);
    defer a.free(raw);
    // Duplicates so consistency checks have something to compare.
    for (raw, 0..) |*x, i| x.* = @intCast((i / 3) * 5 % (@as(u32, 1) << @intCast(desc[D.initial_log])));
    const good = try Synth.image(a, desc, raw, 9);
    defer a.free(good);
    const claims: [88]u32 = @splat(3);
    const outputs = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const root1: [8]u32 = good[im.roots + 8 ..][0..8].*;
    const out = try a.alloc(u32, desc[D.max_payload_words] + 1);
    defer a.free(out);
    const Case = struct { detail: PcsDetail, word: ?u64 = null, value: u32 = 0, claims: bool = false, latch: bool = false, root: bool = false };
    const tr0 = tree(desc, 0);
    // A duplicated query's second copy (index 1 duplicates index 0).
    const cases = [_]Case{
        .{ .detail = .header, .word = 0, .value = 1 },
        .{ .detail = .numerical, .word = 14, .value = 1 },
        .{ .detail = .channel, .word = 15 + 10, .value = 1 },
        .{ .detail = .query_range, .word = im.queries + 3, .value = @as(u32, 1) << @intCast(desc[D.initial_log]) },
        .{ .detail = .noncanonical, .word = im.terminal, .value = modulus },
        .{ .detail = .noncanonical, .word = im.tree_values[0], .value = modulus + 5 },
        .{ .detail = .trace_inconsistent, .word = im.tree_values[0] + 1, .value = 17 },
        .{ .detail = .trace_inconsistent, .word = im.tree_paths[0] + @as(u64, tr0.tree_log) * 8 + 2, .value = 17 },
        .{ .detail = .fri_inconsistent, .word = im.layer_values[0] + (@as(u64, 1) << @intCast(layer(desc, 0).fold_step)) * 8, .value = 17 },
        .{ .detail = .fri_inconsistent, .word = im.layer_paths[0] + (@as(u64, 1) << @intCast(layer(desc, 0).fold_step - layer(desc, 0).leaf_log)) * layerHeight(layer(desc, 0)) * 8, .value = 17 },
        .{ .detail = .section_latch, .latch = true },
        .{ .detail = .noncanonical_public, .claims = true },
        .{ .detail = .root, .root = true },
    };
    for (cases) |c| {
        const img = try a.dupe(u32, good);
        defer a.free(img);
        if (c.word) |w| img[w] = c.value;
        var cl = claims;
        if (c.claims) cl[5] = modulus;
        var latches = [_]u32{ 0, 0, 0, 0 };
        if (c.latch) latches[2] = 1;
        var in = Inputs{ .claims = &cl, .outputs = &outputs, .latches = &latches };
        var bad_root = root1;
        if (c.root) bad_root[3] ^= 1;
        if (desc[D.trees] > 1) in.roots[1] = &bad_root;
        if (c.root and desc[D.trees] == 1) in.roots[0] = &bad_root;
        const v = try encodeHost(a, desc, img, in, out);
        t.expectEqual(G.Verdict.reject(.node_pcs_status, @intFromEnum(c.detail)), v.pcs) catch |err| {
            std.debug.print("case {s}: got 0x{x}\n", .{ @tagName(c.detail), v.pcs });
            return err;
        };
        try t.expectEqual(G.Verdict.reject(.encode_bounds, 2), v.bounds);
        try t.expectEqual(@as(u32, 0), out[0]);
        // The reference rejects the image-side corruptions as well.
        if (c.word != null and c.detail != .header and c.detail != .channel and c.detail != .query_range) {
            if (Ref.encode(a, desc, img, in)) |bytes| {
                a.free(bytes);
                std.debug.print("reference accepted case {s}\n", .{@tagName(c.detail)});
                return error.TestExpectedError;
            } else |_| {}
        }
    }
}

test "outer encode: descriptor refuses shapes the host assembler refuses" {
    const t = std.testing;
    const a = t.allocator;
    const logs = [_]u32{ 3, 2 };
    const bad_perm = [_]u32{ 0, 0 };
    const counts = [_]u32{ 1, 1 };
    const cfg = Config{ .pow_bits = 1, .log_blowup = 1, .log_last_layer = 0, .n_queries = 4, .fold_step = 2, .lifting = null };
    try t.expectError(error.InvalidPcsShape, buildDescriptor(a, .{ .config = cfg, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &bad_perm, .sample_counts = &counts }} }, null, null));
    // Not ascending after the permutation.
    try t.expectError(error.InvalidPcsShape, buildDescriptor(a, .{ .config = cfg, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &.{ 0, 1 }, .sample_counts = &counts }} }, null, null));
    var c2 = cfg;
    c2.log_last_layer = 1;
    try t.expectError(error.UnsupportedFriGeometry, buildDescriptor(a, .{ .config = c2, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &.{ 1, 0 }, .sample_counts = &counts }} }, null, null));
    const d = try buildDescriptor(a, .{ .config = cfg, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &.{ 1, 0 }, .sample_counts = &counts }} }, null, null);
    defer a.free(d);
    try t.expectEqual(@as(u32, 1), d[D.tables + 2]); // sorted_to_original[0] = 1 (logs sorted: [2+1, 3+1])
    try t.expectEqual(@as(u32, 3), d[D.tables]);
    try t.expectEqual(@as(u32, 4), d[D.tables + 1]);
    // Stale magic in a descriptor fails closed at encode.
    const bad = try a.dupe(u32, d);
    defer a.free(bad);
    bad[D.magic] ^= 1;
    var out: [4]u32 = undefined;
    const v = try encodeHost(a, bad, &.{}, .{}, &out);
    try t.expectEqual(G.Verdict.reject(.node_pcs_status, 1), v.pcs);
}
