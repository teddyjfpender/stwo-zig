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
    pub const flags = 3; // bit 0: om31 wire envelope; bit 1: fixed_root is set
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
    /// `fixed_root` holds the class's FIXED root: an expected tree-0 root
    /// (Inputs.roots[0], e.g. the root the node committed and mixed into its
    /// transcript) must equal it, as must the image's tree-0 root. This is
    /// the device form of the host's InvalidOm31DeviceFixedRoot check.
    pub const flag_fixed_root: u32 = 2;
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
const layerHeight = @import("outer_encode_host.zig").layerHeight;

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
    if (fixed_root) |r| {
        d[D.flags] |= D.flag_fixed_root;
        d[D.fixed_root..][0..8].* = r;
    }
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

pub const encodeHost = @import("outer_encode_host.zig").encodeHost;

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

/// STWO_RV64_M8_OUTER_OODS_FAULT_ORDINAL=n (two-key like faultOrdinal):
/// node n's first composition sample coordinate is zeroed on the device; the
/// device node_oods_constraint check must refuse it.
pub fn oodsFaultOrdinal() !?u32 {
    const v = std.posix.getenv("STWO_RV64_M8_OUTER_OODS_FAULT_ORDINAL") orelse return null;
    const n = std.fmt.parseUnsigned(u32, v, 10) catch return error.InvalidOuterOodsFaultOrdinal;
    const armed = std.posix.getenv("STWO_RV64_M8_FAULT_INJECTION") orelse return error.M8FaultInjectionNotArmed;
    if (!std.mem.eql(u8, armed, "1")) return error.M8FaultInjectionNotArmed;
    return n;
}

/// STWO_RV64_M8_OUTER_OODS_POINT_FAULT_ORDINAL=n (two-key like faultOrdinal):
/// node n's OODS point status word is set nonzero on the device; the device
/// node_oods_constraint check must refuse it (detail point).
pub fn oodsPointFaultOrdinal() !?u32 {
    const v = std.posix.getenv("STWO_RV64_M8_OUTER_OODS_POINT_FAULT_ORDINAL") orelse return null;
    const n = std.fmt.parseUnsigned(u32, v, 10) catch return error.InvalidOuterOodsPointFaultOrdinal;
    const armed = std.posix.getenv("STWO_RV64_M8_FAULT_INJECTION") orelse return error.M8FaultInjectionNotArmed;
    if (!std.mem.eql(u8, armed, "1")) return error.M8FaultInjectionNotArmed;
    return n;
}

// ---------------------------------------------------------------------------
// Tests: the mirror against a transliteration of the host assembler +
// stwo_proof_wire writer + om31 wire.encode (hash maps, its own sort), on
// synthetic images of random class shapes; negatives per detail.

test {
    _ = @import("outer_encode_test.zig");
}
