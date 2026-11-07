//! GPU-native recursion node: device seed fill from the children's encoded
//! slab regions, device statement / FIXED transcript mix, and the
//! `seed_tape` / `child_binding` verdicts (design rv64-m8-gpu-native.md
//! §3.3, host work H16/H17/H19; kernel NAT/rv64/jobs/outer_seed.cu).
//!
//! Today the host builds every node's assignment seeds: a fold records them
//! from its children's converted captures (om31_native/fold_tape.zig
//! `record`, through `proof.fromNativeCapped` and `Emit.proof`), a leaf from
//! the native verifier's capture (leaf_tape.zig); and the host derives the
//! node's transcript prefix (om31 `prove.begin` + `MC.mixRoot`, outer_job_
//! prestage.hostCheckpoint) from host outputs. Here the same values come from
//! device data only:
//!
//!   child seed source  every child producer (outer node encoder, native
//!                      Stage 2, TruthJob) leaves its encoded proof in its
//!                      request-slab region and, after the class's wire
//!                      capacity, its enqueue-only PCS readback image
//!                      (hybrid_pcs.decodeWords layout). `Region` names the
//!                      convention (M8-INTERFACES "m8-gn-node").
//!   seed program       per node class, built at warm from the class
//!                      template (seed variables, constants) and the child
//!                      classes' PCS shapes: a list of gather ops in exactly
//!                      `Emit.proof` / `record` order, plus Merkle-cap jobs
//!                      (`proof.fromNativeCapped` + `merkle.hostCap`: the
//!                      only hashing). Every offset is a class constant
//!                      (the image layout is fixed per PCS shape and the
//!                      tape is in raw-query order), so the per-node work
//!                      is a fixed-shape gather: graph-capturable.
//!   statement          a fold's outputs are Blake2s(om31_outer.messageWords)
//!                      over the children's identity / FIXED root / outputs
//!                      (read from their regions); the node's checkpoint is
//!                      blake2s(blake2s(prefix ‖ identity ‖ n ‖ outputs) ‖
//!                      fixed_root) with the class's config/profile prefix
//!                      digest as a class constant (raw_mod_m31 mixU32s /
//!                      mixRoot are plain Blake2s of digest ‖ words).
//!
//! Verdicts: `seed_tape` (0x0305) = the program and every source passed
//! (geometry, canonical M31 values, raw query range, cap coverage, every
//! derived cap hashes to its committed root); `child_binding` (0x0306) =
//! every child region carries the om31 wire envelope of the child class this
//! slot expects (magic, profile, authority identity, output count) and its
//! image is the PCS image of that class (header, FIXED root == class root).
//!
//! `fillHost` / `statementHost` are the bit-exact host mirrors of the kernel
//! (same phases and refusal ranks); the piece harness compares device ==
//! mirror == the legacy host seeds / checkpoint on recorded real nodes.
const std = @import("std");
const Enc = @import("outer_encode.zig");

pub const modulus: u32 = 0x7fff_ffff;
pub const program_magic: u32 = 0x3144_534f; // "OSD1"
pub const program_version: u32 = 1;
pub const max_children = 8;
pub const max_queries = Enc.max_queries;
pub const image_magic: u32 = 0x5256_4d4f;
/// om31 wire magic "STWOCOM1" as two little-endian words.
pub const wire_magic = [2]u32{ 0x4f57_5453, 0x314d_4f43 };

// ---------------------------------------------------------------------------
// Blake2s (std) and the om31 Merkle hasher (vcs_lifted Blake2sPrefixedMerkleHasher)
// ---------------------------------------------------------------------------

pub const Hash = [8]u32;
const B2 = std.crypto.hash.blake2.Blake2s256;
fn prefix(comptime tag: []const u8) [64]u8 {
    var out: [64]u8 = @splat(0);
    @memcpy(out[0..tag.len], tag);
    return out;
}
pub const leaf_prefix = prefix("leaf");
pub const node_prefix = prefix("node");
fn wordsOf(bytes: [32]u8) Hash {
    var h: Hash = undefined;
    for (&h, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return h;
}
fn updateWords(b: *B2, words: []const u32) void {
    var buf: [4]u8 = undefined;
    for (words) |w| {
        std.mem.writeInt(u32, &buf, w, .little);
        b.update(&buf);
    }
}
/// Plain Blake2s-256 over the little-endian bytes of `words`.
pub fn blakeWords(parts: []const []const u32) Hash {
    var b = B2.init(.{});
    for (parts) |p| updateWords(&b, p);
    var out: [32]u8 = undefined;
    b.final(&out);
    return wordsOf(out);
}
pub fn leafHash(values: []const u32) Hash {
    var b = B2.init(.{});
    b.update(&leaf_prefix);
    updateWords(&b, values);
    var out: [32]u8 = undefined;
    b.final(&out);
    return wordsOf(out);
}
pub fn nodeHash(left: Hash, right: Hash) Hash {
    var b = B2.init(.{});
    b.update(&node_prefix);
    updateWords(&b, &left);
    updateWords(&b, &right);
    var out: [32]u8 = undefined;
    b.final(&out);
    return wordsOf(out);
}

// ---------------------------------------------------------------------------
// PCS shape and the readback image layout (hybrid_pcs.decodeWords)
// ---------------------------------------------------------------------------

pub const Tree = struct { logs: []const u32, sorted_to_original: []const u32, sample_counts: []const u32 };
pub const Shape = struct {
    pow_bits: u32,
    log_blowup: u32,
    log_last: u32,
    n_queries: u32,
    fold_step: u32,
    lifting: ?u32,
    degree_log: u32,
    trees: []const Tree,
    /// Parse outer_seed_record.appendShape words (slices borrow `words`).
    pub fn parse(a: std.mem.Allocator, words: []const u32, cursor: *usize) !Shape {
        var r = Reader{ .words = words, .at = cursor.* };
        const h = try r.take(8);
        const n: usize = h[7];
        if (n == 0 or n > Enc.max_trees) return error.GnSeedShapeInvalid;
        const trees = try a.alloc(Tree, n);
        errdefer a.free(trees);
        for (trees) |*t| {
            const c = (try r.take(1))[0];
            if (c == 0 or c > Enc.max_columns) return error.GnSeedShapeInvalid;
            t.* = .{ .logs = try r.take(c), .sorted_to_original = try r.take(c), .sample_counts = try r.take(c) };
        }
        cursor.* = r.at;
        return .{ .pow_bits = h[0], .log_blowup = h[1], .log_last = h[2], .n_queries = h[3], .fold_step = h[4], .lifting = if (h[5] == 0xffff_ffff) null else h[5], .degree_log = h[6], .trees = trees };
    }
    pub fn config(self: Shape) Enc.Config {
        return .{ .pow_bits = self.pow_bits, .log_blowup = self.log_blowup, .log_last_layer = self.log_last, .n_queries = self.n_queries, .fold_step = self.fold_step, .lifting = self.lifting };
    }
};

pub const LayerLayout = struct { root: usize, values: usize, paths: usize, step: u32, leaf_log: u32, shift: u32, count_log: u32, height: u32, slots: u32 };
pub const TreeLayout = struct { values: usize, paths: usize, height: u32, columns: u32, samples: usize };
pub const Layout = struct {
    roots: usize,
    samples: usize,
    nonce: usize,
    terminal: usize,
    queries: usize,
    initial_log: u32,
    nq: u32,
    n_layers: u32,
    layers: [Enc.max_layers]LayerLayout,
    n_trees: u32,
    trees: [Enc.max_trees]TreeLayout,
    words: usize,
    pub fn of(shape: Shape) !Layout {
        var plan: [Enc.max_layers]Enc.FriLayer = undefined;
        const n_layers = try Enc.friPlan(shape.degree_log, shape.config(), &plan);
        var out: Layout = undefined;
        out.nq = shape.n_queries;
        out.initial_log = shape.degree_log + shape.log_blowup;
        out.n_trees = @intCast(shape.trees.len);
        out.n_layers = n_layers;
        var at: usize = 14 + 1 + 16;
        out.roots = at;
        at += 8 * shape.trees.len;
        out.samples = at;
        var samples: usize = 0;
        for (shape.trees, 0..) |t, i| {
            out.trees[i].samples = at + 8 * samples;
            for (t.sample_counts) |c| samples += c;
        }
        at += 8 * samples;
        out.nonce = at;
        at += 2;
        out.terminal = at;
        at += 8;
        out.queries = at;
        at += out.nq;
        for (plan[0..n_layers], out.layers[0..n_layers]) |p, *l| {
            const count_log = std.math.log2_int(u32, p.count);
            const height = count_log - p.leaf_log;
            const slots = @as(u32, 1) << @intCast(p.fold_step - p.leaf_log);
            l.* = .{ .root = at, .values = at + 8, .paths = at + 8 + (@as(usize, out.nq) << @intCast(p.fold_step)) * 8, .step = p.fold_step, .leaf_log = p.leaf_log, .shift = p.shift, .count_log = count_log, .height = height, .slots = slots };
            at = l.paths + @as(usize, out.nq) * slots * height * 8;
        }
        for (shape.trees, 0..) |t, i| {
            var h: u32 = 0;
            for (t.logs) |log| h = @max(h, log + shape.log_blowup);
            out.trees[i].values = at;
            at += t.logs.len * out.nq;
            out.trees[i].paths = at;
            at += @as(usize, out.nq) * h * 8;
            out.trees[i].height = h;
            out.trees[i].columns = @intCast(t.logs.len);
        }
        out.words = at;
        return out;
    }
};

/// `trace.position`: a lifted query row at log `from` mapped to log `to`.
pub fn position(row: u32, from: u32, to: u32) u32 {
    return if (from >= to) ((row >> @intCast(from - to + 1)) << 1) | (row & 1) else ((row >> 1) << @intCast(to - from + 1)) | (row & 1);
}
pub fn capLogFor(height: u32, cap_log: u32) u32 {
    return if (height > cap_log) cap_log else 0;
}

// ---------------------------------------------------------------------------
// Seed program ABI (u32 words; kernel enum mirrors these)
// ---------------------------------------------------------------------------

/// Program header word indices.
pub const P = struct {
    pub const magic = 0;
    pub const version = 1;
    pub const words = 2;
    pub const n_seeds = 3;
    pub const n_constants = 4;
    pub const n_children = 5;
    pub const n_ops = 6;
    pub const ops = 7;
    pub const vars = 8;
    pub const constants = 9;
    pub const n_caps = 10;
    pub const caps = 11;
    pub const scratch_words = 12;
    pub const children = 13; // per child: Child.words
    pub const cap_log = 14;
    pub const n_tape = 15;
    // statement (fold): 0 = none (leaf: the native side supplies outputs)
    pub const statement = 16;
    pub const domain = 17;
    pub const version_word = 18;
    pub const n_outputs = 19; // the node's own outputs
    pub const prefix = 20; // offset of 8 words: class channel prefix digest
    pub const self_key = 21; // offset of 16 words: own identity, own FIXED root
    pub const profile = 22; // offset of 8 words: om31 wire profile (wire bytes 8..40)
    pub const output_map = 23; // 0 = digest word w -> Q(w & 0xffff, w >> 16, 0, 0)
    /// statement 2 (leaf): child 0's region word offset of the node's
    /// outputs (QM31, 4 words each), written by the native producer.
    pub const outputs_at = 24;
    pub const header_words = 32;
};
/// Per-child table entry.
pub const C = struct {
    pub const image = 0; // image offset (words) inside the child's region
    pub const image_words = 1;
    pub const n_outputs = 2;
    pub const wire_words = 3; // min region words before the image (1 + wire capacity)
    pub const identity = 4; // 8 words: expected child authority identity
    pub const fixed_root = 12; // 8 words: expected child FIXED (tree 0) root
    pub const words = 20;
};
pub const Kind = enum(u32) { hash = 1, word = 2, m31 = 3, om31 = 4, q = 5 };
pub const Area = enum(u32) { region = 0, image = 1, scratch = 2 };
pub const Op = extern struct {
    kind: u32,
    child: u32,
    area: u32,
    offset: u32,
    count: u32,
    stride: u32,
    rows: u32,
    row_stride: u32,
    dst: u32, // first seed record
    reserved: u32 = 0,
    pub fn seedsPerUnit(kind: Kind) u32 {
        return switch (kind) {
            .hash => 16,
            .word, .om31 => 2,
            .m31, .q => 1,
        };
    }
    pub fn wordsPerUnit(kind: Kind) u32 {
        return switch (kind) {
            .hash, .om31 => 8,
            .word, .m31 => 1,
            .q => 4,
        };
    }
};
pub const Cap = extern struct {
    kind: u32, // 0 trace tree, 1 FRI layer
    child: u32,
    height: u32, // hostCap height (tree height / layer log after the fold)
    cl: u32,
    values: u32, // image offset
    width: u32, // trace: columns; FRI: coset size 2^step
    paths: u32, // image offset of query 0's sibling at level `level0`
    path_stride: u32, // words between queries
    level0: u32,
    root: u32, // image offset of the committed root
    scratch: u32, // scratch offset of the 2^cl cap hashes
    queries: u32, // image offset of the raw queries
    nq: u32,
    from_log: u32, // trace: lifting log; FRI: layer shift
    to_log: u32, // trace: tree height; FRI: fold step
    layer_log: u32, // FRI: log size before the fold
    pack: u32, // FRI: packed leaves of 4
    reserved: [3]u32 = .{ 0, 0, 0 },
};
comptime {
    if (@sizeOf(Op) != 40 or @sizeOf(Cap) != 80) @compileError("seed program ABI");
}

/// seed_tape detail codes (kernel SeedDetail; lowest rank wins).
pub const SeedDetail = enum(u16) { program = 1, region = 2, image_header = 3, query_range = 4, noncanonical = 5, cap_mismatch = 6, cap_uncovered = 7, cap_root = 8 };
/// child_binding detail codes.
pub const BindDetail = enum(u16) { region = 1, magic = 2, profile = 3, identity = 4, outputs = 5, fixed_root = 6, noncanonical = 7 };

/// A child slot of the node class: what its region must hold.
pub const ChildClass = struct {
    shape: Shape,
    /// Region words before the image (length word + wire capacity words).
    wire_words: u32,
    n_outputs: u32,
    identity: Hash,
    fixed_root: Hash,
};

pub const Program = struct {
    words: []u32,
    pub fn deinit(self: Program, a: std.mem.Allocator) void {
        a.free(self.words);
    }
    pub fn header(self: Program, i: usize) u32 {
        return self.words[i];
    }
    pub fn ops(self: Program) []const Op {
        return std.mem.bytesAsSlice(Op, std.mem.sliceAsBytes(self.words[self.words[P.ops]..][0 .. self.words[P.n_ops] * 10]));
    }
    pub fn caps(self: Program) []const Cap {
        return std.mem.bytesAsSlice(Cap, std.mem.sliceAsBytes(self.words[self.words[P.caps]..][0 .. self.words[P.n_caps] * 20]));
    }
    pub fn child(self: Program, k: usize) []const u32 {
        return self.words[self.words[P.children] + k * C.words ..][0..C.words];
    }
};

const Builder = struct {
    a: std.mem.Allocator,
    ops: std.ArrayListUnmanaged(Op) = .empty,
    caps: std.ArrayListUnmanaged(Cap) = .empty,
    tape: u32 = 0,
    scratch: u32 = 0,
    fn op(self: *Builder, kind: Kind, child: u32, area: Area, offset: usize, count: usize, stride: usize, rows: usize, row_stride: usize) !void {
        if (count == 0 or rows == 0) return;
        const o = Op{ .kind = @intFromEnum(kind), .child = child, .area = @intFromEnum(area), .offset = @intCast(offset), .count = @intCast(count), .stride = @intCast(stride), .rows = @intCast(rows), .row_stride = @intCast(row_stride), .dst = self.tape };
        self.tape += @intCast(count * rows * Op.seedsPerUnit(kind));
        try self.ops.append(self.a, o);
    }
    /// `Emit.proof` of `fromNativeCapped(child)` in emission order.
    fn proof(self: *Builder, k: u32, s: Shape, cap_log: u32) !void {
        const L = try Layout.of(s);
        const nq = L.nq;
        for (0..L.n_trees) |t| try self.op(.hash, k, .image, L.roots + 8 * t, 1, 8, 1, 0);
        var tree_caps: [Enc.max_trees]?u32 = @splat(null);
        for (s.trees, 0..) |tree, t| {
            const tl = L.trees[t];
            // original column -> sorted image position
            var o2s_buf: [Enc.max_columns]u32 = undefined;
            const o2s = o2s_buf[0..tree.logs.len];
            for (tree.sorted_to_original, 0..) |orig, si| o2s[orig] = @intCast(si);
            var sample_at = tl.samples;
            for (0..tree.logs.len) |c| {
                const sc = tree.sample_counts[c];
                try self.op(.om31, k, .image, sample_at, sc, 8, 1, 0);
                sample_at += 8 * sc;
                try self.op(.m31, k, .image, tl.values + o2s[c] * nq, nq, 1, 1, 0);
            }
            const cl = capLogFor(tl.height, cap_log);
            try self.op(.hash, k, .image, tl.paths, tl.height - cl, 8, nq, tl.height * 8);
            if (cl != 0) {
                tree_caps[t] = self.scratch;
                try self.caps.append(self.a, .{ .kind = 0, .child = k, .height = tl.height, .cl = cl, .values = @intCast(tl.values), .width = tl.columns, .paths = @intCast(tl.paths), .path_stride = tl.height * 8, .level0 = 0, .root = @intCast(L.roots + 8 * t), .scratch = self.scratch, .queries = @intCast(L.queries), .nq = nq, .from_log = L.initial_log, .to_log = tl.height, .layer_log = 0, .pack = 0 });
                self.scratch += (@as(u32, 1) << @intCast(cl)) * 8;
            }
        }
        // caps after every tree, in tree order (Emit.proof `source.caps`)
        for (0..L.n_trees) |t| if (tree_caps[t]) |at| {
            const cl = capLogFor(L.trees[t].height, cap_log);
            try self.op(.hash, k, .scratch, at, @as(usize, 1) << @intCast(cl), 8, 1, 0);
        };
        var log = L.initial_log;
        for (L.layers[0..L.n_layers]) |l| {
            const layer_log = log;
            log -= l.step;
            const cl = capLogFor(log, cap_log);
            const subset = @as(usize, 1) << @intCast(l.step);
            try self.op(.om31, k, .image, l.values, subset, 8, nq, subset * 8);
            if (cl != 0) {
                const at = self.scratch;
                try self.caps.append(self.a, .{ .kind = 1, .child = k, .height = log, .cl = cl, .values = @intCast(l.values), .width = @intCast(subset), .paths = @intCast(l.paths + (l.step - l.leaf_log) * 8), .path_stride = l.slots * l.height * 8, .level0 = l.step - l.leaf_log, .root = @intCast(l.root), .scratch = at, .queries = @intCast(L.queries), .nq = nq, .from_log = l.shift, .to_log = l.step, .layer_log = layer_log, .pack = @intFromBool(layer_log >= 2 and l.step > 1) });
                self.scratch += (@as(u32, 1) << @intCast(cl)) * 8;
                try self.op(.hash, k, .scratch, at, @as(usize, 1) << @intCast(cl), 8, 1, 0);
            }
            try self.op(.hash, k, .image, l.root, 1, 8, 1, 0);
            try self.op(.hash, k, .image, l.paths + (l.step - l.leaf_log) * 8, log - cl, 8, nq, l.slots * l.height * 8);
        }
        try self.op(.word, k, .image, L.nonce, 2, 1, 1, 0);
        try self.op(.om31, k, .image, L.terminal, 1, 8, 1, 0);
    }
};

pub const Statement = struct {
    /// 1 = fold (outputs = Blake2s(messageWords)), 2 = outputs read from
    /// child 0's region at `outputs_at` (leaf: the native producer's words).
    kind: u32 = 1,
    outputs_at: u32 = 0,
    domain: u32,
    version_word: u32,
    n_outputs: u32,
    prefix: Hash,
    identity: Hash,
    fixed_root: Hash,
    profile: Hash,
};

/// Fold-class seed program (fold_tape.record order): per child, the
/// captured proof, the child identity (8 guessU32 words) and its outputs.
/// `vars` are the class template's seed variables (all seeds, in order);
/// `constants` the first `vars.len - tape` seeds' values (class data).
pub fn buildFold(a: std.mem.Allocator, children: []const ChildClass, cap_log: u32, vars: []const u32, constants: []const [4]u32, statement: ?Statement) !Program {
    if (children.len == 0 or children.len > max_children) return error.GnSeedProgramInvalid;
    var b = Builder{ .a = a };
    defer b.ops.deinit(a);
    defer b.caps.deinit(a);
    for (children, 0..) |c, k| {
        const kk: u32 = @intCast(k);
        try b.proof(kk, c.shape, cap_log);
        try b.op(.word, kk, .region, 1 + 10, 8, 1, 1, 0); // wire bytes 40..72: authority identity
        try b.op(.q, kk, .region, 1 + 19, c.n_outputs, 4, 1, 0); // wire outputs
    }
    return finish(a, &b, children, cap_log, vars, constants, statement);
}

/// Leaf-class seed program (leaf_tape.cpu / leaf_tape.truth order): the
/// native child's captured proof from its PCS image, then `tail` seeds the
/// native producer writes after its image (the leaf statement: ordinal,
/// statement / manifest digests, GKR transcript values, claims, request
/// words; QM31 limbs, 4 words per seed). `tail` = 0: a proof-only program.
pub fn buildLeaf(a: std.mem.Allocator, child: ChildClass, cap_log: u32, tail: u32, vars: []const u32, constants: []const [4]u32, statement: ?Statement) !Program {
    var b = Builder{ .a = a };
    defer b.ops.deinit(a);
    defer b.caps.deinit(a);
    try b.proof(0, child.shape, cap_log);
    const L = try Layout.of(child.shape);
    try b.op(.q, 0, .region, child.wire_words + L.words, tail, 4, 1, 0);
    return finish(a, &b, &.{child}, cap_log, vars, constants, statement);
}
pub fn leafTapeLength(a: std.mem.Allocator, child: ChildClass, cap_log: u32) !u32 {
    var b = Builder{ .a = a };
    defer b.ops.deinit(a);
    defer b.caps.deinit(a);
    try b.proof(0, child.shape, cap_log);
    return b.tape;
}

fn finish(a: std.mem.Allocator, b: *Builder, children: []const ChildClass, cap_log: u32, vars: []const u32, constants: []const [4]u32, statement: ?Statement) !Program {
    if (vars.len < b.tape or constants.len != vars.len - b.tape) return error.GnSeedProgramLayout;
    const n_ops = b.ops.items.len;
    const n_caps = b.caps.items.len;
    var at: usize = P.header_words;
    const off_children = at;
    at += children.len * C.words;
    const off_ops = at;
    at += n_ops * 10;
    const off_caps = at;
    at += n_caps * 20;
    const off_vars = at;
    at += vars.len;
    const off_constants = at;
    at += constants.len * 4;
    const off_stmt = at;
    if (statement != null) at += 8 + 16 + 8;
    const w = try a.alloc(u32, at);
    @memset(w, 0);
    w[P.magic] = program_magic;
    w[P.version] = program_version;
    w[P.words] = @intCast(at);
    w[P.n_seeds] = @intCast(vars.len);
    w[P.n_constants] = @intCast(constants.len);
    w[P.n_children] = @intCast(children.len);
    w[P.n_ops] = @intCast(n_ops);
    w[P.ops] = @intCast(off_ops);
    w[P.vars] = @intCast(off_vars);
    w[P.constants] = @intCast(off_constants);
    w[P.n_caps] = @intCast(n_caps);
    w[P.caps] = @intCast(off_caps);
    w[P.scratch_words] = @max(b.scratch, 8);
    w[P.children] = @intCast(off_children);
    w[P.cap_log] = cap_log;
    w[P.n_tape] = b.tape;
    for (children, 0..) |c, k| {
        const L = try Layout.of(c.shape);
        const e = w[off_children + k * C.words ..][0..C.words];
        e[C.image] = c.wire_words;
        e[C.image_words] = @intCast(L.words);
        e[C.n_outputs] = c.n_outputs;
        e[C.wire_words] = c.wire_words;
        @memcpy(e[C.identity..][0..8], &c.identity);
        @memcpy(e[C.fixed_root..][0..8], &c.fixed_root);
    }
    // Shift every op's dst by the constants (tape seeds follow them).
    for (b.ops.items, 0..) |o, i| {
        var x = o;
        x.dst += @intCast(constants.len);
        @memcpy(w[off_ops + 10 * i ..][0..10], std.mem.bytesAsSlice(u32, std.mem.asBytes(&x)));
    }
    for (b.caps.items, 0..) |c, i| @memcpy(w[off_caps + 20 * i ..][0..20], std.mem.bytesAsSlice(u32, std.mem.asBytes(&c)));
    @memcpy(w[off_vars..][0..vars.len], vars);
    for (constants, 0..) |c, i| @memcpy(w[off_constants + 4 * i ..][0..4], &c);
    if (statement) |s| {
        w[P.statement] = s.kind;
        w[P.outputs_at] = s.outputs_at;
        w[P.domain] = s.domain;
        w[P.version_word] = s.version_word;
        w[P.n_outputs] = s.n_outputs;
        w[P.prefix] = @intCast(off_stmt);
        w[P.self_key] = @intCast(off_stmt + 8);
        w[P.profile] = @intCast(off_stmt + 24);
        @memcpy(w[off_stmt..][0..8], &s.prefix);
        @memcpy(w[off_stmt + 8 ..][0..8], &s.identity);
        @memcpy(w[off_stmt + 16 ..][0..8], &s.fixed_root);
        @memcpy(w[off_stmt + 24 ..][0..8], &s.profile);
    }
    return .{ .words = w };
}

/// Words a node class's program reserves for the tape (no allocation).
pub fn tapeLength(children: []const ChildClass, cap_log: u32, a: std.mem.Allocator) !u32 {
    var b = Builder{ .a = a };
    defer b.ops.deinit(a);
    defer b.caps.deinit(a);
    for (children, 0..) |c, k| {
        try b.proof(@intCast(k), c.shape, cap_log);
        try b.op(.word, @intCast(k), .region, 11, 8, 1, 1, 0);
        try b.op(.q, @intCast(k), .region, 20, c.n_outputs, 4, 1, 0);
    }
    return b.tape;
}

// ---------------------------------------------------------------------------
// Host mirror of the kernel
// ---------------------------------------------------------------------------

pub const Verdicts = struct { seed_tape: u32 = 0, child_binding: u32 = 0 };
fn reject(check: u16, detail: anytype) u32 {
    return (@as(u32, check) << 16) | @intFromEnum(detail);
}
const seed_check: u16 = 0x0305;
const bind_check: u16 = 0x0306;

/// Seed fill: `out` = n_seeds records of 5 words {var, limb0..3}; `scratch`
/// = P.scratch_words. Child k's region is `children[k]` (length word, wire
/// words, then the image at C.image). Returns the seed_tape verdict; the
/// records are all written only when it accepts.
pub fn fillHost(program: Program, children: []const []const u32, scratch_in: []u32, out: []u32) u32 {
    const w = program.words;
    if (w.len < P.header_words or scratch_in.len < w[P.scratch_words]) return reject(seed_check, SeedDetail.program);
    const scratch = scratch_in[0..w[P.scratch_words]];
    if (w.len < P.header_words or w[P.magic] != program_magic or w[P.version] != program_version or w[P.words] != w.len or children.len != w[P.n_children] or out.len < 5 * @as(usize, w[P.n_seeds]) or scratch.len < w[P.scratch_words]) return reject(seed_check, SeedDetail.program);
    var worst: u16 = 0xffff;
    const rank = struct {
        fn note(worst_: *u16, d: SeedDetail) void {
            worst_.* = @min(worst_.*, @intFromEnum(d));
        }
    };
    // Region / image geometry and header.
    for (children, 0..) |region, k| {
        const e = program.child(k);
        if (region.len < @as(usize, e[C.image]) + e[C.image_words] or region[0] == 0) {
            rank.note(&worst, .region);
            continue;
        }
        const img = region[e[C.image]..][0..e[C.image_words]];
        if (img[0] != image_magic or img[1] != 2) rank.note(&worst, .image_header);
    }
    if (worst != 0xffff) return (@as(u32, seed_check) << 16) | worst;
    // Caps.
    for (program.caps()) |c| {
        const e = program.child(c.child);
        const img = children[c.child][e[C.image]..][0..e[C.image_words]];
        const n_cap = @as(usize, 1) << @intCast(c.cl);
        var known: [64]bool = @splat(false);
        const cap = scratch[c.scratch..][0 .. n_cap * 8];
        var bad = false;
        for (0..c.nq) |qi| {
            const q = img[c.queries + qi];
            if (c.kind == 0 and q >= (@as(u32, 1) << @intCast(c.from_log))) {
                rank.note(&worst, .query_range);
                bad = true;
                continue;
            }
            var node: Hash = undefined;
            var pos: u32 = undefined;
            if (c.kind == 0) {
                var row: [Enc.max_columns]u32 = undefined;
                for (0..c.width) |ci| {
                    const v = img[c.values + ci * c.nq + qi];
                    if (v >= modulus) rank.note(&worst, .noncanonical);
                    row[ci] = v;
                }
                node = leafHash(row[0..c.width]);
                pos = position(q, c.from_log, c.to_log);
            } else {
                node = groupRoot(img[c.values + qi * c.width * 8 ..][0 .. c.width * 8], c.pack != 0, c.to_log, &worst);
                pos = (q >> @intCast(c.from_log)) >> @intCast(c.to_log);
            }
            const walk = c.height - c.cl;
            const path = img[c.paths + qi * c.path_stride ..];
            for (0..walk) |level| {
                const sib = path[level * 8 ..][0..8].*;
                node = if ((pos >> @intCast(level)) & 1 == 1) nodeHash(sib, node) else nodeHash(node, sib);
            }
            const at: usize = pos >> @intCast(walk);
            if (at >= n_cap) {
                rank.note(&worst, .query_range);
                bad = true;
                continue;
            }
            const pairs = [2]struct { i: usize, h: Hash }{ .{ .i = at, .h = node }, .{ .i = at ^ 1, .h = path[walk * 8 ..][0..8].* } };
            for (pairs) |p| {
                if (known[p.i]) {
                    if (!std.mem.eql(u32, cap[p.i * 8 ..][0..8], &p.h)) rank.note(&worst, .cap_mismatch);
                } else {
                    @memcpy(cap[p.i * 8 ..][0..8], &p.h);
                    known[p.i] = true;
                }
            }
        }
        if (bad) continue;
        for (known[0..n_cap]) |k| if (!k) rank.note(&worst, .cap_uncovered);
        var layer: [64]Hash = undefined;
        for (0..n_cap) |i| layer[i] = cap[i * 8 ..][0..8].*;
        var n = n_cap;
        while (n > 1) {
            n /= 2;
            for (0..n) |i| layer[i] = nodeHash(layer[2 * i], layer[2 * i + 1]);
        }
        if (!std.mem.eql(u32, &layer[0], img[c.root..][0..8])) rank.note(&worst, .cap_root);
    }
    // Gather.
    const n_const = w[P.n_constants];
    const vars = w[w[P.vars]..][0..w[P.n_seeds]];
    for (0..n_const) |i| {
        out[5 * i] = vars[i];
        @memcpy(out[5 * i + 1 ..][0..4], w[w[P.constants] + 4 * i ..][0..4]);
    }
    for (program.ops()) |o| {
        const kind: Kind = @enumFromInt(o.kind);
        const src: []const u32 = switch (@as(Area, @enumFromInt(o.area))) {
            .region => children[o.child],
            .image => blk: {
                const e = program.child(o.child);
                break :blk children[o.child][e[C.image]..][0..e[C.image_words]];
            },
            .scratch => scratch,
        };
        var d: usize = o.dst;
        for (0..o.rows) |r| for (0..o.count) |u| {
            const s = o.offset + r * o.row_stride + u * o.stride;
            const n_src = Op.wordsPerUnit(kind);
            if (s + n_src > src.len) {
                rank.note(&worst, .program);
                return (@as(u32, seed_check) << 16) | worst;
            }
            const x = src[s..][0..n_src];
            switch (kind) {
                .hash => for (x) |v| {
                    put(out, vars, d, .{ v & 0xffff, 0, 0, 0 });
                    put(out, vars, d + 1, .{ v >> 16, 0, 0, 0 });
                    d += 2;
                },
                .word => {
                    put(out, vars, d, .{ x[0] & 0xffff, 0, 0, 0 });
                    put(out, vars, d + 1, .{ x[0] >> 16, 0, 0, 0 });
                    d += 2;
                },
                .m31 => {
                    if (x[0] >= modulus) rank.note(&worst, .noncanonical);
                    put(out, vars, d, .{ x[0], 0, 0, 0 });
                    d += 1;
                },
                .om31 => {
                    for (x) |v| if (v >= modulus) rank.note(&worst, .noncanonical);
                    put(out, vars, d, x[0..4].*);
                    put(out, vars, d + 1, x[4..8].*);
                    d += 2;
                },
                .q => {
                    for (x) |v| if (v >= modulus) rank.note(&worst, .noncanonical);
                    put(out, vars, d, x[0..4].*);
                    d += 1;
                },
            }
        };
    }
    return if (worst == 0xffff) 0 else (@as(u32, seed_check) << 16) | worst;
}
fn put(out: []u32, vars: []const u32, i: usize, v: [4]u32) void {
    out[5 * i] = vars[i];
    @memcpy(out[5 * i + 1 ..][0..4], &v);
}
/// proof.zig friGroupRoot: packed leaves of 4 OM31 (when `pack`), then the
/// in-coset node levels up to the coset's group root.
fn groupRoot(values: []const u32, pack: bool, step: u32, worst: *u16) Hash {
    for (values) |v| if (v >= modulus) {
        worst.* = @min(worst.*, @intFromEnum(SeedDetail.noncanonical));
    };
    const width: usize = if (pack) 4 else 1;
    const n_leaves = (values.len / 8) / width;
    var level: [16]Hash = undefined;
    for (0..n_leaves) |i| level[i] = leafHash(values[i * width * 8 ..][0 .. width * 8]);
    const nfolds = step - (if (pack) @as(u32, 2) else 0);
    var n = n_leaves;
    for (0..nfolds) |_| {
        n /= 2;
        for (0..n) |i| level[i] = nodeHash(level[2 * i], level[2 * i + 1]);
    }
    return level[0];
}

/// Fold statement mirror: the node's outputs (4 words each) and its
/// transcript checkpoint (9 words) from the children's regions; returns the
/// child_binding verdict.
pub fn statementHost(program: Program, children: []const []const u32, outputs: []u32, checkpoint: *[9]u32) u32 {
    const w = program.words;
    const kind = w[P.statement];
    if (kind != 1 and kind != 2) return reject(bind_check, BindDetail.region);
    var worst: u16 = 0xffff;
    const n_self = w[P.n_outputs];
    if (outputs.len < 4 * @as(usize, n_self)) return reject(bind_check, BindDetail.region);
    if (kind == 2) {
        const r = children[0];
        const at = w[P.outputs_at];
        if (r.len < @as(usize, at) + 4 * n_self) return reject(bind_check, BindDetail.region);
        for (r[at..][0 .. 4 * n_self]) |v| if (v >= modulus) {
            worst = @min(worst, @intFromEnum(BindDetail.noncanonical));
        };
        @memcpy(outputs[0 .. 4 * n_self], r[at..][0 .. 4 * n_self]);
    } else {
        var msg: std.ArrayListUnmanaged(u32) = .empty;
        const a = std.heap.page_allocator;
        defer msg.deinit(a);
        msg.appendSlice(a, &.{ w[P.domain], w[P.version_word] }) catch return reject(bind_check, BindDetail.region);
        const profile = w[w[P.profile]..][0..8];
        for (children, 0..) |region, k| {
            const e = program.child(k);
            const n_out = e[C.n_outputs];
            if (region.len < @as(usize, e[C.image]) + e[C.image_words] or region[0] < 4 * (19 + 4 * n_out) or e[C.image] < 20 + 4 * n_out) {
                worst = @min(worst, @intFromEnum(BindDetail.region));
                continue;
            }
            if (region[1] != wire_magic[0] or region[2] != wire_magic[1]) worst = @min(worst, @intFromEnum(BindDetail.magic));
            if (!std.mem.eql(u32, region[3..11], profile)) worst = @min(worst, @intFromEnum(BindDetail.profile));
            if (!std.mem.eql(u32, region[11..19], e[C.identity..][0..8])) worst = @min(worst, @intFromEnum(BindDetail.identity));
            if (region[19] != n_out) worst = @min(worst, @intFromEnum(BindDetail.outputs));
            const img = region[e[C.image]..];
            const roots_at: usize = 14 + 1 + 16;
            if (!std.mem.eql(u32, img[roots_at..][0..8], e[C.fixed_root..][0..8])) worst = @min(worst, @intFromEnum(BindDetail.fixed_root));
            for (region[20..][0 .. 4 * n_out]) |v| if (v >= modulus) {
                worst = @min(worst, @intFromEnum(BindDetail.noncanonical));
            };
            msg.appendSlice(a, region[11..19]) catch {};
            msg.appendSlice(a, img[roots_at..][0..8]) catch {};
            msg.append(a, n_out) catch {};
            msg.appendSlice(a, region[20..][0 .. 4 * n_out]) catch {};
        }
        const digest = blakeWords(&.{msg.items});
        for (0..n_self) |i| {
            const v = if (i < 8) digest[i] else 0;
            outputs[4 * i ..][0..4].* = .{ v & 0xffff, v >> 16, 0, 0 };
        }
    }
    const self_key = w[w[P.self_key]..][0..16];
    var head: [9]u32 = undefined;
    @memcpy(head[0..8], self_key[0..8]);
    head[8] = n_self;
    const d1 = blakeWords(&.{ w[w[P.prefix]..][0..8], &head, outputs[0 .. 4 * n_self] });
    const d2 = blakeWords(&.{ &d1, self_key[8..16] });
    @memcpy(checkpoint[0..8], &d2);
    checkpoint[8] = 0;
    return if (worst == 0xffff) 0 else (@as(u32, bind_check) << 16) | worst;
}

// ---------------------------------------------------------------------------
// Recorded real data (outer_seed_record.zig) for the piece harness
// ---------------------------------------------------------------------------

const Reader = struct {
    words: []const u32,
    at: usize,
    fn take(self: *Reader, n: usize) ![]const u32 {
        if (n > self.words.len - self.at) return error.GnRecordTruncated;
        const s = self.words[self.at..][0..n];
        self.at += n;
        return s;
    }
};

pub const Record = struct {
    words: []const u32,
    ordinal: u32,
    is_leaf: bool,
    identity: Hash,
    fixed_root: Hash,
    class: Hash,
    checkpoint: [9]u32,
    expected: []const u32,
    seeds: []const u32,
    shape: Shape,
    image: []const u32,
    claims: []const u32,
    wire: []const u8,
    /// Class transcript prefix checkpoint (config + profile mixes).
    prefix: [9]u32,
    pub fn parse(a: std.mem.Allocator, words: []const u32) !Record {
        var r = Reader{ .words = words, .at = 0 };
        const h = try r.take(4);
        if (h[0] != 0x31524e47 or h[1] != 2) return error.GnRecordMagic;
        var out: Record = undefined;
        out.words = words;
        out.ordinal = h[2];
        out.is_leaf = h[3] != 0;
        out.identity = (try r.take(8))[0..8].*;
        out.fixed_root = (try r.take(8))[0..8].*;
        out.class = (try r.take(8))[0..8].*;
        out.checkpoint = (try r.take(9))[0..9].*;
        out.expected = try r.take((try r.take(1))[0]);
        out.seeds = try r.take((try r.take(1))[0]);
        out.shape = try Shape.parse(a, words, &r.at);
        out.image = try r.take((try r.take(1))[0]);
        out.claims = try r.take((try r.take(1))[0]);
        const n = (try r.take(1))[0];
        out.wire = std.mem.sliceAsBytes(try r.take((n + 3) / 4))[0..n];
        out.prefix = (try r.take(9))[0..9].*;
        return out;
    }
    /// The child region the device would read: [byte length, wire words
    /// (padded to `wire_words - 1`), image].
    pub fn region(self: *const Record, a: std.mem.Allocator, wire_words: u32) ![]u32 {
        const need = (self.wire.len + 3) / 4 + 1;
        if (need > wire_words) return error.GnRecordWireCapacity;
        const out = try a.alloc(u32, wire_words + self.image.len);
        @memset(out, 0);
        out[0] = @intCast(self.wire.len);
        @memcpy(std.mem.sliceAsBytes(out[1..need])[0..self.wire.len], self.wire);
        @memcpy(out[wire_words..], self.image);
        return out;
    }
    pub fn deinit(self: *Record, a: std.mem.Allocator) void {
        a.free(self.shape.trees);
    }
};

pub const PcsRecord = struct {
    shape: Shape,
    image: []const u32,
    pub fn parse(a: std.mem.Allocator, words: []const u32) !PcsRecord {
        if (words.len < 2 or words[0] != 0x31504e47 or words[1] != 1) return error.GnRecordMagic;
        var at: usize = 2;
        const shape = try Shape.parse(a, words, &at);
        var r = Reader{ .words = words, .at = at };
        return .{ .shape = shape, .image = try r.take((try r.take(1))[0]) };
    }
};

// ---------------------------------------------------------------------------
// Device ABI (NAT/rv64/jobs/outer_seed.cu)
// ---------------------------------------------------------------------------

pub const Io = extern struct {
    program: [*]const u32,
    program_words: u64,
    children: [max_children]?[*]const u32,
    children_words: [max_children]u64,
    seeds: [*]u32, // 5 x n_seeds
    seeds_words: u64,
    scratch: [*]u32, // P.scratch_words + 8 (the last 8: refusal rank)
    scratch_words: u64,
    seed_status: *u32,
    bind_status: ?*u32 = null, // with outputs/checkpoint: the fold statement
    outputs: ?[*]u32 = null, // 4 x n_outputs
    checkpoint: ?[*]u32 = null, // 9 words
    /// Optional second copies (e.g. the node's channel seed + a job-slab
    /// field the host reads back in check mode).
    outputs_copy: ?[*]u32 = null,
    checkpoint_copy: ?[*]u32 = null,
    outputs_words: u32 = 0,
    n_children: u32,
    /// Launch geometry (host copies of the program's n_ops / n_caps; the
    /// kernel refuses a program that disagrees).
    n_ops: u32,
    n_caps: u32,
};
comptime {
    if (@sizeOf(Io) != 240) @compileError("outer seed Io ABI");
}
pub const Symbols = struct {
    fill: *const fn (*anyopaque, u32, *const Io) callconv(.c) c_int,
    pub fn load(lib: *std.DynLib) !Symbols {
        const Version = *const fn () callconv(.c) u32;
        const v = lib.lookup(Version, "stwo_rv64_outer_seed_version") orelse return error.MissingOuterSeedKernel;
        if (v() != 1) return error.OuterSeedKernelVersion;
        return .{ .fill = lib.lookup(@FieldType(Symbols, "fill"), "stwo_rv64_outer_seed_fill_v1_on") orelse return error.MissingOuterSeedKernel };
    }
};

// ---------------------------------------------------------------------------
// Tests (host only; the real-data harness is outer_seed_harness_test.zig)
// ---------------------------------------------------------------------------

test "seed program: merkle hashes match the domain-prefixed convention" {
    // leaf("") with prefix only differs from node(0,0); both differ from plain.
    const l = leafHash(&.{});
    const n = nodeHash(@splat(0), @splat(0));
    try std.testing.expect(!std.mem.eql(u32, &l, &n));
    try std.testing.expect(!std.mem.eql(u32, &l, &blakeWords(&.{&.{}})));
}

test "seed program: trace.position matches lifting" {
    try std.testing.expectEqual(@as(u32, 5), position(5, 4, 4));
    // from 5 to 3: drop 2 bits above bit 0
    try std.testing.expectEqual(@as(u32, (0b10110 >> 3) << 1 | 0), position(0b10110, 5, 3));
}

/// Synthetic child (tests): a PCS image whose trace trees are real Merkle
/// trees over pseudo-random rows, with `queries` raw queries.
const Synthetic = struct {
    shape: Shape,
    image: []u32,
    region: []u32,
    trees_store: [2]Tree,
    logs: [2][3]u32,
    s2o: [2][3]u32,
    sc: [2][3]u32,
    fn init(self: *Synthetic, a: std.mem.Allocator, seed: u64, wire_words: u32) !void {
        var rng = std.Random.DefaultPrng.init(seed);
        const r = rng.random();
        self.logs = .{ .{ 3, 2, 3 }, .{ 3, 3, 1 } };
        self.s2o = .{ .{ 1, 0, 2 }, .{ 2, 0, 1 } };
        self.sc = .{ .{ 1, 0, 2 }, .{ 1, 1, 0 } };
        for (&self.trees_store, 0..) |*t, i| t.* = .{ .logs = &self.logs[i], .sorted_to_original = &self.s2o[i], .sample_counts = &self.sc[i] };
        self.shape = .{ .pow_bits = 1, .log_blowup = 1, .log_last = 0, .n_queries = 6, .fold_step = 1, .lifting = null, .degree_log = 3, .trees = &self.trees_store };
        const L = try Layout.of(self.shape);
        self.image = try a.alloc(u32, L.words);
        for (self.image) |*w| w.* = r.int(u32) & 0x3fff_ffff;
        self.image[0] = image_magic;
        self.image[1] = 2;
        const queries = self.image[L.queries..][0..L.nq];
        for (queries) |*q| q.* = r.uintLessThan(u32, @as(u32, 1) << @intCast(L.initial_log));
        for (0..2) |t| {
            const tl = L.trees[t];
            const h = tl.height;
            const n = @as(usize, 1) << @intCast(h);
            // rows (sorted column order) per tree position
            const rows = try a.alloc(u32, n * tl.columns);
            defer a.free(rows);
            for (rows) |*v| v.* = r.uintLessThan(u32, modulus);
            var levels = try a.alloc([]Hash, h + 1);
            defer {
                for (levels) |l| a.free(l);
                a.free(levels);
            }
            levels[0] = try a.alloc(Hash, n);
            for (0..n) |p| levels[0][p] = leafHash(rows[p * tl.columns ..][0..tl.columns]);
            for (1..h + 1) |l| {
                levels[l] = try a.alloc(Hash, n >> @intCast(l));
                for (levels[l], 0..) |*x, i| x.* = nodeHash(levels[l - 1][2 * i], levels[l - 1][2 * i + 1]);
            }
            @memcpy(self.image[L.roots + 8 * t ..][0..8], &levels[h][0]);
            for (queries, 0..) |q, qi| {
                const p = position(q, L.initial_log, h);
                for (0..tl.columns) |ci| self.image[tl.values + ci * L.nq + qi] = rows[p * tl.columns + ci];
                for (0..h) |l| @memcpy(self.image[tl.paths + (qi * h + l) * 8 ..][0..8], &levels[l][(p >> @intCast(l)) ^ 1]);
            }
        }
        // canonical samples / FRI values / terminal
        for (self.image[L.samples..L.queries]) |*w| w.* &= 0x3fff_ffff;
        self.region = try a.alloc(u32, wire_words + L.words);
        @memset(self.region, 0);
        self.region[0] = 4 * (wire_words - 1);
        @memcpy(self.region[wire_words..], self.image);
    }
    fn deinit(self: *Synthetic, a: std.mem.Allocator) void {
        a.free(self.image);
        a.free(self.region);
    }
};

test "seed program: synthetic children fill, caps verified, negatives fail closed" {
    const t = std.testing;
    const a = t.allocator;
    var c0: Synthetic = undefined;
    try c0.init(a, 1, 64);
    defer c0.deinit(a);
    var c1: Synthetic = undefined;
    try c1.init(a, 2, 64);
    defer c1.deinit(a);
    const classes = [_]ChildClass{
        .{ .shape = c0.shape, .wire_words = 64, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) },
        .{ .shape = c1.shape, .wire_words = 64, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) },
    };
    const tape = try tapeLength(&classes, 3, a);
    const n_const = 5;
    const vars = try a.alloc(u32, tape + n_const);
    defer a.free(vars);
    for (vars, 0..) |*v, i| v.* = @intCast(1000 + i);
    const constants = [_][4]u32{ .{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, .{ 9, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 1, 1, 1, 1 } };
    const prog = try buildFold(a, &classes, 3, vars, &constants, null);
    defer prog.deinit(a);
    try t.expectEqual(@as(u32, 4), prog.header(P.n_caps)); // 2 children x 2 trees of height 4 > cap_log 3
    const scratch = try a.alloc(u32, prog.header(P.scratch_words) + 8);
    defer a.free(scratch);
    const out = try a.alloc(u32, 5 * vars.len);
    defer a.free(out);
    const regions = [_][]const u32{ c0.region, c1.region };
    try t.expectEqual(@as(u32, 0), fillHost(prog, &regions, scratch, out));
    for (0..vars.len) |i| try t.expectEqual(vars[i], out[5 * i]);
    try t.expectEqualSlices(u32, &constants[1], out[5 * 1 + 1 ..][0..4]);
    // First tape seeds: child 0 tree-0 root, as 16-bit halves.
    const L = try Layout.of(c0.shape);
    try t.expectEqual(c0.image[L.roots] & 0xffff, out[5 * n_const + 1]);
    try t.expectEqual(c0.image[L.roots] >> 16, out[5 * (n_const + 1) + 1]);
    // Corrupt one path sibling below the cap: the derived cap no longer
    // hashes to the committed root (or two queries disagree).
    const bad = try a.dupe(u32, c1.region);
    defer a.free(bad);
    const L1 = try Layout.of(c1.shape);
    bad[64 + L1.trees[0].paths] ^= 1;
    const regions_bad = [_][]const u32{ c0.region, bad };
    const v = fillHost(prog, &regions_bad, scratch, out);
    try t.expect(v == (@as(u32, 0x0305) << 16 | @intFromEnum(SeedDetail.cap_mismatch)) or v == (@as(u32, 0x0305) << 16 | @intFromEnum(SeedDetail.cap_root)));
    // A noncanonical queried value.
    @memcpy(bad, c1.region);
    bad[64 + L1.trees[1].values] = modulus;
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(SeedDetail.noncanonical)), fillHost(prog, &regions_bad, scratch, out));
    // An empty child region (encoder never ran / overrun refused).
    @memcpy(bad, c1.region);
    bad[0] = 0;
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(SeedDetail.region)), fillHost(prog, &regions_bad, scratch, out));
    // A bad image header.
    @memcpy(bad, c1.region);
    bad[64] = 0;
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(SeedDetail.image_header)), fillHost(prog, &regions_bad, scratch, out));
    // Wrong child count or a corrupted program.
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(SeedDetail.program)), fillHost(prog, regions[0..1], scratch, out));
}
