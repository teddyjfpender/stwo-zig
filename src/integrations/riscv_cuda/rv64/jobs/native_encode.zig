//! M8 GPU-native device ProofEncoder and Stage-2 device checks of a native
//! segment (rv64-m8-gpu-native.md §3.4/§3.5, inventory H10/H11/H13; stream
//! native, piece n-stage2). Kernels: NAT/rv64/jobs/native_encode_proof.cu,
//! NAT/rv64/jobs/native_encode_checks.cu.
//!
//! The encoder writes into the proof's request-slab region exactly the bytes
//! the hybrid host assembly produced per segment (0.26-3.13 s/segment [M]):
//!
//!   WP.encodePhysical(.{ .commitment_scheme_proof =
//!       hybrid_pcs.decodeWords(shape, pcs_words).proof })
//!
//! from the enqueue-only PCS Result.words still in the job arena. Everything
//! the host derived from the class shape (PCS word offsets, tree / FRI
//! geometry, the static wire prefix: magic, config, commitments, sampled
//! values) is a per-class `Program` built once at warm; only the data-dependent
//! parts (query sort, duplicate consistency, Merkle witness selection,
//! queried values) run on device. The encoder also writes the proof's
//! `pcs_status` (decodeWords' header / status / channel checks) and
//! `encode_bounds` (capacity, canonical values, query range, consistency)
//! verdict words; a reject leaves length 0.
//!
//! Checks (one Verdict word each): root_match, words_zero (global_status,
//! composition_accept), public_claims (device RAM boundary reduction), plus
//! the felt patch kernel the Stage-2 job uses for device-drawn parameters.
//! Pure host here except the symbol calls; no waits, no readbacks.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const Assembly = @import("../pcs_assembly.zig");
const F = @import("../fri.zig");

// ---------------------------------------------------------------------------
// Encode program (per class)
// ---------------------------------------------------------------------------

pub const program_magic: u32 = 0x314e454e; // "NEN1"
pub const max_queries: u32 = 1024;
/// Device scratch of the encoder (native_encode_proof.cu layout: node, rep,
/// node2, rep2 at 4 Ki words each, then flags 5 Ki + 16 Ki words).
pub const scratch_words: u32 = 37 * 1024 + 1024;
/// "STWOPRW8" as two little-endian words (proof_wire BINARY_WIRE_MAGIC, OM31).
pub const wire_magic = [2]u32{ 0x4f575453, 0x38575250 };

/// Program header word indices (native_encode_proof.cu `Header`, same order).
pub const H = enum(u32) {
    magic = 0,
    trees,
    queries,
    layers,
    beta,
    initial_log,
    degree_log,
    sample_count,
    pcs_words,
    config0,
    config1,
    config2,
    config3,
    config4,
    config5,
    capacity_words,
    tree_table,
    layer_table,
    off_roots,
    off_samples,
    off_nonce,
    off_terminal,
    off_queries,
    scratch_words,
    prefix_words,
    const_table,
    const_count,
    run_table,
    run_count,
    inverse_table,
    header_words,
};
pub const tree_record: usize = 8;
pub const layer_record: usize = 8;

pub const Program = struct {
    a: std.mem.Allocator,
    words: []u32,
    /// Worst-case encoded bytes of the class (ClassEntry.max_encoded_bytes).
    max_encoded_bytes: usize,
    pcs_words: usize,

    pub fn deinit(self: *Program) void {
        self.a.free(self.words);
        self.* = undefined;
    }
    pub fn get(self: *const Program, h: H) u32 {
        return self.words[@intFromEnum(h)];
    }

    /// The program of one PCS class (`PcsJob.prepared.metadata.shape`): the
    /// same geometry `decodeWords` + `assemble` + the wire writer read.
    pub fn build(a: std.mem.Allocator, shape: Assembly.Shape) !Program {
        const plan = try F.Plan.init(shape.degree_log, shape.config.fri_config);
        try plan.validate();
        const beta = shape.config.fri_config.log_blowup_factor;
        const T = shape.trees.len;
        if (T == 0 or T > 4 or plan.queries == 0 or plan.queries > max_queries) return error.InvalidNativeEncodeShape;
        // assemble's shape validation, verbatim.
        var sample_count: usize = 0;
        for (shape.trees) |tree| {
            if (tree.coefficient_logs.len == 0 or tree.coefficient_logs.len > 65536 or tree.sorted_to_original.len != tree.coefficient_logs.len or tree.sample_counts.len != tree.coefficient_logs.len) return error.InvalidNativeEncodeShape;
            for (tree.coefficient_logs, tree.sample_counts) |log, count| {
                if (log < 1 or log > 28 - beta or count > 5 or (count != 0 and log > shape.degree_log)) return error.InvalidNativeEncodeShape;
                sample_count += count;
            }
            const seen = try a.alloc(bool, tree.coefficient_logs.len);
            defer a.free(seen);
            @memset(seen, false);
            var previous: u32 = 0;
            for (tree.sorted_to_original) |o| {
                if (o >= seen.len or seen[o]) return error.InvalidNativeEncodeShape;
                seen[o] = true;
                const log = tree.coefficient_logs[o] + beta;
                if (log < previous) return error.InvalidNativeEncodeShape;
                previous = log;
            }
        }
        const Q: u32 = @intCast(plan.queries);
        var out: std.ArrayListUnmanaged(u32) = .empty;
        errdefer out.deinit(a);
        try out.appendNTimes(a, 0, @intFromEnum(H.header_words));
        // PCS Result.words offsets (decodeWords reading order).
        var at: usize = 14 + 1 + 16;
        const off_roots = at;
        at += T * 8;
        const off_samples = at;
        at += sample_count * 8;
        const off_nonce = at;
        at += 2;
        const off_terminal = at;
        at += 8;
        const off_queries = at;
        at += Q;
        const layer_table = out.items.len;
        try out.appendNTimes(a, 0, plan.len * layer_record);
        for (plan.layers[0..plan.len], 0..) |l, i| {
            const r = out.items[layer_table + i * layer_record ..][0..layer_record];
            r[0] = l.fold_step;
            r[1] = l.leaf_log;
            r[2] = l.shift;
            r[3] = l.height();
            r[4] = @intCast(at);
            at += 8;
            r[5] = @intCast(at);
            at += l.valueWords(Q);
            r[6] = @intCast(at);
            at += l.pathWords(Q);
        }
        const tree_table = out.items.len;
        try out.appendNTimes(a, 0, T * tree_record);
        var tree_logs: [4]u32 = undefined;
        for (shape.trees, 0..) |tree, t| {
            const tl = std.mem.max(u32, tree.coefficient_logs) + beta;
            tree_logs[t] = tl;
            const n: u32 = @intCast(tree.coefficient_logs.len);
            const logs_off = out.items.len;
            for (tree.sorted_to_original) |o| try out.append(a, tree.coefficient_logs[o] + beta);
            const inverse_off = out.items.len;
            try out.appendNTimes(a, 0, n);
            for (tree.sorted_to_original, 0..) |o, k| out.items[inverse_off + o] = @intCast(k);
            const r = out.items[tree_table + t * tree_record ..][0..tree_record];
            r[0] = n;
            r[1] = tl;
            r[2] = @intCast(logs_off);
            r[3] = @intCast(inverse_off);
            r[4] = @intCast(at);
            at += @as(usize, n) * Q;
            r[5] = @intCast(at);
            at += @as(usize, Q) * tl * 8;
        }
        const pcs_words = at;
        // Static wire prefix: consts (dst, value) and copy runs (dst, src, len).
        var consts: std.ArrayListUnmanaged([2]u32) = .empty;
        defer consts.deinit(a);
        var runs: std.ArrayListUnmanaged([3]u32) = .empty;
        defer runs.deinit(a);
        var w: u32 = 0;
        const C = struct {
            fn put(list: *std.ArrayListUnmanaged([2]u32), al: std.mem.Allocator, cursor: *u32, v: u32) !void {
                try list.append(al, .{ cursor.*, v });
                cursor.* += 1;
            }
        };
        const pc = shape.config;
        const config_words = [6]u32{ pc.pow_bits, pc.fri_config.log_blowup_factor, pc.fri_config.log_last_layer_degree_bound, @intCast(pc.fri_config.n_queries), pc.fri_config.fold_step, pc.lifting_log_size orelse std.math.maxInt(u32) };
        for (wire_magic) |v| try C.put(&consts, a, &w, v);
        for (config_words) |v| try C.put(&consts, a, &w, v);
        try C.put(&consts, a, &w, @intCast(T));
        try runs.append(a, .{ w, @intCast(off_roots), @intCast(T * 8) });
        w += @intCast(T * 8);
        try C.put(&consts, a, &w, @intCast(T));
        var src: usize = off_samples;
        for (shape.trees) |tree| {
            try C.put(&consts, a, &w, @intCast(tree.sample_counts.len));
            for (tree.sample_counts) |count| {
                try C.put(&consts, a, &w, count);
                if (count != 0) {
                    try runs.append(a, .{ w, @intCast(src), count * 8 });
                    w += count * 8;
                    src += @as(usize, count) * 8;
                }
            }
        }
        try C.put(&consts, a, &w, @intCast(T)); // decommitments: tree count
        const prefix_words = w;
        const const_table = out.items.len;
        for (consts.items) |c| try out.appendSlice(a, &c);
        const run_table = out.items.len;
        for (runs.items) |r| try out.appendSlice(a, &r);
        // Worst case: every witness at its bound (trace: Q*tl hashes; FRI:
        // Q*subset values, Q*slots*height hashes), R = Q queried rows.
        var cap: usize = prefix_words;
        for (0..T) |t| cap += 1 + 8 * @as(usize, Q) * tree_logs[t];
        cap += 1;
        for (shape.trees) |tree| cap += 1 + tree.coefficient_logs.len * (1 + @as(usize, Q));
        cap += 2;
        for (plan.layers[0..plan.len]) |l| {
            const subset = @as(usize, 1) << @intCast(l.fold_step);
            const slots = @as(usize, 1) << @intCast(l.fold_step - l.leaf_log);
            cap += 1 + 8 * Q * subset + 1 + 8 * Q * slots * l.height() + 8;
        }
        cap += 1 + 9;
        if (cap > std.math.maxInt(u32) or pcs_words > std.math.maxInt(u32)) return error.InvalidNativeEncodeShape;
        const hdr = out.items[0..@intFromEnum(H.header_words)];
        const set = struct {
            fn f(h: []u32, k: H, v: anytype) void {
                h[@intFromEnum(k)] = @intCast(v);
            }
        }.f;
        set(hdr, .magic, program_magic);
        set(hdr, .trees, T);
        set(hdr, .queries, Q);
        set(hdr, .layers, plan.len);
        set(hdr, .beta, beta);
        set(hdr, .initial_log, plan.initial_log);
        set(hdr, .degree_log, shape.degree_log);
        set(hdr, .sample_count, sample_count);
        set(hdr, .pcs_words, pcs_words);
        for (config_words, 0..) |v, i| hdr[@intFromEnum(H.config0) + i] = v;
        set(hdr, .capacity_words, cap);
        set(hdr, .tree_table, tree_table);
        set(hdr, .layer_table, layer_table);
        set(hdr, .off_roots, off_roots);
        set(hdr, .off_samples, off_samples);
        set(hdr, .off_nonce, off_nonce);
        set(hdr, .off_terminal, off_terminal);
        set(hdr, .off_queries, off_queries);
        set(hdr, .scratch_words, scratch_words);
        set(hdr, .prefix_words, prefix_words);
        set(hdr, .const_table, const_table);
        set(hdr, .const_count, consts.items.len);
        set(hdr, .run_table, run_table);
        set(hdr, .run_count, runs.items.len);
        set(hdr, .inverse_table, 0);
        return .{ .a = a, .words = try out.toOwnedSlice(a), .max_encoded_bytes = cap * 4, .pcs_words = pcs_words };
    }

    /// Region words of one proof of this class (length word + bytes).
    pub fn regionWords(self: *const Program) usize {
        return 1 + self.get(.capacity_words);
    }
};

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

pub const RootMatch = extern struct {
    expected: [4]?[*]const u32 = @splat(null),
    trees: u32,
    fixed: [8]u32 = @splat(0),
    check_fixed: u32 = 0,
};
pub const Boundary = extern struct {
    claim: u32 = std.math.maxInt(u32),
    cells: u32 = 0,
    initial: u32 = 0,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(RootMatch) != 72 or @sizeOf(Boundary) != 16) @compileError("native check ABI changed");
}

pub const EncodeFn = *const fn (*anyopaque, u32, [*]const u32, u64, [*]const u32, u64, [*]u32, u64, [*]u32, u64, [*]u32, [*]u32, [*]const u32) callconv(.c) c_int;
pub const RootFn = *const fn (*anyopaque, u32, [*]const u32, u64, *const RootMatch, [*]u32) callconv(.c) c_int;
pub const ZeroFn = *const fn (*anyopaque, u32, [*]const u32, u32, u32, [*]u32) callconv(.c) c_int;
pub const PublicScratchFn = *const fn (u32, u32) callconv(.c) u64;
pub const PublicFn = *const fn (*anyopaque, u32, [*]const u32, u32, [*]const u32, ?[*]const u32, *const Boundary, ?[*]const u32, *const Boundary, [*]u32, u64, [*]u32) callconv(.c) c_int;
pub const PatchFn = *const fn (*anyopaque, u32, [*]const u32, u32, [*]const u32, [*]const u32, u32, [*]u32, u64) callconv(.c) c_int;

pub const Symbols = struct {
    encode: EncodeFn,
    root_match: RootFn,
    words_zero: ZeroFn,
    public_scratch: PublicScratchFn,
    public_claims: PublicFn,
    patch: PatchFn,
    pub fn load(addon: *std.DynLib) !Symbols {
        return .{
            .encode = addon.lookup(EncodeFn, "stwo_rv64_native_encode_proof_v1_on") orelse return error.MissingNativeEncodeSymbol,
            .root_match = addon.lookup(RootFn, "stwo_rv64_native_root_match_v1_on") orelse return error.MissingNativeEncodeSymbol,
            .words_zero = addon.lookup(ZeroFn, "stwo_rv64_native_words_zero_check_v1_on") orelse return error.MissingNativeEncodeSymbol,
            .public_scratch = addon.lookup(PublicScratchFn, "stwo_rv64_native_public_claims_scratch_words_v1") orelse return error.MissingNativeEncodeSymbol,
            .public_claims = addon.lookup(PublicFn, "stwo_rv64_native_public_claims_check_v1_on") orelse return error.MissingNativeEncodeSymbol,
            .patch = addon.lookup(PatchFn, "stwo_rv64_native_patch_felts_v1_on") orelse return error.MissingNativeEncodeSymbol,
        };
    }
};

fn check(rc: c_int) !void {
    if (rc != 0) return error.CudaEnqueueFailed;
}

// ---------------------------------------------------------------------------
// Encoder (gpu_native.ProofEncoder) and check enqueues
// ---------------------------------------------------------------------------

/// One proof's encoder. `program` is the class program on device (class
/// cache / persistent region), `host` the same words on the host (launch
/// validation only), `pcs` the proof's PCS words in the job arena,
/// `scratch` `scratch_words` arena words, `pcs_status` the proof's
/// Check.pcs_status word. Implements gpu_native.ProofEncoder (whose status
/// argument is the encode_bounds word).
pub const Encoder = struct {
    sym: *const Symbols,
    program: api.DeviceBuffer,
    host: *const Program,
    pcs: api.DeviceBuffer,
    scratch: api.DeviceBuffer,
    pcs_status: api.DeviceBuffer,

    pub fn encoder(self: *Encoder) G.ProofEncoder {
        return .{ .ctx = self, .enqueue = enqueueOf };
    }
    fn enqueueOf(raw: *anyopaque, e: *api.Enqueue, region: api.DeviceBuffer, status: api.DeviceBuffer) anyerror!void {
        const self: *Encoder = @ptrCast(@alignCast(raw));
        return self.enqueue(e.ctx(), region, status);
    }
    pub fn enqueue(self: *const Encoder, ctx: *anyopaque, region: api.DeviceBuffer, encode_status: api.DeviceBuffer) !void {
        if (self.pcs.words != self.host.pcs_words or self.scratch.words < scratch_words or region.words < 2 or self.program.words != self.host.words.len or encode_status.words < 1 or self.pcs_status.words < 1) return error.InvalidNativeEncodeSpan;
        try check(self.sym.encode(ctx, 0, self.program.ptr, self.program.words, self.pcs.ptr, self.pcs.words, self.scratch.ptr, self.scratch.words, region.ptr, region.words, self.pcs_status.ptr, encode_status.ptr, self.host.words.ptr));
    }
};

/// Check.root_match: PCS-rebuilt roots == the committed roots (`expected`,
/// 8 device words each: FIXED, MAIN, INTER, composition), and the committed
/// FIXED root == the class FIXED authority `fixed`.
pub fn rootMatch(sym: *const Symbols, ctx: *anyopaque, pcs: api.DeviceBuffer, expected: []const api.DeviceBuffer, fixed: ?[32]u8, verdict: api.DeviceBuffer) !void {
    if (expected.len == 0 or expected.len > 4 or verdict.words < 1) return error.InvalidNativeCheckSpan;
    var args = RootMatch{ .trees = @intCast(expected.len) };
    for (expected, 0..) |b, t| {
        if (b.words < 8) return error.InvalidNativeCheckSpan;
        args.expected[t] = b.ptr;
    }
    if (fixed) |f| {
        args.check_fixed = 1;
        for (&args.fixed, 0..) |*x, i| x.* = std.mem.readInt(u32, f[4 * i ..][0..4], .little);
    }
    try check(sym.root_match(ctx, 0, pcs.ptr, pcs.words, &args, verdict.ptr));
}

/// Every word of `words` is zero -> accepted; else reject(check, 1 + first).
pub fn wordsZero(sym: *const Symbols, ctx: *anyopaque, words: api.DeviceBuffer, which: G.Check, verdict: api.DeviceBuffer) !void {
    if (words.words == 0 or words.words > std.math.maxInt(u32) or verdict.words < 1) return error.InvalidNativeCheckSpan;
    try check(sym.words_zero(ctx, 0, words.ptr, @intCast(words.words), @intFromEnum(which), verdict.ptr));
}

/// One RAM boundary relation of `public_claims`: the claim slot it binds
/// and the request's boundary tuples (`cells` x 14 canonical words).
pub const BoundaryInput = struct { claim: u32, tuples: api.DeviceBuffer, cells: u32 };

pub fn publicClaimsScratch(sym: *const Symbols, initial: ?BoundaryInput, terminal: ?BoundaryInput) usize {
    return @intCast(sym.public_scratch(if (initial) |b| b.cells else 0, if (terminal) |b| b.cells else 0));
}

/// Check.public_claims (cpu_worker.publicClaims on device): canonical claims
/// and the initial/terminal RAM boundary claims recomputed from the request
/// tuples and the device-drawn RAM challenges `ram` (15 felts).
pub fn publicClaims(sym: *const Symbols, ctx: *anyopaque, claims: api.DeviceBuffer, claim_count: u32, ram: api.DeviceBuffer, initial: ?BoundaryInput, terminal: ?BoundaryInput, scratch: api.DeviceBuffer, verdict: api.DeviceBuffer) !void {
    if (claim_count == 0 or claims.words < @as(usize, claim_count) * 8 or ram.words < 15 * 8 or verdict.words < 1) return error.InvalidNativeCheckSpan;
    const mk = struct {
        fn f(b: ?BoundaryInput, is_initial: bool) Boundary {
            const x = b orelse return .{};
            return .{ .claim = x.claim, .cells = x.cells, .initial = @intFromBool(is_initial) };
        }
    }.f;
    const bi = mk(initial, true);
    const bt = mk(terminal, false);
    for ([2]?BoundaryInput{ initial, terminal }) |b| if (b) |x| if (x.tuples.words < @as(usize, x.cells) * 14) return error.InvalidNativeCheckSpan;
    try check(sym.public_claims(ctx, 0, claims.ptr, claim_count, ram.ptr, if (initial) |b| b.tuples.ptr else null, &bi, if (terminal) |b| b.tuples.ptr else null, &bt, scratch.ptr, scratch.words, verdict.ptr));
}

/// out[dst[i] + c] = src[8 * index[i] + c] (device tables, class constants).
pub fn patchFelts(sym: *const Symbols, ctx: *anyopaque, src: api.DeviceBuffer, index: api.DeviceBuffer, dst: api.DeviceBuffer, out: api.DeviceBuffer) !void {
    if (index.words != dst.words or index.words == 0 or src.words < 8) return error.InvalidNativeCheckSpan;
    try check(sym.patch(ctx, 0, src.ptr, @intCast(src.words / 8), index.ptr, dst.ptr, @intCast(index.words), out.ptr, out.words));
}

// ---------------------------------------------------------------------------
// Synthetic PCS readbacks (tests): a consistent Result.words of any class
// shape, with every value a function of its position (so duplicate queries
// agree), plus single-fault variants for the negative tests.
// ---------------------------------------------------------------------------

pub const Synthetic = struct {
    pub const Fault = enum { none, trace_value, trace_path, fri_value, fri_path, noncanonical, query_range, status, channel, header };

    fn mix(x: u64) u32 {
        var z = x +% 0x9e3779b97f4a7c15;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return @truncate(z ^ (z >> 31));
    }
    fn felt(x: u64) u32 {
        return mix(x) % core.fields.m31.Modulus;
    }

    /// Words of `program`'s class: `queries` are the raw query positions
    /// (duplicates allowed), `step` the PCS channel step (header[13]).
    pub fn words(a: std.mem.Allocator, program: *const Program, shape: Assembly.Shape, queries: []const u32, seed: u64, fault: Fault) ![]u32 {
        const P = program.words;
        const Q = program.get(.queries);
        if (queries.len != Q) return error.InvalidSyntheticQueries;
        const out = try a.alloc(u32, program.pcs_words);
        errdefer a.free(out);
        @memset(out, 0);
        const plan = try F.Plan.init(shape.degree_log, shape.config.fri_config);
        const step: u32 = 5;
        out[0..14].* = .{ 0x52564d4f, 2, 0, 1, 1, 1, 1, @intCast(shape.trees.len), program.get(.sample_count), @intCast(plan.len), plan.initial_log, Q, shape.degree_log, step };
        out[14] = if (fault == .status) 1 else 0;
        for (out[15..23], 0..) |*w, i| w.* = mix(seed ^ (0x51 + i));
        out[15 + 8] = 3;
        out[15 + 9] = step;
        out[15 + 12] = 17 + step;
        if (fault == .channel) out[15 + 13] = 1;
        if (fault == .header) out[7] += 1;
        for (out[program.get(.off_roots)..][0 .. shape.trees.len * 8], 0..) |*w, i| w.* = mix(seed ^ (0x1000 + i));
        for (out[program.get(.off_samples)..][0 .. program.get(.sample_count) * 8], 0..) |*w, i| w.* = felt(seed ^ (0x2000 + i));
        out[program.get(.off_nonce)] = mix(seed ^ 0x3000);
        out[program.get(.off_nonce) + 1] = mix(seed ^ 0x3001);
        for (out[program.get(.off_terminal)..][0..8], 0..) |*w, i| w.* = felt(seed ^ (0x4000 + i));
        @memcpy(out[program.get(.off_queries)..][0..Q], queries);
        const lifting = plan.initial_log;
        for (0..plan.len) |l| {
            const r = P[program.get(.layer_table) + l * layer_record ..][0..layer_record];
            const fold = r[0];
            const leaf = r[1];
            const shift = r[2];
            const height = r[3];
            for (out[r[4]..][0..8], 0..) |*w, i| w.* = mix(seed ^ (0x5000 + l * 8 + i));
            const subset = @as(u32, 1) << @intCast(fold);
            const slots = @as(u32, 1) << @intCast(fold - leaf);
            for (queries, 0..) |q, qi| {
                const start = ((q >> @intCast(shift)) >> @intCast(fold)) << @intCast(fold);
                for (0..subset) |off| for (0..8) |c| {
                    out[r[5] + (qi * subset + off) * 8 + c] = felt((@as(u64, l) << 56) ^ (@as(u64, start + off) << 8) ^ c ^ seed);
                };
                for (0..slots) |slot| for (0..height) |level| {
                    const lf = (start >> @intCast(leaf)) + slot;
                    const sib = (lf >> @intCast(level)) ^ 1;
                    for (0..8) |c| out[r[6] + ((qi * slots + slot) * height + level) * 8 + c] = mix((@as(u64, l + 1) << 58) ^ (@as(u64, level) << 48) ^ (@as(u64, sib) << 8) ^ c ^ seed);
                };
            }
        }
        for (shape.trees, 0..) |_, t| {
            const r = P[program.get(.tree_table) + t * tree_record ..][0..tree_record];
            const n = r[0];
            const tl = r[1];
            const logs = P[r[2]..][0..n];
            for (queries, 0..) |q, qi| {
                const p = position(q, lifting, tl);
                for (0..n) |ci| out[r[4] + ci * Q + qi] = felt((@as(u64, t + 1) << 60) ^ (@as(u64, ci) << 32) ^ position(p, tl, logs[ci]) ^ seed);
                for (0..tl) |level| {
                    const sib = (p >> @intCast(level)) ^ 1;
                    for (0..8) |c| out[r[5] + (qi * tl + level) * 8 + c] = mix((@as(u64, t + 9) << 58) ^ (@as(u64, level) << 48) ^ (@as(u64, sib) << 8) ^ c ^ seed);
                }
            }
        }
        // Faults on the SECOND copy of a duplicated query (the first copy is
        // what a representative-based encoder would emit).
        const dup = duplicateIndex(queries);
        switch (fault) {
            .trace_value => {
                const r = P[program.get(.tree_table)..][0..tree_record];
                out[r[4] + (dup orelse return error.SyntheticNeedsDuplicate)] ^= 1;
            },
            .trace_path => {
                const r = P[program.get(.tree_table)..][0..tree_record];
                out[r[5] + (dup orelse return error.SyntheticNeedsDuplicate) * r[1] * 8 + 3] ^= 1;
            },
            .fri_value => {
                const r = P[program.get(.layer_table)..][0..layer_record];
                out[r[5] + (dup orelse return error.SyntheticNeedsDuplicate) * (@as(u32, 1) << @intCast(r[0])) * 8] ^= 1;
            },
            .fri_path => {
                const r = P[program.get(.layer_table)..][0..layer_record];
                const slots = @as(u32, 1) << @intCast(r[0] - r[1]);
                out[r[6] + (dup orelse return error.SyntheticNeedsDuplicate) * slots * r[3] * 8 + 1] ^= 1;
            },
            .noncanonical => out[program.get(.off_samples)] = core.fields.m31.Modulus,
            .query_range => out[program.get(.off_queries)] = @as(u32, 1) << @intCast(lifting),
            else => {},
        }
        return out;
    }
    fn duplicateIndex(queries: []const u32) ?usize {
        for (queries, 0..) |q, i| for (queries[0..i]) |p| if (p == q) return i;
        return null;
    }
    pub fn position(row: u32, from: u32, to: u32) u32 {
        return if (from >= to) ((row >> @intCast(from - to + 1)) << 1) | (row & 1) else ((row >> 1) << @intCast(to - from + 1)) | (row & 1);
    }
};

// ---------------------------------------------------------------------------
// Host tests (no GPU)
// ---------------------------------------------------------------------------

const WP = @import("stwo_riscv_cpu_integration").rv64_gkr_worker_protocol;
const Decode = @import("../hybrid_pcs.zig");

/// The legacy reference bytes of a PCS readback (finish-time host path).
pub fn legacyBytes(a: std.mem.Allocator, shape: Assembly.Shape, words: []const u32) ![]u8 {
    var decoded = try Decode.decodeWords(a, shape, words);
    defer decoded.proof.deinit(a);
    return WP.encodePhysical(a, .{ .commitment_scheme_proof = decoded.proof });
}

pub const TestShape = struct {
    a: std.mem.Allocator,
    trees: []Assembly.Tree,
    storage: std.ArrayListUnmanaged([]u32) = .empty,
    shape: Assembly.Shape,
    pub fn deinit(self: *TestShape) void {
        for (self.storage.items) |s| self.a.free(s);
        self.storage.deinit(self.a);
        self.a.free(self.trees);
    }
    /// `columns[t]` columns per tree with logs in [lo, degree_log], a shuffled
    /// sorted order and 0..3 samples per column.
    pub fn init(a: std.mem.Allocator, seed: u64, degree_log: u32, columns: []const u32, config: core.pcs.PcsConfig) !TestShape {
        var self = TestShape{ .a = a, .trees = try a.alloc(Assembly.Tree, columns.len), .shape = undefined };
        errdefer self.deinit();
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        for (columns, self.trees) |n, *tree| {
            const logs = try a.alloc(u32, n);
            try self.storage.append(a, logs);
            const order = try a.alloc(u32, n);
            try self.storage.append(a, order);
            const samples = try a.alloc(u32, n);
            try self.storage.append(a, samples);
            for (logs, samples) |*l, *s| {
                l.* = rnd.intRangeAtMost(u32, @max(1, degree_log -| 3), degree_log);
                s.* = rnd.uintAtMost(u32, 3);
            }
            for (order, 0..) |*o, i| o.* = @intCast(i);
            // sorted_to_original sorts by ascending log (stable on index).
            std.sort.block(u32, order, logs, struct {
                fn lt(l: []u32, x: u32, y: u32) bool {
                    return l[x] < l[y] or (l[x] == l[y] and x < y);
                }
            }.lt);
            tree.* = .{ .coefficient_logs = logs, .sorted_to_original = order, .sample_counts = samples };
        }
        self.shape = .{ .config = config, .degree_log = degree_log, .trees = self.trees };
        return self;
    }
};

pub fn testQueries(a: std.mem.Allocator, seed: u64, n: usize, log: u32) ![]u32 {
    var prng = std.Random.DefaultPrng.init(seed);
    const q = try a.alloc(u32, n);
    for (q, 0..) |*x, i| x.* = if (i % 5 == 4) q[i / 2] else prng.random().uintLessThan(u32, @as(u32, 1) << @intCast(log));
    return q;
}

fn cfg(fold: u32, queries: usize, beta: u32) core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = beta, .log_last_layer_degree_bound = 0, .n_queries = queries, .fold_step = fold } };
}

test "encode program: PCS offsets equal decodeWords, capacity bounds the legacy bytes" {
    const a = std.testing.allocator;
    const cases = [_]struct { seed: u64, degree: u32, cols: []const u32, fold: u32, q: usize, beta: u32 }{
        .{ .seed = 1, .degree = 6, .cols = &.{ 3, 5, 2, 4 }, .fold = 1, .q = 7, .beta = 1 },
        .{ .seed = 2, .degree = 9, .cols = &.{ 7, 11, 3, 8 }, .fold = 4, .q = 33, .beta = 1 },
        .{ .seed = 3, .degree = 8, .cols = &.{ 1, 2 }, .fold = 4, .q = 70, .beta = 2 },
        .{ .seed = 4, .degree = 5, .cols = &.{ 4, 4, 4 }, .fold = 1, .q = 1, .beta = 1 },
    };
    for (cases) |c| {
        var ts = try TestShape.init(a, c.seed, c.degree, c.cols, cfg(c.fold, c.q, c.beta));
        defer ts.deinit();
        var program = try Program.build(a, ts.shape);
        defer program.deinit();
        const queries = try testQueries(a, c.seed, c.q, c.degree + c.beta);
        defer a.free(queries);
        const words = try Synthetic.words(a, &program, ts.shape, queries, c.seed, .none);
        defer a.free(words);
        // decodeWords consumes exactly program.pcs_words and accepts the readback.
        const bytes = try legacyBytes(a, ts.shape, words);
        defer a.free(bytes);
        try std.testing.expect(bytes.len % 4 == 0);
        try std.testing.expect(bytes.len <= program.max_encoded_bytes);
        // The static prefix reproduces the legacy bytes' prefix.
        const prefix = try a.alloc(u32, program.get(.prefix_words));
        defer a.free(prefix);
        const P = program.words;
        for (0..program.get(.const_count)) |i| prefix[P[program.get(.const_table) + 2 * i]] = P[program.get(.const_table) + 2 * i + 1];
        for (0..program.get(.run_count)) |i| {
            const r = P[program.get(.run_table) + 3 * i ..][0..3];
            @memcpy(prefix[r[0]..][0..r[2]], words[r[1]..][0..r[2]]);
        }
        try std.testing.expectEqualSlices(u8, bytes[0 .. prefix.len * 4], std.mem.sliceAsBytes(prefix));
    }
}

test "synthetic faults are rejected by the legacy decoder (negative-test oracle)" {
    const a = std.testing.allocator;
    var ts = try TestShape.init(a, 9, 8, &.{ 5, 6, 3, 4 }, cfg(4, 40, 1));
    defer ts.deinit();
    var program = try Program.build(a, ts.shape);
    defer program.deinit();
    const queries = try testQueries(a, 9, 40, 9);
    defer a.free(queries);
    inline for (.{ .trace_value, .trace_path, .fri_value, .fri_path, .noncanonical, .query_range, .status, .channel, .header }) |fault| {
        const words = try Synthetic.words(a, &program, ts.shape, queries, 9, fault);
        defer a.free(words);
        if (legacyBytes(a, ts.shape, words)) |b| {
            a.free(b);
            std.debug.print("fault {s} accepted by the legacy decoder\n", .{@tagName(fault)});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "program refuses shapes the assembler refuses" {
    const a = std.testing.allocator;
    var ts = try TestShape.init(a, 5, 6, &.{ 2, 2 }, cfg(1, 4, 1));
    defer ts.deinit();
    @constCast(ts.trees[0].sample_counts)[0] = 6;
    try std.testing.expectError(error.InvalidNativeEncodeShape, Program.build(a, ts.shape));
    @constCast(ts.trees[0].sample_counts)[0] = 0;
    @constCast(ts.trees[1].sorted_to_original)[0] = ts.trees[1].sorted_to_original[1];
    try std.testing.expectError(error.InvalidNativeEncodeShape, Program.build(a, ts.shape));
}

test {
    _ = @import("native_encode_test.zig");
}
