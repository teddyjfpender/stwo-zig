//! WGKR-LS-RANGE-v0: experimental prover and receiver for the LS scalar-range
//! family, proved either with classic paired LogUp or with LogUp-GKR whose
//! terminal claims are authenticated against the committed MAIN columns.
//! Separate transcript tag; the default Word16 protocol is untouched.
//!
//! Transcript (both variants; GKR-only steps marked):
//!   pcs config -> commit FIXED (table values) -> mix tag/variant/geometry ->
//!   commit MAIN -> draw (z_hi, c_hi, z_lo, c_lo) ->
//!   [gkr] GKR batch over the consumer instances (output claims mixed first) ->
//!   [gkr] receiver scalar checks R1..R6 -> mix ledger claims -> commit INTER ->
//!   composition, OODS, FRI, PoW, queries (unchanged core prover/verifier).
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const pcs_core = core.pcs;
const blake2_merkle = core.vcs_lifted.blake2_merkle;
const engine_mod = @import("stwo_prover_engine");
const prover_engine = engine_mod.engine;
const prover_pcs = engine_mod.pcs;
const prover_transaction = engine_mod.transaction;
const prover_component = engine_mod.air.component_prover;
const lookups = engine_mod.lookups;
const gkr_prover = lookups.gkr_prover;
const gkr_verifier = lookups.gkr_verifier;
const sumcheck = lookups.sumcheck;
const lookup_utils = lookups.utils;
const MleSecure = lookups.mle.Mle(QM31);
const stage_profile = @import("stwo_prover_api").stage_profile;
const proof_wire = @import("stwo_proof_wire");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const W = @import("witness.zig");
const Air = @import("air.zig");
const MP = @import("mle_point.zig");
const FastGkr = @import("fast_gkr.zig");

pub const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = core.channel.blake2s.Blake2sChannel;
pub const Engine = prover_engine.ProverEngine(CpuBackend, Hasher, MerkleChannel, Channel);
pub const Variant = Air.Variant;

pub const TAG: u32 = 0x57474b52; // 'WGKR'
pub const REVISION: u32 = 0;
/// Lane map: GKR leaf (p << 4) | j, j < 12 LOGICAL_U16 order, j >= 12 LOGICAL_U8 order.
pub const LANE_MAP_ID: u32 = 0x4c533136;
const PROOF_MAGIC = "WGKRPRF1";
pub const MAX_INSTANCES: usize = 2;
const MAX_LAYERS: usize = 32;

/// Production suite of the Word16 lane (q70 / PoW 26 / blowup 1).
pub fn productionConfig() pcs_core.PcsConfig {
    return .{ .pow_bits = 26, .fri_config = core.fri.FriConfig.init(0, 1, 70) catch unreachable };
}
pub fn testConfig() pcs_core.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = core.fri.FriConfig.init(0, 1, 3) catch unreachable };
}

/// Prover-side fault injection for the adversarial suite. `none` in production.
pub const Fault = enum {
    none,
    /// GKR input uses a numerator 2 at one leaf (forged multiplicity).
    forge_numerator,
    /// MAIN commits a mutated range value; GKR runs on the original values.
    mutate_main_after_gkr,
    /// MAIN and GKR both use the mutated value; multiplicities are original.
    mutate_main_consistent,
    /// One committed eq-column cell is flipped (S built from the flipped column).
    eq_cell_flip,
    /// The AIR's prefix uses delta + 1 instead of the GKR terminal claim.
    shift_delta,
    /// Skip only the prover's own closure self-check (unbalanced witness tests).
    skip_closure_check,
};

pub const Request = struct {
    statement: W.Statement,
    variant: Variant,
    fault: Fault = .none,
    /// Borrowed for the duration of the proof.
    witness: *const W.Witness,
    /// Receives the GKR wire bytes and timings; owned by `prove`'s caller frame.
    sink: ?*Sink = null,
    /// GKR prover: the parallel clone-free one (byte-identical output) or the
    /// generic reference `lookups/gkr_prover.zig`.
    gkr_prover: GkrProverChoice = .fast,
    gkr_threads: usize = 1,
};

pub const GkrProverChoice = enum { fast, reference };

pub const Sink = struct {
    gkr_bytes: ?[]u8 = null,
    timings: Timings = .{},
    pub fn deinit(self: *Sink, a: std.mem.Allocator) void {
        if (self.gkr_bytes) |b| a.free(b);
        self.gkr_bytes = null;
    }
};

pub const PreparedInput = prover_transaction.PreparedInput(Request);

pub const Timings = struct {
    gkr_ns: u64 = 0,
    gkr_input_ns: u64 = 0,
    binding_ns: u64 = 0,
    interaction_ns: u64 = 0,
    gkr_input_bytes: u64 = 0,
};

pub const ProvedStatement = struct {
    claims: [2 + MAX_INSTANCES]QM31,
    n_claims: usize,
};

/// Per-instance receiver-derivable binding data.
pub const Binding = struct {
    point: MP.MleEvalPoint,
    k_const: QM31,
    u: [W.LANES]QM31,
    delta: QM31,

    /// `r_inst` is the instance's GKR terminal point (length log + 4).
    pub fn init(r_inst: []const QM31, log: u32, ch: Air.Challenges, delta: QM31) !Binding {
        if (r_inst.len != log + W.LOG_LANES) return error.GkrShapeMismatch;
        const r_row = r_inst[0..log];
        const r_lane = r_inst[log..];
        var out: Binding = undefined;
        out.point = try MP.MleEvalPoint.init(r_row);
        out.k_const = QM31.zero();
        for (0..W.LANES) |j| {
            var bits: [W.LOG_LANES]QM31 = undefined;
            for (0..W.LOG_LANES) |b| bits[b] = if ((j >> @intCast(W.LOG_LANES - 1 - b)) & 1 == 1) QM31.one() else QM31.zero();
            const w = MP.eq(&bits, r_lane);
            out.k_const = out.k_const.add(w.mul(ch.offset(j)));
            out.u[j] = w.mul(ch.coefficient(j));
        }
        out.delta = delta;
        return out;
    }
};

/// Shared prover/receiver component set. Geometry fixes every offset.
pub const Components = struct {
    geometry: Air.Geometry,
    classic: [MAX_INSTANCES]Air.ClassicConsumer = undefined,
    gkr: [MAX_INSTANCES]Air.GkrConsumer = undefined,
    tables: [2]Air.Table,

    /// classic: claims = [inst..., hi, lo]; gkr: claims = [hi, lo] and one binding per instance.
    pub fn init(geometry: Air.Geometry, ch: Air.Challenges, claims: []const QM31, bindings: []const Binding) !Components {
        const st = geometry.statement;
        const n = st.instanceCount();
        const table_claims = switch (geometry.variant) {
            .classic => claims[n..],
            .gkr => claims,
        };
        if (table_claims.len != 2) return error.InvalidClaimCount;
        var out = Components{
            .geometry = geometry,
            .tables = .{
                .{ .log_size = st.hi_log, .preprocessed_index = 0, .main_offset = geometry.tableMainOffset(true), .inter_offset = geometry.tableInterOffset(true), .lane = 0, .ch = ch, .claim = table_claims[0] },
                .{ .log_size = st.lo_log, .preprocessed_index = 1, .main_offset = geometry.tableMainOffset(false), .inter_offset = geometry.tableInterOffset(false), .lane = W.HI_LANES, .ch = ch, .claim = table_claims[1] },
            },
        };
        for (0..n) |i| switch (geometry.variant) {
            .classic => out.classic[i] = .{ .log_size = st.instanceLog(i), .main_offset = geometry.mainOffset(i), .inter_offset = geometry.interOffset(i), .ch = ch, .claim = claims[i] },
            .gkr => {
                if (bindings.len != n) return error.InvalidBindingCount;
                out.gkr[i] = .{ .log_size = st.instanceLog(i), .main_offset = geometry.mainOffset(i), .inter_offset = geometry.interOffset(i), .point = bindings[i].point, .k_const = bindings[i].k_const, .u = bindings[i].u, .delta = bindings[i].delta };
            },
        };
        return out;
    }

    pub fn verifiers(self: *const Components, out: []core.air.components.Component) []core.air.components.Component {
        const n = self.geometry.statement.instanceCount();
        for (0..n) |i| out[i] = switch (self.geometry.variant) {
            .classic => self.classic[i].asVerifierComponent(),
            .gkr => self.gkr[i].asVerifierComponent(),
        };
        out[n] = self.tables[0].asVerifierComponent();
        out[n + 1] = self.tables[1].asVerifierComponent();
        return out[0 .. n + 2];
    }

    pub fn provers(self: *const Components, out: []prover_component.ComponentProver) []const prover_component.ComponentProver {
        const n = self.geometry.statement.instanceCount();
        for (0..n) |i| out[i] = switch (self.geometry.variant) {
            .classic => self.classic[i].asProverComponent(),
            .gkr => self.gkr[i].asProverComponent(),
        };
        out[n] = self.tables[0].asProverComponent();
        out[n + 1] = self.tables[1].asProverComponent();
        return out[0 .. n + 2];
    }
};

pub fn mixStatement(channel: anytype, statement: W.Statement, variant: Variant) void {
    var words: [12]u32 = undefined;
    const n = statement.instanceCount();
    words[0] = TAG;
    words[1] = REVISION;
    words[2] = @intFromEnum(variant);
    words[3] = LANE_MAP_ID;
    words[4] = statement.ls_log;
    words[5] = statement.tail_log;
    words[6] = statement.hi_log;
    words[7] = statement.lo_log;
    words[8] = @intCast(n);
    for (0..n) |i| words[9 + i] = statement.instanceLog(i) + W.LOG_LANES;
    channel.mixU32s(words[0 .. 9 + n]);
}

/// Table preprocessed values: storage index p holds value p.
pub fn preprocessedColumns(a: std.mem.Allocator, statement: W.Statement) ![]prover_pcs.ColumnEvaluation {
    const cols = try a.alloc(prover_pcs.ColumnEvaluation, 2);
    var made: usize = 0;
    errdefer {
        for (cols[0..made]) |c| a.free(c.values);
        a.free(cols);
    }
    for ([_]u32{ statement.hi_log, statement.lo_log }, 0..) |log, k| {
        const values = try a.alloc(M31, @as(usize, 1) << @intCast(log));
        for (values, 0..) |*v, p| v.* = M31.fromCanonical(@intCast(p));
        cols[k] = .{ .log_size = log, .values = values };
        made += 1;
    }
    return cols;
}

fn freeColumns(a: std.mem.Allocator, cols: []prover_pcs.ColumnEvaluation) void {
    for (cols) |c| a.free(c.values);
    a.free(cols);
}

pub fn preprocessedRoot(a: std.mem.Allocator, config: pcs_core.PcsConfig, statement: W.Statement) !Hasher.Hash {
    const cols = try preprocessedColumns(a, statement);
    defer freeColumns(a, cols);
    var scheme = try Engine.init(a, config);
    defer Engine.deinit(&scheme, a);
    var channel = Channel{};
    config.mixInto(&channel);
    try scheme.commit(a, cols, &channel);
    return scheme.trees.items[0].commitment.root();
}

/// The single mutated cell used by the mutation faults: instance 0, lane 0, storage row 3.
const MUTATE_ROW: usize = 3;
fn mutatedValue(v: u32, hi_log: u32) u32 {
    return (v + 1) & ((@as(u32, 1) << @intCast(hi_log)) - 1);
}

// ---------------------------------------------------------------------------
// Prover.

const Spec = struct {
    pub const Statement = ProvedStatement;
    pub const PreparedInput = protocol_prepared;
    pub const max_components: usize = MAX_INSTANCES + 2;

    pub const PreparedInteraction = struct {
        columns: prover_transaction.OwnedColumns,
        ch: Air.Challenges,
        claims: [2 + MAX_INSTANCES]QM31,
        n_claims: usize,
        bindings: [MAX_INSTANCES]Binding,
        pub fn deinit(self: *PreparedInteraction, a: std.mem.Allocator) void {
            self.columns.deinit(a);
        }
    };

    pub const ProverContext = struct {
        statement_value: ProvedStatement,
        components: Components,
    };

    pub fn validateRequest(request: Request) !void {
        try request.statement.validate();
        if (!std.meta.eql(request.statement, request.witness.statement)) return error.WitnessStatementMismatch;
    }
    pub fn validatePrepared(prepared: *const protocol_prepared) !void {
        const main = prepared.trace.main.columns orelse return error.PreparedInputConsumed;
        if (main.len != prepared.request.statement.instanceCount() * W.LANES + 2) return error.InvalidPreparedGeometry;
    }
    pub fn compositionLog(request: Request) !u32 {
        return @max(request.statement.ls_log, request.statement.hi_log) + 1;
    }
    pub fn beforeMainCommit(channel: *Channel, request: Request) !void {
        mixStatement(channel, request.statement, request.variant);
    }
    pub fn prepareInteraction(a: std.mem.Allocator, channel: *Channel, prepared: *const protocol_prepared) !PreparedInteraction {
        return generateInteraction(a, channel, prepared.request);
    }
    pub fn deinitPreparedInteraction(prepared: *PreparedInteraction, a: std.mem.Allocator) void {
        prepared.deinit(a);
    }
    pub fn beforeInteractionCommit(channel: *Channel, _: Request, prepared: *const PreparedInteraction) !void {
        channel.mixFelts(prepared.claims[0..prepared.n_claims]);
    }
    pub fn initProverContext(out: *ProverContext, _: *Channel, request: Request, prepared: *const PreparedInteraction) !void {
        const geometry = Air.Geometry{ .statement = request.statement, .variant = request.variant };
        out.* = .{
            .statement_value = .{ .claims = prepared.claims, .n_claims = prepared.n_claims },
            .components = try Components.init(geometry, prepared.ch, prepared.claims[0..prepared.n_claims], prepared.bindings[0..request.statement.instanceCount()]),
        };
        if (request.fault == .shift_delta) {
            out.components.gkr[0].delta = out.components.gkr[0].delta.add(QM31.one());
        }
    }
    pub fn statement(context: *const ProverContext) ProvedStatement {
        return context.statement_value;
    }
    pub fn proverComponents(context: *const ProverContext, out: []prover_component.ComponentProver) ![]const prover_component.ComponentProver {
        return context.components.provers(out);
    }
};
const protocol_prepared = prover_transaction.PreparedInput(Request);

fn laneValue(request: Request, instance: usize, lane: usize, p: usize, committed: bool) u32 {
    const v = request.witness.instances[instance].lanes[lane][p];
    if (instance == 0 and lane == 0 and p == MUTATE_ROW) {
        const mutate = switch (request.fault) {
            .mutate_main_consistent => true,
            .mutate_main_after_gkr => committed,
            else => false,
        };
        if (mutate) return mutatedValue(v, request.statement.hi_log);
    }
    return v;
}

pub fn prepare(a: std.mem.Allocator, request: Request) !protocol_prepared {
    const st = request.statement;
    try st.validate();
    const pre = try preprocessedColumns(a, st);
    var pre_owned = prover_transaction.OwnedColumns.init(pre);
    errdefer pre_owned.deinit(a);
    var mult = try request.witness.multiplicities(a);
    defer mult.deinit(a);
    const n_main = st.instanceCount() * W.LANES + 2;
    const main = try a.alloc(prover_pcs.ColumnEvaluation, n_main);
    var made: usize = 0;
    errdefer {
        for (main[0..made]) |c| a.free(c.values);
        a.free(main);
    }
    for (0..st.instanceCount()) |i| {
        const inst = &request.witness.instances[i];
        for (0..W.LANES) |j| {
            const values = try a.alloc(M31, inst.rows());
            for (values, 0..) |*v, p| v.* = M31.fromCanonical(laneValue(request, i, j, p, true));
            main[made] = .{ .log_size = inst.log, .values = values };
            made += 1;
        }
    }
    for ([_][]const u32{ mult.hi, mult.lo }, [_]u32{ st.hi_log, st.lo_log }) |counts, log| {
        const values = try a.alloc(M31, counts.len);
        for (values, counts) |*v, c| v.* = M31.fromCanonical(c);
        main[made] = .{ .log_size = log, .values = values };
        made += 1;
    }
    var main_owned = prover_transaction.OwnedColumns.init(main);
    errdefer main_owned.deinit(a);
    return .{ .request = request, .trace = try prover_transaction.PreparedTrace.initOwned(a, pre_owned.take(), main_owned.take()) };
}

/// Appends a QM31 column (cyclic prefix or plain values) as 4 base columns.
fn pushSecure(a: std.mem.Allocator, out: *std.ArrayList(prover_pcs.ColumnEvaluation), log: u32, values: []const QM31) !void {
    for (0..4) |coord| {
        const col = try a.alloc(M31, values.len);
        errdefer a.free(col);
        for (values, col) |v, *o| o.* = v.toM31Array()[coord];
        try out.append(a, .{ .log_size = log, .values = col });
    }
}

/// Cyclic coset-order prefix: S(k) = sum_{t<=k} (terms(t) - total/N). Returns total.
fn cyclicPrefix(a: std.mem.Allocator, log: u32, terms: []const QM31, total_override: ?QM31) !struct { prefix: []QM31, total: QM31 } {
    var total = QM31.zero();
    for (terms) |t| total = total.add(t);
    const used = total_override orelse total;
    const shift = try used.divM31(M31.fromU64(terms.len));
    const prefix = try a.alloc(QM31, terms.len);
    var acc = QM31.zero();
    for (0..terms.len) |k| {
        const s = MP.storageIndex(k, log);
        acc = acc.add(terms[s]).sub(shift);
        prefix[s] = acc;
    }
    return .{ .prefix = prefix, .total = total };
}

fn tableColumns(a: std.mem.Allocator, out: *std.ArrayList(prover_pcs.ColumnEvaluation), request: Request, ch: Air.Challenges, claims: []QM31) !void {
    var mult = try request.witness.multiplicities(a);
    defer mult.deinit(a);
    for ([_][]const u32{ mult.hi, mult.lo }, [_]u32{ request.statement.hi_log, request.statement.lo_log }, [_]usize{ 0, W.HI_LANES }, 0..) |counts, log, lane, k| {
        const n = counts.len;
        const den = try a.alloc(QM31, n);
        defer a.free(den);
        for (den, 0..) |*d, p| d.* = ch.denominatorBase(lane, M31.fromCanonical(@intCast(p)));
        const inv = try core.fields.batchInverse(QM31, a, den);
        defer a.free(inv);
        const terms = try a.alloc(QM31, n);
        defer a.free(terms);
        for (terms, inv, counts) |*t, v, c| t.* = v.mulM31(M31.fromCanonical(c)).neg();
        const pre = try cyclicPrefix(a, log, terms, null);
        defer a.free(pre.prefix);
        try pushSecure(a, out, log, inv);
        try pushSecure(a, out, log, pre.prefix);
        claims[k] = pre.total;
    }
}

fn classicConsumerColumns(a: std.mem.Allocator, out: *std.ArrayList(prover_pcs.ColumnEvaluation), request: Request, instance: usize, ch: Air.Challenges) !QM31 {
    const inst = &request.witness.instances[instance];
    const n = inst.rows();
    const products = try a.alloc(QM31, n * Air.CLASSIC_PAIRS);
    defer a.free(products);
    const sums = try a.alloc(QM31, n * Air.CLASSIC_PAIRS);
    defer a.free(sums);
    for (0..n) |p| for (0..Air.CLASSIC_PAIRS) |k| {
        const x = ch.denominatorBase(2 * k, M31.fromCanonical(laneValue(request, instance, 2 * k, p, true)));
        const y = ch.denominatorBase(2 * k + 1, M31.fromCanonical(laneValue(request, instance, 2 * k + 1, p, true)));
        products[k * n + p] = x.mul(y);
        sums[k * n + p] = x.add(y);
    };
    const inv = try core.fields.batchInverse(QM31, a, products);
    defer a.free(inv);
    const terms = try a.alloc(QM31, n);
    defer a.free(terms);
    @memset(terms, QM31.zero());
    for (0..Air.CLASSIC_PAIRS) |k| {
        const col = inv[k * n ..][0..n];
        try pushSecure(a, out, inst.log, col);
        for (terms, col, sums[k * n ..][0..n]) |*t, v, s| t.* = t.add(v.mul(s));
    }
    const pre = try cyclicPrefix(a, inst.log, terms, null);
    defer a.free(pre.prefix);
    try pushSecure(a, out, inst.log, pre.prefix);
    return pre.total;
}

/// GKR input layer: leaf (p << 4) | j = D_j(m_j(p)). `num == null` for singles.
fn gkrInput(a: std.mem.Allocator, request: Request, instance: usize, ch: Air.Challenges) !FastGkr.Input {
    const inst = &request.witness.instances[instance];
    const n = inst.rows();
    const den = try a.alloc(QM31, n * W.LANES);
    errdefer a.free(den);
    const Fill = struct {
        fn run(req: Request, inst_index: usize, c: Air.Challenges, out: []QM31, start: usize, end: usize) void {
            for (start..end) |p| for (0..W.LANES) |j| {
                out[(p << W.LOG_LANES) | j] = c.denominatorBase(j, M31.fromCanonical(laneValue(req, inst_index, j, p, false)));
            };
        }
    };
    const workers = @max(1, @min(request.gkr_threads, n / 4096));
    if (workers == 1) {
        Fill.run(request, instance, ch, den, 0, n);
    } else {
        var threads: [64]std.Thread = undefined;
        const k = @min(workers, threads.len);
        var spawned: usize = 0;
        defer for (threads[0..spawned]) |t| t.join();
        for (1..k) |w| {
            threads[spawned] = try std.Thread.spawn(.{}, Fill.run, .{ request, instance, ch, den, n * w / k, n * (w + 1) / k });
            spawned += 1;
        }
        Fill.run(request, instance, ch, den, 0, n / k);
    }
    if (request.fault == .forge_numerator and instance == 0) {
        const num = try a.alloc(QM31, den.len);
        @memset(num, QM31.one());
        num[0] = QM31.fromBase(M31.fromCanonical(2));
        return .{ .num = num, .den = den };
    }
    return .{ .num = null, .den = den };
}

fn runGkr(a: std.mem.Allocator, channel: *Channel, request: Request, ch: Air.Challenges, timings: *Timings) !gkr_prover.ProveBatchResult {
    const n = request.statement.instanceCount();
    var inputs: [MAX_INSTANCES]FastGkr.Input = undefined;
    var made: usize = 0;
    errdefer for (inputs[0..made]) |in| {
        if (in.num) |x| a.free(x);
        a.free(in.den);
    };
    var timer = try std.time.Timer.start();
    for (0..n) |i| {
        inputs[i] = try gkrInput(a, request, i, ch);
        timings.gkr_input_bytes += @as(u64, inputs[i].den.len) * @sizeOf(QM31);
        made += 1;
    }
    timings.gkr_input_ns = timer.read();
    switch (request.gkr_prover) {
        .fast => {
            made = 0; // ownership moves to the prover
            return FastGkr.proveBatch(a, channel, inputs[0..n], .{ .threads = request.gkr_threads }, null);
        },
        .reference => {
            var layers: [MAX_INSTANCES]gkr_prover.Layer = undefined;
            for (inputs[0..n], 0..) |in, i| {
                layers[i] = if (in.num) |num|
                    .{ .LogUpGeneric = .{ .numerators = try MleSecure.initOwned(num), .denominators = try MleSecure.initOwned(in.den) } }
                else
                    .{ .LogUpSingles = .{ .denominators = try MleSecure.initOwned(in.den) } };
            }
            made = 0;
            defer for (layers[0..n]) |*l| l.deinit(a);
            return gkr_prover.proveBatch(a, channel, layers[0..n]);
        },
    }
}

fn gkrConsumerColumns(a: std.mem.Allocator, out: *std.ArrayList(prover_pcs.ColumnEvaluation), request: Request, instance: usize, binding: *const Binding) !void {
    const inst = &request.witness.instances[instance];
    const n = inst.rows();
    const c = try MP.genEqEvals(a, binding.point.slice());
    defer a.free(c);
    if (request.fault == .eq_cell_flip and instance == 0) c[5] = c[5].add(QM31.one());
    const terms = try a.alloc(QM31, n);
    defer a.free(terms);
    for (terms, 0..) |*t, p| {
        var e = binding.k_const;
        for (0..W.LANES) |j| e = e.sub(binding.u[j].mulM31(M31.fromCanonical(laneValue(request, instance, j, p, true))));
        t.* = c[p].mul(e);
    }
    const delta = if (request.fault == .shift_delta and instance == 0) binding.delta.add(QM31.one()) else binding.delta;
    const pre = try cyclicPrefix(a, inst.log, terms, delta);
    defer a.free(pre.prefix);
    if (request.fault == .none and !pre.total.eql(binding.delta)) return error.GkrBindingSelfCheckFailed;
    try pushSecure(a, out, inst.log, c);
    try pushSecure(a, out, inst.log, pre.prefix);
}

fn generateInteraction(a: std.mem.Allocator, channel: *Channel, request: Request) !Spec.PreparedInteraction {
    var timer = try std.time.Timer.start();
    const st = request.statement;
    const n = st.instanceCount();
    const ch = Air.Challenges.draw(channel);
    var timings = Timings{};
    var cols = std.ArrayList(prover_pcs.ColumnEvaluation).empty;
    errdefer {
        for (cols.items) |c| a.free(c.values);
        cols.deinit(a);
    }
    var claims: [2 + MAX_INSTANCES]QM31 = undefined;
    var n_claims: usize = 0;
    var bindings: [MAX_INSTANCES]Binding = undefined;
    var gkr_sum = QM31.zero();
    switch (request.variant) {
        .classic => {
            for (0..n) |i| claims[i] = try classicConsumerColumns(a, &cols, request, i, ch);
            n_claims = n + 2;
            try tableColumns(a, &cols, request, ch, claims[n .. n + 2]);
            for (claims[0..n]) |cl| gkr_sum = gkr_sum.add(cl);
        },
        .gkr => {
            const gkr_start = timer.read();
            var result = try runGkr(a, channel, request, ch, &timings);
            defer result.deinit(a);
            timings.gkr_ns = timer.read() - gkr_start;
            if (request.sink) |sink| {
                sink.deinit(a);
                sink.gkr_bytes = try encodeGkr(a, &result.proof);
            }
            const bind_start = timer.read();
            const ood = result.artifact.ood_point;
            for (0..n) |i| {
                const nv = st.instanceLog(i) + W.LOG_LANES;
                const out_claims = result.proof.output_claims_by_instance[i];
                gkr_sum = gkr_sum.add(try out_claims[0].div(out_claims[1]));
                bindings[i] = try Binding.init(ood[ood.len - nv ..], st.instanceLog(i), ch, result.artifact.claims_to_verify_by_instance[i][1]);
                try gkrConsumerColumns(a, &cols, request, i, &bindings[i]);
            }
            timings.binding_ns = timer.read() - bind_start;
            n_claims = 2;
            try tableColumns(a, &cols, request, ch, claims[0..2]);
        },
    }
    const table_sum = claims[n_claims - 2].add(claims[n_claims - 1]);
    if (request.fault == .none and !table_sum.add(gkr_sum).isZero()) return error.UnbalancedRangeLookup;
    timings.interaction_ns = timer.read();
    if (request.sink) |sink| sink.timings = timings;
    const owned = try cols.toOwnedSlice(a);
    return .{ .columns = prover_transaction.OwnedColumns.init(owned), .ch = ch, .claims = claims, .n_claims = n_claims, .bindings = bindings };
}

pub const ProveResult = struct {
    bytes: []u8,
    timings: Timings,
    stark_bytes: usize,
    gkr_bytes: usize,
    pub fn deinit(self: *ProveResult, a: std.mem.Allocator) void {
        a.free(self.bytes);
    }
};

/// Proves and returns the encoded proof bundle.
pub fn prove(a: std.mem.Allocator, config: pcs_core.PcsConfig, request_in: Request, recorder: ?*stage_profile.Recorder) !ProveResult {
    var sink = Sink{};
    defer sink.deinit(a);
    var request = request_in;
    request.sink = &sink;
    const prepared = try prepare(a, request);
    var output = if (request.fault == .none)
        try prover_transaction.provePreparedEx(Engine, Spec, false, {}, a, config, prepared, .{ .recorder = recorder })
    else
        try prover_transaction.provePreparedEx(AdversarialEngine, Spec, false, {}, a, config, prepared, .{ .recorder = recorder });
    output.proof.aux.deinit(a);
    const gkr_bytes: []const u8 = sink.gkr_bytes orelse &.{};
    var proof = output.proof.proof;
    defer proof.deinit(a);
    const stark = try proof_wire.encodeProofBytesBinary(a, proof);
    defer a.free(stark);
    const st = output.statement;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, PROOF_MAGIC);
    try putU32(&out, a, @intFromEnum(request.variant));
    for ([_]u32{ request.statement.ls_log, request.statement.tail_log, request.statement.hi_log, request.statement.lo_log }) |v| try putU32(&out, a, v);
    try putU32(&out, a, @intCast(st.n_claims));
    for (st.claims[0..st.n_claims]) |q| try putQ(&out, a, q);
    try putU32(&out, a, @intCast(gkr_bytes.len));
    try out.appendSlice(a, gkr_bytes);
    try putU32(&out, a, @intCast(stark.len));
    try out.appendSlice(a, stark);
    return .{ .bytes = try out.toOwnedSlice(a), .timings = sink.timings, .stark_bytes = stark.len, .gkr_bytes = gkr_bytes.len };
}

/// Fault-injection engine: identical to `Engine`, except that a final OODS
/// mismatch returns the unverified proof instead of an error, so the receiver
/// (not the honest prover's self-check) is what rejects it. Tests only.
const AdversarialEngine = struct {
    pub const Scheme = Engine.Scheme;
    pub const Channel = Engine.Channel;
    pub const Component = Engine.Component;
    pub const ExtendedProof = Engine.ExtendedProof;
    pub const init = Engine.init;
    pub const deinit = Engine.deinit;
    pub const commit = Engine.commit;
    pub const commitPreparedWithBacking = Engine.commitPreparedWithBacking;
    pub const flushPendingCommit = Engine.flushPendingCommit;
    pub fn prove(allocator: std.mem.Allocator, components: []const prover_component.ComponentProver, channel: *Engine.Channel, scheme: Scheme, options: prover_engine.ProveOptions) !ExtendedProof {
        var diagnostic: ?prover_engine.ProveDiagnostic = null;
        var failed: ?ExtendedProof = null;
        return Engine.proveDiagnosedRetainingFailure(allocator, components, channel, scheme, options, &diagnostic, &failed) catch |err| {
            if (err == error.ConstraintsNotSatisfied) if (failed) |p| return p;
            return err;
        };
    }
};

// ---------------------------------------------------------------------------
// GKR wire (fixed 4-coefficient round polynomials, canonical QM31).

fn putU32(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(a, &b);
}
fn putQ(out: *std.ArrayList(u8), a: std.mem.Allocator, q: QM31) !void {
    for (q.toM31Array()) |m| try putU32(out, a, m.v);
}

pub fn encodeGkr(a: std.mem.Allocator, proof: *const gkr_verifier.GkrBatchProof) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    const n = proof.layer_masks_by_instance.len;
    try putU32(&out, a, @intCast(n));
    for (0..n) |i| {
        try putU32(&out, a, @intCast(proof.layer_masks_by_instance[i].len));
        try putU32(&out, a, @intCast(proof.output_claims_by_instance[i].len));
        for (proof.output_claims_by_instance[i]) |q| try putQ(&out, a, q);
    }
    try putU32(&out, a, @intCast(proof.sumcheck_proofs.len));
    for (proof.sumcheck_proofs) |sc| {
        try putU32(&out, a, @intCast(sc.round_polys.len));
        for (sc.round_polys) |poly| {
            const coeffs = poly.coeffsSlice();
            if (coeffs.len > sumcheck.MAX_DEGREE + 1) return error.GkrRoundPolyTooLong;
            for (0..sumcheck.MAX_DEGREE + 1) |k| try putQ(&out, a, if (k < coeffs.len) coeffs[k] else QM31.zero());
        }
    }
    for (proof.layer_masks_by_instance) |masks| for (masks) |mask| {
        try putU32(&out, a, @intCast(mask.columns.len));
        for (mask.columns) |col| {
            try putQ(&out, a, col[0]);
            try putQ(&out, a, col[1]);
        }
    };
    return out.toOwnedSlice(a);
}

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn u32_(self: *Reader) !u32 {
        if (self.at + 4 > self.bytes.len) return error.TruncatedGkrProof;
        const v = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
        self.at += 4;
        return v;
    }
    fn bounded(self: *Reader, max: usize) !usize {
        const v = try self.u32_();
        if (v > max) return error.GkrProofLimit;
        return v;
    }
    fn q(self: *Reader) !QM31 {
        var m: [4]M31 = undefined;
        for (&m) |*x| {
            const v = try self.u32_();
            if (v >= core.fields.m31.Modulus) return error.NonCanonicalField;
            x.* = M31.fromCanonical(v);
        }
        return QM31.fromM31Array(m);
    }
    fn take(self: *Reader, n: usize) ![]const u8 {
        if (self.at + n > self.bytes.len) return error.TruncatedGkrProof;
        const out = self.bytes[self.at .. self.at + n];
        self.at += n;
        return out;
    }
};

pub fn decodeGkr(a: std.mem.Allocator, bytes: []const u8) !gkr_verifier.GkrBatchProof {
    var r = Reader{ .bytes = bytes };
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const n = try r.bounded(MAX_INSTANCES);
    const n_masks = try arena.allocator().alloc(usize, n);
    var proof = gkr_verifier.GkrBatchProof{
        .sumcheck_proofs = try a.alloc(sumcheck.SumcheckProof, 0),
        .layer_masks_by_instance = try a.alloc([]gkr_verifier.GkrMask, n),
        .output_claims_by_instance = try a.alloc([]QM31, n),
    };
    for (proof.layer_masks_by_instance) |*m| m.* = try a.alloc(gkr_verifier.GkrMask, 0);
    for (proof.output_claims_by_instance) |*c| c.* = try a.alloc(QM31, 0);
    errdefer proof.deinit(a);
    for (0..n) |i| {
        n_masks[i] = try r.bounded(MAX_LAYERS);
        const nc = try r.bounded(2);
        a.free(proof.output_claims_by_instance[i]);
        proof.output_claims_by_instance[i] = try a.alloc(QM31, nc);
        for (proof.output_claims_by_instance[i]) |*c| c.* = try r.q();
    }
    const n_layers = try r.bounded(MAX_LAYERS);
    a.free(proof.sumcheck_proofs);
    proof.sumcheck_proofs = try a.alloc(sumcheck.SumcheckProof, n_layers);
    for (proof.sumcheck_proofs) |*sc| sc.* = .{ .round_polys = try a.alloc(lookup_utils.UnivariatePoly(QM31), 0) };
    for (proof.sumcheck_proofs) |*sc| {
        const rounds = try r.bounded(MAX_LAYERS);
        a.free(sc.round_polys);
        sc.round_polys = try a.alloc(lookup_utils.UnivariatePoly(QM31), 0);
        var polys = std.ArrayList(lookup_utils.UnivariatePoly(QM31)).empty;
        errdefer {
            for (polys.items) |*p| p.deinit(a);
            polys.deinit(a);
        }
        for (0..rounds) |_| {
            const coeffs = try a.alloc(QM31, sumcheck.MAX_DEGREE + 1);
            errdefer a.free(coeffs);
            for (coeffs) |*c| c.* = try r.q();
            try polys.append(a, lookup_utils.UnivariatePoly(QM31).initOwned(coeffs));
        }
        a.free(sc.round_polys);
        sc.round_polys = try polys.toOwnedSlice(a);
    }
    for (0..n) |i| {
        var masks = std.ArrayList(gkr_verifier.GkrMask).empty;
        errdefer {
            for (masks.items) |*m| m.deinit(a);
            masks.deinit(a);
        }
        for (0..n_masks[i]) |_| {
            const cols = try r.bounded(2);
            const columns = try a.alloc([2]QM31, cols);
            errdefer a.free(columns);
            for (columns) |*col| col.* = .{ try r.q(), try r.q() };
            try masks.append(a, gkr_verifier.GkrMask.initOwned(columns));
        }
        a.free(proof.layer_masks_by_instance[i]);
        proof.layer_masks_by_instance[i] = try masks.toOwnedSlice(a);
    }
    if (r.at != bytes.len) return error.TrailingGkrBytes;
    return proof;
}

// ---------------------------------------------------------------------------
// Receiver.

pub const VerifyReport = struct {
    gkr_ns: u64 = 0,
    stark_ns: u64 = 0,
    total_ns: u64 = 0,
    gkr_mix_calls: u64 = 0,
    gkr_mixed_felts: u64 = 0,
    gkr_draws: u64 = 0,
    gkr_blake_compressions: u64 = 0,
};

/// Counts transcript work of the GKR phase while forwarding to the real channel.
pub const CountingChannel = struct {
    inner: *Channel,
    mix_calls: u64 = 0,
    mixed_felts: u64 = 0,
    draws: u64 = 0,
    compressions: u64 = 0,
    pub fn mixFelts(self: *CountingChannel, felts: []const QM31) void {
        self.mix_calls += 1;
        self.mixed_felts += felts.len;
        self.compressions += @max(1, (32 + 16 * felts.len + 63) / 64);
        self.inner.mixFelts(felts);
    }
    pub fn drawSecureFelt(self: *CountingChannel) QM31 {
        self.draws += 1;
        self.compressions += 1;
        return self.inner.drawSecureFelt();
    }
};

/// R1: shape is taken from receiver geometry, never from the proof.
pub fn checkGkrShape(statement: W.Statement, proof: *const gkr_verifier.GkrBatchProof) !void {
    const n = statement.instanceCount();
    if (proof.layer_masks_by_instance.len != n or proof.output_claims_by_instance.len != n) return error.GkrShapeMismatch;
    var max_vars: usize = 0;
    for (0..n) |i| {
        const nv = statement.instanceLog(i) + W.LOG_LANES;
        max_vars = @max(max_vars, nv);
        if (proof.layer_masks_by_instance[i].len != nv) return error.GkrShapeMismatch;
        if (proof.output_claims_by_instance[i].len != 2) return error.GkrShapeMismatch;
        for (proof.layer_masks_by_instance[i]) |m| if (m.columns.len != 2) return error.GkrShapeMismatch;
    }
    if (proof.sumcheck_proofs.len != max_vars) return error.GkrShapeMismatch;
    for (proof.sumcheck_proofs, 0..) |sc, k| {
        if (sc.round_polys.len != k) return error.GkrShapeMismatch;
        for (sc.round_polys) |p| if (p.coeffsSlice().len > sumcheck.MAX_DEGREE + 1) return error.GkrShapeMismatch;
    }
}

pub const GkrOutcome = struct {
    bindings: [MAX_INSTANCES]Binding,
    fraction_sum: QM31,
};

/// R1-R5 on the live channel. The caller then checks closure (R6) and runs the STARK (R7).
pub fn verifyGkr(a: std.mem.Allocator, statement: W.Statement, ch: Air.Challenges, proof: *const gkr_verifier.GkrBatchProof, channel: anytype) !GkrOutcome {
    try checkGkrShape(statement, proof);
    const n = statement.instanceCount();
    var out = GkrOutcome{ .bindings = undefined, .fraction_sum = QM31.zero() };
    for (proof.output_claims_by_instance) |claims| {
        if (claims[1].isZero()) return error.GkrZeroRootDenominator; // R2
        out.fraction_sum = out.fraction_sum.add(try claims[0].div(claims[1]));
    }
    var gates: [MAX_INSTANCES]gkr_verifier.Gate = undefined;
    @memset(gates[0..n], .LogUp);
    var artifact = try gkr_verifier.partiallyVerifyBatch(a, gates[0..n], proof, channel); // R3
    defer artifact.deinit(a);
    for (0..n) |i| {
        const nv = statement.instanceLog(i) + W.LOG_LANES;
        if (artifact.n_variables_by_instance[i] != nv) return error.GkrShapeMismatch;
        const claims = artifact.claims_to_verify_by_instance[i];
        if (claims.len != 2) return error.GkrShapeMismatch;
        if (!claims[0].eql(QM31.one())) return error.GkrNumeratorNotOne; // R4
        const ood = artifact.ood_point;
        out.bindings[i] = Binding.init(ood[ood.len - nv ..], statement.instanceLog(i), ch, claims[1]) catch |err| switch (err) {
            error.DegenerateEvalPoint => return error.GkrDegenerateTerminalPoint, // R5
            else => return err,
        };
    }
    return out;
}

/// Fresh-process receiver. `statement` and `variant` come from receiver configuration only.
pub fn verify(a: std.mem.Allocator, config: pcs_core.PcsConfig, statement: W.Statement, variant: Variant, bytes: []const u8) !VerifyReport {
    var timer = try std.time.Timer.start();
    var report = VerifyReport{};
    try statement.validate();
    var r = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try r.take(8), PROOF_MAGIC)) return error.InvalidGkrBundle;
    if (try r.u32_() != @intFromEnum(variant)) return error.VariantMismatch; // R8
    for ([_]u32{ statement.ls_log, statement.tail_log, statement.hi_log, statement.lo_log }) |v| if (try r.u32_() != v) return error.StatementMismatch;
    const n = statement.instanceCount();
    const expected_claims: usize = if (variant == .classic) n + 2 else 2;
    if (try r.u32_() != expected_claims) return error.InvalidClaimCount;
    var claims: [2 + MAX_INSTANCES]QM31 = undefined;
    for (claims[0..expected_claims]) |*c| c.* = try r.q();
    const gkr_len = try r.u32_();
    const gkr_raw = try r.take(gkr_len);
    if (variant == .classic and gkr_len != 0) return error.UnexpectedGkrProof;
    const stark_len = try r.u32_();
    const stark_raw = try r.take(stark_len);
    if (r.at != bytes.len) return error.TrailingBundleBytes;

    var gkr_proof: ?gkr_verifier.GkrBatchProof = if (variant == .gkr) try decodeGkr(a, gkr_raw) else null;
    defer if (gkr_proof) |*p| p.deinit(a);
    if (gkr_proof) |*p| try checkGkrShape(statement, p);

    var proof = try proof_wire.decodeProofBytesBinary(a, stark_raw);
    var proof_owned = true;
    defer if (proof_owned) proof.deinit(a);
    if (!std.meta.eql(proof.commitment_scheme_proof.config, config)) return error.PcsConfigMismatch;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidProofShape;
    const expected_root = try preprocessedRoot(a, config, statement);
    if (!std.mem.eql(u8, &expected_root, &roots[0])) return error.PreprocessedRootMismatch;

    const geometry = Air.Geometry{ .statement = statement, .variant = variant };
    var scheme = try pcs_core.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(a, config);
    defer scheme.deinit(a);
    var channel = Channel{};
    config.mixInto(&channel);
    const pre_logs = geometry.preprocessedLogs();
    try scheme.commit(a, roots[0], &pre_logs, &channel);
    mixStatement(&channel, statement, variant);
    const main_logs = try geometry.mainLogs(a);
    defer a.free(main_logs);
    try scheme.commit(a, roots[1], main_logs, &channel);
    const ch = Air.Challenges.draw(&channel);

    var bindings: [MAX_INSTANCES]Binding = undefined;
    var sum = claims[expected_claims - 2].add(claims[expected_claims - 1]);
    switch (variant) {
        .classic => for (claims[0..n]) |c| {
            sum = sum.add(c);
        },
        .gkr => {
            const gkr_start = timer.read();
            var counting = CountingChannel{ .inner = &channel };
            const outcome = try verifyGkr(a, statement, ch, &gkr_proof.?, &counting);
            report.gkr_ns = timer.read() - gkr_start;
            report.gkr_mix_calls = counting.mix_calls;
            report.gkr_mixed_felts = counting.mixed_felts;
            report.gkr_draws = counting.draws;
            report.gkr_blake_compressions = counting.compressions;
            bindings = outcome.bindings;
            sum = sum.add(outcome.fraction_sum);
        },
    }
    if (!sum.isZero()) return error.UnclosedRangeLookup; // R6
    channel.mixFelts(claims[0..expected_claims]);
    const inter_logs = try geometry.interLogs(a);
    defer a.free(inter_logs);
    try scheme.commit(a, roots[2], inter_logs, &channel);
    const components = try Components.init(geometry, ch, claims[0..expected_claims], bindings[0..n]);
    var handles: [MAX_INSTANCES + 2]core.air.components.Component = undefined;
    const list = components.verifiers(&handles);
    const stark_start = timer.read();
    proof_owned = false;
    try core.verifier.verify(Hasher, MerkleChannel, a, list, &channel, &scheme, proof); // R7
    report.stark_ns = timer.read() - stark_start;
    report.total_ns = timer.read();
    return report;
}
