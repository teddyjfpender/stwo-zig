//! OuterNodeJob pre-stage (M8 outer-job stream): all host work of one
//! recursion node, run on a host pool ahead of phase 1 so it never sits
//! between two GPU stages. This file deliberately lives outside rv64/jobs/:
//! it is the one outer-job file that reuses legacy host preparation
//! (outer_assignment.zig Prepared, outer_source.zig lookupIndices), whose
//! import closures name lease/sync symbols the job sync lint forbids. Nothing
//! under rv64/jobs/ imports it; the request layer calls it and hands the
//! resulting jobs/outer_staged.zig Staged to the job.
//!
//!  * the device assignment plan, with the node's class hint / leaf flag /
//!    seed tape / Blake sample inputs installed on the pool thread exactly as
//!    outer_source.zig's owner controller installs them;
//!  * the host transcript prefix (config, profile, statement, FIXED root): the
//!    same om31 prove.begin + MC.mixRoot calls device_prove.zig makes, so the
//!    device channel starts from a byte-identical checkpoint;
//!  * class statics (plan, gathered FIXED raw evaluations, sorted log tables,
//!    eval-height twiddles), cached per fold class.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Dev = Outer.device_prove;
const Assignment = @import("outer_assignment.zig");
const Source = @import("outer_source.zig");
const Plan = @import("jobs/outer_plan.zig");
const St = @import("jobs/outer_staged.zig");
const TC = @import("jobs/outer_trace_commit.zig");
const K = @import("jobs/outer_kernels.zig");
const Job = @import("jobs/outer_job.zig");
const Checks = @import("jobs/outer_checks.zig");

/// Circuit constants of the om31 LogUp closure (witness.zig lookupSum).
fn lookupStatic() Checks.LookupStatic {
    const T = circuit.witness.trace;
    const u = T.U_VALUE.toM31Array();
    return .{ .relation = circuit.common.component_list.GATE_RELATION_ID, .u_index = @intCast(T.U_VAR_IDX), .u_value = .{ u[0].v, u[1].v, u[2].v, u[3].v } };
}
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const CP = engine.air.component_prover.ForField(Outer.protocol.O);
const O = Outer.protocol.O;

/// PCS sample points of a class at native_pcs.placeholderPoint(): the mask
/// points prove_family.zig draws at the OODS point (components bound with
/// placeholder challenges: masks depend on geometry only), plus the
/// composition tree's single-point columns. Challenge independent except for
/// the point itself, which the device substitutes (native_pcs.zig).
/// Host proof assembly after finish(): the ExtendedStarkProof the legacy
/// engine returns (PCS containers + empty aux, as pcs_native.zig builds it)
/// and the same composition OODS consistency check prove_family.zig runs
/// before returning a proof (ConstraintsNotSatisfied otherwise).
pub fn assemble(a: std.mem.Allocator, key: *const Authority, staged: *const St.Staged, job: *Job.OuterNodeJob) !Outer.prove.Produced {
    return assembleWithOods(a, key, staged, job, null);
}
/// assemble, also returning the two OODS values it compares
/// ([evaluated composition | extracted composition], 8 coordinates each)
/// for the device node_oods_constraint parity check.
pub fn assembleWithOods(a: std.mem.Allocator, key: *const Authority, staged: *const St.Staged, job: *Job.OuterNodeJob, oods: ?*[16]u32) !Outer.prove.Produced {
    // The decoded PCS proof moves into the Produced below, which its owner
    // frees with `a`: it must have been decoded with `a`.
    if (!St.sameAllocator(job.proof_allocator, a)) return error.OuterProofAllocatorMismatch;
    const d = job.decoded orelse return error.OuterJobNotDecoded;
    const pcs = job.pcs_proof orelse return error.OuterJobNotDecoded;
    job.pcs_proof = null;
    var proof = P.Engine.ExtendedProof{ .proof = .{ .commitment_scheme_proof = pcs.proof }, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = core.pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLiftedAux(D.H)).initOwned(&.{}), .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } };
    errdefer proof.deinit(a);
    const bound = try Outer.prove.bind(a, key, d.z, d.alpha, d.claims);
    defer a.free(bound);
    const components = try a.alloc(CP.ComponentProver, bound.len);
    defer a.free(components);
    for (components, bound) |*out, *c| out.* = c.asProverComponent();
    const provers = CP.ComponentProvers{ .components = components, .n_preprocessed_columns = key.fixed_logs.len };
    const log = provers.compositionLogDegreeBound();
    const split = try provers.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(log, split) orelse return error.InvalidOuterCompositionAuthority;
    var x: [8]Outer.protocol.M = undefined;
    var y: [8]Outer.protocol.M = undefined;
    for (&x, job.oods[0..8]) |*m, w| m.* = Outer.protocol.M.fromCanonical(w);
    for (&y, job.oods[8..16]) |*m, w| m.* = Outer.protocol.M.fromCanonical(w);
    const point = D.Point{ .x = O.fromM31Array(x), .y = O.fromM31Array(y) };
    var view = try provers.componentsView(a);
    defer view.deinit(a);
    const composition = proof.proof.extractCompositionOodsEvalWithSplit(point, mask_log + split, split) orelse return error.InvalidStructure;
    const expected = try view.evalCompositionPolynomialAtPointWithWorkCapture(a, point, &proof.proof.commitment_scheme_proof.sampled_values, d.coefficient, mask_log, mask_log + split, split, null);
    if (oods) |out| {
        for (expected.toM31Array(), 0..) |m, i| out[i] = m.v;
        for (composition.toM31Array(), 0..) |m, i| out[8 + i] = m.v;
    }
    if (!composition.eql(expected)) return error.ConstraintsNotSatisfied;
    const outputs = try a.alloc(Q, staged.expected.len / 4);
    errdefer a.free(outputs);
    for (outputs, 0..) |*q, i| q.* = Q.fromU32Unchecked(staged.expected[4 * i], staged.expected[4 * i + 1], staged.expected[4 * i + 2], staged.expected[4 * i + 3]);
    return .{ .allocator = a, .outputs = outputs, .claims = d.claims, .proof = proof };
}
const P = Outer.protocol;

pub const Q = Outer.protocol.Q;
pub const Authority = Outer.prove.Authority;

pub const Input = struct {
    key: *const Authority,
    graph: *const circuit.builder.Context(Q),
    expected: []const Q,
    ordinal: u32,
    class: ?[32]u8 = null,
    is_leaf: bool = false,
    seed_tape: ?*Dev.SeedTape = null,
    blake_sample_inputs: ?[]const [26]u32 = null,
    /// Base image handle; Prepared.init resolves its launch symbols from it.
    library: *std.DynLib,
    /// Build the composition statics (whole-node jobs; prefix-only parity
    /// runs may skip them).
    composition: bool = true,
    /// A host-prepared assignment plan for exactly `graph` (the request
    /// layer's prepare_host, built on the prep thread with the node's hints
    /// installed; required for seed-tape stub graphs). Moved into the Staged
    /// on every path, including failure. Null: Prepared.init here.
    prepared: ?Assignment.Prepared = null,
};

/// Process-wide outer composition catalogue (geometry independent: the pinned
/// AIR bundle's root groups, as outer_source.zig ensureCatalogue builds them),
/// authenticated against the base image's AOT kernel identities.
const StaticOwner = @import("outer_class_statics.zig");
const Statics = StaticOwner.Statics;
const StaticsCache = StaticOwner.StaticsCache;
const Twiddles = StaticOwner.Twiddles;
pub const ClassPin = StaticOwner.ClassPin;

/// Thread-local producer hints Prepared.init reads (outer_source.zig ControllerTls).
const Hints = struct {
    class_hint: ?[32]u8,
    class_is_leaf: bool,
    seed_tape: ?*Dev.SeedTape,
    blake_sample_inputs: ?[]const [26]u32,
    fn get() Hints {
        return .{ .class_hint = Dev.class_hint, .class_is_leaf = Dev.class_is_leaf, .seed_tape = Dev.seed_tape, .blake_sample_inputs = Dev.blake_sample_inputs };
    }
    fn install(self: Hints) void {
        Dev.class_hint = self.class_hint;
        Dev.class_is_leaf = self.class_is_leaf;
        Dev.seed_tape = self.seed_tape;
        Dev.blake_sample_inputs = self.blake_sample_inputs;
    }
};

/// Host transcript prefix: device_prove.zig proveOwnedDirect up to and
/// including the FIXED root mix (prove.begin, then MC.mixRoot of the FIXED
/// root, which is also exactly what adoptDeviceOm31TraceTree(0, ...) mixes).
pub fn hostCheckpoint(a: std.mem.Allocator, key: *const Authority, expected: []const Q) ![9]u32 {
    var channel = try Outer.prove.begin(a, key, expected);
    Outer.protocol.MC.mixRoot(&channel, key.fixedRoot());
    const cp = core.channel.raw_mod_m31.om31Checkpoint(&channel);
    var seed: [9]u32 = undefined;
    for (0..8) |w| seed[w] = std.mem.readInt(u32, cp.digest[4 * w ..][0..4], .little);
    seed[8] = cp.draws;
    return seed;
}

/// Owner of everything a Staged borrows.
const Owner = struct {
    allocator: std.mem.Allocator,
    prepared: Assignment.Prepared,
    statics: *Statics,
    owns_statics: bool,
    /// A reference counted class-plan cache borrow (StaticsCache.unref on release).
    counted_statics: bool = false,
    runs: []St.Run,
    expected: []u32,
    fixed_raw: [][]const u32,
    staged: St.Staged,
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        const a = self.allocator;
        self.prepared.deinit();
        if (self.owns_statics) self.statics.destroy() else if (self.counted_statics) StaticsCache.unref(self.statics);
        a.free(self.runs);
        a.free(self.expected);
        a.free(self.fixed_raw);
        a.destroy(self);
    }
};

/// Builds the node's Staged on the calling (pool) thread. The returned
/// pointer is owned by its own `release` (Staged.deinit).
pub fn prestage(a: std.mem.Allocator, input: Input) !*St.Staged {
    var adopted = input.prepared;
    errdefer if (adopted) |*p| p.deinit();
    const key = input.key;
    try key.requireProverData();
    const graph = input.graph;
    if (!graph.trace_only or !graph.finalized or !graph.record_gates) return error.TraceOnlyGraphRequired;
    if (input.expected.len != key.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
    for (input.expected) |value| for (value.toM31Array()) |m| if (m.v >= core.fields.m31.Modulus) return error.NoncanonicalOm31CircuitOutput;
    const owner = try a.create(Owner);
    errdefer a.destroy(owner);
    owner.allocator = a;
    owner.prepared = if (adopted) |*p| blk: {
        try p.rebind(input.library);
        break :blk p.*;
    } else blk: {
        const previous = Hints.get();
        (Hints{ .class_hint = input.class, .class_is_leaf = input.is_leaf, .seed_tape = input.seed_tape, .blake_sample_inputs = input.blake_sample_inputs }).install();
        defer previous.install();
        break :blk try Assignment.Prepared.init(a, graph, input.library);
    };
    adopted = null;
    errdefer owner.prepared.deinit();
    const prepared = &owner.prepared;
    if (prepared.reference != null or prepared.count == 0 or prepared.count > std.math.maxInt(u32) / 4) return error.TraceOnlySourceRequired;
    // The statics cache already uses the process allocator; retained native
    // templates take a counted pin rather than borrowing request custody.
    const acquired = try StaticsCache.acquire(key, !input.is_leaf and input.class != null, input.library, input.composition);
    errdefer if (acquired.owned) acquired.statics.destroy() else if (acquired.counted) StaticsCache.unref(acquired.statics);
    owner.statics = acquired.statics;
    owner.owns_statics = acquired.owned;
    owner.counted_statics = acquired.counted;
    var needs_ends = false;
    var ends: []const u32 = &.{};
    owner.runs = if (prepared.narrow_plan) |narrow| blk: {
        const runs = try a.alloc(St.Run, narrow.runs.len);
        for (runs, narrow.runs) |*dst, run| {
            dst.* = .{ .kind = switch (run.kind) {
                .ordinary => .ordinary,
                .narrow => .narrow,
                .chain => .chain,
            }, .first_task = run.first_task, .task_count = run.task_count, .first_level = run.first_level, .level_count = run.level_count };
            needs_ends = needs_ends or run.kind == .chain;
        }
        ends = narrow.ends;
        break :blk runs;
    } else try a.alloc(St.Run, 0);
    errdefer a.free(owner.runs);
    owner.expected = try a.alloc(u32, input.expected.len * 4);
    errdefer a.free(owner.expected);
    // This node's raw FIXED evaluations (its own PP; never the class statics').
    owner.fixed_raw = try a.alloc([]const u32, if (owner.statics.fixed_plan != null) key.pp.columns.len else 0);
    errdefer a.free(owner.fixed_raw);
    for (owner.fixed_raw, key.pp.columns[0..owner.fixed_raw.len]) |*dst, column| dst.* = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values));
    for (input.expected, 0..) |q, i| for (q.toM31Array(), 0..) |m, j| {
        owner.expected[4 * i + j] = m.v;
    };
    const sample_tape: ?[]const u32 = if (prepared.blake_sample_inputs) |inputs| std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inputs)) else null;
    if (prepared.blake_sample_outputs) |map| if (prepared.blake_sample_inputs == null or prepared.blake_sample_inputs.?.len != map.len) return error.BlakeSampleInputCountMismatch;
    const assignment = St.Assignment{
        .count = prepared.count,
        .seeds = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(prepared.seeds)),
        .tasks = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(prepared.tasks)),
        .indices = prepared.indices,
        .runs = owner.runs,
        .level_ends = prepared.plan.level_ends,
        .ends = ends,
        .needs_device_ends = needs_ends,
        .seed = @as(K.Launch, @ptrCast(prepared.seed)),
        .level = @as(K.Launch, @ptrCast(prepared.level)),
        .wide = if (prepared.wide_level) |f| @as(K.Launch, @ptrCast(f)) else null,
        .narrow = if (prepared.narrow_run) |f| @as(K.LaunchRun, @ptrCast(f)) else null,
        .chain = if (prepared.chain_run) |f| @as(K.LaunchChain, @ptrCast(f)) else null,
        .sample_tape = sample_tape,
        .sample_map = prepared.blake_sample_outputs,
        .sample_first_gg = if (prepared.blake_sample_span) |span| span.first_gg else 0,
        .reusable = prepared.reusable and !input.is_leaf,
    };
    if (sample_tape != null and prepared.blake_sample_span == null) return error.MissingBlakeSampleClassSpan;
    const device_checks = try Checks.selected();
    var class_key: [32]u8 = undefined;
    {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/m8/outer-job/class/v1\x00");
        h.update(&key.identity);
        h.update(&prepared.identity);
        class_key = h.finalResult();
    }
    var graph_key: [32]u8 = undefined;
    {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/m8/outer-job/graph-topology/v1\x00");
        h.update(std.mem.sliceAsBytes(&key.logs.toArray()));
        h.update(std.mem.sliceAsBytes(&key.fixed_logs));
        for (owner.runs) |run| h.update(std.mem.asBytes(&[_]u32{ @intFromEnum(run.kind), run.first_task, run.task_count, run.first_level, run.level_count }));
        h.update(std.mem.asBytes(&[_]u64{ prepared.plan.level_ends.len, prepared.tasks.len, prepared.seeds.len, prepared.indices.len, prepared.count, @intFromBool(sample_tape != null), @intFromBool(prepared.blake_sample_outputs != null), @intFromBool(input.composition) }));
        // The device checks add one kernel to the body (topology).
        // v2: the body also clears the check words (one memset node).
        if (device_checks) h.update("device-checks/v2");
        graph_key = h.finalResult();
    }
    owner.staged = .{
        .assignment = assignment,
        .statics = &owner.statics.public,
        .checkpoint = try hostCheckpoint(a, key, input.expected),
        .expected = owner.expected,
        .class_key = class_key,
        .graph_key = graph_key,
        .ordinal = input.ordinal,
        .image = St.Staged.layoutWith(&assignment, &owner.statics.public, if (device_checks) owner.expected.len else 0),
        .lookup = if (device_checks) lookupStatic() else null,
        .owner = owner,
        .release = Owner.release,
        .fixed_root = key.fixedRoot(),
        .fixed_logs = &key.fixed_logs,
        .fixed_raw = owner.fixed_raw,
        .pcs_points = if (owner.statics.rc) |*rc| @ptrCast(rc.points) else null,
    };
    return &owner.staged;
}

comptime {
    // The job restates these native ABIs to keep its lint closure clean.
    if (@sizeOf(K.Fractions) != @sizeOf(Source.Fractions) or @sizeOf(K.Cumulative) != @sizeOf(Source.Cumulative) or @sizeOf(K.AssignmentJob) != @sizeOf(Assignment.Job)) @compileError("outer job ABI restatement drifted");
    for (.{ "fixed", "main", "parameters", "numerators", "denominators", "status", "fixed_words", "main_words", "numerator_words", "denominator_words", "component", "row_log" }) |f| {
        if (@offsetOf(K.Fractions, f) != @offsetOf(Source.Fractions, f)) @compileError("Fractions field drifted: " ++ f);
    }
    for (.{ "values", "records", "indices", "status", "value_count", "record_count", "index_count", "first", "count" }) |f| {
        if (@offsetOf(K.AssignmentJob, f) != @offsetOf(Assignment.Job, f)) @compileError("Job field drifted: " ++ f);
    }
}

/// jobs/mod.zig Hooks.outer_prestage (M8-INTERFACES outer-job R4): type-erased
/// so nothing under rv64/jobs/ imports this file. `input` is a *const Input.
pub fn prestageHook(_: ?*anyopaque, a: std.mem.Allocator, input: *const anyopaque) anyerror!*St.Staged {
    const typed: *const Input = @ptrCast(@alignCast(input));
    return prestage(a, typed.*);
}

/// Own the class schedule and statics after a real install-time proof. The
/// retained template has no seed values, public outputs, channel checkpoint,
/// sample tape or pointer into the warm request's authority/allocator.
pub fn packTemplate(a: std.mem.Allocator, source: *const St.Staged) !@import("jobs/outer_packed_class.zig").Class {
    const class_words: usize = @intCast(source.image.words[@intFromEnum(St.Region.class)]);
    const fixed_words: usize = @intCast((source.statics.fixed_plan orelse return error.OuterJobWholeStagingMissing).coefficient_words);
    const raw = try a.alloc(u32, class_words + fixed_words);
    defer a.free(raw);
    @memset(raw, 0);
    try source.pack(.class, raw[0..class_words]);
    try source.packFixed(raw[class_words..]);
    // Assignment tasks have eight fields. Preserve those predictors instead
    // of delta-coding adjacent fields against each other. All class ranges
    // are granule-aligned; scalar-only odd images retain one channel.
    var compressed = try Outer.cache_pack.pack(a, raw, if (raw.len % 8 == 0) 8 else 1);
    defer compressed.deinit(a);
    return @import("jobs/outer_packed_class.zig").build(a, compressed, class_words, fixed_words);
}

pub fn retainTemplate(a: std.mem.Allocator, input: Input, source: *const St.Staged) !*St.Staged {
    if (source.assignment.sample_tape != null or source.assignment.sample_map != null) return error.GnTemplateContainsSampleWitness;
    const owner = try a.create(TemplateOwner);
    errdefer a.destroy(owner);
    owner.* = .{ .a = a, .arena = std.heap.ArenaAllocator.init(a) };
    errdefer owner.arena.deinit();
    const ar = owner.arena.allocator();
    const statics = if (ClassPin.take(@ptrCast(@constCast(source.statics)))) |pin| blk: {
        owner.pin = pin;
        break :blk source.statics;
    } else |_| blk: {
        const s = try Statics.init(a, input.key, input.library, true);
        s.public.class_plan = @ptrCast(&s.slot);
        owner.statics = s;
        break :blk &s.public;
    };
    errdefer {
        if (owner.pin) |pin| ClassPin.release(pin.statics);
        if (owner.statics) |s| s.destroy();
    }
    var assignment = source.assignment;
    const seeds = try ar.dupe(u32, assignment.seeds);
    if (seeds.len % 5 != 0) return error.InvalidOuterSeedLayout;
    for (0..seeds.len / 5) |i| @memset(seeds[5 * i + 1 ..][0..4], 0);
    assignment.seeds = seeds;
    assignment.tasks = try ar.dupe(u32, assignment.tasks);
    assignment.indices = try ar.dupe(u32, assignment.indices);
    assignment.runs = try ar.dupe(St.Run, assignment.runs);
    assignment.level_ends = try ar.dupe(usize, assignment.level_ends);
    assignment.ends = try ar.dupe(u32, assignment.ends);
    assignment.reusable = true;
    const expected = try ar.alloc(u32, source.expected.len);
    @memset(expected, 0);
    const fixed = try ar.alloc([]const u32, source.fixed_raw.len);
    for (fixed, source.fixed_raw) |*out, column| out.* = try ar.dupe(u32, column);
    owner.staged = source.*;
    owner.staged.assignment = assignment;
    owner.staged.statics = statics;
    owner.staged.checkpoint = @splat(0);
    owner.staged.expected = expected;
    owner.staged.fixed_logs = try ar.dupe(u32, source.fixed_logs);
    owner.staged.fixed_raw = fixed;
    owner.staged.pcs_points = if (owner.statics) |s| if (s.rc) |*rc| @ptrCast(rc.points) else null else source.pcs_points;
    owner.staged.image = St.Staged.layoutWith(&assignment, statics, expected.len);
    owner.staged.owner = owner;
    owner.staged.release = TemplateOwner.release;
    return &owner.staged;
}
const TemplateOwner = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    pin: ?ClassPin = null,
    statics: ?*Statics = null,
    staged: St.Staged = undefined,
    fn release(raw: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        const a = self.a;
        self.arena.deinit();
        if (self.pin) |pin| ClassPin.release(pin.statics);
        if (self.statics) |s| s.destroy();
        a.destroy(self);
    }
};
/// Hooks.outer_assemble: heap Outer.prove.Produced (caller deinit + destroy).
/// `key` is a *const Authority.
pub fn assembleHook(_: ?*anyopaque, a: std.mem.Allocator, key: *const anyopaque, staged: *const St.Staged, job: *Job.OuterNodeJob) anyerror!*anyopaque {
    const produced = try a.create(Outer.prove.Produced);
    errdefer a.destroy(produced);
    produced.* = try assemble(a, @ptrCast(@alignCast(key)), staged, job);
    return produced;
}

/// Host inputs of the FIXED precommit job (jobs/outer_fixed_job.zig) for one
/// preprocessed circuit: the FIXED commit plan in the authority's original
/// column order (the same TreePlan Statics.init builds for the node job),
/// its sorted log table, the raw PP columns and the eval-height twiddles.
pub const FixedPrecommit = struct {
    allocator: std.mem.Allocator,
    plan: Plan.TreePlan,
    sorted: []u32,
    raw: [][]const u32,
    pub fn init(a: std.mem.Allocator, pp: *const circuit.common.preprocessed.PreprocessedCircuit) !FixedPrecommit {
        const logs = try a.alloc(u32, pp.columns.len);
        defer a.free(logs);
        for (logs, pp.columns) |*log, column| {
            if (column.values.len == 0 or !std.math.isPowerOfTwo(column.values.len)) return error.InvalidOuterFixedGeometry;
            log.* = column.logSize();
        }
        var plan = try Plan.TreePlan.init(a, logs, (try Outer.protocol.targetConfig()).fri_config.log_blowup_factor);
        errdefer plan.deinit(a);
        const sorted = try a.alloc(u32, plan.order.len);
        errdefer a.free(sorted);
        TC.sortedLogs(&plan, sorted);
        const raw = try a.alloc([]const u32, pp.columns.len);
        for (raw, pp.columns) |*dst, column| dst.* = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values));
        return .{ .allocator = a, .plan = plan, .sorted = sorted, .raw = raw };
    }
    pub fn inputs(self: *const FixedPrecommit) !@import("jobs/outer_fixed_job.zig").Inputs {
        const tw = try Twiddles.get(self.plan.eval_log);
        return .{ .plan = &self.plan, .raw = self.raw, .sorted_logs = self.sorted, .twiddles = tw.twiddles, .itwiddles = tw.itwiddles };
    }
    pub fn deinit(self: *FixedPrecommit) void {
        const a = self.allocator;
        a.free(self.raw);
        a.free(self.sorted);
        self.plan.deinit(a);
        self.* = undefined;
    }
};

/// Per-class OODS program of the device node_oods_constraint check
/// (jobs/outer_encode_oods.zig): every bound component part's AIR bytecode
/// with its mask reads resolved to PCS-image sample indices, the component
/// coset constants and parameter sources, in the order assemble's
/// evalCompositionPolynomialAtPoint accumulates them. Challenge independent:
/// components are bound with placeholder challenges (only geometry, programs
/// and parameter SOURCES are read). `sample_counts[t][c]` are the PCS shape's
/// per-column sample counts (tree, original column), i.e. the image order.
pub fn oodsProgram(a: std.mem.Allocator, key: *const Authority, sample_counts: []const []const u32) ![]u32 {
    const OP = @import("jobs/outer_encode_oods.zig");
    const Geo = Outer.geometry;
    const RG = struct {
        // resident_geometry.offsetIndex
        fn offsetIndex(offsets: []const i32, wanted: i32) ?usize {
            for (offsets, 0..) |offset, index| if (offset == wanted) return index;
            return null;
        }
    };
    const placeholder: [Plan.n_components]O = @splat(O.one());
    const bound = try Outer.prove.bind(a, key, O.one(), O.one(), Outer.witness.Claims.fromArray(placeholder));
    defer a.free(bound);
    const components = try a.alloc(CP.ComponentProver, bound.len);
    defer a.free(components);
    for (components, bound) |*out, *c| out.* = c.asProverComponent();
    const provers = CP.ComponentProvers{ .components = components, .n_preprocessed_columns = key.fixed_logs.len };
    const log = provers.compositionLogDegreeBound();
    const split = try provers.compositionLogSplit();
    if (split != 1) return error.InvalidOuterCompositionAuthority;
    const mask_log = core.verifier_types.compositionMaskLogSize(log, split) orelse return error.InvalidOuterCompositionAuthority;
    if (sample_counts.len != 4) return error.InvalidOuterOodsShape;
    // First sample index of every (tree, column).
    const first = try a.alloc([]u32, sample_counts.len);
    defer a.free(first);
    var made: usize = 0;
    defer for (first[0..made]) |f| a.free(f);
    var total: u32 = 0;
    for (sample_counts, first) |counts, *f| {
        f.* = try a.alloc(u32, counts.len);
        made += 1;
        for (counts, f.*) |c, *x| {
            x.* = total;
            total += c;
        }
    }
    const columns = core.verifier_types.compositionColumnCount(split, 8) orelse return error.InvalidOuterCompositionAuthority;
    if (sample_counts[3].len != columns) return error.InvalidOuterOodsShape;
    for (sample_counts[3]) |c| if (c != 1) return error.InvalidOuterOodsShape;
    var b = OP.Builder{ .a = a };
    defer b.deinit();
    for (bound, 0..) |*component, ci| {
        const c = component.captured;
        if (mask_log < c.trace_log_size) return error.InvalidOm31MaskGeometry;
        const mo = try Geo.offsets(a, c.*, 1);
        defer Geo.freeOffsets(a, mo);
        const io = try Geo.offsets(a, c.*, 2);
        defer Geo.freeOffsets(a, io);
        const spans = [_]Geo.Span{ .{ .start = 0, .end = 0 }, try Geo.span(c.*, 1), try Geo.span(c.*, 2) };
        const Resolve = struct {
            c: @TypeOf(c),
            first: []const []u32,
            counts: []const []const u32,
            spans: []const Geo.Span,
            offs: [2][]const std.ArrayList(i32),
            /// component.zig PointRead.get: the sample index of one physical read.
            fn get(self: @This(), tree: u8, column: u32, offset: i32) !u32 {
                if (tree == 0) {
                    if (offset != 0 or column >= self.c.preprocessed_indices.len) return error.MissingOm31Mask;
                    const global = self.c.preprocessed_indices[column];
                    if (global >= self.counts[0].len or self.counts[0][global] != 1) return error.MissingOm31Mask;
                    return self.first[0][global];
                }
                if (tree > 2) return error.MissingOm31Mask;
                const offsets = self.offs[tree - 1];
                const global = self.spans[tree].start + column;
                if (column >= offsets.len or global >= self.counts[tree].len) return error.MissingOm31Mask;
                if (self.counts[tree][global] != offsets[column].items.len) return error.MissingOm31Mask;
                const at = RG.offsetIndex(offsets[column].items, offset) orelse return error.MissingOm31Mask;
                return self.first[tree][global] + @as(u32, @intCast(at));
            }
        };
        const r = Resolve{ .c = c, .first = first, .counts = sample_counts, .spans = &spans, .offs = .{ mo, io } };
        // Parameter sources (program_lane.zig extensionParameters).
        var params: std.ArrayListUnmanaged(u32) = .empty;
        defer params.deinit(a);
        for (c.ext_sources) |source| try params.appendSlice(a, &switch (source) {
            .constant => |w| [6]u32{ @intFromEnum(OP.ParamKind.constant), w[0], w[1], w[2], w[3], 0 },
            .lookup_z => [6]u32{ @intFromEnum(OP.ParamKind.lookup_z), 0, 0, 0, 0, 0 },
            .lookup_alpha_power => |n| [6]u32{ @intFromEnum(OP.ParamKind.alpha_power), 0, 0, 0, 0, n },
            .lookup_alpha_power_scaled => |x| [6]u32{ @intFromEnum(OP.ParamKind.alpha_power_scaled), x.scale, 0, 0, 0, x.power },
            .claimed_sum_scaled => [6]u32{ @intFromEnum(OP.ParamKind.claimed_sum_scaled), 0, 0, 0, 0, 0 },
        });
        const coset = core.poly.circle.canonic.CanonicCoset.new(c.trace_log_size).coset();
        const scale = try core.fields.m31.M31.fromCanonical(@as(u32, 1) << @intCast(c.trace_log_size)).inv();
        for (c.parts) |part| {
            const p = part.program;
            if (p.header.n_base_params != 0 or p.header.n_ext_params != c.ext_sources.len) return error.InvalidOm31Parameters;
            var row: [OP.Part.words]u32 = @splat(0);
            row[OP.Part.component] = @intCast(ci);
            row[OP.Part.trace_log] = c.trace_log_size;
            row[OP.Part.claim] = @intCast(ci);
            row[OP.Part.params_at] = try b.span(params.items);
            row[OP.Part.n_params] = @intCast(c.ext_sources.len);
            var insts: std.ArrayListUnmanaged(u32) = .empty;
            defer insts.deinit(a);
            for (p.base_insts) |i| {
                var s0: u32 = OP.no_sample;
                var s1: u32 = OP.no_sample;
                switch (i.op) {
                    .trace_col, .preprocessed_col => {
                        // program_lane.zig Reader.read: INTER logical = low + v * high.
                        if (i.interaction != 2) s0 = try r.get(i.interaction, i.a, i.imm) else {
                            const low = (i.a / 4) * 8 + i.a % 4;
                            s0 = try r.get(2, low, i.imm);
                            s1 = try r.get(2, low + 4, i.imm);
                        }
                    },
                    .param => return error.InvalidOm31Parameters,
                    else => {},
                }
                try insts.appendSlice(a, &[_]u32{ @intFromEnum(i.op), i.dst, i.a, i.b, s0, s1 });
            }
            row[OP.Part.base_at] = try b.span(insts.items);
            row[OP.Part.n_base] = @intCast(p.base_insts.len);
            insts.clearRetainingCapacity();
            for (p.ext_insts) |i| try insts.appendSlice(a, &[_]u32{ @intFromEnum(i.op), i.dst, i.a, i.b, i.c, i.d });
            row[OP.Part.ext_at] = try b.span(insts.items);
            row[OP.Part.n_ext] = @intCast(p.ext_insts.len);
            row[OP.Part.roots_at] = try b.span(p.constraint_roots);
            row[OP.Part.n_roots] = @intCast(p.constraint_roots.len);
            row[OP.Part.max_base] = p.header.max_base_regs;
            row[OP.Part.max_ext] = p.header.max_ext_regs;
            row[OP.Part.regs_at] = b.regs(p.header.max_base_regs, p.header.max_ext_regs);
            row[OP.Part.initial] = coset.initial.x.v;
            row[OP.Part.initial + 1] = coset.initial.y.v;
            row[OP.Part.half_step] = coset.half_step.x.v;
            row[OP.Part.half_step + 1] = coset.half_step.y.v;
            row[OP.Part.coset_log] = coset.log_size;
            row[OP.Part.claim_scale] = scale.v;
            try b.part(row);
        }
    }
    var header: [OP.H.header_words]u32 = @splat(0);
    header[OP.H.global_log] = mask_log;
    header[OP.H.composition_log] = mask_log + split;
    header[OP.H.split] = split;
    header[OP.H.composition_sample] = first[3][0];
    header[OP.H.samples] = total;
    header[OP.H.claims] = Plan.n_components;
    return b.finish(header);
}
