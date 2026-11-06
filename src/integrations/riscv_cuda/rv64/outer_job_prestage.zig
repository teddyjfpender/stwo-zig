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
const Comp = @import("jobs/outer_composition.zig");
const Aot = @import("outer_aot.zig");
const Code = @import("composition_codegen.zig");
const RvAir = @import("stwo_riscv_frontend").rv64_air;
const NativePcs = @import("jobs/native_pcs.zig");
const Job = @import("jobs/outer_job.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const CP = engine.air.component_prover.ForField(Outer.protocol.O);
const O = Outer.protocol.O;

/// PCS sample points of a class at native_pcs.placeholderPoint(): the mask
/// points prove_family.zig draws at the OODS point (components bound with
/// placeholder challenges: masks depend on geometry only), plus the
/// composition tree's single-point columns. Challenge independent except for
/// the point itself, which the device substitutes (native_pcs.zig).
fn samplePoints(a: std.mem.Allocator, key: *const Authority) !*core.pcs.TreeVec([][]D.Point) {
    const placeholder = try NativePcs.placeholderPoint();
    const claims: [Plan.n_components]O = @splat(O.zero());
    const bound = try Outer.prove.bind(a, key, O.one(), O.one(), Outer.witness.Claims.fromArray(claims));
    defer a.free(bound);
    const components = try a.alloc(CP.ComponentProver, bound.len);
    defer a.free(components);
    for (components, bound) |*out, *c| out.* = c.asProverComponent();
    const provers = CP.ComponentProvers{ .components = components, .n_preprocessed_columns = key.fixed_logs.len };
    const log = provers.compositionLogDegreeBound();
    const split = try provers.compositionLogSplit();
    if (split != 1 or log != key.bound.max_evaluation_log_size) return error.InvalidOuterCompositionAuthority;
    const mask_log = core.verifier_types.compositionMaskLogSize(log, split) orelse return error.InvalidOuterCompositionAuthority;
    var view = try provers.componentsView(a);
    defer view.deinit(a);
    var points = try view.maskPointsWithWorkCapture(a, placeholder, mask_log, false, null);
    errdefer points.deinitDeep(a);
    const columns = core.verifier_types.compositionColumnCount(split, 8) orelse return error.InvalidOuterCompositionAuthority;
    const tree = try a.alloc([]D.Point, columns);
    for (tree) |*col| {
        col.* = try a.alloc(D.Point, 1);
        col.*[0] = placeholder;
    }
    const out = try a.alloc([][]D.Point, points.items.len + 1);
    @memcpy(out[0..points.items.len], points.items);
    out[points.items.len] = tree;
    a.free(points.items);
    points.items = out;
    const boxed = try a.create(core.pcs.TreeVec([][]D.Point));
    boxed.* = points;
    return boxed;
}

/// Host proof assembly after finish(): the ExtendedStarkProof the legacy
/// engine returns (PCS containers + empty aux, as pcs_native.zig builds it)
/// and the same composition OODS consistency check prove_family.zig runs
/// before returning a proof (ConstraintsNotSatisfied otherwise).
pub fn assemble(a: std.mem.Allocator, key: *const Authority, staged: *const St.Staged, job: *Job.OuterNodeJob) !Outer.prove.Produced {
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
};

/// Process-wide outer composition catalogue (geometry independent: the pinned
/// AIR bundle's root groups, as outer_source.zig ensureCatalogue builds them),
/// authenticated against the base image's AOT kernel identities.
const Catalogue = struct {
    const Group = struct { component: u32, roots: u32, masks: []u32, slots: []u32 };
    var mutex: std.Thread.Mutex = .{};
    var groups: ?[]Group = null;
    var identity: [32]u8 = undefined;
    const IdentityFn = *const fn (u32, [*]u8) callconv(.c) c_int;
    fn bodyIdentity(key: *const Authority) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(@import("stwo_circuit_cpu_integration").air.bundle_sha256);
        var word: [8]u8 = undefined;
        for (key.bound.components) |component| for (component.parts) |part| {
            std.mem.writeInt(u64, &word, part.program.semanticHash(), .little);
            hash.update(&word);
        };
        return hash.finalResult();
    }
    fn get(key: *const Authority, library: *std.DynLib) ![]const Group {
        mutex.lock();
        defer mutex.unlock();
        const body = bodyIdentity(key);
        if (groups) |g| {
            if (!std.mem.eql(u8, &identity, &body)) return error.ChangedOm31CircuitProgram;
            return g;
        }
        const a = std.heap.c_allocator;
        const ident = library.lookup(IdentityFn, "stwo_circuit_om31_composition_identity") orelse return error.MissingOuterCompositionKernel;
        const catalogue = try Aot.groups(a, &key.bound);
        defer a.free(catalogue);
        const out = try a.alloc(Group, catalogue.len);
        for (catalogue, out, 0..) |group, *dst, id| {
            var artifact = try Outer.record.record(a, &key.bound.components[group.component], group.part, group.first, group.count);
            defer artifact.deinit();
            var actual: [64]u8 = undefined;
            if (ident(@intCast(id), &actual) != 0) return error.Om31OuterAotIdentityMismatch;
            if (!std.mem.eql(u8, actual[0..32], &artifact.program.identity) or !std.mem.eql(u8, actual[32..], &(try Code.identity(&artifact.program)))) return error.Om31OuterAotIdentityMismatch;
            const masks = try a.alloc(u32, artifact.program.inputs.len);
            for (masks, artifact.program.inputs) |*m, input| m.* = input.column;
            dst.* = .{ .component = group.component, .roots = @intCast(artifact.program.roots.len), .masks = masks, .slots = try a.dupe(u32, artifact.parameter_slots) };
        }
        groups = out;
        identity = body;
        return out;
    }
};

/// Composition statics of one class: role descriptions plus one class-region
/// blob (FIXED coefficients, masks, denominators, LDE logs, parameter table,
/// commit logs). The blob sits at class-region offset 0.
const Rc = struct {
    static: Comp.Static,
    points: *core.pcs.TreeVec([][]D.Point),
    blob: []u32,
    roles: []Comp.RoleStatic,
    sources: []Comp.Source,
    fixed_offsets: []u64,
    fn deinit(self: *Rc, a: std.mem.Allocator) void {
        self.points.deinitDeep(a);
        a.destroy(self.points);
        a.free(self.blob);
        a.free(self.roles);
        a.free(self.sources);
        a.free(self.fixed_offsets);
    }
    fn init(a: std.mem.Allocator, key: *const Authority, library: *std.DynLib, plan: *const Plan.ClassPlan) !Rc {
        const fixed_tree = key.fixed orelse return error.OuterJobRequiresHostFixedTree;
        const fixed_coefficients = fixed_tree.coefficients orelse return error.OuterJobRequiresHostFixedTree;
        const groups = try Catalogue.get(key, library);
        var blob: std.ArrayList(u32) = .empty;
        errdefer blob.deinit(a);
        const Take = struct {
            fn take(list: *std.ArrayList(u32), al: std.mem.Allocator, words: []const u32) !St.Range {
                const at = list.items.len;
                try list.appendSlice(al, words);
                while (list.items.len % 2 != 0) try list.append(al, 0);
                return .{ .region = .class, .offset = at, .words = words.len };
            }
        };
        // FIXED coefficients, original column order.
        const fixed_offsets = try a.alloc(u64, fixed_coefficients.len);
        errdefer a.free(fixed_offsets);
        const fixed_first = blob.items.len;
        for (fixed_coefficients, fixed_offsets) |poly, *off| {
            off.* = blob.items.len - fixed_first;
            try blob.appendSlice(a, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(poly.coefficients())));
        }
        const fixed = St.Range{ .region = .class, .offset = fixed_first, .words = blob.items.len - fixed_first };
        while (blob.items.len % 2 != 0) try blob.append(a, 0);
        const roles = try a.alloc(Comp.RoleStatic, groups.len);
        errdefer a.free(roles);
        var sources: std.ArrayList(Comp.Source) = .empty;
        errdefer sources.deinit(a);
        const source_first = try a.alloc(usize, groups.len + 1);
        defer a.free(source_first);
        var params: std.ArrayList(u32) = .empty;
        defer params.deinit(a);
        var param_total: u32 = 0;
        const M = Outer.protocol.M;
        for (groups, roles, 0..) |group, *role, id| {
            const component = &key.bound.components[group.component];
            const main = try Outer.geometry.span(component.*, 1);
            const inter = try Outer.geometry.span(component.*, 2);
            const rl = component.trace_log_size;
            const el = component.evaluation_log_size;
            const n = @as(u64, 1) << @intCast(el);
            source_first[id] = sources.items.len;
            for (component.preprocessed_indices) |index| try sources.append(a, .{ .tree = 0, .index = @intCast(index) });
            for (main.start..main.end) |index| try sources.append(a, .{ .tree = 1, .index = @intCast(index) });
            for (inter.start..inter.end) |index| try sources.append(a, .{ .tree = 2, .index = @intCast(index) });
            const columns = sources.items.len - source_first[id];
            const masks = try a.alloc(u32, group.masks.len * 2);
            defer a.free(masks);
            for (group.masks, 0..) |column, i| {
                const offset = @as(u64, column) * n;
                masks[2 * i] = @truncate(offset);
                masks[2 * i + 1] = @truncate(offset >> 32);
            }
            const denominators = try RvAir.geometry.denominatorInverses(a, rl, el);
            defer a.free(denominators);
            const logs = try a.alloc(u32, columns);
            defer a.free(logs);
            @memset(logs, el - 1);
            for (group.slots) |slot| {
                var entry: [16]u32 = @splat(0);
                switch (component.ext_sources[slot]) {
                    .constant => |w| {
                        entry[0] = 0;
                        for (Outer.program.embed(Q.fromU32Unchecked(w[0], w[1], w[2], w[3])).toM31Array(), 0..) |m, j| entry[4 + j] = m.v;
                    },
                    .lookup_z => entry[0] = 1,
                    .lookup_alpha_power => |power| {
                        entry[0] = 2;
                        entry[1] = power;
                    },
                    .lookup_alpha_power_scaled => |x| {
                        entry[0] = 3;
                        entry[1] = x.power;
                        entry[2] = M.fromCanonical(x.scale).v;
                    },
                    .claimed_sum_scaled => {
                        entry[0] = 4;
                        entry[2] = (try M.fromCanonical(@as(u32, 1) << @intCast(rl)).inv()).v;
                        entry[3] = group.component;
                    },
                }
                try params.appendSlice(a, &entry);
            }
            role.* = .{
                .id = @intCast(id),
                .trace_log = rl,
                .eval_log = el,
                .widths = .{ @intCast(component.preprocessed_indices.len), @intCast(main.end - main.start), @intCast(inter.end - inter.start) },
                .sources = &.{},
                .roots = group.roots,
                .masks = try Take.take(&blob, a, masks),
                .mask_count = @intCast(group.masks.len),
                .denominators = try Take.take(&blob, a, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(denominators))),
                .logs = try Take.take(&blob, a, logs),
                .param_count = @intCast(group.slots.len),
                .param_first = param_total,
            };
            param_total += @intCast(group.slots.len);
        }
        source_first[groups.len] = sources.items.len;
        const config = try Outer.protocol.targetConfig();
        const log = key.bound.max_evaluation_log_size;
        const split: u32 = 1;
        var static = Comp.Static{
            .roles = roles,
            .log = log,
            .split = split,
            .total = @intCast(key.bound.total_constraints),
            .beta = config.fri_config.log_blowup_factor,
            .param_total = param_total,
            .param_table = try Take.take(&blob, a, params.items),
            .commit_logs = undefined,
            .fixed = fixed,
            .fixed_offsets = fixed_offsets,
        };
        const commit = try a.alloc(u32, static.outputColumns());
        defer a.free(commit);
        @memset(commit, static.chunkLog());
        static.commit_logs = try Take.take(&blob, a, commit);
        const owned_sources = try sources.toOwnedSlice(a);
        for (roles, 0..) |*role, id| role.sources = owned_sources[source_first[id]..source_first[id + 1]];
        _ = plan;
        const points = try samplePoints(a, key);
        return .{ .static = static, .points = points, .blob = try blob.toOwnedSlice(a), .roles = roles, .sources = owned_sources, .fixed_offsets = fixed_offsets };
    }
};

const Statics = struct {
    public: St.Statics,
    allocator: std.mem.Allocator,
    gather: [Plan.n_components][]u32,
    gathered: []u32,
    rc: ?Rc = null,

    fn init(a: std.mem.Allocator, key: *const Authority, library: *std.DynLib, composition: bool) !*Statics {
        const self = try a.create(Statics);
        errdefer a.destroy(self);
        self.allocator = a;
        var made: usize = 0;
        errdefer for (self.gather[0..made]) |g| a.free(g);
        for (&self.gather, 0..) |*g, c| {
            g.* = try Source.lookupIndices(a, key, c);
            made += 1;
        }
        var pairs: [Plan.n_components]usize = undefined;
        for (&pairs, std.enums.values(circuit.common.component_list.ComponentList)) |*p, kind| p.* = (circuit.witness.trace.RawLookupRows.count(kind) + 1) / 2;
        var geometry = try Plan.Geometry.init(key.logs.toArray(), circuit.witness.trace.traceWidths(), pairs);
        geometry.fixed_logs = &key.fixed_logs;
        for (&geometry.gather, self.gather) |*dst, src| dst.* = src;
        geometry.n_outputs = @intCast(key.pp.n_outputs);
        geometry.beta = (try Outer.protocol.targetConfig()).fri_config.log_blowup_factor;
        geometry.total_constraints = @intCast(key.bound.total_constraints);
        geometry.composition_log = key.bound.max_evaluation_log_size;
        geometry.first_permutation_row = @intCast(key.pp.first_permutation_row);
        const main_logs = try key.treeLogs(a, 1);
        defer a.free(main_logs);
        const inter_logs = try key.treeLogs(a, 2);
        defer a.free(inter_logs);
        var plan = try Plan.ClassPlan.init(a, geometry);
        errdefer plan.deinit(a);
        // The plan's rosters must be the authority's own tree logs.
        if (!std.mem.eql(u32, plan.main.logs, main_logs) or !std.mem.eql(u32, plan.inter.logs, inter_logs)) return error.OuterPlanRosterMismatch;
        if (plan.main.eval_log != plan.inter.eval_log) return error.OuterTreeHeightsDiffer;
        self.gathered = try a.alloc(u32, @intCast(plan.gathered_fixed_words));
        errdefer a.free(self.gathered);
        for (self.gather, plan.gathered_offsets, plan.geometry.components) |indices, offset, c| {
            const rows = @as(usize, 1) << @intCast(c.log);
            for (indices, 0..) |index, k| {
                const values = key.pp.columns[index].values;
                if (values.len != rows) return error.InvalidOuterFixedGather;
                @memcpy(self.gathered[@as(usize, @intCast(offset)) + k * rows ..][0..rows], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(values)));
            }
        }
        self.public = .{ .identity = key.identity, .plan = plan, .gather = undefined, .gathered_fixed = self.gathered, .main_logs = undefined, .inter_logs = undefined };
        for (&self.public.gather, self.gather) |*dst, src| dst.* = src;
        try self.addTable(plan.main.eval_log);
        if (composition) {
            self.rc = try Rc.init(a, key, library, &self.public.plan);
            errdefer self.rc.?.deinit(a);
            self.public.composition = self.rc.?.static;
            self.public.rc_blob = self.rc.?.blob;
            for (self.rc.?.static.roles) |role| try self.addTable(role.eval_log);
            try self.addTable(self.rc.?.static.log);
            try self.addTable(self.rc.?.static.commitLog());
        }
        TC.sortedLogs(&self.public.plan.main, &self.public.main_logs);
        TC.sortedLogs(&self.public.plan.inter, &self.public.inter_logs);
        return self;
    }
    fn addTable(self: *Statics, log: u32) !void {
        if (log >= 29) return error.InvalidOuterTwiddles;
        if (self.public.tables[log] != null) return;
        const tw = try Twiddles.get(log);
        self.public.tables[log] = .{ .twiddles = tw.twiddles, .itwiddles = tw.itwiddles };
    }
    fn destroy(self: *Statics) void {
        const a = self.allocator;
        if (self.rc) |*rc| rc.deinit(a);
        a.free(self.gathered);
        for (self.gather) |g| a.free(g);
        self.public.plan.deinit(a);
        a.destroy(self);
    }
};

/// Eval-height twiddle trees, process lifetime (trace_commit.zig keeps the
/// same trees per context; a profile uses one or two heights).
const Twiddles = struct {
    twiddles: []const u32,
    itwiddles: []const u32,
    var mutex: std.Thread.Mutex = .{};
    var cache: [29]?*Twiddles = @splat(null);
    fn get(log: u32) !*const Twiddles {
        if (log > 28) return error.InvalidOuterTwiddles;
        mutex.lock();
        defer mutex.unlock();
        if (cache[log]) |hit| return hit;
        const a = std.heap.page_allocator;
        const tree = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        const self = try a.create(Twiddles);
        self.* = .{ .twiddles = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.twiddles)), .itwiddles = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)) };
        cache[log] = self;
        return self;
    }
};

/// Fold classes reuse statics; a leaf is its own class and owns its statics.
const StaticsCache = struct {
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayList(*Statics) = .empty;
    const limit = 16;
    fn acquire(key: *const Authority, reusable: bool, library: *std.DynLib, composition: bool) !struct { statics: *Statics, owned: bool } {
        const a = std.heap.c_allocator;
        if (!reusable) return .{ .statics = try Statics.init(a, key, library, composition), .owned = true };
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |s| if (std.mem.eql(u8, &s.public.identity, &key.identity) and (s.rc != null) == composition) return .{ .statics = s, .owned = false };
        const s = try Statics.init(a, key, library, composition);
        if (entries.items.len >= limit) return .{ .statics = s, .owned = true };
        entries.append(a, s) catch return .{ .statics = s, .owned = true };
        return .{ .statics = s, .owned = false };
    }
};

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
    runs: []St.Run,
    expected: []u32,
    staged: St.Staged,
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        const a = self.allocator;
        self.prepared.deinit();
        if (self.owns_statics) self.statics.destroy();
        a.free(self.runs);
        a.free(self.expected);
        a.destroy(self);
    }
};

/// Builds the node's Staged on the calling (pool) thread. The returned
/// pointer is owned by its own `release` (Staged.deinit).
pub fn prestage(a: std.mem.Allocator, input: Input) !*St.Staged {
    const key = input.key;
    try key.requireProverData();
    const graph = input.graph;
    if (!graph.trace_only or !graph.finalized or !graph.record_gates) return error.TraceOnlyGraphRequired;
    if (input.expected.len != key.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
    for (input.expected) |value| for (value.toM31Array()) |m| if (m.v >= core.fields.m31.Modulus) return error.NoncanonicalOm31CircuitOutput;
    const owner = try a.create(Owner);
    errdefer a.destroy(owner);
    owner.allocator = a;
    const previous = Hints.get();
    (Hints{ .class_hint = input.class, .class_is_leaf = input.is_leaf, .seed_tape = input.seed_tape, .blake_sample_inputs = input.blake_sample_inputs }).install();
    owner.prepared = blk: {
        defer previous.install();
        break :blk try Assignment.Prepared.init(a, graph, input.library);
    };
    errdefer owner.prepared.deinit();
    const prepared = &owner.prepared;
    if (prepared.reference != null or prepared.count == 0 or prepared.count > std.math.maxInt(u32) / 4) return error.TraceOnlySourceRequired;
    const acquired = try StaticsCache.acquire(key, !input.is_leaf and input.class != null, input.library, input.composition);
    errdefer if (acquired.owned) acquired.statics.destroy();
    owner.statics = acquired.statics;
    owner.owns_statics = acquired.owned;
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
    var class_key: [32]u8 = undefined;
    {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/m8/outer-job/class/v1\x00");
        h.update(&key.identity);
        h.update(&prepared.identity);
        class_key = h.finalResult();
    }
    owner.staged = .{
        .assignment = assignment,
        .statics = &owner.statics.public,
        .checkpoint = try hostCheckpoint(a, key, input.expected),
        .expected = owner.expected,
        .class_key = class_key,
        .ordinal = input.ordinal,
        .image = St.Staged.layout(&assignment, &owner.statics.public),
        .owner = owner,
        .release = Owner.release,
        .fixed_root = key.fixedRoot(),
        .fixed_logs = &key.fixed_logs,
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
