//! Per-class plan of a GPU-native truth proof (TruthJob), built ONCE per
//! truth class at warm time (rv64-m8-gpu-native.md §3.1, H14/H16-H21 for
//! truths). Everything here is class geometry; nothing depends on a
//! request's values:
//!
//!   witness   the legacy device witness kernel + packet constants
//!             (rv64/truth_source.zig MainJob.run)
//!   FIXED     class-persistent tree (coefficients from the class authority)
//!   MAIN      native_commit plan (evaluation columns: MAIN + keccak tables)
//!   roles     per truth role: interaction plan (truth_interaction.zig) and
//!             composition role spec, each with its parameter gather program
//!             (truth_params.zig) — the challenges/claims are device values
//!   INTER     native_commit plan over the roles' published columns
//!   composition  native_composition plan (truth kernel)
//!   PCS       enqueue-only PcsJob framing at the placeholder OODS point
//!
//! Supported families: classic keccak (both policies) and every delegated v3
//! family the legacy device source supports (sha256, arith256_mod, secp_row,
//! curve). Classic secp is refused (no device source on the legacy path either).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const api = @import("api.zig");
const C = @import("native_commit.zig");
const NC = @import("native_composition.zig");
const NP = @import("native_pcs.zig");
const X = @import("truth_challenges.zig");
const P = @import("truth_params.zig");
const I = @import("truth_interaction.zig");
const T = @import("../truth_codegen.zig");
const Raw = @import("../truth_interaction_codegen.zig");
const Fixtures = @import("../truth_domain_fixtures.zig");
const TO = @import("truth_oods.zig");
const NE = @import("native_encode.zig");

const D = CPU.rv64_device_pcs;
const S = CPU.rv64_gkr_truth_device_source;
const WP = CPU.rv64_gkr_worker_protocol;
const V3 = CPU.rv64_gkr_truth_v3_catalog;
const O = D.O;
const CP = engine.air.component_prover.ForField(O);
pub const Truth = @FieldType(S.Prepare, "truth");
pub const Config = @FieldType(D.Request, "config");

pub const Kind = X.Kind;
pub const PcsColumn = std.meta.Elem(@FieldType(@FieldType(NP.PcsJob, "prepared"), "coefficients"));

/// Device witness kernel family and packet constants.
pub const Witness = union(enum) {
    keccak: struct { policy: u32, chi_log: u32, xor5_log: u32 },
    sha256,
    arith256_mod,
    /// secp_row (kind 0 add / 1 double) and curve (kind = op - 5) share the
    /// packet; `curve` selects stwo_rv64_curve_witness_on.
    secp: struct { kind: u32, curve: bool },
};

pub const Role = struct {
    interaction: I.Plan,
    /// Gather program of the composition role's parameters (claims included).
    composition_program: []P.Entry,
    span: P.Span,
};

pub const FixedColumn = struct { log_size: u32, words: []const u32 };

pub const Class = struct {
    a: std.mem.Allocator,
    key: [32]u8,
    kind: Kind,
    /// The truth authority the class was built from (setup pointers live for
    /// the service): finish rebuilds the legacy components from it.
    truth: Truth,
    truth_tag: u32,
    witness: Witness,
    log: u32,
    main_width: usize,
    compact_words_per_call: usize,
    config: Config,
    beta: u32,
    /// FIXED: class-persistent tree (host coefficients, original order).
    fixed_plan: C.CommitPlan,
    fixed_host: []const []const u32,
    fixed_offsets: []usize,
    fixed_words: usize,
    fixed_key: [32]u8,
    fixed_root: [32]u8,
    fixed_logs: []u32,
    main_plan: C.CommitPlan,
    main_logs: []u32,
    inter_plan: C.CommitPlan,
    inter_logs: []u32,
    roles: []Role,
    /// Claims of the proof (classic 5, delegated 1) and zero-check felts.
    claim_count: u32,
    zero_count: u32,
    composition: NC.Plan,
    comp_log: u32,
    split: u32,
    total: u32,
    mask_log: u32,
    pcs: NP.PcsJob,
    pristine: []PcsColumn,
    /// Device OODS constraint program (gn-truth; truth_oods.zig), built from
    /// class geometry at warm.
    oods: TO.Descriptor,
    /// Device WP.encodePhysical program (native_encode.zig) of the class PCS shape.
    encode: NE.Program,
    owned: std.ArrayListUnmanaged([]u32) = .empty,
    owned_entries: std.ArrayListUnmanaged([]P.Entry) = .empty,

    pub fn deinit(self: *Class) void {
        const a = self.a;
        self.fixed_plan.deinit();
        self.main_plan.deinit();
        self.inter_plan.deinit();
        self.composition.deinit();
        self.oods.deinit();
        self.encode.deinit();
        self.pcs.deinit(a);
        a.free(self.pristine);
        for (self.owned.items) |w| a.free(w);
        self.owned.deinit(a);
        for (self.owned_entries.items) |e| a.free(e);
        self.owned_entries.deinit(a);
        a.free(self.roles);
        a.free(self.fixed_host);
        a.free(self.fixed_offsets);
        a.free(self.fixed_logs);
        a.free(self.main_logs);
        a.free(self.inter_logs);
        self.* = undefined;
    }

    pub fn keccakPolicy(self: *const Class) @TypeOf(@as(T.Role.Component, undefined).keccak_policy) {
        return self.truth.keccak.setup.policy;
    }
    /// Extra status words of a truth proof beyond gpu_native.requiredChecks.
    pub const extra_checks = [_]@import("gpu_native.zig").Check{ .truth_root, .root_match, .truth_oods };
    pub fn localScript(self: *const Class) X.Script {
        return X.local(self.kind);
    }
    pub fn stagedFelts(self: *const Class) u32 {
        return P.stagedFelts(@intCast(self.roles.len));
    }
    pub fn bounds(self: *const Class) P.Bounds {
        return .{ .staged = self.stagedFelts(), .local = self.localScript().felts, .claim = self.claim_count };
    }
    /// Compact input words of a truth with `calls` calls.
    pub fn compactWords(self: *const Class, calls: u32) usize {
        return @as(usize, calls) * self.compact_words_per_call;
    }
    pub fn mainEvalWords(self: *const Class) usize {
        var n: usize = 0;
        for (self.main_logs) |l| n += @as(usize, 1) << @intCast(l);
        return n;
    }
};

fn uniform(a: std.mem.Allocator, n: usize, log: u32) ![]u32 {
    const out = try a.alloc(u32, n);
    @memset(out, log);
    return out;
}

fn words(a: std.mem.Allocator, owned: *std.ArrayListUnmanaged([]u32), n: usize) ![]u32 {
    const out = try a.alloc(u32, n);
    errdefer a.free(out);
    @memset(out, 0);
    try owned.append(a, out);
    return out;
}

/// Compact input words per call (rv64/truth_source.zig compactInputs).
pub fn compactWordsPerCall(truth: Truth) !usize {
    return switch (truth) {
        .keccak => 50,
        .sha256 => 24,
        .arith256_mod => 40,
        .curve => |t| switch (t.setup.op) {
            inline else => |op| A.crypto.curves.Layout(op).PACKET_BYTES / 4,
        },
        .secp_row => |t| if (t.setup.kind == .add) 48 else 24,
        else => error.UnsupportedDeviceTruthFamily,
    };
}

pub fn witnessOf(truth: Truth) !Witness {
    return switch (truth) {
        .keccak => |t| .{ .keccak = .{ .policy = if (t.setup.policy == .triple_v2) 1 else 0, .chi_log = t.setup.policy.tableLog(.chi), .xor5_log = t.setup.policy.tableLog(.xor5) } },
        .sha256 => .sha256,
        .arith256_mod => .arith256_mod,
        .secp_row => |t| .{ .secp = .{ .kind = if (t.setup.kind == .add) 0 else 1, .curve = false } },
        .curve => |t| .{ .secp = .{ .kind = @intFromEnum(t.setup.op) - 5, .curve = true } },
        else => error.UnsupportedDeviceTruthFamily,
    };
}

/// v3 kernel id (truth_source.zig / truth_codegen): sha 3, arith 4, secp_row 5/6, curve 10..14.
pub fn delegatedId(truth: Truth) !u32 {
    return switch (truth) {
        .sha256 => 3,
        .arith256_mod => 4,
        .secp_row => |t| if (t.setup.kind == .add) 5 else 6,
        .curve => |t| try T.curveKernelId(t.setup.op),
        else => error.UnsupportedDeviceTruthFamily,
    };
}

/// Class key: family, span-free geometry, config, FIXED identity. Calls and
/// first id are request values (the staged span), never class geometry.
///
/// Every field is framed explicitly as a little-endian u64: hashing the raw
/// bytes of `Witness` (a tagged union: a payload-free tag leaves its payload
/// bytes undefined) or of `Config` (struct padding, a null `?u32` payload)
/// made the key depend on uninitialised memory, so the same class could get
/// two keys (a warmed class reported as not warmed, or warmed twice).
pub fn classKey(truth: Truth, config: Config, fixed_root: [32]u8) ![32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gpu-truth-class/v2\x00");
    h.update(@tagName(std.meta.activeTag(truth)));
    h.update(&[_]u8{0});
    const Frame = struct {
        fn u(hasher: *std.crypto.hash.sha2.Sha256, v: u64) void {
            var w: [8]u8 = undefined;
            std.mem.writeInt(u64, &w, v, .little);
            hasher.update(&w);
        }
    };
    switch (try witnessOf(truth)) {
        .keccak => |k| {
            Frame.u(&h, 0);
            Frame.u(&h, k.policy);
            Frame.u(&h, k.chi_log);
            Frame.u(&h, k.xor5_log);
        },
        .sha256 => Frame.u(&h, 1),
        .arith256_mod => Frame.u(&h, 2),
        .secp => |s| {
            Frame.u(&h, 3);
            Frame.u(&h, s.kind);
            Frame.u(&h, @intFromBool(s.curve));
        },
    }
    Frame.u(&h, try truthLog(truth));
    Frame.u(&h, config.pow_bits);
    Frame.u(&h, config.fri_config.log_blowup_factor);
    Frame.u(&h, config.fri_config.log_last_layer_degree_bound);
    Frame.u(&h, config.fri_config.n_queries);
    Frame.u(&h, config.fri_config.fold_step);
    if (config.lifting_log_size) |l| {
        Frame.u(&h, 1);
        Frame.u(&h, l);
    } else Frame.u(&h, 0);
    h.update(&fixed_root);
    return h.finalResult();
}

/// `truth` with a request's span (calls, first id). A class is span-free
/// (classKey), so the authority it was built from carries the FIRST
/// request's span; everything that evaluates the request's statement (the
/// delegated component's metadata: count, first id, active flag) must use
/// the request's span instead.
pub fn withSpan(truth: Truth, calls: u32, first_id: u32) Truth {
    var t = truth;
    switch (t) {
        inline else => |*p| {
            p.calls = calls;
            p.first_id = first_id;
        },
    }
    return t;
}

pub fn truthLog(truth: Truth) !u32 {
    return if (truth == .keccak) truth.keccak.setup.log else try V3.logSize(truth);
}

pub const Init = struct {
    truth: Truth,
    config: Config,
    /// FIXED coefficient columns of the truth's authority tree (original order).
    fixed: []const FixedColumn,
    fixed_root: [32]u8,
    psym: NP.Symbols,
    wide_framing: bool,
};

/// Build the class plan. Host only (no device work); the device regions are
/// filled by the first job of the class on each worker (Stager.persistent).
pub fn build(a: std.mem.Allocator, in: Init) !*Class {
    const truth = in.truth;
    const self = try a.create(Class);
    errdefer a.destroy(self);
    const kind: Kind = switch (truth) {
        .keccak => .classic,
        .sha256, .arith256_mod, .secp_row, .curve => .delegated,
        else => return error.UnsupportedDeviceTruthFamily,
    };
    const beta = in.config.fri_config.log_blowup_factor;
    const log = try truthLog(truth);
    var owned: std.ArrayListUnmanaged([]u32) = .empty;
    errdefer {
        for (owned.items) |w| a.free(w);
        owned.deinit(a);
    }
    var owned_entries: std.ArrayListUnmanaged([]P.Entry) = .empty;
    errdefer {
        for (owned_entries.items) |e| a.free(e);
        owned_entries.deinit(a);
    }
    // --- tree logs, checked against the truth authority ---
    const fixed_logs = try truth.logs(a, 0);
    errdefer a.free(fixed_logs);
    const main_logs = try truth.logs(a, 1);
    errdefer a.free(main_logs);
    if (in.fixed.len != fixed_logs.len) return error.TruthClassFixedShape;
    for (in.fixed, fixed_logs) |c, l| if (c.log_size != l or c.words.len != @as(usize, 1) << @intCast(l)) return error.TruthClassFixedShape;
    const main_width: usize = if (kind == .classic) A.crypto.keccak.layout.MAIN else (try V3.shape(truth)).main;
    const extra: usize = if (kind == .classic) 2 else 0;
    if (main_logs.len != main_width + extra) return error.TruthClassMainShape;
    // --- FIXED (persistent, coefficients) ---
    const fixed_shapes = try a.alloc(C.Shape, fixed_logs.len);
    defer a.free(fixed_shapes);
    for (fixed_shapes, fixed_logs) |*s, l| s.* = .{ .log_size = l, .encoding = .coefficients };
    var fixed_plan = try C.CommitPlan.init(a, fixed_shapes, beta);
    errdefer fixed_plan.deinit();
    const fixed_host = try a.alloc([]const u32, in.fixed.len);
    errdefer a.free(fixed_host);
    const fixed_offsets = try a.alloc(usize, in.fixed.len);
    errdefer a.free(fixed_offsets);
    var fixed_words: usize = 0;
    for (in.fixed, fixed_host) |c, *h| {
        h.* = c.words;
        fixed_words += c.words.len;
    }
    // The persistent FIXED region IS the commit plan's coefficient image (ORIGINAL view by offsets).
    @memcpy(fixed_offsets, fixed_plan.offsets);
    var fixed_key: [32]u8 = undefined;
    {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gpu-truth-fixed/v1\x00");
        h.update(&in.fixed_root);
        h.update(std.mem.asBytes(&beta));
        h.update(std.mem.sliceAsBytes(fixed_logs));
        fixed_key = h.finalResult();
    }
    // --- MAIN (evaluations) ---
    const main_shapes = try a.alloc(C.Shape, main_logs.len);
    defer a.free(main_shapes);
    for (main_shapes, main_logs) |*s, l| s.* = .{ .log_size = l, .encoding = .evaluations };
    var main_plan = try C.CommitPlan.init(a, main_shapes, beta);
    errdefer main_plan.deinit();
    // --- roles: legacy component geometry (truth_components.Components.init / truth_v3_worker) ---
    const zero_local = std.mem.zeroes(X.Classic);
    const zero_shared = std.mem.zeroes(X.Shared);
    var classic: [3]T.Role.Component = undefined;
    var delegated: T.V3Role.Component = undefined;
    const n_roles: usize = if (kind == .classic) 3 else 1;
    const roles = try a.alloc(Role, n_roles);
    errdefer a.free(roles);
    var inter_widths: usize = 0;
    var specs: [3]NC.RoleSpec = undefined;
    var claim_count: u32 = 0;
    var zero_count: u32 = 0;
    if (kind == .classic) {
        const policy = truth.keccak.setup.policy;
        const kinds = [3]T.Role.Kind{ .keccak, .chi, .xor5 };
        var offsets: [3]usize = .{ 0, 0, 0 };
        for (&classic, kinds, 0..) |*c, k, i| {
            const crypto = k == .keccak;
            c.* = .{ .kind = k, .log_size = if (i == 0) log else policy.tableLog(if (i == 1) .chi else .xor5), .calls = if (crypto) truth.count() else 0, .first_id = if (crypto) truth.first() else 1, .keccak_policy = policy, .local = zero_local, .shared = zero_shared, .claim = O.zero(), .global_claim = O.zero(), .split = 2 };
            c.offsets = offsets;
            try c.validate();
            for (c.widths(), 0..) |w, t| offsets[t] += w;
        }
        claim_count = 5;
        for (&classic, roles, 0..) |*c, *role, i| {
            const id = try T.classicKernelId(policy, c.kind);
            var raw = try Raw.record(a, id);
            defer raw.deinit();
            const widths = c.widths();
            const program = try P.program(a, .{ .classic = .{ .index = @intCast(i), .claims = false } }, raw.parameter_slots);
            try owned_entries.append(a, program);
            const launch = undefinedLaunch;
            role.* = .{ .interaction = try I.Plan.init(.{ .id = id, .log = c.log_size, .fixed_count = widths[0], .main_count = widths[1], .fixed_first = c.offsets[0], .main_first = c.offsets[1], .groups = raw.groups, .layout = .inverse_prefix, .targets = if (i == 0) .{ .{ .claim = 0 }, .{ .claim = 3 } } else .{ .{ .claim = @intCast(i) }, .{ .claim = @intCast(i) } }, .program = program, .launch = launch }), .composition_program = undefined, .span = .{ .calls = c.calls, .first_id = c.first_id } };
            if ((raw.groups[1] != 0) != (i == 0)) return error.TruthClassInteractionShape;
            inter_widths += role.interaction.width();
            if (role.interaction.width() != widths[2]) return error.TruthClassInteractionShape;
            // Composition role (truth_domain_fixtures: the same artifacts resident_composition loads).
            var rec = try Fixtures.record(a, id);
            defer rec.artifact.deinit();
            if (rec.artifact.program.roots.len != c.nConstraints()) return error.WrongResidentConstraintCount;
            const cprog = try P.program(a, .{ .classic = .{ .index = @intCast(i), .claims = true } }, rec.artifact.parameter_slots);
            try owned_entries.append(a, cprog);
            role.composition_program = cprog;
            const masks = try words(a, &owned, rec.artifact.program.inputs.len);
            for (rec.artifact.program.inputs, masks) |input, *m| m.* = input.column;
            specs[i] = .{ .id = id, .kernel = .truth, .trace_log = c.log_size, .eval_log = c.maxConstraintLogDegreeBound(), .widths = .{ @intCast(widths[0]), @intCast(widths[1]), @intCast(widths[2]) }, .offsets = .{ @intCast(c.offsets[0]), @intCast(c.offsets[1]), @intCast(c.offsets[2]) }, .aux = .last, .parameters = try words(a, &owned, rec.artifact.parameter_slots.len * 8), .mask_columns = masks, .constraints = @intCast(c.nConstraints()) };
        }
    } else {
        delegated = .{ .truth = truth, .wire = zero_shared.wire, .bytes = O.zero(), .claim = O.zero() };
        const shape = delegated.mainShape();
        const id = try delegatedId(truth);
        var raw = try Raw.record(a, id);
        defer raw.deinit();
        claim_count = 1;
        const two = raw.groups[1] != 0;
        zero_count = @intFromBool(two);
        const program = try P.program(a, .{ .delegated = .{ .claims = false } }, raw.parameter_slots);
        try owned_entries.append(a, program);
        roles[0] = .{ .interaction = try I.Plan.init(.{ .id = id, .log = log, .fixed_count = shape.fixed, .main_count = shape.main, .fixed_first = 0, .main_first = 0, .groups = raw.groups, .layout = .cumulative_batches, .targets = if (two) .{ .{ .zero_check = 0 }, .{ .claim = 0 } } else .{ .{ .claim = 0 }, .{ .claim = 0 } }, .program = program, .launch = undefinedLaunch }), .composition_program = undefined, .span = .{ .calls = truth.count(), .first_id = truth.first() } };
        inter_widths = roles[0].interaction.width();
        if (inter_widths != delegated.interWidth()) return error.TruthClassInteractionShape;
        var rec = try Fixtures.record(a, id);
        defer rec.artifact.deinit();
        if (rec.artifact.program.roots.len != delegated.nConstraints()) return error.WrongResidentConstraintCount;
        const cprog = try P.program(a, .{ .delegated = .{ .claims = true } }, rec.artifact.parameter_slots);
        try owned_entries.append(a, cprog);
        roles[0].composition_program = cprog;
        const masks = try words(a, &owned, rec.artifact.program.inputs.len);
        for (rec.artifact.program.inputs, masks) |input, *m| m.* = input.column;
        specs[0] = .{ .id = id, .kernel = .truth, .trace_log = log, .eval_log = delegated.maxConstraintLogDegreeBound(), .widths = .{ @intCast(shape.fixed), @intCast(shape.main), @intCast(delegated.interWidth()) }, .offsets = .{ @intCast(delegated.offsets[0]), @intCast(delegated.offsets[1]), @intCast(delegated.inter_offset) }, .aux = .none, .parameters = try words(a, &owned, rec.artifact.parameter_slots.len * 8), .mask_columns = masks, .constraints = @intCast(delegated.nConstraints()) };
    }
    // --- INTER (evaluations; roles' published columns in order) ---
    const inter_logs = try a.alloc(u32, inter_widths);
    errdefer a.free(inter_logs);
    {
        var at: usize = 0;
        for (roles) |r| {
            @memset(inter_logs[at..][0..r.interaction.width()], r.interaction.log);
            at += r.interaction.width();
        }
    }
    const inter_shapes = try a.alloc(C.Shape, inter_logs.len);
    defer a.free(inter_shapes);
    for (inter_shapes, inter_logs) |*s, l| s.* = .{ .log_size = l, .encoding = .evaluations };
    var inter_plan = try C.CommitPlan.init(a, inter_shapes, beta);
    errdefer inter_plan.deinit();
    // --- composition + PCS framing from the legacy prover components ---
    var handles: [3]CP.ComponentProver = undefined;
    const provers_slice: []const CP.ComponentProver = if (kind == .classic) blk: {
        for (&classic, 0..) |*c, i| handles[i] = c.asProverComponent();
        break :blk handles[0..3];
    } else blk: {
        handles[0] = delegated.asProverComponent();
        break :blk handles[0..1];
    };
    const provers = CP.ComponentProvers{ .components = provers_slice, .n_preprocessed_columns = fixed_logs.len };
    const comp_log: u32 = @intCast(provers.compositionLogDegreeBound());
    const split: u32 = @intCast(try provers.compositionLogSplit());
    const total: u32 = @intCast(provers.totalConstraints());
    const mask_log: u32 = @intCast(core.verifier_types.compositionMaskLogSize(comp_log, split) orelse return error.InvalidStructure);
    var composition = try NC.Plan.init(a, .{ .roles = specs[0..n_roles], .log = comp_log, .split = split, .total = total, .beta = beta, .tree_logs = .{ fixed_logs, main_logs, inter_logs } });
    errdefer composition.deinit();
    try composition.detach();
    const placeholder = try NP.placeholderPoint();
    var view = try provers.componentsView(a);
    defer view.deinit(a);
    var points = try view.maskPointsWithWorkCapture(a, placeholder, mask_log, false, null);
    defer points.deinitDeep(a);
    const n_comp = core.verifier_types.compositionColumnCount(split, 8) orelse return error.InvalidStructure;
    if (n_comp != composition.outputColumns() or points.items.len != 3) return error.TruthClassCompositionShape;
    const comp_tree = try a.alloc([]D.Point, n_comp);
    var comp_made: usize = 0;
    defer {
        for (comp_tree[0..comp_made]) |c| a.free(c);
        a.free(comp_tree);
    }
    for (comp_tree) |*c| {
        c.* = try a.alloc(D.Point, 1);
        c.*[0] = placeholder;
        comp_made += 1;
    }
    var tree_points = [4][][]D.Point{ points.items[0], points.items[1], points.items[2], comp_tree };
    var tree_columns: [4][]D.Column = undefined;
    var made_trees: usize = 0;
    defer for (tree_columns[0..made_trees]) |t| a.free(t);
    const tree_logs = [4][]const u32{ fixed_logs, main_logs, inter_logs, &.{} };
    for (0..4) |t| {
        const count = if (t == 3) n_comp else tree_logs[t].len;
        tree_columns[t] = try a.alloc(D.Column, count);
        made_trees += 1;
        for (tree_columns[t], 0..) |*c, i| c.* = NP.placeholderColumn(if (t == 3) composition.chunkLog() else tree_logs[t][i]);
    }
    // Roots are never compared by the imported-OODS PCS (pcs_enqueue.cu: the
    // transcript authenticates them); the class framing carries zeros.
    const trees = [4]D.Tree{
        .{ .root = in.fixed_root, .columns = tree_columns[0] },
        .{ .root = @splat(0), .columns = tree_columns[1] },
        .{ .root = @splat(0), .columns = tree_columns[2] },
        .{ .root = @splat(0), .columns = tree_columns[3] },
    };
    const request = D.Request{ .scope = null, .config = in.config, .lifting_log_size = composition.chunkLog() + beta, .trees = &trees, .points = .{ .items = &tree_points } };
    var pcs = try NP.PcsJob.prepare(a, in.psym, request, placeholder, in.wide_framing);
    errdefer pcs.deinit(a);
    const pristine = try a.dupe(PcsColumn, pcs.prepared.coefficients);
    errdefer a.free(pristine);
    var oods = try TO.fromGeometry(a, .{ .kind = kind, .truth = truth, .log = log, .roles = roles, .mask_log = mask_log, .split = split, .shape = pcs.prepared.metadata.shape });
    errdefer oods.deinit();
    var encode = try NE.Program.build(a, pcs.prepared.metadata.shape);
    errdefer encode.deinit();
    self.* = .{ .a = a, .key = try classKey(truth, in.config, in.fixed_root), .kind = kind, .truth = truth, .truth_tag = @intFromEnum(std.meta.activeTag(truth)), .witness = try witnessOf(truth), .log = log, .main_width = main_width, .compact_words_per_call = try compactWordsPerCall(truth), .config = in.config, .beta = beta, .fixed_plan = fixed_plan, .fixed_host = fixed_host, .fixed_offsets = fixed_offsets, .fixed_words = fixed_words, .fixed_key = fixed_key, .fixed_root = in.fixed_root, .fixed_logs = fixed_logs, .main_plan = main_plan, .main_logs = main_logs, .inter_plan = inter_plan, .inter_logs = inter_logs, .roles = roles, .claim_count = claim_count, .zero_count = zero_count, .composition = composition, .comp_log = comp_log, .split = split, .total = total, .mask_log = mask_log, .pcs = pcs, .pristine = pristine, .oods = oods, .encode = encode, .owned = owned, .owned_entries = owned_entries };
    return self;
}

/// Launch placeholder until `bindLaunches` resolves the AOT projections from
/// the loaded base image (class geometry is image independent).
fn undefinedLaunch(_: *anyopaque, _: u32, _: [*]const u32, _: [*]const u32, _: [*]const u32, _: [*]u32, _: [*]u32, _: [*]u32, _: u32) callconv(.c) c_int {
    return 1; // fail closed: an unbound projection never runs
}

/// Resolve every role's AOT projection symbol in `base` (warm time).
pub fn bindLaunches(self: *Class, a: std.mem.Allocator, base: *std.DynLib) !void {
    for (self.roles) |*r| {
        const name = try Raw.name(a, r.interaction.id);
        defer a.free(name);
        const z = try a.dupeZ(u8, name);
        defer a.free(z);
        r.interaction.launch = base.lookup(I.Launch, z) orelse return error.MissingTruthProjectionSymbol;
    }
}

/// A per-job PcsJob over the class framing (rv64/jobs/outer_job.zig
/// clonePcs): the sections stay the class's, only the column table is owned.
pub fn clonePcs(a: std.mem.Allocator, self: *const Class) !NP.PcsJob {
    var job = self.pcs;
    job.prepared.coefficients = try a.dupe(PcsColumn, self.pristine);
    job.prepared.section_owned = @splat(false);
    job.prepared.owns_metadata = false;
    job.prepared.geometry = null;
    job.descriptor = job.prepared.descriptor();
    return job;
}

/// A per-job copy of a class commit plan: `stage` writes the staged buffers
/// and the host-offset table, so concurrent jobs never share them.
pub fn jobPlan(a: std.mem.Allocator, plan: *const C.CommitPlan) !C.CommitPlan {
    return C.jobCopy(a, plan);
}
pub fn freeJobPlan(a: std.mem.Allocator, plan: *C.CommitPlan) void {
    C.freeJobCopy(a, plan);
}

/// The stage-2 channel seed of a truth (host, per request, a few Blake2s):
/// worker_protocol.begin(config, expected) [+ the fixed-authority binding
/// framing]. The FIXED root (appendFixed) and the MAIN root are mixed on
/// device from the device trees (root_match checks the FIXED root against
/// the class authority).
pub const Binding = struct { identity: [32]u8, root: [32]u8, profile: ?WP.Candidate.Profile };
pub const binding_profile_tag = "rv64-OM-localGKR-classicTruth-beta2-engineering/v1\x00";
pub fn seed(config: WP.PcsConfig, expected: CPU.rv64_gkr_manifest.ExpectedWorker, binding: ?Binding) [9]u32 {
    var ch = WP.begin(config, expected);
    if (binding) |b| {
        // fixed_authority.emitBindingBegin.
        var tag: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(binding_profile_tag, &tag, .{});
        WP.digest(&ch, tag);
        WP.digest(&ch, b.identity);
        WP.digest(&ch, b.root);
        if (b.profile) |p| if (p.conjectured()) WP.digest(&ch, WP.Candidate.profileIdentity(p));
    }
    var out: [9]u32 = undefined;
    for (out[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, ch.inner.digest[i * 4 ..][0..4], .little);
    out[8] = ch.inner.n_draws;
    return out;
}

/// fixed_setup.coefficientIdentity (the binding's fixed identity).
pub fn fixedIdentity(columns: []const FixedColumn, log_blowup: u32) ![32]u8 {
    if (columns.len == 0) return error.EmptyFixedSetup;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-immutable-M31-prefixed-Blake-fixed-setup/v1\x00");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, log_blowup, .little);
    h.update(&word);
    std.mem.writeInt(u64, &word, columns.len, .little);
    h.update(&word);
    for (columns) |c| {
        if (c.log_size > 28 or c.words.len != @as(usize, 1) << @intCast(c.log_size)) return error.InvalidFixedSetupCoefficientShape;
        std.mem.writeInt(u64, &word, c.log_size, .little);
        h.update(&word);
        h.update(std.mem.sliceAsBytes(c.words));
    }
    return h.finalResult();
}

// ---------------------------------------------------------------------------
// Compact inputs (host packing of the captured advice; rv64/truth_source.zig
// compactInputs, byte for byte).
// ---------------------------------------------------------------------------
pub const Advice = @typeInfo(@FieldType(S.Prepare, "advice")).pointer.child;

pub fn packCompact(a: std.mem.Allocator, truth: Truth, advice: *const Advice) ![]u32 {
    const per = try compactWordsPerCall(truth);
    const output = try a.alloc(u32, try std.math.mul(usize, truth.count(), per));
    errdefer a.free(output);
    if (truth.first() == 0) return error.InvalidDeviceTruthSpan;
    const begin: usize = truth.first() - 1;
    const end = begin + truth.count();
    var offset: usize = 0;
    var written: usize = 0;
    const Put = struct {
        fn state(out: []u32, at: usize, per_call: usize, values: anytype) void {
            for (values, 0..) |value, i| {
                out[at * per_call + 2 * i] = @truncate(value);
                out[at * per_call + 2 * i + 1] = @truncate(value >> 32);
            }
        }
    };
    switch (truth) {
        .keccak => {
            for (advice.keccak) |chunk| for (chunk) |call| {
                if (offset >= begin and offset < end) {
                    Put.state(output, written, per, call.before);
                    written += 1;
                }
                offset += 1;
            };
            for (advice.sponge) |chunk| for (chunk.inputs) |s| {
                if (offset >= begin and offset < end) {
                    Put.state(output, written, per, s);
                    written += 1;
                }
                offset += 1;
            };
        },
        .sha256, .arith256_mod => {
            const chunks = if (truth == .sha256) advice.sha256 else advice.arith256_mod;
            for (chunks) |chunk| for (chunk) |call| {
                if (offset >= begin and offset < end) {
                    Put.state(output, written, per, call.before[0 .. per / 2]);
                    written += 1;
                }
                offset += 1;
            };
        },
        .curve => |t| {
            const index = @intFromEnum(t.setup.op) - 5;
            for (advice.curves) |chunk| for (chunk[index]) |call| {
                if (offset >= begin and offset < end) {
                    Put.state(output, written, per, call.before[0 .. per / 2]);
                    written += 1;
                }
                offset += 1;
            };
        },
        .secp_row => |t| {
            const k: usize = if (t.setup.kind == .add) 0 else 1;
            for (advice.secp) |chunk| for (chunk[k]) |call| {
                if (offset >= begin and offset < end) {
                    Put.state(output, written, per, call.before[0 .. per / 2]);
                    written += 1;
                }
                offset += 1;
            };
        },
        else => return error.UnsupportedDeviceTruthFamily,
    }
    if (written != truth.count()) return error.InvalidDeviceTruthSpan;
    return output;
}

test "truth class is fully analyzed" {
    _ = &build;
    _ = &bindLaunches;
    _ = &clonePcs;
    _ = &packCompact;
}

test "stage-2 seed equals worker_protocol.begin without a binding" {
    const config = WP.PcsConfig.default();
    var expected: CPU.rv64_gkr_manifest.ExpectedWorker = undefined;
    expected.kind = .keccak;
    expected.ordinal = 7;
    expected.statement = @splat(3);
    expected.fixed = @splat(9);
    const got = seed(config, expected, null);
    const ch = WP.begin(config, expected);
    try std.testing.expectEqual(ch.inner.n_draws, got[8]);
    for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, ch.inner.digest[i * 4 ..][0..4], .little), got[i]);
    // The binding framing changes the seed (and only with a binding).
    const bound = seed(config, expected, .{ .identity = @splat(1), .root = @splat(2), .profile = null });
    try std.testing.expect(!std.mem.eql(u32, &got, &bound));
}

test "fixed identity framing matches fixed_setup.coefficientIdentity's layout" {
    const col = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const id = try fixedIdentity(&.{.{ .log_size = 3, .words = &col }}, 2);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-immutable-M31-prefixed-Blake-fixed-setup/v1\x00");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, 2, .little);
    h.update(&word);
    std.mem.writeInt(u64, &word, 1, .little);
    h.update(&word);
    std.mem.writeInt(u64, &word, 3, .little);
    h.update(&word);
    h.update(std.mem.sliceAsBytes(&col));
    try std.testing.expectEqualSlices(u8, &h.finalResult(), &id);
    try std.testing.expectError(error.InvalidFixedSetupCoefficientShape, fixedIdentity(&.{.{ .log_size = 4, .words = &col }}, 2));
}

test "class key frames fields, not memory: padding and inactive payload bytes never change it" {
    const ShaSetup = @typeInfo(@FieldType(@FieldType(Truth, "sha256"), "setup")).pointer.child;
    var setup: ShaSetup = undefined;
    setup.log = 7;
    const truth = Truth{ .sha256 = .{ .setup = &setup, .first_id = 1, .calls = 3 } };
    var configs: [2]Config = undefined;
    for (&configs, [_]u8{ 0x00, 0xff }) |*c, fill| {
        @memset(std.mem.asBytes(c), fill); // padding + the null optional's payload
        c.pow_bits = 20;
        c.fri_config.log_blowup_factor = 2;
        c.fri_config.log_last_layer_degree_bound = 0;
        c.fri_config.n_queries = 70;
        c.fri_config.fold_step = 1;
        c.lifting_log_size = null;
    }
    const root: [32]u8 = @splat(5);
    const k0 = try classKey(truth, configs[0], root);
    try std.testing.expectEqualSlices(u8, &k0, &try classKey(truth, configs[1], root));
    // Span-free: a request span never changes the class.
    try std.testing.expectEqualSlices(u8, &k0, &try classKey(withSpan(truth, 9, 40), configs[0], root));
    // Every framed field does.
    var other = configs[0];
    other.lifting_log_size = 0;
    try std.testing.expect(!std.mem.eql(u8, &k0, &try classKey(truth, other, root)));
    other = configs[0];
    other.fri_config.n_queries = 71;
    try std.testing.expect(!std.mem.eql(u8, &k0, &try classKey(truth, other, root)));
    setup.log = 8;
    try std.testing.expect(!std.mem.eql(u8, &k0, &try classKey(truth, configs[0], root)));
}

test "withSpan replaces only the span" {
    const ShaSetup = @typeInfo(@FieldType(@FieldType(Truth, "sha256"), "setup")).pointer.child;
    var setup: ShaSetup = undefined;
    const truth = Truth{ .sha256 = .{ .setup = &setup, .first_id = 1, .calls = 3 } };
    const t = withSpan(truth, 11, 4);
    try std.testing.expectEqual(@as(u32, 11), t.count());
    try std.testing.expectEqual(@as(u32, 4), t.first());
    try std.testing.expectEqual(@intFromPtr(&setup), @intFromPtr(t.sha256.setup));
    try std.testing.expectEqual(@as(u32, 3), truth.count());
}
