//! Independent benchmark-only single ordinary CPU-shard control. It uses the
//! original FIXED/MAIN and all local/RAM obligations, without a GKR manifest.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const G = @import("../../../../word16_execution/geometry.zig");
const R = @import("../../roster.zig");
const P = @import("../../protocol.zig");
const W = @import("../../gkr_local/worker_protocol.zig");
const Global = @import("../../gkr_local/global_cpu.zig");
const GM = @import("../../gkr_local/global_metadata.zig");
const Manifest = @import("../../gkr_local/manifest.zig");
const NativeProvider = @import("../../gkr_local/native_provider.zig").Provider;
const Frame = @import("../../gkr_local/frame.zig");
const RowSink = @import("../../gkr_local/inputs.zig").RowSink;
const Classic = @import("../../gkr_local/classic_witness.zig");
const Ch = @import("../../gkr_local/challenges.zig").For(O);
const Policy = @import("policy.zig");
const Comp = @import("component.zig");
pub const PROFILE = "RV64-BENCHMARK-OM31-CLASSIC-LOCAL-CPU0/v1\x00";
pub const Slot = struct { role: G.Role, log: u32, fixed: usize, fixed_offset: usize, main_offset: usize, inter_offset: usize, local_claim: ?usize, ram_claim: ?usize };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    slots: []Slot,
    inter_columns: usize,
    local_claims: usize,
    ram_claims: usize,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup) !Plan {
        if (setup.bridges.keccak != null or setup.bridges.add != null or setup.bridges.double != null) return error.ClassicControlServicesUnsupported;
        var slots = std.ArrayList(Slot).empty;
        errdefer slots.deinit(a);
        var inter: usize = 0;
        var locals: usize = 0;
        var ram: usize = 0;
        for (setup.materials.shapes()) |s| {
            if (!s.present()) continue;
            const p = Policy.forRole(s.role);
            const gl = Global.layout(.{ .core = s.role });
            try slots.append(a, .{ .role = s.role, .log = s.log, .fixed = s.widths[0], .fixed_offset = s.offsets[0], .main_offset = s.offsets[1], .inter_offset = inter, .local_claim = if (p.terms != 0) locals else null, .ram_claim = if (gl.ram_queries != 0) ram else null });
            inter += p.width() + gl.width();
            locals += @intFromBool(p.terms != 0);
            ram += @intFromBool(gl.ram_queries != 0);
        }
        return .{ .allocator = a, .slots = try slots.toOwnedSlice(a), .inter_columns = inter, .local_claims = locals, .ram_claims = ram };
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn interLogs(self: *const Plan, a: std.mem.Allocator) ![]u32 {
        const out = try a.alloc(u32, self.inter_columns);
        for (self.slots) |s| @memset(out[s.inter_offset..][0 .. Policy.forRole(s.role).width() + Global.layout(.{ .core = s.role }).width()], s.log);
        return out;
    }
};
pub const Encoded = struct {
    bytes: []u8,
    local_claims: []O,
    ram_claims: []O,
    main_root: [32]u8,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.local_claims);
        a.free(self.ram_claims);
        self.* = undefined;
    }
};
pub const Timing = struct { main_commit_ns: u64 = 0, interaction_ns: u64 = 0, inter_commit_and_prove_ns: u64 = 0 };
fn validate(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: P.Expected, config: W.PcsConfig) !void {
    try W.validateConfig(config);
    if (request.calls[0] != 0 or request.calls[1] != 0 or request.calls[2] != 0) return error.ClassicControlServicesUnsupported;
    _ = try P.admit(a, &.{setup}, &.{}, &.{request}, expected);
}
fn statement(setup: *const R.CpuSetup, r: P.Request, c: W.PcsConfig) [32]u8 {
    return @import("../../gkr_local/cpu_worker.zig").cpuStatement(setup, r, .{ 1, 1, 1 }, c);
}
fn begin(setup: *const R.CpuSetup, r: P.Request, c: W.PcsConfig) W.Channel {
    var ch = W.Channel.init();
    c.mixInto(&ch);
    var tag: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(PROFILE, &tag, .{});
    W.digest(&ch, tag);
    W.digest(&ch, statement(setup, r, c));
    return ch;
}
fn draw(setup: *const R.CpuSetup, r: P.Request, c: W.PcsConfig, main: [32]u8, instances: []const Frame.Instance) struct { local: Ch, shared: Manifest.Shared } {
    var ch = @import("../../gkr_local/child.zig").begin(.{ .statement = statement(setup, r, c), .fixed = setup.key.root, .main = main, .ordinal = 0 }, instances);
    const local = Ch.draw(&ch);
    // Independent control-specific global draw, after the physical roots.
    var global = W.Channel.init();
    var tag: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(PROFILE, &tag, .{});
    W.digest(&global, tag);
    W.digest(&global, statement(setup, r, c));
    W.digest(&global, setup.key.root);
    W.digest(&global, main);
    var ram: A.memory.closed_ram.types.RamChallengesFor(O) = undefined;
    ram.offset = global.drawSecureFelt();
    for (&ram.coefficients) |*v| v.* = global.drawSecureFelt();
    return .{ .local = local, .shared = .{ .ram = ram, .kio = A.crypto.keccak.equations.IoFor(O).draw(&global), .wire = A.crypto.secp256k1.equations.WireFor(O).draw(&global) } };
}
fn mix(ch: *W.Channel, local: []const O, ram: []const O) void {
    ch.mixU32s(&.{ 0x434c4c31, @intCast(local.len), @intCast(ram.len) });
    ch.mixFelts(local);
    ch.mixFelts(ram);
}
fn checkClaims(r: P.Request, plan: *const Plan, shared: Manifest.Shared, local: []const O, ram: []const O) !void {
    if (local.len != plan.local_claims or ram.len != plan.ram_claims) return error.ClassicControlClaimShape;
    var l = O.zero();
    for (local) |v| {
        for (v.toM31Array()) |x| if (x.v >= core.fields.m31.Modulus) return error.NoncanonicalClassicControlClaim;
        l = l.add(v);
    }
    if (!l.isZero()) return error.UnclosedClassicControlLocal;
    var sum = O.zero();
    for (ram) |v| {
        for (v.toM31Array()) |x| if (x.v >= core.fields.m31.Modulus) return error.NoncanonicalClassicControlClaim;
        sum = sum.add(v);
    }
    if (!sum.isZero()) return error.UnclosedClassicControlRam;
    for (plan.slots) |s| if (s.role == .initial or s.role == .terminal) {
        const value = try @import("../../gkr_local/expected_boundary.zig").claim(if (s.role == .initial) r.base.memory.initial else r.base.memory.terminal, s.role == .initial, shared.ram);
        if (!ram[s.ram_claim.?].eql(value)) return error.ClassicControlPublicRamMismatch;
    };
}
pub const LocalProvider = struct {
    pub const PARALLEL_SAFE = true;
    source: *const R.Sources,
    instance: Frame.Instance,
    challenges: *const Ch,
    pub fn fill(self: @This(), logical: usize, d: []O, n: []Classic.Numerator) !void {
        const p = Policy.forRole(self.instance.origin.core);
        if (d.len != p.group_count or n.len != p.group_count) return error.ClassicControlFractionShape;
        var weights: [Policy.MAX_TERMS]M = undefined;
        var denominators: [Policy.MAX_TERMS]O = undefined;
        var sink = RowSink{ .challenges = self.challenges, .numerator = weights[0..p.terms], .denominator = denominators[0..p.terms] };
        try (NativeProvider{ .source = self.source }).emit(self.instance, logical, &sink);
        if (sink.invalid or sink.count != p.terms) return error.ClassicControlFractionShape;
        for (p.groups[0..p.group_count], 0..) |g, i| {
            const first = denominators[g.first];
            if (g.second) |j| {
                d[i] = first.mul(denominators[j]);
                n[i] = .{ .secure = denominators[j].mulM31(weights[g.first]).add(first.mulM31(weights[j])) };
            } else {
                d[i] = first;
                n[i] = .{ .base = weights[g.first] };
            }
        }
    }
};
fn components(a: std.mem.Allocator, setup: *const R.CpuSetup, r: P.Request, plan: *const Plan, ch: Ch, shared: Manifest.Shared, local: []const O, ram: []const O) ![]Comp.Component {
    try checkClaims(r, plan, shared, local, ram);
    const out = try a.alloc(Comp.Component, plan.slots.len);
    errdefer a.free(out);
    for (out, plan.slots) |*c, s| {
        c.* = .{ .role = s.role, .log = s.log, .source_fixed = s.fixed, .offsets = .{ s.fixed_offset, s.main_offset }, .inter_offset = s.inter_offset, .epoch = r.base.epoch, .public = try Comp.publicFor(s.role, setup.materials.geometry, r), .register_public = r.base.cpu, .challenges = ch, .shared = shared, .local_claim = if (s.local_claim) |i| local[i] else O.zero(), .global_claims = .{ .ram = if (s.ram_claim) |i| ram[i] else O.zero(), .kio = O.zero(), .wire = O.zero() } };
        try c.validate();
    }
    return out;
}
/// Consumes source on every success/error path, exactly like owned MAIN commit.
pub fn prove(a: std.mem.Allocator, setup: *const R.CpuSetup, r: P.Request, expected: P.Expected, config: W.PcsConfig, source_value: R.Sources, budget: usize, recorder: ?*@import("stwo_prover_api").stage_profile.Recorder, timing: ?*Timing) !Encoded {
    var source = source_value;
    var source_alive = true;
    defer if (source_alive) source.deinit();
    try validate(a, setup, r, expected, config);
    var plan = try Plan.init(a, setup);
    defer plan.deinit();
    var scheme = try W.Prover.init(a, config);
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    var ch = begin(setup, r, config);
    try W.appendFixed(a, &setup.key, setup.key.root, &scheme, &ch);
    var clock: ?std.time.Timer = if (timing != null) try std.time.Timer.start() else null;
    const main = try source.takeMain(setup);
    try scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 64, recorder, &ch);
    const root = scheme.trees.items[1].root();
    if (clock) |*t| timing.?.main_commit_ns = t.lap();
    const instances = try @import("../../gkr_local/roster.zig").fromSetup(a, setup);
    defer a.free(instances);
    const challenges = draw(setup, r, config, root, instances);
    const locals = try a.alloc(?Classic.Witness, plan.slots.len);
    defer a.free(locals);
    @memset(locals, null);
    defer for (locals) |*w| if (w.*) |*v| v.deinit();
    const globals = try a.alloc(?Classic.Witness, plan.slots.len);
    defer a.free(globals);
    @memset(globals, null);
    defer for (globals) |*w| if (w.*) |*v| v.deinit();
    const local_claims = try a.alloc(O, plan.local_claims);
    errdefer a.free(local_claims);
    const ram_claims = try a.alloc(O, plan.ram_claims);
    errdefer a.free(ram_claims);
    var remaining = budget;
    var stage = try @import("stwo_prover_api").stage_profile.StageScope.begin(recorder, "interaction_generation", "Benchmark OM classic local and RAM interactions");
    defer stage.end();
    for (plan.slots, locals, globals) |s, *l, *g| {
        if (s.local_claim) |i| {
            const p = Policy.forRole(s.role);
            l.* = try Classic.Witness.initTruth(a, s.log, &.{.{ .inverses = @intCast(p.group_count) }}, LocalProvider{ .source = &source, .instance = .{ .origin = .{ .core = s.role }, .row_log = s.log, .terms = @intCast(p.terms), .fixed_offset = s.fixed_offset, .main_offset = s.main_offset }, .challenges = &challenges.local }, remaining);
            remaining -= l.*.?.data.len * @sizeOf(M);
            local_claims[i] = l.*.?.claimSlice()[0];
        }
        if (s.ram_claim) |i| {
            const origin = Frame.Origin{ .core = s.role };
            g.* = try Classic.Witness.init(a, s.log, try GM.groups(origin), GM.Provider{ .source = &source, .origin = origin, .log_size = s.log, .shared = challenges.shared }, remaining);
            remaining -= g.*.?.data.len * @sizeOf(M);
            ram_claims[i] = g.*.?.claimSlice()[0];
        }
    }
    stage.end();
    // All local/RAM advice is represented by committed MAIN and durable I
    // buffers now. No proof component borrows the native source metadata.
    source.deinit();
    source_alive = false;
    if (clock) |*t| timing.?.interaction_ns = t.lap();
    const items = try components(a, setup, r, &plan, challenges.local, challenges.shared, local_claims, ram_claims);
    defer a.free(items);
    const handles = try a.alloc(engine.air.component_prover.ForField(O).ComponentProver, items.len);
    defer a.free(handles);
    for (handles, items) |*h, *c| h.* = c.asProverComponent();
    const headers = try a.alloc(engine.pcs.ColumnEvaluation, plan.inter_columns);
    var owns_buffers = true;
    errdefer if (owns_buffers) a.free(headers);
    const backs = try a.alloc([]M, plan.local_claims + plan.ram_claims);
    errdefer if (owns_buffers) a.free(backs);
    var at: usize = 0;
    for (plan.slots, locals, globals) |s, l, g| {
        var offset = s.inter_offset;
        const rows = @as(usize, 1) << @intCast(s.log);
        for ([2]?Classic.Witness{ l, g }) |w| if (w) |v| {
            backs[at] = v.data;
            at += 1;
            for (headers[offset..][0..v.width()], 0..) |*h, c| h.* = .{ .log_size = s.log, .values = v.data[c * rows ..][0..rows] };
            offset += v.width();
        };
    }
    // All fallible planning finished; transfer each backing once.
    for (locals) |*w| if (w.*) |*v| {
        v.data = &.{};
    };
    for (globals) |*w| if (w.*) |*v| {
        v.data = &.{};
    };
    mix(&ch, local_claims, ram_claims);
    owns_buffers = false;
    try scheme.commitOwnedStreamingWithRecorderAndBacking(a, headers, backs, 64, recorder, &ch);
    owns_scheme = false;
    var proof = try W.Prover.prove(a, handles, &ch, scheme, .{ .recorder = recorder });
    defer proof.deinit(a);
    const bytes = try W.encodePhysical(a, proof.proof);
    if (clock) |*t| timing.?.inter_commit_and_prove_ns = t.read();
    return .{ .bytes = bytes, .local_claims = local_claims, .ram_claims = ram_claims, .main_root = root };
}
pub fn verify(a: std.mem.Allocator, setup: *const R.CpuSetup, r: P.Request, expected: P.Expected, config: W.PcsConfig, encoded: *const Encoded) !void {
    try validate(a, setup, r, expected, config);
    var plan = try Plan.init(a, setup);
    defer plan.deinit();
    var proof = try W.decodePhysical(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.mem.eql(u8, &roots[0], &setup.key.root) or !std.mem.eql(u8, &roots[1], &encoded.main_root) or !std.meta.eql(proof.commitment_scheme_proof.config, config) or proof.commitment_scheme_proof.revision_config != null) return error.ClassicControlProofShape;
    const instances = try @import("../../gkr_local/roster.zig").fromSetup(a, setup);
    defer a.free(instances);
    const challenges = draw(setup, r, config, roots[1], instances);
    const items = try components(a, setup, r, &plan, challenges.local, challenges.shared, encoded.local_claims, encoded.ram_claims);
    defer a.free(items);
    const handles = try a.alloc(core.air.components.ForField(O).Component, items.len);
    defer a.free(handles);
    for (handles, items) |*h, *c| h.* = c.asVerifierComponent();
    var ch = begin(setup, r, config);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, config);
    defer receiver.deinit(a);
    const f = try setup.logs(a, 0);
    defer a.free(f);
    const m = try setup.logs(a, 1);
    defer a.free(m);
    const i = try plan.interLogs(a);
    defer a.free(i);
    try receiver.commit(a, roots[0], f, &ch);
    try receiver.commit(a, roots[1], m, &ch);
    mix(&ch, encoded.local_claims, encoded.ram_claims);
    try receiver.commit(a, roots[2], i, &ch);
    owns = false;
    try core.verifier.ForField(O).verify(W.H, W.MC, a, handles, &ch, &receiver, proof);
}
