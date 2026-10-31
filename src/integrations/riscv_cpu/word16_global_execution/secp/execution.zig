//! Actual independently sized secp-truth protocol. Acceptance requires every
//! physical CPU/bridge and truth STARK plus complete manifest/typed debt closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const B = S.word16_bridge;
const G = @import("../protocol.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Source = @import("../../word16_execution/sources.zig");
const Memory = @import("../../word16_execution/memory/prepared.zig").Prepared;
const CoreComponents = @import("../../word16_execution/components.zig");
const Components = CoreComponents.Components;
comptime {
    if (CoreComponents.COMPOSITION_LOG_SPLIT != 1 and CoreComponents.COMPOSITION_LOG_SPLIT != 2) @compileError("unsupported shared CPU composition geometry");
}
const Advice = @import("collector.zig").Advice;
const Q = G.Q;
const Cell = A.memory.closed_ram.types.Cell;
pub const CpuClaims = struct {
    base: G.Old.Claims,
    bridges: [2]B.types.Claims,
    pub fn values(self: @This()) [P.CPU_CLAIM_COUNT]Q {
        var out: [P.CPU_CLAIM_COUNT]Q = undefined;
        out[0..P.CORE_CLAIM_COUNT].* = self.base.values();
        out[P.CORE_CLAIM_COUNT..][0..5].* = self.bridges[0].values();
        out[P.CORE_CLAIM_COUNT + 5 ..][0..5].* = self.bridges[1].values();
        return out;
    }
    pub fn canonical(self: @This()) !void {
        try Source.validateCanonicalClaims(self.base);
        for (self.bridges) |b| for (b.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
    }
    pub fn ram(self: @This()) Q {
        const base = G.Old.ramClaim(self.base);
        return base.add(self.bridges[0].ram).add(self.bridges[1].ram);
    }
    pub fn local(self: @This()) !void {
        var sum = Q.zero();
        for (self.values()) |v| sum = sum.add(v);
        if (!sum.sub(self.ram()).sub(self.bridges[0].wire).sub(self.bridges[1].wire).isZero()) return error.UnclosedSecpCpuRelations;
    }
};
pub const CpuEncoded = struct {
    bytes: []u8,
    request: P.Request,
    claims: CpuClaims,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.request.base.memory.initial);
        a.free(self.request.base.memory.terminal);
    }
};
pub const TruthEncoded = struct { bytes: []u8, claims: [3]Q };
pub const Bundle = struct {
    manifest: G.Manifest,
    cpus: []CpuEncoded,
    truths: [2]TruthEncoded,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.cpus) |*p| p.deinit(a);
        a.free(self.cpus);
        for (self.truths) |t| a.free(t.bytes);
        self.manifest.deinit();
    }
};
const CpuWorker = struct {
    source: R.CpuSource,
    scheme: G.T.Scheme,
    channel: G.T.P.Channel,
    owns: bool = true,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (self.owns) self.scheme.deinit(a);
        self.source.deinit();
    }
};
const TruthWorker = struct {
    source: R.TruthSource,
    scheme: G.T.Scheme,
    channel: G.T.P.Channel,
    owns: bool = true,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (self.owns) self.scheme.deinit(a);
        self.source.deinit();
    }
};
fn actual(a: std.mem.Allocator, scheme: *G.T.Scheme, key: [32]u8, logs0: []const u32, logs1: []const u32) !G.Receipt {
    if (!std.meta.eql(scheme.config, G.T.P.config()) or scheme.revision_config != null) return error.SecpPcsSuiteMismatch;
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2 or !std.mem.eql(u8, &roots.items[0], &key)) return error.SecpStage1Mismatch;
    for ([2][]const u32{ logs0, logs1 }, 0..) |logs, tree| {
        if (logs.len != scheme.trees.items[tree].columns.len) return error.SecpStage1Mismatch;
        for (logs, scheme.trees.items[tree].columns) |log, col| if (col.log_size != log + G.T.P.config().fri_config.log_blowup_factor) return error.SecpStage1Mismatch;
    }
    return .{ .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
}
fn cpuBridges(s: *const R.CpuSetup, calls: [2]u32, first: [2]u32, ch: G.Old.Draw, wire_ch: S.equations.Wire, claims: [2]B.types.Claims) [2]B.component.Component {
    var out: [2]B.component.Component = undefined;
    for (&out, 0..) |*c, k| c.* = .{ .kind = @enumFromInt(k + 1), .log_size = s.bridge_logs[k], .rows = calls[k], .first_id = first[k], .offsets = .{ s.total(0) + k * B.layout.FIXED, s.total(1) + k * B.layout.MAIN, s.total(2) + k * B.layout.INTERACTION }, .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .wire = wire_ch, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, .claims = claims[k] };
    return out;
}
fn cpuHandles(a: std.mem.Allocator, base: *const Components, bridges: *const [2]B.component.Component) ![]engine.air.component_prover.ComponentProver {
    const old = try base.provers(a);
    defer a.free(old);
    const out = try a.alloc(engine.air.component_prover.ComponentProver, old.len + 2);
    errdefer a.free(out);
    @memcpy(out[0..old.len], old);
    for (bridges, 0..) |*b, k| out[old.len + k] = b.asProverComponent();
    return out;
}
fn cpuVerifierHandles(a: std.mem.Allocator, base: *const Components, bridges: *const [2]B.component.Component) ![]core.air.components.Component {
    const old = try base.verifiers(a);
    defer a.free(old);
    const out = try a.alloc(core.air.components.Component, old.len + 2);
    errdefer a.free(out);
    @memcpy(out[0..old.len], old);
    for (bridges, 0..) |*b, k| out[old.len + k] = b.asVerifierComponent();
    return out;
}
pub const TruthComponents = struct {
    arithmetic: [2]S.component.Component,
    bytes: A.providers.byte.Component,
    pub fn init(setup: *const R.TruthSetup, calls: u32, ch: S.equations.Challenges, claims: [3]Q) TruthComponents {
        return initSpan(setup, 1, calls, ch, claims);
    }
    pub fn initSpan(setup: *const R.TruthSetup, first_id: u32, calls: u32, ch: S.equations.Challenges, claims: [3]Q) TruthComponents {
        return .{ .arithmetic = .{ .{ .kind = .product, .program = S.program.get(setup.kind), .log_size = setup.logs[0], .public = .{ .calls = calls, .first_id = first_id }, .challenges = ch, .claim = claims[0] }, .{ .kind = .linear, .program = S.program.get(setup.kind), .log_size = setup.logs[1], .public = .{ .calls = calls, .first_id = first_id }, .offsets = .{ .fixed = S.layout.FIXED, .main = S.layout.main(.product), .interaction = S.layout.interaction(.product) }, .challenges = ch, .claim = claims[1] } }, .bytes = .{ .fixed_offset = 2 * S.layout.FIXED, .main_offset = S.layout.main(.product) + S.layout.main(.linear), .interaction_offset = S.layout.interaction(.product) + S.layout.interaction(.linear), .alpha = ch.bytes, .claim = claims[2] } };
    }
    pub fn provers(self: *const TruthComponents) [3]engine.air.component_prover.ComponentProver {
        var out = [3]engine.air.component_prover.ComponentProver{ self.arithmetic[0].asProverComponent(), self.arithmetic[1].asProverComponent(), self.bytes.asProverComponent() };
        out[0].pool_exclusive_domain = true;
        out[1].pool_exclusive_domain = true;
        return out;
    }
    pub fn verifiers(self: *const TruthComponents) [3]core.air.components.Component {
        return .{ self.arithmetic[0].asVerifierComponent(), self.arithmetic[1].asVerifierComponent(), self.bytes.asVerifierComponent() };
    }
};
fn firstIds(requests: []const P.Request, index: usize) ![2]u32 {
    return .{ try P.firstCall(requests, index, 0), try P.firstCall(requests, index, 1) };
}
/// Bounded qualification harness: coordinator retains several PCS owners here.
/// No claim of fitting arbitrary execution fanout in one process is made.
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: [2]*const R.TruthSetup, prepared: []const *Native, advice: *const Advice, expected: P.Expected) !Bundle {
    if (setups.len != prepared.len or setups.len != advice.events.len or setups.len != advice.calls.len) return error.InvalidSecpInventory;
    const requests = try a.alloc(P.Request, setups.len);
    defer a.free(requests);
    for (prepared, requests, 0..) |n, *r, index| {
        const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
        r.* = .{ .calls = .{ @intCast(advice.calls[index][0].len), @intCast(advice.calls[index][1].len) }, .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (index == 0) advice.initial else &.{}, .terminal = if (index + 1 == setups.len) advice.terminal else &.{}, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[index].len) } } };
    }
    const calls = try P.admit(a, setups, truths, requests, expected);
    const specs = try a.alloc([32]u8, setups.len + 2);
    defer a.free(specs);
    const receipts = try a.alloc(G.Receipt, setups.len + 2);
    defer a.free(receipts);
    const workers = try a.alloc(CpuWorker, setups.len);
    defer a.free(workers);
    var done: usize = 0;
    defer for (workers[0..done]) |*w| w.deinit(a);
    var first_step: u64 = 0;
    for (setups, prepared, requests, 0..) |s, n, r, index| {
        const initial = try a.dupe(Cell, r.base.memory.initial);
        const terminal = a.dupe(Cell, r.base.memory.terminal) catch |err| {
            a.free(initial);
            return err;
        };
        const mem = try Memory.initOwnedForGlobalRamLadderIndependent(a, advice.events[index], initial, terminal, r.base.epoch, s.materials.geometry.ls_log, s.materials.geometry.ls_tail_log, s.materials.geometry.initialLog(), s.materials.geometry.terminalLog());
        var source = block: {
            var base = try Source.Source.fromPreparedWithOwnedMemory(a, &s.materials, n, mem);
            errdefer base.deinit();
            var add = try B.source.Source.init(a, .add, advice.calls[index][0], try P.firstCall(requests, index, 0), s.bridge_logs[0]);
            errdefer add.deinit();
            var double = try B.source.Source.init(a, .double, advice.calls[index][1], try P.firstCall(requests, index, 1), s.bridge_logs[1]);
            errdefer double.deinit();
            break :block R.CpuSource{ .core = base, .bridges = .{ add, double } };
        };
        errdefer source.deinit();
        try source.mergeRanges();
        var scheme = try G.T.Scheme.init(a, G.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = G.T.P.Channel{};
        try P.beginCpu(&channel, s, r, expected, index, first_step, try firstIds(requests, index));
        first_step += r.base.cpu.steps;
        specs[index] = channel.digestBytes();
        try s.key.append(a, &scheme, &channel);
        const main = try source.columns(a, 1);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, main, 8, &channel);
        try source.releaseMain();
        const l0 = try s.logs(a, 0);
        defer a.free(l0);
        const l1 = try s.logs(a, 1);
        defer a.free(l1);
        receipts[index] = try actual(a, &scheme, s.key.root, l0, l1);
        workers[index] = .{ .source = source, .scheme = scheme, .channel = channel };
        done += 1;
    }
    var truth_workers: [2]TruthWorker = undefined;
    var truth_done: usize = 0;
    defer for (truth_workers[0..truth_done]) |*w| w.deinit(a);
    for (truths, &truth_workers, 0..) |truth, *w, k| {
        const inputs = try a.alloc(B.types.Call, calls[k]);
        defer a.free(inputs);
        var at: usize = 0;
        for (advice.calls) |cc| for (cc[k]) |c| {
            inputs[at] = c;
            at += 1;
        };
        var ts = try R.TruthSource.init(a, truth, inputs, 1);
        errdefer ts.deinit();
        var scheme = try G.T.Scheme.init(a, G.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, calls[k], expected);
        specs[setups.len + k] = channel.digestBytes();
        try truth.key.append(a, &scheme, &channel);
        const main = try ts.columns(a, 1);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, main, 8, &channel);
        try ts.releaseMain();
        const l0 = try truth.columnLogs(a, 0);
        defer a.free(l0);
        const l1 = try truth.columnLogs(a, 1);
        defer a.free(l1);
        receipts[setups.len + k] = try actual(a, &scheme, truth.key.root, l0, l1);
        w.* = .{ .source = ts, .scheme = scheme, .channel = channel };
        truth_done += 1;
    }
    var manifest = try G.Manifest.init(a, specs, receipts);
    errdefer manifest.deinit();
    const common = try P.shared(&manifest);
    const cpus = try a.alloc(CpuEncoded, setups.len);
    errdefer a.free(cpus);
    var finished: usize = 0;
    errdefer for (cpus[0..finished]) |*p| p.deinit(a);
    for (workers, setups, requests, cpus, 0..) |*w, s, r, *encoded, index| {
        const l0 = try s.logs(a, 0);
        defer a.free(l0);
        const l1 = try s.logs(a, 1);
        defer a.free(l1);
        if (!std.meta.eql(try actual(a, &w.scheme, s.key.root, l0, l1), manifest.roots[index])) return error.SecpStage1Mismatch;
        const ch = try P.drawCpu(&w.channel, &manifest, index);
        const base = (try w.source.core.generateForDelegationJoin(ch)).physical;
        var bridges: [2]B.types.Claims = undefined;
        for (&w.source.bridges, &bridges) |*b, *c| c.* = try b.generate(.{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .wire = common.wire, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, w.source.core.range16.dictionary, w.source.core.range8.dictionary);
        const claims = CpuClaims{ .base = base, .bridges = bridges };
        w.channel.mixFelts(&claims.values());
        const inter = try w.source.columns(a, 2);
        defer a.free(inter);
        try w.scheme.commitBorrowedStreaming(a, inter, 8, &w.channel);
        var bc = try Components.init(&s.materials, r.base, ch, base);
        var bb = cpuBridges(s, r.calls, try firstIds(requests, index), ch, common.wire, bridges);
        const handles = try cpuHandles(a, &bc, &bb);
        defer a.free(handles);
        w.owns = false;
        var proof = try engine.prove.prove(Backend, G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &w.channel, w.scheme);
        defer proof.deinit(a);
        const bytes = try wire.encodeProofBytesBinary(a, proof);
        errdefer a.free(bytes);
        var req = r;
        req.base.memory.initial = try a.dupe(Cell, r.base.memory.initial);
        errdefer a.free(req.base.memory.initial);
        req.base.memory.terminal = try a.dupe(Cell, r.base.memory.terminal);
        encoded.* = .{ .bytes = bytes, .request = req, .claims = claims };
        finished += 1;
    }
    var encoded_truths: [2]TruthEncoded = undefined;
    var finished_truths: usize = 0;
    errdefer for (encoded_truths[0..finished_truths]) |t| a.free(t.bytes);
    for (&truth_workers, truths, 0..) |*tw, truth, k| {
        const l0 = try truth.columnLogs(a, 0);
        defer a.free(l0);
        const l1 = try truth.columnLogs(a, 1);
        defer a.free(l1);
        if (!std.meta.eql(try actual(a, &tw.scheme, truth.key.root, l0, l1), manifest.roots[setups.len + k])) return error.SecpStage1Mismatch;
        const ch = try P.drawTruth(&tw.channel, &manifest, truth.kind);
        const claims = [3]Q{ try tw.source.batch.product.generateInteraction(ch), try tw.source.batch.linear.generateInteraction(ch), try tw.source.bytes.generateInteraction(ch.bytes) };
        tw.channel.mixFelts(&claims);
        const inter = try tw.source.columns(a, 2);
        defer a.free(inter);
        try tw.scheme.commitBorrowedStreaming(a, inter, 8, &tw.channel);
        var components = TruthComponents.init(truth, calls[k], ch, claims);
        const handles = components.provers();
        tw.owns = false;
        var proof = try engine.prove.prove(Backend, G.T.P.Hasher, G.T.P.MerkleChannel, a, &handles, &tw.channel, tw.scheme);
        defer proof.deinit(a);
        encoded_truths[k] = .{ .bytes = try wire.encodeProofBytesBinary(a, proof), .claims = claims };
        finished_truths += 1;
    }
    return .{ .manifest = manifest, .cpus = cpus, .truths = encoded_truths };
}

fn checkRoots(proof: anytype, key: [32]u8, manifest: *const G.Manifest, index: usize) !void {
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, G.T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.SecpPcsSuiteMismatch;
    const roots = pcs.commitments.items;
    if (!std.mem.eql(u8, &roots[0], &key) or !std.mem.eql(u8, &roots[0], &manifest.roots[index].fixed.bytes) or !std.mem.eql(u8, &roots[1], &manifest.roots[index].main.bytes)) return error.SecpStage1Mismatch;
}
pub fn verify(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: [2]*const R.TruthSetup, expected: P.Expected, bundle: *const Bundle) !void {
    if (setups.len != bundle.cpus.len) return error.InvalidSecpInventory;
    const requests = try a.alloc(P.Request, setups.len);
    defer a.free(requests);
    for (bundle.cpus, requests) |c, *r| r.* = c.request;
    const calls = try P.admit(a, setups, truths, requests, expected);
    const specs = try a.alloc([32]u8, setups.len + 2);
    defer a.free(specs);
    var first: u64 = 0;
    for (setups, requests, specs[0..setups.len], 0..) |s, r, *spec, index| {
        var ch = G.T.P.Channel{};
        try P.beginCpu(&ch, s, r, expected, index, first, try firstIds(requests, index));
        first += r.base.cpu.steps;
        spec.* = ch.digestBytes();
    }
    for (truths, 0..) |truth, k| {
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, calls[k], expected);
        specs[setups.len + k] = channel.digestBytes();
    }
    try bundle.manifest.check(specs);
    const common = try P.shared(&bundle.manifest);
    var ram = Q.zero();
    var io = Q.zero();
    for (setups, bundle.cpus, 0..) |s, encoded, index| {
        try encoded.claims.canonical();
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.SecpProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        try checkRoots(proof, s.key.root, &bundle.manifest, index);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, G.T.P.config());
        defer verifier.deinit(a);
        var channel = G.T.P.Channel{};
        var before: u64 = 0;
        for (requests[0..index]) |r| before += r.base.cpu.steps;
        try P.beginCpu(&channel, s, encoded.request, expected, index, before, try firstIds(requests, index));
        const roots = proof.commitment_scheme_proof.commitments.items;
        for (0..2) |tree| {
            const logs = try s.logs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, roots[tree], logs, &channel);
        }
        const ch = try P.drawCpu(&channel, &bundle.manifest, index);
        if (!encoded.claims.base.initial.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.base.memory.initial, true, common.ram)) or !encoded.claims.base.terminal.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.base.memory.terminal, false, common.ram))) return error.GlobalBoundaryPhysicalClaimMismatch;
        channel.mixFelts(&encoded.claims.values());
        const logs = try s.logs(a, 2);
        defer a.free(logs);
        try verifier.commit(a, roots[2], logs, &channel);
        var bc = try Components.init(&s.materials, encoded.request.base, ch, encoded.claims.base);
        var bb = cpuBridges(s, encoded.request.calls, try firstIds(requests, index), ch, common.wire, encoded.claims.bridges);
        const handles = try cpuVerifierHandles(a, &bc, &bb);
        defer a.free(handles);
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
        try encoded.claims.local();
        ram = ram.add(encoded.claims.ram());
        for (encoded.claims.bridges) |b| io = io.add(b.wire);
    }
    for (truths, bundle.truths, 0..) |truth, encoded, k| {
        for (encoded.claims) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.SecpProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        try checkRoots(proof, truth.key.root, &bundle.manifest, setups.len + k);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, G.T.P.config());
        defer verifier.deinit(a);
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, calls[k], expected);
        const roots = proof.commitment_scheme_proof.commitments.items;
        for (0..2) |tree| {
            const logs = try truth.columnLogs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, roots[tree], logs, &channel);
        }
        const ch = try P.drawTruth(&channel, &bundle.manifest, truth.kind);
        channel.mixFelts(&encoded.claims);
        const logs = try truth.columnLogs(a, 2);
        defer a.free(logs);
        try verifier.commit(a, roots[2], logs, &channel);
        var components = TruthComponents.init(truth, calls[k], ch, encoded.claims);
        const handles = components.verifiers();
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, &handles, &channel, &verifier, proof);
        for (encoded.claims) |q| io = io.add(q);
    }
    if (!ram.isZero()) return error.UnclosedSecpRam;
    if (!io.isZero()) return error.UnclosedSecpWire;
}
