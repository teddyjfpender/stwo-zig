//! Actual independently sized shared-truth protocol. Acceptance requires every
//! physical CPU/bridge and truth STARK plus complete manifest/typed debt closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const B = K.word16_bridge;
const G = @import("../../protocol.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const Native = @import("../../../word16_execution/prepared.zig").Prepared;
const Source = @import("../../../word16_execution/sources.zig");
const Memory = @import("../../../word16_execution/memory/prepared.zig").Prepared;
const CoreComponents = @import("../../../word16_execution/components.zig");
const Components = CoreComponents.Components;
comptime {
    if (CoreComponents.COMPOSITION_LOG_SPLIT != 1 and CoreComponents.COMPOSITION_LOG_SPLIT != 2) @compileError("unsupported shared CPU composition geometry");
}
const Advice = @import("../collector.zig").Advice;
const Q = G.Q;
const Cell = A.memory.closed_ram.types.Cell;
pub const CpuClaims = struct {
    base: G.Old.Claims,
    bridge: B.types.Claims,
    pub fn values(self: @This()) [38]Q {
        var out: [38]Q = undefined;
        out[0..33].* = self.base.values();
        out[33..].* = self.bridge.values();
        return out;
    }
    pub fn canonical(self: @This()) !void {
        try Source.validateCanonicalClaims(self.base);
        for (self.bridge.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSharedTruthClaim;
    }
    pub fn ram(self: @This()) Q {
        return self.base.ls.ram.add(self.base.initial.ram).add(self.base.terminal.ram).add(self.bridge.ram);
    }
    pub fn local(self: @This()) !void {
        var sum = Q.zero();
        for (self.values()) |v| sum = sum.add(v);
        if (!sum.sub(self.ram()).sub(self.bridge.io).isZero()) return error.UnclosedSharedTruthCpuRelations;
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
    truth: TruthEncoded,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.cpus) |*p| p.deinit(a);
        a.free(self.cpus);
        a.free(self.truth.bytes);
        self.manifest.deinit();
    }
};
pub const BoundedBundle = struct {
    manifest: G.Manifest,
    cpus: []CpuEncoded,
    truths: []TruthEncoded,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.cpus) |*p| p.deinit(a);
        a.free(self.cpus);
        for (self.truths) |p| a.free(p.bytes);
        a.free(self.truths);
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
    if (!std.meta.eql(scheme.config, G.T.P.config()) or scheme.revision_config != null) return error.SharedTruthPcsSuiteMismatch;
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2 or !std.mem.eql(u8, &roots.items[0], &key)) return error.SharedTruthStage1Mismatch;
    for ([2][]const u32{ logs0, logs1 }, 0..) |logs, tree| {
        if (logs.len != scheme.trees.items[tree].columns.len) return error.SharedTruthStage1Mismatch;
        for (logs, scheme.trees.items[tree].columns) |log, col| if (col.log_size != log + G.T.P.config().fri_config.log_blowup_factor) return error.SharedTruthStage1Mismatch;
    }
    return .{ .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
}
fn cpuBridge(s: *const R.CpuSetup, calls: u32, first: u32, ch: G.Old.Draw, io: K.equations.Io, claims: B.types.Claims) B.component.Component {
    return .{ .kind = .bridge, .log_size = s.bridge_log, .rows = calls, .first_id = first, .offsets = .{ s.total(0), s.total(1), s.total(2) }, .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = io, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, .claims = claims };
}
fn cpuHandles(a: std.mem.Allocator, base: *const Components, bridge: *const B.component.Component) ![]engine.air.component_prover.ComponentProver {
    const old = try base.provers(a);
    defer a.free(old);
    const out = try a.alloc(engine.air.component_prover.ComponentProver, old.len + 1);
    errdefer a.free(out);
    @memcpy(out[0..old.len], old);
    out[old.len] = try bridge.asProverComponent().withCompositionGeometryOverrideV1(.{ .composition_log_split = CoreComponents.COMPOSITION_LOG_SPLIT, .max_constraint_log_degree_bound_delta = CoreComponents.COMPOSITION_LOG_SPLIT - 1 });
    return out;
}
fn cpuVerifierHandles(a: std.mem.Allocator, base: *const Components, bridge: *const B.component.Component) ![]core.air.components.Component {
    const old = try base.verifiers(a);
    defer a.free(old);
    const out = try a.alloc(core.air.components.Component, old.len + 1);
    errdefer a.free(out);
    @memcpy(out[0..old.len], old);
    out[old.len] = try bridge.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .composition_log_split = CoreComponents.COMPOSITION_LOG_SPLIT, .max_constraint_log_degree_bound_delta = CoreComponents.COMPOSITION_LOG_SPLIT - 1 });
    return out;
}
fn truthComponents(setup: *const R.TruthSetup, first_id: u32, calls: u32, ch: K.equations.Challenges, claims: [3]Q) [3]K.component.Component {
    return .{ .{ .kind = .permutation, .log_size = setup.log, .calls = calls, .first_call_id = first_id, .challenges = ch, .claim = claims[0] }, .{ .kind = .chi, .log_size = 13, .offsets = .{ .fixed = K.layout.FIXED, .main = K.layout.MAIN, .interaction = K.layout.INTERACTION }, .challenges = ch, .claim = claims[1] }, .{ .kind = .xor5, .log_size = 10, .offsets = .{ .fixed = K.layout.FIXED + 7, .main = K.layout.MAIN + 1, .interaction = K.layout.INTERACTION + 4 }, .challenges = ch, .claim = claims[2] } };
}
/// Bounded qualification harness: coordinator retains several PCS owners here.
/// No claim of fitting arbitrary execution fanout in one process is made.
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truth: *const R.TruthSetup, prepared: []const *Native, advice: *const Advice, expected: P.Expected) !Bundle {
    var calls: u32 = 0;
    for (advice.calls) |cc| calls = try std.math.add(u32, calls, std.math.cast(u32, cc.len) orelse return error.KeccakLookupMassExceeded);
    const bundle = try produceInternal(a, setups, &.{.{ .setup = truth, .first_id = 1, .calls = calls }}, prepared, advice, expected, .single_v2);
    defer a.free(bundle.truths);
    return .{ .manifest = bundle.manifest, .cpus = bundle.cpus, .truth = bundle.truths[0] };
}
/// Bounded qualification harness. Receiver chooses this distinct protocol;
/// proofs never choose their own truth roster, parameters or challenge mode.
pub fn produceBounded(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const P.Truth, prepared: []const *Native, advice: *const Advice, expected: P.Expected) !BoundedBundle {
    return produceInternal(a, setups, truths, prepared, advice, expected, .bounded_v3);
}
fn produceInternal(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const P.Truth, prepared: []const *Native, advice: *const Advice, expected: P.Expected, mode: P.Mode) !BoundedBundle {
    if (setups.len != prepared.len or setups.len != advice.events.len or setups.len != advice.calls.len) return error.InvalidSharedTruthInventory;
    const requests = try a.alloc(P.Request, setups.len);
    defer a.free(requests);
    for (prepared, requests, 0..) |n, *r, index| {
        const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
        r.* = .{ .calls = @intCast(advice.calls[index].len), .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (index == 0) advice.initial else &.{}, .terminal = if (index + 1 == setups.len) advice.terminal else &.{}, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[index].len) } } };
    }
    const calls = try P.admitBounded(a, setups, truths, requests, expected);
    const specs = try a.alloc([32]u8, setups.len + truths.len);
    defer a.free(specs);
    const receipts = try a.alloc(G.Receipt, setups.len + truths.len);
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
        const mem = try Memory.initOwnedForGlobalRamIndependent(a, advice.events[index], initial, terminal, r.base.epoch, s.materials.geometry.ls_log, s.materials.geometry.initialLog(), s.materials.geometry.terminalLog());
        var source = block: {
            var base = try Source.Source.fromPreparedWithOwnedMemory(a, &s.materials, n, mem);
            errdefer base.deinit();
            var bridge = try B.source.Source.init(a, advice.calls[index], try P.firstCall(requests, index), s.bridge_log);
            errdefer bridge.deinit();
            break :block R.CpuSource{ .core = base, .bridge = bridge };
        };
        errdefer source.deinit();
        try source.mergeRanges();
        var scheme = try G.T.Scheme.init(a, G.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = G.T.P.Channel{};
        try P.beginCpuFor(mode, &channel, s, r, expected, index, first_step, try P.firstCall(requests, index), truths.len);
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
    const inputs = try a.alloc(K.trace.State, calls);
    defer a.free(inputs);
    var at: usize = 0;
    for (advice.calls) |cc| for (cc) |c| {
        inputs[at] = c.before;
        at += 1;
    };
    const truth_workers = try a.alloc(TruthWorker, truths.len);
    defer a.free(truth_workers);
    var truth_done: usize = 0;
    defer for (truth_workers[0..truth_done]) |*w| w.deinit(a);
    for (truths, truth_workers, 0..) |t, *w, index| {
        const begin: usize = t.first_id - 1;
        var ts = try R.TruthSource.initSpan(a, inputs[begin..][0..t.calls], t.first_id, t.setup.log);
        errdefer ts.deinit();
        var scheme = try G.T.Scheme.init(a, G.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = G.T.P.Channel{};
        P.beginTruthFor(mode, &channel, t, expected, index, truths.len);
        specs[setups.len + index] = channel.digestBytes();
        try t.setup.key.append(a, &scheme, &channel);
        const tm = try ts.columns(a, 1);
        defer a.free(tm);
        try scheme.commitBorrowedStreaming(a, tm, 8, &channel);
        try ts.releaseMain();
        const tf0 = try t.setup.logs(a, 0);
        defer a.free(tf0);
        const tf1 = try t.setup.logs(a, 1);
        defer a.free(tf1);
        receipts[setups.len + index] = try actual(a, &scheme, t.setup.key.root, tf0, tf1);
        w.* = .{ .source = ts, .scheme = scheme, .channel = channel };
        truth_done += 1;
    }
    var manifest = try G.Manifest.init(a, specs, receipts);
    errdefer manifest.deinit();
    const common = if (mode == .single_v2) try P.shared(&manifest) else try P.sharedBounded(&manifest);
    const cpus = try a.alloc(CpuEncoded, setups.len);
    errdefer a.free(cpus);
    var finished: usize = 0;
    errdefer for (cpus[0..finished]) |*p| p.deinit(a);
    for (workers, setups, requests, cpus, 0..) |*w, s, r, *encoded, index| {
        const l0 = try s.logs(a, 0);
        defer a.free(l0);
        const l1 = try s.logs(a, 1);
        defer a.free(l1);
        if (!std.meta.eql(try actual(a, &w.scheme, s.key.root, l0, l1), manifest.roots[index])) return error.SharedTruthStage1Mismatch;
        const ch = try P.drawCpuFor(mode, &w.channel, &manifest, index);
        const base = (try w.source.core.generateForKeccakJoin(ch)).physical;
        const bridge = try w.source.bridge.generate(.{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = common.io, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, w.source.core.range16.dictionary, w.source.core.range8.dictionary);
        const claims = CpuClaims{ .base = base, .bridge = bridge };
        w.channel.mixFelts(&claims.values());
        const inter = try w.source.columns(a, 2);
        defer a.free(inter);
        try w.scheme.commitBorrowedStreaming(a, inter, 8, &w.channel);
        var bc = try Components.init(&s.materials, r.base, ch, base);
        var bb = cpuBridge(s, r.calls, try P.firstCall(requests, index), ch, common.io, bridge);
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
    const encoded_truths = try a.alloc(TruthEncoded, truths.len);
    errdefer a.free(encoded_truths);
    var finished_truths: usize = 0;
    errdefer for (encoded_truths[0..finished_truths]) |e| a.free(e.bytes);
    for (truth_workers, truths, encoded_truths, 0..) |*tw, t, *encoded, index| {
        const tf0 = try t.setup.logs(a, 0);
        defer a.free(tf0);
        const tf1 = try t.setup.logs(a, 1);
        defer a.free(tf1);
        if (!std.meta.eql(try actual(a, &tw.scheme, t.setup.key.root, tf0, tf1), manifest.roots[setups.len + index])) return error.SharedTruthStage1Mismatch;
        const ch = try P.drawTruthFor(mode, &tw.channel, &manifest, index);
        const claims = [3]Q{ try K.interaction.generate(&tw.source.permutation, ch), try tw.source.chi.generateInteraction(ch), try tw.source.xor5.generateInteraction(ch) };
        tw.channel.mixFelts(&claims);
        const ti = try tw.source.columns(a, 2);
        defer a.free(ti);
        try tw.scheme.commitBorrowedStreaming(a, ti, 8, &tw.channel);
        var components = truthComponents(t.setup, t.first_id, t.calls, ch, claims);
        var handles: [3]engine.air.component_prover.ComponentProver = undefined;
        for (&components, &handles) |*c, *h| h.* = c.asProverComponent();
        tw.owns = false;
        var proof = try engine.prove.prove(Backend, G.T.P.Hasher, G.T.P.MerkleChannel, a, &handles, &tw.channel, tw.scheme);
        defer proof.deinit(a);
        encoded.* = .{ .bytes = try wire.encodeProofBytesBinary(a, proof), .claims = claims };
        finished_truths += 1;
    }
    return .{ .manifest = manifest, .cpus = cpus, .truths = encoded_truths };
}

fn checkRoots(proof: anytype, key: [32]u8, manifest: *const G.Manifest, index: usize) !void {
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, G.T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.SharedTruthPcsSuiteMismatch;
    const roots = pcs.commitments.items;
    if (!std.mem.eql(u8, &roots[0], &key) or !std.mem.eql(u8, &roots[0], &manifest.roots[index].fixed.bytes) or !std.mem.eql(u8, &roots[1], &manifest.roots[index].main.bytes)) return error.SharedTruthStage1Mismatch;
}
pub fn verify(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truth: *const R.TruthSetup, expected: P.Expected, bundle: *const Bundle) !void {
    var calls: u32 = 0;
    for (bundle.cpus) |cpu| calls = try std.math.add(u32, calls, cpu.request.calls);
    var encoded_truth = [1]TruthEncoded{bundle.truth};
    const bounded = BoundedBundle{ .manifest = bundle.manifest, .cpus = bundle.cpus, .truths = &encoded_truth };
    return verifyInternal(a, setups, &.{.{ .setup = truth, .first_id = 1, .calls = calls }}, expected, &bounded, .single_v2);
}
pub fn verifyBounded(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const P.Truth, expected: P.Expected, bundle: *const BoundedBundle) !void {
    return verifyInternal(a, setups, truths, expected, bundle, .bounded_v3);
}
fn verifyInternal(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const P.Truth, expected: P.Expected, bundle: *const BoundedBundle, mode: P.Mode) !void {
    if (setups.len != bundle.cpus.len) return error.InvalidSharedTruthInventory;
    const requests = try a.alloc(P.Request, setups.len);
    defer a.free(requests);
    for (bundle.cpus, requests) |c, *r| r.* = c.request;
    _ = try P.admitBounded(a, setups, truths, requests, expected);
    if (bundle.truths.len != truths.len) return error.IncompleteGlobalExecutionManifest;
    const specs = try a.alloc([32]u8, setups.len + truths.len);
    defer a.free(specs);
    var first: u64 = 0;
    for (setups, requests, specs[0..setups.len], 0..) |s, r, *spec, index| {
        var ch = G.T.P.Channel{};
        try P.beginCpuFor(mode, &ch, s, r, expected, index, first, try P.firstCall(requests, index), truths.len);
        first += r.base.cpu.steps;
        spec.* = ch.digestBytes();
    }
    for (truths, 0..) |t, index| {
        var ch = G.T.P.Channel{};
        P.beginTruthFor(mode, &ch, t, expected, index, truths.len);
        specs[setups.len + index] = ch.digestBytes();
    }
    try bundle.manifest.check(specs);
    const common = if (mode == .single_v2) try P.shared(&bundle.manifest) else try P.sharedBounded(&bundle.manifest);
    var ram = Q.zero();
    var io = Q.zero();
    for (setups, bundle.cpus, 0..) |s, encoded, index| {
        try encoded.claims.canonical();
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.SharedTruthProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        try checkRoots(proof, s.key.root, &bundle.manifest, index);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, G.T.P.config());
        defer verifier.deinit(a);
        var channel = G.T.P.Channel{};
        var before: u64 = 0;
        for (requests[0..index]) |r| before += r.base.cpu.steps;
        try P.beginCpuFor(mode, &channel, s, encoded.request, expected, index, before, try P.firstCall(requests, index), truths.len);
        const roots = proof.commitment_scheme_proof.commitments.items;
        for (0..2) |tree| {
            const logs = try s.logs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, roots[tree], logs, &channel);
        }
        const ch = try P.drawCpuFor(mode, &channel, &bundle.manifest, index);
        if (!encoded.claims.base.initial.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.base.memory.initial, true, common.ram)) or !encoded.claims.base.terminal.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.base.memory.terminal, false, common.ram))) return error.GlobalBoundaryPhysicalClaimMismatch;
        channel.mixFelts(&encoded.claims.values());
        const logs = try s.logs(a, 2);
        defer a.free(logs);
        try verifier.commit(a, roots[2], logs, &channel);
        var bc = try Components.init(&s.materials, encoded.request.base, ch, encoded.claims.base);
        var bb = cpuBridge(s, encoded.request.calls, try P.firstCall(requests, index), ch, common.io, encoded.claims.bridge);
        const handles = try cpuVerifierHandles(a, &bc, &bb);
        defer a.free(handles);
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
        try encoded.claims.local();
        ram = ram.add(encoded.claims.ram());
        io = io.add(encoded.claims.bridge.io);
    }
    for (truths, bundle.truths, 0..) |t, encoded, index| {
        for (encoded.claims) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSharedTruthClaim;
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.SharedTruthProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        try checkRoots(proof, t.setup.key.root, &bundle.manifest, setups.len + index);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, G.T.P.config());
        defer verifier.deinit(a);
        const roots = proof.commitment_scheme_proof.commitments.items;
        var tch = G.T.P.Channel{};
        P.beginTruthFor(mode, &tch, t, expected, index, truths.len);
        for (0..2) |tree| {
            const logs = try t.setup.logs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, roots[tree], logs, &tch);
        }
        const ch = try P.drawTruthFor(mode, &tch, &bundle.manifest, index);
        tch.mixFelts(&encoded.claims);
        const logs = try t.setup.logs(a, 2);
        defer a.free(logs);
        try verifier.commit(a, roots[2], logs, &tch);
        var components = truthComponents(t.setup, t.first_id, t.calls, ch, encoded.claims);
        var handles: [3]core.air.components.Component = undefined;
        for (&components, &handles) |*c, *h| h.* = c.asVerifierComponent();
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, &handles, &tch, &verifier, proof);
        for (encoded.claims) |q| io = io.add(q);
    }
    if (!ram.isZero()) return error.UnclosedSharedTruthRam;
    if (!io.isZero()) return error.UnclosedSharedTruthIo;
}
