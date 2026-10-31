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
const K = A.crypto.keccak;
const KB = K.word16_bridge;
const T = @import("types.zig");
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
    extras: [3]T.ExtraClaims,
    pub fn values(self: @This()) [P.CPU_CLAIM_COUNT]Q {
        var out: [P.CPU_CLAIM_COUNT]Q = undefined;
        out[0..P.CORE_CLAIM_COUNT].* = self.base.values();
        for (self.extras, 0..) |extra, k| out[P.CORE_CLAIM_COUNT + 5 * k ..][0..5].* = extra.values();
        return out;
    }
    pub fn canonical(self: @This()) !void {
        try Source.validateCanonicalClaims(self.base);
        for (self.extras) |b| for (b.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
    }
    pub fn presence(self: @This(), setup: *const R.CpuSetup) !void {
        for (self.extras, 0..) |c, k| if (setup.bridges.at(@enumFromInt(k)) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
    }
    pub fn ram(self: @This()) Q {
        const base = G.Old.ramClaim(self.base);
        var sum = base;
        for (self.extras) |c| sum = sum.add(c.ram);
        return sum;
    }
    pub fn local(self: @This()) !void {
        var sum = Q.zero();
        for (self.values()) |v| sum = sum.add(v);
        sum = sum.sub(self.ram());
        for (self.extras) |c| sum = sum.sub(c.truth);
        if (!sum.isZero()) return error.UnclosedCombinedCpuRelations;
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
    truths: []TruthEncoded,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.cpus) |*p| p.deinit(a);
        a.free(self.cpus);
        for (self.truths) |t| a.free(t.bytes);
        a.free(self.truths);
        self.manifest.deinit();
    }
};
const CpuWorker = struct {
    source: R.Sources,
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
    if (!std.meta.eql(scheme.config, G.T.P.config()) or scheme.revision_config != null) return error.CombinedPcsSuiteMismatch;
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2 or !std.mem.eql(u8, &roots.items[0], &key)) return error.CombinedStage1Mismatch;
    for ([2][]const u32{ logs0, logs1 }, 0..) |logs, tree| {
        if (logs.len != scheme.trees.items[tree].columns.len) return error.CombinedStage1Mismatch;
        for (logs, scheme.trees.items[tree].columns) |log, col| if (col.log_size != log + G.T.P.config().fri_config.log_blowup_factor) return error.CombinedStage1Mismatch;
    }
    return .{ .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
}
const Bridges = struct {
    keccak: ?KB.component.Component = null,
    add: ?B.component.Component = null,
    double: ?B.component.Component = null,
    fn init(setup: *const R.CpuSetup, calls: [3]u32, first: [3]u32, ch: G.Old.Draw, common: P.Shared, claims: [3]T.ExtraClaims) Bridges {
        var out = Bridges{};
        for (0..3) |k| {
            const family: T.Family = @enumFromInt(k);
            const log = setup.bridges.at(family) orelse continue;
            const offsets = [3]usize{ setup.offset(family, 0), setup.offset(family, 1), setup.offset(family, 2) };
            if (k == 0) {
                out.keccak = .{ .kind = .bridge, .log_size = log, .rows = calls[0], .first_id = first[0], .offsets = offsets, .claims = claims[0].toK(), .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = common.kio, .range16 = ch.memory.range16, .range8 = ch.memory.range8 } };
            } else {
                const component = B.component.Component{ .kind = @enumFromInt(k), .log_size = log, .rows = calls[k], .first_id = first[k], .offsets = offsets, .claims = claims[k].toSecp(), .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .wire = common.wire, .range16 = ch.memory.range16, .range8 = ch.memory.range8 } };
                if (k == 1) out.add = component else out.double = component;
            }
        }
        return out;
    }
    fn count(self: *const Bridges) usize {
        return @intFromBool(self.keccak != null) + @as(usize, @intFromBool(self.add != null)) + @intFromBool(self.double != null);
    }
};
fn cpuHandles(a: std.mem.Allocator, base: *const Components, bridges: *const Bridges) ![]engine.air.component_prover.ComponentProver {
    const old = try base.provers(a);
    defer a.free(old);
    const out = try a.alloc(engine.air.component_prover.ComponentProver, old.len + bridges.count());
    @memcpy(out[0..old.len], old);
    var at = old.len;
    inline for (.{ "keccak", "add", "double" }) |name| if (@field(bridges, name)) |*c| {
        out[at] = c.asProverComponent();
        at += 1;
    };
    return out;
}
fn cpuVerifierHandles(a: std.mem.Allocator, base: *const Components, bridges: *const Bridges) ![]core.air.components.Component {
    const old = try base.verifiers(a);
    defer a.free(old);
    const out = try a.alloc(core.air.components.Component, old.len + bridges.count());
    @memcpy(out[0..old.len], old);
    var at = old.len;
    inline for (.{ "keccak", "add", "double" }) |name| if (@field(bridges, name)) |*c| {
        out[at] = c.asVerifierComponent();
        at += 1;
    };
    return out;
}
const TruthComponents = union(enum) {
    keccak: [3]K.component.Component,
    secp: @import("../secp/execution.zig").TruthComponents,
    fn init(truth: R.Truth, ch: P.TruthDraw, claims: [3]Q) !TruthComponents {
        return switch (truth) {
            .keccak => |t| switch (ch) {
                .keccak => |kc| .{ .keccak = @import("../keccak/shared/execution.zig").truthComponents(t.setup, t.first_id, t.calls, kc, claims) },
                else => error.InvalidCombinedTruthChallenge,
            },
            .secp => |t| switch (ch) {
                .secp => |sc| .{ .secp = @import("../secp/execution.zig").TruthComponents.initSpan(t.setup, t.first_id, t.calls, sc, claims) },
                else => error.InvalidCombinedTruthChallenge,
            },
        };
    }
    fn provers(self: *const TruthComponents) [3]engine.air.component_prover.ComponentProver {
        return switch (self.*) {
            .keccak => |*c| .{ c[0].asProverComponent(), c[1].asProverComponent(), c[2].asProverComponent() },
            .secp => |*c| c.provers(),
        };
    }
    fn verifiers(self: *const TruthComponents) [3]core.air.components.Component {
        return switch (self.*) {
            .keccak => |*c| .{ c[0].asVerifierComponent(), c[1].asVerifierComponent(), c[2].asVerifierComponent() },
            .secp => |*c| c.verifiers(),
        };
    }
};
fn generateTruth(source: *R.TruthSource, ch: P.TruthDraw) ![3]Q {
    return switch (source.*) {
        .keccak => |*s| switch (ch) {
            .keccak => |kc| .{ try K.interaction.generate(&s.permutation, kc), try s.chi.generateInteraction(kc), try s.xor5.generateInteraction(kc) },
            else => error.InvalidCombinedTruthChallenge,
        },
        .secp => |*s| switch (ch) {
            .secp => |sc| .{ try s.batch.product.generateInteraction(sc), try s.batch.linear.generateInteraction(sc), try s.bytes.generateInteraction(sc.bytes) },
            else => error.InvalidCombinedTruthChallenge,
        },
    };
}
fn memory(a: std.mem.Allocator, events: []const A.memory.load_store_v2.native.Event, initial: []Cell, terminal: []Cell, epoch: u16, g: @import("../../word16_execution/setup.zig").Geometry) !Memory {
    return Memory.initOwnedForGlobalRamLadderIndependent(a, events, initial, terminal, epoch, g.ls_log, g.ls_tail_log, g.initialLog(), g.terminalLog());
}
/// Bounded qualification harness: coordinator retains several PCS owners here.
/// No claim of fitting arbitrary execution fanout in one process is made.
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, prepared: []const *Native, advice: *const Advice, expected: P.Expected) !Bundle {
    if (setups.len != prepared.len or setups.len != advice.events.len or setups.len != advice.keccak.len or setups.len != advice.secp.len) return error.InvalidCombinedInventory;
    const requests = try a.alloc(P.Request, setups.len);
    defer a.free(requests);
    for (prepared, requests, 0..) |n, *r, index| {
        const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
        r.* = .{ .calls = .{ @intCast(advice.keccak[index].len), @intCast(advice.secp[index][0].len), @intCast(advice.secp[index][1].len) }, .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (index == 0) advice.initial else &.{}, .terminal = if (index + 1 == setups.len) advice.terminal else &.{}, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[index].len) } } };
    }
    _ = try P.admit(a, setups, truths, requests, expected);
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
        const mem = try memory(a, advice.events[index], initial, terminal, r.base.epoch, s.materials.geometry);
        var source = block: {
            var base = try Source.Source.fromPreparedWithOwnedMemory(a, &s.materials, n, mem);
            errdefer base.deinit();
            var kk: ?KB.source.Source = null;
            errdefer if (kk) |*b| b.deinit();
            var aa: ?B.source.Source = null;
            errdefer if (aa) |*b| b.deinit();
            var dd: ?B.source.Source = null;
            errdefer if (dd) |*b| b.deinit();
            const ids = try P.firstIds(requests, index);
            if (s.bridges.keccak) |log| kk = try KB.source.Source.init(a, advice.keccak[index], ids[0], log);
            if (s.bridges.add) |log| aa = try B.source.Source.init(a, .add, advice.secp[index][0], ids[1], log);
            if (s.bridges.double) |log| dd = try B.source.Source.init(a, .double, advice.secp[index][1], ids[2], log);
            break :block R.Sources{ .core = base, .keccak = kk, .add = aa, .double = dd };
        };
        errdefer source.deinit();
        try source.mergeRanges();
        var scheme = try G.T.Scheme.init(a, G.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = G.T.P.Channel{};
        try P.beginCpu(&channel, s, r, expected, index, first_step, try P.firstIds(requests, index));
        first_step += r.base.cpu.steps;
        specs[index] = channel.digestBytes();
        try s.key.append(a, &scheme, &channel);
        const owned = try source.takeMain(s);
        try scheme.commitOwnedStreamingWithRecorderAndBacking(a, owned.columns, owned.backings, 8, null, &channel);
        const l0 = try s.logs(a, 0);
        defer a.free(l0);
        const l1 = try s.logs(a, 1);
        defer a.free(l1);
        receipts[index] = try actual(a, &scheme, s.key.root, l0, l1);
        workers[index] = .{ .source = source, .scheme = scheme, .channel = channel };
        done += 1;
    }
    const truth_workers = try a.alloc(TruthWorker, truths.len);
    defer a.free(truth_workers);
    var truth_done: usize = 0;
    defer for (truth_workers[0..truth_done]) |*w| w.deinit(a);
    for (truths, truth_workers, 0..) |truth, *w, k| {
        var ts = try R.TruthSource.init(a, truth, advice);
        errdefer ts.deinit();
        var scheme = try G.T.Scheme.init(a, G.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, expected, k);
        specs[setups.len + k] = channel.digestBytes();
        try truth.key().append(a, &scheme, &channel);
        const main = try ts.columns(a, 1);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, main, 8, &channel);
        try ts.releaseMain();
        const l0 = try truth.logs(a, 0);
        defer a.free(l0);
        const l1 = try truth.logs(a, 1);
        defer a.free(l1);
        receipts[setups.len + k] = try actual(a, &scheme, truth.key().root, l0, l1);
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
        if (!std.meta.eql(try actual(a, &w.scheme, s.key.root, l0, l1), manifest.roots[index])) return error.CombinedStage1Mismatch;
        const ch = try P.drawCpu(&w.channel, &manifest, index);
        const base = (try w.source.core.generateForDelegationJoin(ch)).physical;
        var extras: [3]T.ExtraClaims = @splat(T.ExtraClaims.zero());
        if (w.source.keccak) |*b| extras[0] = T.ExtraClaims.fromK(try b.generate(.{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = common.kio, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, w.source.core.range16.dictionary, w.source.core.range8.dictionary));
        inline for (.{ "add", "double" }, 1..) |name, k| if (@field(w.source, name)) |*b| {
            extras[k] = T.ExtraClaims.fromSecp(try b.generate(.{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .wire = common.wire, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, w.source.core.range16.dictionary, w.source.core.range8.dictionary));
        };
        const claims = CpuClaims{ .base = base, .extras = extras };
        try claims.presence(s);
        w.channel.mixFelts(&claims.values());
        const inter = try w.source.takeInteraction(s);
        try w.scheme.commitOwnedStreamingWithRecorderAndBacking(a, inter.columns, inter.backings, 8, null, &w.channel);
        var bc = try Components.init(&s.materials, r.base, ch, base);
        var bb = Bridges.init(s, r.calls, try P.firstIds(requests, index), ch, common, extras);
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
    errdefer for (encoded_truths[0..finished_truths]) |t| a.free(t.bytes);
    for (truth_workers, truths, 0..) |*tw, truth, k| {
        const l0 = try truth.logs(a, 0);
        defer a.free(l0);
        const l1 = try truth.logs(a, 1);
        defer a.free(l1);
        if (!std.meta.eql(try actual(a, &tw.scheme, truth.key().root, l0, l1), manifest.roots[setups.len + k])) return error.CombinedStage1Mismatch;
        const ch = try P.drawTruth(&tw.channel, &manifest, truth, k);
        const claims = try generateTruth(&tw.source, ch);
        tw.channel.mixFelts(&claims);
        const inter = try tw.source.columns(a, 2);
        defer a.free(inter);
        try tw.scheme.commitBorrowedStreaming(a, inter, 8, &tw.channel);
        var components = try TruthComponents.init(truth, ch, claims);
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
    if (!std.meta.eql(pcs.config, G.T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.CombinedPcsSuiteMismatch;
    const roots = pcs.commitments.items;
    if (!std.mem.eql(u8, &roots[0], &key) or !std.mem.eql(u8, &roots[0], &manifest.roots[index].fixed.bytes) or !std.mem.eql(u8, &roots[1], &manifest.roots[index].main.bytes)) return error.CombinedStage1Mismatch;
}
pub fn verify(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, bundle: *const Bundle) !void {
    if (setups.len != bundle.cpus.len or truths.len != bundle.truths.len) return error.InvalidCombinedInventory;
    const requests = try a.alloc(P.Request, setups.len);
    defer a.free(requests);
    for (bundle.cpus, requests) |c, *r| r.* = c.request;
    _ = try P.admit(a, setups, truths, requests, expected);
    const specs = try a.alloc([32]u8, setups.len + truths.len);
    defer a.free(specs);
    var first: u64 = 0;
    for (setups, requests, specs[0..setups.len], 0..) |s, r, *spec, index| {
        var ch = G.T.P.Channel{};
        try P.beginCpu(&ch, s, r, expected, index, first, try P.firstIds(requests, index));
        first += r.base.cpu.steps;
        spec.* = ch.digestBytes();
    }
    for (truths, 0..) |truth, k| {
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, expected, k);
        specs[setups.len + k] = channel.digestBytes();
    }
    try bundle.manifest.check(specs);
    const common = try P.shared(&bundle.manifest);
    var ram = Q.zero();
    var io = Q.zero();
    var wire_sum = Q.zero();
    for (setups, bundle.cpus, 0..) |s, encoded, index| {
        try encoded.claims.canonical();
        try encoded.claims.presence(s);
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.CombinedProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        try checkRoots(proof, s.key.root, &bundle.manifest, index);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, G.T.P.config());
        defer verifier.deinit(a);
        var channel = G.T.P.Channel{};
        var before: u64 = 0;
        for (requests[0..index]) |r| before += r.base.cpu.steps;
        try P.beginCpu(&channel, s, encoded.request, expected, index, before, try P.firstIds(requests, index));
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
        var bb = Bridges.init(s, encoded.request.calls, try P.firstIds(requests, index), ch, common, encoded.claims.extras);
        const handles = try cpuVerifierHandles(a, &bc, &bb);
        defer a.free(handles);
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
        try encoded.claims.local();
        ram = ram.add(encoded.claims.ram());
        io = io.add(encoded.claims.extras[0].truth);
        wire_sum = wire_sum.add(encoded.claims.extras[1].truth).add(encoded.claims.extras[2].truth);
    }
    for (truths, bundle.truths, 0..) |truth, encoded, k| {
        for (encoded.claims) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.CombinedProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        try checkRoots(proof, truth.key().root, &bundle.manifest, setups.len + k);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, G.T.P.config());
        defer verifier.deinit(a);
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, expected, k);
        const roots = proof.commitment_scheme_proof.commitments.items;
        for (0..2) |tree| {
            const logs = try truth.logs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, roots[tree], logs, &channel);
        }
        const ch = try P.drawTruth(&channel, &bundle.manifest, truth, k);
        channel.mixFelts(&encoded.claims);
        const logs = try truth.logs(a, 2);
        defer a.free(logs);
        try verifier.commit(a, roots[2], logs, &channel);
        var components = try TruthComponents.init(truth, ch, encoded.claims);
        const handles = components.verifiers();
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, &handles, &channel, &verifier, proof);
        for (encoded.claims) |q| if (truth.family() == .keccak) {
            io = io.add(q);
        } else {
            wire_sum = wire_sum.add(q);
        };
    }
    if (!ram.isZero()) return error.UnclosedCombinedRam;
    if (!io.isZero()) return error.UnclosedCombinedKeccakIo;
    if (!wire_sum.isZero()) return error.UnclosedCombinedSecpWire;
}
