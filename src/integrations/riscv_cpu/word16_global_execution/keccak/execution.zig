//! Versioned Keccak global-RAM prefix. Real CPU+K+RAM proofs, not a host service
//! oracle. All fixed/MAIN roots precede shared RAM and local OWNER/IO draws.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const R = @import("roster.zig");
const P = @import("../protocol.zig");
const OldSource = @import("../../word16_execution/sources.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Memory = @import("../../word16_execution/memory/prepared.zig").Prepared;
const CoreComponents = @import("../../word16_execution/components.zig").Components;
const Collector = @import("collector.zig");
const Q = P.Q;
const Cell = A.memory.closed_ram.types.Cell;
pub const Request = struct { base: P.Old.Request, calls: u32 };
pub const Claims = struct {
    base: P.Old.Claims,
    keccak: R.Claims,
    pub fn values(self: @This()) [41]Q {
        var out: [41]Q = undefined;
        out[0..33].* = self.base.values();
        out[33..].* = self.keccak.values();
        return out;
    }
    pub fn validateCanonical(self: @This()) !void {
        try OldSource.validateCanonicalClaims(self.base);
        for (self.keccak.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalServiceClaim;
    }
    pub fn validate(self: @This()) !void {
        try self.validateCanonical();
        var local = Q.zero();
        for (self.values()) |q| local = local.add(q);
        local = local.sub(self.base.ls.ram).sub(self.base.initial.ram).sub(self.base.terminal.ram).sub(self.keccak.bridge.ram);
        if (!local.isZero()) return error.UnclosedLocalKeccakRelations;
    }
};
pub const Encoded = struct {
    bytes: []u8,
    request: Request,
    claims: Claims,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.request.base.memory.initial);
        a.free(self.request.base.memory.terminal);
    }
};
pub const Bundle = struct {
    manifest: P.Manifest,
    proofs: []Encoded,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.proofs) |*p| p.deinit(a);
        a.free(self.proofs);
        self.manifest.deinit();
    }
};
fn begin(ch: *P.T.P.Channel, setup: *const R.Setup, request: Request, expected: P.Expected, ordinal: usize, first: u64) !void {
    try P.begin(ch, &setup.base, request.base, expected, ordinal, first);
    ch.mixU32s(&.{ 0x57474b45, 1, 19, 14, 11, 41, 25, request.calls, setup.geo.klog, setup.geo.blog });
}
fn draw(ch: *P.T.P.Channel, manifest: *const P.Manifest, ordinal: usize) !struct { base: P.Old.Draw, keccak: K.equations.Challenges } {
    const base = try P.draw(ch, manifest, ordinal);
    ch.mixU32s(&.{ 0x57474b49, 1, 11, 6 });
    return .{ .base = base, .keccak = K.equations.Challenges.draw(ch) };
}
fn validate(a: std.mem.Allocator, setups: []const *const R.Setup, requests: []const Request, expected: P.Expected) !void {
    if (setups.len == 0 or setups.len != requests.len) return error.InvalidServiceExecutionRoster;
    const bases = try a.alloc(*const P.Setup, setups.len);
    defer a.free(bases);
    const rr = try a.alloc(P.Old.Request, setups.len);
    defer a.free(rr);
    var mass: u64 = 0;
    for (setups, requests, bases, rr) |s, r, *b, *old| {
        b.* = &s.base;
        old.* = r.base;
        try K.layout.validateGeometry(r.calls, 1, s.geo.klog);
        _ = try K.word16_bridge.types.validateGeometry(r.calls, 1, s.geo.blog);
        if (r.calls > r.base.cpu.steps or @as(u64, r.calls) + r.base.memory.ls_count > r.base.cpu.steps) return error.InvalidServiceCount;
        const mass16 = try std.math.add(u64, try s.base.materials.geometry.range16Mass(), 22 * (@as(u64, 1) << @intCast(s.geo.blog)));
        const mass8 = try std.math.add(u64, try s.base.materials.geometry.range8Mass(), 19 * (@as(u64, 1) << @intCast(s.geo.blog)));
        if (mass16 >= core.fields.m31.Modulus or mass8 >= core.fields.m31.Modulus) return error.ServiceRangeMassBound;
        mass = try std.math.add(u64, mass, 50 * @as(u64, r.calls) + 2 * @as(u64, r.base.memory.ls_count));
    }
    try P.validateRequests(bases, rr, expected);
    mass = try std.math.add(u64, mass, rr[0].memory.initial.len + rr[rr.len - 1].memory.terminal.len);
    if (mass >= core.fields.m31.Modulus) return error.GlobalRamCharacteristicBound;
}
const Worker = struct {
    a: std.mem.Allocator,
    setup: *const R.Setup,
    source: OldSource.Source,
    k: R.Source,
    request: Request,
    scheme: P.T.Scheme,
    ch: P.T.P.Channel,
    roots: P.Receipt,
    owns: bool = true,
    fn deinit(self: *Worker) void {
        if (self.owns) self.scheme.deinit(self.a);
        self.source.deinit();
        self.k.deinit();
    }
};
fn actual(a: std.mem.Allocator, scheme: *P.T.Scheme, setup: *const R.Setup) !P.Receipt {
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2 or !std.mem.eql(u8, &roots.items[0], &setup.fixed_root)) return error.ServiceStage1RootMismatch;
    for (0..2) |tree| {
        const logs = try setup.columnLogs(a, tree);
        defer a.free(logs);
        if (logs.len != scheme.trees.items[tree].columns.len) return error.ServiceStage1GeometryMismatch;
        for (logs, scheme.trees.items[tree].columns) |log, col| if (col.log_size != log + P.T.P.config().fri_config.log_blowup_factor) return error.ServiceStage1GeometryMismatch;
    }
    return .{ .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
}
/// Bounded qualification harness. Worker PCS owners remain local here; this is
/// not an unbounded multi-process coordinator or a full-block certificate.
pub fn produce(a: std.mem.Allocator, setups: []const *const R.Setup, prepared: []const *Native, advice: *const Collector.Advice, expected: P.Expected) !Bundle {
    if (setups.len != prepared.len or setups.len != advice.events.len or setups.len != advice.calls.len) return error.InvalidServiceExecutionRoster;
    const requests = try a.alloc(Request, setups.len);
    defer a.free(requests);
    for (prepared, requests, 0..) |n, *r, index| {
        const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
        r.* = .{ .calls = @intCast(advice.calls[index].len), .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (index == 0) advice.initial else &.{}, .terminal = if (index + 1 == setups.len) advice.terminal else &.{}, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[index].len) } } };
    }
    try validate(a, setups, requests, expected);
    const workers = try a.alloc(Worker, setups.len);
    defer a.free(workers);
    var done: usize = 0;
    defer for (workers[0..done]) |*w| w.deinit();
    const specs = try a.alloc([32]u8, setups.len);
    defer a.free(specs);
    const roots = try a.alloc(P.Receipt, setups.len);
    defer a.free(roots);
    var first: u64 = 0;
    for (setups, prepared, requests, 0..) |s, n, r, index| {
        const initial = try a.dupe(Cell, r.base.memory.initial);
        const terminal = a.dupe(Cell, r.base.memory.terminal) catch |err| {
            a.free(initial);
            return err;
        };
        const mem = try Memory.initOwnedForGlobalRamIndependent(a, advice.events[index], initial, terminal, r.base.epoch, s.base.materials.geometry.ls_log, s.base.materials.geometry.initialLog(), s.base.materials.geometry.terminalLog());
        var source = try OldSource.Source.fromPreparedWithOwnedMemory(a, &s.base.materials, n, mem);
        errdefer source.deinit();
        var k = try R.Source.init(a, advice.calls[index], s.geo);
        errdefer k.deinit();
        try k.mergeRanges(&source);
        var scheme = try P.T.Scheme.init(a, P.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var ch = P.T.P.Channel{};
        try begin(&ch, s, r, expected, index, first);
        first += r.base.cpu.steps;
        specs[index] = ch.digestBytes();
        try s.appendFixed(a, &scheme, &ch);
        const main = try k.columns(a, &source, 1);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, main, 8, &ch);
        try source.releaseMain();
        try k.releaseMain();
        roots[index] = try actual(a, &scheme, s);
        workers[index] = .{ .a = a, .setup = s, .source = source, .k = k, .request = r, .scheme = scheme, .ch = ch, .roots = roots[index] };
        done += 1;
    }
    var manifest = try P.Manifest.init(a, specs, roots);
    errdefer manifest.deinit();
    const proofs = try a.alloc(Encoded, setups.len);
    errdefer a.free(proofs);
    var finished: usize = 0;
    errdefer for (proofs[0..finished]) |*p| p.deinit(a);
    for (workers, proofs, 0..) |*w, *encoded, index| {
        if (!std.meta.eql(try actual(a, &w.scheme, w.setup), manifest.roots[index])) return error.ServiceStage1RootMismatch;
        const ch = try draw(&w.ch, &manifest, index);
        const claims = Claims{ .base = (try w.source.generateForKeccakJoin(ch.base)).physical, .keccak = try w.k.generate(ch.keccak, ch.base, w.source.range16.dictionary, w.source.range8.dictionary) };
        w.ch.mixFelts(&claims.values());
        const inter = try w.k.columns(a, &w.source, 2);
        defer a.free(inter);
        try w.scheme.commitBorrowedStreaming(a, inter, 8, &w.ch);
        var bc = try CoreComponents.init(&w.setup.base.materials, w.request.base, ch.base, claims.base);
        const bh = try bc.provers(a);
        defer a.free(bh);
        var kc = R.Components.init(w.setup, w.request.calls, ch.keccak, ch.base, claims.keccak);
        const kh = try kc.proverHandles();
        const handles = try a.alloc(engine.air.component_prover.ComponentProver, bh.len + 4);
        defer a.free(handles);
        @memcpy(handles[0..bh.len], bh);
        @memcpy(handles[bh.len..], &kh);
        w.owns = false;
        var proof = try engine.prove.prove(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &w.ch, w.scheme);
        defer proof.deinit(a);
        const bytes = try wire.encodeProofBytesBinary(a, proof);
        errdefer a.free(bytes);
        var req = w.request;
        req.base.memory.initial = try a.dupe(Cell, req.base.memory.initial);
        errdefer a.free(req.base.memory.initial);
        req.base.memory.terminal = try a.dupe(Cell, req.base.memory.terminal);
        encoded.* = .{ .bytes = bytes, .request = req, .claims = claims };
        finished += 1;
    }
    return .{ .manifest = manifest, .proofs = proofs };
}
pub fn verify(a: std.mem.Allocator, setups: []const *const R.Setup, expected: P.Expected, bundle: *const Bundle) !void {
    if (setups.len != bundle.proofs.len) return error.InvalidServiceExecutionRoster;
    const requests = try a.alloc(Request, setups.len);
    defer a.free(requests);
    for (bundle.proofs, requests) |p, *r| r.* = p.request;
    try validate(a, setups, requests, expected);
    const specs = try a.alloc([32]u8, setups.len);
    defer a.free(specs);
    var first: u64 = 0;
    for (setups, requests, specs, 0..) |s, r, *spec, index| {
        var ch = P.T.P.Channel{};
        try begin(&ch, s, r, expected, index, first);
        spec.* = ch.digestBytes();
        first += r.base.cpu.steps;
    }
    try bundle.manifest.check(specs);
    var total = Q.zero();
    for (setups, bundle.proofs, 0..) |s, encoded, index| {
        try encoded.claims.validateCanonical();
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.ServiceProofResourceLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        const pcs = &proof.commitment_scheme_proof;
        if (!std.meta.eql(pcs.config, P.T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.GlobalPcsSuiteMismatch;
        const roots = pcs.commitments.items;
        if (!std.mem.eql(u8, &roots[0], &s.fixed_root) or !std.mem.eql(u8, &roots[0], &bundle.manifest.roots[index].fixed.bytes) or !std.mem.eql(u8, &roots[1], &bundle.manifest.roots[index].main.bytes)) return error.ServiceStage1RootMismatch;
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(P.T.P.Hasher, P.T.P.MerkleChannel).init(a, P.T.P.config());
        defer verifier.deinit(a);
        var channel = P.T.P.Channel{};
        var before: u64 = 0;
        for (requests[0..index]) |r| before += r.base.cpu.steps;
        try begin(&channel, s, encoded.request, expected, index, before);
        for (0..2) |tree| {
            const logs = try s.columnLogs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, roots[tree], logs, &channel);
        }
        const ch = try draw(&channel, &bundle.manifest, index);
        if (!encoded.claims.base.initial.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.base.memory.initial, true, ch.base.memory.ram)) or !encoded.claims.base.terminal.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.base.memory.terminal, false, ch.base.memory.ram))) return error.GlobalBoundaryPhysicalClaimMismatch;
        channel.mixFelts(&encoded.claims.values());
        const logs = try s.columnLogs(a, 2);
        defer a.free(logs);
        try verifier.commit(a, roots[2], logs, &channel);
        var bc = try CoreComponents.init(&s.base.materials, encoded.request.base, ch.base, encoded.claims.base);
        const bh = try bc.verifiers(a);
        defer a.free(bh);
        var kc = R.Components.init(s, encoded.request.calls, ch.keccak, ch.base, encoded.claims.keccak);
        const kh = try kc.verifierHandles();
        const handles = try a.alloc(core.air.components.Component, bh.len + 4);
        defer a.free(handles);
        @memcpy(handles[0..bh.len], bh);
        @memcpy(handles[bh.len..], &kh);
        owns = false;
        try core.verifier.verify(P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
        try encoded.claims.validate();
        for (encoded.claims.values()) |q| total = total.add(q);
    }
    if (!total.isZero()) return error.UnclosedGlobalKeccakExecution;
}
