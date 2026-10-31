//! Actual multi-PCS no-services execution prefix. Complete stage1 roots precede
//! shared RAM randomness; the receiver fresh-verifies EVERY physical shard.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const P = @import("protocol.zig");
const S = @import("../word16_execution/sources.zig");
const Native = @import("../word16_execution/prepared.zig").Prepared;
const Memory = @import("../word16_execution/memory/prepared.zig").Prepared;
const Components = @import("../word16_execution/components.zig").Components;
const Ledger = @import("collector.zig").Ledger;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const Cell = A.memory.closed_ram.types.Cell;
const Event = A.memory.load_store_v2.native.Event;
const Q = P.Q;
pub const Encoded = struct {
    bytes: []u8,
    request: P.Old.Request,
    claims: P.Old.Claims,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.request.memory.initial);
        a.free(self.request.memory.terminal);
    }
};
pub const Bundle = struct {
    manifest: P.Manifest,
    proofs: []Encoded,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        for (self.proofs) |*p| p.deinit(a);
        a.free(self.proofs);
        self.manifest.deinit();
    }
};
pub const Advice = struct {
    allocator: std.mem.Allocator,
    events: [][]Event,
    initial: []Cell,
    terminal: []Cell,
    pub fn deinit(self: *Advice) void {
        for (self.events) |e| self.allocator.free(e);
        self.allocator.free(self.events);
        self.allocator.free(self.initial);
        self.allocator.free(self.terminal);
    }
};
/// One narrow ledger pass; returns the exact union size BEFORE selecting keys.
pub fn collectAdvice(a: std.mem.Allocator, prepared: []const *Native, image: @import("../word16_execution/memory/statement.zig").Image) !Advice {
    if (prepared.len == 0 or prepared.len > 65535) return error.InvalidGlobalExecutionRoster;
    var ledger = Ledger.init(a, image);
    defer ledger.deinit();
    const events = try a.alloc([]Event, prepared.len);
    errdefer a.free(events);
    var done: usize = 0;
    errdefer for (events[0..done]) |e| a.free(e);
    for (prepared, events, 0..) |native, *out, index| {
        const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
        if (cpu.epoch != index + 1) return error.InvalidGlobalExecutionEpoch;
        out.* = try ledger.shard(cpu.memory.items, cpu.epoch);
        done += 1;
    }
    const boundaries = try ledger.boundaries();
    return .{ .allocator = a, .events = events, .initial = boundaries.initial, .terminal = boundaries.terminal };
}
const Worker = struct {
    scheme: P.T.Scheme,
    channel: P.T.P.Channel,
    receipt: P.Receipt,
    owns: bool = true,
    fn deinit(self: *Worker, a: std.mem.Allocator) void {
        if (self.owns) self.scheme.deinit(a);
    }
};
fn checkStage1(a: std.mem.Allocator, scheme: *P.T.Scheme, setup: *const P.Setup) !P.Receipt {
    if (!std.meta.eql(scheme.config, P.T.P.config()) or scheme.revision_config != null) return error.GlobalPcsSuiteMismatch;
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2) return error.InvalidGlobalStage1;
    if (!std.mem.eql(u8, &roots.items[0], &setup.fixed_root.value)) return error.GlobalFixedRootMismatch;
    for (0..2) |tree| {
        const logs = try setup.materials.logs(a, tree);
        defer a.free(logs);
        if (logs.len != scheme.trees.items[tree].columns.len) return error.GlobalStage1GeometryMismatch;
        for (logs, scheme.trees.items[tree].columns) |log, col| if (col.log_size != log + P.T.P.config().fri_config.log_blowup_factor) return error.GlobalStage1GeometryMismatch;
    }
    return .{ .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
}
/// Advice is borrowed; every native event is copied once to provider metadata.
/// Source transfer consumes each native CPU/JALR on success or later error.
pub fn produceWithAdvice(a: std.mem.Allocator, setups: []const *const P.Setup, prepared: []const *Native, advice: *const Advice, expected: P.Expected) !Bundle {
    if (setups.len != prepared.len or setups.len != advice.events.len) return error.InvalidGlobalExecutionRoster;
    var sources: std.ArrayList(S.Source) = .empty;
    defer {
        for (sources.items) |*s| s.deinit();
        sources.deinit(a);
    }
    for (setups, prepared, 0..) |setup, native, index| {
        const initial = try a.dupe(Cell, if (index == 0) advice.initial else &.{});
        const terminal = a.dupe(Cell, if (index + 1 == setups.len) advice.terminal else &.{}) catch |err| {
            a.free(initial);
            return err;
        };
        const memory = try Memory.initOwnedForGlobalRam(a, advice.events[index], initial, terminal, @intCast(index + 1), setup.materials.geometry.ls_log, setup.materials.geometry.boundary_log);
        var source = try S.Source.fromPreparedWithOwnedMemory(a, &setup.materials, native, memory);
        errdefer source.deinit();
        try sources.append(a, source);
    }
    const requests = try a.alloc(P.Old.Request, sources.items.len);
    defer a.free(requests);
    for (sources.items, requests) |*source, *request| request.* = source.request();
    try P.validateRequests(setups, requests, expected);
    var workers: std.ArrayList(Worker) = .empty;
    defer {
        for (workers.items) |*worker| worker.deinit(a);
        workers.deinit(a);
    }
    const specs = try a.alloc([32]u8, setups.len);
    defer a.free(specs);
    const receipts = try a.alloc(P.Receipt, setups.len);
    defer a.free(receipts);
    var first: u64 = 0;
    for (setups, sources.items, requests, 0..) |setup, *source, request, index| {
        var scheme = try P.T.Scheme.init(a, P.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var ch = P.T.P.Channel{};
        try P.begin(&ch, setup, request, expected, index, first);
        specs[index] = ch.digestBytes();
        first += request.cpu.steps;
        try setup.appendFixed(a, &scheme, &ch);
        const main = try source.columns(a, 1);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, main, 8, &ch);
        try source.releaseMain();
        const receipt = try checkStage1(a, &scheme, setup);
        receipts[index] = receipt;
        try workers.append(a, .{ .scheme = scheme, .channel = ch, .receipt = receipt });
    }
    var manifest = try P.Manifest.init(a, specs, receipts);
    errdefer manifest.deinit();
    const proofs = try a.alloc(Encoded, setups.len);
    errdefer a.free(proofs);
    var completed: usize = 0;
    errdefer for (proofs[0..completed]) |*proof| proof.deinit(a);
    for (setups, sources.items, workers.items, 0..) |setup, *source, *worker, index| {
        const actual = try checkStage1(a, &worker.scheme, setup);
        if (!std.meta.eql(actual, manifest.roots[index])) return error.GlobalStage1RootMismatch;
        const ch = try P.draw(&worker.channel, &manifest, index);
        const claims = (try source.generateOpenForGlobalRam(ch)).physical;
        worker.channel.mixFelts(&claims.values());
        const interaction = try source.columns(a, 2);
        defer a.free(interaction);
        try worker.scheme.commitBorrowedStreaming(a, interaction, 8, &worker.channel);
        source.releaseCommittedInteraction();
        var components = try Components.init(&setup.materials, requests[index], ch, claims);
        const handles = try components.provers(a);
        defer a.free(handles);
        worker.owns = false;
        var proof = try engine.prove.prove(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &worker.channel, worker.scheme);
        defer proof.deinit(a);
        const bytes = try wire.encodeProofBytesBinary(a, proof);
        errdefer a.free(bytes);
        var request = requests[index];
        request.memory.initial = try a.dupe(Cell, request.memory.initial);
        errdefer a.free(request.memory.initial);
        request.memory.terminal = try a.dupe(Cell, request.memory.terminal);
        proofs[index] = .{ .bytes = bytes, .request = request, .claims = claims };
        completed += 1;
    }
    return .{ .manifest = manifest, .proofs = proofs };
}
/// Independently supplied setup owners MUST be reconstructed from the pristine
/// program authority and expected geometry. No setup or alpha comes from wire.
pub fn verify(a: std.mem.Allocator, setups: []const *const P.Setup, expected: P.Expected, bundle: *const Bundle) !void {
    if (setups.len != bundle.proofs.len) return error.InvalidGlobalExecutionRoster;
    const requests = try a.alloc(P.Old.Request, setups.len);
    defer a.free(requests);
    for (bundle.proofs, requests) |proof, *request| request.* = proof.request;
    try P.validateRequests(setups, requests, expected);
    const specs = try a.alloc([32]u8, setups.len);
    defer a.free(specs);
    var first: u64 = 0;
    for (setups, requests, 0..) |setup, request, index| {
        var ch = P.T.P.Channel{};
        try P.begin(&ch, setup, request, expected, index, first);
        first += request.cpu.steps;
        specs[index] = ch.digestBytes();
    }
    try bundle.manifest.check(specs);
    var total = Q.zero();
    for (setups, bundle.proofs, 0..) |setup, encoded, index| {
        try S.validateOpenForGlobalRam(encoded.claims);
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.GlobalExecutionProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        const pcs = &proof.commitment_scheme_proof;
        if (!std.meta.eql(pcs.config, P.T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.GlobalPcsSuiteMismatch;
        const roots = pcs.commitments.items;
        if (!std.mem.eql(u8, &roots[0], &setup.fixed_root.value) or !std.mem.eql(u8, &roots[0], &bundle.manifest.roots[index].fixed.bytes) or !std.mem.eql(u8, &roots[1], &bundle.manifest.roots[index].main.bytes)) return error.GlobalStage1RootMismatch;
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(P.T.P.Hasher, P.T.P.MerkleChannel).init(a, P.T.P.config());
        defer verifier.deinit(a);
        var channel = P.T.P.Channel{};
        var before: u64 = 0;
        for (requests[0..index]) |r| before += r.cpu.steps;
        try P.begin(&channel, setup, encoded.request, expected, index, before);
        for (0..2) |tree| {
            const logs = try setup.materials.logs(a, tree);
            defer a.free(logs);
            try verifier.commit(a, roots[tree], logs, &channel);
        }
        const ch = try P.draw(&channel, &bundle.manifest, index);
        if (!encoded.claims.initial.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.memory.initial, true, ch.memory.ram)) or !encoded.claims.terminal.ram.eql(try A.memory.load_store_v2.boundary_source.expectedClaim(encoded.request.memory.terminal, false, ch.memory.ram))) return error.GlobalBoundaryPhysicalClaimMismatch;
        channel.mixFelts(&encoded.claims.values());
        const ilogs = try setup.materials.logs(a, 2);
        defer a.free(ilogs);
        try verifier.commit(a, roots[2], ilogs, &channel);
        var components = try Components.init(&setup.materials, encoded.request, ch, encoded.claims);
        const handles = try components.verifiers(a);
        defer a.free(handles);
        owns = false;
        try core.verifier.verify(P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
        for (encoded.claims.values()) |q| total = total.add(q);
    }
    if (!total.isZero()) return error.UnclosedGlobalExecutionRam;
}
