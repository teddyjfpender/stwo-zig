//! Actual independently sized mixed-service protocol. Acceptance requires every
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
const Profiling = @import("profiling.zig");
const Profile = @import("stwo_prover_api").stage_profile;
pub const ProduceOptions = Profiling.Options;
const Q = G.Q;
const Cell = A.memory.closed_ram.types.Cell;
const Statement = @import("statement.zig");
pub const CpuClaims = Statement.CpuClaims;
pub const CpuEncoded = Statement.CpuEncoded;
pub const TruthEncoded = Statement.TruthEncoded;
pub const Bundle = Statement.Bundle;
const Adapters = @import("air_components.zig");
const Bridges = Adapters.Bridges;
const TruthComponents = Adapters.TruthComponents;
const cpuVerifierHandles = Adapters.cpuVerifierHandles;
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, prepared: []const *Native, advice: *const Advice, expected: P.Expected) !Bundle {
    return produceWithOptions(a, setups, truths, prepared, advice, expected, .{});
}
pub fn produceWithStorage(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, prepared: []const *Native, advice: *const Advice, expected: P.Expected, retained: ?*@import("../retained_main_store.zig").Store) !Bundle {
    return produceWithOptions(a, setups, truths, prepared, advice, expected, .{ .retained_main = retained });
}
pub fn produceWithOptions(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, prepared: []const *Native, advice: *const Advice, expected: P.Expected, options: ProduceOptions) !Bundle {
    return @import("pipeline.zig").produce(a, setups, truths, prepared, advice, expected, options);
}

fn checkRoots(proof: anytype, key: [32]u8, suite: @import("../../word16_execution/pcs_suite.zig").Suite, manifest: *const G.Manifest, index: usize) !void {
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, suite.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.CombinedPcsSuiteMismatch;
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
        try checkRoots(proof, s.key.root, s.key.suite, &bundle.manifest, index);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, s.key.suite.config());
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
        encoded.claims.mix(&channel, s);
        const logs = try s.logs(a, 2);
        defer a.free(logs);
        try verifier.commit(a, roots[2], logs, &channel);
        var bc = try Components.init(&s.materials, encoded.request.base, ch, encoded.claims.base);
        var bb = try Bridges.init(s, encoded.request.calls, try P.firstIds(requests, index), ch, common, encoded.claims.extras).withBulk(s, encoded.request.bulk, ch, encoded.claims.bulk).withSponge(s, encoded.request.sponge, ch, common, encoded.claims.sponge).withDword(s, encoded.request.ls_dword, ch, encoded.claims.ls_dword);
        const handles = try cpuVerifierHandles(a, &bc, &bb);
        defer a.free(handles);
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
        try encoded.claims.local();
        ram = ram.add(encoded.claims.ram());
        io = io.add(encoded.claims.io());
        wire_sum = wire_sum.add(encoded.claims.wire());
    }
    for (truths, bundle.truths, 0..) |truth, encoded, k| {
        for (encoded.claims) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
        if (encoded.bytes.len > 64 * 1024 * 1024) return error.CombinedProofLimit;
        var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
        var owns = true;
        defer if (owns) proof.deinit(a);
        try checkRoots(proof, truth.key().root, truth.key().suite, &bundle.manifest, setups.len + k);
        var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, truth.key().suite.config());
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
        var buffer: [3]core.air.components.Component = undefined;
        const handles = components.verifiers(&buffer);
        owns = false;
        try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
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
