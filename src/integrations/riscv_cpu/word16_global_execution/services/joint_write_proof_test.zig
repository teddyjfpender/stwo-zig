//! Production services transcript and shared manifest, with deliberately forged
//! algebraic witnesses. The proof fragments are real, not altered proof bytes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const P = @import("protocol.zig");
const G = @import("../protocol.zig");
const R = @import("roster.zig");
const S = @import("statement.zig");
const W = @import("worker.zig");
const E = @import("execution.zig");
const Adapters = @import("air_components.zig");
const Components = @import("../../word16_execution/components.zig").Components;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Sources = @import("../../word16_execution/sources.zig");
const Memory = @import("../../word16_execution/memory/prepared.zig").Prepared;
const H = @import("../../word16_execution/memory/joint_write_attack_support.zig");
const Q = H.Q;
const M = H.M;
const a = std.testing.allocator;
const Kind = enum { balanced_alias, orphan_register };
fn localSum(claims: S.CpuClaims) Q {
    var total = Q.zero();
    for (claims.values()) |v| total = total.add(v);
    total = total.sub(claims.ram());
    for (claims.extras) |c| total = total.sub(c.truth);
    return total;
}
/// Low-level physical verification intentionally omits aggregate debt checks;
/// never expose this helper as an accepting application receiver.
fn verifyPhysical(setup: *const R.CpuSetup, expected: P.Expected, manifest: *const G.Manifest, index: usize, encoded: S.CpuEncoded) !void {
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, setup.key.suite.config());
    defer verifier.deinit(a);
    var channel = G.T.P.Channel{};
    try P.beginCpu(&channel, setup, encoded.request, expected, index, 3 * index, .{ 1, 1, 1 });
    for (0..2) |tree| {
        const logs = try setup.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[tree], logs, &channel);
    }
    const ch = try P.drawCpu(&channel, manifest, index);
    channel.mixFelts(&encoded.claims.values());
    const logs = try setup.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], logs, &channel);
    var components = try Components.init(&setup.materials, encoded.request.base, ch, encoded.claims.base);
    var bridges = Adapters.Bridges.init(setup, encoded.request.calls, .{ 1, 1, 1 }, ch, try P.shared(manifest), encoded.claims.extras);
    const handles = try Adapters.cpuVerifierHandles(a, &components, &bridges);
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
}
fn run(kind: Kind) !void {
    var setups: [2]R.CpuSetup = undefined;
    var setup_done: usize = 0;
    defer for (setups[0..setup_done]) |*s| s.deinit();
    for (&setups) |*s| {
        s.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &H.WORDS }, .{ .cpu_log = 5 }, .{});
        setup_done += 1;
    }
    var tapes = [_]@import("stwo_riscv_frontend").rv64.compact_tape.Tape{ try H.tape(a, 0, 3), try H.tape(a, 3, 3) };
    defer for (&tapes) |*t| t.deinit();
    var native: [2]Native = undefined;
    var native_done: usize = 0;
    defer for (native[0..native_done]) |*n| n.deinit();
    for (&native, &setups, &tapes, 0..) |*n, *s, *t, k| {
        n.* = try Native.init(a, &s.materials.program, H.boundary(3 * k, 3), @intCast(k + 1), 5, t, .{});
        native_done += 1;
    }
    var advice = try @import("collector.zig").collect(a, &.{ &native[0], &native[1] }, &.{ &tapes[0], &tapes[1] }, H.image());
    defer advice.deinit();
    try std.testing.expectEqual(@as(u16, 1), advice.events[1][0].before.epoch);
    const expected = P.Expected{ .admission = .{ .image = H.image(), .image_identity = @splat(0x91), .initial_pc = 4096, .initial_registers = H.registers(), .max_prefix_steps = 31 }, .program_identity = setups[0].materials.program.identity, .total_steps = 6, .max_total_steps = 6, .final_pc = 4120, .final_registers = H.registers() };
    var workers: [2]W.Worker = undefined;
    var worker_done: usize = 0;
    defer for (workers[0..worker_done]) |*w| w.deinit(a);
    var requests: [2]P.Request = undefined;
    var specs: [2][32]u8 = undefined;
    var roots: [2]G.Receipt = undefined;
    var honest_cpu: [2][]M = undefined;
    var honest_ls: [2][]M = undefined;
    var forged_cpu: [2][]M = undefined;
    var forged_ls: [2][]M = undefined;
    var matrices: usize = 0;
    defer for (0..matrices) |k| {
        a.free(honest_cpu[k]);
        a.free(honest_ls[k]);
        a.free(forged_cpu[k]);
        a.free(forged_ls[k]);
    };
    for (&workers, &setups, &native, 0..) |*w, *setup, *n, k| {
        const initial = try a.dupe(A.memory.closed_ram.types.Cell, if (k == 0) advice.initial else &.{});
        const terminal = try a.dupe(A.memory.closed_ram.types.Cell, if (k == 1) advice.terminal else &.{});
        const memory = try Memory.initOwnedForGlobalRamLadderIndependent(a, advice.events[k], initial, terminal, @intCast(k + 1), 5, null, 5, 5);
        var source = R.Sources{ .core = try Sources.Source.fromPreparedWithOwnedMemory(a, &setup.materials, n, memory) };
        var owns_source = true;
        errdefer if (owns_source) source.deinit();
        honest_cpu[k] = try a.dupe(M, source.core.cpu.main);
        honest_ls[k] = try a.dupe(M, source.core.memory.ls.main);
        if (kind == .balanced_alias) H.forge(source.core.cpu.main, source.core.memory.ls.main, 3 * k, 3) else if (k == 0) H.forgeRegisterOrphan(source.core.cpu.main);
        forged_cpu[k] = try a.dupe(M, source.core.cpu.main);
        forged_ls[k] = try a.dupe(M, source.core.memory.ls.main);
        matrices += 1;
        requests[k] = .{ .base = source.core.request(), .calls = .{ 0, 0, 0 } };
        w.* = try W.Worker.init(a, .{ .cpu = .{ .setup = setup, .request = requests[k], .ordinal = k, .first_step = 3 * k, .first_ids = .{ 1, 1, 1 } } }, .{ .cpu = source });
        owns_source = false;
        worker_done += 1;
        roots[k] = try w.seal(a, expected, .{}, k);
        specs[k] = w.spec;
    }
    _ = try P.admit(a, &.{ &setups[0], &setups[1] }, &.{}, &requests, expected);
    var manifest = try G.Manifest.init(a, &specs, &roots);
    defer manifest.deinit();
    var encoded: [2]S.CpuEncoded = undefined;
    var encoded_done: usize = 0;
    defer for (encoded[0..encoded_done]) |*c| c.deinit(a);
    var ram = Q.zero();
    for (&workers, &encoded, 0..) |*w, *out, k| {
        const ch = try P.drawCpu(&w.channel, &manifest, k);
        const src = &w.source.cpu.core;
        var claims = S.CpuClaims{ .base = (try src.generateForDelegationJoin(ch)).physical, .extras = @splat(@import("types.zig").ExtraClaims.zero()) };
        const cpu_scratch = try a.alloc(M, A.word16_execution.layout.inter.COUNT * H.N);
        defer a.free(cpu_scratch);
        const ls_scratch = try a.alloc(M, LS_INTERACTION * H.N);
        defer a.free(ls_scratch);
        const honest_ca = try H.repairCpu(honest_cpu[k], cpu_scratch, requests[k].base.cpu, @intCast(k + 1), ch.cpu);
        const honest_lc = try H.repairLs(honest_ls[k], ls_scratch, ch.memory);
        const ca = try H.repairCpu(forged_cpu[k], src.cpu.interaction, requests[k].base.cpu, @intCast(k + 1), ch.cpu);
        const lc = try H.repairLs(forged_ls[k], src.memory.ls.interaction, ch.memory);
        try std.testing.expect(honest_ca.function.eql(ca.function));
        try std.testing.expect(honest_lc.range16.eql(lc.range16));
        try std.testing.expect(honest_lc.range8.eql(lc.range8));
        try std.testing.expect(honest_lc.selection.eql(lc.selection));
        claims.base.cpu = ca.total;
        claims.base.ls = lc;
        if (kind == .balanced_alias or k == 1) {
            try std.testing.expect(ca.register.add(claims.base.regboundary).isZero());
            try std.testing.expect(ca.owner.add(lc.owner).isZero());
            try claims.local();
        } else {
            try std.testing.expect(!ca.register.add(claims.base.regboundary).isZero());
            try std.testing.expectError(error.UnclosedCombinedCpuRelations, claims.local());
        }
        ram = ram.add(claims.ram());
        w.channel.mixFelts(&claims.values());
        const inter = try w.source.cpu.columns(a, &setups[k], 2);
        defer a.free(inter);
        try w.scheme.commitBorrowedStreaming(a, inter, 8, &w.channel);
        src.releaseCommittedInteraction();
        var components = try Components.init(&setups[k].materials, requests[k].base, ch, claims.base);
        const handles = try components.provers(a);
        defer a.free(handles);
        w.owns_scheme = false;
        var proof = try engine.prove.proveExWithRecorder(Backend, G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &w.channel, w.scheme, false, null);
        defer proof.aux.deinit(a);
        defer proof.proof.deinit(a);
        const bytes = try wire.encodeProofBytesBinary(a, proof.proof);
        errdefer a.free(bytes);
        var request = requests[k];
        request.base.memory.initial = try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.initial);
        errdefer a.free(request.base.memory.initial);
        request.base.memory.terminal = try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.terminal);
        out.* = .{ .bytes = bytes, .request = request, .claims = claims };
        encoded_done += 1;
    }
    var fresh: [2]R.CpuSetup = undefined;
    var fresh_done: usize = 0;
    defer for (fresh[0..fresh_done]) |*s| s.deinit();
    for (&fresh, 0..) |*s, k| {
        s.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &H.WORDS }, setups[k].materials.geometry, .{});
        fresh_done += 1;
        try verifyPhysical(s, expected, &manifest, k, encoded[k]);
    }
    var no_truths: [0]S.TruthEncoded = .{};
    const bundle = S.Bundle{ .manifest = manifest, .cpus = &encoded, .truths = &no_truths };
    if (kind == .balanced_alias) {
        try std.testing.expect(!ram.isZero());
        try std.testing.expectError(error.UnclosedCombinedRam, E.verify(a, &.{ &fresh[0], &fresh[1] }, &.{}, expected, &bundle));
    } else {
        try std.testing.expect(ram.isZero());
        try std.testing.expectError(error.UnclosedCombinedCpuRelations, E.verify(a, &.{ &fresh[0], &fresh[1] }, &.{}, expected, &bundle));
        // Explicit API guard: an aggregator cannot sum local debts first. This
        // synthetic ledger pair is not claimed to be a new valid physical proof.
        const debt = localSum(encoded[0].claims);
        var opposite = encoded[1].claims;
        opposite.base.cpu = opposite.base.cpu.sub(debt);
        try std.testing.expect(localSum(encoded[0].claims).add(localSum(opposite)).isZero());
        try std.testing.expectError(error.UnclosedCombinedCpuRelations, opposite.local());
    }
}
const LS_INTERACTION = A.memory.load_store_v2.layout.INTERACTION;
test "LS32 actual cross-shard balanced LD REG SD physical proofs reject only global RAM ancestry" {
    try run(.balanced_alias);
}
test "LS32 actual services physical proofs with closed global RAM still reject a per-proof REG orphan" {
    try run(.orphan_register);
}
