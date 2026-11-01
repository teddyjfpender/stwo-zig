//! Malformed public lists have real proofs under their own transcripts. These
//! tests bypass producer admission deliberately; accepting endpoints must not.
const std = @import("std");
const core = @import("stwo_core");
const wire = @import("stwo_proof_wire");
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.memory.load_store_v2;
const Ram = A.memory.closed_ram;
const Core = @import("../../word16_execution/sources.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const Memory = @import("../../word16_execution/memory/prepared.zig").Prepared;
const MemoryCollector = @import("../../word16_execution/memory/collector.zig");
const Driver = @import("../../word16_execution/driver.zig");
const Components = @import("../../word16_execution/components.zig").Components;
const Fixture = @import("../../tests/rv64_word16_execution_fixture.zig").Fixture;
const Keys = @import("../ethereum/keys.zig").Owner;
const Ethereum = @import("../ethereum/receiver.zig");
const G = @import("../protocol.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const W = @import("worker.zig");
const E = @import("execution.zig");
const a = std.testing.allocator;
const Mode = enum { duplicate_public, unsorted_public, unaligned_public, wrong_initial, physical_permutation };

const rewriteBoundary = @import("../../word16_execution/memory/boundary_fixture.zig").rewrite;

/// Independent physical verification, deliberately omitting native statement
/// admission. The production receivers below must reject despite this success.
fn verifyPhysical(setup: *const R.CpuSetup, expected: P.Expected, bundle: *const E.Bundle) !void {
    const encoded = bundle.cpus[0];
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, setup.key.suite.config());
    defer verifier.deinit(a);
    var channel = G.T.P.Channel{};
    try P.beginCpu(&channel, setup, encoded.request, expected, 0, 0, .{ 1, 1, 1 });
    for (0..2) |tree| {
        const logs = try setup.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[tree], logs, &channel);
    }
    const ch = try P.drawCpu(&channel, &bundle.manifest, 0);
    const common = try P.shared(&bundle.manifest);
    // Even the exact public debts agree. Canonicality belongs to admission.
    try std.testing.expect(encoded.claims.base.initial.ram.eql(try B.boundary_source.expectedClaim(encoded.request.base.memory.initial, true, common.ram)));
    try std.testing.expect(encoded.claims.base.terminal.ram.eql(try B.boundary_source.expectedClaim(encoded.request.base.memory.terminal, false, common.ram)));
    try encoded.claims.local();
    try std.testing.expect(encoded.claims.ram().isZero());
    channel.mixFelts(&encoded.claims.values());
    const logs = try setup.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], logs, &channel);
    var components = try Components.init(&setup.materials, encoded.request.base, ch, encoded.claims.base);
    const handles = try components.verifiers(a); // no service bridges or truths
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
}

fn run(mode: Mode) !void {
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var program = try Program.initWithAuthority(a, &fixture.image.authority);
    defer program.deinit();
    var native = try Native.init(a, &program, fixture.boundary, 1, 5, &fixture.tape, .{ .deduplicate_binary = false, .jalr_log = 5 });
    defer native.deinit();
    var keys = try Keys.init(a, &fixture.image, &.{.{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }}, &.{});
    defer keys.deinit();
    const setup = keys.cpus[0];
    const admission = Driver.admission(&fixture.image);
    var collected = try MemoryCollector.collect(a, admission.image, native.cpu.?.memory.items, 1);
    defer collected.deinit();
    try std.testing.expectEqual(@as(usize, 1), collected.initial.len);
    const initial = try a.alloc(Ram.types.Cell, 3);
    const terminal = a.alloc(Ram.types.Cell, 3) catch |err| {
        a.free(initial);
        return err;
    };
    initial[0] = collected.initial[0];
    terminal[0] = collected.terminal[0];
    for ([_]u64{ 0x2108000, 0x2112000 }, 1..) |address, i| {
        initial[i] = .{ .address = address, .state = .{ .value = 0, .rights = 3 } };
        terminal[i] = initial[i];
    }
    const memory = try Memory.initOwnedForGlobalRamIndependent(a, collected.events, initial, terminal, 1, 5, 5, 5);
    var source = R.Sources{ .core = try Core.Source.fromPreparedWithOwnedMemory(a, &setup.materials, &native, memory) };
    var owns_source = true;
    defer if (owns_source) source.deinit();
    try source.mergeRanges();
    switch (mode) {
        .duplicate_public => {
            initial[2] = initial[1];
            terminal[2] = terminal[1];
        },
        .unsorted_public => {
            std.mem.swap(Ram.types.Cell, &initial[1], &initial[2]);
            std.mem.swap(Ram.types.Cell, &terminal[1], &terminal[2]);
        },
        .unaligned_public => {
            initial[2].address += 1;
            terminal[2].address += 1;
        },
        .wrong_initial => {
            initial[2].state.value = 1;
            terminal[2].state.value = 1;
        },
        .physical_permutation => {},
    }
    rewriteBoundary(&source.core.memory.initial, initial);
    rewriteBoundary(&source.core.memory.terminal, terminal);
    if (mode == .physical_permutation) {
        // Leave the public set canonical, but permute the two inactive-in-RAM
        // boundary occurrences in MAIN and retained interaction metadata.
        inline for (.{ "initial", "terminal" }) |name| {
            const boundary = &@field(source.core.memory, name);
            for (0..B.layout.BOUND_MAIN) |column| std.mem.swap(@TypeOf(boundary.main[0]), &boundary.main[column * 32 + Ram.trace.physical(1, 5)], &boundary.main[column * 32 + Ram.trace.physical(2, 5)]);
            std.mem.swap(B.boundary_source.Metadata, &boundary.metadata[1], &boundary.metadata[2]);
        }
    }
    const request = P.Request{ .base = source.core.request(), .calls = @splat(0) };
    const expected = P.Expected{ .admission = admission, .program_identity = program.identity, .total_steps = fixture.boundary.steps, .max_total_steps = 32, .final_pc = fixture.boundary.final_pc, .final_registers = fixture.boundary.final_registers };
    // Deliberately use the low-level worker, not the producer coordinator that
    // correctly rejects malformed public advice before constructing a proof.
    var worker = try W.Worker.init(a, .{ .cpu = .{ .setup = setup, .request = request, .ordinal = 0, .first_step = 0, .first_ids = .{ 1, 1, 1 } } }, .{ .cpu = source });
    owns_source = false;
    defer worker.deinit(a);
    const root = try worker.seal(a, expected, .{}, 0);
    var manifest = try G.Manifest.init(a, &.{worker.spec}, &.{root});
    var owns_manifest = true;
    defer if (owns_manifest) manifest.deinit();
    const cpus = try a.alloc(@import("statement.zig").CpuEncoded, 1);
    const truths = a.alloc(@import("statement.zig").TruthEncoded, 0) catch |err| {
        a.free(cpus);
        return err;
    };
    var owns_containers = true;
    defer if (owns_containers) {
        a.free(cpus);
        a.free(truths);
    };
    const result = try worker.complete(a, &manifest, .{}, 0);
    cpus[0] = result.cpu;
    var bundle = E.Bundle{ .manifest = manifest, .cpus = cpus, .truths = truths };
    owns_manifest = false;
    owns_containers = false;
    defer bundle.deinit(a);
    try verifyPhysical(setup, expected, &bundle);
    if (mode == .physical_permutation) {
        try E.verify(a, keys.cpus, keys.truths, expected, &bundle);
        try std.testing.expectEqual(@as(?[43]u8, null), try Ethereum.verify(a, &fixture.image, &keys, &bundle, 32, 32, false));
    } else {
        const expected_error = if (mode == .wrong_initial) error.UntrustedGlobalMemoryInitialization else error.GlobalTouchedSetMismatch;
        try std.testing.expectError(expected_error, E.verify(a, keys.cpus, keys.truths, expected, &bundle));
        try std.testing.expectError(expected_error, Ethereum.verify(a, &fixture.image, &keys, &bundle, 32, 32, false));
    }
}

test "services and Ethereum receivers reject genuinely proven malformed public boundaries and accept canonical-set row permutations" {
    for ([_]Mode{ .duplicate_public, .unsorted_public, .unaligned_public, .wrong_initial, .physical_permutation }) |mode| try run(mode);
}
