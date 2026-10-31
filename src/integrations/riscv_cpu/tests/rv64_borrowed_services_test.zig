//! Borrowed matrix ownership and same-source-row authority through real proofs.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const M = @import("stwo_core").fields.m31.M31;
const D = air.arithmetic.division;
const Mul = air.arithmetic.multiplication;
const C = @import("../rv64_keccak_cpu.zig");
const Full = @import("../rv64_full.zig");
const A = @import("../rv64_authenticated_execution.zig");
const Arena = @import("../rv64_authenticated_main_arena.zig").MainArena;
const F = @import("rv64_ethereum_fixture.zig");
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;
const div_requests = [_]D.trace.Request{ .{ .opcode = .DIV, .a = @bitCast(@as(i64, -7)), .b = 3, .result = @bitCast(@as(i64, -2)) }, .{ .opcode = .REMW, .a = 0x80000000, .b = std.math.maxInt(u64), .result = 0 }, .{ .opcode = .DIVU, .a = std.math.maxInt(u64), .b = 0, .result = std.math.maxInt(u64) } };
const mul_requests = [_]Mul.trace.Request{ .{ .opcode = .MULH, .a = std.math.maxInt(u64), .b = 2, .result = std.math.maxInt(u64) }, .{ .opcode = .MULW, .a = 0x80000000, .b = 1, .result = 0xffffffff80000000 }, .{ .opcode = .MULHU, .a = std.math.maxInt(u64), .b = std.math.maxInt(u64), .result = 0xfffffffffffffffe } };
test "borrowed DIV matches owned rows and survives main destruction plus allocation failure" {
    var backing = try a.alloc(M, D.layout.MAIN * 32);
    defer if (backing.len != 0) a.free(backing);
    try std.testing.checkAllAllocationFailures(a, borrowedDivision, .{backing});
    var owned = try D.trace.Trace.initWithLog(a, &div_requests, 5);
    defer owned.deinit();
    var borrowed = try D.trace.Trace.initWithBorrowedMain(a, &div_requests, 5, backing);
    defer borrowed.deinit();
    try std.testing.expect(!borrowed.owns_main);
    try std.testing.expectEqualSlices(M, owned.main, borrowed.main);
    try borrowed.releaseMain();
    a.free(backing);
    backing = &.{};
    var channel = air.protocol.Channel{};
    const ch = D.provider.Challenges.draw(&channel);
    try std.testing.expect((try owned.generateInteraction(ch)).eql(try borrowed.generateInteraction(ch)));
    try std.testing.expectEqualSlices(M, owned.interaction, borrowed.interaction);
}
fn borrowedDivision(allocator: std.mem.Allocator, main: []M) !void {
    @memset(main, M.fromCanonical(42));
    var trace = D.trace.Trace.initWithBorrowedMain(allocator, &div_requests, 5, main) catch |err| {
        for (main) |value| try std.testing.expectEqual(@as(u32, 42), value.v);
        return err;
    };
    defer trace.deinit();
    try trace.releaseMain();
    var channel = air.protocol.Channel{};
    _ = try trace.generateInteraction(D.provider.Challenges.draw(&channel));
}
test "borrowed MUL matches owned rows and survives main destruction plus allocation failure" {
    var backing = try a.alloc(M, Mul.layout.MAIN * 32);
    defer if (backing.len != 0) a.free(backing);
    try std.testing.checkAllAllocationFailures(a, borrowedMultiplication, .{backing});
    var owned = try Mul.trace.Trace.initWithLog(a, &mul_requests, 5);
    defer owned.deinit();
    var borrowed = try Mul.trace.Trace.initWithBorrowedMain(a, &mul_requests, 5, backing);
    defer borrowed.deinit();
    try std.testing.expect(!borrowed.owns_main);
    try std.testing.expectEqualSlices(M, owned.main, borrowed.main);
    try std.testing.expectEqualSlices(u64, &owned.byte_counts, &borrowed.byte_counts);
    try borrowed.releaseMain();
    a.free(backing);
    backing = &.{};
    var channel = air.protocol.Channel{};
    const ch = Mul.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    try std.testing.expect((try owned.generateInteraction(ch, alpha)).eql(try borrowed.generateInteraction(ch, alpha)));
    try std.testing.expectEqualSlices(M, owned.interaction, borrowed.interaction);
}
fn borrowedMultiplication(allocator: std.mem.Allocator, main: []M) !void {
    @memset(main, M.fromCanonical(42));
    var trace = Mul.trace.Trace.initWithBorrowedMain(allocator, &mul_requests, 5, main) catch |err| {
        for (main) |value| try std.testing.expectEqual(@as(u32, 42), value.v);
        return err;
    };
    defer trace.deinit();
    try trace.releaseMain();
    var channel = air.protocol.Channel{};
    const ch = Mul.provider.Challenges.draw(&channel);
    _ = try trace.generateInteraction(ch, channel.drawSecureFelt());
}
fn fixtureTape(fixture: *const F.Fixture) !rv.compact_tape.Tape {
    var tape = try rv.compact_tape.Tape.init(a, F.program.len, F.pc, 0, .ethereum_services_v2);
    errdefer tape.deinit();
    var k: usize = 0;
    var s: usize = 0;
    for (fixture.records) |record| {
        if (record.opcode != .ECALL) try tape.append(record) else if (record.rhs.toInt() == rv.execution_profile.KECCAK_TAG) {
            try tape.appendService(fixture.kcalls[k]);
            k += 1;
        } else {
            try tape.appendSecp(fixture.scalls[s]);
            s += 1;
        }
    }
    return tape;
}
fn borrowedCpu(fixture: *const F.Fixture, tape: *const rv.compact_tape.Tape, setup: *const C.PreparedMaterials, main: []M) !Full.Trace {
    var narrow = fixture.public.statement;
    narrow.cells = &.{};
    narrow.memory_clocks = &.{};
    return Full.Trace.initWithPrivateTapeBorrowedMain(a, tape, 1, .{ 1, 1 }, narrow, .{ .cells = fixture.public.statement.cells, .memory_clocks = fixture.public.statement.memory_clocks }, &setup.base.program, &setup.base.plan, main);
}
test "CPU DIV MUL Keccak secp one ragged backing commits identical real proof and rejects role aliases" {
    const fixture = try F.Fixture.create(a, .ethereum_services_v2);
    defer fixture.deinit();
    var setup = try C.PreparedSetup.init(a, fixture.public);
    defer setup.deinit();
    var tape = try fixtureTape(fixture);
    defer tape.deinit();
    var arena = try Arena.initCore(a, &setup.materials, fixture.public);
    defer arena.deinit();
    var full = try borrowedCpu(fixture, &tape, &setup.materials, try arena.cpuMain());
    var owns_full = true;
    defer if (owns_full) full.deinit();
    const buffers = try arena.coreBuffers();
    var invalid = buffers;
    invalid.arithmetic.division = buffers.keccak.?.permutation[0 .. D.layout.MAIN * 32];
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, C.Trace.fromCpuBorrowed(a, full, fixture.public, &setup.materials, invalid));
    invalid = buffers;
    invalid.arithmetic.multiplication = buffers.arithmetic.multiplication.?[0..1];
    try std.testing.expectError(error.InvalidCryptoMainBuffers, C.Trace.fromCpuBorrowed(a, full, fixture.public, &setup.materials, invalid));
    var trace = try C.Trace.fromCpuBorrowed(a, full, fixture.public, &setup.materials, buffers);
    owns_full = false;
    defer trace.deinit();
    try std.testing.expect(!trace.division.?.owns_main and !trace.multiplication.?.owns_main);
    var control_trace = try C.Trace.initEthereum(a, &fixture.records, .{ .keccak = &fixture.kcalls, .secp = &fixture.scalls }, fixture.public, &setup.materials);
    defer control_trace.deinit();
    var borrowed_bundle = try proveOwnedArena(&setup, fixture.public, &trace, &arena);
    defer borrowed_bundle.deinit(a);
    var control_bundle = try C.proveTrace(a, &setup, fixture.public, &control_trace);
    defer control_bundle.deinit(a);
    const borrowed_bytes = try wire.encodeProofBytesBinary(a, borrowed_bundle.proof);
    defer a.free(borrowed_bytes);
    const control_bytes = try wire.encodeProofBytesBinary(a, control_bundle.proof);
    defer a.free(control_bytes);
    try std.testing.expectEqualSlices(u8, control_bytes, borrowed_bytes);
    try std.testing.expectEqual(@as(usize, 0), trace.cpu.main.len);
    try std.testing.expectEqual(@as(usize, 0), trace.division.?.main.len);
    var receiver = try C.PreparedSetup.init(a, fixture.public);
    defer receiver.deinit();
    try receiver.verifyOwned(a, fixture.public, borrowed_bundle.claims, try wire.decodeProofBytesBinary(a, borrowed_bytes));
}
fn proveOwnedArena(owner: *const C.PreparedSetup, public: C.Public, trace: *C.Trace, arena: *Arena) !C.Bundle {
    const P = air.protocol;
    const setup = &owner.materials;
    const S = C.Support;
    var sources = try S.ProvingSources.init(a, setup, public, trace, null);
    defer sources.deinit();
    var channel = P.Channel{};
    try S.mixPublic(&channel, setup, public);
    var scheme = try A.Scheme.init(a, P.config());
    scheme.setCompactPolynomialStorage(5);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
    const main = try sources.mainColumns();
    defer a.free(main);
    const original_cpu = try a.dupe(M, trace.cpu.main);
    defer a.free(original_cpu);
    try arena.sealFromColumns(main);
    const transfer = try arena.takeForCommit(a);
    // The consuming PCS API owns descriptors/backing even on failure.
    try scheme.commitOwnedWithRecorderAndBacking(a, transfer.columns, transfer.backing, null, &channel);
    try sources.releaseMain();
    const ch = S.draw(&channel, setup);
    const claims = try sources.generate(ch);
    try std.testing.expect(S.effect(claims).eql(try public.statement.expectedStateWithProfile(ch.cpu.state, public.execution_profile)));
    var components = try S.Components.init(setup, public, claims, ch);
    const inter = try sources.interactionColumns();
    defer a.free(inter);
    const Diagnostic = @import("../rv64_cpu_diagnostic.zig");
    const clean = try Diagnostic.inspect(a, setup, public, trace, original_cpu, claims, ch, inter, .{});
    try std.testing.expect(clean.first_failure == null);
    try std.testing.expectEqual(@as(u32, @intCast(trace.cpu.domainSize())), clean.checked_rows);
    const physical = air.witness.physical(1, setup.base.log_size);
    original_cpu[(setup.base.plan.main_count + air.full.frame.ACTIVE) * trace.cpu.domainSize() + physical] = M.fromCanonical(2);
    const changed = try Diagnostic.inspect(a, setup, public, trace, original_cpu, claims, ch, inter, .{ .first_row = 1, .row_count = 1 });
    try std.testing.expectEqual(@as(u32, 1), changed.first_failure.?.logical_row);
    try std.testing.expectEqual(@as(usize, 0), changed.first_failure.?.constraint_index);
    try std.testing.expectEqual(@as(u64, F.pc + 4), changed.first_failure.?.pc.?);
    try std.testing.expectEqual(F.program[1], changed.first_failure.?.raw_instruction.?);
    S.mixClaims(&channel, claims, public);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    var handles: [C.MAX_COMPONENTS]A.engine.air.component_prover.ComponentProver = undefined;
    const count = components.provers(&handles);
    owns_scheme = false;
    return .{ .claims = claims, .proof = try A.engine.prove.prove(A.B, P.Hasher, P.MerkleChannel, a, handles[0..count], &channel, scheme) };
}
