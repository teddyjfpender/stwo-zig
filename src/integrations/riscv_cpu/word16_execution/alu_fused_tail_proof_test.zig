//! Opt-in fused-tail ALU layout (Geometry.alu_fused_tail) end to end: the
//! honest physical proof verifies with a fresh receiver, legacy and fused
//! receivers reject each other's proofs, and forged fused-tail witnesses (pair
//! fraction slots, FUNCTION fraction, prefix, moved fractions) are rejected.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const AF = A.word16_v1.alu_experiment.lookup.fused;
const R = A.memory.closed_ram;
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const Sources = @import("sources.zig");
const Components = @import("components.zig").Components;
const Execution = @import("execution.zig");
const Driver = @import("driver.zig");
const Q = A.evaluation.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const ALU_FUSED = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true, .alu_fused_tail = true };
const CPU_PAIRS = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
const verifyPhysical = @import("memory/boundary_anchor_test.zig").verifyPhysical;
const DELTA = Q.fromU32Unchecked(3, 1, 4, 1);

pub const Tamper = union(enum) {
    none,
    /// Pair fraction witness K_j (j < 5) += delta; centered prefix repaired.
    slot: struct { row: usize, slot: usize },
    /// FUNCTION fraction witness G += delta; centered prefix repaired.
    function: struct { row: usize },
    /// Move row's G (or K_0) mass to a later row: claims unchanged.
    move_function: struct { row: usize, to: usize },
    move_slot: struct { row: usize, to: usize },
    /// Prefix += delta at one row only.
    sum: struct { row: usize },
};
fn readQ(data: []const M, n: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * n + row], data[(column + 1) * n + row], data[(column + 2) * n + row], data[(column + 3) * n + row]);
}
fn addQ(data: []M, n: usize, row: usize, column: usize, value: Q) void {
    R.trace.store(data, n, row, column, readQ(data, n, row, column).add(value));
}
fn shiftPrefix(data: []M, log: u32, from: usize, to: usize, value: Q) void {
    const n = @as(usize, 1) << @intCast(log);
    for (from..to) |logical| addQ(data, n, R.trace.physical(logical, log), AF.PREFIX, value);
}
const Outcome = struct { physical: bool, full: bool, physical_error: ?anyerror = null };
fn run(tamper: Tamper) !Outcome {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, ALU_FUSED);
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const log = source.alu.log_size;
    const n = source.alu.size();
    var scheme = try P.T.Scheme.init(a, P.T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, &setup, request, admission.image_identity);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    try source.releaseMain();
    const draw = P.draw(&channel);
    var claims = (try source.generateForDelegationJoin(draw)).physical;
    try std.testing.expectEqual(AF.INTERACTION * n, source.alu.interaction.len);
    try claims.validate();
    const inter_alu = source.alu.interaction;
    switch (tamper) {
        .none => {},
        .slot => |t| {
            addQ(inter_alu, n, R.trace.physical(t.row, log), 4 * t.slot, DELTA);
            shiftPrefix(inter_alu, log, 0, t.row, DELTA.neg());
            claims.alu.range16 = claims.alu.range16.add(DELTA);
        },
        .function => |t| {
            addQ(inter_alu, n, R.trace.physical(t.row, log), AF.FUNCTION, DELTA);
            shiftPrefix(inter_alu, log, 0, t.row, DELTA);
            claims.alu.function = claims.alu.function.sub(DELTA);
        },
        .move_function => |t| {
            const g = readQ(inter_alu, n, R.trace.physical(t.row, log), AF.FUNCTION);
            try std.testing.expect(!g.isZero());
            shiftPrefix(inter_alu, log, t.row, t.to, g);
        },
        .move_slot => |t| shiftPrefix(inter_alu, log, t.row, t.to, readQ(inter_alu, n, R.trace.physical(t.row, log), 0).neg()),
        .sum => |t| addQ(inter_alu, n, R.trace.physical(t.row, log), AF.PREFIX, DELTA),
    }
    channel.mixFelts(&claims.values());
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    source.releaseCommittedInteraction();
    var components = try Components.init(&setup.materials, request, draw, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
    var failed: ?core.proof.ExtendedStarkProof(P.T.P.Hasher) = null;
    var prover_refused = false;
    var result = engine.prove.proveExWithExecutionDiagnosedRetainingFailure(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, scheme, false, null, null, null, &diagnostic, &failed) catch |err| blk: {
        if (err != error.ConstraintsNotSatisfied) return err;
        prover_refused = true;
        break :blk failed orelse return error.MissingUnverifiedAdversarialProof;
    };
    defer result.aux.deinit(a);
    defer result.proof.deinit(a);
    const bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, result.proof);
    defer a.free(bytes);
    const encoded = Execution.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, ALU_FUSED);
    defer fresh.deinit();
    var physical_error: ?anyerror = null;
    const physical = if (verifyPhysical(&fresh, admission, encoded)) |_| true else |err| blk: {
        physical_error = err;
        break :blk false;
    };
    const full = if (Execution.verify(a, &fresh, admission, encoded)) |_| true else |_| false;
    if (tamper == .none) try std.testing.expect(!prover_refused);
    return .{ .physical = physical, .full = full, .physical_error = physical_error };
}


test "fused-tail ALU: honest physical proof verifies with a fresh receiver" {
    const outcome = try run(.none);
    try std.testing.expect(outcome.physical and outcome.full);
}
test "fused-tail ALU: forged pair fractions, FUNCTION fractions and prefixes are rejected by the physical STARK" {
    for ([_]Tamper{
        .{ .slot = .{ .row = 0, .slot = 0 } },
        .{ .slot = .{ .row = 1, .slot = 4 } },
        .{ .slot = .{ .row = 31, .slot = 2 } },
        .{ .function = .{ .row = 0 } },
        .{ .function = .{ .row = 31 } },
        .{ .sum = .{ .row = 3 } },
    }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "fused-tail ALU: moving a FUNCTION or pair fraction between rows keeps every claim yet is rejected" {
    for ([_]Tamper{ .{ .move_function = .{ .row = 0, .to = 7 } }, .{ .move_slot = .{ .row = 2, .to = 30 } } }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "fused-tail ALU: legacy and fused receivers reject each other's proofs; exact cell delta" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    const admission = Driver.admission(&fixture.image);
    var setups: [2]Mat.Setup = undefined;
    var made: usize = 0;
    defer for (setups[0..made]) |*s| s.deinit();
    for ([_]Mat.Geometry{ CPU_PAIRS, ALU_FUSED }, &setups) |g, *s| {
        s.* = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, g);
        made += 1;
    }
    var proofs: [2]Execution.Encoded = undefined;
    var proved: usize = 0;
    defer for (proofs[0..proved]) |*p| p.deinit(a);
    for (&setups, &proofs) |*s, *p| {
        p.* = try Execution.prove(a, s, admission, fixture.boundary, &fixture.tape, null);
        proved += 1;
    }
    for (&setups, 0..) |*s, i| for (proofs, 0..) |p, j| {
        if (i == j) try Execution.verify(a, s, admission, p) else try std.testing.expect(std.meta.isError(Execution.verify(a, s, admission, p)));
    };
    const before = try Mat.G.cells(&setups[0].materials.shapes());
    const after = try Mat.G.cells(&setups[1].materials.shapes());
    try std.testing.expectEqual(before.fixed, after.fixed);
    try std.testing.expectEqual(before.main, after.main);
    try std.testing.expectEqual(before.interaction - 4 * Mat.G.familyRows(ALU_FUSED.alu_log, ALU_FUSED.alu_tail_log), after.interaction);
    const json = try std.json.Stringify.valueAlloc(a, ALU_FUSED, .{});
    defer a.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"alu_fused_tail\":true") != null);
    var parsed = try std.json.parseFromSlice(Mat.Geometry, a, json, .{});
    defer parsed.deinit();
    try std.testing.expect(std.meta.eql(parsed.value, ALU_FUSED));
}
