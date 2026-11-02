//! Opt-in fused-pair LS32 / INIT / TEARDOWN layout (Geometry.ls_fused_pairs)
//! end to end: the honest physical proof verifies with a fresh receiver, the
//! CPU-pair and LS-pair receivers reject each other's proofs, and forged
//! LS/boundary witnesses are rejected by the physical STARK.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const LS = A.memory.load_store_v2;
const LF = LS.layout.fused;
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
const LS_PAIRS = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true, .ls_fused_pairs = true };
const CPU_PAIRS = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
const verifyPhysical = @import("memory/boundary_anchor_test.zig").verifyPhysical;
const DELTA = Q.fromU32Unchecked(3, 1, 4, 1);

pub const Tamper = union(enum) {
    none,
    /// LS fraction witness K_j += delta at a row; local prefix repaired, so
    /// only the slot residual K_j*a*b = numerator can reject it.
    slot: struct { row: usize, slot: usize },
    /// Move a row's first byte-pair fraction to a later row: claim unchanged.
    drop_pair: struct { row: usize, to: usize },
    /// LS RAM prefix (fused RAM fraction) += delta at one row only.
    ram_sum: struct { row: usize },
    /// LS local prefix += delta at one row only.
    local_sum: struct { row: usize },
    /// INIT prefix (fused single) += delta at one row only.
    initial_sum: struct { row: usize },
    /// INIT fused fraction moved between rows: RAM claim unchanged.
    initial_move: struct { row: usize, to: usize },
};
fn readQ(data: []const M, n: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * n + row], data[(column + 1) * n + row], data[(column + 2) * n + row], data[(column + 3) * n + row]);
}
fn addQ(data: []M, n: usize, row: usize, column: usize, value: Q) void {
    R.trace.store(data, n, row, column, readQ(data, n, row, column).add(value));
}
/// Adds `value` to the prefix column at logical rows [from, to).
fn shiftPrefix(data: []M, log: u32, column: usize, from: usize, to: usize, value: Q) void {
    const n = @as(usize, 1) << @intCast(log);
    for (from..to) |logical| addQ(data, n, R.trace.physical(logical, log), column, value);
}
fn logicalRow(main: []const M, log: u32, logical: usize) [LS.layout.projection.LOGICAL_MAIN]M {
    const n = @as(usize, 1) << @intCast(log);
    var row: [LS.layout.MAIN]M = undefined;
    const pos = R.trace.physical(logical, log);
    for (&row, 0..) |*v, c| v.* = main[c * n + pos];
    return LS.layout.projection.expandFor(M, &row);
}
const Outcome = struct { physical: bool, full: bool, physical_error: ?anyerror = null };
fn run(tamper: Tamper) !Outcome {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, LS_PAIRS);
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const ls_main = try a.dupe(M, source.memory.ls.main);
    defer a.free(ls_main);
    const ls_log = source.memory.ls.log_size;
    const ls_n = source.memory.ls.size();
    const ls_rows = source.memory.ls.rows;
    try std.testing.expect(ls_rows >= 2);
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
    try std.testing.expectEqual(LF.INTERACTION * ls_n, source.memory.ls.interaction.len);
    try std.testing.expectEqual(LF.BOUND_INTERACTION * source.memory.initial.size(), source.memory.initial.interaction.len);
    try claims.validate();
    const ls = source.memory.ls.interaction;
    switch (tamper) {
        .none => {},
        .slot => |t| {
            addQ(ls, ls_n, R.trace.physical(t.row, ls_log), LF.WITNESS + 4 * t.slot, DELTA);
            // Honest repair of the centered prefix: rows before t.row drop by delta.
            shiftPrefix(ls, ls_log, LF.LOCAL_PREFIX, 0, t.row, DELTA.neg());
            claims.ls.owner = claims.ls.owner.add(DELTA);
        },
        .drop_pair => |t| {
            const row = logicalRow(ls_main, ls_log, t.row);
            const at = @as(usize, row[LS.layout.LOGICAL_U8[0]].v) * 256 + row[LS.layout.LOGICAL_U8[1]].v;
            shiftPrefix(ls, ls_log, LF.LOCAL_PREFIX, t.row, t.to, source.and_table.pair_dictionary[at].neg());
        },
        .ram_sum => |t| addQ(ls, ls_n, R.trace.physical(t.row, ls_log), LF.RAM_PREFIX, DELTA),
        .local_sum => |t| addQ(ls, ls_n, R.trace.physical(t.row, ls_log), LF.LOCAL_PREFIX, DELTA),
        .initial_sum => |t| {
            const b = &source.memory.initial;
            addQ(b.interaction, b.size(), R.trace.physical(t.row, b.log_size), 0, DELTA);
        },
        .initial_move => |t| {
            const b = &source.memory.initial;
            // Row t.row's fraction -1/d moves to t.to; the RAM claim is unchanged.
            // Increment = S_r - S_{r-1} (+ claim on the first row, S_{n-1} = 0).
            const n = b.size();
            var f = readQ(b.interaction, n, R.trace.physical(t.row, b.log_size), 0).sub(readQ(b.interaction, n, R.trace.physical((t.row + n - 1) % n, b.log_size), 0));
            if (t.row == 0) f = f.add(claims.initial.ram);
            try std.testing.expect(!f.isZero());
            shiftPrefix(b.interaction, b.log_size, 0, t.row, t.to, f.neg());
        },
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
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, LS_PAIRS);
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

test "fused-pair LS: honest physical proof verifies with a fresh receiver" {
    const outcome = try run(.none);
    try std.testing.expect(outcome.physical and outcome.full);
}
test "fused-pair LS: forged fraction witnesses and prefixes (LS RAM, LS local, INIT) are rejected by the physical STARK" {
    // Row 0 is an active LS event; the last LS row is the mandatory inactive row.
    for ([_]Tamper{
        .{ .slot = .{ .row = 0, .slot = 0 } },
        .{ .slot = .{ .row = 1, .slot = 1 } },
        .{ .slot = .{ .row = 31, .slot = 2 } },
        .{ .slot = .{ .row = 31, .slot = 0 } },
        .{ .ram_sum = .{ .row = 0 } },
        .{ .local_sum = .{ .row = 2 } },
        .{ .initial_sum = .{ .row = 0 } },
    }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "fused-pair LS: moving a byte pair or an INIT fraction between rows keeps every claim yet is rejected" {
    for ([_]Tamper{ .{ .drop_pair = .{ .row = 0, .to = 9 } }, .{ .drop_pair = .{ .row = 30, .to = 31 } }, .{ .initial_move = .{ .row = 0, .to = 5 } } }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "fused-pair LS: LS-pair and CPU-pair receivers reject each other's proofs; exact cell delta and geometry admission" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    const admission = Driver.admission(&fixture.image);
    var setups: [2]Mat.Setup = undefined;
    var made: usize = 0;
    defer for (setups[0..made]) |*s| s.deinit();
    for ([_]Mat.Geometry{ CPU_PAIRS, LS_PAIRS }, &setups) |g, *s| {
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
    // Exact committed cells: LS -12 interaction columns per row, INIT and
    // TEARDOWN -4 each; fixed and MAIN unchanged.
    const before = try Mat.G.cells(&setups[0].materials.shapes());
    const after = try Mat.G.cells(&setups[1].materials.shapes());
    const g = LS_PAIRS;
    try std.testing.expectEqual(before.fixed, after.fixed);
    try std.testing.expectEqual(before.main, after.main);
    try std.testing.expectEqual(before.interaction - 12 * g.lsRows() - 4 * (Mat.G.rows(g.initialLog()) + Mat.G.rows(g.terminalLog())), after.interaction);
    try std.testing.expectEqual((try CPU_PAIRS.range8Mass()) - LS.layout.U8_QUERIES * g.lsRows(), try LS_PAIRS.range8Mass());
    try std.testing.expectEqual((try CPU_PAIRS.andMass()) + LF.PAIR_QUERIES * g.lsRows(), try LS_PAIRS.andMass());
    try std.testing.expectError(error.InvalidLsPairGeometry, (Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .ls_fused_pairs = true }).validate());
    const old_json = try std.json.Stringify.valueAlloc(a, CPU_PAIRS, .{});
    defer a.free(old_json);
    try std.testing.expect(std.mem.indexOf(u8, old_json, "ls_fused_pairs") == null);
    const new_json = try std.json.Stringify.valueAlloc(a, LS_PAIRS, .{});
    defer a.free(new_json);
    try std.testing.expect(std.mem.indexOf(u8, new_json, "\"ls_fused_pairs\":true") != null);
    var parsed = try std.json.parseFromSlice(Mat.Geometry, a, new_json, .{});
    defer parsed.deinit();
    try std.testing.expect(std.meta.eql(parsed.value, LS_PAIRS));
}
