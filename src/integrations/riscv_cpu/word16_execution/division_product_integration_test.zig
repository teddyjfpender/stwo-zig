//! Closed CPU/DIV/MUL graph tests. The false fragments are real STARKs with
//! valid local components; only the complete typed relation closure rejects.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const D = A.arithmetic.division.word16_product;
const X = A.word16_execution;
const M = core.fields.m31.M31;
const Q = A.evaluation.Q;
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const Native = @import("prepared.zig").Prepared;
const Source = @import("sources.zig").Source;
const Components = @import("components.zig").Components;
const Execution = @import("execution.zig");
const Wire = @import("stwo_proof_wire");
const AB = @import("arithmetic_bus.zig");
const a = std.testing.allocator;
const CASES = [_]D.source.Request{
    .{ .opcode = .DIVU, .a = 15, .b = 4, .result = 3 },
    .{ .opcode = .REMU, .a = 15, .b = 4, .result = 3 },
    .{ .opcode = .DIV, .a = @bitCast(@as(i64, -15)), .b = 4, .result = @bitCast(@as(i64, -3)) },
    .{ .opcode = .REM, .a = @bitCast(@as(i64, -15)), .b = 4, .result = @bitCast(@as(i64, -3)) },
    .{ .opcode = .DIVW, .a = 0x1234567880000000, .b = 0xabcdef01ffffffff, .result = 0xffffffff80000000 },
    .{ .opcode = .DIVUW, .a = 0xffffffff, .b = 2, .result = 0x7fffffff },
    .{ .opcode = .REMW, .a = 0x1234567880000000, .b = 0xffffffff, .result = 0 },
    .{ .opcode = .REMUW, .a = 0xdeadbeefffffffff, .b = 0x100000000, .result = 0xffffffffffffffff },
    .{ .opcode = .DIV, .a = 0x8000000000000000, .b = 0xffffffffffffffff, .result = 0x8000000000000000 },
};
var context: u8 = 0;
fn zero(_: *const anyopaque, _: u64) !u64 {
    return 0;
}
fn rights(_: *const anyopaque, _: u64) !u2 {
    return 0;
}
const Fixture = struct {
    words: [CASES.len]u32,
    tape: front.rv64.compact_tape.Tape,
    public: X.types.Boundary,
    fn init(forged: ?u64) !Fixture {
        var result: Fixture = .{ .words = undefined, .tape = try front.rv64.compact_tape.Tape.init(a, CASES.len, 4096, 0, .ethereum_services_v2), .public = .{ .steps = CASES.len, .initial_pc = 4096, .final_pc = 4096 + 4 * CASES.len, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) } };
        result.tape.len = CASES.len;
        for (CASES, 0..) |c, i| {
            const rs1: u32 = @intCast(1 + 2 * i);
            const rs2: u32 = rs1 + 1;
            const rd: u32 = @intCast(20 + i);
            const op_index = for (D.layout.OPCODES, 0..) |op, j| {
                if (op == c.opcode) break j;
            } else unreachable;
            result.words[i] = (@as(u32, 1) << 25) | (rs2 << 20) | (rs1 << 15) | (@as(u32, @intCast(4 + op_index % 4)) << 12) | (rd << 7) | @as(u32, if (op_index >= 4) 0x3b else 0x33);
            const value = if (i == 0) forged orelse c.result else c.result;
            result.public.initial_registers[rs1] = c.a;
            result.public.initial_registers[rs2] = c.b;
            result.public.register_clocks[rs1] = @intCast(4 * i + 1);
            result.public.register_clocks[rs2] = @intCast(4 * i + 2);
            result.public.register_clocks[rd] = @intCast(4 * i + 3);
            result.tape.storage[i] = .{ .next_pc = 4096 + 4 * (i + 1), .lhs = c.a, .rhs = c.b, .previous_rd = 0, .result = value, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        }
        result.public.final_registers = result.public.initial_registers;
        for (CASES, 0..) |c, i| result.public.final_registers[20 + i] = if (i == 0) forged orelse c.result else c.result;
        return result;
    }
    fn admission(self: *const Fixture) Execution.Admission {
        return .{ .image = .{ .context = &context, .initial_word = zero, .rights_at = rights }, .image_identity = @splat(19), .initial_pc = 4096, .initial_registers = self.public.initial_registers };
    }
    fn deinit(self: *Fixture) void {
        self.tape.deinit();
    }
};
test "closed CPU DIV product graph proves every policy with two physical supports and fresh receiver" {
    var f = try Fixture.init(null);
    defer f.deinit();
    var setup = try Mat.Setup.init(a, .{ .base = 4096, .words = &f.words }, .{ .cpu_log = 6 });
    defer setup.deinit();
    var prepared = try Native.capture(a, &setup.materials.program, f.public, 1, 6, &f.tape, .{});
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, 0), prepared.raw_counts.multiplication);
    try std.testing.expectEqual(@as(u32, CASES.len), prepared.raw_counts.division);
    try std.testing.expectEqual(@as(usize, 2 * CASES.len), prepared.multiplication.len);
    const source = try Source.fromPrepared(a, &setup.materials, f.admission().image, &prepared);
    var proof = try Execution.provePrepared(a, &setup, f.admission(), source, null);
    defer proof.deinit(a);
    try std.testing.expectEqual(@as(u32, 2 * CASES.len), proof.request.multiplication_requests);
    var fresh = try Mat.Setup.init(a, .{ .base = 4096, .words = &f.words }, .{ .cpu_log = 6 });
    defer fresh.deinit();
    try Execution.verify(a, &fresh, f.admission(), proof);
    try std.testing.expectEqual(@as(u32, 23), try @import("coverage.zig").minimalMultiplicationLog(2 * ((1 << 22) - 1)));
    try (Mat.Geometry{ .cpu_log = 22, .division_log = 22, .multiplication_log = 23 }).validate();
    try std.testing.expectError(error.InvalidExecutionGeometry, (Mat.Geometry{ .cpu_log = 22, .multiplication_log = 24 }).validate());
}
fn patchWord(main: []M, n: usize, pos: usize, start: usize, value: u64) void {
    for (0..4) |i| main[(start + i) * n + pos] = M.fromCanonical(@as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
}
fn falseFragment(quotient: u64) !void {
    var f = try Fixture.init(quotient);
    defer f.deinit();
    var setup = try Mat.Setup.init(a, .{ .base = 4096, .words = &f.words }, .{ .cpu_log = 6 });
    defer setup.deinit();
    var prepared = try Native.capture(a, &setup.materials.program, f.public, 1, 6, &f.tape, .{});
    defer prepared.deinit();
    const product: u128 = @as(u128, quotient) * 4;
    prepared.multiplication[0] = .{ .opcode = .MUL, .a = quotient, .b = 4, .result = @truncate(product) };
    prepared.multiplication[1] = .{ .opcode = .MULHU, .a = quotient, .b = 4, .result = @intCast(product >> 64) };
    var source = try Source.fromPrepared(a, &setup.materials, f.admission().image, &prepared);
    defer source.deinit();
    const d = &source.division;
    const pos = A.program.provider.physical(0, d.log_size);
    patchWord(d.main, d.domainSize(), pos, D.layout.QUOTIENT, quotient);
    patchWord(d.main, d.domainSize(), pos, D.layout.OUT, quotient);
    for (source.counts16, d.counts16) |*total, count| total.* -= count;
    d.metadata[0].words[5] = quotient;
    d.metadata[0].words[9] = quotient;
    @memset(d.counts16, 0);
    for (d.metadata) |meta| {
        const row = meta.queryRow();
        for (D.equations.rangeValuesFor(Q, &row)) |value| d.counts16[(try value.tryIntoM31()).v] += 1;
    }
    for (source.counts16, d.counts16) |*total, count| total.* += count;
    source.range16.deinit();
    source.range16 = try A.word16_cpu.table_trace.Source.initRange16(a, setup.materials.range16_fixed, source.counts16);
    try proveRejected(&f, &setup, &source, null);
}

fn proveRejected(f: *const Fixture, setup: *Mat.Setup, source: *Source, patched_division: ?[]const M) !void {
    const request = source.request();
    var scheme = try P.T.Scheme.init(a, P.T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, setup, request, f.admission().image_identity);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    try source.releaseMain();
    const draw = P.draw(&channel);
    var claims = (try source.generateForDelegationJoin(draw)).physical;
    // A patched DIV MAIN carries non-canonical tuple limbs that query metadata
    // cannot represent: rebuild DIV interaction from the committed MAIN itself.
    if (patched_division) |main_copy| claims.division = try rebuildDivisionInteraction(main_copy, &source.division, AB.division(draw.cpu.function, draw.cpu.range16));
    try std.testing.expectError(error.UnclosedExecutionRelations, claims.validate());
    channel.mixFelts(&claims.values());
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    var components = try Components.init(&setup.materials, request, draw, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var result = try engine.prove.proveExWithRecorder(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, scheme, false, null);
    result.aux.deinit(a);
    defer result.proof.deinit(a);
    const bytes = try Wire.encodeProofBytesBinary(a, result.proof);
    defer a.free(bytes);
    var fragment = Execution.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    try @import("optional_division_test.zig").verifyPhysicalFragment(setup, f.admission(), fragment);
    try std.testing.expectError(error.UnclosedExecutionRelations, Execution.verify(a, setup, f.admission(), fragment));
    var total = Q.zero();
    for (claims.values()) |value| total = total.add(value);
    fragment.claims.division = fragment.claims.division.sub(total);
    try fragment.claims.validate();
    try f.admission().validate(setup, fragment.request);
    if (Execution.verify(a, setup, f.admission(), fragment)) |_| return error.AcceptedBalancedFalseProduct else |_| {}
}

test "real valid local DIV proofs require BOTH low and high MUL support closure" {
    try falseFragment(4); // False low product12; true MUL says16.
    try falseFragment((@as(u64, 1) << 62) + 3); // Low product12 is true; high must be1, not0.
}

/// Logical-order DIV interaction from actual committed MAIN values (no metadata).
fn rebuildDivisionInteraction(main: []const M, d: *D.source.Source, ch: D.lookup.Challenges) !Q {
    const n = d.domainSize();
    const L = D.layout;
    var sum = Q.zero();
    for (0..n) |logical| {
        const pos = A.program.provider.physical(logical, d.log_size);
        var row: [L.MAIN]Q = undefined;
        for (&row, 0..) |*v, c| v.* = Q.fromBase(main[c * n + pos]);
        const ds = D.lookup.denominatorsFor(Q, &row, ch);
        var inverses = D.lookup.inverseDenominatorsFor(Q, ds);
        for (&inverses) |*v| v.* = try v.inv();
        for (inverses, 0..) |v, i| for (v.toM31Array(), 0..) |coordinate, c| {
            d.interaction[(4 * i + c) * n + pos] = coordinate;
        };
        sum = sum.add(D.lookup.contributionFor(Q, ds, inverses));
        for (sum.toM31Array(), 0..) |coordinate, c| d.interaction[(L.PREFIX + c) * n + pos] = coordinate;
    }
    for (sum.toM31Array(), 0..) |correction, c| for (0..n) |r| {
        d.interaction[(L.PREFIX + c) * n + r] = d.interaction[(L.PREFIX + c) * n + r].sub(correction);
    };
    return sum;
}
const Alias = enum { signed_a, signed_b, word_upper };
/// Non-canonical A/B limbs that every LOCAL DIV obligation and every retained
/// U16 query accepts once the A/B memberships are gone. The only remaining
/// authority is the closed CPU FUNCTION relation over canonical REG/ROM reads.
fn aliasedOperandFragment(alias: Alias) !void {
    var f = try Fixture.init(null);
    defer f.deinit();
    var setup = try Mat.Setup.init(a, .{ .base = 4096, .words = &f.words }, .{ .cpu_log = 6 });
    defer setup.deinit();
    var prepared = try Native.capture(a, &setup.materials.program, f.public, 1, 6, &f.tape, .{});
    defer prepared.deinit();
    var source = try Source.fromPrepared(a, &setup.materials, f.admission().image, &prepared);
    defer source.deinit();
    const d = &source.division;
    const n = d.domainSize();
    const L = D.layout;
    const target = CASES[
        switch (alias) {
            .signed_a => 2,
            .signed_b => 8,
            .word_upper => 4,
        }
    ];
    const op_index = for (L.OPCODES, 0..) |op, j| {
        if (op == target.opcode) break j;
    } else unreachable;
    const logical = for (d.metadata, 0..) |meta, i| {
        if (meta.opcode == op_index and meta.words[0] == target.a and meta.words[1] == target.b) break i;
    } else return error.MissingDivisionRow;
    const pos = A.program.provider.physical(logical, d.log_size);
    const p = core.fields.m31.Modulus;
    const at = struct {
        fn cell(main: []M, size: usize, row: usize, column: usize) *M {
            return &main[column * size + row];
        }
    }.cell;
    switch (alias) {
        .signed_a => {
            try std.testing.expectEqual(@as(u32, 0xfff1), at(d.main, n, pos, L.A).v);
            try std.testing.expectEqual(@as(u32, 1), at(d.main, n, pos, L.CARRY_A).v);
            at(d.main, n, pos, L.A).* = M.fromCanonical(p - 15);
            at(d.main, n, pos, L.A + 1).* = M.fromCanonical(65536);
            at(d.main, n, pos, L.CARRY_A).* = M.zero();
        },
        .signed_b => {
            try std.testing.expectEqual(@as(u32, 1), at(d.main, n, pos, L.NEG_B).v);
            try std.testing.expectEqual(@as(u32, 1), at(d.main, n, pos, L.CARRY_B).v);
            at(d.main, n, pos, L.B).* = M.fromCanonical(p - 1);
            at(d.main, n, pos, L.B + 1).* = M.fromCanonical(65536);
            at(d.main, n, pos, L.CARRY_B).* = M.zero();
        },
        .word_upper => at(d.main, n, pos, L.A + 3).* = M.fromCanonical(p - 1),
    }
    // Every local residual still vanishes and every retained U16 value is in range.
    var row: [L.MAIN]Q = undefined;
    for (&row, 0..) |*v, c| v.* = Q.fromBase(d.main[c * n + pos]);
    var residuals: [L.ARITHMETIC_CONSTRAINTS]Q = undefined;
    var sink = A.evaluation.Sink{ .values = &residuals };
    D.equations.emitFor(Q, &.{ Q.zero(), Q.zero(), Q.zero() }, &row, row[L.COUNT].sub(Q.one()), Q.zero(), &sink);
    for (residuals[0..L.ARITHMETIC_CONSTRAINTS]) |v| try std.testing.expect(v.isZero());
    const honest = d.metadata[logical].queryRow();
    try std.testing.expectEqualDeep(D.equations.rangeValuesFor(Q, &honest), D.equations.rangeValuesFor(Q, &row));
    const copy = try a.dupe(M, d.main);
    defer a.free(copy);
    try proveRejected(&f, &setup, &source, copy);
}
test "real valid local DIV proofs with non-canonical A/B operand limbs fail only the closed CPU FUNCTION relation" {
    try aliasedOperandFragment(.signed_a);
    try aliasedOperandFragment(.signed_b);
    try aliasedOperandFragment(.word_upper);
}
