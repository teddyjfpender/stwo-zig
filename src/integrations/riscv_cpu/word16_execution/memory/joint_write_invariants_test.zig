//! Regression guards for the concrete premises of joint REG/RAM induction.
//! These complement, rather than replace, the actual physical-proof attacks.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const E = A.evaluation;
const LS = A.memory.load_store_v2;
const V = A.memory.load_store_v1;
const R = A.memory.closed_ram;
const X = A.word16_execution;
const K = A.crypto.keccak.word16_bridge;
const S = A.crypto.secp256k1.word16_bridge;
const Q = E.Q;
const a = std.testing.allocator;
fn q(x: u32) Q {
    return E.q(x);
}
fn qrow(values: anytype) [values.len]Q {
    var out: [values.len]Q = undefined;
    for (&out, values) |*v, x| v.* = Q.fromBase(x);
    return out;
}
fn localValues(row: []const Q, values: []Q) []const Q {
    const fixed = [_]Q{ Q.zero(), Q.one(), Q.zero() };
    const previous: [79]Q = @splat(Q.zero());
    var sink = E.Sink{ .values = values };
    V.equations.emitLocalFor(Q, &fixed, row, &previous, 1, &sink);
    return values[0..sink.count];
}
fn hasNewResidual(honest: []const Q, forged: []const Q) bool {
    for (honest, forged) |x, y| if (x.isZero() and !y.isZero()) return true;
    return false;
}
test "LS32 unit OWNER RAM coupling and CPU tick coordinates remain shared and Boolean" {
    const before = R.types.State{ .value = 0, .rights = 3 };
    for (0..8) |index| {
        const tick: u24 = @intCast(4 * index + 4);
        const native = LS.native.logicalRow(.{ .opcode = .LD, .a = 0x1000, .immediate = 0, .c = 0, .epoch = 1, .tick = tick, .before = before, .after = .{ .value = 0, .rights = 3, .epoch = 1, .tick = tick } });
        const logical = qrow(native);
        var cpu: [X.layout.main.COUNT]Q = @splat(Q.zero());
        cpu[X.layout.main.operation] = q(@intFromEnum(front.rv64.decode.Opcode.LD));
        cpu[X.layout.main.active] = Q.one();
        cpu[X.layout.main.a] = q(0x1000);
        const fixed = [_]Q{ q(@intCast(index)), Q.zero(), Q.zero() };
        const owner = X.tuples.owner(Q, &fixed, &cpu, Q.one());
        try std.testing.expectEqualDeep(owner, LS.equations.ownerTupleForLogical(Q, &logical));
        try std.testing.expect(owner[18].eql(q(tick)));
        try std.testing.expect(X.equations.weightsFor(Q, &cpu).owner.eql(logical[0]));
        var off_residue = logical;
        off_residue[12] = off_residue[12].add(Q.one());
        off_residue[3] = off_residue[3].add(Q.one());
        try std.testing.expect(!owner[18].eql(LS.equations.ownerTupleForLogical(Q, &off_residue)[18]));
    }
    const native = LS.native.logicalRow(.{ .opcode = .LD, .a = 0x1000, .immediate = 0, .c = 0, .epoch = 1, .tick = 4, .before = before, .after = .{ .value = 0, .rights = 3, .epoch = 1, .tick = 4 } });
    const honest = qrow(native);
    var baseline: [300]Q = undefined;
    const expected = localValues(&honest, &baseline);
    for (expected) |v| try std.testing.expect(v.isZero());
    for ([_]Q{ q(2), try q(2).inv() }) |weight| {
        var forged = honest;
        forged[0] = weight;
        var values: [300]Q = undefined;
        try std.testing.expect(hasNewResidual(expected, localValues(&forged, &values)));
    }
}
test "LS32 SB selection parity and replacement factor agree at every byte offset" {
    const value: u64 = 0x8070605040302010;
    for (0..8) |offset| {
        const shift: u6 = @intCast(8 * offset);
        const after = (value & ~(@as(u64, 255) << shift)) | (@as(u64, 0xa5) << shift);
        const native = LS.native.logicalRow(.{ .opcode = .SB, .a = 0x1000 + offset, .immediate = 0, .b = 0xa5, .epoch = 1, .tick = 4, .before = .{ .value = value, .rights = 3 }, .after = .{ .value = after, .rights = 3, .epoch = 1, .tick = 4 } });
        const logical = qrow(native);
        var values: [300]Q = undefined;
        for (localValues(&logical, &values)) |v| try std.testing.expect(v.isZero());
        const tuple = V.equations.selectionTuple(Q, &logical);
        try std.testing.expect(tuple[1].eql(q(@intCast(offset & 1))));
        const limb = offset / 2;
        const factor = q(if (offset & 1 == 0) 1 else 256);
        try std.testing.expect(logical[18 + limb].eql(logical[14 + limb].add(factor.mul(logical[V.layout.b_low].sub(tuple[2])))));
        for (logical[18..22]) |v| try std.testing.expect((try v.tryIntoM31()).v < 65536);
    }
}
test "LS32 register writer inventory includes ROM ALU LUI AUIPC JAL JALR and all delegated families" {
    const effects = front.rv64.execution_profile.effects;
    var writers: usize = 0;
    for (std.enums.values(front.rv64.decode.Opcode)) |opcode| {
        const entry = X.features.Entry.fromInstruction(0, 4096, .{ .opcode = opcode, .rs1 = 2, .rs2 = 3, .rd = 1, .imm = 8 });
        if (!entry.valid or !effects(.ethereum_services_v2, opcode).writes_rd) continue;
        writers += 1;
        if (LS.types.isLoadStore(opcode)) {
            try std.testing.expect(!entry.function);
            try std.testing.expectEqual(@as(u8, @intFromEnum(opcode)), entry.operation);
        } else {
            try std.testing.expect(entry.function);
            try std.testing.expect(entry.operation <= 10 or (entry.operation >= 16 and entry.operation <= 18) or (entry.operation >= 32 and entry.operation <= 37) or (entry.operation >= 49 and entry.operation <= 61));
        }
        if (opcode == .LUI or opcode == .AUIPC or opcode == .JAL) {
            try std.testing.expectEqual(@as(u8, 0), entry.operation);
            try std.testing.expect(entry.use_immediate);
            try std.testing.expectEqual(opcode != .LUI, entry.use_pc);
        }
        if (opcode == .JALR) {
            try std.testing.expect(entry.dynamic_next);
            const fact = entry.romTuple(false);
            try std.testing.expectEqual(@as(u32, 4100), fact[X.layout.rom.link].v);
        }
    }
    try std.testing.expectEqual(@as(usize, 52), writers);
    const D = A.arithmetic.division.word16_product;
    var div: [D.layout.MAIN]Q = @splat(Q.zero());
    for (0..4) |limb| div[D.layout.C + limb] = q(@intCast(65536 + limb));
    const queries = D.equations.rangeValuesFor(Q, &div);
    for (0..4) |limb| try std.testing.expect(queries[limb].eql(div[D.layout.C + limb]));
    const MUL = A.arithmetic.multiplication;
    var mul: [MUL.layout.MAIN]Q = @splat(Q.zero());
    for (0..8) |byte| mul[MUL.layout.RESULT + byte] = q(@intCast(256 + byte));
    const bytes = MUL.provider.byteValuesFor(Q, &mul);
    for (0..8) |byte| try std.testing.expect(bytes[MUL.layout.RESULT + byte].eql(mul[MUL.layout.RESULT + byte]));
    const ALU = A.word16_v1.alu_experiment.equations;
    var row: ALU.RowFor(Q) = undefined;
    for (&row.sum, &row.difference, 0..) |*sum, *difference, limb| {
        sum.* = q(@intCast(65536 + limb));
        difference.* = q(@intCast(65540 + limb));
    }
    for (0..4) |limb| {
        try std.testing.expect(ALU.rangeValueFor(Q, &row, limb).eql(row.sum[limb]));
        try std.testing.expect(ALU.rangeValueFor(Q, &row, 4 + limb).eql(row.difference[limb]));
    }
    for (0..8) |bits| {
        const predicate = ALU.signedLessFor(Q, q(@intCast(bits & 1)), q(@intCast((bits >> 1) & 1)), q(@intCast((bits >> 2) & 1)));
        try std.testing.expect(predicate.isZero() or predicate.eql(Q.one()));
    }
    const Binary = A.word16_v1.binary;
    var binary: Binary.RowFor(Q) = undefined;
    for (&binary.a, &binary.b, &binary.ab, 0..) |*x, *y, *z, byte| {
        x.* = q(@intCast(256 + byte));
        y.* = q(@intCast(264 + byte));
        z.* = q(@intCast(272 + byte));
        try std.testing.expectEqualDeep([_]Q{ x.*, y.*, z.* }, Binary.andTupleFor(Q, &binary, byte));
    }
    const Table = A.word16_v1.shift_word_experiment.table;
    for (0..16) |amount| {
        const tuple = Table.tupleAt(65535 * 16 + amount);
        try std.testing.expectEqual(@as(u32, 65535), tuple[2] + tuple[3]);
        try std.testing.expectEqual(@as(u32, 65535), tuple[4] + tuple[5]);
    }
}
/// Secp/SHA Word16 bridges take a typed call span; the Keccak bridge keeps
/// its scalar (calls, first ID) arguments.
fn emitBridge(comptime B: type, comptime kind: ?A.crypto.secp256k1.word16_bridge.types.Kind, fixed: []const Q, current: []const Q, previous: []const Q, inter: []const Q, ch: B.types.Challenges, sink: *E.Sink) void {
    if (kind) |k| {
        B.equations.emitFor(Q, k, fixed, current, previous, inter, inter, .{ .calls = 1, .first_id = 1 }, B.types.Claims.zero(), ch, sink);
    } else {
        B.equations.emitFor(Q, .bridge, fixed, current, previous, inter, inter, 1, 1, B.types.Claims.zero(), ch, sink);
    }
}
fn compareBridge(comptime B: type, comptime kind: ?A.crypto.secp256k1.word16_bridge.types.Kind) !void {
    const zero = Q.zero();
    const ch: B.types.Challenges = if (kind != null) .{ .ram = .{ .offset = Q.one(), .coefficients = @splat(zero) }, .owner = .{ .offset = Q.one(), .coefficients = @splat(zero) }, .wire = .{ .offset = Q.one(), .coefficients = @splat(zero) }, .range16 = .{ .offset = Q.one(), .coefficient = Q.one() }, .range8 = .{ .offset = Q.one(), .coefficient = Q.one() } } else .{ .ram = .{ .offset = Q.one(), .coefficients = @splat(zero) }, .owner = .{ .offset = Q.one(), .coefficients = @splat(zero) }, .io = .{ .offset = Q.one(), .coefficients = @splat(zero) }, .range16 = .{ .offset = Q.one(), .coefficient = Q.one() }, .range8 = .{ .offset = Q.one(), .coefficient = Q.one() } };
    const call = B.types.Call{ .pointer = 0x8000, .epoch = 1, .tick = 4, .before = @splat(0), .after = @splat(0), .predecessors = @splat(.{ .value = 0, .rights = 3 }) };
    const previous_native = if (kind) |k| B.source.nativeRow(k, call, 0, 1) else B.source.nativeRow(call, 0, 1);
    const current_native = if (kind) |k| B.source.nativeRow(k, call, 1, 1) else B.source.nativeRow(call, 1, 1);
    const previous = qrow(previous_native);
    const current = qrow(current_native);
    const fixed_matrix = if (kind) |k| try B.source.fixed(a, k, 5) else try B.source.fixed(a, 5);
    defer a.free(fixed_matrix);
    const p = R.trace.physical(1, 5);
    var fixed: [B.layout.FIXED]Q = undefined;
    for (&fixed, 0..) |*f, column| f.* = Q.fromBase(fixed_matrix[column * 32 + p]);
    var honest: [B.layout.CONSTRAINTS]Q = undefined;
    var forged: [B.layout.CONSTRAINTS]Q = undefined;
    const inter: [B.layout.INTERACTION]Q = @splat(zero);
    var hs = E.Sink{ .values = &honest };
    emitBridge(B, kind, &fixed, &current, &previous, &inter, ch, &hs);
    var changed = current;
    if (kind != null) {
        changed[B.layout.TICK] = changed[B.layout.TICK].add(Q.one());
        changed[B.layout.LOW] = changed[B.layout.LOW].add(Q.one());
    } else {
        changed[3] = changed[3].add(Q.one());
        changed[12] = changed[12].add(Q.one());
    }
    var fs = E.Sink{ .values = &forged };
    emitBridge(B, kind, &fixed, &changed, &previous, &inter, ch, &fs);
    try std.testing.expectEqual(hs.count, fs.count);
    try std.testing.expect(hasNewResidual(honest[0..hs.count], forged[0..fs.count]));
    const start = if (kind != null) B.layout.AFTER else B.layout.AFTER_BYTES;
    const count: usize = if (kind != null) 32 else 8;
    for (start..start + count) |byte| try std.testing.expect(std.mem.indexOfScalar(usize, &B.layout.U8, byte) != null);
    const owner = if (kind) |k| B.equations.ownerTuple(Q, k, &current) else B.equations.ownerTuple(Q, &current);
    for (owner[13..17]) |c| try std.testing.expect(c.isZero());
}
test "LS32 Keccak ADD DOUBLE producers retain byte anchors zero register C and continuation clock equality" {
    try compareBridge(K, null);
    try compareBridge(S, .add);
    try compareBridge(S, .double);
}
fn expectNames(comptime T: type, names: []const []const u8) !void {
    const fields = std.meta.fields(T);
    try std.testing.expectEqual(names.len, fields.len);
    inline for (fields, 0..) |f, i| try std.testing.expectEqualStrings(names[i], f.name);
}
test "services RAM writer inventory matches the joint write induction cases" {
    // Every RAM writer below has a case (W1-W5) in
    // design/riscv-proving-stack/rv64-ls-joint-write-induction.md section 11.
    // Adding a roster source, a bridge kind, a bulk kind or a sponge kind
    // requires adding its case there first, then updating this inventory.
    const Roster = @import("../../word16_global_execution/services/roster.zig");
    try expectNames(Roster.Sources, &.{ "core", "keccak", "add", "double", "sha256", "arith256_mod", "curves", "bulk", "sponge_plan", "sponge", "ls_dword" });
    try expectNames(S.types.Kind, &.{ "add", "double", "sha256", "arith256_mod", "bn254_g1_add", "bn254_g1_double", "bn254_fp2_mul", "bls12_381_fp2_mul", "arith384_mont", "bls12_381_g1_add", "bls12_381_g1_double" });
    const BM = A.crypto.bulk_memory;
    try expectNames(BM.layout.Kind, &.{ "desc", "copy", "set", "ucopy", "cdesc", "cmp" });
    try std.testing.expectEqual(BM.layout.kinds.len, @typeInfo(@FieldType(Roster.Sources, "bulk")).array.len);
    try expectNames(A.crypto.keccak_sponge.layout.Kind, &.{ "call", "perm" });
    try std.testing.expectEqual(@as(usize, 2), @typeInfo(@FieldType(Roster.Sources, "sponge")).array.len);
}

test "LS-D64 writer case: unit OWNER/RAM coupling, CPU tick, LD after = before and SD after = B" {
    // Section 12 of rv64-ls-joint-write-induction.md: LS-D64 is a restriction
    // of the LS32 row, so its two writers are the LS32 LD and SD cases.
    const D = A.memory.load_store_dword;
    const before = R.types.State{ .value = 0x0123456789abcdef, .rights = 3 };
    for ([_]front.rv64.decode.Opcode{ .LD, .SD }) |op| for (0..4) |index| {
        const tick: u24 = @intCast(4 * index + 4);
        const b: u64 = if (op == .SD) 0xfedcba9876543210 else 0;
        const event = LS.native.Event{ .opcode = op, .a = 0x1000, .immediate = 8, .b = b, .c = if (op == .LD) before.value else 0, .epoch = 1, .tick = tick, .before = before, .after = .{ .value = if (op == .SD) b else before.value, .rights = 3, .epoch = 1, .tick = tick } };
        try D.source.validate(event);
        const physical = D.source.row(event);
        const m = D.layout.expandFor(M, &physical);
        // OWNER19 equals the CPU tuple of the same row; weight is RAM `active`.
        var cpu: [X.layout.main.COUNT]Q = @splat(Q.zero());
        cpu[X.layout.main.operation] = q(@intFromEnum(op));
        cpu[X.layout.main.active] = Q.one();
        cpu[X.layout.main.a] = q(0x1000);
        const fixed = [_]Q{ q(@intCast(index)), Q.zero(), Q.zero() };
        const owner = X.tuples.owner(Q, &fixed, &cpu, Q.one());
        const dword_owner = D.equations.ownerTuple(M, &physical);
        try std.testing.expect(owner[0].eql(Q.fromBase(dword_owner[0])));
        try std.testing.expect(owner[18].eql(q(tick)) and dword_owner[18].v == tick);
        try std.testing.expect(X.equations.weightsFor(Q, &cpu).owner.eql(Q.fromBase(m[0])));
        // Written limbs: LD copies before (E3), SD copies B (E4); C is the
        // before word for LD (E2) and zero for SD.
        for (0..4) |c| {
            const want = if (op == .LD) m[14 + c] else m[V.layout.b + c];
            try std.testing.expectEqual(want.v, m[18 + c].v);
            try std.testing.expectEqual(if (op == .LD) m[14 + c].v else 0, m[V.layout.c + c].v);
        }
    };
}
const M = core.fields.m31.M31;
