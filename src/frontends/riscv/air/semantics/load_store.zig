//! Exact pinned Stark-V byte/half/word load-store semantics and lookups.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub const N_ORACLE_COLUMNS: usize = 56;
pub const N_CONSTRAINTS: usize = 69;
pub const CURRENT_TRACE_COMPATIBLE = true;

pub const Row = struct {
    clk: QM31,
    pc: QM31,
    dst: common.Access,
    rs1: common.Access,
    src: common.Access,
    r2_idx: QM31,
    imm_felt: QM31,
    src_msb: QM31,
    shift_amount: QM31,
    src_addr_selector: QM31,
    dst_addr_selector: QM31,
    markers: [4]QM31,
    is_lb: QM31,
    is_lh: QM31,
    is_lbu: QM31,
    is_lhu: QM31,
    is_lw: QM31,
    is_sb: QM31,
    is_sh: QM31,
    is_sw: QM31,
    result: [4]QM31,
    destination: common.Destination,

    pub fn fromOracleColumns(columns: []const QM31) !Row {
        if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
        return .{
            .clk = columns[0],
            .pc = columns[1],
            .dst = common.accessFromColumns(columns[2..12]),
            .rs1 = common.accessFromColumns(columns[12..22]),
            .src = common.accessFromColumns(columns[22..32]),
            .r2_idx = columns[32],
            .imm_felt = columns[33],
            .src_msb = columns[34],
            .shift_amount = columns[35],
            .src_addr_selector = columns[36],
            .dst_addr_selector = columns[37],
            .markers = columns[38..42].*,
            .is_lb = columns[42],
            .is_lh = columns[43],
            .is_lbu = columns[44],
            .is_lhu = columns[45],
            .is_lw = columns[46],
            .is_sb = columns[47],
            .is_sh = columns[48],
            .is_sw = columns[49],
            .result = columns[50..54].*,
            .destination = common.destinationFromColumns(columns[54..56]),
        };
    }

    pub fn active(self: Row) QM31 {
        return self.is_lb.add(self.is_lh).add(self.is_lbu).add(self.is_lhu)
            .add(self.is_lw).add(self.is_sb).add(self.is_sh).add(self.is_sw);
    }
};

pub const Derived = struct {
    opcode_b: QM31,
    opcode_h: QM31,
    opcode_w: QM31,
    is_signed: QM31,
    load_b: QM31,
    load_h: QM31,
    is_store: QM31,
    is_load: QM31,
    mem_addr: QM31,
    marker_sum: QM31,
    shift_id: QM31,
    signed_mask: QM31,
    aligned_addr_quarter: QM31,
};

pub fn derive(row: Row) Derived {
    const enabler = row.active();
    const opcode_b = row.is_lbu.add(row.is_lb).add(row.is_sb);
    const opcode_h = row.is_lhu.add(row.is_lh).add(row.is_sh);
    const is_signed = row.is_lb.add(row.is_lh);
    const is_store = row.is_sb.add(row.is_sh).add(row.is_sw);
    var marker_sum = QM31.zero();
    var shift_id = QM31.zero();
    for (row.markers, 0..) |marker, i| {
        marker_sum = marker_sum.add(marker);
        shift_id = shift_id.add(marker.mul(common.q(i)));
    }
    return .{
        .opcode_b = opcode_b,
        .opcode_h = opcode_h,
        .opcode_w = row.is_lw.add(row.is_sw),
        .is_signed = is_signed,
        .load_b = row.is_lb.add(row.is_lbu),
        .load_h = row.is_lh.add(row.is_lhu),
        .is_store = is_store,
        .is_load = enabler.sub(is_store),
        .mem_addr = common.composeU32(row.rs1.next).add(row.imm_felt),
        .marker_sum = marker_sum,
        .shift_id = shift_id,
        .signed_mask = is_signed.mul(row.src_msb).mul(common.q(255)),
        .aligned_addr_quarter = row.src_addr_selector.add(row.dst_addr_selector)
            .sub(row.r2_idx).mul(common.INV_4),
    };
}

pub const Constraints = common.ConstraintSet(N_CONSTRAINTS);

pub fn evaluate(row: Row) Constraints {
    @setEvalBranchQuota(100_000);
    var out: [N_CONSTRAINTS]QM31 = undefined;
    var n: usize = 0;
    const d = derive(row);
    out[n] = common.bit(row.active());
    n += 1;
    for ([_]QM31{
        row.is_lb, row.is_lh, row.is_lbu, row.is_lhu,
        row.is_lw, row.is_sb, row.is_sh,  row.is_sw,
    }) |flag| {
        out[n] = common.bit(flag);
        n += 1;
    }
    out[n] = common.bit(row.src_msb);
    n += 1;
    // The sign witness has no meaning outside signed loads. Canonicalizing it
    // prevents an unconstrained committed column on every other opcode.
    out[n] = QM31.one().sub(d.is_signed).mul(row.src_msb);
    n += 1;

    for (row.markers) |marker| {
        out[n] = common.bit(marker);
        n += 1;
    }
    out[n] = row.shift_amount.sub(
        d.opcode_b.mul(d.shift_id)
            .add(d.opcode_h.mul(d.shift_id.sub(QM31.one())).mul(common.INV_2)),
    );
    n += 1;
    out[n] = row.src_addr_selector.sub(
        d.is_load.mul(d.mem_addr.sub(row.shift_amount)).add(d.is_store.mul(row.r2_idx)),
    );
    n += 1;
    out[n] = row.dst_addr_selector.sub(
        d.is_load.mul(row.r2_idx).add(d.is_store.mul(d.mem_addr.sub(row.shift_amount))),
    );
    n += 1;
    out[n] = d.opcode_b.mul(QM31.one().sub(d.marker_sum));
    n += 1;
    out[n] = d.opcode_h.mul(common.q(2).sub(d.marker_sum));
    n += 1;
    out[n] = d.opcode_h.mul(QM31.one().sub(d.shift_id)).mul(common.q(5).sub(d.shift_id));
    n += 1;

    for (1..4) |limb| {
        out[n] = d.load_b.mul(d.signed_mask.sub(row.result[limb]));
        n += 1;
    }
    for (0..4) |limb| {
        const marker = row.markers[limb];
        out[n] = d.load_b.mul(row.result[0].sub(row.src.next[limb])).mul(marker);
        n += 1;
        out[n] = row.is_sb.mul(row.dst.next[limb].sub(row.src.next[0])).mul(marker);
        n += 1;
    }
    for (2..4) |limb| {
        out[n] = d.load_h.mul(d.signed_mask.sub(row.result[limb]));
        n += 1;
    }

    const low_half = common.q(5).sub(d.shift_id).mul(common.INV_4);
    const high_half = d.shift_id.sub(QM31.one()).mul(common.INV_4);
    out[n] = d.load_h.mul(low_half).mul(row.result[0].sub(row.src.next[0]));
    n += 1;
    out[n] = d.load_h.mul(low_half).mul(row.result[1].sub(row.src.next[1]));
    n += 1;
    out[n] = d.load_h.mul(high_half).mul(row.result[0].sub(row.src.next[2]));
    n += 1;
    out[n] = d.load_h.mul(high_half).mul(row.result[1].sub(row.src.next[3]));
    n += 1;
    out[n] = row.is_sh.mul(low_half).mul(row.dst.next[0].sub(row.src.next[0]));
    n += 1;
    out[n] = row.is_sh.mul(low_half).mul(row.dst.next[1].sub(row.src.next[1]));
    n += 1;
    out[n] = row.is_sh.mul(high_half).mul(row.dst.next[2].sub(row.src.next[0]));
    n += 1;
    out[n] = row.is_sh.mul(high_half).mul(row.dst.next[3].sub(row.src.next[1]));
    n += 1;

    for (0..4) |limb| {
        out[n] = row.is_lw.mul(row.result[limb].sub(row.src.next[limb]))
            .add(row.is_sw.mul(row.dst.next[limb].sub(row.src.next[limb])));
        n += 1;
    }
    // Read-only accesses must emit exactly the value they consumed. The
    // access chain commits `previous` and `next` as distinct column groups
    // and the semantics above compute on `next`, so without these residuals
    // both source operands are free prover choices that are also written back
    // to the register file or memory. `rs1` is always read-only; `src` is
    // read-only in both directions (the loaded memory word or the stored data
    // register). `dst` is the written access — its `next` is pinned by the
    // load result link and the store constraints instead.
    const enabler = row.active();
    for (common.readOnlyAccessConstraints(row.rs1, enabler)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    for (common.readOnlyAccessConstraints(row.src, enabler)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    // A byte or halfword store overwrites only its marked bytes; every
    // unmarked byte of the target memory word must survive unchanged. The
    // marker set is already pinned by the marker-sum and shift-id constraints
    // (exactly {offset} for SB and exactly {0,1} or {2,3} for SH), so this
    // closes the otherwise-free unmarked limbs of `dst.next`. SW stays a
    // full-word overwrite through the word constraints above and loads are
    // unaffected.
    const partial_store = row.is_sb.add(row.is_sh);
    for (0..4) |limb| {
        out[n] = partial_store
            .mul(QM31.one().sub(row.markers[limb]))
            .mul(row.dst.next[limb].sub(row.dst.previous[limb]));
        n += 1;
    }
    for (common.destinationConstraints(row.r2_idx, row.destination)) |constraint| {
        out[n] = constraint;
        n += 1;
    }
    for (common.destinationResultConstraints(
        row.dst,
        row.result,
        row.destination,
    )) |constraint| {
        out[n] = d.is_load.mul(constraint);
        n += 1;
    }
    // Stores do not have an architectural result. Pin the appended result
    // witness to its canonical zero encoding so no committed cell is free.
    for (row.result) |limb| {
        out[n] = QM31.one().sub(d.is_load).mul(limb);
        n += 1;
    }
    std.debug.assert(n == out.len);
    return .{ .values = out };
}

pub fn placementConstraint(row: Row, is_active: QM31) QM31 {
    return row.active().sub(is_active);
}

pub fn programLookup(row: Row) common.ProgramTuple {
    const opcode_id = row.is_lb.mul(common.q(19)).add(row.is_lh.mul(common.q(20)))
        .add(row.is_lw.mul(common.q(21))).add(row.is_lbu.mul(common.q(22)))
        .add(row.is_lhu.mul(common.q(23))).add(row.is_sb.mul(common.q(24)))
        .add(row.is_sh.mul(common.q(25))).add(row.is_sw.mul(common.q(26)));
    return .{
        .pc = row.pc,
        .opcode_id = opcode_id,
        .rd = row.rs1.addr,
        .rs1 = row.r2_idx,
        .operand = row.imm_felt,
    };
}

pub const AccessLookups = struct {
    rs1: common.AccessChain,
    src: common.AccessChain,
    dst: common.AccessChain,
};

pub fn accessLookups(row: Row) AccessLookups {
    const d = derive(row);
    return .{
        .rs1 = common.registerAccessChain(row.rs1, row.clk),
        .src = common.accessChain(row.src, row.clk, d.is_load, row.src_addr_selector, row.src.next),
        .dst = common.accessChain(row.dst, row.clk, d.is_store, row.dst_addr_selector, row.dst.next),
    };
}

pub fn stateLookup(row: Row) common.RegistersStateChain {
    return common.registersStateChain(row.pc, row.clk);
}

pub fn alignedAddressRangeLookup(row: Row) QM31 {
    return derive(row).aligned_addr_quarter;
}

pub fn baseAddressM31Lookup(row: Row) [2]QM31 {
    return .{ row.rs1.next[0], row.rs1.next[3] };
}

/// Seven-bit residuals that bind `src_msb` to the actual sign-bearing result
/// byte. The caller activates the first tuple for LB and the second for LH.
pub fn signRangeLookups(row: Row) [2][2]QM31 {
    return .{
        .{ QM31.zero(), row.result[0].sub(row.src_msb.mul(common.q(128))) },
        .{ QM31.zero(), row.result[1].sub(row.src_msb.mul(common.q(128))) },
    };
}

fn zeroAccess() common.Access {
    return .{
        .addr = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .previous_clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
    };
}

fn honestSignedByteLoad() Row {
    var dst = zeroAccess();
    dst.addr = common.q(2);
    dst.next = .{ common.q(128), common.q(255), common.q(255), common.q(255) };
    var src = zeroAccess();
    src.addr = QM31.zero();
    src.previous = .{ common.q(7), common.q(128), common.q(9), common.q(10) };
    src.next = src.previous;
    return .{
        .clk = QM31.one(),
        .pc = common.q(0x1000),
        .dst = dst,
        .rs1 = zeroAccess(),
        .src = src,
        .r2_idx = common.q(2),
        .imm_felt = QM31.one(),
        .src_msb = QM31.one(),
        .shift_amount = QM31.one(),
        .src_addr_selector = QM31.zero(),
        .dst_addr_selector = common.q(2),
        .markers = .{ QM31.zero(), QM31.one(), QM31.zero(), QM31.zero() },
        .is_lb = QM31.one(),
        .is_lh = QM31.zero(),
        .is_lbu = QM31.zero(),
        .is_lhu = QM31.zero(),
        .is_lw = QM31.zero(),
        .is_sb = QM31.zero(),
        .is_sh = QM31.zero(),
        .is_sw = QM31.zero(),
        .result = .{ common.q(128), common.q(255), common.q(255), common.q(255) },
        .destination = .{
            .nonzero = QM31.one(),
            .inverse = common.q(2).inv() catch unreachable,
        },
    };
}

test "load store: signed byte load is accepted with exact address roles" {
    var row = honestSignedByteLoad();
    std.mem.doNotOptimizeAway(&row);
    try std.testing.expect(evaluate(row).allZero());
    try std.testing.expect(programLookup(row).opcode_id.eql(common.q(19)));
    const accesses = accessLookups(row);
    try std.testing.expect(accesses.src.next.addr_space.eql(QM31.one()));
    try std.testing.expect(accesses.dst.next.addr_space.isZero());
}

test "load store: forged selected byte and unaligned selector are rejected" {
    var row = honestSignedByteLoad();
    row.dst.next[0] = common.q(127);
    try std.testing.expect(!evaluate(row).allZero());
    row = honestSignedByteLoad();
    row.src_addr_selector = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());

    row = honestSignedByteLoad();
    row.src_msb = common.q(3);
    row.result = .{ common.q(128), common.q(765), common.q(765), common.q(765) };
    row.dst.next = row.result;
    try std.testing.expect(!evaluate(row).allZero());
}

test "load store: read-only accesses must emit the value they consumed" {
    var row = honestSignedByteLoad();
    row.rs1.previous[0] = common.q(7);
    try std.testing.expect(!evaluate(row).allZero());

    row = honestSignedByteLoad();
    row.src.previous[1] = common.q(64);
    try std.testing.expect(!evaluate(row).allZero());
}

fn honestByteStore() Row {
    var row = honestSignedByteLoad();
    row.is_lb = QM31.zero();
    row.is_sb = QM31.one();
    row.src_msb = QM31.zero();
    row.r2_idx = common.q(3);
    row.destination = .{
        .nonzero = QM31.one(),
        .inverse = common.q(3).inv() catch unreachable,
    };
    row.src.addr = common.q(3);
    row.src.previous = .{ common.q(0xab), QM31.zero(), QM31.zero(), QM31.zero() };
    row.src.next = row.src.previous;
    row.dst.addr = QM31.zero();
    row.dst.previous = .{ common.q(1), common.q(2), common.q(3), common.q(4) };
    row.dst.next = .{ common.q(1), common.q(0xab), common.q(3), common.q(4) };
    row.result = .{QM31.zero()} ** 4;
    row.src_addr_selector = common.q(3);
    row.dst_addr_selector = QM31.zero();
    return row;
}

test "load store: byte store preserves the unmarked bytes of the word" {
    var row = honestByteStore();
    try std.testing.expect(evaluate(row).allZero());
    row.dst.next[3] = common.q(0xee);
    try std.testing.expect(!evaluate(row).allZero());
}

test "load store: signed-load range requests bind the selected sign byte" {
    const table = @import("../lookups/tables/schema.zig");

    var row = honestSignedByteLoad();
    const honest = signRangeLookups(row);
    _ = try table.indexSecure(.range_check_m31, &honest[0]);

    row.src_msb = QM31.zero();
    row.result = .{ common.q(128), QM31.zero(), QM31.zero(), QM31.zero() };
    row.dst.next = row.result;
    try std.testing.expect(evaluate(row).allZero());
    const forged = signRangeLookups(row);
    try std.testing.expectError(
        error.ValueOutOfRange,
        table.indexSecure(.range_check_m31, &forged[0]),
    );
}

test "load store: a load to x0 still constrains memory but discards its result" {
    var row = honestSignedByteLoad();
    row.dst.addr = QM31.zero();
    row.r2_idx = QM31.zero();
    row.dst_addr_selector = QM31.zero();
    row.dst.next = .{QM31.zero()} ** 4;
    row.destination = .{ .nonzero = QM31.zero(), .inverse = QM31.zero() };
    try std.testing.expect(evaluate(row).allZero());

    row.src_addr_selector = QM31.one();
    try std.testing.expect(!evaluate(row).allZero());
}

test "load store: word store reverses register and memory roles" {
    var row = honestSignedByteLoad();
    row.is_lb = QM31.zero();
    row.is_sw = QM31.one();
    row.src_msb = QM31.zero();
    row.markers = .{QM31.zero()} ** 4;
    row.shift_amount = QM31.zero();
    row.imm_felt = common.q(4);
    row.r2_idx = common.q(3);
    row.destination = .{
        .nonzero = QM31.one(),
        .inverse = common.q(3).inv() catch unreachable,
    };
    row.src.addr = common.q(3);
    row.src.previous = .{ common.q(1), common.q(2), common.q(3), common.q(4) };
    row.src.next = row.src.previous;
    row.dst.next = row.src.next;
    row.result = .{QM31.zero()} ** 4;
    row.src_addr_selector = common.q(3);
    row.dst_addr_selector = common.q(4);
    try std.testing.expect(evaluate(row).allZero());
    const accesses = accessLookups(row);
    try std.testing.expect(accesses.src.next.addr_space.isZero());
    try std.testing.expect(accesses.dst.next.addr_space.eql(QM31.one()));
    try std.testing.expect(programLookup(row).opcode_id.eql(common.q(26)));
}

test "load store: adapter follows exact role and flag order" {
    var columns = [_]QM31{QM31.zero()} ** N_ORACLE_COLUMNS;
    columns[2] = common.q(10);
    columns[12] = common.q(11);
    columns[22] = common.q(12);
    columns[32] = common.q(13);
    columns[42] = common.q(14);
    columns[49] = common.q(15);
    const row = try Row.fromOracleColumns(&columns);
    try std.testing.expect(row.dst.addr.eql(common.q(10)));
    try std.testing.expect(row.rs1.addr.eql(common.q(11)));
    try std.testing.expect(row.src.addr.eql(common.q(12)));
    try std.testing.expect(row.r2_idx.eql(common.q(13)));
    try std.testing.expect(row.is_lb.eql(common.q(14)));
    try std.testing.expect(row.is_sw.eql(common.q(15)));
}
