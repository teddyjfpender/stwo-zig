//! Exact pinned Stark-V AIR semantics for BLT, BLTU, BGE, and BGEU.
//!
//! The comparison scans byte limbs from most to least significant and uses a
//! signed-MSB witness only for signed opcodes, matching `schema.rs` exactly.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_MAIN_COLUMNS: usize = 37;
        pub const N_CONSTRAINTS: usize = 32;

        pub const Row = struct {
            clock: S,
            pc: S,
            rs1: ops.Access,
            rs2: ops.Access,
            rs1_msl_felt: S,
            rs2_msl_felt: S,
            imm_felt: S,
            cmp_result: S,
            cmp_lt: S,
            diff_markers: [4]S,
            diff_val: S,
            branch_target: S,
            opcode_blt_flag: S,
            opcode_bltu_flag: S,
            opcode_bge_flag: S,
            opcode_bgeu_flag: S,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .clock = columns[0],
                    .pc = columns[1],
                    .rs1 = ctl.accessFromColumns(columns, 2),
                    .rs2 = ctl.accessFromColumns(columns, 12),
                    .rs1_msl_felt = columns[22],
                    .rs2_msl_felt = columns[23],
                    .imm_felt = columns[24],
                    .cmp_result = columns[25],
                    .cmp_lt = columns[26],
                    .diff_markers = columns[27..31].*,
                    .diff_val = columns[31],
                    .branch_target = columns[32],
                    .opcode_blt_flag = columns[33],
                    .opcode_bltu_flag = columns[34],
                    .opcode_bge_flag = columns[35],
                    .opcode_bgeu_flag = columns[36],
                };
            }

            pub fn enabler(self: Row) S {
                return self.opcode_blt_flag
                    .add(self.opcode_bltu_flag)
                    .add(self.opcode_bge_flag)
                    .add(self.opcode_bgeu_flag);
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            @setEvalBranchQuota(10_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var i: usize = 0;

            const enabler = row.enabler();
            const flags = [_]S{
                row.opcode_blt_flag,
                row.opcode_bltu_flag,
                row.opcode_bge_flag,
                row.opcode_bgeu_flag,
            };
            out[i] = ops.bit(enabler);
            i += 1;
            for (flags) |flag| {
                out[i] = ops.bit(flag);
                i += 1;
            }
            out[i] = ops.bit(row.cmp_result);
            i += 1;
            for (row.diff_markers) |marker| {
                out[i] = ops.bit(marker);
                i += 1;
            }

            const not_cmp = S.one().sub(row.cmp_result);
            const selected_target = row.pc
                .add(row.imm_felt.mul(row.cmp_result))
                .add(ops.q(4).mul(not_cmp));
            out[i] = enabler.mul(row.branch_target.sub(selected_target));
            i += 1;

            const rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt);
            const rs2_msl_gap = row.rs2.next[3].sub(row.rs2_msl_felt);
            out[i] = rs1_msl_gap.mul(ops.q(1 << 8).sub(rs1_msl_gap));
            i += 1;
            out[i] = rs2_msl_gap.mul(ops.q(1 << 8).sub(rs2_msl_gap));
            i += 1;

            const prefix = row.diff_markers[0]
                .add(row.diff_markers[1])
                .add(row.diff_markers[2])
                .add(row.diff_markers[3]);
            const lt_sign = ops.q(2).mul(row.cmp_lt).sub(S.one());

            const m3 = row.diff_markers[3];
            const m2 = row.diff_markers[2];
            const m1 = row.diff_markers[1];
            const m0 = row.diff_markers[0];
            const diff3 = lt_sign.mul(row.rs2_msl_felt.sub(row.rs1_msl_felt));
            const diff2 = lt_sign.mul(row.rs2.next[2].sub(row.rs1.next[2]));
            const diff1 = lt_sign.mul(row.rs2.next[1].sub(row.rs1.next[1]));
            const diff0 = lt_sign.mul(row.rs2.next[0].sub(row.rs1.next[0]));

            out[i] = S.one().sub(m3).mul(diff3);
            i += 1;
            out[i] = m3.mul(row.diff_val.sub(diff3));
            i += 1;
            out[i] = S.one().sub(m3).sub(m2).mul(diff2);
            i += 1;
            out[i] = m2.mul(row.diff_val.sub(diff2));
            i += 1;
            out[i] = S.one().sub(m3).sub(m2).sub(m1).mul(diff1);
            i += 1;
            out[i] = m1.mul(row.diff_val.sub(diff1));
            i += 1;
            out[i] = S.one().sub(prefix).mul(diff0);
            i += 1;
            out[i] = m0.mul(row.diff_val.sub(diff0));
            i += 1;
            out[i] = ops.bit(prefix);
            i += 1;
            out[i] = S.one().sub(prefix).mul(row.cmp_lt);
            i += 1;

            const lt = row.opcode_blt_flag.add(row.opcode_bltu_flag);
            const ge = row.opcode_bge_flag.add(row.opcode_bgeu_flag);
            const expected_cmp_lt = row.cmp_result.mul(lt).add(not_cmp.mul(ge));
            out[i] = row.cmp_lt.sub(expected_cmp_lt);
            i += 1;

            // Branches write no register: both accesses are read-only, so their
            // emitted `next` limbs must equal the consumed `previous` limbs.
            for (ops.readOnlyAccessConstraints(row.rs1, enabler)) |constraint| {
                out[i] = constraint;
                i += 1;
            }
            for (ops.readOnlyAccessConstraints(row.rs2, enabler)) |constraint| {
                out[i] = constraint;
                i += 1;
            }

            std.debug.assert(i == out.len);
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.enabler().sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            const opcode_id = row.opcode_blt_flag.mul(ops.q(Opcode.blt.protocolId()))
                .add(row.opcode_bltu_flag.mul(ops.q(Opcode.bltu.protocolId())))
                .add(row.opcode_bge_flag.mul(ops.q(Opcode.bge.protocolId())))
                .add(row.opcode_bgeu_flag.mul(ops.q(Opcode.bgeu.protocolId())));
            return .{
                .pc = row.pc,
                .opcode_id = opcode_id,
                .rd = row.rs1.addr,
                .rs1 = row.rs2.addr,
                .operand = row.imm_felt,
            };
        }

        pub const RangeLookups = struct {
            shifted_msls: ctl.Request(ctl.RangePairTuple),
            positive_difference: ctl.Request(ctl.Range20Tuple),
        };

        pub const Lookups = struct {
            program: ctl.Request(ops.ProgramTuple),
            state: ctl.StateLookups,
            rs1: ctl.RegisterAccessLookups,
            rs2: ctl.RegisterAccessLookups,
            ranges: RangeLookups,
        };

        pub fn lookups(row: Row) Lookups {
            const enabler = row.enabler();
            const signed = row.opcode_blt_flag.add(row.opcode_bge_flag);
            const sign_shift = signed.mul(ops.q(1 << 7));
            const prefix = row.diff_markers[0]
                .add(row.diff_markers[1])
                .add(row.diff_markers[2])
                .add(row.diff_markers[3]);
            return .{
                .program = ctl.programRequest(enabler, programLookup(row)),
                .state = ctl.stateLookups(row.pc, row.clock, row.branch_target, enabler),
                .rs1 = ctl.registerAccessLookups(row.rs1, row.clock, .first, enabler),
                .rs2 = ctl.registerAccessLookups(row.rs2, row.clock, .second, enabler),
                .ranges = .{
                    .shifted_msls = ctl.rangePairRequest(
                        enabler,
                        row.rs1_msl_felt.add(sign_shift),
                        row.rs2_msl_felt.add(sign_shift),
                    ),
                    .positive_difference = ctl.range20Request(
                        prefix,
                        row.diff_val.sub(S.one()),
                    ),
                },
            };
        }

        fn zeroRow() Row {
            const access = ops.Access{
                .addr = S.zero(),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{S.zero()} ** 4,
            };
            return .{
                .clock = S.zero(),
                .pc = S.zero(),
                .rs1 = access,
                .rs2 = access,
                .rs1_msl_felt = S.zero(),
                .rs2_msl_felt = S.zero(),
                .imm_felt = S.zero(),
                .cmp_result = S.zero(),
                .cmp_lt = S.zero(),
                .diff_markers = .{S.zero()} ** 4,
                .diff_val = S.zero(),
                .branch_target = S.zero(),
                .opcode_blt_flag = S.zero(),
                .opcode_bltu_flag = S.zero(),
                .opcode_bge_flag = S.zero(),
                .opcode_bgeu_flag = S.zero(),
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "branch lt: honest BLTU row accepts and emits exact lookups" {
                    var row = zeroRow();
                    row.clock = ops.q(5);
                    row.pc = ops.q(0x1000);
                    row.imm_felt = ops.q(16);
                    row.rs1.addr = ops.q(1);
                    row.rs2.addr = ops.q(2);
                    row.rs1.next[0] = ops.q(1);
                    row.rs1.previous[0] = ops.q(1);
                    row.rs2.next[0] = ops.q(2);
                    row.rs2.previous[0] = ops.q(2);
                    row.cmp_result = S.one();
                    row.cmp_lt = S.one();
                    row.diff_markers[0] = S.one();
                    row.diff_val = S.one();
                    row.branch_target = ops.q(0x1010);
                    row.opcode_bltu_flag = S.one();

                    try std.testing.expect(evaluate(row).allZero());
                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(31)));
                    try std.testing.expect(requests.state.emit.tuple.pc.eql(ops.q(0x1010)));
                    try std.testing.expect(requests.ranges.positive_difference.numerator.eql(S.one().neg()));
                    try std.testing.expect(requests.ranges.positive_difference.tuple.value.isZero());
                }

                test "branch lt: signed BGE correctly does not take negative-one versus zero" {
                    var row = zeroRow();
                    row.pc = ops.q(0x2000);
                    row.rs1.next = .{ ops.q(255), ops.q(255), ops.q(255), ops.q(255) };
                    row.rs1.previous = row.rs1.next;
                    row.rs1_msl_felt = S.one().neg();
                    row.rs2_msl_felt = S.zero();
                    row.cmp_result = S.zero();
                    row.cmp_lt = S.one();
                    row.diff_markers[3] = S.one();
                    row.diff_val = S.one();
                    row.branch_target = ops.q(0x2004);
                    row.opcode_bge_flag = S.one();
                    try std.testing.expect(evaluate(row).allZero());

                    const shifted = lookups(row).ranges.shifted_msls.tuple;
                    try std.testing.expect(shifted.limb_0.eql(ops.q(127)));
                    try std.testing.expect(shifted.limb_1.eql(ops.q(128)));
                }

                test "branch lt: forged comparison and branch target are rejected" {
                    var row = zeroRow();
                    row.pc = ops.q(100);
                    row.imm_felt = ops.q(20);
                    row.rs1.next[0] = ops.q(1);
                    row.rs1.previous[0] = ops.q(1);
                    row.rs2.next[0] = ops.q(2);
                    row.rs2.previous[0] = ops.q(2);
                    row.cmp_result = S.one();
                    row.cmp_lt = S.one();
                    row.diff_markers[0] = S.one();
                    row.diff_val = S.one();
                    row.branch_target = ops.q(121);
                    row.opcode_bltu_flag = S.one();
                    try std.testing.expect(!evaluate(row).allZero());

                    row.branch_target = ops.q(120);
                    row.cmp_lt = S.zero();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "branch lt: read-only source access must emit the value it consumed" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.imm_felt = ops.q(16);
                    row.rs1.next[0] = ops.q(1);
                    row.rs1.previous[0] = ops.q(1);
                    row.rs2.next[0] = ops.q(2);
                    row.rs2.previous[0] = ops.q(2);
                    row.cmp_result = S.one();
                    row.cmp_lt = S.one();
                    row.diff_markers[0] = S.one();
                    row.diff_val = S.one();
                    row.branch_target = ops.q(0x1010);
                    row.opcode_bltu_flag = S.one();
                    try std.testing.expect(evaluate(row).allZero());

                    // The comparison runs over `next`, so swapping the consumed value is only
                    // caught by the read-only binding.
                    row.rs1.previous = .{ ops.q(0xef), ops.q(0xbe), ops.q(0xad), ops.q(0xde) };
                    try std.testing.expect(!evaluate(row).allZero());

                    row.rs1.previous = row.rs1.next;
                    row.rs2.previous[3] = ops.q(0x99);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "branch lt: exact 37-column adapter preserves final witnesses" {
                    var columns = [_]S{S.zero()} ** N_MAIN_COLUMNS;
                    columns[2] = ops.q(1);
                    columns[12] = ops.q(2);
                    columns[22] = ops.q(3);
                    columns[24] = ops.q(4);
                    columns[27] = ops.q(5);
                    columns[31] = ops.q(6);
                    columns[32] = ops.q(7);
                    columns[36] = ops.q(8);
                    const row = try Row.fromMainColumns(&columns);
                    try std.testing.expect(row.rs1.addr.eql(ops.q(1)));
                    try std.testing.expect(row.rs2.addr.eql(ops.q(2)));
                    try std.testing.expect(row.rs1_msl_felt.eql(ops.q(3)));
                    try std.testing.expect(row.imm_felt.eql(ops.q(4)));
                    try std.testing.expect(row.diff_markers[0].eql(ops.q(5)));
                    try std.testing.expect(row.diff_val.eql(ops.q(6)));
                    try std.testing.expect(row.branch_target.eql(ops.q(7)));
                    try std.testing.expect(row.opcode_bgeu_flag.eql(ops.q(8)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
