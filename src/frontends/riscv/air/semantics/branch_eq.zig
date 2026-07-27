//! Exact pinned Stark-V AIR semantics for BEQ and BNE.
//!
//! The 30-column adapter follows `air::schema::branch_eq` at commit
//! d478f783055aa0d73a93768a433a3c6c31c91d1c.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_MAIN_COLUMNS: usize = 30;
        pub const N_CONSTRAINTS: usize = 17;

        pub const Row = struct {
            clock: S,
            pc: S,
            rs1: ops.Access,
            rs2: ops.Access,
            imm_felt: S,
            cmp_result: S,
            diff_inv_markers: [4]S,
            opcode_beq_flag: S,
            opcode_bne_flag: S,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .clock = columns[0],
                    .pc = columns[1],
                    .rs1 = ctl.accessFromColumns(columns, 2),
                    .rs2 = ctl.accessFromColumns(columns, 12),
                    .imm_felt = columns[22],
                    .cmp_result = columns[23],
                    .diff_inv_markers = columns[24..28].*,
                    .opcode_beq_flag = columns[28],
                    .opcode_bne_flag = columns[29],
                };
            }

            pub fn enabler(self: Row) S {
                return self.opcode_beq_flag.add(self.opcode_bne_flag);
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        /// Pinned constraints in generated order: structural enabler booleanity,
        /// opcode-flag booleanity, then the six family constraints from `schema.rs`.
        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            var i: usize = 0;

            const enabler = row.enabler();
            out[i] = ops.bit(enabler);
            i += 1;
            out[i] = ops.bit(row.opcode_beq_flag);
            i += 1;
            out[i] = ops.bit(row.opcode_bne_flag);
            i += 1;
            out[i] = ops.bit(row.cmp_result);
            i += 1;

            const cmp_eq = row.cmp_result.mul(row.opcode_beq_flag)
                .add(S.one().sub(row.cmp_result).mul(row.opcode_bne_flag));
            for (0..4) |limb| {
                out[i] = cmp_eq.mul(row.rs1.next[limb].sub(row.rs2.next[limb]));
                i += 1;
            }

            var diff_inv_sum = cmp_eq;
            for (0..4) |limb| {
                diff_inv_sum = diff_inv_sum.add(
                    row.rs1.next[limb]
                        .sub(row.rs2.next[limb])
                        .mul(row.diff_inv_markers[limb]),
                );
            }
            out[i] = enabler.mul(S.one().sub(diff_inv_sum));
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

        /// Cross-shard placement binds the derived family enabler to its selector.
        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.enabler().sub(is_active);
        }

        pub fn nextPc(row: Row) S {
            return row.pc
                .add(row.imm_felt.mul(row.cmp_result))
                .add(ops.q(4).mul(S.one().sub(row.cmp_result)));
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            const opcode_id = row.opcode_beq_flag.mul(ops.q(Opcode.beq.protocolId()))
                .add(row.opcode_bne_flag.mul(ops.q(Opcode.bne.protocolId())));
            return .{
                .pc = row.pc,
                .opcode_id = opcode_id,
                .rd = row.rs1.addr,
                .rs1 = row.rs2.addr,
                .operand = row.imm_felt,
            };
        }

        pub const Lookups = struct {
            /// Fields retain `schema.rs` declaration order for interaction batching.
            program: ctl.Request(ops.ProgramTuple),
            rs1: ctl.RegisterAccessLookups,
            rs2: ctl.RegisterAccessLookups,
            state: ctl.StateLookups,
        };

        pub fn lookups(row: Row) Lookups {
            const enabler = row.enabler();
            return .{
                .program = ctl.programRequest(enabler, programLookup(row)),
                .rs1 = ctl.registerAccessLookups(row.rs1, row.clock, enabler),
                .rs2 = ctl.registerAccessLookups(row.rs2, row.clock, enabler),
                .state = ctl.stateLookups(row.pc, row.clock, nextPc(row), enabler),
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
                .imm_felt = S.zero(),
                .cmp_result = S.zero(),
                .diff_inv_markers = .{S.zero()} ** 4,
                .opcode_beq_flag = S.zero(),
                .opcode_bne_flag = S.zero(),
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "branch eq: BEQ equality accepts and binds decoded program tuple" {
                    var row = zeroRow();
                    row.clock = ops.q(9);
                    row.pc = ops.q(0x1000);
                    row.imm_felt = ops.q(12);
                    row.cmp_result = S.one();
                    row.opcode_beq_flag = S.one();
                    row.rs1.addr = ops.q(3);
                    row.rs2.addr = ops.q(4);
                    row.rs1.next = .{ ops.q(7), ops.q(8), ops.q(9), ops.q(10) };
                    row.rs1.previous = row.rs1.next;
                    row.rs2.next = row.rs1.next;
                    row.rs2.previous = row.rs2.next;

                    try std.testing.expect(evaluate(row).allZero());
                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(27)));
                    try std.testing.expect(requests.program.tuple.rd.eql(ops.q(3)));
                    try std.testing.expect(requests.program.tuple.rs1.eql(ops.q(4)));
                    try std.testing.expect(requests.state.emit.tuple.pc.eql(ops.q(0x100c)));
                    try std.testing.expect(requests.state.emit.tuple.clock.eql(ops.q(10)));
                }

                test "branch eq: forged equality over unequal limbs is rejected" {
                    var row = zeroRow();
                    row.opcode_beq_flag = S.one();
                    row.cmp_result = S.one();
                    row.rs1.next[2] = ops.q(17);
                    row.rs2.next[2] = ops.q(18);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "branch eq: BNE inequality requires a valid inverse marker" {
                    var row = zeroRow();
                    row.opcode_bne_flag = S.one();
                    row.cmp_result = S.one();
                    row.rs1.next[0] = ops.q(9);
                    row.rs1.previous[0] = ops.q(9);
                    row.rs2.next[0] = ops.q(6);
                    row.rs2.previous[0] = ops.q(6);
                    row.diff_inv_markers[0] = try ops.q(3).inv();
                    try std.testing.expect(evaluate(row).allZero());

                    row.diff_inv_markers[0] = S.zero();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "branch eq: read-only source access must emit the value it consumed" {
                    var row = zeroRow();
                    row.clock = ops.q(9);
                    row.pc = ops.q(0x1000);
                    row.imm_felt = ops.q(12);
                    row.cmp_result = S.one();
                    row.opcode_beq_flag = S.one();
                    row.rs1.addr = ops.q(3);
                    row.rs2.addr = ops.q(4);
                    // Consumed 0xdeadbeef limbs but emits 0x7f7f7f7f limbs on both sources:
                    // the comparison over `next` passes, so only the read-only binding rejects.
                    row.rs1.previous = .{ ops.q(0xef), ops.q(0xbe), ops.q(0xad), ops.q(0xde) };
                    row.rs1.next = .{ ops.q(0x7f), ops.q(0x7f), ops.q(0x7f), ops.q(0x7f) };
                    row.rs2.previous = row.rs1.next;
                    row.rs2.next = row.rs1.next;
                    try std.testing.expect(!evaluate(row).allZero());

                    row.rs1.previous = row.rs1.next;
                    try std.testing.expect(evaluate(row).allZero());

                    row.rs2.next[1] = ops.q(0x11);
                    row.rs1.next[1] = ops.q(0x11);
                    row.rs1.previous[1] = ops.q(0x11);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "branch eq: exact 30-column adapter follows pinned order" {
                    var columns = [_]S{S.zero()} ** N_MAIN_COLUMNS;
                    columns[2] = ops.q(1);
                    columns[7] = ops.q(2);
                    columns[8] = ops.q(3);
                    columns[12] = ops.q(4);
                    columns[17] = ops.q(5);
                    columns[18] = ops.q(6);
                    columns[22] = ops.q(7);
                    columns[28] = ops.q(8);
                    const row = try Row.fromMainColumns(&columns);
                    try std.testing.expect(row.rs1.addr.eql(ops.q(1)));
                    try std.testing.expect(row.rs1.previous_clock.eql(ops.q(2)));
                    try std.testing.expect(row.rs1.next[0].eql(ops.q(3)));
                    try std.testing.expect(row.rs2.addr.eql(ops.q(4)));
                    try std.testing.expect(row.rs2.previous_clock.eql(ops.q(5)));
                    try std.testing.expect(row.rs2.next[0].eql(ops.q(6)));
                    try std.testing.expect(row.imm_felt.eql(ops.q(7)));
                    try std.testing.expect(row.opcode_beq_flag.eql(ops.q(8)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
