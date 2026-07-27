//! Sail-authoritative AIR semantics and lookup requests for JALR.
//!
//! This is an intentional soundness divergence from the pinned Stark-V layout.
//! Its original 32 columns remain an exact prefix; nine soundness columns are
//! appended. The source access is read-only and all four source limbs are
//! bytes. The target is committed both as four bytes and as the program AIR's
//! bounded `target / 4 = low20 + 2^20 * high8` split. A byte-carry recurrence
//! adds the sign-extended I-immediate to rs1 modulo 2^32 and proves that the
//! result is exactly `target + bit0`. Consequently bit 0 is not prover-chosen,
//! successful rows are 4-aligned and program-commitment-bounded locally, and
//! wraparound does not rely on an M31 field alias.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_MAIN_COLUMNS: usize = 41;
        pub const N_CONSTRAINTS: usize = 22;

        pub const Row = struct {
            enabler: S,
            clock: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            to_pc_over_two: S,
            to_pc_lsb: S,
            imm_felt: S,
            result: [4]S,
            destination: ops.Destination,
            target_word_low_20: S,
            target_word_high_8: S,
            target_limbs: [4]S,
            imm_byte_0: S,
            imm_nibble: S,
            imm_sign: S,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ctl.accessFromColumns(columns, 3),
                    .rs1 = ctl.accessFromColumns(columns, 13),
                    .to_pc_over_two = columns[23],
                    .to_pc_lsb = columns[24],
                    .imm_felt = columns[25],
                    .result = columns[26..30].*,
                    .destination = ops.destinationFromColumns(columns[30..32]),
                    .target_word_low_20 = columns[32],
                    .target_word_high_8 = columns[33],
                    .target_limbs = columns[34..38].*,
                    .imm_byte_0 = columns[38],
                    .imm_nibble = columns[39],
                    .imm_sign = columns[40],
                };
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn targetWord(row: Row) S {
            return row.target_word_low_20.add(
                row.target_word_high_8.mul(ops.q(@as(u32, 1) << 20)),
            );
        }

        pub fn jumpTarget(row: Row) S {
            return ops.q(4).mul(targetWord(row));
        }

        fn immediateLimbs(row: Row) [4]S {
            return .{
                row.imm_byte_0,
                row.imm_nibble.add(row.imm_sign.mul(ops.q(240))),
                row.imm_sign.mul(ops.q(255)),
                row.imm_sign.mul(ops.q(255)),
            };
        }

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            var n: usize = 0;
            out[n] = ops.bit(row.enabler);
            n += 1;
            out[n] = ops.bit(row.to_pc_lsb);
            n += 1;
            out[n] = ops.bit(row.imm_sign);
            n += 1;
            out[n] = row.imm_byte_0
                .add(row.imm_nibble.mul(ops.q(256)))
                .sub(row.imm_sign.mul(ops.q(4096)))
                .sub(row.imm_felt);
            n += 1;
            out[n] = ops.composeU32(row.target_limbs).sub(jumpTarget(row));
            n += 1;
            out[n] = row.to_pc_over_two.sub(targetWord(row).mul(ops.q(2)));
            n += 1;

            const immediate = immediateLimbs(row);
            var carry = S.zero();
            for (0..4) |limb| {
                const result_limb = row.target_limbs[limb].add(
                    if (limb == 0) row.to_pc_lsb else S.zero(),
                );
                carry = row.rs1.next[limb]
                    .add(immediate[limb])
                    .add(carry)
                    .sub(result_limb)
                    .mul(ops.INV_BYTE_RADIX());
                out[n] = ops.bit(carry);
                n += 1;
            }

            out[n] = row.enabler.mul(
                ops.composeU32(row.result).sub(row.pc.add(ops.q(4))),
            );
            n += 1;
            @memcpy(out[n .. n + 3], &ops.destinationConstraints(row.rd.addr, row.destination));
            n += 3;
            @memcpy(
                out[n .. n + 4],
                &ops.destinationResultConstraints(row.rd, row.result, row.destination),
            );
            n += 4;
            // rs1 is a source operand: force the emitted access value to equal the
            // consumed one so the access chain cannot double as a register write.
            @memcpy(out[n .. n + 4], &ops.readOnlyAccessConstraints(row.rs1, row.enabler));
            n += 4;
            std.debug.assert(n == out.len);
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.enabler.sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = ops.q(Opcode.jalr.protocolId()),
                .rd = row.rd.addr,
                .rs1 = row.rs1.addr,
                .operand = row.imm_felt,
            };
        }

        pub const Lookups = struct {
            /// The pinned prefix is followed by the row-local target and immediate
            /// bindings in declaration order.
            program: ctl.Request(ops.ProgramTuple),
            rs1: ctl.RegisterAccessLookups,
            rs1_middle_bytes: ctl.Request(ctl.RangePairTuple),
            rs1_outer_bytes: ctl.Request(ctl.RangePairTuple),
            target_word_low_20: ctl.Request(ctl.Range20Tuple),
            target_word_high_8: ctl.Request(ctl.RangePairTuple),
            target_middle_bytes: ctl.Request(ctl.RangePairTuple),
            target_m31: ctl.Request(ctl.RangePairTuple),
            immediate_range: ctl.Request(ctl.RangeTripleTuple),
            state: ctl.StateLookups,
            rd_middle_bytes: ctl.Request(ctl.RangePairTuple),
            rd_m31: ctl.Request(ctl.RangePairTuple),
            rd: ctl.RegisterAccessLookups,
        };

        pub fn lookups(row: Row) Lookups {
            return .{
                .program = ctl.programRequest(row.enabler, programLookup(row)),
                .rs1 = ctl.registerAccessLookups(row.rs1, row.clock, row.enabler),
                .rs1_middle_bytes = ctl.rangePairRequest(
                    row.enabler,
                    row.rs1.next[1],
                    row.rs1.next[2],
                ),
                .rs1_outer_bytes = ctl.rangePairRequest(
                    row.enabler,
                    row.rs1.next[0],
                    row.rs1.next[3],
                ),
                .target_word_low_20 = ctl.range20Request(
                    row.enabler,
                    row.target_word_low_20,
                ),
                .target_word_high_8 = ctl.rangePairRequest(
                    row.enabler,
                    row.target_word_high_8,
                    S.zero(),
                ),
                .target_middle_bytes = ctl.rangePairRequest(
                    row.enabler,
                    row.target_limbs[1],
                    row.target_limbs[2],
                ),
                // Combined with the bounded target/4 split, the M31 outer-byte table
                // excludes the residual target+p byte decomposition.
                .target_m31 = ctl.rangePairRequest(
                    row.enabler,
                    row.target_limbs[0],
                    row.target_limbs[3],
                ),
                .immediate_range = .{
                    .numerator = row.enabler.neg(),
                    .tuple = .{
                        .limb_0 = row.imm_byte_0,
                        .limb_1 = S.zero(),
                        .limb_2 = row.imm_nibble
                            .sub(row.imm_sign.mul(ops.q(8)))
                            .mul(ops.q(2)),
                    },
                },
                .state = ctl.stateLookups(
                    row.pc,
                    row.clock,
                    jumpTarget(row),
                    row.enabler,
                ),
                .rd_middle_bytes = ctl.rangePairRequest(
                    row.enabler,
                    row.result[1],
                    row.result[2],
                ),
                .rd_m31 = ctl.rangePairRequest(
                    row.enabler,
                    row.result[0],
                    row.result[3],
                ),
                .rd = ctl.registerAccessLookups(row.rd, row.clock, row.enabler),
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
                .enabler = S.zero(),
                .clock = S.zero(),
                .pc = S.zero(),
                .rd = access,
                .rs1 = access,
                .to_pc_over_two = S.zero(),
                .to_pc_lsb = S.zero(),
                .imm_felt = S.zero(),
                .result = .{S.zero()} ** 4,
                .destination = .{ .nonzero = S.zero(), .inverse = S.zero() },
                .target_word_low_20 = S.zero(),
                .target_word_high_8 = S.zero(),
                .target_limbs = .{S.zero()} ** 4,
                .imm_byte_0 = S.zero(),
                .imm_nibble = S.zero(),
                .imm_sign = S.zero(),
            };
        }

        fn honestRow() Row {
            var row = zeroRow();
            row.enabler = S.one();
            row.clock = ops.q(7);
            row.pc = ops.q(0x1000);
            row.rd.addr = ops.q(1);
            row.rd.next = .{ ops.q(4), ops.q(0x10), S.zero(), S.zero() };
            row.result = row.rd.next;
            row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
            row.rs1.addr = ops.q(2);
            row.rs1.next[0] = ops.q(101);
            row.rs1.previous = row.rs1.next;
            row.to_pc_over_two = ops.q(52);
            row.to_pc_lsb = S.one();
            row.target_word_low_20 = ops.q(26);
            row.target_limbs[0] = ops.q(104);
            row.imm_felt = ops.q(4);
            row.imm_byte_0 = ops.q(4);
            return row;
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "jalr: honest odd sum clears bit zero to an aligned target" {
                    const row = honestRow();
                    try std.testing.expect(evaluate(row).allZero());

                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(34)));
                    try std.testing.expect(requests.state.emit.tuple.pc.eql(ops.q(104)));
                    try std.testing.expect(requests.state.emit.tuple.clock.eql(ops.q(8)));
                    try std.testing.expect(requests.rs1_middle_bytes.numerator.eql(S.one().neg()));
                    try std.testing.expect(requests.rs1_middle_bytes.tuple.limb_0.eql(row.rs1.next[1]));
                    try std.testing.expect(requests.rs1_middle_bytes.tuple.limb_1.eql(row.rs1.next[2]));
                    try std.testing.expect(requests.target_word_low_20.tuple.value.eql(ops.q(26)));
                }

                test "jalr: rs1 write-back through the access chain is rejected" {
                    var row = honestRow();
                    row.rs1.previous[0] = ops.q(100);
                    const constraints = evaluate(row);
                    for (constraints.values[0..18]) |value| try std.testing.expect(value.isZero());
                    try std.testing.expect(!constraints.allZero());
                }

                test "jalr: target bit, word split, and link register are bound" {
                    var row = honestRow();
                    row.to_pc_lsb = S.zero();
                    try std.testing.expect(!evaluate(row).allZero());

                    row = honestRow();
                    row.target_word_low_20 = ops.q(25);
                    try std.testing.expect(!evaluate(row).allZero());

                    row = honestRow();
                    row.rd.next[0] = ops.q(105);
                    row.result[0] = ops.q(105);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "jalr: signed immediate and u32 wraparound use exact byte carries" {
                    var negative = honestRow();
                    negative.rs1.next = .{ ops.q(4), ops.q(0x10), S.zero(), S.zero() };
                    negative.rs1.previous = negative.rs1.next;
                    negative.to_pc_over_two = ops.q(0x800);
                    negative.to_pc_lsb = S.zero();
                    negative.target_word_low_20 = ops.q(0x400);
                    negative.target_limbs = .{ S.zero(), ops.q(0x10), S.zero(), S.zero() };
                    negative.imm_felt = S.zero().sub(ops.q(4));
                    negative.imm_byte_0 = ops.q(0xfc);
                    negative.imm_nibble = ops.q(0xf);
                    negative.imm_sign = S.one();
                    try std.testing.expect(evaluate(negative).allZero());

                    var wrapped = honestRow();
                    wrapped.rs1.next = .{
                        S.one(),
                        ops.q(0xf8),
                        ops.q(0xff),
                        ops.q(0xff),
                    };
                    wrapped.rs1.previous = wrapped.rs1.next;
                    wrapped.to_pc_over_two = S.zero();
                    wrapped.to_pc_lsb = S.zero();
                    wrapped.target_word_low_20 = S.zero();
                    wrapped.target_limbs = .{S.zero()} ** 4;
                    wrapped.imm_felt = ops.q(0x7ff);
                    wrapped.imm_byte_0 = ops.q(0xff);
                    wrapped.imm_nibble = ops.q(7);
                    try std.testing.expect(evaluate(wrapped).allZero());

                    const table = @import("../lookups/tables/schema.zig");
                    const outer = lookups(wrapped).rs1_outer_bytes.tuple.values();
                    _ = try table.indexSecure(.range_check_8_8, &outer);
                }

                test "jalr: misaligned cleared target is rejected row locally" {
                    var row = honestRow();
                    row.rs1.next[0] = ops.q(100);
                    row.rs1.previous = row.rs1.next;
                    row.to_pc_over_two = ops.q(51);
                    row.target_word_low_20 = ops.q(25);
                    row.target_limbs[0] = ops.q(102);
                    row.imm_felt = ops.q(3);
                    row.imm_byte_0 = ops.q(3);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "jalr: exact adapter expands rd then rs1 after leading enabler" {
                    var columns = [_]S{S.zero()} ** N_MAIN_COLUMNS;
                    columns[0] = ops.q(1);
                    columns[3] = ops.q(2);
                    columns[13] = ops.q(3);
                    columns[23] = ops.q(4);
                    columns[24] = ops.q(5);
                    columns[25] = ops.q(6);
                    columns[32] = ops.q(7);
                    columns[33] = ops.q(8);
                    columns[34] = ops.q(9);
                    columns[38] = ops.q(10);
                    columns[39] = ops.q(11);
                    columns[40] = ops.q(12);
                    const row = try Row.fromMainColumns(&columns);
                    try std.testing.expect(row.enabler.eql(ops.q(1)));
                    try std.testing.expect(row.rd.addr.eql(ops.q(2)));
                    try std.testing.expect(row.rs1.addr.eql(ops.q(3)));
                    try std.testing.expect(row.to_pc_over_two.eql(ops.q(4)));
                    try std.testing.expect(row.to_pc_lsb.eql(ops.q(5)));
                    try std.testing.expect(row.imm_felt.eql(ops.q(6)));
                    try std.testing.expect(row.target_word_low_20.eql(ops.q(7)));
                    try std.testing.expect(row.target_word_high_8.eql(ops.q(8)));
                    try std.testing.expect(row.target_limbs[0].eql(ops.q(9)));
                    try std.testing.expect(row.imm_byte_0.eql(ops.q(10)));
                    try std.testing.expect(row.imm_nibble.eql(ops.q(11)));
                    try std.testing.expect(row.imm_sign.eql(ops.q(12)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
