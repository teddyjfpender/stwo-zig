//! RV32M `MULH`, `MULHSU`, and `MULHU` semantics.
//!
//! This follows Sail's `mult_to_bits_half` semantics. The witness carries both
//! halves of the 64-bit product. Eight `range_check_8_11` requests enforce the
//! byte-wise carry chain, while two `range_check_m31` requests bind each signed
//! operand's sign witness to bit 31.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_ORACLE_COLUMNS: usize = 47;
        pub const N_CONSTRAINTS: usize = 23;
        pub const LOOKUP_BATCH_SIZE: usize = 1;
        pub const BITWISE_LOOKUP_COUNT: usize = 0;
        pub const CURRENT_TRACE_COMPATIBLE = true;
        pub const MISSING_CURRENT_WITNESS_COLUMNS = [_][]const u8{};

        pub const Row = struct {
            clock: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            rs2: ops.Access,
            rd_high: [4]S,
            rs1_sign: S,
            rs2_sign: S,
            is_mulh: S,
            is_mulhsu: S,
            is_mulhu: S,
            result: [4]S,
            destination: ops.Destination,

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                return .{
                    .clock = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = ops.accessFromColumns(columns[12..22]),
                    .rs2 = ops.accessFromColumns(columns[22..32]),
                    .rd_high = columns[32..36].*,
                    .rs1_sign = columns[36],
                    .rs2_sign = columns[37],
                    .is_mulh = columns[38],
                    .is_mulhsu = columns[39],
                    .is_mulhu = columns[40],
                    .result = columns[41..45].*,
                    .destination = ops.destinationFromColumns(columns[45..47]),
                };
            }

            pub fn active(self: Row) S {
                return self.is_mulh.add(self.is_mulhsu).add(self.is_mulhu);
            }
        };

        pub const Derived = struct {
            carries: [8]S,
        };

        pub fn derive(row: Row) Derived {
            @setEvalBranchQuota(100_000);
            const a_fill = row.rs1_sign.mul(ops.q(255));
            const b_fill = row.rs2_sign.mul(ops.q(255));
            var a: [8]S = undefined;
            var b: [8]S = undefined;
            var product: [8]S = undefined;
            @memcpy(a[0..4], &row.rs1.next);
            @memcpy(b[0..4], &row.rs2.next);
            @memcpy(product[0..4], &row.rd_high);
            @memcpy(product[4..8], &row.result);
            for (4..8) |limb| {
                a[limb] = a_fill;
                b[limb] = b_fill;
            }

            var carry: [8]S = undefined;
            var previous = S.zero();
            for (0..8) |output_limb| {
                var numerator = previous;
                for (0..output_limb + 1) |lhs_limb| {
                    numerator = numerator.add(a[lhs_limb].mul(b[output_limb - lhs_limb]));
                }
                carry[output_limb] = numerator.sub(product[output_limb])
                    .mul(ops.INV_BYTE_RADIX());
                previous = carry[output_limb];
            }
            return .{ .carries = carry };
        }

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        fn booleanConstraint(value: S) S {
            return value.mul(S.one().sub(value));
        }

        pub fn evaluate(row: Row) Constraints {
            const active = row.active();
            var out: [N_CONSTRAINTS]S = undefined;
            out[0..8].* = .{
                booleanConstraint(active),
                booleanConstraint(row.is_mulh),
                booleanConstraint(row.is_mulhsu),
                booleanConstraint(row.is_mulhu),
                booleanConstraint(row.rs1_sign),
                booleanConstraint(row.rs2_sign),
                S.one().sub(row.is_mulh).sub(row.is_mulhsu).mul(row.rs1_sign),
                S.one().sub(row.is_mulh).mul(row.rs2_sign),
            };
            @memcpy(out[8..11], &ops.destinationConstraints(row.rd.addr, row.destination));
            @memcpy(
                out[11..15],
                &ops.destinationResultConstraints(row.rd, row.result, row.destination),
            );
            // Source registers are read-only: the emitted `next` limbs must equal the
            // consumed `previous` limbs, otherwise the operand is a free prover choice
            // that is also written back onto the register bus.
            @memcpy(out[15..19], &ops.readOnlyAccessConstraints(row.rs1, active));
            @memcpy(out[19..23], &ops.readOnlyAccessConstraints(row.rs2, active));
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.active().sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            const opcode_id = row.is_mulh.mul(ops.q(Opcode.mulh.protocolId()))
                .add(row.is_mulhsu.mul(ops.q(Opcode.mulhsu.protocolId())))
                .add(row.is_mulhu.mul(ops.q(Opcode.mulhu.protocolId())));
            return .{
                .pc = row.pc,
                .opcode_id = opcode_id,
                .rd = row.rd.addr,
                .rs1 = row.rs1.addr,
                .operand = row.rs2.addr,
            };
        }

        pub const Lookups = struct {
            /// Fields retain the exact `schema.rs` declaration order.
            program: ctl.Request(ops.ProgramTuple),
            state: ctl.StateLookups,
            rs1: ctl.RegisterAccessLookups,
            rs2: ctl.RegisterAccessLookups,
            product_ranges: [8]ctl.Request(ctl.RangePairTuple),
            sign_ranges: [2]ctl.Request(ctl.RangePairTuple),
            rd: ctl.RegisterAccessLookups,
        };

        pub fn lookups(row: Row) Lookups {
            const active = row.active();
            const carries = derive(row).carries;
            var ranges: [8]ctl.Request(ctl.RangePairTuple) = undefined;
            for (&ranges, 0..) |*request, limb| {
                const result_limb = if (limb < 4) row.rd_high[limb] else row.result[limb - 4];
                request.* = ctl.rangePairRequest(active, result_limb, carries[limb]);
            }
            const signed_rs1 = row.is_mulh.add(row.is_mulhsu);
            const signed_rs2 = row.is_mulh;
            return .{
                .program = ctl.programRequest(active, programLookup(row)),
                .state = ctl.stateLookups(row.pc, row.clock, row.pc.add(ops.q(4)), active),
                .rs1 = ctl.registerAccessLookups(row.rs1, row.clock, .first, active),
                .rs2 = ctl.registerAccessLookups(row.rs2, row.clock, .second, active),
                .product_ranges = ranges,
                // `range_check_m31` accepts `(lo8, hi7)`. Keeping `lo8 = 0`
                // proves `top_byte - 128 * sign` is a seven-bit value, which is
                // equivalent to `sign == bit31` for an already byte-ranged operand.
                .sign_ranges = .{
                    ctl.rangePairRequest(
                        signed_rs1,
                        S.zero(),
                        row.rs1.next[3].sub(row.rs1_sign.mul(ops.q(128))),
                    ),
                    ctl.rangePairRequest(
                        signed_rs2,
                        S.zero(),
                        row.rs2.next[3].sub(row.rs2_sign.mul(ops.q(128))),
                    ),
                },
                .rd = ctl.registerAccessLookups(row.rd, row.clock, .third, active),
            };
        }

        fn zeroAccess() ops.Access {
            return .{
                .addr = S.zero(),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{S.zero()} ** 4,
            };
        }

        fn honestUnsignedMaxRow() Row {
            var rd = zeroAccess();
            rd.addr = ops.q(3);
            rd.next = .{ ops.q(254), ops.q(255), ops.q(255), ops.q(255) };
            var rs1 = zeroAccess();
            rs1.addr = ops.q(1);
            rs1.next = .{ops.q(255)} ** 4;
            rs1.previous = rs1.next;
            var rs2 = zeroAccess();
            rs2.addr = ops.q(2);
            rs2.next = .{ops.q(255)} ** 4;
            rs2.previous = rs2.next;
            return .{
                .clock = ops.q(9),
                .pc = ops.q(0x1000),
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .rd_high = .{ S.one(), S.zero(), S.zero(), S.zero() },
                .rs1_sign = S.zero(),
                .rs2_sign = S.zero(),
                .is_mulh = S.zero(),
                .is_mulhsu = S.zero(),
                .is_mulhu = S.one(),
                .result = rd.next,
                .destination = .{
                    .nonzero = S.one(),
                    .inverse = ops.q(3).inv() catch unreachable,
                },
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "mulh: unsigned maximal product has eight bounded carry requests" {
                    const row = honestUnsignedMaxRow();
                    try std.testing.expect(evaluate(row).allZero());
                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(40)));
                    for (requests.product_ranges) |request| {
                        const limb = try request.tuple.limb_0.tryIntoM31();
                        const carry = try request.tuple.limb_1.tryIntoM31();
                        try std.testing.expect(limb.toU32() < 256);
                        try std.testing.expect(carry.toU32() < 2048);
                    }
                }

                test "mulh: unsigned opcode rejects a forged signed witness" {
                    var row = honestUnsignedMaxRow();
                    row.rs1_sign = S.one();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "mulh: signed operand sign is bound to bit 31" {
                    var row = honestUnsignedMaxRow();
                    row.is_mulhu = S.zero();
                    row.is_mulh = S.one();
                    row.rs1_sign = S.one();
                    row.rs2_sign = S.one();
                    try std.testing.expect(evaluate(row).allZero());

                    const honest = lookups(row);
                    try std.testing.expect(
                        honest.sign_ranges[0].tuple.limb_1.eql(ops.q(127)),
                    );
                    try std.testing.expect(
                        honest.sign_ranges[1].tuple.limb_1.eql(ops.q(127)),
                    );

                    row.rs1_sign = S.zero();
                    const forged = lookups(row);
                    const forged_top = try forged.sign_ranges[0].tuple.limb_1.tryIntoM31();
                    try std.testing.expect(forged_top.toU32() >= 128);
                }

                test "mulh: forged high product escapes constraints but fails range table" {
                    var row = honestUnsignedMaxRow();
                    row.rd.next[0] = ops.q(255);
                    row.result[0] = ops.q(255);
                    try std.testing.expect(evaluate(row).allZero());
                    const forged_carry = try derive(row).carries[4].tryIntoM31();
                    try std.testing.expect(forged_carry.toU32() >= 2048);
                }

                test "mulh: source register write-back forgery is rejected" {
                    var forged_rs1 = honestUnsignedMaxRow();
                    forged_rs1.rs1.previous[0] = ops.q(9);
                    try std.testing.expect(!evaluate(forged_rs1).allZero());

                    var forged_rs2 = honestUnsignedMaxRow();
                    forged_rs2.rs2.previous[2] = ops.q(11);
                    try std.testing.expect(!evaluate(forged_rs2).allZero());
                }

                test "mulh: adapter follows access then witness then flag order" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[2] = ops.q(1);
                    columns[12] = ops.q(2);
                    columns[22] = ops.q(3);
                    columns[32] = ops.q(4);
                    columns[36] = ops.q(5);
                    columns[40] = ops.q(6);
                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.rd.addr.eql(ops.q(1)));
                    try std.testing.expect(row.rs1.addr.eql(ops.q(2)));
                    try std.testing.expect(row.rs2.addr.eql(ops.q(3)));
                    try std.testing.expect(row.rd_high[0].eql(ops.q(4)));
                    try std.testing.expect(row.rs1_sign.eql(ops.q(5)));
                    try std.testing.expect(row.is_mulhu.eql(ops.q(6)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
