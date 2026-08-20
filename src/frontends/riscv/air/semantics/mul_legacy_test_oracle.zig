//! Legacy pinned Stark-V `MUL` semantics retained as a differential oracle.
//!
//! The low-word product is enforced by four singleton `range_check_8_11`
//! lookups over the schoolbook carry chain. There is intentionally no direct
//! multiplication constraint: this is the degree-bounded upstream design.
//! Oracle: pinned `crates/air/src/schema.rs` and `runner/src/ops/muldiv.rs`.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_ORACLE_COLUMNS: usize = 39;
        pub const N_CONSTRAINTS: usize = 16;
        pub const LOOKUP_BATCH_SIZE: usize = 1;
        pub const BITWISE_LOOKUP_COUNT: usize = 0;
        pub const CURRENT_TRACE_COMPATIBLE = true;
        pub const MISSING_CURRENT_WITNESS_COLUMNS = [_][]const u8{};

        pub const Row = struct {
            enabler: S,
            clock: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            rs2: ops.Access,
            result: [4]S,
            destination: ops.Destination,

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ops.accessFromColumns(columns[3..13]),
                    .rs1 = ops.accessFromColumns(columns[13..23]),
                    .rs2 = ops.accessFromColumns(columns[23..33]),
                    .result = columns[33..37].*,
                    .destination = ops.destinationFromColumns(columns[37..39]),
                };
            }
        };

        pub const Derived = struct {
            carries: [4]S,
        };

        pub fn derive(row: Row) Derived {
            @setEvalBranchQuota(100_000);
            const lhs = row.rs1.next;
            const rhs = row.rs2.next;
            const result = row.result;
            var carry: [4]S = undefined;
            carry[0] = lhs[0].mul(rhs[0]).sub(result[0]).mul(ops.INV_BYTE_RADIX());
            carry[1] = carry[0].add(lhs[1].mul(rhs[0])).add(lhs[0].mul(rhs[1]))
                .sub(result[1]).mul(ops.INV_BYTE_RADIX());
            carry[2] = carry[1].add(lhs[2].mul(rhs[0])).add(lhs[1].mul(rhs[1]))
                .add(lhs[0].mul(rhs[2])).sub(result[2]).mul(ops.INV_BYTE_RADIX());
            carry[3] = carry[2].add(lhs[3].mul(rhs[0])).add(lhs[2].mul(rhs[1]))
                .add(lhs[1].mul(rhs[2])).add(lhs[0].mul(rhs[3]))
                .sub(result[3]).mul(ops.INV_BYTE_RADIX());
            return .{ .carries = carry };
        }

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            out[0] = row.enabler.mul(S.one().sub(row.enabler));
            @memcpy(out[1..4], &ops.destinationConstraints(row.rd.addr, row.destination));
            @memcpy(
                out[4..8],
                &ops.destinationResultConstraints(row.rd, row.result, row.destination),
            );
            // Source registers are read-only: the emitted `next` limbs must equal the
            // consumed `previous` limbs, otherwise the operand is a free prover choice
            // that is also written back onto the register bus.
            @memcpy(out[8..12], &ops.readOnlyAccessConstraints(row.rs1, row.enabler));
            @memcpy(out[12..16], &ops.readOnlyAccessConstraints(row.rs2, row.enabler));
            return .{ .values = out };
        }

        /// Binds the table-local enabler to the component placement selector.
        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.enabler.sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            return .{
                .pc = row.pc,
                .opcode_id = ops.q(Opcode.mul.protocolId()),
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
            product_ranges: [4]ctl.Request(ctl.RangePairTuple),
            rd: ctl.RegisterAccessLookups,
        };

        pub fn lookups(row: Row) Lookups {
            const carries = derive(row).carries;
            var ranges: [4]ctl.Request(ctl.RangePairTuple) = undefined;
            for (&ranges, 0..) |*request, limb| {
                request.* = ctl.rangePairRequest(row.enabler, row.result[limb], carries[limb]);
            }
            return .{
                .program = ctl.programRequest(row.enabler, programLookup(row)),
                .state = ctl.stateLookups(
                    row.pc,
                    row.clock,
                    row.pc.add(ops.q(4)),
                    row.enabler,
                ),
                .rs1 = ctl.registerAccessLookups(row.rs1, row.clock, .first, row.enabler),
                .rs2 = ctl.registerAccessLookups(row.rs2, row.clock, .second, row.enabler),
                .product_ranges = ranges,
                .rd = ctl.registerAccessLookups(row.rd, row.clock, .third, row.enabler),
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

        fn honestRow() Row {
            var rd = zeroAccess();
            rd.addr = ops.q(3);
            rd.next = .{ ops.q(1), S.zero(), S.zero(), S.zero() };
            var rs1 = zeroAccess();
            rs1.addr = ops.q(1);
            rs1.next = .{ops.q(255)} ** 4;
            rs1.previous = rs1.next;
            var rs2 = zeroAccess();
            rs2.addr = ops.q(2);
            rs2.next = .{ops.q(255)} ** 4;
            rs2.previous = rs2.next;
            return .{
                .enabler = S.one(),
                .clock = ops.q(9),
                .pc = ops.q(0x1000),
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
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
                test "mul: maximal operands produce exact bounded carry requests" {
                    const row = honestRow();
                    try std.testing.expect(evaluate(row).allZero());
                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(37)));
                    for (requests.product_ranges) |request| {
                        const limb = try request.tuple.limb_0.tryIntoM31();
                        const carry = try request.tuple.limb_1.tryIntoM31();
                        try std.testing.expect(limb.toU32() < 256);
                        try std.testing.expect(carry.toU32() < 2048);
                        try std.testing.expect(request.numerator.eql(S.one().neg()));
                    }
                }

                test "mul: forged low product is rejected by exact range request" {
                    var row = honestRow();
                    row.rs1.next = .{ S.one(), S.zero(), S.zero(), S.zero() };
                    row.rs2.next = row.rs1.next;
                    row.rd.next[0] = ops.q(2);
                    row.result[0] = ops.q(2);
                    const forged_carry = try derive(row).carries[0].tryIntoM31();
                    try std.testing.expect(forged_carry.toU32() >= 2048);
                }

                test "mul: source register write-back forgery is rejected" {
                    var forged_rs1 = honestRow();
                    forged_rs1.rs1.previous = .{ ops.q(5), S.zero(), S.zero(), S.zero() };
                    try std.testing.expect(!evaluate(forged_rs1).allZero());

                    var forged_rs2 = honestRow();
                    forged_rs2.rs2.previous[3] = ops.q(7);
                    try std.testing.expect(!evaluate(forged_rs2).allZero());
                }

                test "mul: adapter starts with the generated enabler column" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[0] = ops.q(1);
                    columns[1] = ops.q(2);
                    columns[2] = ops.q(3);
                    columns[3] = ops.q(4);
                    columns[13] = ops.q(5);
                    columns[23] = ops.q(6);
                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.enabler.eql(ops.q(1)));
                    try std.testing.expect(row.clock.eql(ops.q(2)));
                    try std.testing.expect(row.rd.addr.eql(ops.q(4)));
                    try std.testing.expect(row.rs1.addr.eql(ops.q(5)));
                    try std.testing.expect(row.rs2.addr.eql(ops.q(6)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
