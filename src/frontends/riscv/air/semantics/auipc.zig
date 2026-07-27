//! Exact pinned Stark-V AIR semantics and lookup requests for AUIPC.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const control = @import("control_common.zig");
const Opcode = @import("../program/opcode.zig").Opcode;

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const N_MAIN_COLUMNS: usize = 29;
        pub const N_CONSTRAINTS: usize = 16;

        pub const Row = struct {
            enabler: S,
            clock: S,
            pc: S,
            rd: ops.Access,
            imm_felt: S,
            result: [4]S,
            destination: ops.Destination,
            pc_limbs: [4]S,
            imm_limbs: [4]S,
            imm_sign: S,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ctl.accessFromColumns(columns, 3),
                    .imm_felt = columns[13],
                    .result = columns[14..18].*,
                    .destination = ops.destinationFromColumns(columns[18..20]),
                    .pc_limbs = columns[20..24].*,
                    .imm_limbs = columns[24..28].*,
                    .imm_sign = columns[28],
                };
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            var n: usize = 0;
            out[n] = ops.bit(row.enabler);
            n += 1;
            out[n] = ops.composeU32(row.pc_limbs).sub(row.pc);
            n += 1;
            // `imm_felt` is the signed i32 value bound by the decoded-program lookup.
            // In M31, converting its u32 bit pattern adds 2^32 == 2 for negatives.
            out[n] = ops.composeU32(row.imm_limbs)
                .sub(row.imm_felt)
                .sub(row.imm_sign.mul(ops.q(2)));
            n += 1;
            out[n] = ops.bit(row.imm_sign);
            n += 1;
            // U-type immediates hardwire their low 12 bits to zero, so an honest row
            // always commits imm_limbs[0] == 0. This also makes the decomposition
            // injective: 2^32 == 2p + 2 in M31, so each residue has a second u32
            // preimage offset by +-(p + 2) = +-0x80000001 whose low byte becomes 0x01
            // or 0xff, and the residual word == p candidate has low byte 0xff. Pinning
            // the low byte to zero (with the sibling byte/sign range lookups) leaves
            // exactly one accepted (imm_limbs, imm_sign) witness per ROM `imm_felt`.
            out[n] = ops.selected(row.enabler, row.imm_limbs[0]);
            n += 1;
            var carry = S.zero();
            for (0..4) |limb| {
                const numerator = row.pc_limbs[limb]
                    .add(row.imm_limbs[limb])
                    .add(carry)
                    .sub(row.result[limb]);
                carry = numerator.mul(ops.INV_BYTE_RADIX());
                out[n] = ops.bit(carry);
                n += 1;
            }
            @memcpy(out[n .. n + 3], &ops.destinationConstraints(row.rd.addr, row.destination));
            n += 3;
            @memcpy(
                out[n .. n + 4],
                &ops.destinationResultConstraints(row.rd, row.result, row.destination),
            );
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
                .opcode_id = ops.q(Opcode.auipc.protocolId()),
                .rd = row.rd.addr,
                .rs1 = row.imm_felt,
                .operand = S.zero(),
            };
        }

        pub const RangeLookups = struct {
            result: [2]ctl.Request(ctl.RangePairTuple),
            pc: [2]ctl.Request(ctl.RangePairTuple),
            immediate: [2]ctl.Request(ctl.RangePairTuple),
        };

        pub const Lookups = struct {
            /// Fields retain `schema.rs` declaration order for interaction batching.
            program: ctl.Request(ops.ProgramTuple),
            state: ctl.StateLookups,
            ranges: RangeLookups,
            rd: ctl.RegisterAccessLookups,
        };

        pub fn lookups(row: Row) Lookups {
            return .{
                .program = ctl.programRequest(row.enabler, programLookup(row)),
                .state = ctl.stateLookups(
                    row.pc,
                    row.clock,
                    row.pc.add(ops.q(4)),
                    row.enabler,
                ),
                .ranges = .{
                    .result = .{
                        ctl.rangePairRequest(row.enabler, row.result[0], row.result[1]),
                        ctl.rangePairRequest(row.enabler, row.result[2], row.result[3]),
                    },
                    // PC is profile-bounded below 2^30. `range_check_m31` on the
                    // outer bytes additionally makes the field decomposition injective.
                    .pc = .{
                        ctl.rangePairRequest(row.enabler, row.pc_limbs[1], row.pc_limbs[2]),
                        ctl.rangePairRequest(row.enabler, row.pc_limbs[0], row.pc_limbs[3]),
                    },
                    // The second tuple is consumed by range_check_m31: subtracting
                    // 128*sign binds `imm_sign` to bit 31 while range-checking both
                    // outer bytes.
                    .immediate = .{
                        ctl.rangePairRequest(row.enabler, row.imm_limbs[1], row.imm_limbs[2]),
                        ctl.rangePairRequest(
                            row.enabler,
                            row.imm_limbs[0],
                            row.imm_limbs[3].sub(row.imm_sign.mul(ops.q(128))),
                        ),
                    },
                },
                .rd = ctl.registerAccessLookups(row.rd, row.clock, row.enabler),
            };
        }

        fn zeroRow() Row {
            return .{
                .enabler = S.zero(),
                .clock = S.zero(),
                .pc = S.zero(),
                .rd = .{
                    .addr = S.zero(),
                    .previous = .{S.zero()} ** 4,
                    .previous_clock = S.zero(),
                    .next = .{S.zero()} ** 4,
                },
                .imm_felt = S.zero(),
                .result = .{S.zero()} ** 4,
                .destination = .{ .nonzero = S.zero(), .inverse = S.zero() },
                .pc_limbs = .{S.zero()} ** 4,
                .imm_limbs = .{S.zero()} ** 4,
                .imm_sign = S.zero(),
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "auipc: honest result satisfies direct equation and exact ranges" {
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.clock = ops.q(4);
                    row.pc = ops.q(0x1000);
                    row.pc_limbs = .{ S.zero(), ops.q(0x10), S.zero(), S.zero() };
                    row.imm_felt = ops.q(0x2000);
                    row.imm_limbs = .{ S.zero(), ops.q(0x20), S.zero(), S.zero() };
                    row.rd.addr = ops.q(8);
                    row.destination = .{
                        .nonzero = S.one(),
                        .inverse = ops.q(8).inv() catch unreachable,
                    };
                    row.rd.next = .{ ops.q(0), ops.q(0x30), ops.q(0), ops.q(0) };
                    row.result = row.rd.next;
                    try std.testing.expect(evaluate(row).allZero());

                    const requests = lookups(row);
                    try std.testing.expect(requests.program.tuple.opcode_id.eql(ops.q(36)));
                    try std.testing.expect(requests.program.tuple.rs1.eql(ops.q(0x2000)));
                    try std.testing.expect(requests.state.emit.tuple.pc.eql(ops.q(0x1004)));
                    try std.testing.expect(requests.ranges.result[0].tuple.limb_1.eql(ops.q(0x30)));
                }

                test "auipc: forged destination is rejected" {
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.pc = ops.q(100);
                    row.pc_limbs[0] = ops.q(100);
                    row.imm_felt = ops.q(20);
                    row.imm_limbs[0] = ops.q(20);
                    row.rd.next[0] = ops.q(121);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "auipc: p + 2 aliased immediate decomposition is rejected" {
                    // Same ROM word (imm_felt = 0x2000) but the limbs decompose
                    // 0x2000 + p + 2 = 0x80002001 with imm_sign = 1. The compose/sign/adder
                    // equations all hold, so only the low-limb pin rejects the forgery.
                    var row = zeroRow();
                    row.enabler = S.one();
                    row.clock = ops.q(4);
                    row.pc = ops.q(0x1000);
                    row.pc_limbs = .{ S.zero(), ops.q(0x10), S.zero(), S.zero() };
                    row.imm_felt = ops.q(0x2000);
                    row.imm_limbs = .{ ops.q(0x01), ops.q(0x20), S.zero(), ops.q(0x80) };
                    row.imm_sign = S.one();
                    row.rd.addr = ops.q(8);
                    row.destination = .{
                        .nonzero = S.one(),
                        .inverse = ops.q(8).inv() catch unreachable,
                    };
                    // rd would receive 0x80003001 instead of 0x3000.
                    row.rd.next = .{ ops.q(0x01), ops.q(0x30), ops.q(0), ops.q(0x80) };
                    row.result = row.rd.next;
                    try std.testing.expect(!evaluate(row).allZero());

                    // Restoring the honest decomposition re-accepts the row.
                    row.imm_limbs = .{ S.zero(), ops.q(0x20), S.zero(), S.zero() };
                    row.imm_sign = S.zero();
                    row.rd.next = .{ ops.q(0), ops.q(0x30), ops.q(0), ops.q(0) };
                    row.result = row.rd.next;
                    try std.testing.expect(evaluate(row).allZero());
                }

                test "auipc: exact adapter has upstream enabler first" {
                    var columns = [_]S{S.zero()} ** N_MAIN_COLUMNS;
                    columns[0] = ops.q(1);
                    columns[3] = ops.q(2);
                    columns[8] = ops.q(3);
                    columns[9] = ops.q(4);
                    columns[13] = ops.q(5);
                    const row = try Row.fromMainColumns(&columns);
                    try std.testing.expect(row.enabler.eql(ops.q(1)));
                    try std.testing.expect(row.rd.addr.eql(ops.q(2)));
                    try std.testing.expect(row.rd.previous_clock.eql(ops.q(3)));
                    try std.testing.expect(row.rd.next[0].eql(ops.q(4)));
                    try std.testing.expect(row.imm_felt.eql(ops.q(5)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
