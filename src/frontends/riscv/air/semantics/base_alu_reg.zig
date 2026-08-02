//! Exact direct semantics for ADD/SUB and lookup requests for bitwise R-type
//! instructions, expressed over the full committed family-column layout.
//!
//! Oracle: `stark-v` `crates/air/src/schema.rs`, `base_alu_reg`, pinned by
//! `conformance/upstream.md`.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const read_access = @import("read_access.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const reads = read_access.Ops(S, ops.Access);

        pub const N_ORACLE_COLUMNS: usize = 35;
        pub const N_CONSTRAINTS: usize = 21;

        pub const Row = struct {
            clk: S,
            pc: S,
            rd: ops.Access,
            rs1: reads.ReadAccess,
            rs2: reads.ReadAccess,
            is_add: S,
            is_sub: S,
            is_xor: S,
            is_or: S,
            is_and: S,
            result: [4]S,
            destination: ops.Destination,

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = reads.fromColumns(columns[12..18]),
                    .rs2 = reads.fromColumns(columns[18..24]),
                    .is_add = columns[24],
                    .is_sub = columns[25],
                    .is_xor = columns[26],
                    .is_or = columns[27],
                    .is_and = columns[28],
                    .result = columns[29..33].*,
                    .destination = ops.destinationFromColumns(columns[33..35]),
                };
            }

            pub fn active(self: Row) S {
                return self.is_add.add(self.is_sub).add(self.is_xor).add(self.is_or).add(self.is_and);
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        /// Direct AIR constraints. The byte-range lookups documented in
        /// `rangeCheckPairs` and the decoded program lookup returned by
        /// `programLookup` must be wired alongside these constraints.
        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            var i: usize = 0;

            out[i] = ops.bit(row.active());
            i += 1;
            const flags = [_]S{ row.is_add, row.is_sub, row.is_xor, row.is_or, row.is_and };
            for (flags) |flag| {
                out[i] = ops.bit(flag);
                i += 1;
            }
            var carry = S.zero();
            for (0..4) |limb| {
                const numerator = row.rs1.value[limb].add(row.rs2.value[limb]).add(carry).sub(row.result[limb]);
                carry = numerator.mul(ops.INV_BYTE_RADIX());
                out[i] = ops.selected(row.is_add, ops.bit(carry));
                i += 1;
            }

            carry = S.zero();
            for (0..4) |limb| {
                const numerator = row.result[limb].add(row.rs2.value[limb]).add(carry).sub(row.rs1.value[limb]);
                carry = numerator.mul(ops.INV_BYTE_RADIX());
                out[i] = ops.selected(row.is_sub, ops.bit(carry));
                i += 1;
            }
            for (ops.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
                out[i] = constraint;
                i += 1;
            }
            for (ops.destinationResultConstraints(row.rd, row.result, row.destination)) |constraint| {
                out[i] = constraint;
                i += 1;
            }
            std.debug.assert(i == out.len);
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.active().sub(is_active);
        }

        /// The upstream opcode ids are protocol constants, not Zig enum ordinals.
        pub fn programLookup(row: Row) ops.ProgramTuple {
            const opcode_id = row.is_add.mul(ops.q(0))
                .add(row.is_sub.mul(ops.q(1)))
                .add(row.is_xor.mul(ops.q(5)))
                .add(row.is_or.mul(ops.q(8)))
                .add(row.is_and.mul(ops.q(9)));
            return .{
                .pc = row.pc,
                .opcode_id = opcode_id,
                .rd = row.rd.addr,
                .rs1 = row.rs1.addr,
                .operand = row.rs2.addr,
            };
        }

        /// Bitwise table requests. The caller multiplies their LogUp numerators by
        /// `is_xor + is_or + is_and`; ADD/SUB rows therefore emit no bitwise entries.
        pub fn bitwiseLookups(row: Row) [4]ops.BitwiseTuple {
            const operation_id = row.is_xor.mul(ops.q(2)).add(row.is_or);
            var tuples: [4]ops.BitwiseTuple = undefined;
            for (&tuples, 0..) |*tuple, i| {
                tuple.* = .{
                    .lhs = row.rs1.value[i],
                    .rhs = row.rs2.value[i],
                    .result = row.result[i],
                    .operation_id = operation_id,
                };
            }
            return tuples;
        }

        pub fn bitwiseLookupEnabler(row: Row) S {
            return row.is_xor.add(row.is_or).add(row.is_and);
        }

        /// Each pair is one `range_check_8_8` request.
        pub fn rangeCheckPairs(row: Row) [6][2]S {
            return .{
                .{ row.result[0], row.result[1] },
                .{ row.result[2], row.result[3] },
                .{ row.rs1.value[0], row.rs1.value[1] },
                .{ row.rs1.value[2], row.rs1.value[3] },
                .{ row.rs2.value[0], row.rs2.value[1] },
                .{ row.rs2.value[2], row.rs2.value[3] },
            };
        }

        pub const AccessLookups = struct {
            rd: ops.AccessChain,
            rs1: ops.AccessChain,
            rs2: ops.AccessChain,
        };

        /// Register-file state-chain entries use the protocol's strict
        /// source-before-destination subclocks.
        pub fn accessLookups(row: Row) AccessLookups {
            return .{
                .rd = ops.registerAccessChain(row.rd, row.clk, .third),
                .rs1 = ops.registerAccessChain(row.rs1.asAccess(), row.clk, .first),
                .rs2 = ops.registerAccessChain(row.rs2.asAccess(), row.clk, .second),
            };
        }

        fn zeroRow() Row {
            const zero_access = ops.Access{
                .addr = S.zero(),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{S.zero()} ** 4,
            };
            const zero_read = reads.ReadAccess{
                .addr = S.zero(),
                .value = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
            };
            return .{
                .clk = S.zero(),
                .pc = S.zero(),
                .is_add = S.zero(),
                .is_sub = S.zero(),
                .is_xor = S.zero(),
                .is_or = S.zero(),
                .is_and = S.zero(),
                .result = .{S.zero()} ** 4,
                .destination = .{ .nonzero = S.zero(), .inverse = S.zero() },
                .rd = zero_access,
                .rs1 = zero_read,
                .rs2 = zero_read,
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "base alu reg semantics: ADD accepts byte carry chain" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_add = S.one();
                    row.rs1.value = .{ ops.q(255), ops.q(255), ops.q(0), ops.q(0) };
                    row.rs2.value = .{ ops.q(1), ops.q(0), ops.q(0), ops.q(0) };
                    row.rd.next = .{ ops.q(0), ops.q(0), ops.q(1), ops.q(0) };
                    row.result = row.rd.next;
                    try std.testing.expect(evaluate(row).allZero());
                }

                test "base alu reg semantics: compact sources alias consumed and emitted values" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_add = S.one();
                    row.rs1.value[0] = ops.q(7);
                    row.rs2.value[0] = ops.q(9);
                    row.rd.next[0] = ops.q(16);
                    row.result = row.rd.next;
                    try std.testing.expect(evaluate(row).allZero());

                    const rs1_access = row.rs1.asAccess();
                    const rs2_access = row.rs2.asAccess();
                    try std.testing.expectEqual(rs1_access.previous, rs1_access.next);
                    try std.testing.expectEqual(rs2_access.previous, rs2_access.next);
                }

                test "base alu reg semantics: ADD rejects a forged result" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_add = S.one();
                    row.rs1.value[0] = ops.q(7);
                    row.rs2.value[0] = ops.q(9);
                    row.rd.next[0] = ops.q(17);
                    row.result[0] = ops.q(17);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "base alu reg semantics: x0 discards arithmetic and bitwise results" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.is_add = S.one();
                    row.rs1.value[0] = ops.q(7);
                    row.rs2.value[0] = ops.q(9);
                    row.result[0] = ops.q(16);
                    try std.testing.expect(evaluate(row).allZero());

                    row.is_add = S.zero();
                    row.is_xor = S.one();
                    try std.testing.expect(bitwiseLookupEnabler(row).eql(S.one()));
                }

                test "base alu reg semantics: SUB accepts unsigned wraparound" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_sub = S.one();
                    row.rs1.value = .{S.zero()} ** 4;
                    row.rs2.value[0] = ops.q(1);
                    row.rd.next = .{ ops.q(255), ops.q(255), ops.q(255), ops.q(255) };
                    row.result = row.rd.next;
                    try std.testing.expect(evaluate(row).allZero());
                }

                test "base alu reg semantics: decoded tuple uses pinned Stark-V ids" {
                    var row = zeroRow();
                    row.is_xor = S.one();
                    const tuple = programLookup(row);
                    try std.testing.expect(tuple.opcode_id.eql(ops.q(5)));
                }

                test "base alu reg semantics: access lookups emit at derived subclocks" {
                    var row = zeroRow();
                    row.clk = ops.q(19);
                    row.rs1.addr = ops.q(7);
                    row.rs1.previous_clock = ops.q(11);
                    row.rs1.value[0] = ops.q(41);

                    const chain = accessLookups(row).rs1;
                    try std.testing.expect(chain.previous.addr_space.isZero());
                    try std.testing.expect(chain.previous.addr.eql(ops.q(7)));
                    try std.testing.expect(chain.previous.clock.eql(ops.q(11)));
                    try std.testing.expect(chain.previous.limbs[0].eql(ops.q(41)));
                    try std.testing.expect(chain.next.clock.eql(ops.q(73)));
                    try std.testing.expect(chain.next.limbs[0].eql(ops.q(41)));
                    try std.testing.expect(chain.clock_gap.eql(ops.q(61)));
                }

                test "base alu reg semantics: oracle adapter preserves access-first layout" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[2] = ops.q(1);
                    columns[3] = ops.q(2);
                    columns[7] = ops.q(3);
                    columns[8] = ops.q(4);
                    columns[12] = ops.q(5);
                    columns[17] = ops.q(6);
                    columns[13] = ops.q(7);
                    columns[18] = ops.q(8);
                    columns[23] = ops.q(9);
                    columns[19] = ops.q(10);
                    columns[24] = ops.q(11);

                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.rd.addr.eql(ops.q(1)));
                    try std.testing.expect(row.rd.previous[0].eql(ops.q(2)));
                    try std.testing.expect(row.rd.previous_clock.eql(ops.q(3)));
                    try std.testing.expect(row.rd.next[0].eql(ops.q(4)));
                    try std.testing.expect(row.rs1.addr.eql(ops.q(5)));
                    try std.testing.expect(row.rs1.previous_clock.eql(ops.q(6)));
                    try std.testing.expect(row.rs1.value[0].eql(ops.q(7)));
                    try std.testing.expect(row.rs2.addr.eql(ops.q(8)));
                    try std.testing.expect(row.rs2.previous_clock.eql(ops.q(9)));
                    try std.testing.expect(row.rs2.value[0].eql(ops.q(10)));
                    try std.testing.expect(row.is_add.eql(ops.q(11)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
