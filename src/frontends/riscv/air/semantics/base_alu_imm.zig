//! Test-only oracle for retired BASE_ALU_IMM semantics.
//!
//! Production consumes `typed_base_alu_imm_authority.zig`. This independent
//! Stark-V-shaped evaluator remains rooted by tests to detect polynomial or
//! relation-order drift.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);

        pub const N_ORACLE_COLUMNS: usize = 35;
        pub const N_CONSTRAINTS: usize = 21;

        pub const Row = struct {
            clk: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            imm_0: S,
            imm_1: S,
            imm_msb: S,
            is_addi: S,
            is_xori: S,
            is_ori: S,
            is_andi: S,
            result: [4]S,
            destination: ops.Destination,

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = ops.accessFromColumns(columns[12..22]),
                    .imm_0 = columns[22],
                    .imm_1 = columns[23],
                    .imm_msb = columns[24],
                    .is_addi = columns[25],
                    .is_xori = columns[26],
                    .is_ori = columns[27],
                    .is_andi = columns[28],
                    .result = columns[29..33].*,
                    .destination = ops.destinationFromColumns(columns[33..35]),
                };
            }

            pub fn active(self: Row) S {
                return self.is_addi.add(self.is_xori).add(self.is_ori).add(self.is_andi);
            }
        };

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        fn immediateLimbs(row: Row) [4]S {
            // Sign extension of `[imm_0:8, imm_1:3, sign:1]` to four bytes.
            const limb_1 = row.imm_1.add(row.imm_msb.mul(ops.q(248)));
            const fill = row.imm_msb.mul(ops.q(255));
            return .{ row.imm_0, limb_1, fill, fill };
        }

        pub fn unsignedImmediate(row: Row) S {
            return row.imm_0
                .add(row.imm_1.mul(ops.q(1 << 8)))
                .add(row.imm_msb.mul(ops.q(1 << 11)));
        }

        /// Exact direct constraints, conditional on the documented immediate and
        /// register-limb range lookups.
        pub fn evaluate(row: Row) Constraints {
            var out: [N_CONSTRAINTS]S = undefined;
            var i: usize = 0;

            out[i] = ops.bit(row.active());
            i += 1;
            const flags = [_]S{ row.is_addi, row.is_xori, row.is_ori, row.is_andi };
            for (flags) |flag| {
                out[i] = ops.bit(flag);
                i += 1;
            }
            out[i] = ops.bit(row.imm_msb);
            i += 1;
            const imm = immediateLimbs(row);
            var carry = S.zero();
            for (0..4) |limb| {
                const numerator = row.rs1.next[limb].add(imm[limb]).add(carry).sub(row.result[limb]);
                carry = numerator.mul(ops.INV_BYTE_RADIX());
                out[i] = ops.selected(row.is_addi, ops.bit(carry));
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
            // rs1 is read-only: it must emit exactly the value it consumed.
            for (ops.readOnlyAccessConstraints(row.rs1, row.active())) |constraint| {
                out[i] = constraint;
                i += 1;
            }
            std.debug.assert(i == out.len);
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.active().sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            const opcode_id = row.is_addi.mul(ops.q(10))
                .add(row.is_xori.mul(ops.q(13)))
                .add(row.is_ori.mul(ops.q(14)))
                .add(row.is_andi.mul(ops.q(15)));
            return .{
                .pc = row.pc,
                .opcode_id = opcode_id,
                .rd = row.rd.addr,
                .rs1 = row.rs1.addr,
                .operand = unsignedImmediate(row),
            };
        }

        pub fn bitwiseLookups(row: Row) [4]ops.BitwiseTuple {
            const operation_id = row.is_xori.mul(ops.q(2)).add(row.is_ori);
            const imm = immediateLimbs(row);
            var tuples: [4]ops.BitwiseTuple = undefined;
            for (&tuples, 0..) |*tuple, i| {
                tuple.* = .{
                    .lhs = row.rs1.next[i],
                    .rhs = imm[i],
                    .result = row.result[i],
                    .operation_id = operation_id,
                };
            }
            return tuples;
        }

        pub fn bitwiseLookupEnabler(row: Row) S {
            return row.is_xori.add(row.is_ori).add(row.is_andi);
        }

        /// Inputs for the upstream `range_check_8_11` immediate lookup. The second
        /// coordinate is shifted by eight bits exactly as in the pinned schema.
        pub fn immediateRangeLookup(row: Row) [2]S {
            return .{ row.imm_0, row.imm_1.mul(ops.q(1 << 8)) };
        }

        pub fn registerRangeCheckPairs(row: Row) [4][2]S {
            return .{
                .{ row.result[0], row.result[1] },
                .{ row.result[2], row.result[3] },
                .{ row.rs1.next[0], row.rs1.next[1] },
                .{ row.rs1.next[2], row.rs1.next[3] },
            };
        }

        pub const AccessLookups = struct {
            rd: ops.AccessChain,
            rs1: ops.AccessChain,
        };

        pub fn accessLookups(row: Row) AccessLookups {
            return .{
                .rd = ops.registerAccessChain(row.rd, row.clk, .second),
                .rs1 = ops.registerAccessChain(row.rs1, row.clk, .first),
            };
        }

        fn zeroRow() Row {
            const zero_access = ops.Access{
                .addr = S.zero(),
                .previous = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
                .next = .{S.zero()} ** 4,
            };
            return .{
                .clk = S.zero(),
                .pc = S.zero(),
                .is_addi = S.zero(),
                .is_xori = S.zero(),
                .is_ori = S.zero(),
                .is_andi = S.zero(),
                .imm_0 = S.zero(),
                .imm_1 = S.zero(),
                .imm_msb = S.zero(),
                .result = .{S.zero()} ** 4,
                .destination = .{ .nonzero = S.zero(), .inverse = S.zero() },
                .rd = zero_access,
                .rs1 = zero_access,
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "base alu imm semantics: exact ADDI accepts an honest row" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_addi = S.one();
                    row.imm_0 = ops.q(1);
                    row.rd.next[0] = ops.q(1);
                    row.result[0] = ops.q(1);
                    try std.testing.expect(evaluate(row).allZero());
                }

                test "base alu imm semantics: rs1 must emit the value it consumed" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_addi = S.one();
                    row.imm_0 = ops.q(1);
                    row.rs1.next[0] = ops.q(41);
                    row.rs1.previous = row.rs1.next;
                    row.rd.next[0] = ops.q(42);
                    row.result[0] = ops.q(42);
                    try std.testing.expect(evaluate(row).allZero());

                    // The addition runs on `next`; forging `previous` turns the source read
                    // into an arbitrary register write and must be rejected.
                    row.rs1.previous[0] = ops.q(0xbe);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "base alu imm semantics: exact ADDI rejects known impossible witness" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_addi = S.one();
                    row.imm_0 = ops.q(1);
                    // The pre-existing prover test claimed ADDI x1,x1,1 while rs1 remained 0
                    // and rd advanced to 2. The byte carry constraint must reject that row.
                    row.rs1.next[0] = ops.q(0);
                    row.rd.next[0] = ops.q(2);
                    row.result[0] = ops.q(2);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "base alu imm semantics: byte carries reject M31 word alias" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_addi = S.one();
                    // 0x7fffffff is the M31 modulus, so a single reconstructed word equation
                    // would confuse this forged result with zero. Per-byte carries do not.
                    row.rd.next = .{ ops.q(255), ops.q(255), ops.q(255), ops.q(127) };
                    row.result = row.rd.next;
                    try std.testing.expect(ops.composeU32(row.rd.next).isZero());
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "base alu imm semantics: x0 discards arithmetic and bitwise results" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.is_addi = S.one();
                    row.imm_0 = ops.q(1);
                    row.result[0] = ops.q(1);
                    try std.testing.expect(evaluate(row).allZero());

                    row.is_addi = S.zero();
                    row.is_xori = S.one();
                    try std.testing.expect(bitwiseLookupEnabler(row).eql(S.one()));
                }

                test "base alu imm semantics: negative immediate sign extends by bytes" {
                    var row = zeroRow();
                    row.pc = ops.q(0x1000);
                    row.rd.addr = S.one();
                    row.destination = .{ .nonzero = S.one(), .inverse = S.one() };
                    row.is_addi = S.one();
                    row.imm_0 = ops.q(255);
                    row.imm_1 = ops.q(7);
                    row.imm_msb = S.one();
                    row.rs1.next = .{S.zero()} ** 4;
                    row.rd.next = .{ ops.q(255), ops.q(255), ops.q(255), ops.q(255) };
                    row.result = row.rd.next;
                    try std.testing.expect(evaluate(row).allZero());

                    const tuple = programLookup(row);
                    try std.testing.expect(tuple.opcode_id.eql(ops.q(10)));
                    try std.testing.expect(tuple.operand.eql(ops.q(4095)));
                }

                test "base alu imm semantics: access lookups preserve register chain values" {
                    var row = zeroRow();
                    row.clk = ops.q(23);
                    row.rd.addr = ops.q(3);
                    row.rd.previous_clock = ops.q(17);
                    row.rd.previous[2] = ops.q(90);
                    row.rd.next[2] = ops.q(91);

                    const chain = accessLookups(row).rd;
                    try std.testing.expect(chain.previous.addr.eql(ops.q(3)));
                    try std.testing.expect(chain.previous.clock.eql(ops.q(17)));
                    try std.testing.expect(chain.previous.limbs[2].eql(ops.q(90)));
                    try std.testing.expect(chain.next.clock.eql(ops.q(90)));
                    try std.testing.expect(chain.next.limbs[2].eql(ops.q(91)));
                    try std.testing.expect(chain.clock_gap.eql(ops.q(72)));
                }

                test "base alu imm semantics: oracle adapter preserves access-first layout" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[2] = ops.q(1);
                    columns[3] = ops.q(2);
                    columns[7] = ops.q(3);
                    columns[8] = ops.q(4);
                    columns[12] = ops.q(5);
                    columns[13] = ops.q(6);
                    columns[17] = ops.q(7);
                    columns[18] = ops.q(8);
                    columns[22] = ops.q(9);
                    columns[25] = ops.q(10);

                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.rd.addr.eql(ops.q(1)));
                    try std.testing.expect(row.rd.previous[0].eql(ops.q(2)));
                    try std.testing.expect(row.rd.previous_clock.eql(ops.q(3)));
                    try std.testing.expect(row.rd.next[0].eql(ops.q(4)));
                    try std.testing.expect(row.rs1.addr.eql(ops.q(5)));
                    try std.testing.expect(row.rs1.previous[0].eql(ops.q(6)));
                    try std.testing.expect(row.rs1.previous_clock.eql(ops.q(7)));
                    try std.testing.expect(row.rs1.next[0].eql(ops.q(8)));
                    try std.testing.expect(row.imm_0.eql(ops.q(9)));
                    try std.testing.expect(row.is_addi.eql(ops.q(10)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
