//! Exact pinned Stark-V byte/half/word load-store semantics and lookups.
//!
//! The effective address is a base-field sum, `composeU32(rs1.value) + imm_felt`,
//! and the base field is not `2^32`. That is only the architectural address
//! while the sum stays inside the canonical range of `M31 = 2^31 - 1`, so the
//! base carries an explicit bound: its high limb is pinned to zero, which puts
//! every admitted base below `2^24` and therefore more than a displacement away
//! from the modulus. Without that bound a base within one displacement below
//! the modulus wraps onto a small, word-aligned address and names a different
//! memory word than the architecture does (issue #140).

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");
const read_access = @import("read_access.zig");

pub fn Semantics(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const reads = read_access.Ops(S, ops.Access);

        pub const N_ORACLE_COLUMNS: usize = 48;
        pub const N_CONSTRAINTS: usize = 62;
        pub const CURRENT_TRACE_COMPATIBLE = true;

        pub const Row = struct {
            clk: S,
            pc: S,
            dst: ops.Access,
            rs1: reads.ReadAccess,
            src: reads.ReadAccess,
            r2_idx: S,
            imm_felt: S,
            src_msb: S,
            shift_amount: S,
            src_addr_selector: S,
            dst_addr_selector: S,
            markers: [4]S,
            is_lb: S,
            is_lh: S,
            is_lbu: S,
            is_lhu: S,
            is_lw: S,
            is_sb: S,
            is_sh: S,
            is_sw: S,
            result: [4]S,
            destination: ops.Destination,

            pub fn fromOracleColumns(columns: []const S) !Row {
                if (columns.len != N_ORACLE_COLUMNS) return error.InvalidOracleTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .dst = ops.accessFromColumns(columns[2..12]),
                    .rs1 = reads.fromColumns(columns[12..18]),
                    .src = reads.fromColumns(columns[18..24]),
                    .r2_idx = columns[24],
                    .imm_felt = columns[25],
                    .src_msb = columns[26],
                    .shift_amount = columns[27],
                    .src_addr_selector = columns[28],
                    .dst_addr_selector = columns[29],
                    .markers = columns[30..34].*,
                    .is_lb = columns[34],
                    .is_lh = columns[35],
                    .is_lbu = columns[36],
                    .is_lhu = columns[37],
                    .is_lw = columns[38],
                    .is_sb = columns[39],
                    .is_sh = columns[40],
                    .is_sw = columns[41],
                    .result = columns[42..46].*,
                    .destination = ops.destinationFromColumns(columns[46..48]),
                };
            }

            pub fn active(self: Row) S {
                return self.is_lb.add(self.is_lh).add(self.is_lbu).add(self.is_lhu)
                    .add(self.is_lw).add(self.is_sb).add(self.is_sh).add(self.is_sw);
            }
        };

        pub const Derived = struct {
            opcode_b: S,
            opcode_h: S,
            opcode_w: S,
            is_signed: S,
            load_b: S,
            load_h: S,
            is_store: S,
            is_load: S,
            mem_addr: S,
            marker_sum: S,
            shift_id: S,
            signed_mask: S,
            aligned_addr_quarter: S,
        };

        pub fn derive(row: Row) Derived {
            const enabler = row.active();
            const opcode_b = row.is_lbu.add(row.is_lb).add(row.is_sb);
            const opcode_h = row.is_lhu.add(row.is_lh).add(row.is_sh);
            const is_signed = row.is_lb.add(row.is_lh);
            const is_store = row.is_sb.add(row.is_sh).add(row.is_sw);
            var marker_sum = S.zero();
            var shift_id = S.zero();
            for (row.markers, 0..) |marker, i| {
                marker_sum = marker_sum.add(marker);
                shift_id = shift_id.add(marker.mul(ops.q(i)));
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
                .mem_addr = ops.composeU32(row.rs1.value).add(row.imm_felt),
                .marker_sum = marker_sum,
                .shift_id = shift_id,
                .signed_mask = is_signed.mul(row.src_msb).mul(ops.q(255)),
                .aligned_addr_quarter = row.src_addr_selector.add(row.dst_addr_selector)
                    .sub(row.r2_idx).mul(ops.INV_4()),
            };
        }

        pub const Constraints = ops.ConstraintSet(N_CONSTRAINTS);

        pub fn evaluate(row: Row) Constraints {
            @setEvalBranchQuota(100_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var n: usize = 0;
            const d = derive(row);
            out[n] = ops.bit(row.active());
            n += 1;
            for ([_]S{
                row.is_lb, row.is_lh, row.is_lbu, row.is_lhu,
                row.is_lw, row.is_sb, row.is_sh,  row.is_sw,
            }) |flag| {
                out[n] = ops.bit(flag);
                n += 1;
            }
            out[n] = ops.bit(row.src_msb);
            n += 1;
            // The sign witness has no meaning outside signed loads. Canonicalizing it
            // prevents an unconstrained committed column on every other opcode.
            out[n] = S.one().sub(d.is_signed).mul(row.src_msb);
            n += 1;

            for (row.markers) |marker| {
                out[n] = ops.bit(marker);
                n += 1;
            }
            out[n] = row.shift_amount.sub(
                d.opcode_b.mul(d.shift_id)
                    .add(d.opcode_h.mul(d.shift_id.sub(S.one())).mul(ops.INV_2())),
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
            out[n] = d.opcode_b.mul(S.one().sub(d.marker_sum));
            n += 1;
            out[n] = d.opcode_h.mul(ops.q(2).sub(d.marker_sum));
            n += 1;
            out[n] = d.opcode_h.mul(S.one().sub(d.shift_id)).mul(ops.q(5).sub(d.shift_id));
            n += 1;

            for (1..4) |limb| {
                out[n] = d.load_b.mul(d.signed_mask.sub(row.result[limb]));
                n += 1;
            }
            for (0..4) |limb| {
                const marker = row.markers[limb];
                out[n] = d.load_b.mul(row.result[0].sub(row.src.value[limb])).mul(marker);
                n += 1;
                out[n] = row.is_sb.mul(row.dst.next[limb].sub(row.src.value[0])).mul(marker);
                n += 1;
            }
            for (2..4) |limb| {
                out[n] = d.load_h.mul(d.signed_mask.sub(row.result[limb]));
                n += 1;
            }

            const low_half = ops.q(5).sub(d.shift_id).mul(ops.INV_4());
            const high_half = d.shift_id.sub(S.one()).mul(ops.INV_4());
            out[n] = d.load_h.mul(low_half).mul(row.result[0].sub(row.src.value[0]));
            n += 1;
            out[n] = d.load_h.mul(low_half).mul(row.result[1].sub(row.src.value[1]));
            n += 1;
            out[n] = d.load_h.mul(high_half).mul(row.result[0].sub(row.src.value[2]));
            n += 1;
            out[n] = d.load_h.mul(high_half).mul(row.result[1].sub(row.src.value[3]));
            n += 1;
            out[n] = row.is_sh.mul(low_half).mul(row.dst.next[0].sub(row.src.value[0]));
            n += 1;
            out[n] = row.is_sh.mul(low_half).mul(row.dst.next[1].sub(row.src.value[1]));
            n += 1;
            out[n] = row.is_sh.mul(high_half).mul(row.dst.next[2].sub(row.src.value[0]));
            n += 1;
            out[n] = row.is_sh.mul(high_half).mul(row.dst.next[3].sub(row.src.value[1]));
            n += 1;

            for (0..4) |limb| {
                out[n] = row.is_lw.mul(row.result[limb].sub(row.src.value[limb]))
                    .add(row.is_sw.mul(row.dst.next[limb].sub(row.src.value[limb])));
                n += 1;
            }
            const enabler = row.active();
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
                    .mul(S.one().sub(row.markers[limb]))
                    .mul(row.dst.next[limb].sub(row.dst.previous[limb]));
                n += 1;
            }
            for (ops.destinationConstraints(row.r2_idx, row.destination)) |constraint| {
                out[n] = constraint;
                n += 1;
            }
            for (ops.destinationResultConstraints(
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
                out[n] = S.one().sub(d.is_load).mul(limb);
                n += 1;
            }
            // The address is a base-field sum, so it is the architectural address
            // only while `base + imm` stays below `M31`. The aligned-address
            // `range_check_20` confines every admitted address to `[0, 2^22)` and
            // the displacement is a signed 12-bit field, so an honest base is
            // always below `2^22 + 2^11`. Pinning the base's high limb to zero
            // bounds it by `2^24`: above every address this AIR can admit, and
            // more than a displacement below the modulus, so the sum cannot wrap.
            // The bound reads the remaining limbs as bytes, which is the memory
            // bus's job here as it is for every other family's operand
            // arithmetic — each register write is byte-range-checked by the
            // family that made it.
            // Only rows whose field address already disagrees with their
            // architectural address are lost — `LW x7, 8(x5)` with
            // `x5 = 0x7ffffffb` is architecturally the misaligned `0x80000003`
            // but the field sum is the clean `0x00000004` (issue #140).
            out[n] = enabler.mul(row.rs1.value[3]);
            n += 1;
            std.debug.assert(n == out.len);
            return .{ .values = out };
        }

        pub fn placementConstraint(row: Row, is_active: S) S {
            return row.active().sub(is_active);
        }

        pub fn programLookup(row: Row) ops.ProgramTuple {
            const opcode_id = row.is_lb.mul(ops.q(19)).add(row.is_lh.mul(ops.q(20)))
                .add(row.is_lw.mul(ops.q(21))).add(row.is_lbu.mul(ops.q(22)))
                .add(row.is_lhu.mul(ops.q(23))).add(row.is_sb.mul(ops.q(24)))
                .add(row.is_sh.mul(ops.q(25))).add(row.is_sw.mul(ops.q(26)));
            return .{
                .pc = row.pc,
                .opcode_id = opcode_id,
                .rd = row.rs1.addr,
                .rs1 = row.r2_idx,
                .operand = row.imm_felt,
            };
        }

        pub const AccessLookups = struct {
            rs1: ops.AccessChain,
            src: ops.AccessChain,
            dst: ops.AccessChain,
        };

        pub fn accessLookups(row: Row) AccessLookups {
            const d = derive(row);
            const second = ops.accessClock(row.clk, .second);
            return .{
                .rs1 = ops.registerAccessChain(row.rs1.asAccess(), row.clk, .first),
                // Loads read memory after rs1 and rd bookkeeping; stores read
                // rs2 second. Both use the same committed `src` block.
                .src = ops.accessChain(
                    row.src.asAccess(),
                    second.add(d.is_load),
                    d.is_load,
                    row.src_addr_selector,
                    row.src.value,
                ),
                // Loads write rd second; stores update memory third.
                .dst = ops.accessChain(
                    row.dst,
                    second.add(d.is_store),
                    d.is_store,
                    row.dst_addr_selector,
                    row.dst.next,
                ),
            };
        }

        pub fn stateLookup(row: Row) ops.RegistersStateChain {
            return ops.registersStateChain(row.pc, row.clk);
        }

        pub fn alignedAddressRangeLookup(row: Row) S {
            return derive(row).aligned_addr_quarter;
        }

        pub fn baseAddressM31Lookup(row: Row) [2]S {
            return .{ row.rs1.value[0], row.rs1.value[3] };
        }

        /// Seven-bit residuals that bind `src_msb` to the actual sign-bearing result
        /// byte. The caller activates the first tuple for LB and the second for LH.
        pub fn signRangeLookups(row: Row) [2][2]S {
            return .{
                .{ S.zero(), row.result[0].sub(row.src_msb.mul(ops.q(128))) },
                .{ S.zero(), row.result[1].sub(row.src_msb.mul(ops.q(128))) },
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

        fn zeroReadAccess() reads.ReadAccess {
            return .{
                .addr = S.zero(),
                .value = .{S.zero()} ** 4,
                .previous_clock = S.zero(),
            };
        }

        fn honestSignedByteLoad() Row {
            var dst = zeroAccess();
            dst.addr = ops.q(2);
            dst.next = .{ ops.q(128), ops.q(255), ops.q(255), ops.q(255) };
            var src = zeroReadAccess();
            src.addr = S.zero();
            src.value = .{ ops.q(7), ops.q(128), ops.q(9), ops.q(10) };
            return .{
                .clk = S.one(),
                .pc = ops.q(0x1000),
                .dst = dst,
                .rs1 = zeroReadAccess(),
                .src = src,
                .r2_idx = ops.q(2),
                .imm_felt = S.one(),
                .src_msb = S.one(),
                .shift_amount = S.one(),
                .src_addr_selector = S.zero(),
                .dst_addr_selector = ops.q(2),
                .markers = .{ S.zero(), S.one(), S.zero(), S.zero() },
                .is_lb = S.one(),
                .is_lh = S.zero(),
                .is_lbu = S.zero(),
                .is_lhu = S.zero(),
                .is_lw = S.zero(),
                .is_sb = S.zero(),
                .is_sh = S.zero(),
                .is_sw = S.zero(),
                .result = .{ ops.q(128), ops.q(255), ops.q(255), ops.q(255) },
                .destination = .{
                    .nonzero = S.one(),
                    .inverse = ops.q(2).inv() catch unreachable,
                },
            };
        }

        /// An `LW x7, imm(x5)` row that reads `0xdeadbeef` from `address`.
        ///
        /// The address is supplied rather than derived so the caller can build
        /// both an honest row and the issue #140 row whose field address and
        /// architectural address disagree.
        fn wordLoad(base: u32, imm: u32, address: u32) Row {
            var rs1 = zeroReadAccess();
            rs1.addr = ops.q(5);
            for (&rs1.value, 0..) |*limb, i| {
                limb.* = ops.q((base >> @as(u5, @intCast(8 * i))) & 0xff);
            }
            var src = zeroReadAccess();
            src.addr = ops.q(address);
            src.value = .{ ops.q(0xef), ops.q(0xbe), ops.q(0xad), ops.q(0xde) };
            var dst = zeroAccess();
            dst.addr = ops.q(7);
            dst.next = src.value;
            return .{
                .clk = S.one(),
                .pc = ops.q(0x1000),
                .dst = dst,
                .rs1 = rs1,
                .src = src,
                .r2_idx = ops.q(7),
                .imm_felt = ops.q(imm),
                .src_msb = S.zero(),
                .shift_amount = S.zero(),
                .src_addr_selector = ops.q(address),
                .dst_addr_selector = ops.q(7),
                .markers = .{S.zero()} ** 4,
                .is_lb = S.zero(),
                .is_lh = S.zero(),
                .is_lbu = S.zero(),
                .is_lhu = S.zero(),
                .is_lw = S.one(),
                .is_sb = S.zero(),
                .is_sh = S.zero(),
                .is_sw = S.zero(),
                .result = src.value,
                .destination = .{
                    .nonzero = S.one(),
                    .inverse = ops.q(7).inv() catch unreachable,
                },
            };
        }

        fn honestByteStore() Row {
            var row = honestSignedByteLoad();
            row.is_lb = S.zero();
            row.is_sb = S.one();
            row.src_msb = S.zero();
            row.r2_idx = ops.q(3);
            row.destination = .{
                .nonzero = S.one(),
                .inverse = ops.q(3).inv() catch unreachable,
            };
            row.src.addr = ops.q(3);
            row.src.value = .{ ops.q(0xab), S.zero(), S.zero(), S.zero() };
            row.dst.addr = S.zero();
            row.dst.previous = .{ ops.q(1), ops.q(2), ops.q(3), ops.q(4) };
            row.dst.next = .{ ops.q(1), ops.q(0xab), ops.q(3), ops.q(4) };
            row.result = .{S.zero()} ** 4;
            row.src_addr_selector = ops.q(3);
            row.dst_addr_selector = S.zero();
            return row;
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "load store: signed byte load is accepted with exact address roles" {
                    var row = honestSignedByteLoad();
                    std.mem.doNotOptimizeAway(&row);
                    try std.testing.expect(evaluate(row).allZero());
                    try std.testing.expect(programLookup(row).opcode_id.eql(ops.q(19)));
                    const accesses = accessLookups(row);
                    try std.testing.expect(accesses.src.next.addr_space.eql(S.one()));
                    try std.testing.expect(accesses.dst.next.addr_space.isZero());
                }

                test "load store: forged selected byte and unaligned selector are rejected" {
                    var row = honestSignedByteLoad();
                    row.dst.next[0] = ops.q(127);
                    try std.testing.expect(!evaluate(row).allZero());
                    row = honestSignedByteLoad();
                    row.src_addr_selector = S.one();
                    try std.testing.expect(!evaluate(row).allZero());

                    row = honestSignedByteLoad();
                    row.src_msb = ops.q(3);
                    row.result = .{ ops.q(128), ops.q(765), ops.q(765), ops.q(765) };
                    row.dst.next = row.result;
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "load store: compact reads alias consumed and emitted values" {
                    const row = honestSignedByteLoad();
                    const rs1 = row.rs1.asAccess();
                    const src = row.src.asAccess();
                    try std.testing.expectEqual(rs1.previous, rs1.next);
                    try std.testing.expectEqual(src.previous, src.next);
                }

                test "load store: byte store preserves the unmarked bytes of the word" {
                    var row = honestByteStore();
                    try std.testing.expect(evaluate(row).allZero());
                    row.dst.next[3] = ops.q(0xee);
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "load store: signed-load range requests bind the selected sign byte" {
                    const table = @import("../lookups/tables/schema.zig");

                    var row = honestSignedByteLoad();
                    const honest = signRangeLookups(row);
                    _ = try table.indexSecure(.range_check_m31, &honest[0]);

                    row.src_msb = S.zero();
                    row.result = .{ ops.q(128), S.zero(), S.zero(), S.zero() };
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
                    row.dst.addr = S.zero();
                    row.r2_idx = S.zero();
                    row.dst_addr_selector = S.zero();
                    row.dst.next = .{S.zero()} ** 4;
                    row.destination = .{ .nonzero = S.zero(), .inverse = S.zero() };
                    try std.testing.expect(evaluate(row).allZero());

                    row.src_addr_selector = S.one();
                    try std.testing.expect(!evaluate(row).allZero());
                }

                test "load store: word store reverses register and memory roles" {
                    var row = honestSignedByteLoad();
                    row.is_lb = S.zero();
                    row.is_sw = S.one();
                    row.src_msb = S.zero();
                    row.markers = .{S.zero()} ** 4;
                    row.shift_amount = S.zero();
                    row.imm_felt = ops.q(4);
                    row.r2_idx = ops.q(3);
                    row.destination = .{
                        .nonzero = S.one(),
                        .inverse = ops.q(3).inv() catch unreachable,
                    };
                    row.src.addr = ops.q(3);
                    row.src.value = .{ ops.q(1), ops.q(2), ops.q(3), ops.q(4) };
                    row.dst.next = row.src.value;
                    row.result = .{S.zero()} ** 4;
                    row.src_addr_selector = ops.q(3);
                    row.dst_addr_selector = ops.q(4);
                    try std.testing.expect(evaluate(row).allZero());
                    const accesses = accessLookups(row);
                    try std.testing.expect(accesses.src.next.addr_space.isZero());
                    try std.testing.expect(accesses.dst.next.addr_space.eql(S.one()));
                    try std.testing.expect(programLookup(row).opcode_id.eql(ops.q(26)));
                }

                test "load store: a base near the field modulus cannot alias an address" {
                    // Issue #140. `LW x7, 8(x5)` with `x5 = 0x7ffffffb` is
                    // architecturally a load from `0x80000003`, which is not even
                    // word aligned, so the architecture traps. The base-field sum
                    // wraps the modulus and lands on `0x00000004` instead. Every
                    // other constraint in the family accepts that row, so the base
                    // bound has to be the one that rejects it — the count below
                    // fails if some unrelated edit starts carrying this witness.
                    const aliased = wordLoad(0x7ffffffb, 8, 4);
                    var fired: usize = 0;
                    for (evaluate(aliased).values) |value| {
                        if (!value.isZero()) fired += 1;
                    }
                    try std.testing.expectEqual(@as(usize, 1), fired);
                    try std.testing.expect(
                        !evaluate(aliased).values[N_CONSTRAINTS - 1].isZero(),
                    );

                    // Nothing an honest program can reach is lost: the aligned
                    // address range check already bounds the address by `2^22`, and
                    // both an ordinary base and the largest admitted address stay
                    // accepted.
                    try std.testing.expect(evaluate(wordLoad(0x2000, 8, 0x2008)).allZero());
                    try std.testing.expect(
                        evaluate(wordLoad(0x3ffffc, 0, 0x3ffffc)).allZero(),
                    );
                    // A negative displacement still reaches through the field wrap
                    // it is encoded with.
                    var negative = wordLoad(0x2010, 0, 0x2000);
                    negative.imm_felt = S.zero().sub(ops.q(16));
                    try std.testing.expect(evaluate(negative).allZero());
                }

                test "load store: adapter follows exact role and flag order" {
                    var columns = [_]S{S.zero()} ** N_ORACLE_COLUMNS;
                    columns[2] = ops.q(10);
                    columns[12] = ops.q(11);
                    columns[18] = ops.q(12);
                    columns[24] = ops.q(13);
                    columns[34] = ops.q(14);
                    columns[41] = ops.q(15);
                    const row = try Row.fromOracleColumns(&columns);
                    try std.testing.expect(row.dst.addr.eql(ops.q(10)));
                    try std.testing.expect(row.rs1.addr.eql(ops.q(11)));
                    try std.testing.expect(row.src.addr.eql(ops.q(12)));
                    try std.testing.expect(row.r2_idx.eql(ops.q(13)));
                    try std.testing.expect(row.is_lb.eql(ops.q(14)));
                    try std.testing.expect(row.is_sw.eql(ops.q(15)));
                }
            };
        }
    };
}

comptime {
    _ = Semantics(QM31).selfTests();
}
