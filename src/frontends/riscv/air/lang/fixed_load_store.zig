//! Allocation-free executable RV32 load/store polynomial core.
//!
//! This fixed scalar program mirrors the pinned 62-root load/store semantics
//! exactly. It is retained by the authenticated authority so the AIR hot path
//! performs no arena traversal, string lookup, allocation, or callback dispatch.

const std = @import("std");
const common = @import("../semantics/common.zig");
const read_access = @import("../semantics/read_access.zig");

pub fn Evaluator(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const reads = read_access.Ops(S, ops.Access);

        pub const MAIN_COLUMN_COUNT: usize = 48;
        pub const CONSTRAINT_COUNT: usize = 62;
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

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT) return error.InvalidMainTraceShape;
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

        pub const Constraints = ops.ConstraintSet(CONSTRAINT_COUNT);

        pub fn evaluate(row: Row) Constraints {
            @setEvalBranchQuota(100_000);
            var out: [CONSTRAINT_COUNT]S = undefined;
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
    };
}

comptime {
    if (Evaluator(@import("stwo_core").fields.qm31.QM31).CONSTRAINT_COUNT != 62)
        @compileError("fixed load/store root geometry drifted");
}
