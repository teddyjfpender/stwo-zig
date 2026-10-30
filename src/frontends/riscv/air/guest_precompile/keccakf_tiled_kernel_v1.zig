//! Experimental paired-lane equations over independently fixed shifted views.
//! This is a constrained kernel, NOT a STARK verifier or caller receipt. Exact
//! packed_value private-table providers and caller I/O closure remain integration
//! obligations. The released Keccak component is unchanged.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const A = @import("keccakf_authority.zig");
const W = @import("keccakf_witness.zig");
pub fn Kernel(comptime lanes: usize) type {
    return KernelWithTables(lanes, false, false);
}
/// Each throughput output remains a separate lookup coordinate. Packing several
/// unconstrained output cells into one field would allow carries/field aliases.
pub fn KernelWithTables(comptime lanes: usize, comptime full_chi: bool, comptime full_xor: bool) type {
    comptime if (lanes != 1 and lanes != 5) @compileError("experimental tiles support one or five paired lanes");
    return struct {
        pub const rows_per_state = A.lane_count / lanes;
        const stride: i32 = @intCast(rows_per_state);
        pub const state_width = lanes * A.lane_bits;
        pub const parity_width = (A.geometry.parity_positions + rows_per_state - 1) / rows_per_state;
        pub const parity = state_width;
        pub const chi_width = if (full_chi) A.lane_bits else state_width;
        pub const chi = parity + parity_width;
        pub const xor = chi + chi_width;
        pub const chi_event_columns = chi_width;
        pub const xor_event_columns = if (full_xor) (parity_width + 2) / 3 else parity_width;
        pub const main_columns = xor + parity_width;
        pub const fixed_columns = W.row_count + rows_per_state + 2;
        pub const rows_per_slot = W.row_count * rows_per_state;
        pub const Row = [main_columns]M;
        pub const Fixed = [fixed_columns]M;
        pub const active_a = fixed_columns - 2;
        pub const active_b = fixed_columns - 1;
        pub fn fixed(logical: usize, calls: usize) !Fixed {
            if (calls > A.geometry.maximum_calls) return error.InvalidTiledKeccakCensus;
            const slots = (calls + 1) / 2;
            var result: Fixed = @splat(M.zero());
            if (logical >= slots * rows_per_slot) return result;
            const slot = logical / rows_per_slot;
            const local = logical % rows_per_slot;
            result[local / rows_per_state] = M.one();
            result[W.row_count + local % rows_per_state] = M.one();
            result[active_a] = M.one();
            result[active_b] = M.fromCanonical(@intFromBool(slot * 2 + 1 < calls));
            return result;
        }
        fn c(comptime S: type, value: u32) S {
            return if (S == M) M.fromCanonical(value) else S.fromBase(M.fromCanonical(value));
        }
        fn readState(comptime S: type, view: anytype, anchor: usize, x: usize, y: usize, z: usize) !S {
            const lane = A.laneIndex(x, y);
            return view.read(@as(i32, @intCast(lane / lanes)) - @as(i32, @intCast(anchor)), (lane % lanes) * A.lane_bits + z);
        }
        fn readParity(comptime S: type, view: anytype, anchor: usize, x: usize, z: usize) !S {
            const position = x * A.lane_bits + z;
            return view.read(@as(i32, @intCast(position / parity_width)) - @as(i32, @intCast(anchor)), parity + position % parity_width);
        }
        fn theta(comptime S: type, view: anytype, anchor: usize, x: usize, y: usize, z: usize) !S {
            return (try readState(S, view, anchor, x, y, z)).add(try readParity(S, view, anchor, (x + 4) % 5, z)).add(try readParity(S, view, anchor, (x + 1) % 5, (z + 63) % 64));
        }
        /// A packed_value input is a field-linear map of original compact tuples.
        /// Membership in the exact packed_value table image supplies the input bounds.
        pub fn inputs(comptime S: type, view: anytype, selectors: []const S) !struct { chi: [chi_width]S, xor: [parity_width]S } {
            if (selectors.len != fixed_columns) return error.InvalidTiledKeccakFixed;
            var result = .{ .chi = @as([chi_width]S, @splat(S.zero())), .xor = @as([parity_width]S, @splat(S.zero())) };
            for (0..rows_per_state) |anchor| {
                const selected = selectors[W.row_count + anchor];
                for (0..chi_width) |local| {
                    if (full_chi and (anchor * lanes) % 5 != 0) continue;
                    const lane = anchor * lanes + local / A.lane_bits;
                    const x = lane % 5;
                    const y = lane / 5;
                    const z = local % A.lane_bits;
                    var packed_value = S.zero();
                    var power: u32 = 1;
                    for (0..if (full_chi) @as(usize, 5) else @as(usize, 3)) |offset| {
                        const output_x = (x + offset) % 5;
                        const source_x = (output_x + 3 * y) % 5;
                        const source_y = output_x;
                        const source_z = (z + A.lane_bits - A.rho_offsets[source_x][source_y]) % A.lane_bits;
                        packed_value = packed_value.add((try theta(S, view, anchor, source_x, source_y, source_z)).mul(c(S, power)));
                        power *= 28;
                    }
                    result.chi[local] = result.chi[local].add(selected.mul(packed_value));
                }
                for (0..parity_width) |local| {
                    const position = anchor * parity_width + local;
                    if (position >= A.geometry.parity_positions) continue;
                    const x = position / A.lane_bits;
                    const z = position % A.lane_bits;
                    var packed_value = S.zero();
                    var power: u32 = 1;
                    for (0..5) |y| {
                        packed_value = packed_value.add((try readState(S, view, anchor, x, y, z)).mul(c(S, power)));
                        if (!full_xor) power *= 16;
                    }
                    result.xor[local] = result.xor[local].add(selected.mul(packed_value));
                }
            }
            return .{ .chi = result.chi, .xor = result.xor };
        }
        fn roundConstant(comptime S: type, selectors: []const S, local: usize) S {
            var iota = S.zero();
            if (local / A.lane_bits == 0) for (0..A.round_count) |r| {
                if (((A.round_constants[r] >> @intCast(local % A.lane_bits)) & 1) != 0)
                    iota = iota.add(selectors[2 + r].mul(selectors[W.row_count]));
            };
            return iota;
        }
        /// Fixed selectors must come from fixed(), not a prover-supplied frame.
        /// Sink receives all direct equations and exactly one typed private
        /// lookup per output bit/parity position (including zero-weight padding).
        pub fn evaluate(comptime S: type, view: anytype, selectors: []const S, sink: anytype) !void {
            if (selectors.len != fixed_columns) return error.InvalidTiledKeccakFixed;
            const expected = try inputs(S, view, selectors);
            var round = S.zero();
            for (selectors[2..26]) |selected| round = round.add(selected);
            const active = selectors[active_a];
            const active_round = round;
            const boundary = selectors[0].add(selectors[1]).add(selectors[27]).add(selectors[28]);
            for (0..state_width) |local| {
                const value = try view.read(0, local);
                try sink.constraint(boundary.mul(value).mul(S.one().sub(value)), 3);
                try sink.constraint(S.one().sub(active).mul(value), 2);
                const inactive_b = S.one().sub(selectors[active_b]);
                try sink.constraint(selectors[1].mul(inactive_b).mul(value), 3);
                try sink.constraint(selectors[2].mul(value.sub(try view.read(-2 * stride, local)).sub((try view.read(-stride, local)).mul(c(S, 8)))), 2);
                try sink.constraint(selectors[26].mul(value.sub(try view.read(stride, local)).sub((try view.read(2 * stride, local)).mul(c(S, 8)))), 2);
            }
            var anchor_selector = S.zero();
            if (full_chi) for (0..rows_per_state) |anchor| {
                if ((anchor * lanes) % 5 == 0) anchor_selector = anchor_selector.add(selectors[W.row_count + anchor]);
            };
            for (0..chi_width) |local| {
                const packed_value = try view.read(0, chi + local);
                const iota = roundConstant(S, selectors, local);
                try sink.constraint(packed_value.sub(active_round.mul(expected.chi[local])).sub(iota.mul(c(S, if (full_chi) A.geometry.chi_span else 28 * 28 * 28))), 3);
                if (full_chi) {
                    var tuple: [6]S = undefined;
                    tuple[0] = packed_value;
                    for (0..5) |x| tuple[1 + x] = try view.read(stride + @as(i32, @intCast(x / lanes)), (x % lanes) * A.lane_bits + local);
                    try sink.chi(tuple, active_round.mul(anchor_selector));
                } else try sink.chi(.{ packed_value, try view.read(stride, local) }, active_round);
            }
            for (0..parity_width) |local| {
                const value = try view.read(0, parity + local);
                const packed_value = try view.read(0, xor + local);
                var present = S.zero();
                for (0..rows_per_state) |anchor| {
                    if (anchor * parity_width + local < A.geometry.parity_positions) present = present.add(selectors[W.row_count + anchor]);
                }
                const selected = active_round.mul(present);
                try sink.constraint(packed_value.sub(active_round.mul(expected.xor[local])), 3);
                try sink.constraint(S.one().sub(selected).mul(value), 3);
                if (!full_xor) try sink.xor(.{ packed_value, value }, selected);
            }
            if (full_xor) for (0..xor_event_columns) |batch| {
                var tuple: [6]S = @splat(S.zero());
                for (0..3) |i| {
                    const position = batch * 3 + i;
                    if (position < parity_width) {
                        tuple[i] = try view.read(0, xor + position);
                        tuple[3 + i] = try view.read(0, parity + position);
                    }
                }
                try sink.xor(tuple, active_round);
            };
        }
        pub const Trace = struct {
            a: std.mem.Allocator,
            rows: []Row,
            calls: usize,
            pub fn deinit(self: *@This()) void {
                self.a.free(self.rows);
                self.* = undefined;
            }
            pub const View = struct {
                trace: *const Trace,
                row: usize,
                pub fn read(self: @This(), offset: i32, column: usize) !M {
                    if (column >= main_columns) return error.InvalidTiledKeccakColumn;
                    const target: usize = @intCast(@mod(@as(i64, @intCast(self.row)) + offset, @as(i64, @intCast(self.trace.rows.len))));
                    return self.trace.rows[target][column];
                }
            };
            pub fn view(self: *const Trace, row: usize) View {
                return .{ .trace = self, .row = row };
            }
        };
        /// Differential fixture adapter, not an accepted witness producer.
        pub fn fromSlots(a: std.mem.Allocator, slots: []const W.Slot, calls: usize) !Trace {
            if (slots.len != (calls + 1) / 2 or calls > A.geometry.maximum_calls) return error.InvalidTiledKeccakCensus;
            const size = try std.math.ceilPowerOfTwo(usize, @max(rows_per_slot, try std.math.mul(usize, slots.len, rows_per_slot)));
            const rows = try a.alloc(Row, size);
            errdefer a.free(rows);
            @memset(rows, @splat(M.zero()));
            var out = Trace{ .a = a, .rows = rows, .calls = calls };
            for (slots, 0..) |slot, index| for (slot.rows, 0..) |wide, group| for (0..rows_per_state) |tile| {
                const row = &rows[index * rows_per_slot + group * rows_per_state + tile];
                for (row[0..state_width], 0..) |*value, bit| value.* = M.fromCanonical(wide.state[tile * state_width + bit]);
                if (group >= 2 and group < 26) for (0..parity_width) |local| {
                    const position = tile * parity_width + local;
                    if (position < A.geometry.parity_positions) row[parity + local] = M.fromCanonical(wide.parity[position]);
                };
            };
            for (rows, 0..) |*row, ordinal| {
                const selectors = try fixed(ordinal, calls);
                const values = try inputs(M, out.view(ordinal), &selectors);
                var round = M.zero();
                for (selectors[2..26]) |selected| round = round.add(selected);
                for (values.chi, row[chi..][0..chi_width], 0..) |value, *target, local| target.* = value.mul(round).add(roundConstant(M, &selectors, local).mul(M.fromCanonical(if (full_chi) A.geometry.chi_span else 28 * 28 * 28)));
                for (values.xor, row[xor..][0..parity_width]) |value, *target| target.* = value.mul(round);
            }
            return out;
        }
    };
}
