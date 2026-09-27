//! Shared exact 55-equation integer access AIR, field-parametric.
//! Legacy witness construction stays in integer_bridge_v2; this kernel reads
//! the same committed columns at arbitrary OODS points and symbolic inputs.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const source = @import("block_execution_access_bridge_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
pub const COLUMN_COUNT: usize = 48;
pub const RESIDUAL_COUNT: usize = 55;
pub fn Algebra(comptime S: type) type {
    return struct {
        pub const Witness = struct {
            word_index: [4]S,
            byte_address: [4]S,
            local_clock: [4]S,
            global_clock: [8]S,
            address_carry: [5]S,
            clock_carry: [9]S,
            word_high_bits: [6]S,
            clock_high_bits: [3]S,
            register_bits: [5]S,

            pub fn zero() Witness {
                return .{
                    .word_index = @splat(S.zero()),
                    .byte_address = @splat(S.zero()),
                    .local_clock = @splat(S.zero()),
                    .global_clock = @splat(S.zero()),
                    .address_carry = @splat(S.zero()),
                    .clock_carry = @splat(S.zero()),
                    .word_high_bits = @splat(S.zero()),
                    .clock_high_bits = @splat(S.zero()),
                    .register_bits = @splat(S.zero()),
                };
            }

            pub fn columns(self: Witness) [COLUMN_COUNT]S {
                var result: [COLUMN_COUNT]S = undefined;
                var cursor: usize = 0;
                inline for (.{ self.word_index, self.byte_address, self.local_clock, self.global_clock, self.address_carry, self.clock_carry, self.word_high_bits, self.clock_high_bits, self.register_bits }) |part| {
                    @memcpy(result[cursor..][0..part.len], &part);
                    cursor += part.len;
                }
                std.debug.assert(cursor == COLUMN_COUNT);
                return result;
            }

            pub fn fromColumns(values: [COLUMN_COUNT]S) Witness {
                var result = zero();
                var cursor: usize = 0;
                inline for (.{ &result.word_index, &result.byte_address, &result.local_clock, &result.global_clock, &result.address_carry, &result.clock_carry, &result.word_high_bits, &result.clock_high_bits, &result.register_bits }) |part| {
                    @memcpy(part, values[cursor..][0..part.len]);
                    cursor += part.len;
                }
                std.debug.assert(cursor == COLUMN_COUNT);
                return result;
            }
        };

        pub fn transitionAtPoint(pair: source.Pair(S), witness: Witness) [bus.TRANSITION_ARITY]S {
            var tuple: [bus.TRANSITION_ARITY]S = undefined;
            tuple[0] = pair.space;
            @memcpy(tuple[1..5], &witness.byte_address);
            @memcpy(tuple[5..13], &witness.global_clock);
            @memcpy(tuple[13..17], &pair.before);
            @memcpy(tuple[17..21], &pair.after);
            return tuple;
        }

        pub const Residuals = struct {
            values: [64]S = undefined,
            len: usize = 0,
            fn add(self: *Residuals, value: S) void {
                std.debug.assert(self.len < self.values.len);
                self.values[self.len] = value;
                self.len += 1;
            }
        };

        pub fn constraints(pair: source.Pair(S), witness: Witness, base_clock_bytes: [8]S) Residuals {
            const active = pair.active;
            const space = pair.space;
            const multiplier = if (pair.address_unit == .word_index)
                S.one().add(q(3).mul(space))
            else
                S.one();
            var out = Residuals{};
            out.add(active.mul(active.sub(S.one())));
            out.add(active.mul(space).mul(space.sub(S.one())));
            for (pair.pair_residuals) |residual| out.add(residual);
            for (witness.word_high_bits) |bit| out.add(active.mul(bit).mul(bit.sub(S.one())));
            for (witness.clock_high_bits) |bit| out.add(active.mul(bit).mul(bit.sub(S.one())));
            for (witness.register_bits) |bit| out.add(active.mul(S.one().sub(space)).mul(bit).mul(bit.sub(S.one())));
            out.add(active.mul(witness.word_index[3].sub(bitsValue(&witness.word_high_bits))));
            out.add(active.mul(witness.local_clock[3].sub(bitsValue(&witness.clock_high_bits))));
            out.add(active.mul(S.one().sub(space)).mul(witness.word_index[0].sub(bitsValue(&witness.register_bits))));
            for (witness.word_index[1..]) |byte_value| out.add(active.mul(S.one().sub(space)).mul(byte_value));
            out.add(active.mul(pair.source_address.sub(packBytes(&witness.word_index))));
            out.add(active.mul(pair.local_clock.sub(packBytes(&witness.local_clock))));
            out.add(active.mul(witness.address_carry[0]));
            out.add(active.mul(witness.address_carry[4]));
            for (0..4) |i| {
                const carry = witness.address_carry[i + 1];
                // A base-256 multiplication by at most four has carries in 0..3.
                out.add(active.mul(carry).mul(carry.sub(q(1))).mul(carry.sub(q(2))).mul(carry.sub(q(3))));
                out.add(active.mul(multiplier.mul(witness.word_index[i])
                    .add(witness.address_carry[i])
                    .sub(witness.byte_address[i])
                    .sub(q(256).mul(carry))));
            }
            out.add(active.mul(witness.clock_carry[0]));
            out.add(active.mul(witness.clock_carry[8]));
            for (0..8) |i| {
                const carry = witness.clock_carry[i + 1];
                out.add(active.mul(carry).mul(carry.sub(S.one())));
                const local = if (i < 4) witness.local_clock[i] else S.zero();
                out.add(active.mul(base_clock_bytes[i].add(local)
                    .add(witness.clock_carry[i])
                    .sub(witness.global_clock[i])
                    .sub(q(256).mul(carry))));
            }
            return out;
        }

        fn packBytes(bytes: *const [4]S) S {
            var value = S.zero();
            for (bytes, 0..) |byte_value, i| value = value.add(q(@as(u32, 1) << @intCast(i * 8)).mul(byte_value));
            return value;
        }

        fn bitsValue(bits: anytype) S {
            var value = S.zero();
            for (bits, 0..) |bit, i| value = value.add(q(@as(u32, 1) << @intCast(i)).mul(bit));
            return value;
        }

        fn q(value: u32) S {
            return S.fromBase(M.fromCanonical(value));
        }
    };
}
pub fn clockBytes(comptime S: type, value: u64) [8]S {
    var result: [8]S = undefined;
    for (&result, 0..) |*out, i| out.* = S.fromBase(M.fromCanonical(@as(u8, @truncate(value >> @intCast(8 * i)))));
    return result;
}
