//! Shared scalar building blocks for RISC-V opcode semantics.
//!
//! The component evaluator works over `QM31` at both the out-of-domain point
//! and the lifted evaluation domain. Keeping these functions scalar makes the
//! same formulas usable in both paths without an expression-tree adapter.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const access_clock = @import("../../access_clock.zig");

pub fn Ops(comptime S: type) type {
    return struct {
        // Functions, not constants: a scalar constant is only computable once
        // the scalar type can build one, and the recording instantiation builds
        // nodes in an arena that does not exist at container-analysis time.
        // The base-field values themselves stay comptime.
        pub inline fn BYTE_RADIX() S {
            return q(1 << 8);
        }

        pub inline fn WORD_RADIX() S {
            return q(@as(u64, 1) << 32);
        }

        pub inline fn INV_BYTE_RADIX() S {
            return S.fromBase(comptime M31.fromCanonical(1 << 8).invUncheckedNonZero());
        }

        pub inline fn INV_2() S {
            return S.fromBase(comptime M31.fromCanonical(2).invUncheckedNonZero());
        }

        pub inline fn INV_4() S {
            return S.fromBase(comptime M31.fromCanonical(4).invUncheckedNonZero());
        }

        pub inline fn INV_32() S {
            return S.fromBase(comptime M31.fromCanonical(32).invUncheckedNonZero());
        }

        pub fn ConstraintSet(comptime n: usize) type {
            return struct {
                values: [n]S,

                pub fn allZero(self: @This()) bool {
                    for (self.values) |value| {
                        if (!value.isZero()) return false;
                    }
                    return true;
                }
            };
        }

        /// Canonical Stark-V program relation tuple.
        ///
        /// This decoded tuple is deliberately distinct from the current Zig raw-word
        /// program bus. A lookup against a ROM table built by decoding the ELF is the
        /// sound way to bind opcode flags and operands to the fetched instruction.
        pub const ProgramTuple = struct {
            pc: S,
            opcode_id: S,
            rd: S,
            rs1: S,
            operand: S,

            pub fn values(self: @This()) [5]S {
                return .{ self.pc, self.opcode_id, self.rd, self.rs1, self.operand };
            }
        };

        /// One `(lhs byte, rhs byte, result byte, operation id)` lookup request.
        pub const BitwiseTuple = struct {
            lhs: S,
            rhs: S,
            result: S,
            operation_id: S,

            pub fn values(self: @This()) [4]S {
                return .{ self.lhs, self.rhs, self.result, self.operation_id };
            }
        };

        /// One committed register or memory access block.
        pub const Access = struct {
            addr: S,
            previous: [4]S,
            previous_clock: S,
            next: [4]S,
        };

        /// Residuals forcing a read-only access to emit the value it consumed.
        ///
        /// The access chain consumes `previous` and emits `next` as two distinct
        /// committed column groups, and the opcode semantics compute on `next`. Without
        /// these residuals a source operand is a free prover choice that is also
        /// written back to the register or memory cell, so any register-reading
        /// instruction doubles as an arbitrary write. Destination accesses must not use
        /// this: their `next` is pinned by `destinationResultConstraints` instead.
        pub fn readOnlyAccessConstraints(access: Access, enabler: S) [4]S {
            var constraints: [4]S = undefined;
            for (&constraints, access.next, access.previous) |*constraint, next, previous| {
                constraint.* = enabler.mul(next.sub(previous));
            }
            return constraints;
        }

        /// Witness that turns a five-bit architectural destination address into an
        /// exact write-enable without increasing result constraints above degree two.
        ///
        /// `nonzero` is forced to zero for x0 and one for every other register:
        ///
        ///   nonzero * (nonzero - 1) = 0
        ///   addr * (1 - nonzero) = 0
        ///   addr * inverse - nonzero = 0
        ///
        /// The final equation also fixes `inverse` for non-zero addresses.  Its value
        /// is deliberately unconstrained at address zero; the canonical witness uses
        /// zero so padding rows remain all-zero.
        pub const Destination = struct {
            nonzero: S,
            inverse: S,
        };

        pub fn destinationFromColumns(columns: []const S) Destination {
            std.debug.assert(columns.len == 2);
            return .{ .nonzero = columns[0], .inverse = columns[1] };
        }

        pub fn destinationConstraints(addr: S, destination: Destination) [3]S {
            return .{
                bit(destination.nonzero),
                addr.mul(S.one().sub(destination.nonzero)),
                addr.mul(destination.inverse).sub(destination.nonzero),
            };
        }

        pub fn destinationResultConstraints(
            access: Access,
            result: [4]S,
            destination: Destination,
        ) [4]S {
            var constraints: [4]S = undefined;
            for (&constraints, access.next, result) |*constraint, actual, computed| {
                constraint.* = actual.sub(destination.nonzero.mul(computed));
            }
            return constraints;
        }

        /// Canonical Stark-V `memory_access` relation tuple.
        pub const MemoryAccessTuple = struct {
            addr_space: S,
            addr: S,
            clock: S,
            limbs: [4]S,

            pub fn values(self: @This()) [7]S {
                return .{
                    self.addr_space,
                    self.addr,
                    self.clock,
                    self.limbs[0],
                    self.limbs[1],
                    self.limbs[2],
                    self.limbs[3],
                };
            }
        };

        /// The two sides of one access-chain transition. The caller consumes
        /// `previous` with a negative numerator and emits `next` with a positive
        /// numerator, both gated by the component enabler. `clock_gap` is the
        /// shifted sibling `range_check_20` request `next - previous - 1`.
        /// Consequently every enabled transition advances by at least one and
        /// a same-tuple/same-clock self-loop cannot disappear from the relation.
        pub const AccessChain = struct {
            previous: MemoryAccessTuple,
            next: MemoryAccessTuple,
            clock_gap: S,
        };

        pub const RegistersStateTuple = struct {
            pc: S,
            clock: S,

            pub fn values(self: @This()) [2]S {
                return .{ self.pc, self.clock };
            }
        };

        pub const RegistersStateChain = struct {
            previous: RegistersStateTuple,
            next: RegistersStateTuple,
        };

        pub fn registersStateChain(pc: S, clock: S) RegistersStateChain {
            return .{
                .previous = .{ .pc = pc, .clock = clock },
                .next = .{ .pc = pc.add(q(4)), .clock = clock.add(S.one()) },
            };
        }

        pub fn accessClock(instruction_clock: S, ordinal: access_clock.Ordinal) S {
            return instruction_clock.sub(S.one())
                .mul(q(access_clock.STRIDE))
                .add(q(@intFromEnum(ordinal) + 1));
        }

        pub fn registerAccessChain(
            access: Access,
            instruction_clock: S,
            ordinal: access_clock.Ordinal,
        ) AccessChain {
            return accessChain(
                access,
                accessClock(instruction_clock, ordinal),
                S.zero(),
                access.addr,
                access.next,
            );
        }

        pub fn accessChain(
            access: Access,
            current_clock: S,
            addr_space: S,
            addr: S,
            next: [4]S,
        ) AccessChain {
            return .{
                .previous = .{
                    .addr_space = addr_space,
                    .addr = addr,
                    .clock = access.previous_clock,
                    .limbs = access.previous,
                },
                .next = .{
                    .addr_space = addr_space,
                    .addr = addr,
                    .clock = current_clock,
                    .limbs = next,
                },
                .clock_gap = current_clock.sub(access.previous_clock).sub(S.one()),
            };
        }

        pub fn accessFromColumns(columns: []const S) Access {
            std.debug.assert(columns.len == 10);
            return .{
                .addr = columns[0],
                .previous = columns[1..5].*,
                .previous_clock = columns[5],
                .next = columns[6..10].*,
            };
        }

        pub inline fn q(value: u64) S {
            return S.fromBase(M31.fromU64(value));
        }

        pub inline fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        pub inline fn selected(selector: S, value: S) S {
            return selector.mul(value);
        }

        pub fn composeU32(limbs: [4]S) S {
            var value = limbs[3];
            value = value.mul(BYTE_RADIX()).add(limbs[2]);
            value = value.mul(BYTE_RADIX()).add(limbs[1]);
            return value.mul(BYTE_RADIX()).add(limbs[0]);
        }

        /// Constrain a derived base-256 carry to be a bit when `selector == 1`.
        /// Byte-range lookups for every input and output limb are a required sibling
        /// constraint; without them, a field element is not necessarily a byte.
        pub inline fn selectedCarryBit(selector: S, numerator: S) S {
            const carry = numerator.mul(INV_BYTE_RADIX());
            return selected(selector, bit(carry));
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "semantics common: compose little-endian word" {
                    const actual = composeU32(.{ q(0x78), q(0x56), q(0x34), q(0x12) });
                    try std.testing.expect(actual.eql(q(0x12345678)));
                }
            };
        }
    };
}

/// The shipped instantiation.  Every consumer outside the extraction
/// tooling reaches these declarations through this one namespace.
pub const Qm31 = Ops(QM31);

comptime {
    _ = Ops(QM31).selfTests();
}
