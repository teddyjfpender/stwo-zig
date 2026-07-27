//! Shared lookup request types for control-flow and upper-immediate families.
//!
//! Numerators preserve the signs and gates from the pinned Stark-V schema so
//! interaction-column integration does not have to reconstruct policy.

const QM31 = @import("stwo_core").fields.qm31.QM31;
const common = @import("common.zig");

pub fn Ops(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);

        pub fn Request(comptime Tuple: type) type {
            return struct {
                numerator: S,
                tuple: Tuple,
            };
        }

        pub const RegisterStateTuple = struct {
            pc: S,
            clock: S,

            pub fn values(self: @This()) [2]S {
                return .{ self.pc, self.clock };
            }
        };

        pub const Range20Tuple = struct {
            value: S,

            pub fn values(self: @This()) [1]S {
                return .{self.value};
            }
        };

        pub const RangePairTuple = struct {
            limb_0: S,
            limb_1: S,

            pub fn values(self: @This()) [2]S {
                return .{ self.limb_0, self.limb_1 };
            }
        };

        pub const RangeTripleTuple = struct {
            limb_0: S,
            limb_1: S,
            limb_2: S,

            pub fn values(self: @This()) [3]S {
                return .{ self.limb_0, self.limb_1, self.limb_2 };
            }
        };

        pub const StateLookups = struct {
            consume: Request(RegisterStateTuple),
            emit: Request(RegisterStateTuple),
        };

        pub fn stateLookups(
            pc: S,
            clock: S,
            next_pc: S,
            enabler: S,
        ) StateLookups {
            return .{
                .consume = .{
                    .numerator = enabler.neg(),
                    .tuple = .{ .pc = pc, .clock = clock },
                },
                .emit = .{
                    .numerator = enabler,
                    .tuple = .{ .pc = next_pc, .clock = clock.add(S.one()) },
                },
            };
        }

        pub const RegisterAccessLookups = struct {
            consume: Request(ops.MemoryAccessTuple),
            emit: Request(ops.MemoryAccessTuple),
            clock_gap: Request(Range20Tuple),
        };

        pub fn registerAccessLookups(
            access: ops.Access,
            row_clock: S,
            enabler: S,
        ) RegisterAccessLookups {
            const chain = ops.registerAccessChain(access, row_clock);
            return .{
                .consume = .{ .numerator = enabler.neg(), .tuple = chain.previous },
                .emit = .{ .numerator = enabler, .tuple = chain.next },
                .clock_gap = .{
                    .numerator = enabler.neg(),
                    .tuple = .{ .value = chain.clock_gap },
                },
            };
        }

        pub fn accessFromColumns(columns: []const S, start: usize) ops.Access {
            return .{
                .addr = columns[start],
                .previous = .{
                    columns[start + 1],
                    columns[start + 2],
                    columns[start + 3],
                    columns[start + 4],
                },
                .previous_clock = columns[start + 5],
                .next = .{
                    columns[start + 6],
                    columns[start + 7],
                    columns[start + 8],
                    columns[start + 9],
                },
            };
        }

        pub fn programRequest(
            enabler: S,
            tuple: ops.ProgramTuple,
        ) Request(ops.ProgramTuple) {
            return .{ .numerator = enabler.neg(), .tuple = tuple };
        }

        pub fn range20Request(enabler: S, value: S) Request(Range20Tuple) {
            return .{ .numerator = enabler.neg(), .tuple = .{ .value = value } };
        }

        pub fn rangePairRequest(
            enabler: S,
            limb_0: S,
            limb_1: S,
        ) Request(RangePairTuple) {
            return .{
                .numerator = enabler.neg(),
                .tuple = .{ .limb_0 = limb_0, .limb_1 = limb_1 },
            };
        }

        /// Family self-tests.  Wrapped in a function so only the shipped
        /// QM31 instantiation below compiles them: their bodies use field
        /// operations (`inv`, `eql`, `tryIntoM31`) that are deliberately
        /// absent from the scalar interface the extraction instantiates.
        fn selfTests() type {
            return struct {
                test "control common: register access preserves signed relation requests" {
                    const std = @import("std");
                    const access = ops.Access{
                        .addr = ops.q(7),
                        .previous = .{ ops.q(1), ops.q(2), ops.q(3), ops.q(4) },
                        .previous_clock = ops.q(11),
                        .next = .{ ops.q(5), ops.q(6), ops.q(7), ops.q(8) },
                    };
                    const requests = registerAccessLookups(access, ops.q(19), S.one());
                    try std.testing.expect(requests.consume.numerator.eql(S.one().neg()));
                    try std.testing.expect(requests.consume.tuple.clock.eql(ops.q(11)));
                    try std.testing.expect(requests.emit.numerator.eql(S.one()));
                    try std.testing.expect(requests.emit.tuple.clock.eql(ops.q(19)));
                    try std.testing.expect(requests.clock_gap.tuple.value.eql(ops.q(8)));
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
