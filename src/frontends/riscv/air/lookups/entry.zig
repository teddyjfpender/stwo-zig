//! Canonical Stark-V relation entries before LogUp batching.
//!
//! The entry builders are generic over the scalar type for the same reason the
//! semantics are: `Builder(Symbolic)` replays the shipped request sequence into
//! the SMT model instead of a second, drift-prone transcription of it. Only
//! `denominator`/`pair` are QM31-bound, because only they touch the challenge
//! tower; they are analysed lazily and never reached from a symbolic replay.

const QM31 = @import("stwo_core").fields.qm31.QM31;
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const common = @import("../semantics/common.zig");
const control = @import("../semantics/control_common.zig");

pub const MAX_ARITY: usize = 32;
pub const MAX_ENTRIES: usize = 25;
pub const MAX_BATCHES: usize = 25;

/// Relation order is transcript order and must stay aligned with
/// `relation_challenges.Relations.fromDraws`.
pub const Domain = enum(u8) {
    registers_state = 0,
    memory_access = 1,
    program_access = 2,
    merkle = 3,
    poseidon2 = 4,
    poseidon2_io = 5,
    bitwise = 6,
    range_check_20 = 7,
    range_check_8_11 = 8,
    range_check_8_8_4 = 9,
    range_check_8_8 = 10,
    range_check_m31 = 11,
};

pub const DOMAIN_COUNT: usize = @typeInfo(Domain).@"enum".fields.len;

pub const Error = error{InvalidRelationArity};

/// Semantic role of one ordered lookup event.
///
/// This is construction metadata, not part of the LogUp denominator.  Keeping
/// it beside the exact production entry lets formal export distinguish bus
/// consumption from emission without inferring roles from adjacent domains.
pub const EventRole = enum(u8) {
    request = 0,
    consume = 1,
    emit = 2,
};

pub fn expectedArity(domain: Domain) u8 {
    return switch (domain) {
        .registers_state, .range_check_8_11, .range_check_8_8, .range_check_m31 => 2,
        .memory_access => 7,
        .program_access => 5,
        .merkle, .bitwise => 4,
        .poseidon2 => 16,
        .poseidon2_io => 32,
        .range_check_20 => 1,
        .range_check_8_8_4 => 3,
    };
}

pub fn Builder(comptime S: type) type {
    return struct {
        // Inner references are `Self`-qualified: the file re-exports these same
        // names for the shipped QM31 instantiation, and an unqualified name that
        // resolves both inside and outside the generic is a compile error.
        const Self = @This();
        const ops = common.Ops(S);
        const ctl = control.Ops(S);

        pub const Entry = struct {
            domain: Domain,
            numerator: S,
            // No default: a scalar zero is not computable when the container
            // is analysed (the recording scalar needs a live arena). Every
            // producer fills `values[0..arity]` immediately after construction.
            values: [MAX_ARITY]S = undefined,
            arity: u8,
            role: EventRole = .request,
            /// One-based architectural access group. Only memory consume/emit
            /// events and their range-check-20 clock-gap request carry it.
            access_ordinal: ?u8 = null,

            pub fn validate(self: *const @This()) Error!void {
                if (self.arity != expectedArity(self.domain)) return error.InvalidRelationArity;
            }

            pub fn denominator(self: *const @This(), relations: *const relations_mod.Relations) Error!QM31 {
                try self.validate();
                return switch (self.domain) {
                    .registers_state => relations.registers_state.combineSecure(self.values[0..2].*),
                    .memory_access => relations.memory_access.combineSecure(self.values[0..7].*),
                    .program_access => relations.program_access.combineSecure(self.values[0..5].*),
                    .merkle => relations.merkle.combineSecure(self.values[0..4].*),
                    .poseidon2 => relations.poseidon2.combineSecure(self.values[0..16].*),
                    .poseidon2_io => relations.poseidon2_io.combineSecure(self.values[0..32].*),
                    .bitwise => relations.bitwise.combineSecure(self.values[0..4].*),
                    .range_check_20 => relations.range_check_20.combineSecure(self.values[0..1].*),
                    .range_check_8_11 => relations.range_check_8_11.combineSecure(self.values[0..2].*),
                    .range_check_8_8_4 => relations.range_check_8_8_4.combineSecure(self.values[0..3].*),
                    .range_check_8_8 => relations.range_check_8_8.combineSecure(self.values[0..2].*),
                    .range_check_m31 => relations.range_check_m31.combineSecure(self.values[0..2].*),
                };
            }
        };

        pub const List = struct {
            entries: [MAX_ENTRIES]Self.Entry = undefined,
            len: usize = 0,
            batch_size: usize = 2,

            pub fn append(self: *@This(), entry: Self.Entry) void {
                std.debug.assert(self.len < self.entries.len);
                self.entries[self.len] = entry;
                self.len += 1;
            }

            pub fn batchCount(self: *const @This()) usize {
                return (self.len + self.batch_size - 1) / self.batch_size;
            }

            pub fn pair(self: *const @This(), batch: usize, relations: *const relations_mod.Relations) Error!logup.RowPair {
                const first = &self.entries[batch * self.batch_size];
                if (self.batch_size == 1 or batch * self.batch_size + 1 == self.len) {
                    return logup.RowPair.single(first.numerator, try first.denominator(relations));
                }
                const second = &self.entries[batch * self.batch_size + 1];
                return .{
                    .n1 = first.numerator,
                    .d1 = try first.denominator(relations),
                    .n2 = second.numerator,
                    .d2 = try second.denominator(relations),
                };
            }
        };

        pub fn program(list: *Self.List, numerator: S, tuple: ops.ProgramTuple) void {
            list.append(make(.program_access, numerator, tuple.values(), .request, null));
        }

        pub fn state(list: *Self.List, numerator: S, tuple: anytype) void {
            list.append(make(.registers_state, numerator, tuple.values(), .request, null));
        }

        pub fn memory(list: *Self.List, numerator: S, tuple: ops.MemoryAccessTuple) void {
            list.append(make(.memory_access, numerator, tuple.values(), .request, null));
        }

        pub fn stateEvent(
            list: *Self.List,
            role: EventRole,
            numerator: S,
            tuple: anytype,
        ) void {
            list.append(make(.registers_state, numerator, tuple.values(), role, null));
        }

        pub fn memoryEvent(
            list: *Self.List,
            role: EventRole,
            numerator: S,
            tuple: ops.MemoryAccessTuple,
        ) void {
            list.append(make(.memory_access, numerator, tuple.values(), role, null));
        }

        pub fn memoryEventAt(
            list: *Self.List,
            role: EventRole,
            access_ordinal: u8,
            numerator: S,
            tuple: ops.MemoryAccessTuple,
        ) void {
            list.append(make(
                .memory_access,
                numerator,
                tuple.values(),
                role,
                access_ordinal,
            ));
        }

        pub fn access(list: *Self.List, lookup: anytype) void {
            Self.memoryEvent(list, .consume, lookup.consume.numerator, lookup.consume.tuple);
            Self.memoryEvent(list, .emit, lookup.emit.numerator, lookup.emit.tuple);
            Self.range20(list, lookup.clock_gap.numerator, lookup.clock_gap.tuple.value);
        }

        pub fn accessAt(list: *Self.List, lookup: anytype, access_ordinal: u8) void {
            Self.memoryEventAt(
                list,
                .consume,
                access_ordinal,
                lookup.consume.numerator,
                lookup.consume.tuple,
            );
            Self.memoryEventAt(
                list,
                .emit,
                access_ordinal,
                lookup.emit.numerator,
                lookup.emit.tuple,
            );
            Self.range20At(
                list,
                access_ordinal,
                lookup.clock_gap.numerator,
                lookup.clock_gap.tuple.value,
            );
        }

        pub fn accessChain(list: *Self.List, chain: ops.AccessChain, enabler: S) void {
            Self.memoryEvent(list, .consume, enabler.neg(), chain.previous);
            Self.memoryEvent(list, .emit, enabler, chain.next);
            Self.range20(list, enabler.neg(), chain.clock_gap);
        }

        pub fn accessChainAt(
            list: *Self.List,
            chain: ops.AccessChain,
            enabler: S,
            access_ordinal: u8,
        ) void {
            Self.memoryEventAt(list, .consume, access_ordinal, enabler.neg(), chain.previous);
            Self.memoryEventAt(list, .emit, access_ordinal, enabler, chain.next);
            Self.range20At(list, access_ordinal, enabler.neg(), chain.clock_gap);
        }

        pub fn stateChain(list: *Self.List, chain: ops.RegistersStateChain, enabler: S) void {
            Self.stateEvent(list, .consume, enabler.neg(), chain.previous);
            Self.stateEvent(list, .emit, enabler, chain.next);
        }

        pub fn stateRequests(list: *Self.List, requests: ctl.StateLookups) void {
            Self.stateEvent(list, .consume, requests.consume.numerator, requests.consume.tuple);
            Self.stateEvent(list, .emit, requests.emit.numerator, requests.emit.tuple);
        }

        pub fn bitwise(list: *Self.List, numerator: S, tuple: ops.BitwiseTuple) void {
            list.append(make(.bitwise, numerator, tuple.values(), .request, null));
        }

        pub fn range20(list: *Self.List, numerator: S, value: S) void {
            list.append(make(.range_check_20, numerator, .{value}, .request, null));
        }

        pub fn range20At(
            list: *Self.List,
            access_ordinal: u8,
            numerator: S,
            value: S,
        ) void {
            list.append(make(
                .range_check_20,
                numerator,
                .{value},
                .request,
                access_ordinal,
            ));
        }

        pub fn range811(list: *Self.List, numerator: S, values: [2]S) void {
            list.append(make(.range_check_8_11, numerator, values, .request, null));
        }

        pub fn range884(list: *Self.List, numerator: S, values: [3]S) void {
            list.append(make(.range_check_8_8_4, numerator, values, .request, null));
        }

        pub fn range88(list: *Self.List, numerator: S, values: [2]S) void {
            list.append(make(.range_check_8_8, numerator, values, .request, null));
        }

        pub fn rangeM31(list: *Self.List, numerator: S, values: [2]S) void {
            list.append(make(.range_check_m31, numerator, values, .request, null));
        }

        fn make(
            domain: Domain,
            numerator: S,
            input: anytype,
            role: EventRole,
            access_ordinal: ?u8,
        ) Self.Entry {
            const arity = input.len;
            var result = Self.Entry{
                .domain = domain,
                .numerator = numerator,
                .arity = @intCast(arity),
                .role = role,
                .access_ordinal = access_ordinal,
            };
            inline for (input, 0..) |value, index| result.values[index] = value;
            return result;
        }
    };
}

const std = @import("std");

const shipped = Builder(QM31);

pub const Entry = shipped.Entry;
pub const List = shipped.List;
pub const program = shipped.program;
pub const state = shipped.state;
pub const memory = shipped.memory;
pub const stateEvent = shipped.stateEvent;
pub const memoryEvent = shipped.memoryEvent;
pub const memoryEventAt = shipped.memoryEventAt;
pub const access = shipped.access;
pub const accessAt = shipped.accessAt;
pub const accessChain = shipped.accessChain;
pub const accessChainAt = shipped.accessChainAt;
pub const stateChain = shipped.stateChain;
pub const stateRequests = shipped.stateRequests;
pub const bitwise = shipped.bitwise;
pub const range20 = shipped.range20;
pub const range20At = shipped.range20At;
pub const range811 = shipped.range811;
pub const range884 = shipped.range884;
pub const range88 = shipped.range88;
pub const rangeM31 = shipped.rangeM31;

test "lookup entry domains retain transcript order" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Domain.registers_state));
    try std.testing.expectEqual(@as(u8, 6), @intFromEnum(Domain.bitwise));
    try std.testing.expectEqual(@as(u8, 11), @intFromEnum(Domain.range_check_m31));
}

test "lookup entry arities cover all twelve relation domains and fail closed" {
    const relations = relations_mod.Relations.dummy();
    for (0..DOMAIN_COUNT) |index| {
        const domain: Domain = @enumFromInt(index);
        var relation_entry = Entry{
            .domain = domain,
            .numerator = QM31.one(),
            .values = .{QM31.zero()} ** MAX_ARITY,
            .arity = expectedArity(domain),
        };
        try relation_entry.validate();
        _ = try relation_entry.denominator(&relations);
        relation_entry.arity -|= 1;
        try std.testing.expectError(error.InvalidRelationArity, relation_entry.validate());
        try std.testing.expectError(
            error.InvalidRelationArity,
            relation_entry.denominator(&relations),
        );
    }
}
