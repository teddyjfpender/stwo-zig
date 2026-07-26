//! Canonical Stark-V relation entries before LogUp batching.

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
    registers_state,
    memory_access,
    program_access,
    merkle,
    poseidon2,
    poseidon2_io,
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

pub const DOMAIN_COUNT: usize = @typeInfo(Domain).@"enum".fields.len;

pub const Error = error{InvalidRelationArity};

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

pub const Entry = struct {
    domain: Domain,
    numerator: QM31,
    values: [MAX_ARITY]QM31 = .{QM31.zero()} ** MAX_ARITY,
    arity: u8,

    pub fn validate(self: Entry) Error!void {
        if (self.arity != expectedArity(self.domain)) return error.InvalidRelationArity;
    }

    pub fn denominator(self: Entry, relations: *const relations_mod.Relations) Error!QM31 {
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
    entries: [MAX_ENTRIES]Entry = undefined,
    len: usize = 0,
    batch_size: usize = 2,

    pub fn append(self: *List, entry: Entry) void {
        std.debug.assert(self.len < self.entries.len);
        self.entries[self.len] = entry;
        self.len += 1;
    }

    pub fn batchCount(self: List) usize {
        return (self.len + self.batch_size - 1) / self.batch_size;
    }

    pub fn pair(self: List, batch: usize, relations: *const relations_mod.Relations) Error!logup.RowPair {
        const first = self.entries[batch * self.batch_size];
        if (self.batch_size == 1 or batch * self.batch_size + 1 == self.len) {
            return logup.RowPair.single(first.numerator, try first.denominator(relations));
        }
        const second = self.entries[batch * self.batch_size + 1];
        return .{
            .n1 = first.numerator,
            .d1 = try first.denominator(relations),
            .n2 = second.numerator,
            .d2 = try second.denominator(relations),
        };
    }
};

const std = @import("std");

pub fn program(list: *List, numerator: QM31, tuple: common.ProgramTuple) void {
    list.append(make(.program_access, numerator, tuple.values()));
}

pub fn state(list: *List, numerator: QM31, tuple: anytype) void {
    list.append(make(.registers_state, numerator, tuple.values()));
}

pub fn memory(list: *List, numerator: QM31, tuple: common.MemoryAccessTuple) void {
    list.append(make(.memory_access, numerator, tuple.values()));
}

pub fn access(list: *List, lookup: anytype) void {
    memory(list, lookup.consume.numerator, lookup.consume.tuple);
    memory(list, lookup.emit.numerator, lookup.emit.tuple);
    range20(list, lookup.clock_gap.numerator, lookup.clock_gap.tuple.value);
}

pub fn accessChain(list: *List, chain: common.AccessChain, enabler: QM31) void {
    memory(list, enabler.neg(), chain.previous);
    memory(list, enabler, chain.next);
    range20(list, enabler.neg(), chain.clock_gap);
}

pub fn stateChain(list: *List, chain: common.RegistersStateChain, enabler: QM31) void {
    state(list, enabler.neg(), chain.previous);
    state(list, enabler, chain.next);
}

pub fn stateRequests(list: *List, requests: control.StateLookups) void {
    state(list, requests.consume.numerator, requests.consume.tuple);
    state(list, requests.emit.numerator, requests.emit.tuple);
}

pub fn bitwise(list: *List, numerator: QM31, tuple: common.BitwiseTuple) void {
    list.append(make(.bitwise, numerator, tuple.values()));
}

pub fn range20(list: *List, numerator: QM31, value: QM31) void {
    list.append(make(.range_check_20, numerator, .{value}));
}

pub fn range811(list: *List, numerator: QM31, values: [2]QM31) void {
    list.append(make(.range_check_8_11, numerator, values));
}

pub fn range884(list: *List, numerator: QM31, values: [3]QM31) void {
    list.append(make(.range_check_8_8_4, numerator, values));
}

pub fn range88(list: *List, numerator: QM31, values: [2]QM31) void {
    list.append(make(.range_check_8_8, numerator, values));
}

pub fn rangeM31(list: *List, numerator: QM31, values: [2]QM31) void {
    list.append(make(.range_check_m31, numerator, values));
}

fn make(domain: Domain, numerator: QM31, input: anytype) Entry {
    const arity = input.len;
    var result = Entry{ .domain = domain, .numerator = numerator, .arity = @intCast(arity) };
    inline for (input, 0..) |value, index| result.values[index] = value;
    return result;
}

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
