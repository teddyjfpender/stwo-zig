//! Signed multiplicity counters for the six preprocessed lookup tables.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../../infra_trace.zig");
const entry = @import("../entry.zig");
const schema = @import("schema.zig");

pub const Error = schema.Error || error{OutOfMemory};

pub const Counter = struct {
    kind: schema.Kind,
    /// Canonical table-row order. Values are signed source numerators modulo M31.
    values: []M31,

    pub fn init(allocator: std.mem.Allocator, kind: schema.Kind) !Counter {
        const values = try allocator.alloc(M31, schema.size(kind));
        @memset(values, M31.zero());
        return .{ .kind = kind, .values = values };
    }

    pub fn deinit(self: *Counter, allocator: std.mem.Allocator) void {
        allocator.free(self.values);
        self.* = undefined;
    }

    pub fn register(self: *Counter, relation_entry: entry.Entry) Error!void {
        if (relation_entry.domain != schema.domain(self.kind)) return error.InvalidRelationDomain;
        if (relation_entry.arity != schema.arity(self.kind)) return error.InvalidArity;
        const numerator = relation_entry.numerator.tryIntoM31() catch return error.NonBaseFieldValue;
        if (numerator.eql(M31.zero())) return;
        const row = try schema.indexSecure(
            self.kind,
            relation_entry.values[0..relation_entry.arity],
        );
        self.values[row] = self.values[row].add(numerator);
    }

    pub fn registerRaw(
        self: *Counter,
        numerator: QM31,
        tuple: []const QM31,
    ) Error!void {
        var relation_entry = entry.Entry{
            .domain = schema.domain(self.kind),
            .numerator = numerator,
            .arity = @intCast(tuple.len),
        };
        if (tuple.len > relation_entry.values.len) return error.InvalidArity;
        @memcpy(relation_entry.values[0..tuple.len], tuple);
        try self.register(relation_entry);
    }

    pub fn registerList(self: *Counter, list: entry.List) Error!void {
        for (list.entries[0..list.len]) |relation_entry| {
            if (relation_entry.domain == schema.domain(self.kind)) try self.register(relation_entry);
        }
    }

    pub fn signedTotal(self: *const Counter) M31 {
        var total = M31.zero();
        for (self.values) |value| total = total.add(value);
        return total;
    }

    /// Commit multiplicities in circle-domain bit-reversed order. The stored
    /// sign is unchanged; the table interaction applies the balancing minus.
    pub fn committedColumn(self: *const Counter, allocator: std.mem.Allocator) ![]M31 {
        const result = try allocator.alloc(M31, self.values.len);
        errdefer allocator.free(result);
        const table = try infra.BitReversalTable.init(allocator, schema.logSize(self.kind));
        defer table.deinit(allocator);
        for (self.values, 0..) |value, row| result[table.map(row)] = value;
        return result;
    }
};

pub const Set = struct {
    counters: [schema.KIND_COUNT]Counter,

    pub fn init(allocator: std.mem.Allocator) !Set {
        var result: Set = undefined;
        var initialized: usize = 0;
        errdefer for (result.counters[0..initialized]) |*counter| counter.deinit(allocator);
        for (&result.counters, 0..) |*counter, index| {
            counter.* = try Counter.init(allocator, @enumFromInt(index));
            initialized += 1;
        }
        return result;
    }

    pub fn deinit(self: *Set, allocator: std.mem.Allocator) void {
        for (&self.counters) |*counter| counter.deinit(allocator);
        self.* = undefined;
    }

    pub fn get(self: *Set, kind: schema.Kind) *Counter {
        return &self.counters[@intFromEnum(kind)];
    }

    pub fn registerList(self: *Set, list: entry.List) Error!void {
        for (list.entries[0..list.len]) |relation_entry| {
            const kind = kindForDomain(relation_entry.domain) orelse continue;
            try self.get(kind).register(relation_entry);
        }
    }

    /// Adds one worker-private counter set in canonical table-row order.
    /// Both sets keep their ownership; callers may release `source` after the
    /// merge.  Generated witness workers use this to avoid synchronization in
    /// their row hot loops.
    pub fn mergeFrom(self: *Set, source: *const Set) void {
        for (&self.counters, &source.counters) |*destination, *input| {
            std.debug.assert(destination.kind == input.kind);
            std.debug.assert(destination.values.len == input.values.len);
            for (destination.values, input.values) |*value, addend| {
                value.* = value.add(addend);
            }
        }
    }
};

pub fn kindForDomain(domain: entry.Domain) ?schema.Kind {
    return switch (domain) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        else => null,
    };
}

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

test "signed counter preserves consumer signs and committed order" {
    const allocator = std.testing.allocator;
    var counter = try Counter.init(allocator, .range_check_8_8);
    defer counter.deinit(allocator);
    try counter.registerRaw(QM31.one().neg(), &.{ q(1), q(2) });
    try counter.registerRaw(QM31.one().neg(), &.{ q(1), q(2) });
    try counter.registerRaw(QM31.one(), &.{ q(1), q(2) });
    const row = try schema.indexSecure(.range_check_8_8, &.{ q(1), q(2) });
    try std.testing.expect(counter.values[row].eql(M31.one().neg()));
    try std.testing.expect(counter.signedTotal().eql(M31.one().neg()));

    const committed = try counter.committedColumn(allocator);
    defer allocator.free(committed);
    const table = try infra.BitReversalTable.init(allocator, schema.logSize(.range_check_8_8));
    defer table.deinit(allocator);
    try std.testing.expect(committed[table.map(row)].eql(M31.one().neg()));
}

test "counter rejects value, result, domain, and extension-field mutations" {
    const allocator = std.testing.allocator;
    var bitwise = try Counter.init(allocator, .bitwise);
    defer bitwise.deinit(allocator);
    try std.testing.expectError(
        error.InvalidTuple,
        bitwise.registerRaw(QM31.one().neg(), &.{ q(7), q(3), q(0), q(2) }),
    );
    try std.testing.expectError(
        error.ValueOutOfRange,
        bitwise.registerRaw(QM31.one().neg(), &.{ q(256), q(3), q(259), q(1) }),
    );
    var wrong = entry.Entry{ .domain = .range_check_20, .numerator = QM31.one().neg(), .arity = 1 };
    wrong.values[0] = q(7);
    try std.testing.expectError(error.InvalidRelationDomain, bitwise.register(wrong));
    try std.testing.expectError(
        error.NonBaseFieldValue,
        bitwise.registerRaw(QM31.fromU32Unchecked(1, 1, 0, 0), &.{ q(1), q(1), q(1), q(0) }),
    );
}

test "counter set registers every lookup domain without semantic branching" {
    const allocator = std.testing.allocator;
    var counters = try Set.init(allocator);
    defer counters.deinit(allocator);
    var list = entry.List{};
    entry.range20(&list, QM31.one().neg(), q(9));
    entry.range811(&list, QM31.one().neg(), .{ q(2), q(3) });
    entry.range884(&list, QM31.one().neg(), .{ q(2), q(3), q(4) });
    entry.range88(&list, QM31.one().neg(), .{ q(2), q(3) });
    entry.rangeM31(&list, QM31.one().neg(), .{ q(2), q(3) });
    entry.bitwise(&list, QM31.one().neg(), .{ .lhs = q(7), .rhs = q(3), .result = q(4), .operation_id = q(2) });
    try counters.registerList(list);
    for (&counters.counters) |*counter| {
        try std.testing.expect(counter.signedTotal().eql(M31.one().neg()));
    }
}
