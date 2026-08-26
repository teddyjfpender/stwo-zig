//! Append-only scalar expression arena over authenticated row-window samples.
//!
//! The logical AIR V1 expression union is frozen into existing manifests. This
//! separate V2 arena lets physical composition name shifted committed columns
//! without silently changing those bytes. Every value is an M31 scalar; the
//! row-window compiler later binds each shifted ID to a typed owner, physical
//! column, offset, boundary rule, and PCS mask point.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const expr = @import("expr.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const FORMAT_ID = "stwo.typed-air.window-expression-v2";
pub const FORMAT_VERSION: u16 = 2;
pub const Degree = u32;

pub const Error = std.mem.Allocator.Error ||
    types.IdError ||
    source.SpanError ||
    error{
        DegreeOverflow,
        InvalidInternIndex,
        InvalidOperandOrder,
        NonCanonicalConstant,
        UnknownSource,
        UnknownValue,
    };

pub const Arena = struct {
    allocator: std.mem.Allocator,
    /// Source IDs below this bound belong to the surrounding logical arena.
    /// Zero admits generated spans only.
    source_limit: usize,
    nodes: std.ArrayList(expr.WindowNode),
    interned_nodes: expr.WindowMap,

    pub fn init(allocator: std.mem.Allocator, source_limit: usize) Arena {
        return .{
            .allocator = allocator,
            .source_limit = source_limit,
            .nodes = .empty,
            .interned_nodes = expr.WindowMap.init(allocator),
        };
    }

    pub fn deinit(self: *Arena) void {
        self.interned_nodes.deinit();
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn node(
        self: *const Arena,
        id: types.WindowValueId,
    ) ?expr.WindowNode {
        const index = types.idIndex(id);
        if (index >= self.nodes.items.len) return null;
        return self.nodes.items[index];
    }

    pub fn nodesView(self: *const Arena) []const expr.WindowNode {
        return self.nodes.items;
    }

    pub fn constantField(
        self: *Arena,
        canonical: u32,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        if (canonical >= m31.Modulus) return error.NonCanonicalConstant;
        return self.internNode(.{ .op = .{ .constant = canonical } }, span);
    }

    pub fn shiftedColumn(
        self: *Arena,
        column: types.ShiftedColumnId,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        return self.internNode(.{ .op = .{ .shifted_column = column } }, span);
    }

    pub fn add(
        self: *Arena,
        lhs: types.WindowValueId,
        rhs: types.WindowValueId,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        return self.binary(.add, lhs, rhs, span);
    }

    pub fn sub(
        self: *Arena,
        lhs: types.WindowValueId,
        rhs: types.WindowValueId,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        return self.binary(.sub, lhs, rhs, span);
    }

    pub fn mul(
        self: *Arena,
        lhs: types.WindowValueId,
        rhs: types.WindowValueId,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        return self.binary(.mul, lhs, rhs, span);
    }

    pub fn neg(
        self: *Arena,
        value: types.WindowValueId,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        if (self.node(value) == null) return error.UnknownValue;
        return self.internNode(.{ .op = .{ .neg = value } }, span);
    }

    /// Rechecks topology, canonical constants, source custody, and the
    /// structural-intern table without allocating.
    pub fn validate(self: *const Arena) Error!void {
        if (self.interned_nodes.count() != self.nodes.items.len)
            return error.InvalidInternIndex;
        for (self.nodes.items, 0..) |node_value, index| {
            try self.validateSpan(node_value.primary_source);
            const expected = try types.idFromIndex(types.WindowValueId, index);
            if (self.interned_nodes.get(node_value.key) != expected)
                return error.InvalidInternIndex;
            switch (node_value.key.op) {
                .constant => |value| if (value >= m31.Modulus)
                    return error.NonCanonicalConstant,
                .shifted_column => {},
                .add, .sub, .mul => |binary_value| {
                    if (types.idIndex(binary_value.lhs) >= index or
                        types.idIndex(binary_value.rhs) >= index)
                    {
                        return error.InvalidOperandOrder;
                    }
                },
                .neg => |value| if (types.idIndex(value) >= index)
                    return error.InvalidOperandOrder,
            }
        }
    }

    fn binary(
        self: *Arena,
        comptime tag: std.meta.Tag(expr.WindowOp),
        lhs: types.WindowValueId,
        rhs: types.WindowValueId,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        if (self.node(lhs) == null or self.node(rhs) == null)
            return error.UnknownValue;
        const binary_value = expr.WindowBinary{ .lhs = lhs, .rhs = rhs };
        const op = switch (tag) {
            .add => expr.WindowOp{ .add = binary_value },
            .sub => expr.WindowOp{ .sub = binary_value },
            .mul => expr.WindowOp{ .mul = binary_value },
            else => unreachable,
        };
        return self.internNode(.{ .op = op }, span);
    }

    fn internNode(
        self: *Arena,
        key: expr.WindowKey,
        span: source.SourceSpan,
    ) Error!types.WindowValueId {
        try self.validateSpan(span);
        if (self.interned_nodes.get(key)) |existing| return existing;
        const id = try types.idFromIndex(types.WindowValueId, self.nodes.items.len);
        try self.nodes.append(self.allocator, .{
            .key = key,
            .primary_source = span,
        });
        errdefer _ = self.nodes.pop();
        try self.interned_nodes.put(key, id);
        return id;
    }

    fn validateSpan(
        self: *const Arena,
        span: source.SourceSpan,
    ) Error!void {
        try span.validate();
        if (span.source) |source_id| {
            if (types.idIndex(source_id) >= self.source_limit)
                return error.UnknownSource;
        }
    }
};

pub const DegreeAnalysis = struct {
    allocator: std.mem.Allocator,
    values: []Degree,
    maximum: Degree,

    pub fn deinit(self: *DegreeAnalysis) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn value(
        self: *const DegreeAnalysis,
        id: types.WindowValueId,
    ) ?Degree {
        const index = types.idIndex(id);
        if (index >= self.values.len) return null;
        return self.values[index];
    }
};

pub fn analyzeDegrees(
    allocator: std.mem.Allocator,
    arena: *const Arena,
) Error!DegreeAnalysis {
    try arena.validate();
    const values = try allocator.alloc(Degree, arena.nodesView().len);
    errdefer allocator.free(values);
    const maximum = try fillDegrees(arena, values);
    return .{ .allocator = allocator, .values = values, .maximum = maximum };
}

/// Allocation-free degree replay into caller-owned storage.
pub fn fillDegrees(
    arena: *const Arena,
    values: []Degree,
) Error!Degree {
    try arena.validate();
    if (values.len != arena.nodesView().len) return error.UnknownValue;
    var maximum: Degree = 0;
    for (arena.nodesView(), 0..) |node_value, index| {
        values[index] = switch (node_value.key.op) {
            .constant => 0,
            .shifted_column => 1,
            .add, .sub => |binary_value| @max(
                values[types.idIndex(binary_value.lhs)],
                values[types.idIndex(binary_value.rhs)],
            ),
            .mul => |binary_value| std.math.add(
                Degree,
                values[types.idIndex(binary_value.lhs)],
                values[types.idIndex(binary_value.rhs)],
            ) catch return error.DegreeOverflow,
            .neg => |value| values[types.idIndex(value)],
        };
        maximum = @max(maximum, values[index]);
    }
    return maximum;
}
