//! Polynomial expression nodes and legacy lookup-program ownership.
//! Typed base/lookup polynomial programs and backend capability contracts.

const std = @import("std");

pub const BasePolynomialOp = enum(u8) { constant, column, add, sub, mul, neg };

pub const BasePolynomialNode = struct {
    op: BasePolynomialOp,
    lhs: u32 = 0,
    rhs: u32 = 0,
    value: u32 = 0,
};

pub const OwnedBasePolynomialProgram = struct {
    allocator: std.mem.Allocator,
    nodes: []BasePolynomialNode,
    roots: []u32,
    column_count: usize,

    pub fn deinit(self: *OwnedBasePolynomialProgram) void {
        self.allocator.free(self.roots);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn validate(self: OwnedBasePolynomialProgram) !void {
        if (self.column_count == 0 or self.nodes.len == 0 or self.roots.len == 0)
            return error.InvalidBasePolynomialProgram;
        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => {},
            .column => if (node.value >= self.column_count)
                return error.InvalidBasePolynomialProgram,
            .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index)
                return error.InvalidBasePolynomialProgram,
            .neg => if (node.lhs >= index)
                return error.InvalidBasePolynomialProgram,
        };
        for (self.roots) |root| if (root >= self.nodes.len)
            return error.InvalidBasePolynomialProgram;
    }
};

/// A committed base-polynomial component that a backend may evaluate from the
/// proof's own residency handles. The selector is the final program input;
/// preceding inputs are the contiguous main-column block. The exporter is
/// invoked only during proving and must derive its program from the production
/// evaluator rather than maintain an independent constraint transcription.
pub const BasePolynomialCapabilityV1 = struct {
    program_id: u64,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedBasePolynomialProgram,
};

pub const MAX_LOOKUP_POLYNOMIAL_ARITY: usize = 32;

pub const LookupPolynomialEntry = struct {
    numerator: u32,
    values: [MAX_LOOKUP_POLYNOMIAL_ARITY]u32 = undefined,
    arity: u8,
};

pub const OwnedLookupPolynomialProgram = struct {
    allocator: std.mem.Allocator,
    nodes: []BasePolynomialNode,
    entries: []LookupPolynomialEntry,
    column_count: usize,
    batch_size: usize,

    pub fn deinit(self: *OwnedLookupPolynomialProgram) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn batchCount(self: OwnedLookupPolynomialProgram) usize {
        return (self.entries.len + self.batch_size - 1) / self.batch_size;
    }

    pub fn parameterCount(self: OwnedLookupPolynomialProgram) usize {
        var count = self.batchCount();
        for (self.entries) |entry| count += 1 + entry.arity;
        return count;
    }

    pub fn validate(self: OwnedLookupPolynomialProgram) !void {
        if (self.column_count == 0 or self.nodes.len == 0 or
            self.entries.len == 0 or (self.batch_size != 1 and self.batch_size != 2))
            return error.InvalidLookupPolynomialProgram;
        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => {},
            .column => if (node.value >= self.column_count)
                return error.InvalidLookupPolynomialProgram,
            .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index)
                return error.InvalidLookupPolynomialProgram,
            .neg => if (node.lhs >= index)
                return error.InvalidLookupPolynomialProgram,
        };
        for (self.entries) |entry| {
            if (entry.arity == 0 or entry.arity > MAX_LOOKUP_POLYNOMIAL_ARITY or
                entry.numerator >= self.nodes.len)
                return error.InvalidLookupPolynomialProgram;
            for (entry.values[0..entry.arity]) |value| if (value >= self.nodes.len)
                return error.InvalidLookupPolynomialProgram;
        }
    }
};
