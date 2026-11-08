//! Expression nodes, assignments, and deterministic variable generation.

const std = @import("std");
const m31_mod = @import("../../fields/m31.zig");
const qm31_mod = @import("../../fields/qm31.zig");

const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;

pub const ColumnExpr = struct {
    interaction: usize,
    idx: usize,
    offset: isize,

    pub fn lessThan(_: void, lhs: ColumnExpr, rhs: ColumnExpr) bool {
        if (lhs.interaction != rhs.interaction) return lhs.interaction < rhs.interaction;
        if (lhs.idx != rhs.idx) return lhs.idx < rhs.idx;
        return lhs.offset < rhs.offset;
    }
};

pub const BaseExprNode = union(enum) {
    col: ColumnExpr,
    constant: M31,
    param: []const u8,
    add: struct { lhs: *const BaseExprNode, rhs: *const BaseExprNode },
    sub: struct { lhs: *const BaseExprNode, rhs: *const BaseExprNode },
    mul: struct { lhs: *const BaseExprNode, rhs: *const BaseExprNode },
    neg: *const BaseExprNode,
    inv: *const BaseExprNode,
};

pub const BaseExpr = *const BaseExprNode;

pub const ExtExprNode = union(enum) {
    secure_col: [4]BaseExpr,
    constant: QM31,
    param: []const u8,
    add: struct { lhs: *const ExtExprNode, rhs: *const ExtExprNode },
    sub: struct { lhs: *const ExtExprNode, rhs: *const ExtExprNode },
    mul: struct { lhs: *const ExtExprNode, rhs: *const ExtExprNode },
    neg: *const ExtExprNode,
};

pub const ExtExpr = *const ExtExprNode;

pub const EvalError = error{
    MissingColumn,
    MissingParam,
    MissingExtParam,
    DivisionByZero,
};

pub const DegreeError = error{
    InvalidInverseDegree,
};

pub const Assignment = struct {
    columns: std.AutoHashMap(ColumnExpr, M31),
    params: std.StringHashMap(M31),
    ext_params: std.StringHashMap(QM31),

    pub fn init(allocator: std.mem.Allocator) Assignment {
        return .{
            .columns = std.AutoHashMap(ColumnExpr, M31).init(allocator),
            .params = std.StringHashMap(M31).init(allocator),
            .ext_params = std.StringHashMap(QM31).init(allocator),
        };
    }

    pub fn deinit(self: *Assignment) void {
        self.columns.deinit();
        self.params.deinit();
        self.ext_params.deinit();
        self.* = undefined;
    }

    pub fn setColumn(self: *Assignment, column: ColumnExpr, value: M31) !void {
        try self.columns.put(column, value);
    }

    pub fn setParam(self: *Assignment, name: []const u8, value: M31) !void {
        try self.params.put(name, value);
    }

    pub fn setExtParam(self: *Assignment, name: []const u8, value: QM31) !void {
        try self.ext_params.put(name, value);
    }
};

pub const ExprVariables = struct {
    cols: std.AutoArrayHashMap(ColumnExpr, void),
    params: std.StringArrayHashMap(void),
    ext_params: std.StringArrayHashMap(void),

    pub fn init(allocator: std.mem.Allocator) ExprVariables {
        return .{
            .cols = std.AutoArrayHashMap(ColumnExpr, void).init(allocator),
            .params = std.StringArrayHashMap(void).init(allocator),
            .ext_params = std.StringArrayHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *ExprVariables) void {
        self.cols.deinit();
        self.params.deinit();
        self.ext_params.deinit();
        self.* = undefined;
    }

    pub fn collectBase(self: *ExprVariables, expr: BaseExpr) !void {
        switch (expr.*) {
            .col => |col| try self.addCol(col),
            .constant => {},
            .param => |name| try self.addParam(name),
            .add => |pair| {
                try self.collectBase(pair.lhs);
                try self.collectBase(pair.rhs);
            },
            .sub => |pair| {
                try self.collectBase(pair.lhs);
                try self.collectBase(pair.rhs);
            },
            .mul => |pair| {
                try self.collectBase(pair.lhs);
                try self.collectBase(pair.rhs);
            },
            .neg, .inv => |value| try self.collectBase(value),
        }
    }

    pub fn collectExt(self: *ExprVariables, expr: ExtExpr) !void {
        switch (expr.*) {
            .secure_col => |values| {
                for (values) |value| try self.collectBase(value);
            },
            .constant => {},
            .param => |name| try self.addExtParam(name),
            .add => |pair| {
                try self.collectExt(pair.lhs);
                try self.collectExt(pair.rhs);
            },
            .sub => |pair| {
                try self.collectExt(pair.lhs);
                try self.collectExt(pair.rhs);
            },
            .mul => |pair| {
                try self.collectExt(pair.lhs);
                try self.collectExt(pair.rhs);
            },
            .neg => |value| try self.collectExt(value),
        }
    }

    pub fn randomAssignment(
        self: *const ExprVariables,
        allocator: std.mem.Allocator,
        salt: u64,
    ) !Assignment {
        var assignment = Assignment.init(allocator);
        errdefer assignment.deinit();

        const cols_sorted = try allocator.dupe(ColumnExpr, self.cols.keys());
        defer allocator.free(cols_sorted);
        std.sort.heap(ColumnExpr, cols_sorted, {}, ColumnExpr.lessThan);

        for (cols_sorted) |col| {
            const h = hashColumn(salt, col);
            try assignment.setColumn(col, M31.fromU64(h));
        }

        const params_sorted = try allocator.dupe([]const u8, self.params.keys());
        defer allocator.free(params_sorted);
        std.sort.heap([]const u8, params_sorted, {}, lessString);

        for (params_sorted) |name| {
            try assignment.setParam(name, M31.fromU64(hashName(salt, name, 0)));
        }

        const ext_sorted = try allocator.dupe([]const u8, self.ext_params.keys());
        defer allocator.free(ext_sorted);
        std.sort.heap([]const u8, ext_sorted, {}, lessString);

        for (ext_sorted) |name| {
            const value = QM31.fromM31Array(.{
                M31.fromU64(hashName(salt, name, 1)),
                M31.fromU64(hashName(salt, name, 2)),
                M31.fromU64(hashName(salt, name, 3)),
                M31.fromU64(hashName(salt, name, 4)),
            });
            try assignment.setExtParam(name, value);
        }

        return assignment;
    }

    fn addCol(self: *ExprVariables, col: ColumnExpr) !void {
        try self.cols.put(col, {});
    }

    fn addParam(self: *ExprVariables, name: []const u8) !void {
        try self.params.put(name, {});
    }

    fn addExtParam(self: *ExprVariables, name: []const u8) !void {
        try self.ext_params.put(name, {});
    }
};

fn lessString(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn hashColumn(salt: u64, col: ColumnExpr) u64 {
    var hasher = std.hash.Wyhash.init(salt);

    var interaction: u64 = @intCast(col.interaction);
    var idx: u64 = @intCast(col.idx);
    var offset: i64 = @intCast(col.offset);

    hasher.update(std.mem.asBytes(&interaction));
    hasher.update(std.mem.asBytes(&idx));
    hasher.update(std.mem.asBytes(&offset));
    return hasher.final();
}

fn hashName(salt: u64, name: []const u8, tag: u64) u64 {
    var hasher = std.hash.Wyhash.init(salt ^ (tag *% 0x9e37_79b9_7f4a_7c15));
    hasher.update(name);
    return hasher.final();
}
