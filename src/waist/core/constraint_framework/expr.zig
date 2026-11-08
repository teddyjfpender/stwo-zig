const std = @import("std");
const m31_mod = @import("../fields/m31.zig");
const qm31_mod = @import("../fields/qm31.zig");

const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;

const expr_types = @import("expr/types.zig");
const expr_format = @import("expr/format.zig");

pub const ColumnExpr = expr_types.ColumnExpr;
pub const BaseExprNode = expr_types.BaseExprNode;
pub const BaseExpr = expr_types.BaseExpr;
pub const ExtExprNode = expr_types.ExtExprNode;
pub const ExtExpr = expr_types.ExtExpr;
pub const EvalError = expr_types.EvalError;
pub const DegreeError = expr_types.DegreeError;
pub const Assignment = expr_types.Assignment;
pub const ExprVariables = expr_types.ExprVariables;

pub const ExprArena = struct {
    arena: std.heap.ArenaAllocator,

    pub fn init(backing_allocator: std.mem.Allocator) ExprArena {
        return .{ .arena = std.heap.ArenaAllocator.init(backing_allocator) };
    }

    pub fn deinit(self: *ExprArena) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn allocator(self: *ExprArena) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn allocBase(self: *ExprArena, node: BaseExprNode) !BaseExpr {
        const ptr = try self.allocator().create(BaseExprNode);
        ptr.* = node;
        return ptr;
    }

    fn allocExt(self: *ExprArena, node: ExtExprNode) !ExtExpr {
        const ptr = try self.allocator().create(ExtExprNode);
        ptr.* = node;
        return ptr;
    }

    fn dupString(self: *ExprArena, s: []const u8) ![]const u8 {
        return self.allocator().dupe(u8, s);
    }

    pub fn baseConst(self: *ExprArena, value: M31) !BaseExpr {
        return self.allocBase(.{ .constant = value });
    }

    pub fn baseZero(self: *ExprArena) !BaseExpr {
        return self.baseConst(M31.zero());
    }

    pub fn baseOne(self: *ExprArena) !BaseExpr {
        return self.baseConst(M31.one());
    }

    pub fn baseCol(self: *ExprArena, interaction: usize, idx: usize, offset: isize) !BaseExpr {
        return self.allocBase(.{ .col = .{ .interaction = interaction, .idx = idx, .offset = offset } });
    }

    pub fn baseParam(self: *ExprArena, name: []const u8) !BaseExpr {
        return self.allocBase(.{ .param = try self.dupString(name) });
    }

    pub fn baseAdd(self: *ExprArena, lhs: BaseExpr, rhs: BaseExpr) !BaseExpr {
        return self.allocBase(.{ .add = .{ .lhs = lhs, .rhs = rhs } });
    }

    pub fn baseSub(self: *ExprArena, lhs: BaseExpr, rhs: BaseExpr) !BaseExpr {
        return self.allocBase(.{ .sub = .{ .lhs = lhs, .rhs = rhs } });
    }

    pub fn baseMul(self: *ExprArena, lhs: BaseExpr, rhs: BaseExpr) !BaseExpr {
        return self.allocBase(.{ .mul = .{ .lhs = lhs, .rhs = rhs } });
    }

    pub fn baseNeg(self: *ExprArena, value: BaseExpr) !BaseExpr {
        return self.allocBase(.{ .neg = value });
    }

    pub fn baseInv(self: *ExprArena, value: BaseExpr) !BaseExpr {
        return self.allocBase(.{ .inv = value });
    }

    pub fn extConst(self: *ExprArena, value: QM31) !ExtExpr {
        return self.allocExt(.{ .constant = value });
    }

    pub fn extZero(self: *ExprArena) !ExtExpr {
        return self.extConst(QM31.zero());
    }

    pub fn extOne(self: *ExprArena) !ExtExpr {
        return self.extConst(QM31.one());
    }

    pub fn extParam(self: *ExprArena, name: []const u8) !ExtExpr {
        return self.allocExt(.{ .param = try self.dupString(name) });
    }

    pub fn extSecureCol(self: *ExprArena, values: [4]BaseExpr) !ExtExpr {
        return self.allocExt(.{ .secure_col = values });
    }

    pub fn extFromBase(self: *ExprArena, value: BaseExpr) !ExtExpr {
        const zero = try self.baseZero();
        return self.extSecureCol(.{ value, zero, zero, zero });
    }

    pub fn extAdd(self: *ExprArena, lhs: ExtExpr, rhs: ExtExpr) !ExtExpr {
        return self.allocExt(.{ .add = .{ .lhs = lhs, .rhs = rhs } });
    }

    pub fn extSub(self: *ExprArena, lhs: ExtExpr, rhs: ExtExpr) !ExtExpr {
        return self.allocExt(.{ .sub = .{ .lhs = lhs, .rhs = rhs } });
    }

    pub fn extMul(self: *ExprArena, lhs: ExtExpr, rhs: ExtExpr) !ExtExpr {
        return self.allocExt(.{ .mul = .{ .lhs = lhs, .rhs = rhs } });
    }

    pub fn extNeg(self: *ExprArena, value: ExtExpr) !ExtExpr {
        return self.allocExt(.{ .neg = value });
    }

    pub fn simplifyBase(self: *ExprArena, expr: BaseExpr) !BaseExpr {
        return self.simplifyBaseUnchecked(expr);
    }

    fn simplifyBaseUnchecked(self: *ExprArena, expr: BaseExpr) !BaseExpr {
        switch (expr.*) {
            .add => |pair| {
                const a = try self.simplifyBaseUnchecked(pair.lhs);
                const b = try self.simplifyBaseUnchecked(pair.rhs);

                if (baseConstValue(a)) |ac| {
                    if (baseConstValue(b)) |bc| return self.baseConst(ac.add(bc));
                    if (ac.isZero()) return b;
                }
                if (baseConstValue(b)) |bc| {
                    if (bc.isZero()) return a;
                }

                if (baseNegInner(a)) |minus_a| {
                    if (baseNegInner(b)) |minus_b| {
                        const sum = try self.baseAdd(minus_a, minus_b);
                        return self.baseNeg(sum);
                    }
                    return self.baseSub(b, minus_a);
                }
                if (baseNegInner(b)) |minus_b| {
                    return self.baseSub(a, minus_b);
                }
                return self.baseAdd(a, b);
            },
            .sub => |pair| {
                const a = try self.simplifyBaseUnchecked(pair.lhs);
                const b = try self.simplifyBaseUnchecked(pair.rhs);

                if (baseConstValue(a)) |ac| {
                    if (baseConstValue(b)) |bc| return self.baseConst(ac.sub(bc));
                    if (ac.isZero()) return self.baseNeg(b);
                }
                if (baseConstValue(b)) |bc| {
                    if (bc.isZero()) return a;
                }

                if (baseNegInner(a)) |minus_a| {
                    if (baseNegInner(b)) |minus_b| {
                        return self.baseSub(minus_b, minus_a);
                    }
                    const sum = try self.baseAdd(minus_a, b);
                    return self.baseNeg(sum);
                }
                if (baseNegInner(b)) |minus_b| {
                    return self.baseAdd(a, minus_b);
                }
                return self.baseSub(a, b);
            },
            .mul => |pair| {
                const a = try self.simplifyBaseUnchecked(pair.lhs);
                const b = try self.simplifyBaseUnchecked(pair.rhs);

                if (baseConstValue(a)) |ac| {
                    if (baseConstValue(b)) |bc| return self.baseConst(ac.mul(bc));
                    if (ac.isZero()) return self.baseZero();
                    if (ac.eql(M31.one())) return b;
                    const minus_one = M31.fromCanonical(m31_mod.Modulus - 1);
                    if (ac.eql(minus_one)) return self.baseNeg(b);
                }
                if (baseConstValue(b)) |bc| {
                    if (bc.isZero()) return self.baseZero();
                    if (bc.eql(M31.one())) return a;
                    const minus_one = M31.fromCanonical(m31_mod.Modulus - 1);
                    if (bc.eql(minus_one)) return self.baseNeg(a);
                }

                if (baseNegInner(a)) |minus_a| {
                    if (baseNegInner(b)) |minus_b| {
                        return self.baseMul(minus_a, minus_b);
                    }
                    const prod = try self.baseMul(minus_a, b);
                    return self.baseNeg(prod);
                }
                if (baseNegInner(b)) |minus_b| {
                    const prod = try self.baseMul(a, minus_b);
                    return self.baseNeg(prod);
                }
                return self.baseMul(a, b);
            },
            .neg => |inner| {
                const a = try self.simplifyBaseUnchecked(inner);
                if (baseConstValue(a)) |c| return self.baseConst(c.neg());
                if (baseNegInner(a)) |minus_a| return minus_a;
                if (baseSubParts(a)) |parts| return self.baseSub(parts.rhs, parts.lhs);
                return self.baseNeg(a);
            },
            .inv => |inner| {
                const a = try self.simplifyBaseUnchecked(inner);
                if (baseInvInner(a)) |inv_a| return inv_a;
                if (baseConstValue(a)) |c| {
                    const inv = c.inv() catch return error.DivisionByZero;
                    return self.baseConst(inv);
                }
                return self.baseInv(a);
            },
            else => return expr,
        }
    }

    pub fn simplifyExt(self: *ExprArena, expr: ExtExpr) !ExtExpr {
        return self.simplifyExtUnchecked(expr);
    }

    fn simplifyExtUnchecked(self: *ExprArena, expr: ExtExpr) !ExtExpr {
        switch (expr.*) {
            .add => |pair| {
                const a = try self.simplifyExtUnchecked(pair.lhs);
                const b = try self.simplifyExtUnchecked(pair.rhs);

                if (extConstValue(a)) |ac| {
                    if (extConstValue(b)) |bc| return self.extConst(ac.add(bc));
                    if (ac.isZero()) return b;
                }
                if (extConstValue(b)) |bc| {
                    if (bc.isZero()) return a;
                }

                if (extNegInner(a)) |minus_a| {
                    if (extNegInner(b)) |minus_b| {
                        const sum = try self.extAdd(minus_a, minus_b);
                        return self.extNeg(sum);
                    }
                    return self.extSub(b, minus_a);
                }
                if (extNegInner(b)) |minus_b| {
                    return self.extSub(a, minus_b);
                }
                return self.extAdd(a, b);
            },
            .sub => |pair| {
                const a = try self.simplifyExtUnchecked(pair.lhs);
                const b = try self.simplifyExtUnchecked(pair.rhs);

                if (extConstValue(a)) |ac| {
                    if (extConstValue(b)) |bc| return self.extConst(ac.sub(bc));
                    if (ac.isZero()) return self.extNeg(b);
                }
                if (extConstValue(b)) |bc| {
                    if (bc.isZero()) return a;
                }

                if (extNegInner(a)) |minus_a| {
                    if (extNegInner(b)) |minus_b| {
                        return self.extSub(minus_b, minus_a);
                    }
                    const sum = try self.extAdd(minus_a, b);
                    return self.extNeg(sum);
                }
                if (extNegInner(b)) |minus_b| {
                    return self.extAdd(a, minus_b);
                }
                return self.extSub(a, b);
            },
            .mul => |pair| {
                const a = try self.simplifyExtUnchecked(pair.lhs);
                const b = try self.simplifyExtUnchecked(pair.rhs);

                if (extConstValue(a)) |ac| {
                    if (extConstValue(b)) |bc| return self.extConst(ac.mul(bc));
                    if (ac.isZero()) return self.extZero();
                    if (ac.eql(QM31.one())) return b;
                    const minus_one = QM31.fromU32Unchecked(m31_mod.Modulus - 1, 0, 0, 0);
                    if (ac.eql(minus_one)) return self.extNeg(b);
                }
                if (extConstValue(b)) |bc| {
                    if (bc.isZero()) return self.extZero();
                    if (bc.eql(QM31.one())) return a;
                    const minus_one = QM31.fromU32Unchecked(m31_mod.Modulus - 1, 0, 0, 0);
                    if (bc.eql(minus_one)) return self.extNeg(a);
                }

                if (extNegInner(a)) |minus_a| {
                    if (extNegInner(b)) |minus_b| {
                        return self.extMul(minus_a, minus_b);
                    }
                    const prod = try self.extMul(minus_a, b);
                    return self.extNeg(prod);
                }
                if (extNegInner(b)) |minus_b| {
                    const prod = try self.extMul(a, minus_b);
                    return self.extNeg(prod);
                }
                return self.extMul(a, b);
            },
            .neg => |inner| {
                const a = try self.simplifyExtUnchecked(inner);
                if (extConstValue(a)) |c| return self.extConst(c.neg());
                if (extNegInner(a)) |minus_a| return minus_a;
                if (extSubParts(a)) |parts| return self.extSub(parts.rhs, parts.lhs);
                return self.extNeg(a);
            },
            .secure_col => |values| {
                var simplified_values: [4]BaseExpr = undefined;
                for (values, 0..) |value, i| {
                    simplified_values[i] = try self.simplifyBaseUnchecked(value);
                }

                if (baseConstArray(simplified_values)) |const_values| {
                    return self.extConst(QM31.fromM31Array(const_values));
                }
                return self.extSecureCol(simplified_values);
            },
            else => return expr,
        }
    }

    pub fn simplifyAndFormatBaseAlloc(
        self: *ExprArena,
        expr: BaseExpr,
        out_allocator: std.mem.Allocator,
    ) ![]u8 {
        const simplified = try self.simplifyBase(expr);
        return formatBaseAlloc(simplified, out_allocator);
    }

    pub fn simplifyAndFormatExtAlloc(
        self: *ExprArena,
        expr: ExtExpr,
        out_allocator: std.mem.Allocator,
    ) ![]u8 {
        const simplified = try self.simplifyExt(expr);
        return formatExtAlloc(simplified, out_allocator);
    }
};

pub const NamedExprs = struct {
    base_exprs: std.StringHashMap(BaseExpr),
    ext_exprs: std.StringHashMap(ExtExpr),

    pub fn init(allocator: std.mem.Allocator) NamedExprs {
        return .{
            .base_exprs = std.StringHashMap(BaseExpr).init(allocator),
            .ext_exprs = std.StringHashMap(ExtExpr).init(allocator),
        };
    }

    pub fn deinit(self: *NamedExprs) void {
        self.base_exprs.deinit();
        self.ext_exprs.deinit();
        self.* = undefined;
    }

    pub fn putBase(self: *NamedExprs, name: []const u8, expr: BaseExpr) !void {
        try self.base_exprs.put(name, expr);
    }

    pub fn putExt(self: *NamedExprs, name: []const u8, expr: ExtExpr) !void {
        try self.ext_exprs.put(name, expr);
    }

    pub fn degreeBoundName(self: *const NamedExprs, name: []const u8) DegreeError!usize {
        if (self.base_exprs.get(name)) |expr| {
            return degreeBoundBase(expr, self);
        }
        if (self.ext_exprs.get(name)) |expr| {
            return degreeBoundExt(expr, self);
        }
        if (std.mem.startsWith(u8, name, "preprocessed.")) {
            return 1;
        }
        return 0;
    }
};

pub fn evalBase(expr: BaseExpr, assignment: *const Assignment) EvalError!M31 {
    switch (expr.*) {
        .col => |col| return assignment.columns.get(col) orelse EvalError.MissingColumn,
        .constant => |value| return value,
        .param => |name| return assignment.params.get(name) orelse EvalError.MissingParam,
        .add => |pair| return (try evalBase(pair.lhs, assignment)).add(try evalBase(pair.rhs, assignment)),
        .sub => |pair| return (try evalBase(pair.lhs, assignment)).sub(try evalBase(pair.rhs, assignment)),
        .mul => |pair| return (try evalBase(pair.lhs, assignment)).mul(try evalBase(pair.rhs, assignment)),
        .neg => |value| return (try evalBase(value, assignment)).neg(),
        .inv => |value| return (try evalBase(value, assignment)).inv() catch EvalError.DivisionByZero,
    }
}

pub fn evalExt(expr: ExtExpr, assignment: *const Assignment) EvalError!QM31 {
    switch (expr.*) {
        .secure_col => |values| {
            var coords: [4]M31 = undefined;
            for (values, 0..) |value, i| {
                coords[i] = try evalBase(value, assignment);
            }
            return QM31.fromM31Array(coords);
        },
        .constant => |value| return value,
        .param => |name| return assignment.ext_params.get(name) orelse EvalError.MissingExtParam,
        .add => |pair| return (try evalExt(pair.lhs, assignment)).add(try evalExt(pair.rhs, assignment)),
        .sub => |pair| return (try evalExt(pair.lhs, assignment)).sub(try evalExt(pair.rhs, assignment)),
        .mul => |pair| return (try evalExt(pair.lhs, assignment)).mul(try evalExt(pair.rhs, assignment)),
        .neg => |value| return (try evalExt(value, assignment)).neg(),
    }
}

pub fn degreeBoundBase(expr: BaseExpr, named_exprs: *const NamedExprs) DegreeError!usize {
    switch (expr.*) {
        .col => return 1,
        .constant => return 0,
        .param => |name| return named_exprs.degreeBoundName(name),
        .add => |pair| return @max(
            try degreeBoundBase(pair.lhs, named_exprs),
            try degreeBoundBase(pair.rhs, named_exprs),
        ),
        .sub => |pair| return @max(
            try degreeBoundBase(pair.lhs, named_exprs),
            try degreeBoundBase(pair.rhs, named_exprs),
        ),
        .mul => |pair| return (try degreeBoundBase(pair.lhs, named_exprs)) +
            (try degreeBoundBase(pair.rhs, named_exprs)),
        .neg => |value| return degreeBoundBase(value, named_exprs),
        .inv => |value| switch (value.*) {
            .param => |name| {
                const degree = try named_exprs.degreeBoundName(name);
                if (degree == 0) return 0;
                return DegreeError.InvalidInverseDegree;
            },
            .constant => return 0,
            else => return DegreeError.InvalidInverseDegree,
        },
    }
}

pub fn degreeBoundExt(expr: ExtExpr, named_exprs: *const NamedExprs) DegreeError!usize {
    switch (expr.*) {
        .secure_col => |values| {
            var max_degree: usize = 0;
            for (values) |value| {
                max_degree = @max(max_degree, try degreeBoundBase(value, named_exprs));
            }
            return max_degree;
        },
        .constant => return 0,
        .param => |name| return named_exprs.degreeBoundName(name),
        .add => |pair| return @max(
            try degreeBoundExt(pair.lhs, named_exprs),
            try degreeBoundExt(pair.rhs, named_exprs),
        ),
        .sub => |pair| return @max(
            try degreeBoundExt(pair.lhs, named_exprs),
            try degreeBoundExt(pair.rhs, named_exprs),
        ),
        .mul => |pair| return (try degreeBoundExt(pair.lhs, named_exprs)) +
            (try degreeBoundExt(pair.rhs, named_exprs)),
        .neg => |value| return degreeBoundExt(value, named_exprs),
    }
}

pub const formatBaseAlloc = expr_format.formatBaseAlloc;
pub const formatExtAlloc = expr_format.formatExtAlloc;

fn baseConstValue(expr: BaseExpr) ?M31 {
    return switch (expr.*) {
        .constant => |value| value,
        else => null,
    };
}

fn extConstValue(expr: ExtExpr) ?QM31 {
    return switch (expr.*) {
        .constant => |value| value,
        else => null,
    };
}

fn baseNegInner(expr: BaseExpr) ?BaseExpr {
    return switch (expr.*) {
        .neg => |value| value,
        else => null,
    };
}

fn extNegInner(expr: ExtExpr) ?ExtExpr {
    return switch (expr.*) {
        .neg => |value| value,
        else => null,
    };
}

fn baseInvInner(expr: BaseExpr) ?BaseExpr {
    return switch (expr.*) {
        .inv => |value| value,
        else => null,
    };
}

fn baseSubParts(expr: BaseExpr) ?struct { lhs: BaseExpr, rhs: BaseExpr } {
    return switch (expr.*) {
        .sub => |pair| .{ .lhs = pair.lhs, .rhs = pair.rhs },
        else => null,
    };
}

fn extSubParts(expr: ExtExpr) ?struct { lhs: ExtExpr, rhs: ExtExpr } {
    return switch (expr.*) {
        .sub => |pair| .{ .lhs = pair.lhs, .rhs = pair.rhs },
        else => null,
    };
}

fn baseConstArray(values: [4]BaseExpr) ?[4]M31 {
    var out: [4]M31 = undefined;
    for (values, 0..) |value, i| {
        out[i] = baseConstValue(value) orelse return null;
    }
    return out;
}

test "constraint framework expr: simplify preserves evaluation" {
    const alloc = std.testing.allocator;

    var arena = ExprArena.init(alloc);
    defer arena.deinit();

    const col0 = try arena.baseCol(1, 0, 0);
    const col1 = try arena.baseCol(1, 1, 0);
    const a = try arena.baseParam("a");
    const b = try arena.baseParam("b");
    const zero = try arena.baseZero();
    const one = try arena.baseOne();

    const term = try arena.baseMul(
        try arena.baseAdd(zero, try arena.baseMul(col0, one)),
        try arena.baseAdd(try arena.baseNeg(col1), try arena.baseNeg(a)),
    );
    const expr = try arena.baseAdd(term, try arena.baseMul(zero, b));

    const simplified = try arena.simplifyBase(expr);

    var vars = ExprVariables.init(alloc);
    defer vars.deinit();
    try vars.collectBase(expr);

    var salt: u64 = 0;
    while (salt < 64) : (salt += 1) {
        var assignment = try vars.randomAssignment(alloc, salt);
        defer assignment.deinit();

        const original_value = try evalBase(expr, &assignment);
        const simplified_value = try evalBase(simplified, &assignment);
        try std.testing.expect(original_value.eql(simplified_value));
    }
}

test "constraint framework expr: vector parity" {
    const alloc = std.testing.allocator;

    const input = try std.fs.cwd().readFileAlloc(alloc, "vectors/constraint_expr.json", 1 << 20);
    defer alloc.free(input);

    const Vectors = struct {
        const ColumnValue = struct {
            interaction: usize,
            idx: usize,
            offset: isize,
            value: u32,
        };

        const BaseParamValue = struct {
            name: []const u8,
            value: u32,
        };

        const ExtParamValue = struct {
            name: []const u8,
            value: [4]u32,
        };

        const Case = struct {
            name: []const u8,
            columns: []ColumnValue,
            params: []BaseParamValue,
            ext_params: []ExtParamValue,
            base_eval: ?u32 = null,
            ext_eval: ?[4]u32 = null,
            base_degree: ?usize = null,
            ext_degree: ?usize = null,
            base_format: ?[]const u8 = null,
            ext_format: ?[]const u8 = null,
            base_simplified_format: ?[]const u8 = null,
            ext_simplified_format: ?[]const u8 = null,
            evaluator_formatted: ?[]const u8 = null,
            evaluator_degree_bounds: ?[]usize = null,
        };

        meta: struct {
            upstream_commit: []const u8,
            schema_version: u32,
            sample_count: usize,
            seed_strategy: []const u8,
        },
        cases: []Case,
    };

    var parsed = try std.json.parseFromSlice(Vectors, alloc, input, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
        parsed.value.meta.upstream_commit,
    );
    try std.testing.expectEqual(@as(u32, 1), parsed.value.meta.schema_version);

    for (parsed.value.cases) |case| {
        if (std.mem.eql(u8, case.name, "evaluator_logup")) continue;

        var arena = ExprArena.init(alloc);
        defer arena.deinit();

        var named = NamedExprs.init(alloc);
        defer named.deinit();

        const built = try buildVectorCase(&arena, &named, case.name);

        var assignment = Assignment.init(alloc);
        defer assignment.deinit();

        for (case.columns) |col| {
            try assignment.setColumn(
                .{ .interaction = col.interaction, .idx = col.idx, .offset = col.offset },
                M31.fromCanonical(col.value),
            );
        }
        for (case.params) |param| {
            try assignment.setParam(param.name, M31.fromCanonical(param.value));
        }
        for (case.ext_params) |param| {
            try assignment.setExtParam(param.name, qm31FromU32Array(param.value));
        }

        if (case.base_eval) |expected| {
            const value = try evalBase(built.base_expr.?, &assignment);
            try std.testing.expectEqual(expected, value.toU32());
        }
        if (case.ext_eval) |expected| {
            const value = try evalExt(built.ext_expr.?, &assignment);
            try std.testing.expectEqualSlices(u32, &expected, &qm31ToU32Array(value));
        }

        if (case.base_degree) |expected| {
            const degree = try degreeBoundBase(built.base_expr.?, &named);
            try std.testing.expectEqual(expected, degree);
        }
        if (case.ext_degree) |expected| {
            const degree = try degreeBoundExt(built.ext_expr.?, &named);
            try std.testing.expectEqual(expected, degree);
        }

        if (case.base_format) |expected| {
            const formatted = try formatBaseAlloc(built.base_expr.?, alloc);
            defer alloc.free(formatted);
            try std.testing.expectEqualStrings(expected, formatted);
        }
        if (case.ext_format) |expected| {
            const formatted = try formatExtAlloc(built.ext_expr.?, alloc);
            defer alloc.free(formatted);
            try std.testing.expectEqualStrings(expected, formatted);
        }

        if (case.base_simplified_format) |expected| {
            const formatted = try arena.simplifyAndFormatBaseAlloc(built.base_expr.?, alloc);
            defer alloc.free(formatted);
            try std.testing.expectEqualStrings(expected, formatted);
        }
        if (case.ext_simplified_format) |expected| {
            const formatted = try arena.simplifyAndFormatExtAlloc(built.ext_expr.?, alloc);
            defer alloc.free(formatted);
            try std.testing.expectEqualStrings(expected, formatted);
        }
    }
}

const BuiltCase = struct {
    base_expr: ?BaseExpr = null,
    ext_expr: ?ExtExpr = null,
};

fn buildVectorCase(arena: *ExprArena, named: *NamedExprs, name: []const u8) !BuiltCase {
    if (std.mem.eql(u8, name, "base_arith")) {
        const col_1_0_0 = try arena.baseCol(1, 0, 0);
        const col_1_1_neg_1 = try arena.baseCol(1, 1, -1);
        const a = try arena.baseParam("a");
        const b = try arena.baseParam("b");
        const c = try arena.baseParam("c");

        const sum = try arena.baseAdd(col_1_0_0, a);
        const diff = try arena.baseSub(col_1_1_neg_1, b);
        const prod = try arena.baseMul(sum, diff);
        const expr = try arena.baseAdd(prod, try arena.baseInv(c));

        return .{ .base_expr = expr };
    }

    if (std.mem.eql(u8, name, "ext_arith")) {
        const col_1_0_0 = try arena.baseCol(1, 0, 0);
        const col_1_1_0 = try arena.baseCol(1, 1, 0);
        const a = try arena.baseParam("a");
        const b = try arena.baseParam("b");

        const secure_col = try arena.extSecureCol(.{
            try arena.baseSub(col_1_0_0, col_1_1_0),
            try arena.baseMul(col_1_1_0, try arena.baseNeg(a)),
            try arena.baseAdd(a, try arena.baseInv(a)),
            try arena.baseMul(b, try arena.baseConst(M31.fromCanonical(7))),
        });

        const q = try arena.extParam("q");
        const q_sq = try arena.extMul(q, q);
        const one_as_base = try arena.baseConst(M31.one());
        const expr = try arena.extSub(
            try arena.extAdd(secure_col, q_sq),
            try arena.extFromBase(one_as_base),
        );

        return .{ .ext_expr = expr };
    }

    if (std.mem.eql(u8, name, "degree_named")) {
        const intermediate = try arena.baseMul(
            try arena.baseMul(
                try arena.baseAdd(
                    try arena.baseConst(M31.fromCanonical(12)),
                    try arena.baseCol(1, 1, 0),
                ),
                try arena.baseParam("a"),
            ),
            try arena.baseCol(1, 0, 0),
        );
        const qintermediate = try arena.extSecureCol(.{
            intermediate,
            try arena.baseConst(M31.fromCanonical(12)),
            try arena.baseParam("b"),
            try arena.baseConst(M31.zero()),
        });

        try named.putBase("intermediate", intermediate);
        try named.putBase("low_degree_intermediate", try arena.baseConst(M31.fromCanonical(12_345)));
        try named.putExt("qintermediate", qintermediate);

        const expr = try arena.baseMul(
            try arena.baseParam("intermediate"),
            try arena.baseCol(2, 1, 0),
        );

        const qexpr = try arena.extMul(
            try arena.extSecureCol(.{
                try arena.baseCol(2, 1, 0),
                expr,
                try arena.baseConst(M31.zero()),
                try arena.baseConst(M31.one()),
            }),
            try arena.extFromBase(try arena.baseParam("qintermediate")),
        );

        return .{ .base_expr = expr, .ext_expr = qexpr };
    }

    return error.UnknownVectorCase;
}

fn qm31FromU32Array(values: [4]u32) QM31 {
    return QM31.fromU32Unchecked(values[0], values[1], values[2], values[3]);
}

fn qm31ToU32Array(value: QM31) [4]u32 {
    const arr = value.toM31Array();
    return .{ arr[0].toU32(), arr[1].toU32(), arr[2].toU32(), arr[3].toU32() };
}
