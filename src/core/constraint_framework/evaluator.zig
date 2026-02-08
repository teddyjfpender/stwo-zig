const std = @import("std");
const expr_mod = @import("expr.zig");

const M31 = @import("../fields/m31.zig").M31;
const QM31 = @import("../fields/qm31.zig").QM31;

const ExprArena = expr_mod.ExprArena;
const BaseExpr = expr_mod.BaseExpr;
const ExtExpr = expr_mod.ExtExpr;
const Assignment = expr_mod.Assignment;
const ExprVariables = expr_mod.ExprVariables;
const NamedExprs = expr_mod.NamedExprs;

pub const PREPROCESSED_TRACE_IDX: usize = 0;
pub const ORIGINAL_TRACE_IDX: usize = 1;
pub const INTERACTION_TRACE_IDX: usize = 2;

pub const FractionExpr = struct {
    numerator: ExtExpr,
    denominator: ExtExpr,
};

pub const EvaluatorError = error{
    LogupFinalized,
    InvalidBatchingLength,
    InvalidBatchingSequence,
    EmptyBatching,
    EmptyFractions,
} || std.mem.Allocator.Error || expr_mod.EvalError || expr_mod.DegreeError;

pub const FormalLogupAtRow = struct {
    interaction: usize,
    claimed_sum: ExtExpr,
    fracs: std.ArrayList(FractionExpr),
    is_finalized: bool,
    is_first: BaseExpr,
    cumsum_shift: ExtExpr,

    pub fn init(
        arena: *ExprArena,
        interaction: usize,
    ) !FormalLogupAtRow {
        const claimed_sum = try arena.extParam("claimed_sum");
        const column_size = try arena.baseParam("column_size");
        const cumsum_shift = try arena.extMul(claimed_sum, try arena.extFromBase(try arena.baseInv(column_size)));
        return .{
            .interaction = interaction,
            .claimed_sum = claimed_sum,
            .fracs = .empty,
            .is_finalized = true,
            .is_first = try arena.baseZero(),
            .cumsum_shift = cumsum_shift,
        };
    }

    pub fn deinit(self: *FormalLogupAtRow, allocator: std.mem.Allocator) void {
        self.fracs.deinit(allocator);
        self.* = undefined;
    }
};

pub const ExprEvaluator = struct {
    arena: *ExprArena,
    allocator: std.mem.Allocator,
    cur_var_index: usize,
    constraints: std.ArrayList(ExtExpr),
    logup: FormalLogupAtRow,
    intermediates: std.StringHashMap(BaseExpr),
    ext_intermediates: std.StringHashMap(ExtExpr),
    ordered_intermediates: std.ArrayList([]const u8),

    pub fn init(arena: *ExprArena, allocator: std.mem.Allocator) !ExprEvaluator {
        return .{
            .arena = arena,
            .allocator = allocator,
            .cur_var_index = 0,
            .constraints = .empty,
            .logup = try FormalLogupAtRow.init(arena, INTERACTION_TRACE_IDX),
            .intermediates = std.StringHashMap(BaseExpr).init(allocator),
            .ext_intermediates = std.StringHashMap(ExtExpr).init(allocator),
            .ordered_intermediates = .empty,
        };
    }

    pub fn deinit(self: *ExprEvaluator) void {
        for (self.ordered_intermediates.items) |name| self.allocator.free(name);
        self.ordered_intermediates.deinit(self.allocator);
        self.intermediates.deinit();
        self.ext_intermediates.deinit();
        self.constraints.deinit(self.allocator);
        self.logup.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn nextTraceMask(self: *ExprEvaluator) !BaseExpr {
        const mask = try self.nextInteractionMask(1, ORIGINAL_TRACE_IDX, .{0});
        return mask[0];
    }

    pub fn nextInteractionMask(
        self: *ExprEvaluator,
        comptime N: usize,
        interaction: usize,
        offsets: [N]isize,
    ) ![N]BaseExpr {
        var res: [N]BaseExpr = undefined;
        for (offsets, 0..) |offset, i| {
            res[i] = try self.arena.baseCol(interaction, self.cur_var_index, offset);
        }
        self.cur_var_index += 1;
        return res;
    }

    pub fn nextExtensionInteractionMask(
        self: *ExprEvaluator,
        comptime N: usize,
        interaction: usize,
        offsets: [N]isize,
    ) ![N]ExtExpr {
        const c0 = try self.nextInteractionMask(N, interaction, offsets);
        const c1 = try self.nextInteractionMask(N, interaction, offsets);
        const c2 = try self.nextInteractionMask(N, interaction, offsets);
        const c3 = try self.nextInteractionMask(N, interaction, offsets);

        var out: [N]ExtExpr = undefined;
        inline for (0..N) |i| {
            out[i] = try self.arena.extSecureCol(.{ c0[i], c1[i], c2[i], c3[i] });
        }
        return out;
    }

    pub fn addConstraint(self: *ExprEvaluator, constraint: ExtExpr) !void {
        try self.constraints.append(self.allocator, constraint);
    }

    pub fn addIntermediate(self: *ExprEvaluator, value: BaseExpr) !BaseExpr {
        const name = try std.fmt.allocPrint(
            self.allocator,
            "intermediate{}",
            .{self.intermediates.count() + self.ext_intermediates.count()},
        );
        const intermediate = try self.arena.baseParam(name);
        try self.intermediates.put(name, value);
        try self.ordered_intermediates.append(self.allocator, name);
        return intermediate;
    }

    pub fn addExtensionIntermediate(self: *ExprEvaluator, value: ExtExpr) !ExtExpr {
        const name = try std.fmt.allocPrint(
            self.allocator,
            "intermediate{}",
            .{self.intermediates.count() + self.ext_intermediates.count()},
        );
        const intermediate = try self.arena.extParam(name);
        try self.ext_intermediates.put(name, value);
        try self.ordered_intermediates.append(self.allocator, name);
        return intermediate;
    }

    pub fn formatConstraints(self: *ExprEvaluator, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);

        var wrote_any = false;
        for (self.ordered_intermediates.items) |name| {
            if (self.intermediates.get(name)) |intermediate| {
                const formatted = try self.arena.simplifyAndFormatBaseAlloc(intermediate, allocator);
                defer allocator.free(formatted);
                if (wrote_any) try out.writer(allocator).writeAll("\n\n");
                try out.writer(allocator).print("let {s} = {s};", .{ name, formatted });
                wrote_any = true;
            } else if (self.ext_intermediates.get(name)) |intermediate| {
                const formatted = try self.arena.simplifyAndFormatExtAlloc(intermediate, allocator);
                defer allocator.free(formatted);
                if (wrote_any) try out.writer(allocator).writeAll("\n\n");
                try out.writer(allocator).print("let {s} = {s};", .{ name, formatted });
                wrote_any = true;
            }
        }

        for (self.constraints.items, 0..) |constraint, i| {
            const formatted = try self.arena.simplifyAndFormatExtAlloc(constraint, allocator);
            defer allocator.free(formatted);
            if (wrote_any) try out.writer(allocator).writeAll("\n\n");
            try out.writer(allocator).print("let constraint_{d} = {s};", .{ i, formatted });
            wrote_any = true;
        }

        return out.toOwnedSlice(allocator);
    }

    pub fn constraintDegreeBounds(self: *ExprEvaluator, allocator: std.mem.Allocator) ![]usize {
        var named = NamedExprs.init(allocator);
        defer named.deinit();

        var base_it = self.intermediates.iterator();
        while (base_it.next()) |entry| {
            try named.putBase(entry.key_ptr.*, entry.value_ptr.*);
        }

        var ext_it = self.ext_intermediates.iterator();
        while (ext_it.next()) |entry| {
            try named.putExt(entry.key_ptr.*, entry.value_ptr.*);
        }

        var out = try allocator.alloc(usize, self.constraints.items.len);
        errdefer allocator.free(out);
        for (self.constraints.items, 0..) |constraint, i| {
            out[i] = try expr_mod.degreeBoundExt(constraint, &named);
        }
        return out;
    }

    fn collectVariables(self: *ExprEvaluator, allocator: std.mem.Allocator) !ExprVariables {
        var vars = ExprVariables.init(allocator);
        errdefer vars.deinit();

        for (self.constraints.items) |constraint| {
            try vars.collectExt(constraint);
        }
        var base_it = self.intermediates.iterator();
        while (base_it.next()) |entry| {
            try vars.collectBase(entry.value_ptr.*);
        }
        var ext_it = self.ext_intermediates.iterator();
        while (ext_it.next()) |entry| {
            try vars.collectExt(entry.value_ptr.*);
        }

        for (self.ordered_intermediates.items) |name| {
            _ = vars.params.swapRemove(name);
        }

        return vars;
    }

    pub fn randomAssignment(self: *ExprEvaluator, allocator: std.mem.Allocator) !Assignment {
        var vars = try self.collectVariables(allocator);
        defer vars.deinit();

        var assignment = try vars.randomAssignment(allocator, 0);
        errdefer assignment.deinit();

        for (self.ordered_intermediates.items) |name| {
            if (self.intermediates.get(name)) |intermediate| {
                const value = try expr_mod.evalBase(intermediate, &assignment);
                try assignment.setParam(name, value);
            } else if (self.ext_intermediates.get(name)) |intermediate| {
                const value = try expr_mod.evalExt(intermediate, &assignment);
                try assignment.setExtParam(name, value);
            } else {
                return error.MissingIntermediate;
            }
        }

        return assignment;
    }

    pub fn writeLogupFrac(self: *ExprEvaluator, fraction: FractionExpr) !void {
        if (self.logup.fracs.items.len == 0) {
            self.logup.is_finalized = false;
        }
        try self.logup.fracs.append(self.allocator, fraction);
    }

    pub fn finalizeLogupBatched(self: *ExprEvaluator, batching: []const usize) EvaluatorError!void {
        if (self.logup.is_finalized) return EvaluatorError.LogupFinalized;
        if (batching.len != self.logup.fracs.items.len) return EvaluatorError.InvalidBatchingLength;
        if (batching.len == 0) return EvaluatorError.EmptyBatching;

        const last_batch = std.mem.max(usize, batching);

        var fracs_by_batch = try self.allocator.alloc(std.ArrayList(FractionExpr), last_batch + 1);
        defer self.allocator.free(fracs_by_batch);
        for (fracs_by_batch) |*fracs| fracs.* = .empty;
        defer for (fracs_by_batch) |*fracs| fracs.deinit(self.allocator);

        var visited_batches = try self.allocator.alloc(bool, last_batch + 1);
        defer self.allocator.free(visited_batches);
        @memset(visited_batches, false);

        for (batching, self.logup.fracs.items) |batch, frac| {
            try fracs_by_batch[batch].append(self.allocator, frac);
            visited_batches[batch] = true;
        }

        for (visited_batches) |visited| {
            if (!visited) return EvaluatorError.InvalidBatchingSequence;
        }

        var prev_col_cumsum = try self.arena.extZero();

        var batch_id: usize = 0;
        while (batch_id < last_batch) : (batch_id += 1) {
            const frac = try sumFractions(self.arena, fracs_by_batch[batch_id].items);
            const current = try self.nextExtensionInteractionMask(1, self.logup.interaction, .{0});
            const diff = try self.arena.extSub(current[0], prev_col_cumsum);
            prev_col_cumsum = current[0];
            try self.addConstraint(try self.arena.extSub(
                try self.arena.extMul(diff, frac.denominator),
                frac.numerator,
            ));
        }

        const final_frac = try sumFractions(self.arena, fracs_by_batch[last_batch].items);
        const cumsums = try self.nextExtensionInteractionMask(2, self.logup.interaction, .{ -1, 0 });
        const diff = try self.arena.extSub(
            try self.arena.extSub(cumsums[1], cumsums[0]),
            prev_col_cumsum,
        );
        const shifted_diff = try self.arena.extAdd(diff, self.logup.cumsum_shift);

        try self.addConstraint(try self.arena.extSub(
            try self.arena.extMul(shifted_diff, final_frac.denominator),
            final_frac.numerator,
        ));
        self.logup.is_finalized = true;
    }

    pub fn finalizeLogup(self: *ExprEvaluator) !void {
        const batching = try self.allocator.alloc(usize, self.logup.fracs.items.len);
        defer self.allocator.free(batching);
        for (batching, 0..) |*batch, i| batch.* = i;
        try self.finalizeLogupBatched(batching);
    }

    pub fn finalizeLogupInPairs(self: *ExprEvaluator) !void {
        const batching = try self.allocator.alloc(usize, self.logup.fracs.items.len);
        defer self.allocator.free(batching);
        for (batching, 0..) |*batch, i| batch.* = i / 2;
        try self.finalizeLogupBatched(batching);
    }
};

fn sumFractions(arena: *ExprArena, fractions: []const FractionExpr) EvaluatorError!FractionExpr {
    if (fractions.len == 0) return EvaluatorError.EmptyFractions;

    var acc = fractions[0];
    for (fractions[1..]) |frac| {
        const left_num = try arena.extMul(acc.numerator, frac.denominator);
        const right_num = try arena.extMul(frac.numerator, acc.denominator);
        acc = .{
            .numerator = try arena.extAdd(left_num, right_num),
            .denominator = try arena.extMul(acc.denominator, frac.denominator),
        };
    }
    return acc;
}

test "constraint framework evaluator: mask progression" {
    const alloc = std.testing.allocator;

    var arena = ExprArena.init(alloc);
    defer arena.deinit();

    var evaluator = try ExprEvaluator.init(&arena, alloc);
    defer evaluator.deinit();

    const m0 = try evaluator.nextTraceMask();
    const m1 = try evaluator.nextTraceMask();

    const f0 = try expr_mod.formatBaseAlloc(m0, alloc);
    defer alloc.free(f0);
    const f1 = try expr_mod.formatBaseAlloc(m1, alloc);
    defer alloc.free(f1);

    try std.testing.expectEqualStrings("trace_1_column_0_offset_0", f0);
    try std.testing.expectEqualStrings("trace_1_column_1_offset_0", f1);
}

test "constraint framework evaluator: intermediates and random assignment" {
    const alloc = std.testing.allocator;

    var arena = ExprArena.init(alloc);
    defer arena.deinit();

    var evaluator = try ExprEvaluator.init(&arena, alloc);
    defer evaluator.deinit();

    const m0 = try evaluator.nextTraceMask();
    const m1 = try evaluator.nextTraceMask();

    const intermediate_expr = try arena.baseMul(m0, m1);
    const intermediate = try evaluator.addIntermediate(intermediate_expr);

    const constraint = try arena.extFromBase(try arena.baseMul(m0, intermediate));
    try evaluator.addConstraint(constraint);

    var assignment = try evaluator.randomAssignment(alloc);
    defer assignment.deinit();

    const expected_intermediate = try expr_mod.evalBase(intermediate_expr, &assignment);
    const actual_intermediate = assignment.params.get("intermediate0") orelse return error.MissingIntermediate;
    try std.testing.expect(expected_intermediate.eql(actual_intermediate));

    const formatted = try evaluator.formatConstraints(alloc);
    defer alloc.free(formatted);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "let intermediate0") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "let constraint_0") != null);

    const degrees = try evaluator.constraintDegreeBounds(alloc);
    defer alloc.free(degrees);
    try std.testing.expectEqual(@as(usize, 3), degrees[0]);
}

test "constraint framework evaluator: logup batching semantics" {
    const alloc = std.testing.allocator;

    var arena = ExprArena.init(alloc);
    defer arena.deinit();

    var evaluator = try ExprEvaluator.init(&arena, alloc);
    defer evaluator.deinit();

    const n0 = try arena.extFromBase(try arena.baseParam("n0"));
    const d0 = try arena.extFromBase(try arena.baseParam("d0"));
    const n1 = try arena.extFromBase(try arena.baseParam("n1"));
    const d1 = try arena.extFromBase(try arena.baseParam("d1"));
    const n2 = try arena.extFromBase(try arena.baseParam("n2"));
    const d2 = try arena.extFromBase(try arena.baseParam("d2"));

    try evaluator.writeLogupFrac(.{ .numerator = n0, .denominator = d0 });
    try evaluator.writeLogupFrac(.{ .numerator = n1, .denominator = d1 });
    try evaluator.writeLogupFrac(.{ .numerator = n2, .denominator = d2 });

    try evaluator.finalizeLogupBatched(&[_]usize{ 0, 1, 1 });
    try std.testing.expectEqual(@as(usize, 2), evaluator.constraints.items.len);
    try std.testing.expect(evaluator.logup.is_finalized);
    try std.testing.expectError(EvaluatorError.LogupFinalized, evaluator.finalizeLogup());

    var evaluator_invalid = try ExprEvaluator.init(&arena, alloc);
    defer evaluator_invalid.deinit();

    try evaluator_invalid.writeLogupFrac(.{ .numerator = n0, .denominator = d0 });
    try evaluator_invalid.writeLogupFrac(.{ .numerator = n1, .denominator = d1 });

    try std.testing.expectError(
        EvaluatorError.InvalidBatchingSequence,
        evaluator_invalid.finalizeLogupBatched(&[_]usize{ 0, 2 }),
    );
    try std.testing.expectError(
        EvaluatorError.InvalidBatchingLength,
        evaluator_invalid.finalizeLogupBatched(&[_]usize{0}),
    );
}
