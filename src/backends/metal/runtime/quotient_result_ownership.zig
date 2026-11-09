//! Consuming ownership at quotient receipt and runtime-tree adoption boundaries.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;

/// The receipt may reject after the runtime has published device handles.
/// Consume on both success and error; callers must not also destroy the source.
pub fn acceptReceipt(a: std.mem.Allocator, provider: anytype, product: anytype) !@TypeOf(product.*) {
    var owned = product.*;
    product.* = undefined;
    const budget = Budget.fromAllocator(a);
    if (budget) |owner| _ = owner.retain();
    defer if (budget) |owner| owner.destroy();
    errdefer owned.tree.deinit();
    errdefer if (comptime @hasField(@TypeOf(owned), "fri")) {
        for (owned.fri.trees) |*tree| tree.deinit();
        a.free(owned.fri.trees);
    };
    try provider.completeMetalRowExecution(owned.execution);
    return owned;
}

/// `fromSharedRuntime` consumes each raw tree on BOTH success and error. Take
/// before invoking it, so failed adoption cannot double-destroy that handle.
pub fn Batch(comptime Tree: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        budget: ?*Budget,
        initial: ?Tree,
        trees: []Tree,
        consumed: usize = 0,
        active: bool = true,

        pub fn init(a: std.mem.Allocator, initial: Tree, trees: []Tree) Self {
            const budget = Budget.fromAllocator(a);
            return .{ .allocator = a, .budget = if (budget) |owner| owner.retain() else null, .initial = initial, .trees = trees };
        }
        pub fn takeInitial(self: *Self) !Tree {
            if (!self.active) return error.QuotientResultUnavailable;
            const tree = self.initial orelse return error.QuotientInitialTreeConsumed;
            self.initial = null;
            return tree;
        }
        pub fn takeNext(self: *Self) !Tree {
            if (!self.active or self.consumed == self.trees.len) return error.QuotientResultUnavailable;
            const tree = self.trees[self.consumed];
            self.consumed += 1;
            return tree;
        }
        pub fn deinit(self: *Self) void {
            if (!self.active) return;
            if (self.initial) |*tree| tree.deinit();
            for (self.trees[self.consumed..]) |*tree| tree.deinit();
            self.allocator.free(self.trees);
            const budget = self.budget;
            self.active = false;
            self.initial = null;
            self.trees = &.{};
            self.budget = null;
            if (budget) |owner| owner.destroy();
        }
    };
}
