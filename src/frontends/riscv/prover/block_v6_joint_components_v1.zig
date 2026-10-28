//! Exact tree relocation for a joint native/companion STARK. No equations,
//! column masks or physical claims are dropped. Does not grant proof authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CP = engine.air.component_prover;
const C = core.air.components;
const Point = core.circle.CirclePointQM31;
const Q = core.fields.qm31.QM31;
const DA = engine.air.accumulation.DomainEvaluationAccumulator;

pub fn Relocated(comptime proving: bool) type {
    return struct {
        inner: if (proving) CP.ComponentProver else C.Component,
        map: [4]usize,
        source_trees: usize,
        destination_trees: usize,
        split: u32,
        main_providers: ?[]const Handle = null,
        const Handle = if (proving) CP.ComponentProver else C.Component;
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, CP.ComponentProver, CP.Trace, DA);

        pub fn init(inner: if (proving) CP.ComponentProver else C.Component, native: bool, access: bool, split: u32) !Self {
            if (split < inner.compositionLogSplit() or split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT)
                return error.InvalidJointCompositionSplit;
            var adjusted = inner;
            if (split != inner.compositionLogSplit()) {
                // Native q1 quotients require the existing polynomial-extension
                // transform when joining q2 companions. Relabeling the split
                // alone changes the OODS identity and is incorrect.
                if (split - inner.compositionLogSplit() != 1 or inner.composition_geometry_override_v1 != null)
                    return error.UnsupportedJointCompositionLift;
                adjusted = try inner.withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = @intCast(split) });
            }
            return .{ .inner = adjusted, .map = if (native) .{ 0, 1, if (access) 3 else 2, 0 } else if (access) .{ 0, 1, 2, 4 } else .{ 0, 1, 3, 0 }, .source_trees = if (native or !access) 3 else 4, .destination_trees = if (access) 5 else 4, .split = split };
        }
        pub fn asProverComponent(self: *const Self) CP.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.profile_identity = self.inner.profile_identity;
            result.pool_exclusive_domain = self.inner.pool_exclusive_domain;
            if (self.inner.domain_parallel_evaluator != null) result.domain_parallel_evaluator = parallel;
            return result;
        }
        pub fn asVerifierComponent(self: *const Self) C.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.inner.nConstraints();
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.inner.maxConstraintLogDegreeBound();
        }
        pub fn compositionLogSplit(self: *const Self) u32 {
            return self.split;
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return self.inner.preprocessedColumnIndices(a);
        }

        fn relocate(self: *const Self, comptime T: type, a: std.mem.Allocator, original: core.pcs.TreeVec([]T)) !core.pcs.TreeVec([]T) {
            var owned = original;
            errdefer owned.deinitDeep(a);
            if (original.items.len != self.source_trees) return error.InvalidJointComponentTrees;
            const result = try a.alloc([]T, self.destination_trees);
            // Zero-length holes carry no columns or masks. Ownership of each
            // nonempty inner tree transfers exactly once, after allocation.
            @memset(result, &.{});
            for (original.items, self.map[0..self.source_trees]) |tree, to| result[to] = tree;
            a.free(original.items);
            return .initOwned(result);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
            const original = try self.inner.traceLogDegreeBounds(a);
            if (self.main_providers != null and original.items.len == self.source_trees) {
                // Components concatenates non-fixed column declarations. The
                // native roster already declares the shared main tree once.
                a.free(original.items[1]);
                original.items[1] = &.{};
            }
            return self.relocate(u32, a, original);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
            var original = try self.inner.maskPoints(a, point, max_log);
            // Native openings must contain every requested companion point at
            // the same sample index. Never silently discard an extra opening.
            if (self.main_providers) |providers| {
                self.requireSharedMain(a, providers, &original, point, max_log) catch |err| {
                    original.deinitDeep(a);
                    return err;
                };
                for (original.items[1]) |column| a.free(column);
                a.free(original.items[1]);
                original.items[1] = &.{};
            }
            return self.relocate([]Point, a, original);
        }
        fn requireSharedMain(self: *const Self, a: std.mem.Allocator, providers: []const Handle, original: *const C.MaskPoints, point: Point, max_log: u32) !void {
            if (original.items.len != self.source_trees) return error.InvalidJointComponentTrees;
            const required = original.items[1];
            if (required.len == 0) return;
            var offset: usize = 0;
            for (providers) |provider| {
                var supplied = try provider.maskPoints(a, point, max_log);
                defer supplied.deinitDeep(a);
                if (supplied.items.len != 3 or supplied.items[1].len > required.len - offset) return error.InvalidJointSharedMain;
                for (supplied.items[1], required[offset..][0..supplied.items[1].len]) |have, need| {
                    if (have.len < need.len) return error.MissingJointSharedMainOpening;
                    for (have[0..need.len], need) |actual, expected| if (!std.meta.eql(actual, expected)) return error.ChangedJointSharedMainOpening;
                }
                offset += supplied.items[1].len;
            }
            if (offset != required.len) return error.InvalidJointSharedMain;
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (mask.items.len != self.destination_trees and mask.items.len != self.destination_trees + 1) return error.InvalidJointComponentTrees;
            var items: [4][][]Q = undefined;
            for (self.map[0..self.source_trees], 0..) |from, i| items[i] = mask.items[from];
            const mapped = C.MaskValues{ .items = items[0..self.source_trees] };
            try self.inner.evaluateConstraintQuotientsAtPoint(point, &mapped, accumulator, max_log);
        }
        fn view(self: *const Self, trace: *const CP.Trace, trees: *[4][]const CP.Poly) !CP.Trace {
            if (trace.polys.items.len != self.destination_trees) return error.InvalidJointComponentTrees;
            for (self.map[0..self.source_trees], 0..) |from, i| trees[i] = trace.polys.items[from];
            var mapped = trace.*;
            mapped.polys = .initOwned(trees[0..self.source_trees]);
            return mapped;
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, accumulator: *DA) !void {
            var trees: [4][]const CP.Poly = undefined;
            const mapped = try self.view(trace, &trees);
            try self.inner.evaluateConstraintQuotientsOnDomain(&mapped, accumulator);
        }
        fn parallel(raw: *const anyopaque, trace: *const CP.Trace, accumulator: *DA, pool: *engine.work_pool.WorkPool) !void {
            const self: *const Self = @ptrCast(@alignCast(raw));
            var trees: [4][]const CP.Poly = undefined;
            const mapped = try self.view(trace, &trees);
            try self.inner.evaluateConstraintQuotientsOnDomainParallel(&mapped, accumulator, pool);
        }
    };
}

pub fn Combined(comptime proving: bool) type {
    return struct {
        wrappers: []Relocated(proving),
        handles: []Handle,
        const Handle = if (proving) CP.ComponentProver else C.Component;
        pub fn init(a: std.mem.Allocator, native: []const Handle, companion: []const Handle, access: bool) !@This() {
            if (native.len == 0 or companion.len == 0) return error.EmptyJointComponentRoster;
            var split: u32 = 0;
            for (native) |item| split = @max(split, item.compositionLogSplit());
            for (companion) |item| split = @max(split, item.compositionLogSplit());
            const wrappers = try a.alloc(Relocated(proving), try std.math.add(usize, native.len, companion.len));
            errdefer a.free(wrappers);
            const handles = try a.alloc(Handle, wrappers.len);
            errdefer a.free(handles);
            for (wrappers, handles, 0..) |*wrapper, *handle, i| {
                wrapper.* = try Relocated(proving).init(if (i < native.len) native[i] else companion[i - native.len], i < native.len, access, split);
                if (i >= native.len) wrapper.main_providers = native;
                handle.* = if (proving) wrapper.asProverComponent() else wrapper.asVerifierComponent();
            }
            return .{ .wrappers = wrappers, .handles = handles };
        }
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            a.free(self.handles);
            a.free(self.wrappers);
            self.* = undefined;
        }
    };
}

/// Borrowed native equations and columns. Callers own these through proving
/// or verification. Context alone is never a verified native receipt.
pub const Context = struct {
    native: *const @import("block_v5_native_components_v3.zig").Owner,
    columns: []const engine.pcs.ColumnEvaluation = &.{},
    logs: []const u32,
    reuse_projections: bool = false,
    pub fn mix(self: Context, channel: *core.proof_suites.Blake3.Channel) !void {
        channel.mixU32s(&.{ 0x42364a50, if (self.reuse_projections) 2 else 1 }); // B6JP, new joint proof domain.
        try @import("block_v5_native_template_protocol_v3.zig").mixClaims(channel, &self.native.statement, &self.native.claims);
    }
};

/// Derived once from independently admitted native geometry. The null entries
/// still need companion equations. No caller may supply this plan in a proof.
pub const ProjectionLayout = struct {
    aliases: []?Q,
    count: usize,
    pub fn init(a: std.mem.Allocator, joint: ?Context, projections: []const @import("block_v5_native_projection_fused_source_v1.zig").Slot) !@This() {
        const aliases = try a.alloc(?Q, projections.len);
        errdefer a.free(aliases);
        @memset(aliases, null);
        var count = projections.len;
        if (joint) |context| if (context.reuse_projections) {
            var cache = @import("block_v6_projection_alias_v1.zig").Cache{};
            defer cache.deinit();
            for (projections, aliases) |slot, *alias| {
                alias.* = try cache.claim(a, &context.native.statement, &context.native.claims, slot);
                if (alias.* != null) count -= 1;
            }
        };
        // The current companion owner declares the interaction tree through
        // its first surviving projection. An all-aliased schedule requires a
        // separately admitted owner, not silent loss of column declarations.
        if (projections.len != 0 and count == 0) return error.UnsupportedFullyAliasedProjectionRoster;
        return .{ .aliases = aliases, .count = count };
    }
    pub fn deinit(self: @This(), a: std.mem.Allocator) void {
        a.free(self.aliases);
    }
};
