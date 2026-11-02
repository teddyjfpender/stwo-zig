//! One lane-generic entry point for the composition polynomial of an RV64
//! Ethereum batch proof at a point. It reproduces
//! `core.air.Components.evalCompositionPolynomialAtPoint` for the roster the
//! receiver key builds: same component order, same Horner accumulation
//! `acc = acc * alpha + c`, same per-component vanishing denominators and
//! geometry, with every challenge, claim and public scalar supplied as lane
//! values through the flat layouts of rv64_point_layout.zig.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const Key = @import("rv64_execution_verifier_key.zig");
pub const Layout = @import("rv64_point_layout.zig");
pub const Lift = @import("rv64_point_lift.zig");
const rv = A.rv;
const core = A.core;
const E = rv.evaluation;
const geometry = rv.geometry;
const Q = A.Q;
const Point = core.circle.CirclePointQM31;
pub const PointFor = geometry.PointFor;
pub const NativeMasks = rv.lane.NativeMasks;

/// The native roster plus the static geometry the verifier derives from it.
pub const Roster = struct {
    components: *const Key.Components,
    layouts: Lift.Layouts,
    n_preprocessed_columns: usize,
    /// `max_log_degree_bound` as `core.verifier` passes it to every component.
    global_log: u32,
    composition_log_split: u32,
    pub fn init(key: *const Key.ReceiverKey, components: *const Key.Components) !Roster {
        const core_components = core.air.components.Components{ .components = components.verifiers(), .n_preprocessed_columns = key.fixed_logs.len };
        const split = try core_components.compositionLogSplit();
        const global_log = core.verifier_types.compositionMaskLogSize(core_components.compositionLogDegreeBound(), split) orelse return error.InvalidRv64CompositionGeometry;
        return .{ .components = components, .layouts = .init(Layout.Flags.fromView(key.view())), .n_preprocessed_columns = key.fixed_logs.len, .global_log = global_log, .composition_log_split = split };
    }
    pub fn count(self: *const Roster) usize {
        return self.components.count;
    }
    fn coreComponents(self: *const Roster) core.air.components.Components {
        return .{ .components = self.components.verifiers(), .n_preprocessed_columns = self.n_preprocessed_columns };
    }
};
pub fn AccumulatorFor(comptime F: type) type {
    return if (F == Q) core.air.accumulation.PointEvaluationAccumulator else rv.lane.PointAccumulator(F);
}

/// Composition value at `point` over lane F. `masks` follows the lane.zig
/// accessor contract over the proof's sampled values; the three flat slices
/// follow `Layout.Challenges`, `Layout.Claims` and `Layout.Publics`.
pub fn evalCompositionAtPointFor(comptime F: type, roster: *const Roster, point: PointFor(F), masks: anytype, composition_randomness: F, challenges: []const F, claims: []const F, publics: []const F) !F {
    return evalSelectedFor(F, roster, null, point, masks, composition_randomness, challenges, claims, publics);
}
/// One component (verifier handle order) into a fresh Horner accumulator.
pub fn evalComponentAtPointFor(comptime F: type, roster: *const Roster, ordinal: usize, point: PointFor(F), masks: anytype, composition_randomness: F, challenges: []const F, claims: []const F, publics: []const F) !F {
    if (ordinal >= roster.count()) return error.InvalidRv64ComponentOrdinal;
    return evalSelectedFor(F, roster, ordinal, point, masks, composition_randomness, challenges, claims, publics);
}
fn evalSelectedFor(comptime F: type, roster: *const Roster, only: ?usize, point: PointFor(F), masks: anytype, composition_randomness: F, challenges: []const F, claims: []const F, publics: []const F) !F {
    const C = E.ConstFor(F);
    const lifted = try Lift.lift(C, roster.components, roster.layouts, .{ .challenges = challenges, .claims = claims, .publics = publics });
    var accumulator = AccumulatorFor(F).init(composition_randomness);
    var sink = E.SinkFor(F){ .values = null, .accumulator = &accumulator };
    var cursor = Cursor(F){ .only = only, .point = point, .global_log = roster.global_log, .sink = &sink };
    try cursor.visit(&lifted.cpu, masks);
    try cursor.visit(&lifted.program, masks);
    try cursor.visit(&lifted.bytes, masks);
    if (lifted.bitwise) |*component| try cursor.visit(component, masks);
    if (lifted.shifts) |*component| try cursor.visit(component, masks);
    if (lifted.division) |*component| try cursor.visit(component, masks);
    if (lifted.multiplication) |*component| try cursor.visit(component, masks);
    if (lifted.permutation) |*component| try cursor.visit(component, masks);
    if (lifted.chi) |*component| try cursor.visit(component, masks);
    if (lifted.xor5) |*component| try cursor.visit(component, masks);
    if (lifted.bridge) |*component| try cursor.visit(component, masks);
    for (&lifted.secp) |*group| if (group.*) |*value| {
        try cursor.visit(&value.product, masks);
        try cursor.visit(&value.linear, masks);
        try cursor.visit(&value.bridge, masks);
    };
    if (lifted.ram) |*ram| {
        try cursor.visit(&ram.chunk, masks);
        try cursor.visit(&ram.common_cells, masks);
        try cursor.visit(&ram.edge_cells, masks);
        try cursor.visit(&ram.leaf, masks);
        try cursor.visit(&ram.node, masks);
        try cursor.visit(&ram.side, masks);
        try cursor.visit(&ram.common_permits, masks);
        try cursor.visit(&ram.edge_permits, masks);
        try cursor.visit(&ram.permutations, masks);
        try cursor.visit(&ram.policy, masks);
    }
    if (cursor.ordinal != roster.count()) return error.InvalidRv64RosterOrder;
    return accumulator.finalize();
}
fn Cursor(comptime F: type) type {
    return struct {
        only: ?usize,
        ordinal: usize = 0,
        point: PointFor(F),
        global_log: u32,
        sink: *E.SinkFor(F),
        fn visit(self: *@This(), component: anytype, masks: anytype) !void {
            defer self.ordinal += 1;
            if (self.only) |selected| if (selected != self.ordinal) return;
            try component.evaluateQuotientsAtPointFor(F, self.point, self.global_log, masks, self.sink);
        }
    };
}

/// Static proof shape an external verifier needs: per tree the committed
/// column log sizes in order, and per tree/column the mask offsets (in coset
/// steps of the global domain) in sample order.
pub const Shape = struct {
    allocator: std.mem.Allocator,
    tree_column_log_sizes: [][]u32,
    mask_offsets: [][][]i32,
    global_log: u32,
    composition_log_split: u32,
    pub fn deinit(self: *Shape) void {
        for (self.tree_column_log_sizes) |tree| self.allocator.free(tree);
        self.allocator.free(self.tree_column_log_sizes);
        for (self.mask_offsets) |tree| {
            for (tree) |column| self.allocator.free(column);
            self.allocator.free(tree);
        }
        self.allocator.free(self.mask_offsets);
        self.* = undefined;
    }
};
pub fn describeShape(a: std.mem.Allocator, roster: *const Roster) !Shape {
    const core_components = roster.coreComponents();
    var logs = try core_components.columnLogSizes(a);
    errdefer logs.deinitDeep(a);
    const probe = core.circle.secureFieldPointFromRandomSeed(Q.fromU32Unchecked(7, 11, 13, 17));
    var points = try core_components.maskPoints(a, probe, roster.global_log, false);
    defer points.deinitDeep(a);
    const step = core.poly.circle.canonic.CanonicCoset.new(roster.global_log).coset().step;
    const lifted = Point{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) };
    var candidates: [5]Point = undefined;
    for (&candidates, 0..) |*candidate, i| candidate.* = probe.add(lifted.mulSigned(@as(isize, @intCast(i)) - 2));
    const offsets = try a.alloc([][]i32, points.items.len);
    var trees: usize = 0;
    errdefer {
        for (offsets[0..trees]) |tree| {
            for (tree) |column| a.free(column);
            a.free(tree);
        }
        a.free(offsets);
    }
    for (points.items, offsets) |tree, *out| {
        out.* = try a.alloc([]i32, tree.len);
        trees += 1;
        var columns: usize = 0;
        errdefer for (out.*[0..columns]) |column| a.free(column);
        for (tree, out.*) |column, *destination| {
            destination.* = try a.alloc(i32, column.len);
            columns += 1;
            for (column, destination.*) |sample, *offset| {
                offset.* = for (candidates, 0..) |candidate, i| {
                    if (sample.eql(candidate)) break @as(i32, @intCast(i)) - 2;
                } else return error.UnknownRv64MaskOffset;
            }
        }
    }
    return .{ .allocator = a, .tree_column_log_sizes = logs.items, .mask_offsets = offsets, .global_log = roster.global_log, .composition_log_split = roster.composition_log_split };
}
