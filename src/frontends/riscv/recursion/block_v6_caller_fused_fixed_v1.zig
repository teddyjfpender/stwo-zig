//! Original B5CF geometry and verifier DAGs from independent admission.
//! Public claims remain symbolic ports. No capture or successful verifier
//! receipt is manufactured. Complete transcript/PCS/roster assembly follows.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Admission = @import("../prover/block_v5_caller_fused_recursive_admission_v1.zig");
pub const Claims = Admission.Fused.ClaimFrames;
const Equation = @import("air/block_v5_caller_fused_composition_v1.zig");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const R = @import("air/composition_graph_recorder.zig");
const S = R.Scalar;
const Source = @import("air/blake3_execution_composition.zig").Source;
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Arithmetic = @import("block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
pub const Limits = struct { max_bytes: usize = 512 << 20, shape: Shape.Limits = .{} };
pub const Compiled = struct {
    allocator: std.mem.Allocator,
    circuit: R.Circuit,
    sources: []Source,
    pub fn deinit(self: *Compiled) void {
        self.circuit.deinit();
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    template_id: [32]u8,
    shape: Shape.Owned,
    composition: Compiled,
    deep_graph: Deep.Circuit,
    fri_graph: Fri.Circuit,
    arithmetic: Arithmetic,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = false;
    pub fn derive(backing: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Claims, limits: Limits) !*Owned {
        try admitted.validate(admitted.template_id);
        if (limits.max_bytes == 0) return error.CallerFusedFixedResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        // Validate original physical claim framing, then use those header
        // values only to reconstruct original masks/counts, never DAG values.
        const public = try Equation.publicInputs(a, admitted, claims);
        defer a.free(public);
        const relations = try Admission.Protocol.drawRelations(a, admitted.sealed);
        const word = try @import("../prover/block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, admitted.sealed);
        const memory = try @import("../prover/block_memory_relation_v2.zig").Challenges.draw(a, admitted.sealed);
        var components = try Admission.Fused.Components.init(a, &admitted.schedule, &claims, &relations, &memory, &word, admitted.logs[3], admitted.logs[2], admitted.sealed.register_custody_mode);
        defer components.deinit();
        const handles = try components.verifier();
        defer a.free(handles);
        const all = core.air.components.Components{ .components = handles, .n_preprocessed_columns = admitted.logs[0].len };
        var shape = try Shape.Owned.init(a, &admitted.logs, all, admitted.config, limits.shape);
        errdefer shape.deinit();
        var composition = try compile(a, admitted, &shape, public.len, handles);
        errdefer composition.deinit();
        var deep = try Deep.build(a, shape.deepProfile());
        errdefer deep.deinit();
        var fri = try Fri.build(a, shape.friProfile());
        errdefer fri.deinit();
        var arithmetic = try Arithmetic.init(a, .{ composition.circuit.graph(), deep.graph(), fri.graph() });
        errdefer arithmetic.deinit();
        self.* = .{ .allocator = a, .budget = budget, .template_id = admitted.template_id, .shape = shape, .composition = composition, .deep_graph = deep, .fri_graph = fri, .arithmetic = arithmetic };
        return self;
    }
    pub fn validateAgainst(self: *const Owned, admitted: *const Admission.Prepared, claims: Claims, limits: Limits) !void {
        const cold = try Owned.derive(self.allocator, admitted, claims, limits);
        defer cold.deinit();
        if (!std.meta.eql(self.template_id, cold.template_id) or !std.meta.eql(self.composition.circuit.identity_digest, cold.composition.circuit.identity_digest) or
            !std.meta.eql(self.deep_graph.graph().identity_digest, cold.deep_graph.graph().identity_digest) or !std.meta.eql(self.fri_graph.graph().identity_digest, cold.fri_graph.graph().identity_digest) or
            self.composition.sources.len != cold.composition.sources.len or self.shape.columns.len != cold.shape.columns.len or
            !std.mem.eql(@import("sample_point_layout.zig").Layout, self.shape.layouts, cold.shape.layouts) or !std.mem.eql(u32, self.shape.mask_logs, cold.shape.mask_logs) or !std.mem.eql(u32, self.shape.widths, cold.shape.widths))
            return error.UntrustedCallerFusedFixed;
        for (self.composition.sources, cold.composition.sources) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedCallerFusedFixed;
        for (self.shape.columns, cold.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedCallerFusedFixed;
        try self.composition.circuit.validate();
        try self.deep_graph.validate();
        try self.fri_graph.validate();
        try self.arithmetic.validate();
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        self.arithmetic.deinit();
        self.fri_graph.deinit();
        self.deep_graph.deinit();
        self.composition.deinit();
        self.shape.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
fn input(builder: *R.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const symbol = try builder.input();
    try sources.append(a, source);
    return symbol.value;
}
fn compile(a: std.mem.Allocator, admitted: *const Admission.Prepared, shape: *const Shape.Owned, public_count: usize, handles: []const core.air.components.Component) !Compiled {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    var samples = Equation.Samples{ .offsets = undefined, .lengths = undefined, .values = undefined };
    var count: usize = 0;
    for (shape.layouts) |layout| count = try std.math.add(usize, count, layout.sampleCount());
    const values = try temp.alloc(S, count);
    var at: usize = 0;
    var flat: usize = 0;
    for (shape.columns, 0..) |columns, tree| {
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.lengths[tree] = try temp.alloc(usize, columns.len);
        for (columns, 0..) |_, column| {
            const n = shape.layouts[flat].sampleCount();
            samples.offsets[tree][column] = at;
            samples.lengths[tree][column] = n;
            for (0..n) |_| {
                values[at] = try input(&builder, a, &sources, .{ .sample = @intCast(at) });
                at += 1;
            }
            flat += 1;
        }
    }
    samples.values = values;
    var draws: [@import("air/universal_challenges.zig").RELATION_COUNT][2]S = undefined;
    for (&draws, 0..) |*pair, i| {
        for (pair, 0..) |*value, j| value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * i + j) });
    }
    var word: [10]S = undefined;
    for (&word, 0..) |*value, i| value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * draws.len + i) });
    const public = try temp.alloc(S, public_count);
    for (public, 0..) |*value, i| value.* = try input(&builder, a, &sources, .{ .public_input = @intCast(i) });
    const random = try input(&builder, a, &sources, .composition);
    const seed = try input(&builder, a, &sources, .oods);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const point = R.pointFromSeed(seed);
    var accumulated = S.zero();
    const n_constraints = try Equation.recordConstraints(admitted, samples, public, draws, word, random, point, shape.mask_log, &accumulated);
    var actual: usize = 0;
    for (handles) |handle| actual += handle.nConstraints();
    if (n_constraints != actual) return error.InvalidCallerFusedRecursiveEquationCount;
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(shape.split) orelse return error.InvalidCallerFusedRecursiveGeometry);
    for (chunks, 0..) |*out, i| out.* = R.fromPartialEvals(.{ try samples.at(4, 4 * i, 0), try samples.at(4, 4 * i + 1, 0), try samples.at(4, 4 * i + 2, 0), try samples.at(4, 4 * i + 3, 0) });
    try builder.constrainZero((try R.reconstructSplitComposition(chunks, point, shape.composition_log, shape.split)).sub(accumulated));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}
