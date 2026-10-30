//! Independently admitted B6JP-v3 geometry and original verifier DAGs.
//! No proof, capture, witness values or verifier-success token is accepted.
//! Transcript/source/PCS row assembly is still required for a complete key.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Admission = @import("../prover/block_v6_partitioned_recursive_admission_v1.zig");
const Claims = @import("block_v6_partitioned_public_bus_v1.zig").Claims;
const Components = @import("air/block_v6_partitioned_components_v1.zig");
const Equation = @import("air/block_v6_partitioned_composition_v1.zig");
const R = @import("air/composition_graph_recorder.zig");
const S = R.Scalar;
const Source = @import("air/blake3_execution_composition.zig").Source;
const Layout = @import("sample_point_layout.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Arithmetic = @import("block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
pub const Limits = struct { max_bytes: usize = 512 << 20, max_columns: usize = 1 << 16 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    template_id: [32]u8,
    config: core.pcs.PcsConfig,
    columns: []const []const u32,
    trees: []Deep.TreeProfile,
    layouts: []Layout.Layout,
    widths: []u32,
    mask_log: u32,
    lifting_log: u32,
    composition_log: u32,
    split: u32,
    composition: R.Circuit,
    sources: []Source,
    deep_graph: Deep.Circuit,
    fri_graph: Fri.Circuit,
    arithmetic: Arithmetic,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = false;

    pub fn derive(backing: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Claims, limits: Limits) !*Owned {
        try admitted.validate(admitted.template_id);
        // Public claims select no sample geometry. They are validated and used
        // only by original component headers; the DAG has symbolic public ports.
        var public = try @import("block_v6_partitioned_public_bus_v1.zig").Values.init(backing, admitted, claims);
        defer public.deinit();
        if (limits.max_bytes == 0 or limits.max_columns == 0 or admitted.config.fri_config.n_queries == 0 or admitted.config.fri_config.n_queries > 128 or admitted.config.fri_config.fold_step == 0 or admitted.config.fri_config.fold_step > Fri.MAX_FOLD_STEP) return error.PartitionedFixedResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        // Original public-seal challenges make well-formed component headers.
        // No evaluation is performed and these values never enter the DAG.
        const word = try @import("../prover/block_v5_word_memory_protocol_v1.zig").Challenges.draw(temp, admitted.native.sealed);
        const memory = try @import("../prover/block_memory_relation_v2.zig").Challenges.draw(temp, admitted.native.sealed);
        var owner = try Components.Owner.initForClaims(temp, admitted, claims.projection, claims.memory, &word, &memory);
        defer owner.deinit();
        const all = owner.all(admitted.logs[0].len);
        const composition_log = all.compositionLogDegreeBound();
        const split = try all.compositionLogSplit();
        const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidPartitionedFixedGeometry;
        const current = core.circle.SECURE_FIELD_CIRCLE_GEN;
        const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
        const previous = current.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
        var masks = try all.maskPoints(temp, current, mask_log, false);
        defer masks.deinitDeep(temp);
        if (masks.items.len != admitted.tree_count) return error.InvalidPartitionedFixedGeometry;
        const columns = try temp.alloc([]const u32, admitted.tree_count + 1);
        const trees = try temp.alloc(Deep.TreeProfile, columns.len);
        var layouts: std.ArrayList(Layout.Layout) = .empty;
        var lifting: u32 = 0;
        for (admitted.logs[0..admitted.tree_count], masks.items, columns[0..admitted.tree_count]) |logs, points, *out| {
            if (logs.len != points.len or try std.math.add(usize, layouts.items.len, logs.len) > limits.max_columns) return error.PartitionedFixedResourceLimit;
            const extended = try temp.alloc(u32, logs.len);
            for (logs, points, extended) |log, samples, *value| {
                value.* = try std.math.add(u32, log, admitted.config.fri_config.log_blowup_factor);
                if (samples.len != 0) lifting = @max(lifting, value.*);
                try layouts.append(temp, try Layout.classifyColumn(samples, current, previous));
            }
            out.* = extended;
        }
        const composition_count = core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidPartitionedFixedGeometry;
        if (try std.math.add(usize, layouts.items.len, composition_count) > limits.max_columns) return error.PartitionedFixedResourceLimit;
        const composition_columns = try temp.alloc(u32, composition_count);
        @memset(composition_columns, try std.math.add(u32, mask_log, admitted.config.fri_config.log_blowup_factor));
        lifting = @max(lifting, composition_columns[0]);
        columns[admitted.tree_count] = composition_columns;
        try layouts.appendNTimes(temp, .current, composition_count);
        for (trees, columns) |*tree, values| tree.* = .{ .column_log_sizes = values };
        var widths: std.ArrayList(u32) = .empty;
        var remaining = lifting;
        const terminal = try std.math.add(u32, admitted.config.fri_config.log_blowup_factor, admitted.config.fri_config.log_last_layer_degree_bound);
        while (remaining > terminal) {
            const shift = @min(admitted.config.fri_config.fold_step, remaining - terminal);
            try widths.append(temp, @as(u32, 1) << @intCast(shift));
            remaining -= shift;
        }
        var compiled = try compile(a, admitted, columns, layouts.items, composition_log, split, mask_log, all);
        errdefer compiled.circuit.deinit();
        errdefer a.free(compiled.sources);
        const deep_profile = Deep.Profile{ .trees = trees, .sample_layouts = layouts.items, .lifting_log_size = lifting, .log_blowup_factor = admitted.config.fri_config.log_blowup_factor, .query_count = @intCast(admitted.config.fri_config.n_queries) };
        var dg = try Deep.build(a, deep_profile);
        errdefer dg.deinit();
        const fri_profile = Fri.Profile{ .lifting_log_size = lifting, .log_blowup_factor = admitted.config.fri_config.log_blowup_factor, .log_last_layer_degree_bound = admitted.config.fri_config.log_last_layer_degree_bound, .query_count = @intCast(admitted.config.fri_config.n_queries), .fold_widths = widths.items };
        var fg = try Fri.build(a, fri_profile);
        errdefer fg.deinit();
        var arithmetic = try Arithmetic.init(a, .{ compiled.circuit.graph(), dg.graph(), fg.graph() });
        errdefer arithmetic.deinit();
        try admitted.validate(admitted.template_id);
        self.* = .{ .allocator = a, .budget = budget, .arena = arena, .template_id = admitted.template_id, .config = admitted.config, .columns = columns, .trees = trees, .layouts = layouts.items, .widths = widths.items, .mask_log = mask_log, .lifting_log = lifting, .composition_log = composition_log, .split = split, .composition = compiled.circuit, .sources = compiled.sources, .deep_graph = dg, .fri_graph = fg, .arithmetic = arithmetic };
        return self;
    }
    pub fn deepProfile(self: *const Owned) Deep.Profile {
        return .{ .trees = self.trees, .sample_layouts = self.layouts, .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .query_count = @intCast(self.config.fri_config.n_queries) };
    }
    pub fn friProfile(self: *const Owned) Fri.Profile {
        return .{ .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .log_last_layer_degree_bound = self.config.fri_config.log_last_layer_degree_bound, .query_count = @intCast(self.config.fri_config.n_queries), .fold_widths = self.widths };
    }
    /// Rebuild from independently admitted metadata; resealing a mutated DAG is
    /// not an authority check. This is intentionally separate from live parity.
    pub fn validateAgainst(self: *const Owned, admitted: *const Admission.Prepared, claims: Claims, limits: Limits) !void {
        if (!std.meta.eql(self.template_id, admitted.template_id) or !std.meta.eql(self.config, admitted.config)) return error.UntrustedPartitionedFixedSetup;
        const cold = try Owned.derive(self.allocator, admitted, claims, limits);
        defer cold.deinit();
        if (!std.meta.eql(self.composition.identity_digest, cold.composition.identity_digest) or !std.meta.eql(self.deep_graph.graph().identity_digest, cold.deep_graph.graph().identity_digest) or !std.meta.eql(self.fri_graph.graph().identity_digest, cold.fri_graph.graph().identity_digest) or self.sources.len != cold.sources.len or self.columns.len != cold.columns.len or self.trees.len != cold.trees.len or !std.mem.eql(Layout.Layout, self.layouts, cold.layouts) or !std.mem.eql(u32, self.widths, cold.widths)) return error.UntrustedPartitionedFixedSetup;
        if (self.mask_log != cold.mask_log or self.lifting_log != cold.lifting_log or self.composition_log != cold.composition_log or self.split != cold.split or !std.meta.eql(self.arithmetic.reference.authority_digest, cold.arithmetic.reference.authority_digest) or !std.meta.eql(self.arithmetic.plan.authority_digest, cold.arithmetic.plan.authority_digest) or self.arithmetic.boundaries.len != cold.arithmetic.boundaries.len) return error.UntrustedPartitionedFixedSetup;
        inline for (0..4) |i| {
            if (self.arithmetic.fused.fixed[i].len != cold.arithmetic.fused.fixed[i].len) return error.UntrustedPartitionedFixedSetup;
            for (self.arithmetic.fused.fixed[i], cold.arithmetic.fused.fixed[i]) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedFixedSetup;
        }
        for (self.arithmetic.boundaries, cold.arithmetic.boundaries) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedFixedSetup;
        for (self.sources, cold.sources) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedFixedSetup;
        for (self.columns, cold.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedPartitionedFixedSetup;
        for (self.trees, cold.trees) |got, want| if (!std.mem.eql(u32, got.column_log_sizes, want.column_log_sizes)) return error.UntrustedPartitionedFixedSetup;
        try self.composition.validate();
        try self.deep_graph.validate();
        try self.fri_graph.validate();
        try self.arithmetic.validate();
    }
    /// Diagnostic equality only, never an expected-key authority operation.
    pub fn validateLive(self: *const Owned, composition: *const Equation.Prepared, deep: *const Deep.Circuit, fri: *const Fri.Circuit) !void {
        if (!std.meta.eql(self.composition.identity_digest, composition.circuit.identity_digest) or !std.meta.eql(self.deep_graph.graph().identity_digest, deep.graph().identity_digest) or !std.meta.eql(self.fri_graph.graph().identity_digest, fri.graph().identity_digest) or self.sources.len != composition.sources.len) return error.UntrustedPartitionedFixedParity;
        for (self.sources, composition.sources) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedFixedParity;
    }
    pub fn requireComplete(_: *const Owned) error{MissingPartitionedFixedTranscriptSourcesPcsAndRoster}!void {
        return error.MissingPartitionedFixedTranscriptSourcesPcsAndRoster;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        self.arithmetic.deinit();
        self.fri_graph.deinit();
        self.deep_graph.deinit();
        self.composition.deinit();
        a.free(self.sources);
        self.arena.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
const Compiled = struct { circuit: R.Circuit, sources: []Source };
fn compile(a: std.mem.Allocator, admitted: *const Admission.Prepared, columns: []const []const u32, layouts: []const Layout.Layout, composition_log: u32, split: u32, mask_log: u32, all: core.air.components.Components) !Compiled {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    const Samples = struct {
        offsets: [][]usize,
        lengths: [][]usize,
        values: []S,
        pub fn at(self: @This(), tree: usize, column: usize, sample: usize) !S {
            if (tree >= self.offsets.len or column >= self.offsets[tree].len or sample >= self.lengths[tree][column]) return error.InvalidPartitionedFixedSamples;
            return self.values[self.offsets[tree][column] + sample];
        }
    };
    var samples = Samples{ .offsets = try temp.alloc([]usize, columns.len), .lengths = try temp.alloc([]usize, columns.len), .values = undefined };
    var count: usize = 0;
    for (layouts) |layout| count = try std.math.add(usize, count, layout.sampleCount());
    samples.values = try temp.alloc(S, count);
    var cursor: usize = 0;
    var flat: usize = 0;
    for (columns, 0..) |logs, tree| {
        samples.offsets[tree] = try temp.alloc(usize, logs.len);
        samples.lengths[tree] = try temp.alloc(usize, logs.len);
        for (logs, 0..) |_, column| {
            const n = layouts[flat].sampleCount();
            samples.offsets[tree][column] = cursor;
            samples.lengths[tree][column] = n;
            for (0..n) |_| {
                samples.values[cursor] = try input(&builder, a, &sources, .{ .sample = @intCast(cursor) });
                cursor += 1;
            }
            flat += 1;
        }
    }
    var draws: [@import("air/universal_challenges.zig").RELATION_COUNT][2]S = undefined;
    for (&draws, 0..) |*pair, i| for (pair, 0..) |*value, j| {
        value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * i + j) });
    };
    var word_draws: [10]S = undefined;
    for (&word_draws, 0..) |*value, i| value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * draws.len + i) });
    const public = try temp.alloc(S, try Equation.publicCount(admitted.projections.len, admitted.slots.len));
    for (public, 0..) |*value, i| value.* = try input(&builder, a, &sources, .{ .public_input = @intCast(i) });
    const random = try input(&builder, a, &sources, .composition);
    const seed = try input(&builder, a, &sources, .oods);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const point = R.pointFromSeed(seed);
    var accumulated = S.zero();
    const constraint_count = Equation.recordConstraints(admitted, samples, public, draws, word_draws, random, point, mask_log, &accumulated) catch |err| return builder.failure orelse err;
    if (builder.failure) |err| return err;
    var expected_count: usize = 0;
    for (all.components) |component| expected_count += component.nConstraints();
    if (constraint_count != expected_count) return error.InvalidPartitionedFixedConstraintCount;
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(split) orelse return error.InvalidPartitionedFixedGeometry);
    for (chunks, 0..) |*out, chunk| out.* = R.fromPartialEvals(.{ try samples.at(admitted.tree_count, 4 * chunk, 0), try samples.at(admitted.tree_count, 4 * chunk + 1, 0), try samples.at(admitted.tree_count, 4 * chunk + 2, 0), try samples.at(admitted.tree_count, 4 * chunk + 3, 0) });
    try builder.constrainZero((try R.reconstructSplitComposition(chunks, point, composition_log, split)).sub(accumulated));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    return .{ .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}
fn input(builder: *R.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const value = try builder.input();
    try sources.append(a, source);
    return value.value;
}

test "partitioned cold fixed compiler API is capture-free" {
    const F = @TypeOf(&Owned.derive);
    const ptr: F = &Owned.derive;
    std.mem.doNotOptimizeAway(ptr);
    std.mem.doNotOptimizeAway(&Owned.validateAgainst);
    std.mem.doNotOptimizeAway(&Owned.validateLive);
}
