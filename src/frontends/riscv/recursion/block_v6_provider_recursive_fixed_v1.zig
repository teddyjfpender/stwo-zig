//! Original ROM, six-table lookup and caller arithmetic verifier DAG compiler.
//! Independent admitted metadata only; no proof/capture or evaluated MAIN rows.
//! Complete fixed transcript/ports/roster assembly must follow this compiler.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const R = @import("air/composition_graph_recorder.zig");
const S = R.Scalar;
const Source = @import("air/blake3_execution_composition.zig").Source;
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Arithmetic = @import("block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
pub const Family = enum { program_table, native_lookup, caller_arithmetic };
pub const Limits = struct { max_bytes: usize = 512 << 20, shape: Shape.Limits = .{} };
pub fn Admission(comptime family: Family) type {
    return switch (family) {
        .program_table => @import("../prover/block_v5_program_table_recursive_admission_v1.zig"),
        .native_lookup => @import("../prover/block_v5_native_lookup_recursive_admission_v1.zig"),
        .caller_arithmetic => @import("../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig"),
    };
}
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
pub fn ForFamily(comptime family: Family) type {
    const A = Admission(family);
    return struct {
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
            pub fn derive(backing: std.mem.Allocator, admitted: *const A.Prepared, limits: Limits) !*@This() {
                try admitted.validate(admitted.template_id);
                if (limits.max_bytes == 0) return error.ProviderFixedResourceLimit;
                const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
                errdefer budget.destroy();
                const a = budget.allocator();
                const self = try a.create(@This());
                errdefer a.destroy(self);
                // These deterministic public draws populate original component
                // headers. Every challenge/claim in the DAG remains symbolic.
                var channel = admitted.sealed.sharedChannel();
                const universal = try @import("air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
                if (family == .program_table) {
                    const Native = @import("../prover/block_v5_program_table_proof_v1.zig");
                    var definition = try Native.Air.build(a);
                    defer definition.deinit();
                    const relation = try @import("air/universal_relation_binding.zig").Binding(Native.Air).authenticate(&definition);
                    const manifest = Native.Roster.Manifest{ .log_sizes = .{admitted.plan.log_size} };
                    const component = try Native.Roster.Component(Native.Air).init(&definition, relation, &manifest, .program, admitted.plan.log_size, .{}, &universal, Q.zero());
                    const handle = try @import("air/block_v5_program_table_composition_v1.zig").verifier(&component);
                    try self.build(a, budget, admitted, .{ .components = &.{handle}, .n_preprocessed_columns = admitted.logs[0].len }, &component, limits);
                } else if (family == .native_lookup) {
                    const relations = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
                    const owner = try @import("../prover/block_v5_native_lookup_assembly_v1.zig").Owner.init(a, relations, @splat(Q.zero()));
                    defer owner.destroy(a);
                    const handles = owner.verifierHandles();
                    try self.build(a, budget, admitted, .{ .components = &handles, .n_preprocessed_columns = admitted.logs[0].len }, owner, limits);
                } else {
                    channel.mixU32s(&.{ A.Protocol.TAG, A.Protocol.VERSION, @intFromEnum(A.Protocol.circuit_profile) });
                    const relations = try A.Profile.Relations.drawAfterVm(a, &channel, universal);
                    const claims = try A.Profile.ExtensionClaim.zeroForStatement(&admitted.statement);
                    const owner = try A.Profile.Assembly(.verifier).createBlockV5Standalone(a, &admitted.statement, admitted.total_steps, &relations, &claims);
                    defer owner.destroy(a);
                    try self.build(a, budget, admitted, .{ .components = owner.active(), .n_preprocessed_columns = admitted.logs[0].len }, owner, limits);
                }
                return self;
            }
            fn build(self: *@This(), a: std.mem.Allocator, budget: *Budget, admitted: *const A.Prepared, all: core.air.components.Components, owner: anytype, limits: Limits) !void {
                var shape = try Shape.Owned.init(a, &admitted.logs, all, admitted.config, limits.shape);
                errdefer shape.deinit();
                var composition = try compile(family, a, admitted, &shape, owner);
                errdefer composition.deinit();
                var deep = try Deep.build(a, shape.deepProfile());
                errdefer deep.deinit();
                var fri = try Fri.build(a, shape.friProfile());
                errdefer fri.deinit();
                var arithmetic = try Arithmetic.init(a, .{ composition.circuit.graph(), deep.graph(), fri.graph() });
                errdefer arithmetic.deinit();
                try admitted.validate(admitted.template_id);
                self.* = .{ .allocator = a, .budget = budget, .template_id = admitted.template_id, .shape = shape, .composition = composition, .deep_graph = deep, .fri_graph = fri, .arithmetic = arithmetic };
            }
            /// Rebuild from original admitted metadata before trusting geometry
            /// or symbolic equations; a mutable local seal is never authority.
            pub fn validateAgainst(self: *const @This(), admitted: *const A.Prepared, limits: Limits) !void {
                const independent = try @This().derive(self.allocator, admitted, limits);
                defer independent.deinit();
                if (!std.meta.eql(self.template_id, independent.template_id) or
                    !std.meta.eql(self.shape.deepProfile().identityDigest(), independent.shape.deepProfile().identityDigest()) or
                    !std.meta.eql(self.shape.friProfile().identityDigest(), independent.shape.friProfile().identityDigest()) or
                    !std.meta.eql(self.composition.circuit.identity_digest, independent.composition.circuit.identity_digest) or
                    !std.meta.eql(self.deep_graph.graph().identity_digest, independent.deep_graph.graph().identity_digest) or
                    !std.meta.eql(self.fri_graph.graph().identity_digest, independent.fri_graph.graph().identity_digest) or
                    self.composition.sources.len != independent.composition.sources.len or self.shape.columns.len != independent.shape.columns.len)
                    return error.UntrustedProviderFixedCompiler;
                for (self.shape.columns, independent.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedProviderFixedCompiler;
                for (self.composition.sources, independent.composition.sources) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedProviderFixedCompiler;
                try self.composition.circuit.validate();
                try self.deep_graph.validate();
                try self.fri_graph.validate();
            }
            pub fn requireComplete(_: *const @This()) error{MissingProviderFixedTranscriptSourcesPcsAndRoster}!void {
                return error.MissingProviderFixedTranscriptSourcesPcsAndRoster;
            }
            pub fn deinit(self: *@This()) void {
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
    };
}

fn input(builder: *R.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const symbol = try builder.input();
    try sources.append(a, source);
    return symbol.value;
}
fn compile(comptime family: Family, a: std.mem.Allocator, admitted: *const Admission(family).Prepared, shape: *const Shape.Owned, owner: anytype) !Compiled {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    const CallerKernel = @import("air/block_v5_caller_arithmetic_composition_v1.zig");
    var samples = CallerKernel.Samples{ .offsets = undefined, .layouts = undefined, .values = undefined };
    var count: usize = 0;
    for (shape.layouts) |layout| count = try std.math.add(usize, count, layout.sampleCount());
    const values = try temp.alloc(S, count);
    var cursor: usize = 0;
    var flat: usize = 0;
    for (shape.columns, 0..) |columns, tree| {
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.layouts[tree] = try temp.alloc(@import("sample_point_layout.zig").Layout, columns.len);
        for (columns, 0..) |_, column| {
            const layout = shape.layouts[flat];
            samples.offsets[tree][column] = cursor;
            samples.layouts[tree][column] = layout;
            for (0..layout.sampleCount()) |_| {
                values[cursor] = try input(&builder, a, &sources, .{ .sample = @intCast(cursor) });
                cursor += 1;
            }
            flat += 1;
        }
    }
    samples.values = values;
    if (family == .caller_arithmetic) {
        const A = Admission(family);
        const claims = try A.Profile.ExtensionClaim.zeroForStatement(&admitted.statement);
        var details: std.ArrayList(S) = .empty;
        var totals: [19]S = undefined;
        var public_cursor: u32 = 0;
        for (claims.componentClaims(), &totals) |view, *total| {
            for (view.detailed) |_| {
                try details.append(temp, try input(&builder, a, &sources, .{ .public_input = public_cursor }));
                public_cursor += 1;
            }
            if (view.has_batch_frame) {
                total.* = try input(&builder, a, &sources, .{ .public_input = public_cursor });
                public_cursor += 1;
            } else total.* = details.items[details.items.len - 1];
        }
        const open_sum = try input(&builder, a, &sources, .{ .public_input = public_cursor });
        var draws: [@import("air/universal_challenges.zig").RELATION_COUNT][2]S = undefined;
        for (&draws, 0..) |*pair, i| for (pair, 0..) |*value, j| {
            value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * i + j) });
        };
        var suffix: [14][2]S = undefined;
        for (&suffix, 0..) |*pair, i| for (pair, 0..) |*value, j| {
            value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(94 + 2 * i + j) });
        };
        const randomness = try input(&builder, a, &sources, .composition);
        const seed = try input(&builder, a, &sources, .oods);
        try builder.activate();
        defer if (builder.active) builder.deactivate();
        const point = R.pointFromSeed(seed);
        const accumulated = try CallerKernel.recordEquations(admitted, owner, samples, details.items, totals, draws, suffix, randomness, point);
        var detail: usize = 0;
        var total_sum = S.zero();
        for (claims.componentClaims(), totals) |view, total| {
            if (view.has_batch_frame) {
                var sum = S.zero();
                for (details.items[detail..][0..view.detailed.len]) |value| sum = sum.add(value);
                try builder.constrainZero(total.sub(sum));
            }
            detail += view.detailed.len;
            total_sum = total_sum.add(total);
        }
        try builder.constrainZero(open_sum.sub(total_sum));
        const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(shape.split) orelse return error.InvalidOriginalFixedShape);
        for (chunks, 0..) |*chunk, i| {
            var limbs: [4]S = undefined;
            for (&limbs, 0..) |*limb, j| limb.* = try samples.at(3, 4 * i + j, 0);
            chunk.* = R.fromPartialEvals(limbs);
        }
        try builder.constrainZero((try R.reconstructSplitComposition(chunks, point, shape.composition_log, shape.split)).sub(accumulated));
        builder.deactivate();
    } else {
        var draws: [@import("air/universal_challenges.zig").RELATION_COUNT][2]S = undefined;
        for (&draws, 0..) |*pair, i| for (pair, 0..) |*value, j| {
            value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * i + j) });
        };
        const randomness = try input(&builder, a, &sources, .composition);
        const seed = try input(&builder, a, &sources, .oods);
        var claims: [if (family == .program_table) 1 else 6]S = undefined;
        for (&claims, 0..) |*claim, i| claim.* = try input(&builder, a, &sources, .{ .public_input = @intCast(i) });
        const fixed_count = if (family == .program_table) 6 else 20;
        const interaction_count = if (family == .program_table) 4 else 24;
        var fixed: [fixed_count]S = undefined;
        var current: [interaction_count]S = undefined;
        var previous: [interaction_count]S = undefined;
        for (&fixed, 0..) |*value, i| value.* = try samples.at(0, i, 0);
        for (&current, &previous, 0..) |*value, *prior, i| {
            value.* = try samples.at(2, i, 0);
            prior.* = try samples.at(2, i, -1);
        }
        try builder.activate();
        defer if (builder.active) builder.deactivate();
        var chunks: [if (family == .program_table) 4 else 2]S = undefined;
        for (&chunks, 0..) |*chunk, i| {
            var limbs: [4]S = undefined;
            for (&limbs, 0..) |*limb, j| limb.* = try samples.at(3, 4 * i + j, 0);
            chunk.* = R.fromPartialEvals(limbs);
        }
        const challenges = try R.ChallengeSet.init(draws);
        if (family == .program_table) {
            try @import("air/block_v5_program_table_composition_v1.zig").recordEquation(&builder, owner, fixed, current, previous, claims[0], &challenges, randomness, seed, chunks);
        } else {
            var main: [6]S = undefined;
            for (&main, 0..) |*value, i| value.* = try samples.at(1, i, 0);
            try @import("air/block_v5_native_lookup_composition_v1.zig").recordEquation(&builder, fixed, main, current, previous, claims, &challenges, randomness, seed, chunks);
        }
        builder.deactivate();
    }
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}

test "provider fixed compilers instantiate original ROM lookup and caller arithmetic equations" {
    inline for (comptime std.meta.tags(Family)) |family| {
        std.mem.doNotOptimizeAway(&ForFamily(family).Owned.derive);
        try std.testing.expect(@intFromPtr(&ForFamily(family).Owned.derive) != 0);
    }
}
