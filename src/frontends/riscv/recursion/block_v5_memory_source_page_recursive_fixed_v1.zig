//! Complete original PAGE composition/DEEP/FRI fixed graph pieces. Public graph
//! policy is independent; missing transcript/path/source/context ports reject
//! full family setup. No capture, success token or received key is fabricated.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const Shape = @import("block_v5_memory_source_page_recursive_shape_v1.zig");
const Equation = @import("air/block_v5_memory_source_page_shape_composition_v1.zig");
const Masks = @import("air/block_v5_memory_source_page_shape_masks_v1.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Arithmetic = @import("block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
const Layout = @import("sample_point_layout.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Native = Shape.ForKind(kind);
    const Admitted = Admission.ForKind(kind).Prepared;
    return struct {
        pub const Profile = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            config: core.pcs.PcsConfig,
            columns: [10][]u32,
            trees: [10]Deep.TreeProfile,
            layouts: []Layout.Layout,
            widths: []u32,
            mask_log: u32,
            lifting_log: u32,
            pub fn init(a: std.mem.Allocator, native: *const Native.Owned, config: core.pcs.PcsConfig) !*Self {
                const geometry = try native.geometryView();
                try Native.validateLogs(native.logViews(), geometry.geometry, native.limits);
                _ = try core.fri.FriConfig.init(config.fri_config.log_last_layer_degree_bound, config.fri_config.log_blowup_factor, config.fri_config.n_queries);
                if (config.fri_config.fold_step == 0 or config.fri_config.fold_step > Fri.MAX_FOLD_STEP or config.fri_config.n_queries == 0 or config.fri_config.n_queries > 128 or config.pow_bits > 256) return error.InvalidPageShapePcsConfig;
                const mask_log = core.verifier_types.compositionMaskLogSize(geometry.constraint_log, geometry.split) orelse return error.InvalidPageShapePcsGeometry;
                const point = core.circle.SECURE_FIELD_CIRCLE_GEN;
                const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
                const previous = point.sub(.{ .x = core.fields.qm31.QM31.fromBase(step.x), .y = core.fields.qm31.QM31.fromBase(step.y) });
                var masks = try Masks.derive(kind, a, geometry.geometry, native.logViews(), .{ .max_columns = native.limits.max_columns }, point, mask_log);
                defer masks.deinitDeep(a);
                const composition_count = core.verifier_types.compositionColumnCount(geometry.split, 4) orelse return error.InvalidPageShapePcsGeometry;
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                self.* = .{ .allocator = a, .budget = lease, .config = config, .columns = @splat(&.{}), .trees = undefined, .layouts = &.{}, .widths = &.{}, .mask_log = mask_log, .lifting_log = try std.math.add(u32, mask_log, config.fri_config.log_blowup_factor) };
                errdefer self.freeStorage();
                var layouts: std.ArrayList(Layout.Layout) = .empty;
                defer layouts.deinit(a);
                for (native.logs, masks.items, self.columns[0..9]) |logs, columns, *extended| {
                    if (logs.len != columns.len) return error.InvalidPageShapePcsGeometry;
                    extended.* = try a.alloc(u32, logs.len);
                    for (logs, columns, extended.*) |log, points, *out| {
                        out.* = try std.math.add(u32, log, config.fri_config.log_blowup_factor);
                        try layouts.append(a, try Layout.classifyColumn(points, point, previous));
                    }
                }
                self.columns[9] = try a.alloc(u32, composition_count);
                @memset(self.columns[9], self.lifting_log);
                try layouts.appendNTimes(a, .current, composition_count);
                self.layouts = try layouts.toOwnedSlice(a);
                for (&self.trees, self.columns) |*tree, columns| tree.* = .{ .column_log_sizes = columns };
                var widths: std.ArrayList(u32) = .empty;
                defer widths.deinit(a);
                var remaining = self.lifting_log;
                const terminal = try std.math.add(u32, config.fri_config.log_blowup_factor, config.fri_config.log_last_layer_degree_bound);
                while (remaining > terminal) {
                    const shift = @min(config.fri_config.fold_step, remaining - terminal);
                    try widths.append(a, @as(u32, 1) << @intCast(shift));
                    remaining -= shift;
                }
                self.widths = try widths.toOwnedSlice(a);
                try self.deepProfile().validate();
                try self.friProfile().validate();
                return self;
            }
            pub fn deepProfile(self: *const Self) Deep.Profile {
                return .{ .trees = &self.trees, .sample_layouts = self.layouts, .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .query_count = @intCast(self.config.fri_config.n_queries) };
            }
            pub fn friProfile(self: *const Self) Fri.Profile {
                return .{ .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .log_last_layer_degree_bound = self.config.fri_config.log_last_layer_degree_bound, .fold_widths = self.widths, .query_count = @intCast(self.config.fri_config.n_queries) };
            }
            fn freeStorage(self: *Self) void {
                for (self.columns) |columns| self.allocator.free(columns);
                self.allocator.free(self.layouts);
                self.allocator.free(self.widths);
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.budget;
                self.freeStorage();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            native: *Native.Owned,
            profile: *Profile,
            composition: Equation.ForKind(kind).Compiled,
            deep_graph: Deep.Circuit,
            fri_graph: Fri.Circuit,
            arithmetic: Arithmetic,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            pub fn derive(a: std.mem.Allocator, admitted: *const Admitted, expected: [32]u8, public_claims: Semantic.Claims, limits: Shape.Limits) !*Self {
                try admitted.validate(expected);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                const native = try Native.Owned.derive(a, admitted, expected, public_claims, limits);
                errdefer native.deinit();
                const profile = try Profile.init(a, native, admitted.config);
                errdefer profile.deinit();
                var composition = try Equation.ForKind(kind).compile(a, native);
                errdefer composition.deinit();
                var deep_graph = try Deep.build(a, profile.deepProfile());
                errdefer deep_graph.deinit();
                var fri_graph = try Fri.build(a, profile.friProfile());
                errdefer fri_graph.deinit();
                var arithmetic = try Arithmetic.init(a, .{ composition.circuit.graph(), deep_graph.graph(), fri_graph.graph() });
                errdefer arithmetic.deinit();
                try admitted.validate(expected);
                self.* = .{ .allocator = a, .budget = lease, .native = native, .profile = profile, .composition = composition, .deep_graph = deep_graph, .fri_graph = fri_graph, .arithmetic = arithmetic };
                return self;
            }
            pub fn validateAgainst(self: *const Self, admitted: *const Admitted, expected: [32]u8, public_claims: Semantic.Claims) !void {
                try self.native.validateAgainst(admitted, expected, public_claims);
                const independent = try Profile.init(self.allocator, self.native, admitted.config);
                defer independent.deinit();
                try self.composition.validateAgainst(self.native);
                try self.arithmetic.validate();
                try self.deep_graph.validate();
                try self.fri_graph.validate();
                if (!std.meta.eql(self.profile.deepProfile().identityDigest(), independent.deepProfile().identityDigest()) or !std.meta.eql(self.profile.friProfile().identityDigest(), independent.friProfile().identityDigest()) or !std.meta.eql(self.deep_graph.profile_digest, independent.deepProfile().identityDigest()) or !std.meta.eql(self.fri_graph.profile_digest, independent.friProfile().identityDigest())) return error.UntrustedPageShapeFixedProfile;
                try admitted.validate(expected);
            }
            pub fn requireComplete(_: *const Self) error{MissingPageRecursiveTranscriptPathsSourcesAndContext}!void {
                return error.MissingPageRecursiveTranscriptPathsSourcesAndContext;
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.budget;
                self.arithmetic.deinit();
                self.fri_graph.deinit();
                self.deep_graph.deinit();
                self.composition.deinit();
                self.profile.deinit();
                self.native.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
