//! Original native word-family fixed graph pieces. No lower-parent Shape,
//! successful capture, witness/private transcript or received key is accepted.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Composition = @import("air/block_v5_word_recursive_shape_composition_v1.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Arithmetic = @import("block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
const ShapeModule = @import("block_v5_word_recursive_shape_v1.zig");
pub const Limits = ShapeModule.Limits;
pub fn ForFamily(comptime family: Composition.Family) type {
    const Spec = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_component_v1.zig").Spec else @import("../prover/block_v5_range16_component_v1.zig").Spec;
    const Admission = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig") else @import("../prover/block_v5_range16_recursive_admission_v1.zig");
    const NativeShape = ShapeModule.ForSpec(Spec);
    const Equation = Composition.ForFamily(family);
    return struct {
        pub const Shape = NativeShape.Shape;
        pub const Compiled = Equation.Compiled;
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            template_id: [32]u8,
            shape: *Shape,
            composition: Compiled,
            deep_graph: Deep.Circuit,
            fri_graph: Fri.Circuit,
            arithmetic: Arithmetic,
            pub const fixed_setup_only = true;
            pub const native_trace_trees = 3;
            pub const original_constraints = Spec.CONSTRAINT_COUNT;
            pub const complete_family_setup = false;
            /// The policy's original admission performs the full independent
            /// roster, seal, root/config/count/endpoint checks. It stays live
            /// for this synchronous call only; no policy pointers escape.
            pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared, expected: [32]u8, limits: Limits) !*Self {
                try admitted.validate(expected);
                const row_log = if (family == .ram_lanes) admitted.pin.claim.row_log else @import("../prover/block_v5_range16_v1.zig").TABLE_LOG;
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                const shape = try Shape.init(a, row_log, admitted.config, limits);
                errdefer shape.deinit();
                var composition = try Equation.compile(a, shape);
                errdefer composition.deinit();
                var deep_graph = try Deep.build(a, shape.deepProfile());
                errdefer deep_graph.deinit();
                var fri_graph = try Fri.build(a, shape.friProfile());
                errdefer fri_graph.deinit();
                var arithmetic = try Arithmetic.init(a, .{ composition.circuit.graph(), deep_graph.graph(), fri_graph.graph() });
                errdefer arithmetic.deinit();
                try admitted.validate(expected);
                self.* = .{ .allocator = a, .budget = lease, .template_id = expected, .shape = shape, .composition = composition, .deep_graph = deep_graph, .fri_graph = fri_graph, .arithmetic = arithmetic };
                return self;
            }
            pub fn validateAgainst(self: *const Self, admitted: *const Admission.Prepared, expected: [32]u8) !void {
                try admitted.validate(expected);
                const row_log = if (family == .ram_lanes) admitted.pin.claim.row_log else @import("../prover/block_v5_range16_v1.zig").TABLE_LOG;
                if (!std.meta.eql(self.template_id, expected)) return error.UntrustedWordRecursiveFixedTemplate;
                try self.shape.validateAgainst(row_log, admitted.config);
                try self.composition.validateAgainst(self.shape);
                try self.arithmetic.validate();
                try self.deep_graph.validate();
                if (!std.meta.eql(self.deep_graph.profile_digest, self.shape.deepProfile().identityDigest())) return error.UntrustedWordRecursiveDeepProfile;
                try self.fri_graph.validate();
                if (!std.meta.eql(self.fri_graph.profile_digest, self.shape.friProfile().identityDigest())) return error.UntrustedWordRecursiveFriProfile;
                try admitted.validate(expected);
            }
            pub fn requireComplete(_: *const Self) error{MissingWordRecursiveTranscriptPathsSourcesAndContext}!void {
                return error.MissingWordRecursiveTranscriptPathsSourcesAndContext;
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.budget;
                self.arithmetic.deinit();
                self.fri_graph.deinit();
                self.deep_graph.deinit();
                self.composition.deinit();
                self.shape.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
