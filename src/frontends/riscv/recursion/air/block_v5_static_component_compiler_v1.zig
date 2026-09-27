//! Immutable original typed compiler view, deliberately not a verifier component.
//! It has no relations, claims, successful capture or asVerifierComponent method.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Binding = @import("universal_relation_binding.zig");
const Direct = @import("direct_constraint_program.zig");
const Geometry = @import("universal_typed_geometry.zig");
pub fn ForAirs(comptime Airs: anytype) type {
    const Setup = @import("../../prover/block_v5_packed_hash_setup_v1.zig").ForAirs(Airs);
    const Components = blk: {
        var types: [Airs.len]type = undefined;
        for (Airs, 0..) |Air, index| types[index] = struct {
            direct: Direct.Program,
            relation_plan: Binding.Binding(Air).Plan,
            parameters: [Geometry.parameterColumnCount(Air)]core.fields.m31.M31,
        };
        break :blk std.meta.Tuple(&types);
    };
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        budget: ?*Budget,
        setup_lease: Setup.Lease,
        components: Components,
        logs: [Airs.len]u32,
        pub const fixed_setup_only = true;
        pub fn init(a: std.mem.Allocator, setup: *const Setup, logs: [Airs.len]u32, parameters: anytype) !*Self {
            for (logs) |log| if (log < 1 or log > 24) return error.InvalidStaticComponentCompilerGeometry;
            var setup_lease = try setup.lease();
            errdefer setup_lease.deinit();
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.* = .{ .allocator = a, .budget = lease, .setup_lease = setup_lease, .logs = logs, .components = undefined };
            inline for (Airs, 0..) |Air, index| {
                const definition = &setup.definitions[index];
                try definition.validate();
                try setup.plans[index].validateAgainst(&definition.arena, Air.SEMANTIC_DIGEST, Binding.Binding(Air).events(definition));
                const direct = try Direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
                if (direct.constraint_count != Air.DIRECT_CONSTRAINT_COUNT) return error.InvalidStaticComponentCompiler;
                self.components[index] = .{ .direct = direct, .relation_plan = setup.plans[index], .parameters = parameters[index] };
            }
            return self;
        }
        /// Setup identity and exact parameters come from independent original
        /// admission. This view is immutable during every synchronous borrow.
        pub fn validateAgainst(self: *const Self, setup: *const Setup, logs: [Airs.len]u32, parameters: anytype) !void {
            if (try self.setup_lease.get() != setup or !std.meta.eql(self.logs, logs)) return error.UntrustedStaticComponentCompiler;
            inline for (Airs, 0..) |Air, index| {
                try setup.definitions[index].validate();
                try self.components[index].relation_plan.validateAgainst(&setup.definitions[index].arena, Air.SEMANTIC_DIGEST, Binding.Binding(Air).events(&setup.definitions[index]));
                const independent = try Direct.authenticate(&setup.definitions[index].arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
                const actual = &self.components[index].direct;
                // Only initialized instructions/constraints are compared; unused
                // fixed-capacity storage is not part of authenticated geometry.
                if (actual.semantic_format_version != independent.semantic_format_version or actual.evaluation_node_count != independent.evaluation_node_count or actual.input_count != independent.input_count or actual.node_count != independent.node_count or actual.compiled_node_count != independent.compiled_node_count or actual.constraint_count != independent.constraint_count or !std.meta.eql(actual.semantic_digest, independent.semantic_digest)) return error.UntrustedStaticComponentCompiler;
                if (!std.meta.eql(self.components[index].parameters, parameters[index])) return error.UntrustedStaticComponentCompiler;
                for (actual.nodes[0..actual.compiled_node_count], independent.nodes[0..independent.compiled_node_count]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedStaticComponentCompiler;
                for (actual.evaluation_nodes[0..actual.evaluation_node_count], independent.evaluation_nodes[0..independent.evaluation_node_count]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedStaticComponentCompiler;
                for (actual.constraints[0..actual.constraint_count], independent.constraints[0..independent.constraint_count]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedStaticComponentCompiler;
            }
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            const lease = self.budget;
            self.setup_lease.deinit();
            a.destroy(self);
            if (lease) |owner| owner.destroy();
        }
    };
}
