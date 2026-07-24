//! AIR-neutral lifecycle and scheduled dispatch for a resident CUDA proof.

const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const execution_plan = @import(
    "../../../backends/cuda/runtime/execution_plan.zig",
);
const scheduled_executor = @import("scheduled_executor.zig");

/// `Hooks` owns request admission, canonical frontend state, target identity,
/// and stage implementations. This layer owns the compiled-plan lifecycle,
/// geometry validation, and schedule dispatch.
pub fn PipelineFor(
    comptime RequestType: type,
    comptime GeometryType: type,
    comptime StructuralPlan: type,
    comptime CanonicalState: type,
    comptime Hooks: type,
) type {
    comptime assertHooks(Hooks);
    return struct {
        const Self = @This();

        pub const Request = RequestType;
        pub const Geometry = GeometryType;
        pub const BundleDescriptor = Hooks.BundleDescriptor;

        pub const PreparedPlan = struct {
            structural: StructuralPlan,
            canonical: CanonicalState,

            pub fn init(
                allocator: std.mem.Allocator,
                geometry: Geometry,
                target: execution_plan.CompileOptions,
            ) !PreparedPlan {
                var structural = try StructuralPlan.initForTarget(
                    allocator,
                    geometry,
                    target,
                );
                errdefer structural.deinit(allocator);
                return .{
                    .structural = structural,
                    .canonical = try Hooks.initCanonical(
                        allocator,
                        geometry,
                    ),
                };
            }

            pub fn deinit(
                self: *PreparedPlan,
                allocator: std.mem.Allocator,
            ) void {
                Hooks.deinitCanonical(&self.canonical, allocator);
                self.structural.deinit(allocator);
                self.* = undefined;
            }

            pub fn requirements(
                self: *const PreparedPlan,
            ) []const arena.Requirement {
                return self.structural.requirements();
            }

            pub fn proofSlot(self: *const PreparedPlan) arena.SlotId {
                return self.structural.proofSlot();
            }

            pub fn instantiateArenaPlan(
                self: *const PreparedPlan,
                allocator: std.mem.Allocator,
            ) std.mem.Allocator.Error!arena.Plan {
                return self.structural.instantiateArenaPlan(allocator);
            }

            pub fn schedule(
                self: *const PreparedPlan,
            ) []const execution_plan.ScheduledNode {
                return self.structural.schedule();
            }

            pub fn cacheKey(self: *const PreparedPlan) [32]u8 {
                return self.structural.cuda_plan.cache_key;
            }

            pub fn graphsEnabled(self: *const PreparedPlan) bool {
                return self.structural.cuda_plan.target.enable_graphs;
            }
        };

        pub fn admit(request: Request) !Geometry {
            return Hooks.admit(request);
        }

        pub fn prepare(
            allocator: std.mem.Allocator,
            geometry: Geometry,
            target: execution_plan.CompileOptions,
        ) !PreparedPlan {
            return PreparedPlan.init(allocator, geometry, target);
        }

        pub fn planTarget(
            session: anytype,
        ) !execution_plan.CompileOptions {
            return Hooks.planTarget(session);
        }

        pub fn validatePrepared(
            prepared: *const PreparedPlan,
            geometry: Geometry,
        ) !void {
            try requireGeometry(prepared, geometry);
        }

        pub fn ingress(
            transaction: anytype,
            prepared: *PreparedPlan,
            geometry: Geometry,
        ) !void {
            try requireGeometry(prepared, geometry);
            try Hooks.ingress(
                transaction,
                &prepared.structural,
                &prepared.canonical,
            );
        }

        pub fn executeNode(
            transaction: anytype,
            prepared: *PreparedPlan,
            geometry: Geometry,
            scheduled: execution_plan.ScheduledNode,
        ) !void {
            try requireGeometry(prepared, geometry);
            return Scheduled.executeNode(
                transaction,
                prepared,
                geometry,
                scheduled,
            );
        }

        fn requireGeometry(
            prepared: *const PreparedPlan,
            geometry: Geometry,
        ) !void {
            if (!std.meta.eql(
                prepared.structural.logical.geometry,
                geometry,
            )) {
                return error.InvalidKernelDescriptor;
            }
        }

        const Adapter = struct {
            pub const PreparedPlan = Self.PreparedPlan;
            pub const Geometry = GeometryType;

            pub fn program(
                prepared: *const PreparedPlan,
            ) *const @import(
                "stwo_backend_contracts",
            ).proof_program.ProofProgram {
                return &prepared.structural.proof_program;
            }

            pub fn traceGeneration(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.traceGeneration(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }

            pub fn traceCommit(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.traceCommit(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }

            pub fn constraintEvaluation(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.constraintEvaluation(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }

            pub fn oods(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.oods(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }

            pub fn quotient(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.quotient(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }

            pub fn friCommit(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.friCommit(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }

            pub fn pow(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.pow(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }

            pub fn decommit(
                transaction: anytype,
                prepared: *PreparedPlan,
                _: Geometry,
            ) !void {
                try Hooks.decommit(
                    transaction,
                    &prepared.structural,
                    &prepared.canonical,
                );
            }
        };

        const Scheduled = scheduled_executor.ExecutorFor(Adapter);
    };
}

fn assertHooks(comptime Hooks: type) void {
    inline for (&.{
        "admit",
        "BundleDescriptor",
        "planTarget",
        "initCanonical",
        "deinitCanonical",
        "ingress",
        "traceGeneration",
        "traceCommit",
        "constraintEvaluation",
        "oods",
        "quotient",
        "friCommit",
        "pow",
        "decommit",
    }) |name| {
        if (!@hasDecl(Hooks, name))
            @compileError("CUDA pipeline hooks are missing " ++ name);
    }
}
