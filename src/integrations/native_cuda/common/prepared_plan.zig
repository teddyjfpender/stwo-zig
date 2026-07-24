//! Descriptor-driven ownership of one compiled resident CUDA proof plan.

const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const execution_plan = @import(
    "../../../backends/cuda/runtime/execution_plan.zig",
);
const proof_ir = @import("stwo_backend_contracts").proof_program;

/// The policy owns frontend allocation cardinalities, program emission, the
/// terminal slot, and a deterministic test target. Structural lifetimes and
/// cleanup order remain identical for every AIR.
pub fn PreparedPlanFor(
    comptime Geometry: type,
    comptime Layout: type,
    comptime Topology: type,
    comptime ProofBundle: type,
    comptime Transcript: type,
    comptime Policy: type,
) type {
    comptime assertPolicy(Policy);
    return struct {
        const Self = @This();

        logical: Layout,
        quotient: Topology.Quotient,
        fri: Topology.Fri,
        decommit: Topology.Decommit,
        proof: ProofBundle,
        transcript: Transcript,
        requirement_storage: []arena.Requirement,
        proof_program: proof_ir.ProofProgram,
        cuda_plan: execution_plan.CudaPlan,

        pub fn init(
            allocator: std.mem.Allocator,
            geometry: Geometry,
        ) !Self {
            return initForTarget(
                allocator,
                geometry,
                Policy.defaultTarget(),
            );
        }

        pub fn initForTarget(
            allocator: std.mem.Allocator,
            geometry: Geometry,
            target: execution_plan.CompileOptions,
        ) !Self {
            var logical = try Layout.init(allocator, geometry);
            errdefer logical.deinit(allocator);
            try logical.validate();
            var quotient = try Topology.Quotient.init(allocator, logical);
            errdefer quotient.deinit(allocator);
            var fri = try Topology.Fri.init(allocator, logical);
            errdefer fri.deinit(allocator);
            var decommit = try Topology.Decommit.init(allocator, logical);
            errdefer decommit.deinit(allocator);
            var proof = try ProofBundle.init(
                allocator,
                logical,
                decommit,
            );
            errdefer proof.deinit(allocator);
            try proof.validate(decommit.assembly_words);
            const arena_requirements = try Policy.buildRequirements(
                allocator,
                geometry,
                quotient,
                fri,
                decommit,
                proof,
            );
            errdefer allocator.free(arena_requirements);
            var program = try Policy.emitProgram(
                allocator,
                geometry,
                logical,
                quotient,
                fri,
                arena_requirements,
            );
            errdefer program.deinit(allocator);
            var cuda_plan = try execution_plan.CudaPlan.compile(
                allocator,
                program,
                target,
            );
            errdefer cuda_plan.deinit(allocator);
            if (cuda_plan.arena_plan.total_words > Policy.maxTotalWords())
                return error.SizeOverflow;
            return .{
                .logical = logical,
                .quotient = quotient,
                .fri = fri,
                .decommit = decommit,
                .proof = proof,
                .transcript = try Transcript.init(geometry),
                .requirement_storage = arena_requirements,
                .proof_program = program,
                .cuda_plan = cuda_plan,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.cuda_plan.deinit(allocator);
            self.proof_program.deinit(allocator);
            allocator.free(self.requirement_storage);
            self.proof.deinit(allocator);
            self.decommit.deinit(allocator);
            self.fri.deinit(allocator);
            self.quotient.deinit(allocator);
            self.logical.deinit(allocator);
            self.* = undefined;
        }

        pub fn requirements(self: *const Self) []const arena.Requirement {
            return self.requirement_storage;
        }

        pub fn proofSlot(_: *const Self) arena.SlotId {
            return Policy.proofSlot();
        }

        pub fn totalWords(self: *const Self) usize {
            return self.cuda_plan.arena_plan.total_words;
        }

        pub fn instantiateArenaPlan(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!arena.Plan {
            return self.cuda_plan.instantiateArenaPlan(allocator);
        }

        pub fn schedule(
            self: *const Self,
        ) []const execution_plan.ScheduledNode {
            return self.cuda_plan.schedule;
        }
    };
}

fn assertPolicy(comptime Policy: type) void {
    inline for (&.{
        "buildRequirements",
        "emitProgram",
        "proofSlot",
        "maxTotalWords",
        "defaultTarget",
    }) |name| {
        if (!@hasDecl(Policy, name))
            @compileError("CUDA plan policy is missing " ++ name);
    }
}
