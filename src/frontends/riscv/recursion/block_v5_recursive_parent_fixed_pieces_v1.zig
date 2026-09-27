//! Capture-free fixed compiler pieces. This is deliberately NOT a complete key.
//! Remaining original boundary/opening/link/roster assembly must be supplied
//! before a fixed commitment or standalone verifier authority can be emitted.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const ShapeModule = @import("block_v5_recursive_parent_shape_v1.zig");
const Composition = @import("air/block_v5_open_parent_composition_v2.zig");
const Arithmetic = @import("air/block_v5_recursive_parent_fixed_arithmetic_v1.zig");
const Transcript = @import("air/block_v5_recursive_parent_fixed_transcript_v1.zig");
const Queries = @import("air/blake3_query_links.zig");
const Paths = @import("air/blake3_stark_paths.zig");
pub const Limits = struct {
    shape: ShapeModule.Limits = .{},
    arithmetic: Arithmetic.Limits = .{},
    transcript: Transcript.Limits = .{},
};
const AdmissionLimits = Limits;
pub fn ForAdmission(comptime Admission: type) type {
    comptime if (!@hasDecl(Admission, "fixed_setup_only") or !Admission.fixed_setup_only) @compileError("fixed compiler requires independently reconstructed setup-only admission");
    return struct {
        pub const Limits = AdmissionLimits;
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            shape: *ShapeModule.Shape,
            composition: Composition.Compiled,
            arithmetic: *Arithmetic.Owned,
            transcript: Transcript.Owned,
            queries: Queries.Prepared,
            paths: Paths.FixedShape,
            pub const complete_fixed_setup = false;
            pub const complete_block_authority = false;
            pub fn init(a: std.mem.Allocator, admission: *const Admission, retry_capacity: u32, limits: AdmissionLimits) !*Self {
                try admission.validate();
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                const shape = try ShapeModule.Shape.initForAdmission(a, admission, limits.shape);
                errdefer shape.deinit();
                var composition = try Composition.compileShape(a, admission);
                errdefer composition.deinit();
                const arithmetic = try Arithmetic.Owned.init(a, shape, limits.arithmetic);
                errdefer arithmetic.deinit();
                // Exact original namespace selected by finishReplay for this parent.
                var transcript = try Transcript.Owned.init(a, admission, shape, 1_000_000, retry_capacity, limits.transcript);
                errdefer transcript.deinit();
                var queries = try Queries.build(a, transcript.fixed.fixed.query_outputs, &arithmetic.deep_graph, &arithmetic.fri_graph, shape.config.fri_config.n_queries, shape.widths.len);
                errdefer queries.deinit();
                const paths = try Paths.compileFixedShape(a, shape, &queries);
                self.* = .{ .allocator = a, .budget = lease, .shape = shape, .composition = composition, .arithmetic = arithmetic, .transcript = transcript, .queries = queries, .paths = paths };
                return self;
            }
            pub fn validateAgainst(self: *const Self, admission: *const Admission) !void {
                try self.shape.validateAgainst(admission);
                try self.composition.circuit.validate();
                try self.arithmetic.validateAgainst(self.shape);
                try self.transcript.validateAgainst(self.shape);
                if (!std.meta.eql(self.paths.shape_id, self.shape.seal)) return error.UntrustedRecursiveParentShape;
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.budget;
                self.paths.deinit();
                self.queries.deinit();
                self.transcript.deinit();
                self.arithmetic.deinit();
                self.composition.deinit();
                self.shape.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
const Default = ForAdmission(@import("block_v5_closed_input_request_shape_admission_v1.zig").Admission);
pub const Owned = Default.Owned;
