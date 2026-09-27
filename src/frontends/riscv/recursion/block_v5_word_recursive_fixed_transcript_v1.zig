//! Original native RAM/range transcript preprocessing without proof captures.
//! Shared prefix/suffix grammars feed only the original trusted fixed emitter.
//! Public words are routing placeholders; no verifier or witness is executed.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Prefix = @import("air/block_v5_word_transcript_prefix_v1.zig");
const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
const ShapeFactory = @import("block_v5_word_recursive_shape_v1.zig");
const Roots = @import("air/blake3_root_sources.zig");
pub const Limits = Sink.Limits;
pub fn ForFamily(comptime family: Prefix.Family) type {
    const Spec = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_component_v1.zig").Spec else @import("../prover/block_v5_range16_component_v1.zig").Spec;
    const Admission = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig") else @import("../prover/block_v5_range16_recursive_admission_v1.zig");
    return struct {
        pub const Shape = ShapeFactory.ForSpec(Spec).Shape;
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            fixed: Plan,
            shape_id: [32]u8,
            template_id: [32]u8,
            retry_capacity: u32,
            limits: Limits,
            pub const fixed_setup_only = true;
            pub const native_trace_trees = 3;
            pub const external_key_and_main_roots = true;
            pub const complete_family_setup = false;
            pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared, expected: [32]u8, shape: *const Shape, capacity: u32, limits: Limits) !Self {
                try admitted.validate(expected);
                const log = if (family == .ram_lanes) admitted.pin.claim.row_log else @import("../prover/block_v5_range16_v1.zig").TABLE_LOG;
                try shape.validateAgainst(log, admitted.config);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                var fixed = try recordForShape(a, shape, capacity, limits);
                errdefer fixed.deinit();
                try admitted.validate(expected);
                return .{ .allocator = a, .lease = lease, .fixed = fixed, .shape_id = shape.seal, .template_id = expected, .retry_capacity = capacity, .limits = limits };
            }
            /// Independent reconstruction precedes fixed-plan comparison. A
            /// resealed or received plan cannot nominate its expected identity.
            pub fn validateAgainst(self: *const Self, admitted: *const Admission.Prepared, expected: [32]u8, shape: *const Shape) !void {
                try self.fixed.validate();
                var independent = try Self.derive(self.allocator, admitted, expected, shape, self.retry_capacity, self.limits);
                defer independent.deinit();
                if (!std.meta.eql(self.shape_id, independent.shape_id) or !std.meta.eql(self.template_id, independent.template_id) or
                    !std.meta.eql(self.fixed.config, independent.fixed.config) or !std.meta.eql(self.fixed.id, independent.fixed.id))
                    return error.UntrustedWordRecursiveFixedTranscript;
            }
            pub fn deinit(self: *Self) void {
                const lease = self.lease;
                self.fixed.deinit();
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        /// Routing compiler only. This cannot construct an admitted owner or
        /// complete key. Genuine derive above still requires original policy.
        pub fn recordForShape(a: std.mem.Allocator, shape: *const Shape, capacity: u32, limits: Limits) !Plan {
            try shape.validateAgainst(shape.row_log, shape.config);
            if (family == .range16 and shape.row_log != @import("../prover/block_v5_range16_v1.zig").TABLE_LOG)
                return error.InvalidRangeShapeComposition;
            if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0)
                return error.InvalidBlake3Transcript;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var r = Sink.Recorder{ .a = temp, .limits = limits };
            try Prefix.emit(family, temp, &r, Prefix.FixedValues{}, Prefix.FixedDraw);
            if (r.skipped_roots != 2) return error.InvalidNativeBlake3Transcript;
            try r.suffix(.{ .commitment = .{ .slot = 2, .source = try Roots.caller(2) } });
            var suffix: std.ArrayList(Schema.Operation) = .empty;
            try Schema.appendPcsSuffix(temp, &suffix, shape.config, shape.deepProfile(), shape.friProfile(), 4);
            for (suffix.items) |operation| try r.suffix(operation);
            try r.check();
            return Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
        }
    };
}
