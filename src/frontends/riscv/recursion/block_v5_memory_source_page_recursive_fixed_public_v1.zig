//! Independently admitted original PAGE public suppliers. Private component
//! values and all eight public prefix roots remain outside fixed setup.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const NativeModule = @import("block_v5_memory_source_page_recursive_fixed_v1.zig");
const TranscriptModule = @import("block_v5_memory_source_page_recursive_fixed_transcript_v1.zig");
const Composition = @import("air/block_v5_memory_source_page_composition_v1.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Native = NativeModule.ForKind(kind);
    const Transcript = TranscriptModule.ForKind(kind);
    const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    const Bus = @import("block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    return struct {
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            wires: []Bus.Wire,
            schedule_id: [32]u8,
            shape_id: [32]u8,
            transcript_id: [32]u8,
            template_id: [32]u8,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            pub fn derive(a: std.mem.Allocator, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, transcript: *const Transcript.Owned) !Self {
                try native.validateAgainst(admitted, expected, public_claims);
                try transcript.validateAgainst(admitted, expected, native, public_claims);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const queries = std.math.cast(u32, admitted.config.fri_config.n_queries) orelse return error.InvalidFusedRecursivePublicSchedule;
                const wires = try Bus.collectFixedSchedule(a, &transcript.fixed, &native.composition, transcript.layout.word_count, Composition.claimCount(kind), 8, queries, admitted.limits.max_public_wires);
                errdefer a.free(wires);
                const schedule_id = try Bus.scheduleDigest(wires);
                try native.validateAgainst(admitted, expected, public_claims);
                try transcript.validateAgainst(admitted, expected, native, public_claims);
                return .{ .allocator = a, .lease = lease, .wires = wires, .schedule_id = schedule_id, .shape_id = transcript.shape_id, .transcript_id = transcript.fixed.id, .template_id = expected };
            }
            pub fn validateAgainst(self: *const Self, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, transcript: *const Transcript.Owned) !void {
                var original = try Self.derive(self.allocator, native, admitted, expected, public_claims, transcript);
                defer original.deinit();
                if (!std.meta.eql(self.template_id, original.template_id) or !std.meta.eql(self.shape_id, original.shape_id) or !std.meta.eql(self.transcript_id, original.transcript_id) or !std.meta.eql(self.schedule_id, original.schedule_id) or self.wires.len != original.wires.len) return error.UntrustedPageFixedPublicSchedule;
                for (self.wires, original.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedPageFixedPublicSchedule;
            }
            pub fn deinit(self: *Self) void {
                const lease = self.lease;
                self.allocator.free(self.wires);
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
