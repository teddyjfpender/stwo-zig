//! Independently derived native public supplier schedule. Roots, transcript
//! statement words and original equation inputs stay external to fixed setup.
//! Original native admission and fresh verification remain separate duties.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Word = @import("block_v5_word_recursive_fixed_v1.zig");
const Transcript = @import("block_v5_word_recursive_fixed_transcript_v1.zig");
const Schedule = @import("air/block_v5_word_public_schedule_v1.zig");
pub fn ForFamily(comptime family: Schedule.Family) type {
    const Native = Word.ForFamily(family);
    const TypedTranscript = Transcript.ForFamily(family);
    const Admission = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig") else @import("../prover/block_v5_range16_recursive_admission_v1.zig");
    const Bus = if (family == .ram_lanes) @import("block_v5_ram_lanes_recursive_public_bus_v1.zig") else @import("block_v5_range16_recursive_public_bus_v1.zig");
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
            pub fn derive(a: std.mem.Allocator, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, transcript: *const TypedTranscript.Owned) !Self {
                try native.validateAgainst(admitted, expected);
                try transcript.validateAgainst(admitted, expected, native.shape);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const queries = std.math.cast(u32, native.shape.config.fri_config.n_queries) orelse return error.InvalidWordPublicQueryCount;
                const wires = try Schedule.For(family, Bus).collect(a, &transcript.fixed, &native.composition, queries);
                errdefer a.free(wires);
                const schedule_id = try Bus.scheduleDigest(wires);
                try native.validateAgainst(admitted, expected);
                try transcript.validateAgainst(admitted, expected, native.shape);
                return .{ .allocator = a, .lease = lease, .wires = wires, .schedule_id = schedule_id, .shape_id = native.shape.seal, .transcript_id = transcript.fixed.id, .template_id = expected };
            }
            pub fn validateAgainst(self: *const Self, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, transcript: *const TypedTranscript.Owned) !void {
                var original = try Self.derive(self.allocator, native, admitted, expected, transcript);
                defer original.deinit();
                if (!std.meta.eql(self.template_id, original.template_id) or !std.meta.eql(self.shape_id, original.shape_id) or !std.meta.eql(self.transcript_id, original.transcript_id) or !std.meta.eql(self.schedule_id, original.schedule_id) or self.wires.len != original.wires.len) return error.UntrustedWordFixedPublicSchedule;
                for (self.wires, original.wires) |actual, wire| if (!std.meta.eql(actual, wire)) return error.UntrustedWordFixedPublicSchedule;
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
