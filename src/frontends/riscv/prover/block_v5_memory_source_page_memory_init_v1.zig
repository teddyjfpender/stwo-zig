//! Select the genuine source PAGE receiver inside the original global loop.
//! No caller-supplied Open/Scoped receipt enters this initialization boundary.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Page = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Admission = @import("block_v5_memory_source_page_transition_admission_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Source = struct { owner: *Page.Owner, loader: Page.Loader };
pub fn ForStack(comptime Stack: type) type {
    return struct {
        const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
        pub fn init(comptime Backend: type, a: std.mem.Allocator, pins: Memory.Pins, public_input: []const u8, source: Source, loader: Memory.Loader, sealed: Seal.Sealed) !Memory.ForBackend(Backend) {
            comptime if (!Stack.is_capacity or Backend != Cpu) @compileError("source PAGE global path requires explicit CPU capacity stack");
            const sorted = switch (pins.memory) {
                .lanes => |value| value,
                .word => return error.NoncanonicalSourcePageTransitionMemory,
            };
            try Memory.admitPins(a, pins, sealed);
            try Admission.sameMemory(sorted, source.owner.memory);
            if (!std.meta.eql(sealed, source.owner.context.base)) return error.UntrustedSourcePageTransitionSeal;
            try Admission.requirePublicInput(sorted.source.initial.public_input_len, sorted.source.initial.public_input_sha256, public_input);
            if (try Admission.eventCensus(pins, sealed.register_custody_mode) != sorted.expected_total_events) return error.UntrustedSourcePageTransitionCensus;
            const fresh = try source.owner.verify(a, source.loader);
            try Admission.requireSource(fresh, sorted, sealed);
            const parts = try a.alloc(Memory.ExecutionBytes, pins.executions.len);
            for (parts, 0..) |*part, index| part.* = .{ .index = @intCast(index), .event_count = 0, .request_count = 0, .max_requests = 0, .sum = @import("stwo_core").fields.qm31.QM31.zero() };
            // The same private semantic conversion as the actual transition
            // receiver, justified here by original PAGE/lane/range verification.
            // Original TableJoin still closes register and all provider equations.
            return .{ .a = a, .pins = pins, .sealed = sealed, .loader = loader, .byte_parts = parts, .fresh_memory = .{
                .transition_sum = fresh.transition_sum,
                .register_endpoints_verified = false,
                .register_endpoint_count = 0,
                .event_count = fresh.events,
                .first_touch_count = fresh.first_touches,
                .endpoint_count = fresh.endpoints,
                .range_count = fresh.range_requests,
                .memory_instances = fresh.memory_instances,
                .range_shards = fresh.range_shards,
                .initial_rw_root = fresh.initial_root,
                .final_rw_root = fresh.final_root,
                .sealed_digest = fresh.base_seal,
                .memory_plan_digest = fresh.memory_plan,
            } };
        }
    };
}
