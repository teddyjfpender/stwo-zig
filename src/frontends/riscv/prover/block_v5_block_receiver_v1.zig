//! First fresh native-v5/program/initial/sorted-memory orchestration slice.
//! It intentionally has no CompleteBlock constructor: universal memory,
//! execution transitions, endpoint providers, callers and v5 exact recursion
//! must be freshly verified and closed before a complete receiver can exist.
const std = @import("std");
const core = @import("stwo_core");
const artifact = @import("block_v5_block_artifact_v1.zig");
const programs_v2 = @import("block_v5_program_native_batch_receiver_v1.zig");
const programs_v3 = @import("block_v5_program_native_batch_receiver_v3.zig");
const memory = @import("block_v5_memory_batch_receiver_v1.zig");
const endpoints = @import("block_v5_rw_endpoint_receiver_v1.zig");
const Q = core.fields.qm31.QM31;

pub const Remaining = struct {
    /// sealNativeOnly exports requests to six shared native lookup tables;
    /// their independently planned global provider proof is mandatory.
    global_native_lookup_providers: void = {},
    universal_memory_and_native_public_providers: void = {},
    opcode_transition_and_byte_tables: void = {},
    final_rw_endpoint: enum { pending, verified } = .pending,
    precompile_arithmetic_and_ordered_caller_bus: void = {},
    native_v5_exact_recursive_forest: void = {},
};
pub const VerifiedOpenCore = struct {
    native_program_initial_memory_range_fresh_verified: void = {},
    seal_digest: [32]u8,
    execution_count: u32,
    program_fetches: u64,
    memory_events: u64,
    native_open_sum: Q,
    program_provider_sum: Q,
    precompile_open_sum: Q,
    sorted_transition_sum: Q,
    remaining: Remaining = .{},
};

pub fn ForBackend(comptime Backend: type) type {
    return ForNativeBackend(Backend, false);
}
/// Canonical native-v3 path uses packed36/range16, global joins and exact recursion.
pub fn ForLightweightBackend(comptime Backend: type) type {
    return @import("block_v5_global_receiver_v1.zig").ForBackend(Backend);
}
/// Historical scoped native-v3/byte-memory qualification only.
pub fn ForLegacyMemoryLightweightBackend(comptime Backend: type) type {
    return ForNativeBackend(Backend, true);
}
fn ForNativeBackend(comptime Backend: type, comptime lightweight: bool) type {
    const programs = if (lightweight) programs_v3 else programs_v2;
    const Pins = if (lightweight) artifact.LightweightPins else artifact.Pins;
    const Inputs = if (lightweight) artifact.LightweightInputs else artifact.Inputs;
    return struct {
        pub fn verifyOpen(a: std.mem.Allocator, pins: Pins, inputs: Inputs) !VerifiedOpenCore {
            const sealed = try pins.validate();
            if ((pins.endpoints != null) != (inputs.endpoints != null))
                return error.MissingV5BlockEndpointProofs;
            const verified_program = try programs.ForBackend(Backend).verifyWithExtensions(a, pins.seal, pins.roster, sealed, pins.catalog, pins.program, pins.executions, pins.extensions, inputs.program);
            const verified_memory = if (pins.endpoints) |endpoint_pins| blk: {
                const loaded = inputs.endpoints.?;
                const closed = try endpoints.verify(Backend, a, pins.memory, endpoint_pins, inputs.public_input, .{ .initial = inputs.initial_sources, .endpoints = loaded.file }, loaded.loader, sealed);
                break :blk closed.memory;
            } else try memory.verify(Backend, a, pins.memory, inputs.public_input, inputs.initial_sources, inputs.memory, sealed);
            if (!std.meta.eql(verified_program.seal_digest, sealed.digest) or
                !std.meta.eql(verified_memory.seal_digest, sealed.digest))
                return error.UntrustedV5OpenCoreSeal;
            // Do not add different bus totals and interpret one accidental
            // zero as closure. Every remaining partition has its own fresh
            // proof/admission/census obligation in the final receiver.
            return .{ .seal_digest = sealed.digest, .execution_count = sealed.execution_instance_count, .program_fetches = verified_program.fetch_count, .memory_events = verified_memory.event_count, .native_open_sum = verified_program.native_open_sum, .program_provider_sum = verified_program.program_provider_sum, .precompile_open_sum = verified_program.precompile_open_sum, .sorted_transition_sum = verified_memory.transition_sum, .remaining = .{ .final_rw_endpoint = if (pins.endpoints != null)
                .verified
            else
                .pending } };
        }
    };
}
