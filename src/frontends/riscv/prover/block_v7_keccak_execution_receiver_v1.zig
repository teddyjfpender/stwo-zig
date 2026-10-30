//! Complete finite execution receiver for explicitly admitted shared Keccak
//! batches. Every source is freshly verified; global sums alone grant nothing.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("block_v7_execution_epoch_v1.zig");
const Old = @import("block_v7_execution_receiver_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig");
const N = @import("block_v7_native_proof_v1.zig");
const NS = @import("block_v7_native_source_v1.zig");
const BatchProof = @import("block_v7_keccak_batch_proof_v1.zig");
const BatchSource = @import("block_v7_keccak_batch_source_v1.zig");
const BatchClosure = @import("block_v7_keccak_batch_closure_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const Joint = @import("block_v7_memory_joint_proof_v1.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const Batch = struct { pin: BatchSource.Pin, proof: *const BatchProof.Proof };
pub const Input = struct {
    epoch: E.Epoch,
    entries: []const E.Entry,
    natives: []const Old.Native,
    batches: []const Batch,
    program_plan: @import("block_v5_program_table_v1.zig").Plan,
    program_roots: [2][32]u8,
    program: *const ROM.Proof,
    lookup_plan: LP.Plan,
    lookup_roots: [2][32]u8,
    lookup: struct { layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout, proof: *const Lookup.Proof },
    memory: *const Joint.Proof,
};
pub const Limits = struct { receiver: Old.Limits = .{}, batch: BatchProof.Limits = .{}, max_batches: usize = 64 };
/// Exact finite recipe request bound, derived from canonical original slots.
/// Each selected effect has Boolean caller enabler under the original AIR.
pub fn batchDemand(a: std.mem.Allocator, pin: BatchSource.Pin, limits: BatchProof.Limits) ![Schema.KIND_COUNT]u64 {
    var owners = try pin.ownerLayout(a, limits.owners);
    defer owners.deinit();
    var lookup = try @import("block_v7_keccak_window_lookup_v1.zig").Owned.init(a, pin.geometry.log_size, 0, 0, pin.geometry.x0_local_custody_version);
    defer lookup.deinit();
    var per_call: [Schema.KIND_COUNT]u64 = @splat(0);
    for (lookup.slots) |slot| {
        const table = @intFromEnum(slot.table);
        if (table >= per_call.len) return error.InvalidKeccakBatchLookupRecipe;
        per_call[table] = try std.math.add(u64, per_call[table], slot.entry_count);
    }
    var expected: [Schema.KIND_COUNT]u64 = @splat(0);
    expected[@intFromEnum(Schema.Kind.range_check_20)] = 51;
    expected[@intFromEnum(Schema.Kind.range_check_8_8)] = 1;
    expected[@intFromEnum(Schema.Kind.range_check_8_8_4)] = 1;
    if (!std.meta.eql(per_call, expected)) return error.InvalidKeccakBatchLookupRecipe;
    for (&per_call) |*count| count.* = try std.math.mul(u64, count.*, pin.geometry.call_count);
    try LP.addDemand(&per_call, try LP.sidecarMemoryDemand(try std.math.mul(u64, pin.geometry.call_count, 50)));
    return per_call;
}
pub fn For(comptime Backend: type) type {
    return struct {
        pub fn verify(a: std.mem.Allocator, trusted: Old.Trusted, input: Input, limits: Limits) !Old.Verified {
            if (trusted.profile != @import("blake3_ethereum_sha_profile.zig").execution_profile or input.natives.len == 0 or input.natives.len > limits.receiver.max_segments or input.batches.len == 0 or input.batches.len > limits.max_batches or input.entries.len > limits.receiver.max_entries) return error.InvalidKeccakExecutionRoster;
            if (input.epoch.counts[@intFromEnum(E.Family.native)] != input.natives.len or input.epoch.counts[@intFromEnum(E.Family.caller_fused)] != input.batches.len or input.epoch.counts[@intFromEnum(E.Family.caller_arithmetic)] != 0 or input.epoch.counts[@intFromEnum(E.Family.memory_joint)] != 1) return error.InvalidKeccakExecutionRoster;
            try input.epoch.requireCompleteFamilies();
            var initialized = try Initial.Owned.derive(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.receiver.initial);
            defer initialized.deinit();
            var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, trusted.elf, &initialized, limits.receiver.initial);
            defer image.deinit();
            const policy = Policy.Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = trusted.terminal, .config = trusted.config };
            try input.epoch.require(try policy.digest(), trusted.config, input.epoch.counts, input.entries, limits.receiver.max_entries);
            const natives = try a.alloc(NS.Pin, input.natives.len);
            defer a.free(natives);
            const windows = try a.alloc(Policy.Native, natives.len);
            defer a.free(windows);
            const external = try a.alloc(u32, natives.len);
            defer a.free(external);
            @memset(external, 0);
            for (input.natives, natives, 0..) |native, *pin, i| {
                pin.* = native.pin;
                if (pin.index != i or pin.template.execution_profile != trusted.profile) return error.UntrustedKeccakNativeRoster;
            }
            var demand: [Schema.KIND_COUNT]u64 = @splat(0);
            var caller_windows: usize = 0;
            for (input.batches, 0..) |batch, i| {
                if (batch.pin.index != i) return error.UntrustedKeccakBatchRoster;
                _ = try batch.pin.require(a, natives, input.epoch, input.entries, limits.batch.owners);
                for (batch.pin.windows) |window| {
                    if (external[window.execution_index] != 0) return error.DuplicateKeccakBatchOwner;
                    external[window.execution_index] = window.calls;
                    caller_windows += 1;
                }
                try LP.addDemand(&demand, try batchDemand(a, batch.pin, limits.batch));
            }
            for (natives, windows, 0..) |native, *window, i| {
                if (native.template.external_retirements != external[i]) return error.UnownedKeccakNativeCalls;
                window.* = .{ .shape = native.shape, .frame = native.frame, .external_retirements = external[i] };
                try LP.addDemand(&demand, try LP.nativeDemand(native.shape, external[i]));
                try LP.addDemand(&demand, try LP.sidecarMemoryDemand(native.expected_events));
            }
            try policy.validateWindows(windows);
            const plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = @intCast(natives.len), .max_requests = demand };
            if (!std.meta.eql(plan, input.lookup_plan)) return error.UntrustedKeccakLookupDemand;
            if (!std.meta.eql(input.program_plan.program_root, image.root) or input.program_plan.leaves.len != image.leaves.len) return error.UntrustedV7ProgramImage;
            for (input.program_plan.leaves, image.leaves) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedV7ProgramImage;
            const rom = try ROM.ForBackend(Backend).verifyBorrowed(a, input.program, .{ .plan = input.program_plan, .expected_program_root = image.root, .roots = input.program_roots, .epoch = input.epoch, .entries = input.entries });
            const tables = try Lookup.For(Backend).verify(a, input.lookup.proof, .{ .plan = plan, .layout = input.lookup.layout, .roots = input.lookup_roots, .epoch = input.epoch, .entries = input.entries }, limits.receiver.compact_lookup);
            const memory = try Joint.For(Backend).verify(a, policy, input.epoch, input.entries, input.memory, limits.receiver.joint_memory);
            var closure = try @import("block_v7_execution_claim_closure_v1.zig").Accumulator.init(a, natives.len, caller_windows, rom.claim, rom.fetch_count, tables, memory);
            defer closure.deinit();
            for (input.natives, 0..) |native, i| try closure.addNative(i, try N.For(Backend).verify(a, native.proof, native.pin, input.epoch, input.entries));
            for (input.batches) |batch| {
                const open = try BatchProof.ForBackend(Backend).verify(a, batch.proof, batch.pin, natives, input.epoch, input.entries, limits.batch);
                try BatchClosure.addToExecution(&closure, batch.pin, open);
            }
            const closed = try closure.finish();
            return .{ .statement = try policy.digest(), .epoch = input.epoch.digest, .cycles = trusted.terminal.final_cycle, .segments = @intCast(natives.len), .ram_events = closed.events, .program_fetches = closed.fetches, .output = trusted.terminal.output };
        }
    };
}
