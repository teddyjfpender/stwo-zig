//! Bounded warm family12 producer. Output stays provisional until fresh global
//! program/ROM closure; the sink receives proof ownership, never authority.
const std = @import("std");
const core = @import("stwo_core");
const Batch = @import("block_v5_precompile_batch_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Slots = @import("block_v5_program_extension_slots_v1.zig");
const Program = @import("block_v5_program_extension_proof_v1.zig");
const Columns = @import("block_v5_program_extension_columns_v1.zig").Columns;
const Shared = @import("block_v5_shared_first_round_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
/// First-pass proposal metadata from the independently checked arithmetic
/// record. This grants no authority; the receiver reconstructs the same ID.
pub fn firstRoundEntry(a: std.mem.Allocator, record: *const Batch.Record, config: core.pcs.PcsConfig) !Seal.Entry {
    try Protocol.validate(&record.statement, record.total_steps, config);
    try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &record.statement);
    if (!std.meta.eql(record.key_id, try Protocol.keyId(&record.statement, record.total_steps, config, record.roots[0])) or
        !std.meta.eql(record.instance_id, Protocol.instanceId(record.key_id, record.execution.instance_id, record.execution.index, record.roots)))
        return error.UntrustedV5WarmProgramRecord;
    const fixed_logs = try Protocol.columnLogs(a, &record.statement, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try Protocol.columnLogs(a, &record.statement, .main);
    defer a.free(main_logs);
    const slots = try Slots.fromProfile(a, &record.statement, fixed_logs, main_logs, 0, 0);
    defer a.free(slots);
    var fetches: u64 = 0;
    for (slots) |slot| fetches = try std.math.add(u64, fetches, slot.active_calls);
    if (slots.len == 0 or fetches != Profile.externalCount(&record.statement)) return error.InvalidV5WarmProgramCensus;
    return .{ .family = .program_extension_request, .index = record.execution.index, .instance_id = Program.instanceId(record.instance_id, record.execution.instance_id, record.execution.index, slots), .roots = record.roots };
}
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership; error leaves it with the producer.
    put_program: *const fn (*anyopaque, u32, *Program.Proof) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Producer = Batch.ForBackend(Backend);
        const Api = Program.ForBackend(Backend);
        sink: Sink,
        pub fn hooks(self: *Self) Producer.Hooks {
            return .{ .context = self, .on_first_round = onFirstRound };
        }
        fn onFirstRound(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmCaller) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            var proof = try proveWarm(a, warm);
            var owned = true;
            defer if (owned) proof.deinit(a);
            try self.sink.put_program(self.sink.context, warm.record.execution.index, &proof);
            owned = false;
        }
        /// Useful when composing several production warm callbacks. No scheme
        /// or witness is retained, and the source arithmetic remains unconsumed.
        pub fn proveWarm(a: std.mem.Allocator, warm: Producer.WarmCaller) !Program.Proof {
            const binding = warm.first.binding(warm.sealed);
            try Protocol.admit(binding, warm.sealed, warm.pins, warm.entries);
            try Protocol.validate(&warm.record.statement, warm.record.total_steps, warm.pins.config);
            try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &warm.record.statement);
            if (!warm.first.owns_scheme or !std.meta.eql(warm.first.entry(), warm.record.entry()) or
                !std.meta.eql(warm.first.config, warm.pins.config) or
                !std.meta.eql(warm.first.scheme.config, warm.pins.config) or
                !std.meta.eql(warm.first.key_id, warm.record.key_id) or
                warm.first.total_steps != warm.record.total_steps or
                !std.meta.eql(warm.witness.statement, warm.record.statement) or
                warm.witness.total_steps != warm.record.total_steps or
                warm.first.witness != warm.witness or
                !std.meta.eql(binding.execution_instance_id, warm.record.execution.instance_id) or
                binding.execution_index != warm.record.execution.index or
                !std.meta.eql(binding.caller_key_id, try Protocol.keyId(&warm.record.statement, warm.record.total_steps, warm.pins.config, binding.first_roots[0])))
                return error.UntrustedV5WarmProgramCaller;
            const fixed_logs = try Protocol.columnLogs(a, &warm.record.statement, .fixed);
            var fixed_owned = true;
            defer if (fixed_owned) a.free(fixed_logs);
            const main_logs = try Protocol.columnLogs(a, &warm.record.statement, .main);
            var main_owned = true;
            defer if (main_owned) a.free(main_logs);
            // Family11 roots contain extension columns only: no old native/hash
            // prefix is admitted, and the independently typed offsets are zero.
            const slots = try Slots.fromProfile(a, &warm.record.statement, fixed_logs, main_logs, 0, 0);
            defer a.free(slots);
            var fetches: u64 = 0;
            for (slots) |slot| fetches = try std.math.add(u64, fetches, slot.active_calls);
            if (slots.len == 0 or fetches != Profile.externalCount(&warm.record.statement))
                return error.InvalidV5WarmProgramCensus;
            const expected_entry = try firstRoundEntry(a, warm.record, warm.pins.config);
            var found = false;
            for (warm.entries) |entry| if (entry.family == .program_extension_request and entry.index == binding.execution_index) {
                if (!std.meta.eql(entry, expected_entry))
                    return error.UntrustedV5WarmProgramEntry;
                found = true;
            };
            if (!found) return error.MissingV5WarmProgramEntry;
            var channel = core.proof_suites.Blake3.Channel{};
            const scheme = try Shared.copy(Backend, a, &warm.first.scheme, &channel);
            var first = Api.FirstRound{ .scheme = scheme, .roots = binding.first_roots, .fixed_logs = fixed_logs, .main_logs = main_logs };
            fixed_owned = false;
            main_owned = false;
            defer first.deinit(a);
            var actual_roots = try first.scheme.roots(a);
            defer actual_roots.deinit(a);
            if (actual_roots.items.len != 2 or !std.meta.eql(actual_roots.items[0..2].*, binding.first_roots))
                return error.UntrustedV5WarmProgramLease;
            for (first.scheme.trees.items, warm.first.scheme.trees.items) |lease, original| {
                if (lease.columns.len != original.columns.len) return error.UntrustedV5WarmProgramLease;
                for (lease.columns, original.columns) |left, right| {
                    if (left.log_size != right.log_size or left.values.ptr != right.values.ptr or
                        left.values.len != right.values.len or
                        (left.coefficient_values == null) != (right.coefficient_values == null))
                        return error.UnsharedV5WarmProgramLease;
                    if (left.coefficient_values) |coefficients| if (coefficients.ptr != right.coefficient_values.?.ptr or
                        coefficients.len != right.coefficient_values.?.len) return error.UnsharedV5WarmProgramLease;
                }
            }
            var columns = try Columns.init(Backend, a, warm.first, fixed_logs, main_logs, slots);
            defer columns.deinit(a);
            const proof = try Api.prove(a, &first, columns.fixed, columns.main, slots, warm.sealed.programSeal(), binding.caller_instance_id, binding.execution_instance_id, binding.execution_index, binding.first_roots);
            // Only the lease is consumed by Program.prove. Original ownership
            // stays with Batch for its real arithmetic proof and bounded release.
            return proof;
        }
    };
}
