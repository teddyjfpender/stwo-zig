//! Fresh program-request verification at independently admitted family11
//! roots. This is a program-only receipt: the enclosing receiver must also
//! fresh-verify family11 arithmetic and the ordered native caller bus.
const std = @import("std");
const core = @import("stwo_core");
const profile = @import("blake3_ethereum_sha_profile.zig");
const protocol = @import("block_v5_precompile_protocol_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const slots_mod = @import("block_v5_program_extension_slots_v1.zig");
const proof_mod = @import("block_v5_program_extension_proof_v1.zig");

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// No received metadata supplies the expected instance/shape/roots.
        /// `binding`, `statement`, and logs come from the independently pinned
        /// family11 admission used for fresh arithmetic verification.
        pub fn verifyOwned(a: std.mem.Allocator, received: proof_mod.Proof,
            sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry,
            binding: protocol.CallerBinding, statement: *const profile.admission.Statement,
            total_steps: u32, fixed_logs: []const u32, main_logs: []const u32,
        ) !proof_mod.VerifiedReceipt {
            var owned = received;
            var owns = true;
            defer if (owns) owned.deinit(a);
            try protocol.admit(binding, sealed, pins, entries);
            const expected_key = try protocol.keyId(statement, total_steps,
                pins.config, binding.first_roots[0]);
            if (!std.meta.eql(expected_key, binding.caller_key_id))
                return error.UntrustedV5ProgramExtensionKey;
            const expected_fixed_logs = try protocol.columnLogs(a, statement, .fixed);
            defer a.free(expected_fixed_logs);
            const expected_main_logs = try protocol.columnLogs(a, statement, .main);
            defer a.free(expected_main_logs);
            if (!std.mem.eql(u32, fixed_logs, expected_fixed_logs) or
                !std.mem.eql(u32, main_logs, expected_main_logs))
                return error.UntrustedV5ProgramExtensionLogs;
            const slots = try slots_mod.fromProfile(a, statement, fixed_logs, main_logs, 0, 0);
            defer a.free(slots);
            const request_id = proof_mod.instanceId(binding.caller_instance_id,
                binding.execution_instance_id, binding.execution_index, slots);
            var found = false;
            for (entries) |entry| {
                if (entry.family != .program_extension_request or
                    entry.index != binding.execution_index) continue;
                if (!std.meta.eql(entry.instance_id, request_id) or
                    !std.meta.eql(entry.roots, binding.first_roots))
                    return error.UntrustedV5ProgramExtensionRoots;
                found = true;
            }
            if (!found) return error.MissingV5ProgramExtensionRequest;
            owns = false;
            return proof_mod.ForBackend(Backend).verifyOwned(a, owned,
                sealed.programSeal(), binding.execution_index, binding.caller_instance_id,
                binding.execution_instance_id, slots, fixed_logs, main_logs,
                binding.first_roots, binding.first_roots, pins.config);
        }
    };
}
