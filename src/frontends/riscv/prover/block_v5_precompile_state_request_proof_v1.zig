//! Same-caller-root PC/clock projection. A freshly verified family11 caller
//! supplies the binding; the projection itself supplies no standalone authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Program = @import("block_v5_program_extension_proof_v1.zig");
const Slots = @import("block_v5_program_extension_slots_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
const Table = @import("block_v5_program_table_proof_v1.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const CallerColumns = @import("block_v5_program_extension_columns_v1.zig").Columns;

pub const Proof = struct {
    projection: Program.Proof,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.projection.deinit(a);
        self.* = undefined;
    }
};
pub const Receipt = struct { sum: Q, caller_count: u64, binding: Protocol.CallerBinding };

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Quotient = Program.ForProjectionBackend(Backend, .state);
        pub const FirstRound = Quotient.FirstRound;

        /// Lease immutable fixed/main roots, without repeating their commitments.
        pub fn borrowFirstRound(a: std.mem.Allocator, caller: *Family.ForBackend(Backend).FirstRound) !FirstRound {
            if (!caller.owns_scheme) return error.InvalidV5CallerStateFirstRound;
            try Protocol.validate(&caller.witness.statement, caller.total_steps, caller.config);
            try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &caller.witness.statement);
            if (!std.meta.eql(caller.config, caller.scheme.config) or
                caller.witness.total_steps != caller.total_steps or
                !std.meta.eql(caller.instance_id, Protocol.instanceId(caller.key_id, caller.execution_instance_id, caller.index, caller.roots)) or
                !std.meta.eql(caller.key_id, try Protocol.keyId(&caller.witness.statement, caller.total_steps, caller.config, caller.roots[0])))
                return error.UntrustedV5CallerStateKey;
            const fixed = try Protocol.columnLogs(a, &caller.witness.statement, .fixed);
            errdefer a.free(fixed);
            const main = try Protocol.columnLogs(a, &caller.witness.statement, .main);
            errdefer a.free(main);
            var channel = core.proof_suites.Blake3.Channel{};
            try Selected.validateTrees(&caller.scheme, fixed, main);
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, &caller.scheme, &channel);
            errdefer scheme.deinit(a);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (!std.meta.eql(roots.items[0..2].*, caller.roots)) return error.UntrustedV5CallerStateRoots;
            return .{ .scheme = scheme, .roots = caller.roots, .fixed_logs = fixed, .main_logs = main };
        }

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, witness: *const Witness, binding: Protocol.CallerBinding, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, total_steps: u32) !Proof {
            if (witness.total_steps != total_steps) return error.UntrustedV5CallerStateSteps;
            return proveFromCommitted(a, first, &witness.statement, binding, sealed, pins, roster, total_steps);
        }
        pub fn proveFromCommitted(a: std.mem.Allocator, first: *FirstRound, statement: *const Profile.admission.Statement, binding: Protocol.CallerBinding, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, total_steps: u32) !Proof {
            try validate(a, binding, sealed, pins, roster, statement, total_steps);
            if (!first.owns_scheme or !std.meta.eql(first.scheme.config, pins.config) or
                !std.meta.eql(first.roots, binding.first_roots)) return error.UntrustedV5CallerStateRoots;
            const fixed_logs = try Protocol.columnLogs(a, statement, .fixed);
            defer a.free(fixed_logs);
            const main_logs = try Protocol.columnLogs(a, statement, .main);
            defer a.free(main_logs);
            if (!std.mem.eql(u32, first.fixed_logs, fixed_logs) or !std.mem.eql(u32, first.main_logs, main_logs))
                return error.UntrustedV5CallerStateGeometry;
            const slots = try Slots.fromProfile(a, statement, fixed_logs, main_logs, 0, 0);
            defer a.free(slots);
            var columns = try CallerColumns.initFromScheme(a, &first.scheme, fixed_logs, main_logs, slots);
            defer columns.deinit(a);
            return .{ .projection = try Quotient.prove(a, first, columns.fixed, columns.main, slots, channelSeal(sealed), binding.caller_instance_id, binding.execution_instance_id, binding.execution_index, binding.first_roots) };
        }

        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, fresh: *const Family.OpenReceipt, statement: *const Profile.admission.Statement, total_steps: u32) !Receipt {
            var proof = received;
            var owned = true;
            defer if (owned) proof.deinit(a);
            const binding = fresh.binding;
            try validate(a, binding, sealed, pins, roster, statement, total_steps);
            const fixed = try Protocol.columnLogs(a, statement, .fixed);
            defer a.free(fixed);
            const main = try Protocol.columnLogs(a, statement, .main);
            defer a.free(main);
            const slots = try Slots.fromProfile(a, statement, fixed, main, 0, 0);
            defer a.free(slots);
            owned = false; // Quotient owns the complete projection on every path.
            const receipt = try Quotient.verifyOwned(a, proof.projection, channelSeal(sealed), binding.execution_index, binding.caller_instance_id, binding.execution_instance_id, slots, fixed, main, binding.first_roots, binding.first_roots, pins.config);
            return .{ .sum = receipt.sum, .caller_count = receipt.fetch_count, .binding = binding };
        }
    };
}

fn validate(a: std.mem.Allocator, binding: Protocol.CallerBinding, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, statement: *const Profile.admission.Statement, total_steps: u32) !void {
    try Protocol.admit(binding, sealed, pins, roster);
    try Protocol.validate(statement, total_steps, pins.config);
    try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
    if (!std.meta.eql(binding.caller_key_id, try Protocol.keyId(statement, total_steps, pins.config, binding.first_roots[0])))
        return error.UntrustedV5CallerStateKey;
}
fn channelSeal(sealed: Seal.Sealed) Table.Seal {
    // Only source_digest is consumed by the distinct, linear B5PS transcript.
    return .{ .source_digest = sealed.digest, .native_roster_digest = @splat(0), .plan_digest = @splat(0), .program_root = .{ .bytes = @splat(0) }, .first_roots = @splat(@splat(0)) };
}
