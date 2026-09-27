//! Fresh Ethereum-SHA native and external-memory sidecar verification. Roots,
//! key, extension geometry and span are supplied by the trusted block pins.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const native_mod = @import("blake3_ethereum_sha_proof.zig");
const external = @import("block_execution_external_batch_v2.zig");
const opcode = @import("block_execution_sidecar_batch_v2.zig");
const source = @import("block_execution_external_trace_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const event = @import("../air/block/memory_event.zig");

pub const MAX_EXTERNAL_STARK_BYTES: usize = 128 * 1024 * 1024;
pub const Wire = struct {
    native_artifact: []const u8,
    external_stark: []const u8,
    external_claims: []const external.Claim,
};
pub const SidecarWire = struct { external_stark: []const u8, external_claims: []const external.Claim };

pub fn ForEthereumShaBackend(comptime Backend: type) type {
    return struct {
        const Native = native_mod.ForBackend(Backend);
        const Api = external.ForBackend(Backend);
        const Prepared = Native.PreparedVerifier;

        /// `trusted_witness_root` must come from the independently pinned
        /// family-10 first-round roster, never from `wire.external_stark`.
        pub fn verify(a: std.mem.Allocator, wire: Wire, prepared: *Prepared, expected_key_id: [32]u8,
            statement: span.SpanStatement, sealed: seal_mod.SourceSeal, instance_index: u32,
            trusted_witness_root: suite.Hasher.Hash, config: core.pcs.PcsConfig) !external.VerifiedReceipt {
            if (!sealed.bound_rosters or !sealed.extension_rosters_bound or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(prepared.config, config) or wire.external_stark.len == 0 or
                wire.external_stark.len > MAX_EXTERNAL_STARK_BYTES)
                return error.InvalidExternalReceiverInput;
            try prepared.validate(expected_key_id);
            const native_proof = try native_mod.codec.decode(a, wire.native_artifact, prepared, expected_key_id);
            var capture = try Native.verifyCaptureOwned(a, native_proof, prepared, expected_key_id);
            defer capture.deinit();
            try capture.validate(prepared, expected_key_id);
            if (capture.proof.commitments.len < 2) return error.InvalidNativeExecutionCapture;
            const roots: [2]suite.Hasher.Hash = capture.proof.commitments[0..2].*;
            return verifySidecar(a, .{ .external_stark = wire.external_stark, .external_claims = wire.external_claims },
                prepared, expected_key_id, statement, sealed, instance_index, roots, trusted_witness_root, config);
        }

        /// Call only after `opcode_receipt` was returned by a fresh opcode
        /// verifier in this same block verification call. A publicly
        /// constructible receipt alone is never proof authority.
        pub fn verifyAfterVerifiedOpcode(a: std.mem.Allocator, wire: SidecarWire, prepared: *Prepared,
            expected_key_id: [32]u8, statement: span.SpanStatement, sealed: seal_mod.SourceSeal,
            instance_index: u32, opcode_receipt: *const opcode.VerifiedExecutionReceipt,
            trusted_witness_root: suite.Hasher.Hash, config: core.pcs.PcsConfig) !external.VerifiedReceipt {
            if (opcode_receipt.instance_index != instance_index or
                !std.mem.eql(u8, &opcode_receipt.native_key_id, &expected_key_id))
                return error.UntrustedOpcodeReceiptForExternalAccess;
            var channel = sealed.sharedChannel();
            const digest = channel.digestBytes();
            if (!std.mem.eql(u8, &opcode_receipt.sealed_channel_digest, &digest))
                return error.UntrustedOpcodeReceiptForExternalAccess;
            return verifySidecar(a, wire, prepared, expected_key_id, statement, sealed, instance_index,
                opcode_receipt.native_roots, trusted_witness_root, config);
        }

        fn verifySidecar(a: std.mem.Allocator, wire: SidecarWire, prepared: *Prepared, expected_key_id: [32]u8,
            statement: span.SpanStatement, sealed: seal_mod.SourceSeal, instance_index: u32,
            roots: [2]suite.Hasher.Hash, trusted_witness_root: suite.Hasher.Hash,
            config: core.pcs.PcsConfig) !external.VerifiedReceipt {
            if (!sealed.bound_rosters or !sealed.extension_rosters_bound or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(prepared.config, config) or wire.external_stark.len == 0 or
                wire.external_stark.len > MAX_EXTERNAL_STARK_BYTES)
                return error.InvalidExternalReceiverInput;
            try prepared.validate(expected_key_id);
            if (statement.body != .executed) return error.InvalidBlockExecutionSpan;
            const executed = statement.body.executed;
            if (executed.first_segment != instance_index or executed.cycle_count == 0 or
                executed.cycle_count > std.math.maxInt(u32)) return error.InvalidBlockExecutionSpan;
            const frame = event.Frame{ .clock_frame = .leaf_local,
                .global_first_cycle = try std.math.add(u64, executed.first_cycle, 1),
                .cycle_count = @intCast(executed.cycle_count) };
            const slots = try source.descriptorsFromStatement(a, &prepared.extension, prepared.logs[0], prepared.logs[1], frame);
            defer a.free(slots);
            if (slots.len == 0 or wire.external_claims.len != slots.len) return error.InvalidExternalAccessClaims;
            try postcard.proof_preflight.validateFive(wire.external_stark,
                try preflightShape(config, slots, prepared.logs[0], prepared.logs[1]));
            var stream = std.io.fixedBufferStream(wire.external_stark);
            var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
            var owns_stark = true;
            errdefer if (owns_stark) stark.deinit(a);
            if (stream.pos != wire.external_stark.len) return error.TrailingExternalSidecarBytes;
            const claims = try a.dupe(external.Claim, wire.external_claims);
            var owns_claims = true;
            errdefer if (owns_claims) a.free(claims);
            const received = external.Proof{ .stark = stark, .claims = claims };
            owns_stark = false;
            owns_claims = false;
            const receipt = try Api.verifyOwned(a, received, sealed, instance_index, expected_key_id, slots,
                prepared.logs[0], prepared.logs[1], roots, trusted_witness_root, config);
            errdefer { var owned = receipt; owned.deinit(a); }
            if (receipt.event_count != try source.expectedEventCount(&prepared.extension))
                return error.InvalidExternalEventCensus;
            return receipt;
        }
    };
}

fn preflightShape(config: core.pcs.PcsConfig, slots: []const source.Descriptor,
    fixed_logs: []const u32, main_logs: []const u32) !postcard.proof_preflight.Shape5 {
    if (slots.len == 0) return error.InvalidExternalAccessRoster;
    var max_slot_log: u32 = 0;
    var max_merkle_log: u32 = 0;
    for (slots) |slot| max_slot_log = @max(max_slot_log, slot.log_size);
    for (fixed_logs) |log| max_merkle_log = @max(max_merkle_log, log);
    for (main_logs) |log| max_merkle_log = @max(max_merkle_log, log);
    max_merkle_log = @max(max_merkle_log, max_slot_log);
    const composition = core.verifier_types.compositionColumnCount(2, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidExternalAccessGeometry;
    return .{ .config = .{
        .pow_bits = config.pow_bits,
        .log_blowup_factor = config.fri_config.log_blowup_factor,
        .n_queries = config.fri_config.n_queries,
        .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
        .fold_step = config.fri_config.fold_step,
        .lifting_log_size = config.lifting_log_size,
    }, .tree_columns = .{
        std.math.cast(u32, fixed_logs.len) orelse return error.InvalidExternalAccessGeometry,
        std.math.cast(u32, main_logs.len) orelse return error.InvalidExternalAccessGeometry,
        std.math.cast(u32, slots.len * @import("block_execution_integer_bridge_v2.zig").COLUMN_COUNT) orelse return error.InvalidExternalAccessGeometry,
        std.math.cast(u32, slots.len * @import("block_execution_sidecar_stark_eval_v2.zig").INTERACTION_COUNT) orelse return error.InvalidExternalAccessGeometry,
        std.math.cast(u32, composition) orelse return error.InvalidExternalAccessGeometry,
    }, .max_column_log_size = max_slot_log, .max_merkle_column_log_size = max_merkle_log,
        // Keccak state bits are opened both at the caller row and +27.
        .sample_width_limits = .{ 1, 2, 1, 2, 1 },
        .hash_size = 32, .max_wire_bytes = MAX_EXTERNAL_STARK_BYTES };
}
