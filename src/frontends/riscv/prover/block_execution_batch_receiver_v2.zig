//! Fresh native-plus-sidecar receiver for one block execution segment. The
//! independently prepared native key and public SpanStatement select every
//! verifier parameter; proof bytes never choose a key, root or access slot.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const base_native = @import("blake3_execution_proof.zig");
const sidecar = @import("block_execution_sidecar_batch_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const leaf = @import("../recursion/blake3_block_execution_span_v3.zig");
const event = @import("../air/block/memory_event.zig");

pub const MAX_SIDECAR_STARK_BYTES: usize = 64 * 1024 * 1024;
pub const Wire = struct {
    native_artifact: []const u8,
    sidecar_stark: []const u8,
    sidecar_claims: []const sidecar.Claim,
};

pub fn ForBackend(comptime Backend: type) type {
    return ForNativeProfile(Backend, base_native, true);
}

/// Ethereum SHA jobs must verify their extension claim and precompile AIR in
/// the native proof before the same-root sidecar is admitted.
pub fn ForEthereumShaBackend(comptime Backend: type) type {
    return ForNativeProfile(Backend, @import("blake3_ethereum_sha_proof.zig"), false);
}

fn ForNativeProfile(comptime Backend: type, comptime NativeModule: type, comptime base: bool) type {
    return struct {
        const NativeApi = NativeModule.ForBackend(Backend);
        const SidecarApi = sidecar.ForBackend(Backend);
        const Prepared = NativeApi.PreparedVerifier;

        /// Returns a receipt only after both independent PCS/FRI verifiers
        /// pass and the sidecar's native fixed/main roots match the capture.
        pub fn verify(
            a: std.mem.Allocator,
            wire: Wire,
            prepared: *Prepared,
            expected_key_id: [32]u8,
            statement: span.SpanStatement,
            sealed: seal_mod.SourceSeal,
            instance_index: u32,
            trusted_witness_root: suite.Hasher.Hash,
            config: core.pcs.PcsConfig,
        ) !sidecar.VerifiedExecutionReceipt {
            if (!sealed.bound_rosters or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(prepared.config, config) or
                wire.sidecar_stark.len > MAX_SIDECAR_STARK_BYTES)
                return error.InvalidBlockExecutionReceiverInput;
            try prepared.validate(expected_key_id);
            const native_proof = try NativeModule.codec.decode(a, wire.native_artifact, prepared, expected_key_id);
            var capture = if (base)
                try NativeApi.verifyPreparedCaptureOwned(a, native_proof, prepared, expected_key_id)
            else
                try NativeApi.verifyCaptureOwned(a, native_proof, prepared, expected_key_id);
            defer capture.deinit();
            try capture.validate(prepared, expected_key_id);
            if (capture.proof.commitments.len < 2) return error.InvalidNativeExecutionCapture;
            const roots: [2]suite.Hasher.Hash = capture.proof.commitments[0..2].*;

            if (statement.body != .executed) return error.InvalidBlockExecutionSpan;
            const executed = statement.body.executed;
            if (executed.first_segment != instance_index or executed.cycle_count == 0 or
                executed.cycle_count > std.math.maxInt(u32)) return error.InvalidBlockExecutionSpan;
            const frame = event.Frame{
                .clock_frame = .leaf_local,
                .global_first_cycle = try std.math.add(u64, executed.first_cycle, 1),
                .cycle_count = @intCast(executed.cycle_count),
            };
            const native_shape = if (base) &prepared.shape else &prepared.native;
            const slots = try sidecar.slotsFromStatement(a, native_shape, frame);
            defer a.free(slots);
            if (wire.sidecar_claims.len != slots.len) return error.InvalidExecutionSlotClaims;
            if (slots.len == 0) {
                if (wire.sidecar_stark.len != 0 or
                    !std.meta.eql(trusted_witness_root, sidecar.emptyWitnessRoot()))
                    return error.InvalidEmptyExecutionSidecar;
                var shared = sealed.sharedChannel();
                var receipt = sidecar.VerifiedExecutionReceipt{
                    .instance_index = instance_index, .transition_sum = core.fields.qm31.QM31.zero(),
                    .event_count = 0,
                    .range_claims = try a.alloc(@import("block_execution_byte_range_v2.zig").Claims, 0),
                    .native_roots = roots, .witness_root = trusted_witness_root,
                    .native_key_id = expected_key_id, .sealed_channel_digest = shared.digestBytes(),
                };
                errdefer receipt.deinit(a);
                try leaf.validate(statement, &native_shape.public_data, config, sealed,
                    expected_key_id, roots, trusted_witness_root, &receipt);
                return receipt;
            }
            if (wire.sidecar_stark.len == 0) return error.InvalidBlockExecutionReceiverInput;

            // Allocation-free five-tree wire walk before postcard can allocate
            // nested vectors from an untrusted length prefix.
            try postcard.proof_preflight.validateFive(wire.sidecar_stark, try preflightShape(config, slots, prepared.logs[0], prepared.logs[1]));

            var stream = std.io.fixedBufferStream(wire.sidecar_stark);
            var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
            var owns_stark = true;
            errdefer if (owns_stark) stark.deinit(a);
            if (stream.pos != wire.sidecar_stark.len) return error.TrailingExecutionSidecarBytes;
            const claims = try a.dupe(sidecar.Claim, wire.sidecar_claims);
            var owns_claims = true;
            errdefer if (owns_claims) a.free(claims);
            const received = sidecar.Proof{ .stark = stark, .claims = claims };
            owns_stark = false;
            owns_claims = false;
            const receipt = try SidecarApi.verifyOwned(
                a, received, sealed, instance_index, expected_key_id, slots,
                prepared.logs[0], prepared.logs[1], roots, trusted_witness_root, config,
            );
            errdefer { var owned = receipt; owned.deinit(a); }
            try leaf.validate(statement, &native_shape.public_data, config, sealed, expected_key_id, roots, trusted_witness_root, &receipt);
            return receipt;
        }
    };
}

fn preflightShape(config: core.pcs.PcsConfig, slots: []const sidecar.Slot, fixed_logs: []const u32, main_logs: []const u32) !postcard.proof_preflight.Shape5 {
    if (slots.len == 0) return error.InvalidExecutionSlotRoster;
    var max_slot_log: u32 = 0;
    var max_merkle_log: u32 = 0;
    for (slots) |slot| max_slot_log = @max(max_slot_log, slot.log_size);
    for (fixed_logs) |log| max_merkle_log = @max(max_merkle_log, log);
    for (main_logs) |log| max_merkle_log = @max(max_merkle_log, log);
    max_merkle_log = @max(max_merkle_log, max_slot_log);
    const composition = core.verifier_types.compositionColumnCount(2, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidExecutionSidecarGeometry;
    return .{
        .config = .{
            .pow_bits = config.pow_bits,
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .n_queries = config.fri_config.n_queries,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .fold_step = config.fri_config.fold_step,
            .lifting_log_size = config.lifting_log_size,
        },
        .tree_columns = .{
            std.math.cast(u32, fixed_logs.len) orelse return error.InvalidExecutionSidecarGeometry,
            std.math.cast(u32, main_logs.len) orelse return error.InvalidExecutionSidecarGeometry,
            std.math.cast(u32, slots.len * @import("block_execution_integer_bridge_v2.zig").COLUMN_COUNT) orelse return error.InvalidExecutionSidecarGeometry,
            std.math.cast(u32, slots.len * @import("block_execution_sidecar_stark_eval_v2.zig").INTERACTION_COUNT) orelse return error.InvalidExecutionSidecarGeometry,
            std.math.cast(u32, composition) orelse return error.InvalidExecutionSidecarGeometry,
        },
        .max_column_log_size = max_slot_log,
        .max_merkle_column_log_size = max_merkle_log,
        .hash_size = 32,
        .max_wire_bytes = MAX_SIDECAR_STARK_BYTES,
    };
}

test "ethereum SHA receiver rejects an unbound proof batch before decoding" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Receiver = ForEthereumShaBackend(Cpu);
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(17), .instance_count = 1 };
    const unbound = try seal_mod.SourceSeal.init(base, 0, @splat(18));
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    try std.testing.expectError(error.InvalidBlockExecutionReceiverInput, Receiver.verify(
        std.testing.allocator,
        .{ .native_artifact = &.{}, .sidecar_stark = &.{}, .sidecar_claims = &.{} },
        undefined, @splat(0), undefined, unbound, 0, @splat(0), config,
    ));
}
