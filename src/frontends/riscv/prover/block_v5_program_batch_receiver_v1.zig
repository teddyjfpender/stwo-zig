//! Scoped v5 program receiver. It grants program-relation closure only after
//! fresh native, same-root opcode-request, and complete-ROM table verification
//! in this call. Other block relations and recursive authority remain separate.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const Native = @import("blake3_ethereum_sha_proof.zig");
const Request = @import("block_v5_program_request_proof_v1.zig");
const Table = @import("block_v5_program_table_proof_v1.zig");
const Program = @import("block_v5_program_table_v1.zig");
const Boundary = @import("block_v5_program_boundary_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const Air = @import("../recursion/air/blake3_public_program.zig");
const COMPOSITION_COLUMNS: u32 = 16; // split depth 2 × QM31 degree 4.

pub const MAX_PROGRAM_STARK_BYTES: usize = 128 * 1024 * 1024;
pub const TableWire = struct { stark: []const u8, claim: core.fields.qm31.QM31 };
pub const InstanceWire = struct {
    native_artifact: []const u8,
    request_stark: []const u8,
    request_claims: []const Request.Claim,
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const NativeApi = Native.ForBackend(Backend);
        const RequestApi = Request.ForBackend(Backend);
        const TableApi = Table.ForBackend(Backend);
        pub const Instance = struct {
            /// Constructed from independently pinned native statement/plan,
            /// never decoded from the proof artifact under verification.
            prepared: *NativeApi.PreparedVerifier,
            wire: InstanceWire,
        };

        /// `pins`, `roster`, `expected_seal`, prepared keys and the full ROM
        /// must come from independent job policy. Proof-carried bytes provide
        /// no expected roots, IDs, public state, or fetch counts.
        pub fn verify(
            a: std.mem.Allocator,
            pins: Seal.Pins,
            roster: []const Seal.Entry,
            expected_seal: Seal.Sealed,
            plan: Program.Plan,
            table_wire: TableWire,
            instances: []const Instance,
        ) !void {
            try expected_seal.require(pins, roster);
            if (instances.len != pins.counts[@intFromEnum(Seal.Family.execution) - 1] or
                !std.meta.eql(plan.program_root.bytes, pins.program_root) or
                !std.meta.eql(try plan.digest(), pins.program_plan_digest))
                return error.InvalidV5ProgramBatchPins;
            const table_entry = entry(pins, roster, .program, 0);
            if (!std.meta.eql(table_entry.instance_id, try Table.instanceId(plan)))
                return error.UntrustedV5ProgramTableId;
            // Check every independently pinned key/first-round identity before
            // decoding even the global table proof.
            for (instances, 0..) |instance, index| {
                const prepared = instance.prepared;
                const ordinal: u32 = @intCast(index);
                const native_entry = entry(pins, roster, .execution, ordinal);
                const request_entry = entry(pins, roster, .program_request, ordinal);
                try prepared.validate(native_entry.instance_id);
                if (!std.meta.eql(prepared.id, native_entry.instance_id) or
                    !std.meta.eql(prepared.config, pins.config) or
                    !std.meta.eql(prepared.plan.roots[0], plan.program_root) or
                    !std.meta.eql(request_entry.roots, native_entry.roots))
                    return error.UntrustedV5NativeProgramInstance;
                const slots = try Request.slotsFromStatement(a, &prepared.native);
                defer a.free(slots);
                if (!std.meta.eql(request_entry.instance_id, Request.instanceId(prepared.id, ordinal, slots)) or
                    instance.wire.request_claims.len != slots.len)
                    return error.UntrustedV5ProgramRequestId;
            }
            const subproof = expected_seal.programSeal();
            const table_receipt = try TableApi.verifyOwned(a,
                .{ .stark = try decodeStark(a, table_wire.stark, tableShape(pins.config, plan.log_size)), .claim = table_wire.claim },
                plan, subproof, plan.program_root, table_entry.roots, pins.config);
            const receipts = try a.alloc(Table.VerifiedNativeRequest, instances.len * 2);
            defer a.free(receipts);
            var relation_channel = subproof.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            for (instances, 0..) |instance, index| {
                const prepared = instance.prepared;
                const ordinal: u32 = @intCast(index);
                const native_entry = entry(pins, roster, .execution, ordinal);
                const request_entry = entry(pins, roster, .program_request, ordinal);
                try prepared.validate(native_entry.instance_id);
                if (!std.meta.eql(prepared.id, native_entry.instance_id) or
                    !std.meta.eql(prepared.config, pins.config) or
                    !std.meta.eql(prepared.plan.roots[0], plan.program_root) or
                    !std.meta.eql(request_entry.roots, native_entry.roots))
                    return error.UntrustedV5NativeProgramInstance;
                const slots = try Request.slotsFromStatement(a, &prepared.native);
                defer a.free(slots);
                if (!std.meta.eql(request_entry.instance_id, Request.instanceId(prepared.id, ordinal, slots)) or
                    instance.wire.request_claims.len != slots.len)
                    return error.UntrustedV5ProgramRequestId;
                const native_proof = try Native.codec.decode(a, instance.wire.native_artifact, prepared, prepared.id);
                var capture = try NativeApi.verifyCaptureOwned(a, native_proof, prepared, prepared.id);
                defer capture.deinit();
                try capture.validate(prepared, prepared.id);
                if (capture.proof.commitments.len < 2 or
                    !std.meta.eql(capture.proof.commitments[0..2].*, native_entry.roots))
                    return error.UntrustedV5NativeProgramRoots;
                const request_receipt = try verifyRequestWire(a, instance.wire, subproof, ordinal,
                    prepared.id, slots, prepared.logs[0], prepared.logs[1], native_entry.roots,
                    request_entry.roots, pins.config);
                receipts[2 * index] = request_receipt.closureReceipt();
                const boundary = try Boundary.deriveFromPinnedNativePublic(.rv32im_zkvm_ethereum_sha_v1,
                    &prepared.native.public_data, &relations);
                var digest_channel = subproof.sharedChannel();
                receipts[2 * index + 1] = .{ .claim = boundary.sum, .fetch_count = boundary.fetch_count,
                    .sealed_channel_digest = digest_channel.digestBytes() };
            }
            try Table.closed(table_receipt, receipts, subproof);
        }

        fn verifyRequestWire(a: std.mem.Allocator, wire: InstanceWire, seal: Table.Seal,
            index: u32, key_id: [32]u8, slots: []const Request.Slot, fixed_logs: []const u32,
            main_logs: []const u32, native_roots: [2][32]u8, request_roots: [2][32]u8,
            config: core.pcs.PcsConfig) !Request.VerifiedReceipt {
            var stark = try decodeStark(a, wire.request_stark, requestShape(config, slots, fixed_logs, main_logs));
            var transferred = false;
            defer if (!transferred) stark.deinit(a);
            const claims = try a.dupe(Request.Claim, wire.request_claims);
            transferred = true;
            return RequestApi.verifyOwned(a, .{ .stark = stark, .claims = claims }, seal, index, key_id,
                slots, fixed_logs, main_logs, native_roots, request_roots, config);
        }
    };
}

fn entry(pins: Seal.Pins, roster: []const Seal.Entry, family: Seal.Family, index: u32) Seal.Entry {
    var offset: usize = 0;
    for (pins.counts[0 .. @intFromEnum(family) - 1]) |count| offset += count;
    return roster[offset + index]; // SourceSeal.require checked order/count.
}

fn decodeStark(a: std.mem.Allocator, raw: []const u8, shape: postcard.proof_preflight.Shape) !suite.Proof {
    try postcard.proof_preflight.validate(raw, shape);
    var stream = std.io.fixedBufferStream(raw);
    var proof = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer proof.deinit(a);
    if (stream.pos != raw.len) return error.TrailingV5ProgramProofBytes;
    return proof;
}

fn configShape(config: core.pcs.PcsConfig) postcard.proof_preflight.Config {
    return .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor,
        .n_queries = config.fri_config.n_queries,
        .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
        .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size };
}

fn tableShape(config: core.pcs.PcsConfig, log_size: u32) postcard.proof_preflight.Shape {
    return .{ .config = configShape(config), .tree_columns = .{ Air.PREPROCESSED_COLUMN_COUNT, 0,
        Air.INTERACTION_COLUMN_COUNT, COMPOSITION_COLUMNS }, .allow_empty_main_tree = true,
        .max_column_log_size = log_size,
        .hash_size = 32, .max_wire_bytes = MAX_PROGRAM_STARK_BYTES };
}

fn requestShape(config: core.pcs.PcsConfig, slots: []const Request.Slot,
    fixed_logs: []const u32, main_logs: []const u32) postcard.proof_preflight.Shape {
    var max_slot_log: u32 = 0;
    var max_merkle_log: u32 = 0;
    for (fixed_logs) |log| max_merkle_log = @max(max_merkle_log, log);
    for (main_logs) |log| max_merkle_log = @max(max_merkle_log, log);
    for (slots) |slot| max_slot_log = @max(max_slot_log, slot.log_size);
    return .{ .config = configShape(config), .tree_columns = .{ @intCast(fixed_logs.len),
        @intCast(main_logs.len), @intCast(slots.len * 4), COMPOSITION_COLUMNS },
        .max_column_log_size = max_slot_log,
        .max_merkle_column_log_size = @max(max_merkle_log, max_slot_log),
        .allow_zero_samples = true,
        .hash_size = 32,
        .max_wire_bytes = MAX_PROGRAM_STARK_BYTES };
}

test "block-v5 program table preflight permits only empty main tree" {
    const config = core.pcs.PcsConfig{ .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const shape = tableShape(config, 7);
    try std.testing.expectError(error.EndOfStream, postcard.proof_preflight.validate(&.{}, shape));
    var changed = shape;
    changed.allow_empty_main_tree = false;
    try std.testing.expectError(error.InvalidPreflightShape,
        postcard.proof_preflight.validate(&.{}, changed));
    inline for ([_]usize{ 0, 2, 3 }) |index| {
        changed = shape;
        changed.tree_columns[index] = 0;
        try std.testing.expectError(error.InvalidPreflightShape,
            postcard.proof_preflight.validate(&.{}, changed));
    }
}
