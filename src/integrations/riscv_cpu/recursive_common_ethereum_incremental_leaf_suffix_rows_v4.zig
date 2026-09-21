//! Exact logical rows 10--17 under schema-4 suffix admission.
//!
//! Every row is reconstructed from the typed witnesses retained by the
//! verifier-owned rows-10--34 aggregate.  No SegmentV2 source or detached
//! claim vector enters this boundary.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const rows_10_34 =
    @import("recursive_common_ethereum_incremental_leaf_rows_10_34_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");

const M31 = stwo_core.fields.m31.M31;
const air = frontend.recursion.air;
const binding = air.universal_relation_binding;
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const publication_hash = @import("recursive_common_ethereum_incremental_leaf_publication_hash_v4.zig");
const publication_words = @import("recursive_common_ethereum_incremental_leaf_publication_words_v4.zig");
const native_publication_words = @import("recursive_common_ethereum_incremental_leaf_native_publication_words_v4.zig");
const field_frames = @import("recursive_common_ethereum_incremental_leaf_field_frame_routing_v4.zig");
const native_identity = @import("recursive_common_ethereum_incremental_leaf_native_identity_routing_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 4;
pub const FIRST_ROW: usize = 10;
pub const LAST_ROW: usize = 17;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const EXACT_TYPED_ROWS_AVAILABLE = true;
pub const SEGMENT_V2_NOMINAL_INPUT_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-suffix-rows/v4-schema4\x00";

pub const StatementInputRelation = binding.Binding(manifest_mod.StatementInputAir);
pub const StatementSemanticsRelation =
    binding.Binding(manifest_mod.StatementSemanticsAir);
pub const ClaimInputRelation = binding.Binding(manifest_mod.ClaimInputAir);
pub const ClaimHashRelation = binding.Binding(manifest_mod.ClaimHashAir);
pub const IoHashRelation = binding.Binding(air.vm_public_io_hash);
pub const ClaimSemanticsRelation =
    binding.Binding(air.vm_public_claim_semantics_input);
pub const PublicLogupAir = air.ethereum_public_logup_input_v1;
pub const PublicLogupRelation = binding.Binding(PublicLogupAir);
pub const PublicLogupControlAir = air.ethereum_publication_control_v1;
pub const PublicLogupControlRelation = binding.Binding(PublicLogupControlAir);

pub const Error = error{
    EthereumIncrementalSuffixRowsMismatchV4,
};

pub fn PreparedV4(comptime Engine: type) type {
    const Source = rows_10_34.OwnerV4(Engine);

    return struct {
        allocator: std.mem.Allocator,
        source: *const Source,
        statement_input: []StatementInputRelation.Row,
        statement_semantics: []StatementSemanticsRelation.Row,
        claim_input: []ClaimInputRelation.Row,
        claim_hash: []ClaimHashRelation.Row,
        io_hash: []IoHashRelation.Row,
        claim_semantics: []ClaimSemanticsRelation.Row,
        public_logup: []PublicLogupRelation.Row,
        public_logup_control: []PublicLogupControlRelation.Row,
        seal: [32]u8,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Source,
        ) !Self {
            const inputs = try source.preparationView();
            const statement = inputs.statement;
            const child = inputs.child;
            const claim_reference = try child.claimReference();
            const row16 = inputs.row16;
            const row17 = inputs.row17;
            const initial_shape: ?air.ethereum_initial_input_lane_v1.Shape = if (inputs.materialized.initial_input_admission) |admitted| try air.ethereum_initial_input_lane_v1.Shape.init(admitted.claimShape().max_input_words) else null;
            const field_plan = if (inputs.transcript) |program| program.field_plan else null;
            var routing = row16.statementRouting().*;
            var extra_uses = [_]u32{0} ** 412;
            if (field_plan) |plan| for (&extra_uses, 0..) |*uses, index| {
                uses.* = field_frames.statementUses(plan, 0, @intCast(index));
            };
            if (inputs.identity_hashes) |hashes| {
                for (0..hashes.phases()[1].preimage_word_count) |index| {
                    const source_binding = try native_identity.bindingForWord(hashes, .native_authority, index);
                    if (source_binding == .statement_word) extra_uses[source_binding.statement_word.index] += 1;
                }
                for (0..2) |limb| extra_uses[native_identity.cycleUpperWord(@intCast(limb)).index] += 1;
            }
            routing = try routing.withAdditionalUses(extra_uses);

            const statement_input_preprocessing =
                try statement.statementInputPreprocessing();
            const statement_words = try statement.statementWords();
            const statement_input_rows = try allocator.alloc(
                StatementInputRelation.Row,
                statement_input_preprocessing.rows.len,
            );
            errdefer allocator.free(statement_input_rows);
            for (
                statement_input_rows,
                statement_input_preprocessing.rows,
            ) |*destination, preprocessing| {
                destination.* = try routing.providerRow(
                    preprocessing,
                    .{ .segment_leaf = statement_words },
                );
            }

            const statement_semantics_preprocessing =
                try statement.statementSemanticsPreprocessing();
            const statement_semantics_values =
                try statement.statementSemanticsValues();
            if (statement_semantics_preprocessing.rows.len !=
                statement_semantics_values.len)
            {
                return mismatch();
            }
            const statement_semantics_rows = try allocator.alloc(
                StatementSemanticsRelation.Row,
                statement_semantics_values.len + routing.rowCount() + claim_reference.nativeRootConsumerCount(),
            );
            errdefer allocator.free(statement_semantics_rows);
            for (
                statement_semantics_rows[0..statement_semantics_values.len],
                statement_semantics_preprocessing.rows,
                statement_semantics_values,
            ) |*destination, preprocessing, value| {
                destination.* = try routing.logicalConsumerRow(preprocessing, value);
            }

            var routed_at = statement_semantics_values.len;
            for (0..statement_words.len) |word| {
                const row = routing.consumerRow(word) orelse continue;
                statement_semantics_rows[routed_at] = try routing.logicalConsumerRow(row, statement_words[word]);
                routed_at += 1;
            }
            for (row16.clockWords(), 0..) |value, index| {
                statement_semantics_rows[routed_at] = try routing.logicalConsumerRow(routing.clockConsumerRow(index), value);
                routed_at += 1;
            }
            for (row16.nativeRootWords(), 0..) |value, side| {
                const row = routing.nativeRootConsumerRow(@intCast(side)) orelse return mismatch();
                statement_semantics_rows[routed_at] = try routing.logicalConsumerRow(row, value);
                routed_at += 1;
                if (claim_reference.nativeRootConsumerRow(@intCast(side))) |claim_row| {
                    statement_semantics_rows[routed_at] = try routing.logicalConsumerRow(claim_row, value);
                    routed_at += 1;
                }
            }
            std.debug.assert(routed_at == statement_semantics_rows.len);

            const claim_input_main = try child.claimInputMain();
            const claim_input_rows = try allocator.alloc(
                ClaimInputRelation.Row,
                claim_input_main.rows.len,
            );
            errdefer allocator.free(claim_input_rows);
            if (claim_input_main.rows.len !=
                claim_reference.claim_preprocessing.rows.len)
            {
                return mismatch();
            }
            for (
                claim_input_rows,
                claim_input_main.rows,
                claim_reference.claim_preprocessing.rows,
            ) |*destination, main, preprocessing| {
                var source_uses = row16.roleRouting().claimUses(preprocessing.word_index);
                if (initial_shape) |shape| source_uses[0] = try std.math.add(u32, source_uses[0], try shape.claimSourceUses(preprocessing.word_index));
                if (field_plan) |plan| source_uses[0] = try std.math.add(u32, source_uses[0], field_frames.claimUses(plan, preprocessing.word_index));
                destination.* = manifest_mod.ClaimInputAir.logicalRow(air.vm_public_claim_input_witness.logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                ), source_uses);
            }

            // Ethereum binds claim words through semantics, role inputs and IO
            // hashes. Its transcript has no legacy VM-claim-digest endpoint.
            // Row 13 therefore contains only the five actual publication hashes.
            var publication = try publication_hash.Prepared.initAdmitted(
                allocator,
                inputs.materialized,
                0,
            );
            defer publication.deinit();
            const identity_hash_rows: []const ClaimHashRelation.Row = if (inputs.identity_hashes) |hashes| hashes.rows() else &.{};
            const claim_hash_rows = try allocator.alloc(ClaimHashRelation.Row, publication.rows.len + identity_hash_rows.len);
            errdefer allocator.free(claim_hash_rows);
            @memcpy(claim_hash_rows[0..publication.rows.len], publication.rows);
            @memcpy(claim_hash_rows[publication.rows.len..], identity_hash_rows);

            const io_hash_main = try child.ioHashMain();
            const io_hash_preprocessing = try child.ioHashPreprocessing();
            const io_hash_rows = try allocator.alloc(
                IoHashRelation.Row,
                io_hash_main.rows.len,
            );
            errdefer allocator.free(io_hash_rows);
            if (io_hash_main.rows.len != io_hash_preprocessing.rows.len)
                return mismatch();
            for (
                io_hash_rows,
                io_hash_main.rows,
                io_hash_preprocessing.rows,
            ) |*destination, main, preprocessing| {
                destination.* = air.vm_public_io_hash_witness.logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                );
            }

            const semantics_prepared = try child.semanticsPrepared();
            const claim_semantics_rows = try allocator.alloc(
                ClaimSemanticsRelation.Row,
                semantics_prepared.row_witness.rows.len,
            );
            errdefer allocator.free(claim_semantics_rows);
            if (semantics_prepared.row_witness.rows.len !=
                claim_reference.row_preprocessing.rows.len)
            {
                return mismatch();
            }
            for (
                claim_semantics_rows,
                semantics_prepared.row_witness.rows,
                claim_reference.row_preprocessing.rows,
            ) |*destination, main, preprocessing| {
                destination.* = air.vm_public_claim_semantics_input_witness
                    .logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                    M31.fromCanonical(
                        air.vm_public_claim_input.VM_CLAIM_SEMANTICS_SCOPE,
                    ),
                    M31.fromCanonical(
                        air.statement_input.VM_CLAIM_STATEMENT_SCOPE,
                    ),
                );
            }

            const public_logup_preprocessing = try row16.preprocessing();
            const public_logup_main = try row16.mainWitness();
            const public_logup_rows = try allocator.alloc(
                PublicLogupRelation.Row,
                public_logup_main.rows.len + row16.roleRouting().rows.len,
            );
            errdefer allocator.free(public_logup_rows);
            if (public_logup_main.rows.len !=
                public_logup_preprocessing.rows.len)
            {
                return mismatch();
            }
            for (
                public_logup_rows[0..public_logup_main.rows.len],
                public_logup_main.rows,
                public_logup_preprocessing.rows,
            ) |*destination, main, preprocessing| {
                destination.* = PublicLogupAir.logicalRow(air.vm_public_logup_input_witness.logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                    M31.fromCanonical(
                        air.vm_public_claim_input.VM_PUBLIC_LOGUP_SCOPE,
                    ),
                    M31.fromCanonical(
                        air.control_slice_witness.SEGMENT_VERIFIER_ID,
                    ),
                    M31.fromCanonical(
                        air.relation_challenge_witness
                            .VM_PUBLIC_LOGUP_CHALLENGE_SCOPE,
                    ),
                    M31.fromCanonical(@intFromEnum(
                        air.transcript_payload.VerifierInputKind.claimed_sum,
                    )),
                ), 0, null, air.vm_public_claim_input.VM_PUBLIC_LOGUP_SCOPE, null);
            }
            @memcpy(public_logup_rows[public_logup_main.rows.len..], row16.roleRouting().rows);
            if (initial_shape != null) try @import("recursive_common_ethereum_initial_input_rows_v1.zig").validateOrdinaryRolePublishers(public_logup_rows);

            const control_preprocessing = try row17.preprocessing();
            const field_row_count = if (field_plan) |plan| field_frames.rowCount(plan) else 0;
            const identity_row_extra = if (inputs.identity_hashes) |hashes| hashes.phases()[1].preimage_word_count else 0;
            const public_logup_control_rows = try allocator.alloc(
                PublicLogupControlRelation.Row,
                try std.math.add(usize, control_preprocessing.rows.len, publication_words.ROW_COUNT + native_publication_words.ROW_COUNT + field_row_count + identity_row_extra),
            );
            errdefer allocator.free(public_logup_control_rows);
            for (
                public_logup_control_rows[0..control_preprocessing.rows.len],
                control_preprocessing.rows,
            ) |*destination, row| {
                destination.* = PublicLogupControlAir.controlRow(air.control_slice_witness.logicalRow(
                    row,
                    .segment_leaf,
                ));
            }
            try publication_words.writeWithCompletionPolicy(&inputs.materialized.schedule, inputs.materialized.base.input.global_admission != null, (try source.nativeCore()).completionPolicy(), public_logup_control_rows[control_preprocessing.rows.len..][0..publication_words.ROW_COUNT]);
            var control_at = control_preprocessing.rows.len + publication_words.ROW_COUNT;
            if (inputs.identity_hashes) |hashes| {
                try native_publication_words.writeFieldProfile(&inputs.materialized.schedule, &inputs.materialized.base.transcript.execution, inputs.materialized.base.input.stage101.profile.protocol.protocol_id, public_logup_control_rows[control_at..][0..native_publication_words.FIELD_ROW_COUNT]);
                control_at += native_publication_words.FIELD_ROW_COUNT;
                const identity_count = native_identity.integratedRowCount(hashes);
                var native_statement: [412]u32 = undefined;
                for (&native_statement, statement_words) |*word, value| word.* = value.toU32();
                const vm_program = inputs.materialized.base.composition.program();
                if (!vm_program.input_profile.vm_native_continuation_roots or !routing.usesNativeRoots() or row16.nativeRootWords().len != 2) return mismatch();
                var vm_root_uses = [_]u32{0} ** 2;
                for (vm_program.bindings) |input| if (input.source == .native_continuation_root) {
                    const side = input.source.native_continuation_root;
                    vm_root_uses[side] = try std.math.add(u32, vm_root_uses[side], 1);
                };
                if (!std.meta.eql(vm_root_uses, [2]u32{ 1, 1 })) return mismatch();
                var root_uses: [2]u32 = undefined;
                for (&root_uses, 0..) |*uses, side| {
                    const endpoint = native_identity.rootStatementWord(@enumFromInt(side));
                    uses.* = try std.math.add(u32, routing.nativeRootSourceUses(@intCast(side)), vm_root_uses[side]);
                    uses.* = try std.math.add(u32, uses.*, claim_reference.nativeRootSourceUses(@intCast(side)));
                    if (field_plan) |plan| uses.* = try std.math.add(u32, uses.*, field_frames.statementUses(plan, endpoint.scope, endpoint.index));
                }
                try native_identity.writeIntegrated(hashes, inputs.materialized.base.input.stage101.statement.public_data.words(), &native_statement, root_uses, public_logup_control_rows[control_at..][0..identity_count]);
                control_at += identity_count;
            } else {
                try native_publication_words.write(&inputs.materialized.schedule, &inputs.materialized.base.transcript.execution, public_logup_control_rows[control_at..][0..native_publication_words.ROW_COUNT]);
                control_at += native_publication_words.ROW_COUNT;
            }
            if (field_plan) |plan| {
                try field_frames.write(plan, &inputs.materialized.base.transcript.execution, public_logup_control_rows[control_at..]);
                control_at += field_row_count;
            }
            std.debug.assert(control_at == public_logup_control_rows.len);

            var result = Self{
                .allocator = allocator,
                .source = source,
                .statement_input = statement_input_rows,
                .statement_semantics = statement_semantics_rows,
                .claim_input = claim_input_rows,
                .claim_hash = claim_hash_rows,
                .io_hash = io_hash_rows,
                .claim_semantics = claim_semantics_rows,
                .public_logup = public_logup_rows,
                .public_logup_control = public_logup_control_rows,
                .seal = undefined,
            };
            result.seal = result.computeSeal();
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.public_logup_control);
            self.allocator.free(self.public_logup);
            self.allocator.free(self.claim_semantics);
            self.allocator.free(self.io_hash);
            self.allocator.free(self.claim_hash);
            self.allocator.free(self.claim_input);
            self.allocator.free(self.statement_semantics);
            self.allocator.free(self.statement_input);
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            const logs = (try self.source.preparationView()).log_sizes;
            if (self.statement_input.len > try support.traceSize(logs[0]) or
                self.statement_semantics.len > try support.traceSize(logs[1]) or
                self.claim_input.len > try support.traceSize(logs[2]) or
                self.claim_hash.len > try support.traceSize(logs[3]) or
                self.io_hash.len > try support.traceSize(logs[4]) or
                self.claim_semantics.len > try support.traceSize(logs[5]) or
                self.public_logup.len > try support.traceSize(logs[6]) or
                self.public_logup_control.len > try support.traceSize(logs[7]))
            {
                return mismatch();
            }
            if (!std.mem.eql(u8, &self.seal, &self.computeSeal()))
                return mismatch();
        }

        fn computeSeal(self: *const Self) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(IDENTITY_DOMAIN);
            support.hashInt(&hash, u16, FORMAT_VERSION);
            support.hashInt(&hash, u16, SCHEMA_VERSION);
            support.hashRows(&hash, self.statement_input);
            support.hashRows(&hash, self.statement_semantics);
            support.hashRows(&hash, self.claim_input);
            support.hashRows(&hash, self.claim_hash);
            support.hashRows(&hash, self.io_hash);
            support.hashRows(&hash, self.claim_semantics);
            support.hashRows(&hash, self.public_logup);
            support.hashRows(&hash, self.public_logup_control);
            return hash.finalResult();
        }
    };
}

fn mismatch() Error {
    return error.EthereumIncrementalSuffixRowsMismatchV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 4 or FIRST_ROW != 10 or
        LAST_ROW != 17 or ROW_COUNT != 8 or !EXACT_TYPED_ROWS_AVAILABLE or
        SEGMENT_V2_NOMINAL_INPUT_ADMITTED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental suffix rows V4 drifted");
    }
}
