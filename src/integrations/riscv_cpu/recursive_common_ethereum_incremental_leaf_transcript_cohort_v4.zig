//! Prepared Tree0/1/2 cohort for universal role-0 transcript rows 0--9.
//!
//! The source is the opaque Stage101 fresh-capture row owner. This module
//! derives the exact typed logical rows, validates every direct constraint,
//! exposes challenge-independent tuple contributions, and publishes all three
//! trees. It cannot close the complete 36-row cohort by itself.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const components_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_components_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const rows_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");
const interactions =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_interactions.zig");

const M31 = stwo_core.fields.m31.M31;
const air = frontend.recursion.air;
const source_rows = frontend.recursion.segment_transcript_outer_source_v2;
const relation_interaction = air.relation_interaction;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 0;
pub const LAST_ROW: usize = 9;
pub const ROW_COUNT: usize = 10;
pub const TREE0_AVAILABLE = true;
pub const TREE1_AVAILABLE = true;
pub const TREE2_AVAILABLE = true;
pub const TUPLE_LEDGER_AVAILABLE = true;
pub const COMPLETE_36_CLAIM_CLOSURE_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-transcript-cohort/v4-schema3\x00";

pub const Error = support.Error || error{
    EthereumIncrementalTranscriptCohortMismatchV4,
};

pub fn PreparedV4(comptime Engine: type) type {
    const Rows = rows_mod.OwnerV4(Engine);
    const Components = components_mod.OwnerV4(Engine);

    return struct {
        allocator: std.mem.Allocator,
        rows: *const Rows,
        components: *const Components,
        manifest: *const manifest_mod.Manifest,
        control: []components_mod.ControlRelation.Row,
        transcript_air: []components_mod.TranscriptAirRelation.Row,
        transcript_binding: []components_mod.TranscriptBindingRelation.Row,
        transcript_state: []components_mod.TranscriptStateRelation.Row,
        transcript_word: []components_mod.TranscriptWordRelation.Row,
        transcript_payload: []components_mod.TranscriptPayloadRelation.Row,
        pow_check: []components_mod.PowCheckRelation.Row,
        pow_frame: []components_mod.PowFrameRelation.Row,
        relation_challenge: []components_mod.RelationChallengeRelation.Row,
        verifier_randomness: []components_mod.VerifierRandomnessRelation.Row,
        seal: [32]u8,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            components: *const Components,
            manifest: *const manifest_mod.Manifest,
        ) !Self {
            try components.validateAgainst(manifest);
            const rows = components.rows;
            const views = try rows.views();
            const control = try allocator.alloc(
                components_mod.ControlRelation.Row,
                views.control.rows.len,
            );
            errdefer allocator.free(control);
            const transcript_air = try allocator.alloc(
                components_mod.TranscriptAirRelation.Row,
                views.transcript_air.len,
            );
            errdefer allocator.free(transcript_air);
            const transcript_binding = try allocator.alloc(
                components_mod.TranscriptBindingRelation.Row,
                views.transcript_binding.len,
            );
            errdefer allocator.free(transcript_binding);
            const transcript_state = try allocator.alloc(
                components_mod.TranscriptStateRelation.Row,
                views.transcript_state.len,
            );
            errdefer allocator.free(transcript_state);
            const transcript_word = try allocator.alloc(
                components_mod.TranscriptWordRelation.Row,
                views.transcript_word.len,
            );
            errdefer allocator.free(transcript_word);
            const transcript_payload = try allocator.alloc(
                components_mod.TranscriptPayloadRelation.Row,
                views.transcript_payload.len,
            );
            errdefer allocator.free(transcript_payload);
            const pow_check = try allocator.alloc(
                components_mod.PowCheckRelation.Row,
                views.pow_check.len,
            );
            errdefer allocator.free(pow_check);
            const pow_frame = try allocator.alloc(
                components_mod.PowFrameRelation.Row,
                views.pow_frame.len,
            );
            errdefer allocator.free(pow_frame);
            const relation_challenge = try allocator.alloc(
                components_mod.RelationChallengeRelation.Row,
                views.relation_preprocessed.rows.len,
            );
            errdefer allocator.free(relation_challenge);
            const verifier_randomness = try allocator.alloc(
                components_mod.VerifierRandomnessRelation.Row,
                views.randomness_preprocessed.rows.len,
            );
            errdefer allocator.free(verifier_randomness);

            var result = Self{
                .allocator = allocator,
                .rows = rows,
                .components = components,
                .manifest = manifest,
                .control = control,
                .transcript_air = transcript_air,
                .transcript_binding = transcript_binding,
                .transcript_state = transcript_state,
                .transcript_word = transcript_word,
                .transcript_payload = transcript_payload,
                .pow_check = pow_check,
                .pow_frame = pow_frame,
                .relation_challenge = relation_challenge,
                .verifier_randomness = verifier_randomness,
                .seal = undefined,
            };
            try result.deriveLogicalRows(views);
            try result.validateDirectConstraints();
            result.seal = result.computeSeal();
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.verifier_randomness);
            self.allocator.free(self.relation_challenge);
            self.allocator.free(self.pow_frame);
            self.allocator.free(self.pow_check);
            self.allocator.free(self.transcript_payload);
            self.allocator.free(self.transcript_word);
            self.allocator.free(self.transcript_state);
            self.allocator.free(self.transcript_binding);
            self.allocator.free(self.transcript_air);
            self.allocator.free(self.control);
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            try self.components.validateAgainst(self.manifest);
            try self.rows.validate();
            const views = try self.rows.views();
            if (self.components.rows != self.rows or
                self.control.len != views.control.rows.len or
                self.transcript_air.len != views.transcript_air.len or
                self.transcript_binding.len != views.transcript_binding.len or
                self.transcript_state.len != views.transcript_state.len or
                self.transcript_word.len != views.transcript_word.len or
                self.transcript_payload.len != views.transcript_payload.len or
                self.pow_check.len != views.pow_check.len or
                self.pow_frame.len != views.pow_frame.len or
                self.relation_challenge.len !=
                    views.relation_preprocessed.rows.len or
                self.verifier_randomness.len !=
                    views.randomness_preprocessed.rows.len or
                !std.mem.eql(u8, &self.seal, &self.computeSeal()))
            {
                return mismatch();
            }
            try self.validateDirectConstraints();
        }

        pub fn appendTupleContributions(
            self: *const Self,
            ledger: *relation_interaction.TupleLedger,
        ) !void {
            try self.validate();
            const owners = &self.components.owners;
            try support.appendTuples(
                &owners.control.relation,
                ledger,
                .control,
                self.control,
            );
            try support.appendTuples(
                &owners.transcript_air.relation,
                ledger,
                .transcript_air,
                self.transcript_air,
            );
            try support.appendTuples(
                &owners.transcript_binding.relation,
                ledger,
                .transcript_binding,
                self.transcript_binding,
            );
            try support.appendTuples(
                &owners.transcript_state.relation,
                ledger,
                .transcript_state,
                self.transcript_state,
            );
            try support.appendTuples(
                &owners.transcript_word.relation,
                ledger,
                .transcript_word,
                self.transcript_word,
            );
            try support.appendTuples(
                &owners.transcript_payload.relation,
                ledger,
                .transcript_payload,
                self.transcript_payload,
            );
            try support.appendTuples(
                &owners.pow_check.relation,
                ledger,
                .pow_check,
                self.pow_check,
            );
            try support.appendTuples(
                &owners.pow_frame.relation,
                ledger,
                .pow_frame,
                self.pow_frame,
            );
            try support.appendTuples(
                &owners.relation_challenge.relation,
                ledger,
                .relation_challenge,
                self.relation_challenge,
            );
            try support.appendTuples(
                &owners.verifier_randomness.relation,
                ledger,
                .verifier_randomness,
                self.verifier_randomness,
            );
        }

        pub fn fillPreprocessedInto(
            self: *const Self,
            destination: []const []M31,
        ) !void {
            try self.fillBaseTree(
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
        }

        pub fn fillMainInto(
            self: *const Self,
            destination: []const []M31,
        ) !void {
            try self.fillBaseTree(manifest_mod.MAIN_TREE_INDEX, destination);
        }

        pub fn fillInteractionInto(
            self: *const Self,
            relations: *const air.universal_challenges.UniversalRelations,
            destination: []const []M31,
        ) !components_mod.ClaimsV4 {
            try self.validate();
            try relations.validate();
            const protected = try self.protectedRanges();
            try support.preflightTree(
                self.manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
                &protected,
            );
            return self.generateInteractions(relations, destination);
        }

        /// Replays each authenticated relation plan against the retained rows.
        /// These audits are verifier-reconstructible custody for whole-cohort
        /// domain closure; the claim values alone are not admission.
        pub fn auditClaims(
            self: *const Self,
            relations: *const air.universal_challenges.UniversalRelations,
            claims: components_mod.ClaimsV4,
        ) ![ROW_COUNT]relation_interaction.DomainAudit {
            try self.validate();
            try relations.validate();
            const owners = &self.components.owners;
            return .{
                try owners.control.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.control,
                    relations,
                    claims.values[0],
                ),
                try owners.transcript_air.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.transcript_air,
                    relations,
                    claims.values[1],
                ),
                try owners.transcript_binding.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.transcript_binding,
                    relations,
                    claims.values[2],
                ),
                try owners.transcript_state.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.transcript_state,
                    relations,
                    claims.values[3],
                ),
                try owners.transcript_word.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.transcript_word,
                    relations,
                    claims.values[4],
                ),
                try owners.transcript_payload.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.transcript_payload,
                    relations,
                    claims.values[5],
                ),
                try owners.pow_check.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.pow_check,
                    relations,
                    claims.values[6],
                ),
                try owners.pow_frame.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.pow_frame,
                    relations,
                    claims.values[7],
                ),
                try owners.relation_challenge.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.relation_challenge,
                    relations,
                    claims.values[8],
                ),
                try owners.verifier_randomness.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.verifier_randomness,
                    relations,
                    claims.values[9],
                ),
            };
        }

        fn deriveLogicalRows(
            self: *Self,
            views: rows_mod.ViewsV4,
        ) !void {
            for (self.control, views.control.rows) |*target, row|
                target.* = air.control_witness.logicalRow(row, .segment_leaf);
            for (self.transcript_air, views.transcript_air) |*target, row|
                target.* = try air.transcript_air_witness.logicalRow(row);
            for (self.transcript_binding, views.transcript_binding) |*target, row|
                target.* = air.transcript_binding_witness.logicalInputs(
                    row.main,
                    row.preprocessing,
                    .segment_leaf,
                );
            for (self.transcript_state, views.transcript_state) |*target, row|
                target.* = air.transcript_state_witness.logicalInputs(
                    row.main,
                    row.preprocessing,
                    .segment_leaf,
                );
            for (self.transcript_word, views.transcript_word) |*target, row|
                target.* = try air.transcript_word_witness.logicalRow(
                    row.preprocessing,
                    row.value,
                    .segment_leaf,
                );
            for (self.transcript_payload, views.transcript_payload) |*target, row|
                target.* = try air.transcript_payload_witness.logicalRow(
                    row.preprocessing,
                    row.value,
                    .segment_leaf,
                );
            for (self.pow_check, views.pow_check) |*target, row|
                target.* = powCheckLogicalRow(row);
            for (self.pow_frame, views.pow_frame) |*target, row|
                target.* = powFrameLogicalRow(row);
            for (
                self.relation_challenge,
                views.relation_main.rows,
                views.relation_preprocessed.rows,
            ) |*target, main, preprocessing| {
                target.* = air.relation_challenge_witness.logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                );
            }
            for (
                self.verifier_randomness,
                views.randomness_main.rows,
                views.randomness_preprocessed.rows,
            ) |*target, main, preprocessing| {
                target.* = air.verifier_randomness_witness.logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                );
            }
        }

        fn validateDirectConstraints(self: *const Self) !void {
            const owners = &self.components.owners;
            try support.validateDirect(
                air.control,
                &owners.control.direct,
                self.control,
            );
            try support.validateDirect(
                air.transcript_air,
                &owners.transcript_air.direct,
                self.transcript_air,
            );
            try support.validateDirect(
                air.transcript_binding,
                &owners.transcript_binding.direct,
                self.transcript_binding,
            );
            try support.validateDirect(
                air.transcript_state,
                &owners.transcript_state.direct,
                self.transcript_state,
            );
            try support.validateDirect(
                air.transcript_word,
                &owners.transcript_word.direct,
                self.transcript_word,
            );
            try support.validateDirect(
                air.transcript_payload,
                &owners.transcript_payload.direct,
                self.transcript_payload,
            );
            try support.validateDirect(
                air.pow_check,
                &owners.pow_check.direct,
                self.pow_check,
            );
            try support.validateDirect(
                air.pow_frame,
                &owners.pow_frame.direct,
                self.pow_frame,
            );
            try support.validateDirect(
                air.relation_challenge,
                &owners.relation_challenge.direct,
                self.relation_challenge,
            );
            try support.validateDirect(
                air.verifier_randomness,
                &owners.verifier_randomness.direct,
                self.verifier_randomness,
            );
        }

        fn fillBaseTree(
            self: *const Self,
            tree: usize,
            destination: []const []M31,
        ) !void {
            try self.validate();
            if (tree != manifest_mod.PREPROCESSED_TREE_INDEX and
                tree != manifest_mod.MAIN_TREE_INDEX)
            {
                return error.InvalidTreeIndex;
            }
            const protected = try self.protectedRanges();
            try support.preflightTree(
                self.manifest,
                tree,
                destination,
                &protected,
            );
            support.writePhysical(
                air.control,
                self.control,
                try self.manifest.placement(.control),
                tree,
                destination,
            );
            support.writePhysical(
                air.transcript_air,
                self.transcript_air,
                try self.manifest.placement(.transcript_air),
                tree,
                destination,
            );
            support.writePhysical(
                air.transcript_binding,
                self.transcript_binding,
                try self.manifest.placement(.transcript_binding),
                tree,
                destination,
            );
            support.writePhysical(
                air.transcript_state,
                self.transcript_state,
                try self.manifest.placement(.transcript_state),
                tree,
                destination,
            );
            support.writePhysical(
                air.transcript_word,
                self.transcript_word,
                try self.manifest.placement(.transcript_word),
                tree,
                destination,
            );
            support.writePhysical(
                air.transcript_payload,
                self.transcript_payload,
                try self.manifest.placement(.transcript_payload),
                tree,
                destination,
            );
            support.writePhysical(
                air.pow_check,
                self.pow_check,
                try self.manifest.placement(.pow_check),
                tree,
                destination,
            );
            support.writePhysical(
                air.pow_frame,
                self.pow_frame,
                try self.manifest.placement(.pow_frame),
                tree,
                destination,
            );
            support.writePhysical(
                air.relation_challenge,
                self.relation_challenge,
                try self.manifest.placement(.relation_challenge),
                tree,
                destination,
            );
            support.writePhysical(
                air.verifier_randomness,
                self.verifier_randomness,
                try self.manifest.placement(.verifier_randomness),
                tree,
                destination,
            );
        }

        fn protectedRanges(self: *const Self) ![11]support.AddressRange {
            return .{
                try support.sliceRange(std.mem.asBytes(self)[0..]),
                try support.sliceRange(self.control),
                try support.sliceRange(self.transcript_air),
                try support.sliceRange(self.transcript_binding),
                try support.sliceRange(self.transcript_state),
                try support.sliceRange(self.transcript_word),
                try support.sliceRange(self.transcript_payload),
                try support.sliceRange(self.pow_check),
                try support.sliceRange(self.pow_frame),
                try support.sliceRange(self.relation_challenge),
                try support.sliceRange(self.verifier_randomness),
            };
        }

        fn computeSeal(self: *const Self) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(IDENTITY_DOMAIN);
            support.hashInt(&hash, u16, FORMAT_VERSION);
            support.hashInt(&hash, u16, SCHEMA_VERSION);
            support.hashRows(&hash, self.control);
            support.hashRows(&hash, self.transcript_air);
            support.hashRows(&hash, self.transcript_binding);
            support.hashRows(&hash, self.transcript_state);
            support.hashRows(&hash, self.transcript_word);
            support.hashRows(&hash, self.transcript_payload);
            support.hashRows(&hash, self.pow_check);
            support.hashRows(&hash, self.pow_frame);
            support.hashRows(&hash, self.relation_challenge);
            support.hashRows(&hash, self.verifier_randomness);
            return hash.finalResult();
        }

        fn generateInteractions(
            self: *const Self,
            relations: *const air.universal_challenges.UniversalRelations,
            destination: []const []M31,
        ) !components_mod.ClaimsV4 {
            return interactions.generateAll(self, relations, destination);
        }
    };
}

fn powCheckLogicalRow(
    row: source_rows.PowCheckRowV2,
) components_mod.PowCheckRelation.Row {
    var result: components_mod.PowCheckRelation.Row = undefined;
    result[0] = M31.fromCanonical(row.enabler);
    result[1] = M31.fromCanonical(row.verifier_id);
    result[2] = M31.fromCanonical(@intFromEnum(row.pow_kind));
    result[3] = M31.fromCanonical(row.call_id);
    result[4] = M31.fromCanonical(row.bits);
    result[5] = row.word;
    for (row.word_bits, 0..) |value, index|
        result[6 + index] = M31.fromCanonical(value);
    for (row.active_bits, 0..) |value, index|
        result[6 + air.pow_check.M31_BIT_COUNT + index] =
            M31.fromCanonical(value);
    return result;
}

fn powFrameLogicalRow(
    row: source_rows.PowFrameRowV2,
) components_mod.PowFrameRelation.Row {
    return .{
        M31.fromCanonical(row.enabler),
        M31.fromCanonical(row.verifier_id),
        M31.fromCanonical(row.instruction_index),
        M31.fromCanonical(@intFromEnum(row.pow_kind)),
        M31.fromCanonical(row.hash_id),
        M31.fromCanonical(row.call_id),
        M31.fromCanonical(row.bits),
    } ++ row.words;
}

fn mismatch() Error {
    return error.EthereumIncrementalTranscriptCohortMismatchV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 0 or
        LAST_ROW != 9 or ROW_COUNT != 10 or !TREE0_AVAILABLE or
        !TREE1_AVAILABLE or !TREE2_AVAILABLE or !TUPLE_LEDGER_AVAILABLE or
        COMPLETE_36_CLAIM_CLOSURE_AVAILABLE or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental transcript cohort V4 drifted");
    }
}
