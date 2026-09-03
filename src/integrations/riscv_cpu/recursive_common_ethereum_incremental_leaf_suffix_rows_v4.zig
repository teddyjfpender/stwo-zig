//! Exact logical rows 10--17 for the schema-3 role-0 universal wrapper.
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

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 10;
pub const LAST_ROW: usize = 17;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const EXACT_TYPED_ROWS_AVAILABLE = true;
pub const SEGMENT_V2_NOMINAL_INPUT_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-suffix-rows/v4-schema3\x00";

pub const StatementInputRelation = binding.Binding(air.statement_input);
pub const StatementSemanticsRelation =
    binding.Binding(air.statement_semantics_input);
pub const ClaimInputRelation = binding.Binding(air.vm_public_claim_input);
pub const ClaimHashRelation = binding.Binding(air.vm_public_claim_hash);
pub const IoHashRelation = binding.Binding(air.vm_public_io_hash);
pub const ClaimSemanticsRelation =
    binding.Binding(air.vm_public_claim_semantics_input);
pub const PublicLogupRelation = binding.Binding(air.vm_public_logup_input);
pub const PublicLogupControlAir = air.vm_public_logup_control.Air;
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
            try source.validate();
            const statement = try source.childStatement();
            const child = try source.childPublic();
            const row16 = try source.publicLogupInput();
            const row17 = try source.publicLogupControl();

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
                destination.* = try air.statement_input_witness.logicalRow(
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
                statement_semantics_values.len,
            );
            errdefer allocator.free(statement_semantics_rows);
            for (
                statement_semantics_rows,
                statement_semantics_preprocessing.rows,
                statement_semantics_values,
            ) |*destination, preprocessing, value| {
                destination.* = try air.statement_semantics_input_witness
                    .logicalRow(preprocessing, value, .segment_leaf);
            }

            const claim_reference = try child.claimReference();
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
                destination.* = air.vm_public_claim_input_witness.logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                );
            }

            const claim_hash_main = try child.claimHashMain();
            const claim_hash_preprocessing =
                try child.claimHashPreprocessing();
            const claim_hash_rows = try allocator.alloc(
                ClaimHashRelation.Row,
                claim_hash_main.rows.len,
            );
            errdefer allocator.free(claim_hash_rows);
            if (claim_hash_main.rows.len != claim_hash_preprocessing.rows.len)
                return mismatch();
            for (
                claim_hash_rows,
                claim_hash_main.rows,
                claim_hash_preprocessing.rows,
            ) |*destination, main, preprocessing| {
                destination.* = air.vm_public_claim_hash_witness.logicalInputs(
                    main,
                    preprocessing,
                    .segment_leaf,
                );
            }

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
                public_logup_main.rows.len,
            );
            errdefer allocator.free(public_logup_rows);
            if (public_logup_main.rows.len !=
                public_logup_preprocessing.rows.len)
            {
                return mismatch();
            }
            for (
                public_logup_rows,
                public_logup_main.rows,
                public_logup_preprocessing.rows,
            ) |*destination, main, preprocessing| {
                destination.* = air.vm_public_logup_input_witness.logicalInputs(
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
                );
            }

            const control_preprocessing = try row17.preprocessing();
            const public_logup_control_rows = try allocator.alloc(
                PublicLogupControlRelation.Row,
                control_preprocessing.rows.len,
            );
            errdefer allocator.free(public_logup_control_rows);
            for (
                public_logup_control_rows,
                control_preprocessing.rows,
            ) |*destination, row| {
                destination.* = air.control_slice_witness.logicalRow(
                    row,
                    .segment_leaf,
                );
            }

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
            try self.source.validate();
            const logs = try self.source.logSizes();
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
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 10 or
        LAST_ROW != 17 or ROW_COUNT != 8 or !EXACT_TYPED_ROWS_AVAILABLE or
        SEGMENT_V2_NOMINAL_INPUT_ADMITTED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental suffix rows V4 drifted");
    }
}
