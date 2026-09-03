//! Prepared Tree0/1/2 cohort for role-0 rows 10--17.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const components_mod =
    @import("recursive_common_ethereum_incremental_leaf_suffix_components_v4.zig");
const interactions =
    @import("recursive_common_ethereum_incremental_leaf_suffix_cohort_v4_interactions.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const rows_mod =
    @import("recursive_common_ethereum_incremental_leaf_suffix_rows_v4.zig");
const rows_10_34 =
    @import("recursive_common_ethereum_incremental_leaf_rows_10_34_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");

const M31 = stwo_core.fields.m31.M31;
const air = frontend.recursion.air;
const relation_interaction = air.relation_interaction;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 10;
pub const LAST_ROW: usize = 17;
pub const ROW_COUNT: usize = 8;
pub const TREE0_AVAILABLE = true;
pub const TREE1_AVAILABLE = true;
pub const TREE2_AVAILABLE = true;
pub const TUPLE_LEDGER_AVAILABLE = true;
pub const PRODUCTION_ACTIVATION = false;

pub const Error = support.Error || error{
    EthereumIncrementalSuffixCohortMismatchV4,
};

pub fn PreparedV4(comptime Engine: type) type {
    const Source = rows_10_34.OwnerV4(Engine);
    const Rows = rows_mod.PreparedV4(Engine);
    const Components = components_mod.OwnerV4(Engine);

    return struct {
        allocator: std.mem.Allocator,
        source: *const Source,
        rows: *Rows,
        components: Components,
        manifest: *const manifest_mod.Manifest,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Source,
            manifest: *const manifest_mod.Manifest,
        ) !Self {
            try source.validate();
            try manifest.validate();
            const rows = try allocator.create(Rows);
            errdefer allocator.destroy(rows);
            rows.* = try Rows.init(allocator, source);
            errdefer rows.deinit();
            var components = try Components.init(allocator, rows, manifest);
            errdefer components.deinit();
            var result = Self{
                .allocator = allocator,
                .source = source,
                .rows = rows,
                .components = components,
                .manifest = manifest,
            };
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.components.deinit();
            self.rows.deinit();
            self.allocator.destroy(self.rows);
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            try self.source.validate();
            try self.rows.validate();
            try self.components.validate();
            if (self.rows.source != self.source or
                self.components.rows != self.rows or
                self.components.manifest != self.manifest)
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
                &owners.statement_input.relation,
                ledger,
                .statement_input,
                self.rows.statement_input,
            );
            try support.appendTuples(
                &owners.statement_semantics.relation,
                ledger,
                .statement_semantics_input,
                self.rows.statement_semantics,
            );
            try support.appendTuples(
                &owners.claim_input.relation,
                ledger,
                .vm_public_claim_input,
                self.rows.claim_input,
            );
            try support.appendTuples(
                &owners.claim_hash.relation,
                ledger,
                .vm_public_claim_hash,
                self.rows.claim_hash,
            );
            try support.appendTuples(
                &owners.io_hash.relation,
                ledger,
                .vm_public_io_hash,
                self.rows.io_hash,
            );
            try support.appendTuples(
                &owners.claim_semantics.relation,
                ledger,
                .vm_public_claim_semantics_input,
                self.rows.claim_semantics,
            );
            try support.appendTuples(
                &owners.public_logup.relation,
                ledger,
                .vm_public_logup_input,
                self.rows.public_logup,
            );
            try support.appendTuples(
                &owners.public_logup_control.relation,
                ledger,
                .vm_public_logup_control,
                self.rows.public_logup_control,
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
            return interactions.generateAll(self, relations, destination);
        }

        pub fn auditClaims(
            self: *const Self,
            relations: *const air.universal_challenges.UniversalRelations,
            claims: components_mod.ClaimsV4,
        ) ![ROW_COUNT]relation_interaction.DomainAudit {
            try self.validate();
            try relations.validate();
            const owners = &self.components.owners;
            return .{
                try owners.statement_input.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.statement_input,
                    relations,
                    claims.values[0],
                ),
                try owners.statement_semantics.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.statement_semantics,
                    relations,
                    claims.values[1],
                ),
                try owners.claim_input.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.claim_input,
                    relations,
                    claims.values[2],
                ),
                try owners.claim_hash.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.claim_hash,
                    relations,
                    claims.values[3],
                ),
                try owners.io_hash.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.io_hash,
                    relations,
                    claims.values[4],
                ),
                try owners.claim_semantics.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.claim_semantics,
                    relations,
                    claims.values[5],
                ),
                try owners.public_logup.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.public_logup,
                    relations,
                    claims.values[6],
                ),
                try owners.public_logup_control.relation.auditPreparedDomainSums(
                    self.allocator,
                    self.rows.public_logup_control,
                    relations,
                    claims.values[7],
                ),
            };
        }

        fn validateDirectConstraints(self: *const Self) !void {
            const owners = &self.components.owners;
            try support.validateDirect(
                air.statement_input,
                &owners.statement_input.direct,
                self.rows.statement_input,
            );
            try support.validateDirect(
                air.statement_semantics_input,
                &owners.statement_semantics.direct,
                self.rows.statement_semantics,
            );
            try support.validateDirect(
                air.vm_public_claim_input,
                &owners.claim_input.direct,
                self.rows.claim_input,
            );
            try support.validateDirect(
                air.vm_public_claim_hash,
                &owners.claim_hash.direct,
                self.rows.claim_hash,
            );
            try support.validateDirect(
                air.vm_public_io_hash,
                &owners.io_hash.direct,
                self.rows.io_hash,
            );
            try support.validateDirect(
                air.vm_public_claim_semantics_input,
                &owners.claim_semantics.direct,
                self.rows.claim_semantics,
            );
            try support.validateDirect(
                air.vm_public_logup_input,
                &owners.public_logup.direct,
                self.rows.public_logup,
            );
            try support.validateDirect(
                rows_mod.PublicLogupControlAir,
                &owners.public_logup_control.direct,
                self.rows.public_logup_control,
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
                air.statement_input,
                self.rows.statement_input,
                try self.manifest.placement(.statement_input),
                tree,
                destination,
            );
            support.writePhysical(
                air.statement_semantics_input,
                self.rows.statement_semantics,
                try self.manifest.placement(.statement_semantics_input),
                tree,
                destination,
            );
            support.writePhysical(
                air.vm_public_claim_input,
                self.rows.claim_input,
                try self.manifest.placement(.vm_public_claim_input),
                tree,
                destination,
            );
            support.writePhysical(
                air.vm_public_claim_hash,
                self.rows.claim_hash,
                try self.manifest.placement(.vm_public_claim_hash),
                tree,
                destination,
            );
            support.writePhysical(
                air.vm_public_io_hash,
                self.rows.io_hash,
                try self.manifest.placement(.vm_public_io_hash),
                tree,
                destination,
            );
            support.writePhysical(
                air.vm_public_claim_semantics_input,
                self.rows.claim_semantics,
                try self.manifest.placement(.vm_public_claim_semantics_input),
                tree,
                destination,
            );
            support.writePhysical(
                air.vm_public_logup_input,
                self.rows.public_logup,
                try self.manifest.placement(.vm_public_logup_input),
                tree,
                destination,
            );
            support.writePhysical(
                rows_mod.PublicLogupControlAir,
                self.rows.public_logup_control,
                try self.manifest.placement(.vm_public_logup_control),
                tree,
                destination,
            );
        }

        fn protectedRanges(self: *const Self) ![9]support.AddressRange {
            return .{
                try support.sliceRange(std.mem.asBytes(self)[0..]),
                try support.sliceRange(self.rows.statement_input),
                try support.sliceRange(self.rows.statement_semantics),
                try support.sliceRange(self.rows.claim_input),
                try support.sliceRange(self.rows.claim_hash),
                try support.sliceRange(self.rows.io_hash),
                try support.sliceRange(self.rows.claim_semantics),
                try support.sliceRange(self.rows.public_logup),
                try support.sliceRange(self.rows.public_logup_control),
            };
        }
    };
}

fn mismatch() Error {
    return error.EthereumIncrementalSuffixCohortMismatchV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 10 or
        LAST_ROW != 17 or ROW_COUNT != 8 or !TREE0_AVAILABLE or
        !TREE1_AVAILABLE or !TREE2_AVAILABLE or !TUPLE_LEDGER_AVAILABLE or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental suffix cohort V4 drifted");
    }
}
