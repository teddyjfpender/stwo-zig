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

/// Owns the admitted logical rows, component plans and manifest snapshot.
/// No mutable row/plan/manifest alias escapes this owner. Construction and
/// explicit validate are admission boundaries; operational reads are cheap.
pub fn PreparedV4(comptime Engine: type) type {
    const Storage = StorageV4(Engine);
    return opaque {
        const Self = @This();
        pub const Generated = interactions.Generated;

        pub fn init(allocator: std.mem.Allocator, source: *const rows_10_34.OwnerV4(Engine), manifest: *const manifest_mod.Manifest) !*Self {
            const value = try allocator.create(Storage);
            errdefer allocator.destroy(value);
            value.* = try Storage.init(allocator, source, manifest);
            return @ptrCast(value);
        }
        fn storage(self: *const Self) *const Storage {
            return @ptrCast(@alignCast(self));
        }
        pub fn deinit(self: *Self) void {
            const value: *Storage = @ptrCast(@alignCast(self));
            const allocator = value.allocator;
            value.deinit();
            allocator.destroy(value);
        }
        pub fn validate(self: *const Self) !void {
            try self.storage().validate();
        }
        pub fn identity(self: *const Self) [32]u8 {
            const value = self.storage();
            return value.rows.seal;
        }
        pub fn initComponents(self: *const Self, relations: *const air.universal_challenges.UniversalRelations, claims: components_mod.ClaimsV4) !components_mod.ComponentsV4 {
            const value = self.storage();
            return value.components.initComponentsFromPrepared(relations, claims);
        }
        /// Const diagnostic projection; no definition arenas or mutable rows
        /// are exposed. The observer cannot mint preparation/proof authority.
        pub fn auditTypedAirRows(self: *const Self, observer: anytype) !void {
            const value = self.storage();
            inline for (.{ "statement_input", "statement_semantics", "claim_input", "claim_hash", "io_hash", "claim_semantics", "public_logup", "public_logup_control" }, 10..) |name, index| {
                const entry = manifest_mod.StatementRootProfile.StatementRoutingOuterCatalog.LOGICAL_ROWS[index];
                const owner: *const @TypeOf(@field(value.components.owners, name)) = &@field(value.components.owners, name);
                const logical: []const [entry.Air.LOGICAL_INPUT_COUNT]M31 = @field(value.rows, name);
                const parameters: []const M31 = &@field(value.components.parameters, name);
                try observer.check(entry.Air, @tagName(entry.row), logical, parameters, &owner.direct, &owner.relation);
            }
        }
        pub fn tupleContributionUpperBound(self: *const Self) !usize {
            return self.storage().tupleContributionUpperBound();
        }
        pub fn appendTupleContributions(self: *const Self, ledger: *relation_interaction.TupleLedger) !void {
            try self.storage().appendTupleContributions(ledger);
        }
        pub fn fillPreprocessedInto(self: *const Self, destination: []const []M31) !void {
            try self.storage().fillPreprocessedInto(destination);
        }
        pub fn fillMainInto(self: *const Self, destination: []const []M31) !void {
            try self.storage().fillMainInto(destination);
        }
        pub fn fillInteractionInto(self: *const Self, relations: *const air.universal_challenges.UniversalRelations, destination: []const []M31) !components_mod.ClaimsV4 {
            return (try self.fillInteractionWithAudit(relations, destination)).claims;
        }
        pub fn fillInteractionWithAudit(self: *const Self, relations: *const air.universal_challenges.UniversalRelations, destination: []const []M31) !Generated {
            return self.storage().fillInteractionInto(relations, destination);
        }
        /// Explicit cold check. Returned sums are diagnostic data, never an
        /// externally supplied capability accepted in place of verification.
        pub fn auditClaims(self: *const Self, relations: *const air.universal_challenges.UniversalRelations, claims: components_mod.ClaimsV4) ![ROW_COUNT]relation_interaction.DomainAudit {
            return self.storage().auditClaims(relations, claims);
        }
    };
}

fn StorageV4(comptime Engine: type) type {
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
            supplied_manifest: *const manifest_mod.Manifest,
        ) !Self {
            try supplied_manifest.validate();
            const manifest = try allocator.create(manifest_mod.Manifest);
            errdefer allocator.destroy(manifest);
            manifest.* = supplied_manifest.*;
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
            // Rows/components are owned construction results. Check the
            // final typed equations once; do not reconstruct their upstream
            // source again while publishing this private transaction.
            try result.validateDirectConstraints();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.components.deinit();
            self.rows.deinit();
            self.allocator.destroy(self.rows);
            self.allocator.destroy(self.manifest);
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            if (self.rows.source != self.source or
                self.components.rows != self.rows or
                self.components.manifest != self.manifest)
            {
                return mismatch();
            }
            // Components validate their rows, which validate the source.
            // Check their ownership links first; do not repeat that traversal.
            try self.components.validate();
            try self.validateDirectConstraints();
        }

        /// Resource-only upper bound over the already admitted logical rows.
        /// Unused event weights can reduce actual contributions, never add them.
        pub fn tupleContributionUpperBound(self: *const Self) !usize {
            var count: usize = 0;
            inline for (.{
                "statement_input", "statement_semantics", "claim_input",  "claim_hash",
                "io_hash",         "claim_semantics",     "public_logup", "public_logup_control",
            }) |name| {
                const rows = @field(self.rows, name);
                const plan = &@field(self.components.owners, name).relation;
                count = try std.math.add(usize, count, try std.math.mul(usize, rows.len, plan.events.len));
            }
            return count;
        }

        pub fn appendTupleContributions(
            self: *const Self,
            ledger: *relation_interaction.TupleLedger,
        ) !void {
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
        ) !interactions.Generated {
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
                manifest_mod.StatementInputAir,
                &owners.statement_input.direct,
                self.rows.statement_input,
            );
            try support.validateDirect(
                manifest_mod.StatementSemanticsAir,
                &owners.statement_semantics.direct,
                self.rows.statement_semantics,
            );
            try support.validateDirect(
                manifest_mod.ClaimInputAir,
                &owners.claim_input.direct,
                self.rows.claim_input,
            );
            try support.validateDirect(
                manifest_mod.ClaimHashAir,
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
                rows_mod.PublicLogupAir,
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
                manifest_mod.StatementInputAir,
                self.rows.statement_input,
                try self.manifest.placement(.statement_input),
                tree,
                destination,
            );
            support.writePhysical(
                manifest_mod.StatementSemanticsAir,
                self.rows.statement_semantics,
                try self.manifest.placement(.statement_semantics_input),
                tree,
                destination,
            );
            support.writePhysical(
                manifest_mod.ClaimInputAir,
                self.rows.claim_input,
                try self.manifest.placement(.vm_public_claim_input),
                tree,
                destination,
            );
            support.writePhysical(
                manifest_mod.ClaimHashAir,
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
                rows_mod.PublicLogupAir,
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
