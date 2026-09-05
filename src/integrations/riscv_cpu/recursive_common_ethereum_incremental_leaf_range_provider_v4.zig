//! Authenticated row-35 provider derived from the complete rows0--34 ledger.
//!
//! The ledger is diagnostic storage, not admission: every contribution was
//! emitted by an authenticated relation plan over retained logical rows. This
//! owner admits only the exact `(8,8)` domain and snapshots its signed counter
//! through the canonical shared-provider bridge.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const air = frontend.recursion.air;
const lookup_counter = frontend.air.lookups.tables.counter;
const lookup_interaction = frontend.air.lookups.tables.interaction;
const range_bridge = air.range_check_8_8_bridge;
const relation_interaction = air.relation_interaction;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROW: usize = 35;
pub const LOG_SIZE: u32 = range_bridge.LOG_SIZE;
pub const EXACT_LEDGER_DERIVATION_AVAILABLE = true;
pub const CALLER_MULTIPLICITY_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-range-provider/v4-schema3\x00";

pub const Error = support.Error || error{
    EthereumIncrementalRangeProviderMismatchV4,
};

pub const Adapter = shared_provider.RangeCheck8x8AdapterForManifest(
    manifest_mod,
);

pub const GeneratedV4 = struct {
    owner_identity_sha256: [32]u8,
    relation_registry_sha256: [32]u8,
    provider_relations_sha256: [32]u8,
    claim: QM31,

    pub fn validateAgainst(
        self: GeneratedV4,
        owner: *const OwnerV4,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try owner.validate();
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        if (!std.mem.eql(
            u8,
            &self.owner_identity_sha256,
            &owner.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.relation_registry_sha256,
            &relations.registry_order_digest,
        ) or !std.mem.eql(
            u8,
            &self.provider_relations_sha256,
            &(try provider_relations.identityDigest()),
        ) or !secureCanonical(self.claim)) return mismatch();
    }
};

pub const OwnerV4 = struct {
    allocator: std.mem.Allocator,
    definition: range_bridge.Definition,
    executor: range_bridge.Executor,
    relation: range_bridge.RelationPlan,
    batch: range_bridge.PreparedBatch,
    relation_rows: []range_bridge.RelationRow,
    scratch: []QM31,
    source_contribution_count: usize,
    identity_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        source_ledger: *const relation_interaction.TupleLedger,
    ) !OwnerV4 {
        var counter = try lookup_counter.Counter.init(
            allocator,
            range_bridge.TABLE_KIND,
        );
        defer counter.deinit(allocator);
        var contribution_count: usize = 0;
        for (source_ledger.contributions.items) |contribution| {
            if (contribution.domain != .range_check_8_8) continue;
            if (contribution.component == ROW or
                contribution.arity != range_bridge.TUPLE_ARITY)
            {
                return mismatch();
            }
            try counter.registerRaw(
                contribution.signed_weight,
                contribution.tuple_prefix[0..range_bridge.TUPLE_ARITY],
            );
            contribution_count = std.math.add(
                usize,
                contribution_count,
                1,
            ) catch return error.ArithmeticOverflow;
        }

        var batch = try range_bridge.PreparedBatch.init(allocator, &counter);
        errdefer batch.deinit();
        var definition = try range_bridge.build(allocator);
        errdefer definition.deinit();
        const canonical_binding = try range_bridge.Binding.canonical(&definition);
        const executor = try range_bridge.Executor.init(
            &definition,
            &canonical_binding,
        );
        const relation = try range_bridge.authenticateRelation(&definition);
        const relation_rows = try allocator.alloc(
            range_bridge.RelationRow,
            range_bridge.TABLE_SIZE,
        );
        errdefer allocator.free(relation_rows);
        try executor.generateRelationRowsInto(&batch, relation_rows);
        const scratch = try allocator.alloc(
            QM31,
            2 * lookup_interaction.CHUNK_ROWS,
        );
        errdefer allocator.free(scratch);

        var result = OwnerV4{
            .allocator = allocator,
            .definition = definition,
            .executor = executor,
            .relation = relation,
            .batch = batch,
            .relation_rows = relation_rows,
            .scratch = scratch,
            .source_contribution_count = contribution_count,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = result.computeIdentity();
        try result.validate();
        return result;
    }

    pub fn deinit(self: *OwnerV4) void {
        self.allocator.free(self.scratch);
        self.allocator.free(self.relation_rows);
        self.definition.deinit();
        self.batch.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const OwnerV4) !void {
        try self.definition.validate();
        try self.executor.validate();
        try self.batch.validate();
        try self.relation.validateAgainst(
            &self.definition.arena,
            range_bridge.SEMANTIC_DIGEST,
            self.definition.events,
        );
        if (self.relation_rows.len != range_bridge.TABLE_SIZE or
            self.scratch.len != 2 * lookup_interaction.CHUNK_ROWS or
            self.source_contribution_count == 0 or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &self.computeIdentity(),
            ))
        {
            return mismatch();
        }
        for (self.relation_rows, 0..) |row, index| if (!std.meta.eql(
            row,
            self.batch.preparedRelationRow(index),
        )) return mismatch();
    }

    pub fn appendTupleContributions(
        self: *const OwnerV4,
        ledger: *relation_interaction.TupleLedger,
    ) !void {
        try self.validate();
        try self.relation.appendPreparedTupleContributions(
            ledger,
            ROW,
            self.relation_rows,
            relation_interaction.allDomainMask(),
        );
    }

    pub fn fillPreprocessedInto(
        self: *const OwnerV4,
        manifest: *const manifest_mod.Manifest,
        destination: []const []M31,
    ) !void {
        try self.preflight(manifest, manifest_mod.PREPROCESSED_TREE_INDEX, destination);
        const placement = try manifest.placement(.range_check_8_8);
        const offset: usize = @intCast(placement.preprocessed_offset);
        var tuples: [range_bridge.PREPROCESSED_COLUMN_COUNT][]M31 = .{
            destination[offset + 1],
            destination[offset + 2],
        };
        errdefer {
            @memset(destination[offset], M31.zero());
            for (tuples) |column| @memset(column, M31.zero());
        }
        try self.executor.generatePreprocessedInto(&self.batch, &tuples);
        destination[offset][range_bridge.committedRow(0)] = M31.one();
    }

    pub fn fillMainInto(
        self: *const OwnerV4,
        manifest: *const manifest_mod.Manifest,
        destination: []const []M31,
    ) !void {
        try self.preflight(manifest, manifest_mod.MAIN_TREE_INDEX, destination);
        const placement = try manifest.placement(.range_check_8_8);
        const offset: usize = @intCast(placement.main_offset);
        var columns: [range_bridge.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = .{
            destination[offset],
        };
        try self.executor.generateMainInto(&self.batch, &columns);
    }

    pub fn fillInteractionInto(
        self: *OwnerV4,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        destination: []const []M31,
    ) !GeneratedV4 {
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        try self.preflight(manifest, manifest_mod.INTERACTION_TREE_INDEX, destination);
        const placement = try manifest.placement(.range_check_8_8);
        const offset: usize = @intCast(placement.interaction_offset);
        var columns: [lookup_interaction.N_COLUMNS][]M31 = undefined;
        for (&columns, destination[offset..][0..columns.len]) |*target, source|
            target.* = source;
        const claim = try self.batch.generateNativeInteractionInto(
            &provider_relations.native,
            &columns,
            self.scratch[0..lookup_interaction.CHUNK_ROWS],
            self.scratch[lookup_interaction.CHUNK_ROWS..],
        );
        const result = GeneratedV4{
            .owner_identity_sha256 = self.identity_sha256,
            .relation_registry_sha256 = relations.registry_order_digest,
            .provider_relations_sha256 = try provider_relations.identityDigest(),
            .claim = claim,
        };
        try result.validateAgainst(self, relations, provider_relations);
        return result;
    }

    pub fn auditGenerated(
        self: *const OwnerV4,
        relations: *const universal.UniversalRelations,
        generated: GeneratedV4,
    ) !relation_interaction.DomainAudit {
        try self.validate();
        try relations.validate();
        return self.relation.auditPreparedDomainSums(
            self.allocator,
            self.relation_rows,
            relations,
            generated.claim,
        );
    }

    pub fn initComponent(
        self: *const OwnerV4,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        generated: GeneratedV4,
    ) !Adapter {
        try generated.validateAgainst(self, relations, provider_relations);
        return Adapter.init(
            &self.definition,
            &self.executor,
            manifest,
            provider_relations,
            relations,
            generated.claim,
        );
    }

    fn preflight(
        self: *const OwnerV4,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
        destination: []const []M31,
    ) !void {
        try self.validate();
        const protected = [_]support.AddressRange{
            try support.sliceRange(std.mem.asBytes(self)[0..]),
            try support.sliceRange(self.relation_rows),
            try support.sliceRange(self.scratch),
            try support.sliceRange(self.batch.counter.values),
        };
        try support.preflightTree(manifest, tree, destination, &protected);
        const placement = try manifest.placement(.range_check_8_8);
        if (!std.meta.eql(placement.geometry, Adapter.manifestGeometry()))
            return mismatch();
    }

    fn computeIdentity(self: *const OwnerV4) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(IDENTITY_DOMAIN);
        support.hashInt(&hash, u16, FORMAT_VERSION);
        support.hashInt(&hash, u16, SCHEMA_VERSION);
        support.hashInt(&hash, u64, self.source_contribution_count);
        hash.update(&self.batch.authority_digest);
        hash.update(&self.executor.binding_digest);
        hash.update(&self.relation.semantic_digest);
        hash.update(&self.relation.registry_order_digest);
        return hash.finalResult();
    }
};

fn secureCanonical(value: QM31) bool {
    for (value.toM31Array()) |limb| if (limb.toU32() >=
        stwo_core.fields.m31.Modulus)
    {
        return false;
    };
    return true;
}

fn mismatch() Error {
    return error.EthereumIncrementalRangeProviderMismatchV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or ROW != 35 or
        LOG_SIZE != 16 or !EXACT_LEDGER_DERIVATION_AVAILABLE or
        CALLER_MULTIPLICITY_ADMITTED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental range provider V4 drifted");
    }
}
