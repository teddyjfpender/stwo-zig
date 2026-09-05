//! Complete physical rows0--35 cohort for the schema-3 role-0 wrapper.
//!
//! This owner joins the transcript prefix, V4 statement/public spine, genuine
//! verifier core, and two authenticated shared providers. It closes exact
//! tuples before challenges and reconstructs every domain audit after Tree2.
//! Proof and cold-capture activation remain intentionally outside this file.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const closure_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_closure_v4.zig");
const geometry_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const native_core =
    @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
const range_provider =
    @import("recursive_common_ethereum_incremental_leaf_range_provider_v4.zig");
const recursive_core = @import("recursive_fri_outer.zig");
const rows_10_34 =
    @import("recursive_common_ethereum_incremental_leaf_rows_10_34_v4.zig");
const suffix_cohort =
    @import("recursive_common_ethereum_incremental_leaf_suffix_cohort_v4.zig");
const suffix_components =
    @import("recursive_common_ethereum_incremental_leaf_suffix_components_v4.zig");
const transcript_cohort =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4.zig");
const transcript_components =
    @import("recursive_common_ethereum_incremental_leaf_transcript_components_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");
const outer_support = @import("recursive_binary_outer_support.zig");

const M31 = stwo_core.fields.m31.M31;
const air = frontend.recursion.air;
const relation_interaction = air.relation_interaction;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const TREE0_AVAILABLE = true;
pub const TREE1_AVAILABLE = true;
pub const TREE2_AVAILABLE = true;
pub const EXACT_TUPLE_CLOSURE_AVAILABLE = true;
pub const COMPLETE_36_CLAIM_CLOSURE_AVAILABLE = true;
pub const UNIVERSAL_PROOF_GATE_AVAILABLE = false;
pub const COLD_CAPTURE_AVAILABLE = false;
pub const FOLD_CHILD_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-complete-cohort/v4-schema3\x00";
const GENERATED_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-generated/v4-schema3\x00";

pub const Error = error{
    EthereumIncrementalCompleteCohortMismatchV4,
    EthereumIncrementalTupleNotClosedV4,
};

pub const GeneratedV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    cohort_identity_sha256: [32]u8,
    manifest_seal: [32]u8,
    relation_registry_sha256: [32]u8,
    provider_relations_sha256: [32]u8,
    prefix: transcript_components.ClaimsV4,
    suffix: suffix_components.ClaimsV4,
    native: recursive_core.NativeSegmentCoreGeneratedV2,
    range: range_provider.GeneratedV4,
    claims: manifest_mod.ClaimVector,
    closure: closure_mod.ReceiptV4,
    identity_sha256: [32]u8,

    pub fn validateStructure(self: *const GeneratedV4) !void {
        try self.closure.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            std.mem.allEqual(u8, &self.cohort_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.manifest_seal, 0) or
            std.mem.allEqual(u8, &self.relation_registry_sha256, 0) or
            std.mem.allEqual(u8, &self.provider_relations_sha256, 0) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &generatedIdentity(self),
            ))
        {
            return mismatch();
        }
    }
};

/// Exact physical component set for the role-0 universal proof gate. The
/// four children retain their native AIR definitions, rebound only through
/// the manifest-generic role-0 adapter after exact placement validation; no
/// canonical-empty or common-fold component is reused through a cast.
pub const ComponentSetV4 = struct {
    prefix: transcript_components.ComponentsV4,
    suffix: suffix_components.ComponentsV4,
    native: native_core.NativeCoreComponentsV4,
    range: range_provider.Adapter,

    pub fn deinit(self: *ComponentSetV4) void {
        self.native.deinit();
        self.* = undefined;
    }

    pub fn appendToGate(
        self: *const ComponentSetV4,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        if (gate.count != 0)
            return error.EthereumIncrementalCompleteCohortMismatchV4;
        try self.prefix.appendToGate(manifest, gate);
        try self.suffix.appendToGate(manifest, gate);
        try self.native.appendToGate(manifest, gate);
        try gate.append(manifest, try self.range.binding(manifest));
        if (gate.count != COMPONENT_COUNT)
            return error.EthereumIncrementalCompleteCohortMismatchV4;
    }
};

pub fn CohortV4(comptime Engine: type) type {
    const Geometry = geometry_mod.OwnerV4(Engine);
    const PrefixComponents = transcript_components.OwnerV4(Engine);
    const Prefix = transcript_cohort.PreparedV4(Engine);
    const SuffixSource = rows_10_34.OwnerV4(Engine);
    const Suffix = suffix_cohort.PreparedV4(Engine);
    const Native = native_core.OwnerV4(Engine);
    const InteractionTree = outer_support.TreeStorageForManifest(manifest_mod);

    return opaque {
        const Self = @This();

        /// Consumes the mutable finalization state of `geometry`. A failed
        /// initialization is not retryable with the same geometry owner.
        pub fn init(
            allocator: std.mem.Allocator,
            geometry: *Geometry,
        ) !*Self {
            try geometry.validate();
            const manifest_value = try geometry.manifest();
            const suffix_source = try geometry.rows10Through34Mutable();
            const native = try suffix_source.nativeCoreMutable();
            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            backing.* = .{
                .allocator = allocator,
                .geometry = geometry,
                .manifest = manifest_value,
                .suffix_source = suffix_source,
                .native = native,
                .prefix_components = undefined,
                .prefix_components_initialized = false,
                .prefix = undefined,
                .prefix_initialized = false,
                .suffix = undefined,
                .suffix_initialized = false,
                .range = undefined,
                .range_initialized = false,
                .tuple_closure = undefined,
                .identity_sha256 = undefined,
            };
            errdefer backing.destroyInitialized(false);

            backing.prefix_components = try PrefixComponents.init(
                allocator,
                try geometry.transcriptRows(),
                manifest_value,
            );
            backing.prefix_components_initialized = true;
            backing.prefix = try Prefix.init(
                allocator,
                &backing.prefix_components,
                manifest_value,
            );
            backing.prefix_initialized = true;
            backing.suffix = try Suffix.init(
                allocator,
                suffix_source,
                manifest_value,
            );
            backing.suffix_initialized = true;

            // Row34 becomes immutable and complete before the tuple ledger or
            // any external tree can observe it.
            try native.finalizeSharedProviderMain(manifest_value);
            var source_ledger = relation_interaction.TupleLedger.init(allocator);
            defer source_ledger.deinit();
            try backing.appendSourceTupleContributions(&source_ledger);
            backing.range = try range_provider.OwnerV4.init(
                allocator,
                &source_ledger,
            );
            backing.range_initialized = true;
            try backing.range.appendTupleContributions(&source_ledger);
            backing.tuple_closure = source_ledger.classify();
            if (!backing.tuple_closure.isClosed())
                return error.EthereumIncrementalTupleNotClosedV4;

            backing.identity_sha256 = try backing.computeIdentity();
            try backing.validateStructure();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroyInitialized(true);
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validateStructure();
        }

        pub fn manifest(self: *const Self) !*const manifest_mod.Manifest {
            try self.validate();
            return storageConst(self).manifest;
        }

        pub fn tupleClosure(
            self: *const Self,
        ) !relation_interaction.TupleClosureReport {
            try self.validate();
            return storageConst(self).tuple_closure;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            try self.validate();
            return storageConst(self).identity_sha256;
        }

        pub fn fillPreprocessedInto(
            self: *Self,
            destination: []const []M31,
        ) !void {
            return storage(self).fillBaseTree(
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
        }

        pub fn fillMainInto(
            self: *Self,
            destination: []const []M31,
        ) !void {
            return storage(self).fillBaseTree(
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );
        }

        pub fn fillInteractionInto(
            self: *Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            destination: []const []M31,
        ) !GeneratedV4 {
            return storage(self).fillInteractionInto(
                relations,
                provider_relations,
                destination,
            );
        }

        pub fn validateGenerated(
            self: *Self,
            generated: *const GeneratedV4,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !void {
            return storage(self).validateGenerated(
                generated,
                relations,
                provider_relations,
            );
        }

        /// Verifier-side challenge replay. The temporary Tree2 storage is
        /// private and discarded after the exact claims/audit receipt have
        /// been reconstructed; it never becomes proof or freshness custody.
        pub fn rebuildGeneratedInteractions(
            self: *Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !GeneratedV4 {
            const value = storage(self);
            var interaction = try InteractionTree.init(
                value.allocator,
                value.manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
            );
            defer interaction.deinit();
            return value.fillInteractionInto(
                relations,
                provider_relations,
                interaction.columns,
            );
        }

        pub fn initComponents(
            self: *Self,
            generated: *const GeneratedV4,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !ComponentSetV4 {
            const value = storage(self);
            try value.validateGenerated(
                generated,
                relations,
                provider_relations,
            );
            return .{
                .prefix = try value.prefix_components.initComponents(
                    value.manifest,
                    relations,
                    generated.prefix,
                ),
                .suffix = try value.suffix.components.initComponents(
                    relations,
                    generated.suffix,
                ),
                .native = try value.native.initComponents(
                    value.manifest,
                    relations,
                    provider_relations,
                    &generated.native,
                ),
                .range = try value.range.initComponent(
                    value.manifest,
                    relations,
                    provider_relations,
                    generated.range,
                ),
            };
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            geometry: *Geometry,
            manifest: *const manifest_mod.Manifest,
            suffix_source: *SuffixSource,
            native: *Native,
            prefix_components: PrefixComponents,
            prefix_components_initialized: bool,
            prefix: Prefix,
            prefix_initialized: bool,
            suffix: Suffix,
            suffix_initialized: bool,
            range: range_provider.OwnerV4,
            range_initialized: bool,
            tuple_closure: relation_interaction.TupleClosureReport,
            identity_sha256: [32]u8,

            fn validateStructure(self: *const Storage) !void {
                try self.geometry.validate();
                try self.suffix_source.validate();
                try self.native.validate();
                try self.native.nativeCoreConst().validateComplete();
                if (!self.prefix_components_initialized or
                    !self.prefix_initialized or !self.suffix_initialized or
                    !self.range_initialized or
                    self.manifest != try self.geometry.manifest() or
                    self.suffix_source != try self.geometry.rows10Through34() or
                    self.native != try self.suffix_source.nativeCore() or
                    !self.tuple_closure.isClosed())
                {
                    return mismatch();
                }
                try self.prefix_components.validateAgainst(self.manifest);
                try self.prefix.validate();
                try self.suffix.validate();
                try self.range.validate();
                if (!std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &(try self.computeIdentity()),
                )) return mismatch();
            }

            fn appendSourceTupleContributions(
                self: *const Storage,
                ledger: *relation_interaction.TupleLedger,
            ) !void {
                try self.prefix.appendTupleContributions(ledger);
                try self.suffix.appendTupleContributions(ledger);
                try self.native.appendTupleContributions(self.allocator, ledger);
            }

            fn fillBaseTree(
                self: *Storage,
                tree: usize,
                destination: []const []M31,
            ) !void {
                try self.validateStructure();
                try preflightFreshTree(self.manifest, tree, destination);
                errdefer clearTree(destination);
                switch (tree) {
                    manifest_mod.PREPROCESSED_TREE_INDEX => {
                        try self.prefix.fillPreprocessedInto(destination);
                        try self.suffix.fillPreprocessedInto(destination);
                        try self.native.fillPreprocessedInto(
                            self.manifest,
                            destination,
                        );
                        try self.range.fillPreprocessedInto(
                            self.manifest,
                            destination,
                        );
                    },
                    manifest_mod.MAIN_TREE_INDEX => {
                        try self.prefix.fillMainInto(destination);
                        try self.suffix.fillMainInto(destination);
                        try self.native.fillMainInto(self.manifest, destination);
                        try self.range.fillMainInto(self.manifest, destination);
                    },
                    else => return error.InvalidTreeIndex,
                }
            }

            fn fillInteractionInto(
                self: *Storage,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
                destination: []const []M31,
            ) !GeneratedV4 {
                try self.validateStructure();
                try relations.validate();
                try provider_relations.validateAgainst(relations);
                try preflightFreshTree(
                    self.manifest,
                    manifest_mod.INTERACTION_TREE_INDEX,
                    destination,
                );
                errdefer clearTree(destination);

                // Native preparation is the only retained, allocation-bearing
                // core operation and completes before the first external copy.
                const native_generated = try self.native.prepareInteractions(
                    self.allocator,
                    relations,
                    provider_relations,
                );
                const prefix_claims = try self.prefix.fillInteractionInto(
                    relations,
                    destination,
                );
                const suffix_claims = try self.suffix.fillInteractionInto(
                    relations,
                    destination,
                );
                try self.native.fillInteractionInto(
                    self.manifest,
                    &native_generated,
                    relations,
                    provider_relations,
                    destination,
                );
                const range_generated = try self.range.fillInteractionInto(
                    self.manifest,
                    relations,
                    provider_relations,
                    destination,
                );
                const claims = try claimVector(
                    self.manifest,
                    prefix_claims,
                    suffix_claims,
                    &native_generated,
                    range_generated,
                );
                const closure = try closure_mod.auditAndClose(
                    self.manifest,
                    &claims,
                    &self.prefix,
                    prefix_claims,
                    &self.suffix,
                    suffix_claims,
                    self.native,
                    &native_generated,
                    &self.range,
                    range_generated,
                    relations,
                );
                var result = GeneratedV4{
                    .cohort_identity_sha256 = self.identity_sha256,
                    .manifest_seal = self.manifest.seal,
                    .relation_registry_sha256 = relations.registry_order_digest,
                    .provider_relations_sha256 = try provider_relations.identityDigest(),
                    .prefix = prefix_claims,
                    .suffix = suffix_claims,
                    .native = native_generated,
                    .range = range_generated,
                    .claims = claims,
                    .closure = closure,
                    .identity_sha256 = undefined,
                };
                result.identity_sha256 = generatedIdentity(&result);
                try self.validateGenerated(&result, relations, provider_relations);
                return result;
            }

            fn validateGenerated(
                self: *Storage,
                generated: *const GeneratedV4,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
            ) !void {
                try self.validateStructure();
                try generated.validateStructure();
                try generated.native.validateAgainst(
                    self.native.nativeCoreConst(),
                    relations,
                    provider_relations,
                );
                try generated.range.validateAgainst(
                    &self.range,
                    relations,
                    provider_relations,
                );
                const expected_claims = try claimVector(
                    self.manifest,
                    generated.prefix,
                    generated.suffix,
                    &generated.native,
                    generated.range,
                );
                const expected_closure = try closure_mod.auditAndClose(
                    self.manifest,
                    &expected_claims,
                    &self.prefix,
                    generated.prefix,
                    &self.suffix,
                    generated.suffix,
                    self.native,
                    &generated.native,
                    &self.range,
                    generated.range,
                    relations,
                );
                if (!std.mem.eql(
                    u8,
                    &generated.cohort_identity_sha256,
                    &self.identity_sha256,
                ) or !std.mem.eql(
                    u8,
                    &generated.manifest_seal,
                    &self.manifest.seal,
                ) or !std.mem.eql(
                    u8,
                    &generated.relation_registry_sha256,
                    &relations.registry_order_digest,
                ) or !std.mem.eql(
                    u8,
                    &generated.provider_relations_sha256,
                    &(try provider_relations.identityDigest()),
                ) or !std.meta.eql(generated.claims, expected_claims) or
                    !std.meta.eql(generated.closure, expected_closure))
                {
                    return mismatch();
                }
            }

            fn computeIdentity(self: *const Storage) ![32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hash.update(&(try self.geometry.identity()));
                hash.update(&self.manifest.seal);
                hash.update(&self.prefix.seal);
                hash.update(&self.range.identity_sha256);
                hashInt(&hash, u64, self.tuple_closure.contribution_count);
                hashInt(&hash, u64, self.tuple_closure.unmatched_tuple_count);
                return hash.finalResult();
            }

            fn destroyInitialized(self: *Storage, destroy_storage: bool) void {
                const allocator = self.allocator;
                if (self.range_initialized) self.range.deinit();
                if (self.suffix_initialized) self.suffix.deinit();
                if (self.prefix_initialized) self.prefix.deinit();
                if (self.prefix_components_initialized)
                    self.prefix_components.deinit();
                self.* = undefined;
                if (destroy_storage) allocator.destroy(self);
            }
        };

        fn handle(value: *Storage) *Self {
            return @ptrCast(value);
        }

        fn storage(value: *Self) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn storageConst(value: *const Self) *const Storage {
            return @ptrCast(@alignCast(value));
        }
    };
}

fn claimVector(
    manifest: *const manifest_mod.Manifest,
    prefix: transcript_components.ClaimsV4,
    suffix: suffix_components.ClaimsV4,
    native: *const recursive_core.NativeSegmentCoreGeneratedV2,
    range: range_provider.GeneratedV4,
) !manifest_mod.ClaimVector {
    var result = try manifest_mod.ClaimVector.init(manifest);
    try prefix.bindInto(&result);
    try suffix.bindInto(&result);
    for (native.claims, 18..) |claim, row|
        try result.bind(@enumFromInt(row), claim);
    try result.bind(.range_check_8_8, range.claim);
    try result.sealClaims(manifest);
    return result;
}

fn preflightFreshTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    const protected = [_]support.AddressRange{};
    try support.preflightTree(manifest, tree, destination, &protected);
    for (destination) |column| for (column) |value| if (!value.isZero())
        return error.EthereumIncrementalCompleteCohortMismatchV4;
}

fn clearTree(destination: []const []M31) void {
    for (destination) |column| @memset(column, M31.zero());
}

fn generatedIdentity(value: *const GeneratedV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GENERATED_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.cohort_identity_sha256);
    hash.update(&value.manifest_seal);
    hash.update(&value.relation_registry_sha256);
    hash.update(&value.provider_relations_sha256);
    for (value.claims.values) |claim| hashQm31(&hash, claim);
    hash.update(&value.claims.seal);
    hash.update(&value.closure.identity_sha256);
    hash.update(&value.native.identity);
    hash.update(&value.range.owner_identity_sha256);
    return hash.finalResult();
}

fn hashQm31(hash: anytype, value: stwo_core.fields.qm31.QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn mismatch() Error {
    return error.EthereumIncrementalCompleteCohortMismatchV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        COMPONENT_COUNT != 36 or !TREE0_AVAILABLE or !TREE1_AVAILABLE or
        !TREE2_AVAILABLE or !EXACT_TUPLE_CLOSURE_AVAILABLE or
        !COMPLETE_36_CLAIM_CLOSURE_AVAILABLE or
        UNIVERSAL_PROOF_GATE_AVAILABLE or COLD_CAPTURE_AVAILABLE or
        FOLD_CHILD_AVAILABLE or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental complete cohort V4 drifted");
    }
}
