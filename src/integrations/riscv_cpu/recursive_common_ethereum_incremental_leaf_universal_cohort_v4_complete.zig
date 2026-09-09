//! Complete physical rows0--35 cohort for the schema-3 role-0 wrapper.
//!
//! This owner joins the transcript prefix, V4 statement/public spine, genuine
//! verifier core, and two authenticated shared providers. It closes exact
//! tuples before challenges and reconstructs every domain audit after Tree2.
//! Proof and cold-capture activation remain intentionally outside this file.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const process_usage = @import("stwo_prover_engine").measurement.process_usage;
const compact_ledger = @import("recursive_compact_tuple_ledger_v1.zig");

const statement_boundary = @import("recursive_common_ethereum_incremental_leaf_public_statement_boundary_v4.zig");
const closure_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_closure_v4.zig");
const geometry_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig");
const ordinary_manifest =
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
pub const COMPONENT_COUNT: usize = ordinary_manifest.COMPONENT_COUNT;
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
    EthereumIncrementalTupleReservationExceededV4,
};

pub const Ordinary = Types(ordinary_manifest);
pub const Initial38 = Types(air.ethereum_initial_input_manifest_v1);
pub const GeneratedV4 = Ordinary.Generated;
pub const ComponentSetV4 = Ordinary.ComponentSet;
pub const CohortV4 = Ordinary.Cohort;

/// Select only the physical proof roster. Existing row preparation retains its
/// ordinary prefix contract; the initial extension must close all38 rows.
pub fn Types(comptime manifest_mod: type) type {
    const initial = manifest_mod == air.ethereum_initial_input_manifest_v1;
    if (!initial and manifest_mod != ordinary_manifest)
        @compileError("Ethereum complete cohort requires an explicitly selected manifest");
    return struct {
        const initial_rows = @import("recursive_common_ethereum_initial_input_rows_v1.zig");
        const verifier_components = @import("ethereum_wrapper_verifier_components_v1.zig").Types(manifest_mod);
        pub const Generated = struct {
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
            initial_claims: if (initial) [2]stwo_core.fields.qm31.QM31 else void = if (initial) @splat(stwo_core.fields.qm31.QM31.zero()) else {},
            claims: manifest_mod.ClaimVector,
            closure: closure_mod.ReceiptV4,
            identity_sha256: [32]u8,

            pub fn validateStructure(self: *const Generated) !void {
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
        const OrdinaryComponents = struct {
            prefix: transcript_components.ComponentsV4,
            suffix: suffix_components.ComponentsV4,
            native: native_core.NativeCoreComponentsV4,
            range: range_provider.Adapter,

            pub fn deinit(self: *ComponentSet) void {
                self.native.deinit();
                self.* = undefined;
            }

            pub fn appendToGate(
                self: *const ComponentSet,
                manifest: *const manifest_mod.Manifest,
                gate: *manifest_mod.ProofGate,
            ) !void {
                if (gate.count != 0)
                    return error.EthereumIncrementalCompleteCohortMismatchV4;
                try self.prefix.appendToGate(manifest, gate);
                try self.suffix.appendToGate(manifest, gate);
                try self.native.appendToGate(manifest, gate);
                try gate.append(manifest, try self.range.binding(manifest));
                if (gate.count != manifest_mod.COMPONENT_COUNT)
                    return error.EthereumIncrementalCompleteCohortMismatchV4;
                try @import("ethereum_wrapper_composition_v1.zig").admitGate(manifest, gate);
            }
        };

        pub const ComponentSet = if (initial) struct {
            owner: *verifier_components.OwnedComponentsV1,
            pub fn deinit(self: *@This()) void {
                self.owner.deinit();
                self.* = undefined;
            }
            pub fn appendToGate(self: *const @This(), manifest: *const manifest_mod.Manifest, gate: *manifest_mod.ProofGate) !void {
                return self.owner.appendToGate(manifest, gate);
            }
        } else OrdinaryComponents;

        pub fn Cohort(comptime Engine: type) type {
            const Geometry = geometry_mod.OwnerV4(Engine);
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
                    var resources = ResourceMeasurements.init();
                    resources.mark("begin", null);
                    try geometry.validate();
                    const manifest_value = try geometry.manifest();
                    const preparation = try (try geometry.rows10Through34()).preparationView();
                    if (initial != (preparation.materialized.initial_input_admission != null)) return error.InvalidEthereumInitialInputAdmission;
                    const selected_manifest = if (initial) try manifest_mod.build(manifest_value, (try preparation.materialized.claimShape()).max_input_words) else {};
                    const suffix_source = try geometry.rows10Through34Mutable();
                    const native = try suffix_source.nativeCoreMutable();
                    const backing = try allocator.create(Storage);
                    errdefer allocator.destroy(backing);
                    backing.* = .{
                        .allocator = allocator,
                        .geometry = geometry,
                        .manifest = undefined,
                        .manifest_value = if (initial) selected_manifest else manifest_value.*,
                        .initial_rows = null,
                        .suffix_source = suffix_source,
                        .native = native,
                        .prefix = undefined,
                        .prefix_initialized = false,
                        .suffix = undefined,
                        .suffix_initialized = false,
                        .range = undefined,
                        .range_initialized = false,
                        .tuple_closure = undefined,
                        .identity_sha256 = undefined,
                    };
                    backing.manifest = &backing.manifest_value;
                    errdefer backing.destroyInitialized(false);
                    resources.mark("geometry-ready", null);

                    backing.prefix = try Prefix.init(
                        allocator,
                        try geometry.transcriptRows(),
                        manifest_value,
                    );
                    backing.prefix_initialized = true;
                    resources.mark("prefix-rows", null);
                    backing.suffix = try Suffix.init(
                        allocator,
                        suffix_source,
                        manifest_value,
                    );
                    backing.suffix_initialized = true;
                    resources.mark("suffix-rows", null);

                    // Row34 becomes immutable and complete before the tuple ledger or
                    // any external tree can observe it.
                    try native.finalizeSharedProviderMain(manifest_value);
                    resources.mark("provider-main", null);
                    if (initial) {
                        const prepared = try suffix_source.preparationView();
                        backing.initial_rows = try initial_rows.OwnedV1.init(allocator, prepared.materialized, native);
                        try backing.initial_rows.?.validateAgainst(prepared.materialized, native);
                    }
                    // The ledger remains a challenge-independent closure check,
                    // but retains live tuple balances rather than every event.
                    var closure_ledger = try compact_ledger.Owner.init(allocator, initial);
                    defer {
                        closure_ledger.deinit();
                        resources.mark("ledger-released", null);
                    }
                    var source_ledger = closure_ledger.ledger();
                    defer source_ledger.deinit();
                    resources.mark("ledger-begin", &closure_ledger);
                    try backing.appendSourceTupleContributions(&source_ledger, &closure_ledger, &resources);
                    try closure_ledger.validate();
                    backing.range = try range_provider.OwnerV4.initFromCompact(allocator, &closure_ledger, backing.initial_rows);
                    backing.range_initialized = true;
                    resources.mark("range-provider", &closure_ledger);
                    try backing.range.appendTupleContributions(&source_ledger);
                    resources.mark("ledger-range", &closure_ledger);
                    backing.tuple_closure = try closure_ledger.classify();
                    resources.mark("ledger-classified", &closure_ledger);
                    if (!backing.tuple_closure.isClosed()) {
                        std.debug.print("ETHEREUM_TUPLE_CLOSURE contributions={d} unmatched={d} by_domain={any}\n", .{
                            backing.tuple_closure.contribution_count,
                            backing.tuple_closure.unmatched_tuple_count,
                            backing.tuple_closure.unmatched_by_domain,
                        });
                        source_ledger.printUnmatched(3);
                        return error.EthereumIncrementalTupleNotClosedV4;
                    }

                    backing.identity_sha256 = backing.computeIdentity(try geometry.identity());
                    // Geometry was admitted at entry. The only mutation since
                    // then is native provider finalization inside this call;
                    // check its complete state and our new children locally.
                    try backing.validatePreparedStructure();
                    return handle(backing);
                }

                pub fn deinit(self: *Self) void {
                    storage(self).destroyInitialized(true);
                }

                pub fn validate(self: *const Self) !void {
                    try storageConst(self).validateStructure();
                }

                /// Immutable admission metadata. Full input/proof checks are
                /// explicit through validate(), never a side effect of a read.
                pub fn manifest(self: *const Self) !*const manifest_mod.Manifest {
                    return storageConst(self).manifest;
                }

                pub fn tupleClosure(
                    self: *const Self,
                ) !relation_interaction.TupleClosureReport {
                    return storageConst(self).tuple_closure;
                }

                pub fn identity(self: *const Self) ![32]u8 {
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
                ) !Generated {
                    return storage(self).fillInteractionInto(
                        relations,
                        provider_relations,
                        destination,
                    );
                }

                pub fn validateGenerated(
                    self: *Self,
                    generated: *const Generated,
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
                ) !Generated {
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
                    generated: *const Generated,
                    relations: *const universal.UniversalRelations,
                    provider_relations: *const shared_provider.SharedProviderRelations,
                ) !ComponentSet {
                    const value = storage(self);
                    try value.validateGenerated(
                        generated,
                        relations,
                        provider_relations,
                    );
                    if (initial) return .{ .owner = try verifier_components.OwnedComponentsV1.init(value.allocator, value.manifest, .{ .query_reference = (try value.native.verifierParameters()).query_reference, .poseidon_active_rows = (try value.native.verifierParameters()).poseidon_active_rows }, relations, .{ .values = generated.claims.values, .poseidon_partials = generated.native.poseidon2_partials }) };
                    return .{
                        .prefix = try value.prefix.initComponents(
                            relations,
                            generated.prefix,
                        ),
                        .suffix = try value.suffix.initComponents(
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
                    manifest_value: manifest_mod.Manifest,
                    initial_rows: ?*initial_rows.OwnedV1,
                    suffix_source: *SuffixSource,
                    native: *Native,
                    prefix: *Prefix,
                    prefix_initialized: bool,
                    suffix: *Suffix,
                    suffix_initialized: bool,
                    range: range_provider.OwnerV4,
                    range_initialized: bool,
                    tuple_closure: relation_interaction.TupleClosureReport,
                    identity_sha256: [32]u8,

                    fn ordinaryManifest(self: *const Storage) *const ordinary_manifest.Manifest {
                        return if (initial) &self.manifest.ordinary else self.manifest;
                    }
                    fn prefixDestination(self: *const Storage, tree: usize, destination: []const []M31) []const []M31 {
                        const m = self.ordinaryManifest();
                        return destination[0..switch (tree) {
                            0 => m.total_preprocessed_columns,
                            1 => m.total_main_columns,
                            2 => m.total_interaction_columns,
                            else => unreachable,
                        }];
                    }

                    fn validateStructure(self: *const Storage) !void {
                        // One synchronous upstream admission for the shared
                        // materialization, program and source rows. Children
                        // below check their owned preparation locally.
                        try self.geometry.validate();
                        try self.validatePreparedStructure();
                    }

                    // Construction uses privately owned transcript rows and plans.
                    // Geometry still admits all borrowed Native source inputs;
                    // external validate/validateGenerated keep full source replay.
                    fn validateOperationalStructure(self: *const Storage) !void {
                        try self.geometry.validateOperational();
                        try self.validatePreparedStructure();
                    }

                    // Shared local tail after constructor finalization, full
                    // source admission, or operational transcript validation.
                    // Both runtime entries retain borrowed Native admission.
                    fn validatePreparedStructure(self: *const Storage) !void {
                        const geometry_view = try self.geometry.geometryView();
                        const native = try self.suffix_source.nativeCore();
                        try self.native.validatePreparedComplete();
                        if (!self.prefix_initialized or !self.suffix_initialized or
                            !self.range_initialized or
                            (if (initial) !std.meta.eql(self.manifest.ordinary, geometry_view.manifest.*) else !std.meta.eql(self.manifest.*, geometry_view.manifest.*)) or
                            self.suffix_source != geometry_view.suffix or
                            self.native != native or
                            !self.tuple_closure.isClosed())
                        {
                            return mismatch();
                        }
                        if (initial) {
                            try self.manifest.validate();
                            const prepared = try self.suffix_source.preparationView();
                            try (self.initial_rows orelse return mismatch()).validateAgainst(prepared.materialized, self.native);
                        } else if (self.initial_rows != null) return mismatch();
                        try self.prefix.validatePreparedRows();
                        try self.suffix.validate();
                        try self.range.validate();
                        if (!std.mem.eql(
                            u8,
                            &self.identity_sha256,
                            &self.computeIdentity(geometry_view.identity_sha256),
                        )) return mismatch();
                    }

                    fn appendSourceTupleContributions(
                        self: *const Storage,
                        ledger: *relation_interaction.TupleLedger,
                        closure_ledger: *const compact_ledger.Owner,
                        resources: *ResourceMeasurements,
                    ) !void {
                        try self.prefix.appendTupleContributions(ledger);
                        resources.mark("ledger-prefix", closure_ledger);
                        try self.suffix.appendTupleContributions(ledger);
                        resources.mark("ledger-suffix", closure_ledger);
                        try self.native.appendTupleContributions(self.allocator, ledger);
                        resources.mark("ledger-native", closure_ledger);
                        if (self.initial_rows) |rows| try rows.appendTupleContributions(ledger, relation_interaction.allDomainMask());
                        const prepared = try self.suffix_source.preparationView();
                        try statement_boundary.appendTupleContributions(ledger, &prepared.materialized.schedule.node_public, @intCast(manifest_mod.COMPONENT_COUNT));
                    }

                    fn fillBaseTree(
                        self: *Storage,
                        tree: usize,
                        destination: []const []M31,
                    ) !void {
                        try self.validateOperationalStructure();
                        try preflightFreshTree(self.manifest, tree, destination);
                        if (self.initial_rows) |rows| try rows.validateDestination(destination);
                        errdefer clearTree(destination);
                        const prefix_destination = self.prefixDestination(tree, destination);
                        switch (tree) {
                            manifest_mod.PREPROCESSED_TREE_INDEX => {
                                try self.prefix.fillPreprocessedInto(prefix_destination);
                                try self.suffix.fillPreprocessedInto(prefix_destination);
                                try self.native.fillPreprocessedInto(
                                    self.ordinaryManifest(),
                                    prefix_destination,
                                );
                                try self.range.fillPreprocessedInto(
                                    self.ordinaryManifest(),
                                    prefix_destination,
                                );
                            },
                            manifest_mod.MAIN_TREE_INDEX => {
                                try self.prefix.fillMainInto(prefix_destination);
                                try self.suffix.fillMainInto(prefix_destination);
                                try self.native.fillMainInto(self.ordinaryManifest(), prefix_destination);
                                try self.range.fillMainInto(self.ordinaryManifest(), prefix_destination);
                            },
                            else => return error.InvalidTreeIndex,
                        }
                        if (initial) try self.initial_rows.?.fillBaseInto(self.manifest, tree, destination);
                    }

                    fn fillInteractionInto(
                        self: *Storage,
                        relations: *const universal.UniversalRelations,
                        provider_relations: *const shared_provider.SharedProviderRelations,
                        destination: []const []M31,
                    ) !Generated {
                        try self.validateOperationalStructure();
                        try relations.validate();
                        try provider_relations.validateAgainst(relations);
                        try preflightFreshTree(
                            self.manifest,
                            manifest_mod.INTERACTION_TREE_INDEX,
                            destination,
                        );
                        if (self.initial_rows) |rows| try rows.validateDestination(destination);
                        errdefer clearTree(destination);
                        const prefix_destination = self.prefixDestination(manifest_mod.INTERACTION_TREE_INDEX, destination);

                        // Native preparation is the only retained, allocation-bearing
                        // core operation and completes before the first external copy.
                        const native_generated = try self.native.prepareInteractions(
                            self.allocator,
                            relations,
                            provider_relations,
                        );
                        const prefix_generated = try self.prefix.fillInteractionWithAudit(
                            relations,
                            prefix_destination,
                        );
                        const suffix_generated = try self.suffix.fillInteractionWithAudit(
                            relations,
                            prefix_destination,
                        );
                        try self.native.fillInteractionInto(
                            self.ordinaryManifest(),
                            &native_generated,
                            relations,
                            provider_relations,
                            prefix_destination,
                        );
                        const range_generated = try self.range.fillInteractionInto(
                            self.ordinaryManifest(),
                            relations,
                            provider_relations,
                            prefix_destination,
                        );
                        const prefix_claims = prefix_generated.claims;
                        const suffix_claims = suffix_generated.claims;
                        const initial_claims = if (initial) try self.initial_rows.?.fillInteractionInto(self.manifest, relations, destination) else {};
                        const claims = try claimVector(
                            self.manifest,
                            prefix_claims,
                            suffix_claims,
                            &native_generated,
                            range_generated,
                            initial_claims,
                        );
                        // These audits come from the same inverse planes that
                        // produced Tree2, inside this private transaction. Caller
                        // supplied generated values still use the cold audit below.
                        var audits: [manifest_mod.COMPONENT_COUNT]relation_interaction.DomainAudit = undefined;
                        audits[0..10].* = prefix_generated.audits;
                        audits[10..18].* = suffix_generated.audits;
                        audits[18..35].* = native_generated.audits;
                        audits[35] = try self.range.auditGenerated(relations, range_generated);
                        if (initial) audits[36..38].* = try self.initial_rows.?.auditClaims(relations, initial_claims);
                        const closure = try closure_mod.closeAudits(
                            self.manifest,
                            &claims,
                            &audits,
                            try closure_mod.PublicWireBoundaryV4.derive(self.native, relations),
                            try closure_mod.PublicStatementBoundaryV4.derive(
                                &(try self.suffix_source.preparationView()).materialized.schedule.node_public,
                                relations,
                            ),
                        );
                        var result = Generated{
                            .cohort_identity_sha256 = self.identity_sha256,
                            .manifest_seal = self.manifest.seal,
                            .relation_registry_sha256 = relations.registry_order_digest,
                            .provider_relations_sha256 = try provider_relations.identityDigest(),
                            .prefix = prefix_claims,
                            .suffix = suffix_claims,
                            .native = native_generated,
                            .range = range_generated,
                            .initial_claims = initial_claims,
                            .claims = claims,
                            .closure = closure,
                            .identity_sha256 = undefined,
                        };
                        result.identity_sha256 = generatedIdentity(&result);
                        try result.validateStructure();
                        return result;
                    }

                    fn validateGenerated(
                        self: *Storage,
                        generated: *const Generated,
                        relations: *const universal.UniversalRelations,
                        provider_relations: *const shared_provider.SharedProviderRelations,
                    ) !void {
                        try self.validateStructure();
                        try generated.validateStructure();
                        try self.native.validateGenerated(
                            &generated.native,
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
                            generated.initial_claims,
                        );
                        const expected_closure = try auditAndClose(
                            self.manifest,
                            &expected_claims,
                            self.prefix,
                            generated.prefix,
                            self.suffix,
                            generated.suffix,
                            self.native,
                            &generated.native,
                            &self.range,
                            generated.range,
                            &(try self.suffix_source.preparationView()).materialized.schedule.node_public,
                            relations,
                            self.initial_rows,
                            generated.initial_claims,
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

                    fn computeIdentity(self: *const Storage, geometry_identity: [32]u8) [32]u8 {
                        var hash = std.crypto.hash.sha2.Sha256.init(.{});
                        hash.update(IDENTITY_DOMAIN);
                        hashInt(&hash, u16, FORMAT_VERSION);
                        hashInt(&hash, u16, SCHEMA_VERSION);
                        hash.update(&geometry_identity);
                        hash.update(&self.manifest.seal);
                        hash.update(&self.prefix.identity());
                        hash.update(&self.range.identity_sha256);
                        hashInt(&hash, u64, self.tuple_closure.contribution_count);
                        hashInt(&hash, u64, self.tuple_closure.unmatched_tuple_count);
                        return hash.finalResult();
                    }

                    fn destroyInitialized(self: *Storage, destroy_storage: bool) void {
                        const allocator = self.allocator;
                        if (self.range_initialized) self.range.deinit();
                        if (self.initial_rows) |rows| rows.deinit();
                        if (self.suffix_initialized) self.suffix.deinit();
                        if (self.prefix_initialized) self.prefix.deinit();
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
            initial_claims: if (initial) [2]stwo_core.fields.qm31.QM31 else void,
        ) !manifest_mod.ClaimVector {
            var result = try manifest_mod.ClaimVector.init(manifest);
            for (prefix.values, 0..) |claim, row| try result.bind(@enumFromInt(row), claim);
            for (suffix.values, 10..) |claim, row| try result.bind(@enumFromInt(row), claim);
            for (native.claims, 18..) |claim, row|
                try result.bind(@enumFromInt(row), claim);
            try result.bind(.range_check_8_8, range.claim);
            if (initial) for (initial_claims, 36..) |claim, row| try result.bind(@enumFromInt(row), claim);
            try result.sealClaims(manifest);
            return result;
        }

        fn auditAndClose(manifest: *const manifest_mod.Manifest, claims: *const manifest_mod.ClaimVector, prefix: anytype, prefix_claims: transcript_components.ClaimsV4, suffix: anytype, suffix_claims: suffix_components.ClaimsV4, native: anytype, native_generated: anytype, range: *const range_provider.OwnerV4, range_generated: range_provider.GeneratedV4, node_public: *const @import("recursive_field_node_public_v2.zig").NodePublicV2, relations: *const universal.UniversalRelations, rows: ?*const initial_rows.OwnedV1, initial_claims: if (initial) [2]stwo_core.fields.qm31.QM31 else void) !closure_mod.ReceiptV4 {
            // The caller completed validateStructure in this same synchronous
            // admission. Recompute domain sums from private prepared rows,
            // without reaccepting that shared upstream source again.
            var audits: [manifest_mod.COMPONENT_COUNT]relation_interaction.DomainAudit = undefined;
            audits[0..10].* = try prefix.auditPreparedClaims(relations, prefix_claims);
            audits[10..18].* = try suffix.auditClaims(relations, suffix_claims);
            audits[18..35].* = native_generated.audits;
            audits[35] = try range.auditGenerated(relations, range_generated);
            if (initial) audits[36..38].* = try (rows orelse return mismatch()).auditClaims(relations, initial_claims);
            return closure_mod.closeAudits(manifest, claims, &audits, try closure_mod.PublicWireBoundaryV4.derive(native, relations), try closure_mod.PublicStatementBoundaryV4.derive(node_public, relations));
        }

        fn preflightFreshTree(
            manifest: *const manifest_mod.Manifest,
            tree: usize,
            destination: []const []M31,
        ) !void {
            if (!initial) {
                const protected = [_]support.AddressRange{};
                try support.preflightTree(manifest, tree, destination, &protected);
            } else {
                try manifest.validate();
                const count = switch (tree) {
                    0 => manifest.total_preprocessed_columns,
                    1 => manifest.total_main_columns,
                    2 => manifest.total_interaction_columns,
                    else => return error.InvalidTreeIndex,
                };
                if (destination.len != count) return error.DestinationColumnCountMismatch;
                for (manifest.placements) |maybe| {
                    const placement = maybe orelse return mismatch();
                    const offset: usize = switch (tree) {
                        0 => placement.preprocessed_offset,
                        1 => placement.main_offset,
                        2 => placement.interaction_offset,
                        else => unreachable,
                    };
                    const width: usize = switch (tree) {
                        0 => placement.geometry.preprocessed_columns,
                        1 => placement.geometry.main_columns,
                        2 => placement.geometry.interaction_columns,
                        else => unreachable,
                    };
                    for (destination[offset..][0..width]) |column| if (column.len != @as(usize, 1) << @intCast(placement.geometry.log_size)) return error.DestinationLogSizeMismatch;
                }
                for (destination, 0..) |column, index| {
                    const range = try support.sliceRange(column);
                    for (destination[0..index]) |other| if (range.overlaps(try support.sliceRange(other))) return error.DestinationAlias;
                }
            }
            for (destination) |column| for (column) |value| if (!value.isZero())
                return error.EthereumIncrementalCompleteCohortMismatchV4;
        }

        fn clearTree(destination: []const []M31) void {
            for (destination) |column| @memset(column, M31.zero());
        }

        fn generatedIdentity(value: *const Generated) [32]u8 {
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
    };
}

/// Phase measurements for the compact Ethereum-only closure owner. Footprint
/// is a process lifetime high-water mark; tuple counts are logical events and
/// map capacity is storage, not an estimate of protocol work.
const ResourceMeasurements = struct {
    timer: ?std.time.Timer,

    fn init() ResourceMeasurements {
        return .{ .timer = std.time.Timer.start() catch null };
    }

    fn mark(
        self: *ResourceMeasurements,
        comptime phase: []const u8,
        ledger: ?*const compact_ledger.Owner,
    ) void {
        const wall_ns: ?u64 = if (self.timer) |*timer| timer.lap() else null;
        const snapshot: ?process_usage.Snapshot = process_usage.sample() catch null;
        const metrics = if (ledger) |value| value.metrics() else null;
        @import("ethereum_wrapper_resources_v1.zig").progress(
            "ETHEREUM_COHORT_RESOURCES phase={s} wall_ns={?d} source={s} " ++
                "lifetime_peak_footprint_bytes={?d} ledger_present={} ledger_mode=compact " ++
                "ledger_len={d} ledger_live_entries={d} ledger_peak_entries={d} " ++
                "ledger_capacity_entries={d} ledger_source_range_contributions={d} " ++
                "ledger_retained_bytes_estimate={d} " ++
                "sampling_unavailable={s}\n",
            .{
                phase,
                wall_ns,
                if (snapshot) |value| @tagName(value.source) else "unavailable",
                if (snapshot) |value| value.lifetime_peak_physical_footprint_bytes else null,
                ledger != null,
                if (metrics) |value| value.contribution_count else 0,
                if (metrics) |value| value.live_entries else 0,
                if (metrics) |value| value.peak_entries else 0,
                if (metrics) |value| value.capacity_entries else 0,
                if (metrics) |value| value.source_range_contribution_count else 0,
                if (metrics) |value| value.retained_bytes else 0,
                if (snapshot) |value| value.unavailable_reason orelse "none" else "sampling_failed",
            },
        );
    }
};

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
