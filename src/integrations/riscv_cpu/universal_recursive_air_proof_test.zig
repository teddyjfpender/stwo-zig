//! Full-roster native PCS/FRI gate for the universal recursion AIR.
//!
//! This is the first proof lane that installs all 36 manifest rows in one
//! ordered outer proof: 34 compiler-owned logical components and the two
//! authenticated shared native providers.  The witness is deliberately the
//! canonical inactive verifier schedule.  It proves composition/offset/mask
//! integration and global proof plumbing; it does not yet verify child proof
//! bytes or claim a production recursive verifier.

const std = @import("std");
const postcard = @import("interop_postcard");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const prover_pcs = @import("stwo_prover_engine").pcs;

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const recursion_air = recursion.air;
const recursion_engine = recursion.engine;
const adapter = recursion_air.universal_typed_component;
const binding = recursion_air.universal_relation_binding;
const catalog = recursion_air.universal_catalog;
const manifest_mod = recursion_air.universal_adapter_manifest;
const universal_manifest = recursion_air.universal_manifest;
const provider = recursion_air.universal_shared_provider;
const range_bridge = recursion_air.range_check_8_8_bridge;
const roster = recursion_air.universal_roster;
const universal = recursion_air.universal_challenges;

const Engine = recursion_engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion_engine.Hasher,
    recursion_engine.MerkleChannel,
);
const LOGICAL_LOG_SIZE: u32 = 4;
const POSEIDON_LOG_SIZE: u32 = 4;

const FunctionalConfig: stwo_core.pcs.PcsConfig = .{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

test "R-012 full 36-row universal recursion AIR proves and independently verifies" {
    const allocator = std.testing.allocator;
    const log_sizes = canonicalLogSizes();
    const manifest = try universal_manifest.build(log_sizes);
    try std.testing.expectEqual(@as(u8, roster.COMPONENT_COUNT), manifest.roster_count);

    var proof = try proveInactiveUniversal(allocator, &manifest);
    var proof_owned = true;
    defer if (proof_owned) proof.deinit(allocator);
    const proof_size = proof.sizeEstimate();
    const commitments = proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(
        @as(usize, manifest_mod.TREE_COUNT + 1),
        commitments.len,
    );

    // Recursive tree entries carry canonical proof bytes, not an aliased Zig
    // object. Exercise the exact postcard boundary before independent replay.
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try postcard.serializeProof(
        recursion_engine.Hasher,
        encoded.writer(allocator),
        proof,
    );
    proof.deinit(allocator);
    proof_owned = false;
    var stream = std.io.fixedBufferStream(encoded.items);
    var decoded = try postcard.deserializeProof(
        recursion_engine.Hasher,
        allocator,
        stream.reader(),
    );
    var decoded_owned = true;
    defer if (decoded_owned) decoded.deinit(allocator);
    if (stream.pos != encoded.items.len) return error.TrailingProofBytes;
    decoded_owned = false;
    try verifyInactiveUniversal(allocator, &manifest, decoded);

    try std.testing.expect(proof_size != 0 and encoded.items.len != 0);
    std.debug.print(
        "\n  R-012 universal recursion proof: roster={d} " ++
            "columns={d}+{d}+{d} constraints={d} " ++
            "proof_estimate={d} postcard_bytes={d}\n",
        .{
            manifest.roster_count,
            manifest.total_preprocessed_columns,
            manifest.total_main_columns,
            manifest.total_interaction_columns,
            manifest.total_constraints,
            proof_size,
            encoded.items.len,
        },
    );
}

fn proveInactiveUniversal(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
) !recursion_engine.Proof {
    var scheme = try Engine.init(allocator, FunctionalConfig);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};

    var preprocessed = try TreeStorage.init(
        allocator,
        manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    try fillCanonicalProviderPreprocessed(manifest, &preprocessed);
    try preprocessed.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    var main = try TreeStorage.init(
        allocator,
        manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    try main.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    try manifest.mixStatementPrefix(&channel);
    const relations = try universal.UniversalRelations.draw(allocator, &channel);

    var owners: LogicalOwners = undefined;
    var owner_count: usize = 0;
    defer deinitLogicalOwners(&owners, owner_count);
    var provider_relations = try provider.SharedProviderRelations.init(&relations);
    var range_definition = try range_bridge.build(allocator);
    defer range_definition.deinit();
    const range_binding = try range_bridge.Binding.canonical(&range_definition);
    const range_executor = try range_bridge.Executor.init(
        &range_definition,
        &range_binding,
    );
    var poseidon_adapter = try provider.Poseidon2Adapter.init(
        manifest,
        POSEIDON_LOG_SIZE,
        0,
        &provider_relations,
        &relations,
        .{QM31.zero()} ** provider.POSEIDON_INTERACTION_BATCH_COUNT,
    );
    var range_adapter = try provider.RangeCheck8x8Adapter.init(
        &range_definition,
        &range_executor,
        manifest,
        &provider_relations,
        &relations,
        QM31.zero(),
    );

    var gate = try manifest_mod.ProofGate.init(manifest);
    try initLogicalOwners(
        allocator,
        &owners,
        &owner_count,
        manifest,
        &relations,
        &gate,
    );
    try gate.append(manifest, try poseidon_adapter.binding(manifest));
    try gate.append(manifest, try range_adapter.binding(manifest));
    try gate.sealGate(manifest);
    try gate.claims.mixInteractionClaims(manifest, &channel);

    var interaction = try TreeStorage.init(
        allocator,
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();
    try interaction.commit(&scheme, &channel);

    scheme_owned = false;
    var extended = try Engine.prove(
        allocator,
        try gate.proverSlice(),
        &channel,
        scheme,
        .{},
    );
    defer extended.aux.deinit(allocator);
    const proof = extended.proof;
    extended.proof = undefined;
    return proof;
}

fn verifyInactiveUniversal(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    proof_in: recursion_engine.Proof,
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != manifest_mod.TREE_COUNT + 1)
        return error.InvalidProofShape;

    var scheme = try VerifierScheme.init(allocator, FunctionalConfig);
    defer scheme.deinit(allocator);
    var channel = Engine.Channel{};
    try commitVerifierTree(
        allocator,
        &scheme,
        manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
        &channel,
    );
    try commitVerifierTree(
        allocator,
        &scheme,
        manifest,
        manifest_mod.MAIN_TREE_INDEX,
        commitments[manifest_mod.MAIN_TREE_INDEX],
        &channel,
    );
    try manifest.mixStatementPrefix(&channel);
    const relations = try universal.UniversalRelations.draw(allocator, &channel);

    var owners: LogicalOwners = undefined;
    var owner_count: usize = 0;
    defer deinitLogicalOwners(&owners, owner_count);
    var provider_relations = try provider.SharedProviderRelations.init(&relations);
    var range_definition = try range_bridge.build(allocator);
    defer range_definition.deinit();
    const range_binding = try range_bridge.Binding.canonical(&range_definition);
    const range_executor = try range_bridge.Executor.init(
        &range_definition,
        &range_binding,
    );
    var poseidon_adapter = try provider.Poseidon2Adapter.init(
        manifest,
        POSEIDON_LOG_SIZE,
        0,
        &provider_relations,
        &relations,
        .{QM31.zero()} ** provider.POSEIDON_INTERACTION_BATCH_COUNT,
    );
    var range_adapter = try provider.RangeCheck8x8Adapter.init(
        &range_definition,
        &range_executor,
        manifest,
        &provider_relations,
        &relations,
        QM31.zero(),
    );

    var gate = try manifest_mod.ProofGate.init(manifest);
    try initLogicalOwners(
        allocator,
        &owners,
        &owner_count,
        manifest,
        &relations,
        &gate,
    );
    try gate.append(manifest, try poseidon_adapter.binding(manifest));
    try gate.append(manifest, try range_adapter.binding(manifest));
    try gate.sealGate(manifest);
    try gate.claims.mixInteractionClaims(manifest, &channel);
    try commitVerifierTree(
        allocator,
        &scheme,
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        commitments[manifest_mod.INTERACTION_TREE_INDEX],
        &channel,
    );

    proof_moved = true;
    try stwo_core.verifier.verify(
        recursion_engine.Hasher,
        recursion_engine.MerkleChannel,
        allocator,
        try gate.verifierSlice(),
        &channel,
        &scheme,
        proof,
    );
}

fn LogicalOwner(comptime entry: catalog.Entry) type {
    const Air = entry.Air;
    const Relation = binding.Binding(Air);
    const TypedAdapter = adapter.Component(Air, Relation);
    return struct {
        definition: Air.Definition,
        component: TypedAdapter,

        fn init(
            allocator: std.mem.Allocator,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
        ) !@This() {
            var definition = if (entry.requires_location)
                try Air.build(allocator, .generated)
            else
                try Air.build(allocator);
            errdefer definition.deinit();
            const relation_plan = try Relation.authenticate(&definition);
            const parameters = [_]M31{M31.zero()} **
                TypedAdapter.PARAMETER_COLUMN_COUNT;
            const component = try TypedAdapter.init(
                &definition,
                relation_plan,
                manifest,
                entry.row,
                LOGICAL_LOG_SIZE,
                parameters,
                relations,
                QM31.zero(),
            );
            return .{ .definition = definition, .component = component };
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

fn LogicalOwnersType() type {
    var types: [catalog.LOGICAL_COUNT]type = undefined;
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index|
        types[index] = LogicalOwner(entry);
    return std.meta.Tuple(&types);
}

const LogicalOwners = LogicalOwnersType();

fn initLogicalOwners(
    allocator: std.mem.Allocator,
    owners: *LogicalOwners,
    initialized: *usize,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    gate: *manifest_mod.ProofGate,
) !void {
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        owners[index] = try LogicalOwner(entry).init(
            allocator,
            manifest,
            relations,
        );
        initialized.* += 1;
        try gate.append(
            manifest,
            try owners[index].component.binding(manifest),
        );
    }
}

fn deinitLogicalOwners(owners: *LogicalOwners, initialized: usize) void {
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        _ = entry;
        if (index < initialized) owners[index].deinit();
    }
}

const TreeStorage = struct {
    allocator: std.mem.Allocator,
    evaluations: []prover_pcs.ColumnEvaluation,
    storage: []M31,
    backing: [][]M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !TreeStorage {
        const column_count = treeColumnCount(manifest, tree);
        const evaluations = try allocator.alloc(
            prover_pcs.ColumnEvaluation,
            column_count,
        );
        errdefer allocator.free(evaluations);
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset = treeOffset(placement, tree);
            const count = treeGeometryColumns(placement.geometry, tree);
            for (evaluations[offset..][0..count]) |*evaluation|
                evaluation.log_size = placement.geometry.log_size;
        }
        var cells: usize = 0;
        for (evaluations) |evaluation| {
            const rows = @as(usize, 1) << @intCast(evaluation.log_size);
            cells = try std.math.add(usize, cells, rows);
        }
        const storage = try allocator.alloc(M31, cells);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (evaluations) |*evaluation| {
            const rows = @as(usize, 1) << @intCast(evaluation.log_size);
            evaluation.values = storage[cursor..][0..rows];
            cursor += rows;
        }
        std.debug.assert(cursor == storage.len);
        const backing = try allocator.alloc([]M31, 1);
        errdefer allocator.free(backing);
        backing[0] = storage;
        return .{
            .allocator = allocator,
            .evaluations = evaluations,
            .storage = storage,
            .backing = backing,
        };
    }

    fn deinit(self: *TreeStorage) void {
        if (self.evaluations.len != 0) self.allocator.free(self.evaluations);
        if (self.backing.len != 0) self.allocator.free(self.backing);
        if (self.storage.len != 0) self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn column(self: *TreeStorage, index: usize) []M31 {
        return @constCast(self.evaluations[index].values);
    }

    fn commit(
        self: *TreeStorage,
        scheme: *Engine.Scheme,
        channel: *Engine.Channel,
    ) !void {
        const evaluations = self.evaluations;
        const backing = self.backing;
        self.evaluations = &.{};
        self.backing = &.{};
        self.storage = &.{};
        try Engine.commitWithBacking(
            scheme,
            self.allocator,
            evaluations,
            backing,
            null,
            channel,
        );
    }
};

fn fillCanonicalProviderPreprocessed(
    manifest: *const manifest_mod.Manifest,
    tree: *TreeStorage,
) !void {
    const poseidon = try manifest.placement(.poseidon2);
    tree.column(poseidon.preprocessed_offset)[
        committedRow(0, poseidon.geometry.log_size)
    ] = M31.one();

    const range = try manifest.placement(.range_check_8_8);
    tree.column(range.preprocessed_offset)[range_bridge.committedRow(0)] =
        M31.one();
    const low = tree.column(range.preprocessed_offset + 1);
    const high = tree.column(range.preprocessed_offset + 2);
    for (0..range_bridge.TABLE_SIZE) |logical_row| {
        const destination = range_bridge.committedRow(logical_row);
        low[destination] = M31.fromCanonical(@intCast(logical_row & 0xff));
        high[destination] = M31.fromCanonical(@intCast(logical_row >> 8));
    }
}

fn commitVerifierTree(
    allocator: std.mem.Allocator,
    scheme: *VerifierScheme,
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    commitment: recursion_engine.Hasher.Hash,
    channel: *Engine.Channel,
) !void {
    const logs = try allocator.alloc(u32, treeColumnCount(manifest, tree));
    defer allocator.free(logs);
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = treeGeometryColumns(placement.geometry, tree);
        @memset(logs[offset..][0..count], placement.geometry.log_size);
    }
    try scheme.commit(allocator, commitment, logs, channel);
}

fn canonicalLogSizes() universal_manifest.LogSizes {
    var result = [_]u32{LOGICAL_LOG_SIZE} ** roster.COMPONENT_COUNT;
    result[@intFromEnum(roster.Component.poseidon2)] = POSEIDON_LOG_SIZE;
    result[@intFromEnum(roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    return result;
}

fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn treeGeometryColumns(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

fn committedRow(logical_row: usize, log_size: u32) usize {
    return stwo_core.utils.bitReverseIndex(
        stwo_core.utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

comptime {
    if (catalog.LOGICAL_COUNT != 34 or roster.COMPONENT_COUNT != 36)
        @compileError("universal recursion proof roster drifted");
}
