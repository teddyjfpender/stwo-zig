//! One real-capture functional gate for the SegmentV2 non-core owner.
//!
//! This helper deliberately accepts the already prepared native leaf so the
//! shared ingress gate pays for native proving exactly once. It exercises no
//! outer STARK; the full proof belongs to the aggregate cohort gate.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const subject = integration.recursive_segment_v2_noncore_owner;
const core_outer = integration.recursive_fri_outer;
const leaf_outer = integration.recursive_segment_v2_leaf_outer;

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;

pub const Error = error{
    CachedGenerationMismatch,
    CoreTreeMutation,
    ForeignContextAccepted,
    InteractionCacheMutation,
    RelationContextDidNotChange,
    TreePublicationEmpty,
};

pub fn runPrepared(
    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
) !void {
    try prepared.validate();
    const source_preflight = subject.PreflightV2.init(prepared) catch |err| {
        return failStage("preflight", err);
    };
    var public_native_relations = subject.nativeRelations(prepared);
    const public_native_inputs = subject.publicInputs(
        prepared,
        &public_native_relations,
    );
    var public_native_sum_source = recursion
        .segment_public_native_sum_authority_v2.SourceV2.init(
        allocator,
        &source_preflight.public_prepared,
        public_native_inputs,
    ) catch |err| return failStage("public_native_sum_source", err);
    defer public_native_sum_source.deinit();
    var log_sizes = [_]u32{0} ** subject.UNIVERSAL_COMPONENT_COUNT;
    try source_preflight.installLogSizes(&log_sizes);
    for (
        prepared.rows_18_34_core.log_sizes,
        core_outer.NATIVE_V2_CORE_FIRST_ROW..,
    ) |log_size, row| log_sizes[row] = log_size;

    // The boundary-independent core receipt counts only its suffix. Row 34
    // commits the admitted transcript + authority prefix and the core suffix
    // as one provider, so install its complete minimal domain here.
    const complete_poseidon_calls = try std.math.add(
        usize,
        prepared.row34_boundary_prefix_calls.len,
        prepared.rows_18_34_core.core_poseidon_call_count,
    );
    log_sizes[34] = @intCast(@max(
        @as(usize, 1),
        std.math.log2_int_ceil(usize, complete_poseidon_calls),
    ));
    const manifest = manifest_mod.build(
        log_sizes,
        &source_preflight.transcript_manifest,
        &source_preflight.statement_manifest,
        &source_preflight.public_manifest,
        &source_preflight.boundary_manifest,
    ) catch |err| return failStage("manifest", err);

    var init_timer = try std.time.Timer.start();
    const owner = try allocator.create(subject.Owner);
    subject.Owner.initInPlace(
        owner,
        allocator,
        prepared,
        &manifest,
        &public_native_sum_source,
    ) catch |err| {
        allocator.destroy(owner);
        return failStage("owner_init", err);
    };
    const init_ns = init_timer.read();
    defer {
        owner.deinit();
        allocator.destroy(owner);
    }
    owner.validate() catch |err| return failStage("owner_validate", err);

    var tree0 = PublicationTree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    ) catch |err| return failStage("tree0_init", err);
    defer tree0.deinit();
    var tree1 = PublicationTree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    ) catch |err| return failStage("tree1_init", err);
    defer tree1.deinit();
    var tree2 = PublicationTree.init(
        allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    ) catch |err| return failStage("tree2_init", err);
    defer tree2.deinit();
    var publish_01_timer = try std.time.Timer.start();
    owner.fillPreprocessedInto(&manifest, tree0.columns) catch |err|
        return failStage("tree0_fill", err);
    owner.fillMainInto(&manifest, tree1.columns) catch |err|
        return failStage("tree1_fill", err);
    const publish_01_ns = publish_01_timer.read();
    if (!containsNonZero(tree0.storage) or !containsNonZero(tree1.storage))
        return error.TreePublicationEmpty;
    if (!coreRowsAreZero(&manifest, manifest_mod.PREPROCESSED_TREE_INDEX, tree0.columns) or
        !coreRowsAreZero(&manifest, manifest_mod.MAIN_TREE_INDEX, tree1.columns))
    {
        return error.CoreTreeMutation;
    }

    // Use an actual transcript draw distinct from ingress admission. This is
    // the lifecycle check that forces boundary Tree 2 regeneration while the
    // owner itself enforces byte equality for committed Tree 0/1.
    var channel = leaf_outer.Engine.Channel{};
    channel.mixU32s(&.{ 0x4e43_5632, 1, 38, 47 });
    const relations = universal.UniversalRelations.draw(allocator, &channel) catch |err|
        return failStage("relation_draw", err);
    const provider_relations = shared_provider.SharedProviderRelations.init(
        &relations,
    ) catch |err| return failStage("provider_relations", err);
    var interaction_timer = try std.time.Timer.start();
    const generated = owner.prepareInteractions(
        allocator,
        &relations,
        &provider_relations,
    ) catch |err| return failStage("interaction_prepare", err);
    const interaction_ns = interaction_timer.read();
    try generated.validateCachedAgainst(owner, &relations, &provider_relations);
    if (std.mem.eql(
        u8,
        &owner.boundary_active_prepared.?.outer_relation_context_sha_id,
        &prepared.authority_prepared.outer_relation_context_sha_id,
    )) return error.RelationContextDidNotChange;

    var publish_2_timer = try std.time.Timer.start();
    const published = owner.fillInteractionInto(&manifest, tree2.columns) catch |err|
        return failStage("tree2_fill", err);
    const publish_2_ns = publish_2_timer.read();
    if (!std.meta.eql(generated, published) or !containsNonZero(tree2.storage))
        return error.TreePublicationEmpty;
    if (!coreRowsAreZero(
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        tree2.columns,
    )) return error.CoreTreeMutation;

    // Generic engine validation is intentionally cached and allocation-free.
    // Repeating it here protects the performance contract from an accidental
    // reintroduction of the 21-row independent audit replay.
    const validation_iterations: usize = 4;
    var cached_timer = try std.time.Timer.start();
    for (0..validation_iterations) |_| try generated.validateCachedAgainst(
        owner,
        &relations,
        &provider_relations,
    );
    const cached_validation_ns = cached_timer.read();
    const cached = try owner.prepareInteractions(
        allocator,
        &relations,
        &provider_relations,
    );
    if (!std.meta.eql(generated, cached))
        return error.CachedGenerationMismatch;

    // A second challenge context is rejected before cached Tree 2, workspaces,
    // or the active pointer-free receipt can change.
    const receipt_before = owner.active_generated.?;
    const tree_before = try owner.interactionTreeIdentity();
    const admission_provider = try shared_provider.SharedProviderRelations.init(
        &prepared.outer_relations,
    );
    if (owner.prepareInteractions(
        allocator,
        &prepared.outer_relations,
        &admission_provider,
    )) |_| return error.ForeignContextAccepted else |_| {}
    if (!std.meta.eql(receipt_before, owner.active_generated.?))
        return error.InteractionCacheMutation;
    const tree_after = try owner.interactionTreeIdentity();
    if (!std.mem.eql(u8, &tree_before, &tree_after))
        return error.InteractionCacheMutation;

    std.debug.print(
        "\nV2_NONCORE_OWNER_REAL rows={d} init_ms={d:.3} " ++
            "publish_01_ms={d:.3} interaction_ms={d:.3} " ++
            "publish_2_ms={d:.3} cached_validate_ns={d} " ++
            "cached_validate_iterations={d} hot_allocations={d}/{d}/{d} " ++
            "cold_independent_audit_replays={d}\n",
        .{
            subject.OWNED_ROW_COUNT,
            milliseconds(init_ns),
            milliseconds(publish_01_ns),
            milliseconds(interaction_ns),
            milliseconds(publish_2_ns),
            cached_validation_ns,
            validation_iterations,
            subject.HOT_TREE_HEAP_ALLOCATIONS[0],
            subject.HOT_TREE_HEAP_ALLOCATIONS[1],
            subject.HOT_TREE_HEAP_ALLOCATIONS[2],
            subject.COLD_INDEPENDENT_AUDIT_REPLAYS_PER_GENERATION,
        },
    );
}

const PublicationTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !PublicationTree {
        const column_count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
            manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
            manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
            else => return error.InvalidTreeIndex,
        };
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        for (columns) |*column| column.* = @constCast((&[_]M31{})[0..]);
        var words: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const count: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const rows = @as(usize, 1) << @intCast(placement.geometry.log_size);
            words = try std.math.add(
                usize,
                words,
                try std.math.mul(usize, count, rows),
            );
        }
        const storage = try allocator.alloc(M31, words);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
                manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
                manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
                else => unreachable,
            };
            const count: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const rows = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[cursor..][0..rows];
                cursor += rows;
            }
        }
        std.debug.assert(cursor == storage.len);
        return .{ .allocator = allocator, .columns = columns, .storage = storage };
    }

    fn deinit(self: *PublicationTree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

fn containsNonZero(values: []const M31) bool {
    for (values) |value| if (!value.isZero()) return true;
    return false;
}

fn coreRowsAreZero(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    columns: []const []M31,
) bool {
    for (core_outer.NATIVE_V2_CORE_FIRST_ROW..core_outer.NATIVE_V2_CORE_LAST_ROW + 1) |row| {
        const placement = manifest.placements[row].?;
        const offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
            manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
            manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
            else => return false,
        };
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
            manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
            manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
            else => return false,
        };
        for (columns[offset..][0..count]) |column|
            for (column) |value| if (!value.isZero()) return false;
    }
    return true;
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn failStage(stage: []const u8, err: anyerror) anyerror {
    std.debug.print("\nV2_NONCORE_OWNER_REAL_FAIL stage={s} error={s}\n", .{
        stage,
        @errorName(err),
    });
    return err;
}
