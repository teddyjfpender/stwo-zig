const std = @import("std");
const compat = @import("typed_poseidon2_compat.zig");
const identity = @import("typed_poseidon2_identity.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const proof_harness = @import("typed_poseidon2_proof_harness.zig");
const relations = @import("typed_poseidon2_relations.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const witness = @import("typed_poseidon2_witness.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

test "Poseidon program identity is source and allocation invariant with a fixed golden" {
    var first = try Fixture.init(
        std.testing.allocator,
        "air/components/poseidon2_m31.first.zig",
        2,
    );
    defer first.deinit();
    var second_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer second_allocator.deinit();
    var second = try Fixture.init(
        second_allocator.allocator(),
        "a/completely/different/source/tree/poseidon2.zig",
        700,
    );
    defer second.deinit();

    const first_identity = try first.programIdentity();
    const second_identity = try second.programIdentity();
    try std.testing.expectEqualSlices(
        u8,
        &first_identity.semantic_digest,
        &second_identity.semantic_digest,
    );
    try std.testing.expectEqualSlices(
        u8,
        &first_identity.layout_digest,
        &second_identity.layout_digest,
    );
    try std.testing.expectEqualSlices(
        u8,
        &first_identity.executor_digest,
        &second_identity.executor_digest,
    );
    try std.testing.expectEqualSlices(
        u8,
        &first_identity.relation_digest,
        &second_identity.relation_digest,
    );
    const first_bytes = try first_identity.receiptBytes();
    const second_bytes = try second_identity.receiptBytes();
    try std.testing.expectEqualSlices(u8, &first_bytes, &second_bytes);
    var receipt_sha256: identity.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first_bytes, &receipt_sha256, .{});
    try std.testing.expectEqualSlices(
        u8,
        &identity.CANONICAL_RECEIPT_SHA256,
        &receipt_sha256,
    );

    const decoded = try identity.ProgramIdentity.fromReceiptBytes(&first_bytes);
    try std.testing.expectEqualDeep(first_identity, decoded);

    try std.testing.expectEqualDeep(identity.ProgramIdentity.canonical(), first_identity);
}

test "all four child identities affect the combined identity and transport rejects corruption" {
    var fixture = try Fixture.init(std.testing.allocator, "identity-classes.zig", 2);
    defer fixture.deinit();
    const canonical = try fixture.programIdentity();

    inline for (0..4) |identity_class| {
        var semantic_digest = canonical.semantic_digest;
        var layout_digest = canonical.layout_digest;
        var executor_digest = canonical.executor_digest;
        var relation_digest = canonical.relation_digest;
        switch (identity_class) {
            0 => semantic_digest[0] ^= 1,
            1 => layout_digest[0] ^= 1,
            2 => executor_digest[0] ^= 1,
            3 => relation_digest[0] ^= 1,
            else => unreachable,
        }
        const changed = identity.ProgramIdentity.sealDigests(
            semantic_digest,
            layout_digest,
            executor_digest,
            relation_digest,
        );
        try std.testing.expect(!std.mem.eql(
            u8,
            &canonical.combined_digest,
            &changed.combined_digest,
        ));
    }

    var invalid_seal = canonical;
    invalid_seal.combined_digest[0] ^= 1;
    try std.testing.expectError(
        error.ProgramIdentityMismatch,
        invalid_seal.validate(),
    );

    const canonical_bytes = try canonical.receiptBytes();
    for (0..canonical_bytes.len) |index| {
        var corrupted = canonical_bytes;
        corrupted[index] ^= 1;
        try expectReceiptRejected(&corrupted);
    }
}

test "layout identity pins every main mapping and physical interaction and claim slot" {
    var fixture = try Fixture.init(std.testing.allocator, "layout.zig", 2);
    defer fixture.deinit();
    const canonical = try identity.LayoutIdentity.init(
        &fixture.binding,
        &fixture.relation_plan,
    );
    const canonical_digest = try canonical.digestValue();

    for (0..compat.N_MATERIALIZATIONS) |ordinal| {
        var changed = canonical;
        const next = (ordinal + 1) % compat.N_MATERIALIZATIONS;
        const column = compat.TEMPORARY_START + ordinal;
        const next_column = compat.TEMPORARY_START + next;
        const saved = changed.main_columns[column].materialization.plan_materialization;
        changed.main_columns[column].materialization.plan_materialization =
            changed.main_columns[next_column].materialization.plan_materialization;
        changed.main_columns[next_column].materialization.plan_materialization = saved;
        const changed_digest = try changed.digestValue();
        try std.testing.expect(!std.mem.eql(
            u8,
            &canonical_digest,
            &changed_digest,
        ));
    }

    var wrong_role = canonical;
    wrong_role.main_columns[compat.ENABLER_COLUMN] = .wide;
    try std.testing.expectError(error.LayoutColumnMismatch, wrong_role.validate());

    var wrong_order = canonical;
    const first_temporary = compat.TEMPORARY_START;
    const saved = wrong_order.main_columns[first_temporary];
    wrong_order.main_columns[first_temporary] =
        wrong_order.main_columns[first_temporary + 1];
    wrong_order.main_columns[first_temporary + 1] = saved;
    try std.testing.expectError(error.LayoutColumnMismatch, wrong_order.validate());

    var wrong_interaction = canonical;
    wrong_interaction.interaction_columns[0].coordinate = 1;
    try std.testing.expectError(
        error.LayoutInteractionMismatch,
        wrong_interaction.validate(),
    );

    var wrong_claim = canonical;
    wrong_claim.claim_slots[0].batch_ordinal = 1;
    try std.testing.expectError(error.LayoutClaimMismatch, wrong_claim.validate());
}

test "relation identity covers every event and batch field and binds the layout" {
    var fixture = try Fixture.init(std.testing.allocator, "relations.zig", 2);
    defer fixture.deinit();
    const layout = try identity.LayoutIdentity.init(
        &fixture.binding,
        &fixture.relation_plan,
    );
    const layout_digest = try layout.digestValue();
    const canonical = try identity.relationDigest(&fixture.relation_plan, layout_digest);

    var changed_layout_digest = layout_digest;
    changed_layout_digest[0] ^= 1;
    const layout_bound = try identity.relationDigest(
        &fixture.relation_plan,
        changed_layout_digest,
    );
    try std.testing.expect(!std.mem.eql(u8, &canonical, &layout_bound));

    var changed = fixture.relation_plan;
    changed.events[0].id = .io;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].ordinal += 1;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].schema = @enumFromInt(@intFromEnum(changed.events[0].schema) + 1);
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].schema_version += 1;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].domain = .poseidon2_io;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].role = .emit;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].access_ordinal = 0;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].relation_arity -= 1;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].semantic_width -= 1;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].numerator = .enabled_io;
    try expectRelationEventRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.events[0].projection = .input_output;
    try expectRelationEventRejected(&changed, layout_digest);

    changed = fixture.relation_plan;
    changed.batches[0].ordinal += 1;
    try expectRelationBatchRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.batches[0].first = .wide_output;
    try expectRelationBatchRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.batches[0].second = .io;
    try expectRelationBatchRejected(&changed, layout_digest);
    changed = fixture.relation_plan;
    changed.batches[0].interaction_column_start += 1;
    try expectRelationBatchRejected(&changed, layout_digest);
}

test "executor and cross-component corruption fail closed" {
    var fixture = try Fixture.init(std.testing.allocator, "corruption.zig", 2);
    defer fixture.deinit();
    _ = try fixture.executor.identityDigest();

    const saved_input_slot = fixture.executor.input_slots[0];
    fixture.executor.input_slots[0] = fixture.executor.input_slots[1];
    try std.testing.expectError(
        error.CorruptExecutor,
        fixture.executor.identityDigest(),
    );
    fixture.executor.input_slots[0] = saved_input_slot;
    _ = try fixture.executor.identityDigest();

    fixture.relation_plan.program_digest[0] ^= 1;
    try std.testing.expectError(
        error.ComponentIdentityMismatch,
        fixture.programIdentity(),
    );
}

test "proof receipt reauthenticates owned H-003 state after authority construction" {
    var context = try proof_harness.Context.init(
        std.testing.allocator,
        "v006-lifecycle-test",
        .none,
    );
    defer context.deinit();

    // This changes only the owned H-003 plan. The H-004/H-005/H-006 snapshots
    // and the identity sealed at construction remain untouched, so local child
    // digest recomputation alone cannot observe the drift.
    context.authority.plan.program_digest[0] ^= 1;
    try std.testing.expectError(error.ProgramDigestMismatch, context.receipt());
}

test "proof receipt rejects a self-consistent noncanonical program identity" {
    const canonical = identity.ProgramIdentity.canonical();
    var changed_semantic = canonical.semantic_digest;
    changed_semantic[0] ^= 1;
    const noncanonical = identity.ProgramIdentity.sealDigests(
        changed_semantic,
        canonical.layout_digest,
        canonical.executor_digest,
        canonical.relation_digest,
    );
    try noncanonical.validate();
    try std.testing.expect(!noncanonical.isCanonical());

    const receipt = proof_harness.Receipt{
        .backend_name = "v006-receipt-test",
        .active_rows = 1,
        .narrow_rows = 1,
        .wide_rows = 0,
        .io_rows = 0,
        .main_column_offset = 0,
        .interaction_column_offset = 0,
        .main_columns = compat.N_MAIN_COLUMNS,
        .interaction_columns = relations.N_INTERACTION_COLUMNS,
        .main_matched_legacy = true,
        .interaction_matched_legacy = true,
        .transcript_claim_from_typed = true,
        .component_claims_from_typed = true,
        .output_claims_from_typed = true,
        .commits_seen = 3,
        .typed_claims = .{ QM31.zero(), QM31.zero() },
        .program_identity = noncanonical,
    };
    try std.testing.expectError(
        error.PoseidonProgramIdentityMismatch,
        receipt.validate(),
    );
}

test "identity construction releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator, "allocation-failure.zig", 2);
    defer fixture.deinit();
    _ = try fixture.programIdentity();
}

fn expectReceiptRejected(bytes: *const [identity.RECEIPT_BYTES_LEN]u8) !void {
    if (identity.ProgramIdentity.fromReceiptBytes(bytes)) |_| {
        return error.TestExpectedError;
    } else |_| {}
}

fn expectRelationEventRejected(
    plan: *const relations.Plan,
    layout_digest: identity.Digest,
) !void {
    try std.testing.expectError(
        error.EventPlanMismatch,
        identity.relationDigest(plan, layout_digest),
    );
}

fn expectRelationBatchRejected(
    plan: *const relations.Plan,
    layout_digest: identity.Digest,
) !void {
    try std.testing.expectError(
        error.BatchPlanMismatch,
        identity.relationDigest(plan, layout_digest),
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,
    materialization_plan: materializer.Plan,
    binding: compat.OwnedBinding,
    executor: witness.Executor,
    relation_plan: relations.Plan,

    fn init(
        allocator: std.mem.Allocator,
        source_path: []const u8,
        first_line: u32,
    ) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource(source_path);
        const gate = try arena.input(
            compat.ENABLER_NAME,
            .selector,
            try spanAt(source_id, first_line),
        );
        const spans = try distinctSpans(source_id, first_line + 1);
        const definition = try poseidon.define(&arena, spans);
        const roots = poseidon.values(definition.outputs);
        var materialization_plan = try materializer.plan(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
        });
        errdefer materialization_plan.deinit();
        var schedule = try compat.generate(allocator);
        defer schedule.deinit(allocator);
        var binding = try compat.bindPlan(
            allocator,
            &arena,
            definition,
            spans,
            schedule,
            &materialization_plan,
        );
        errdefer binding.deinit(allocator);
        var executor = try witness.Executor.init(
            allocator,
            &arena,
            definition,
            spans,
            &materialization_plan,
            &binding,
        );
        errdefer executor.deinit();
        var result = Fixture{
            .allocator = allocator,
            .arena = arena,
            .gate = gate,
            .spans = spans,
            .definition = definition,
            .materialization_plan = materialization_plan,
            .binding = binding,
            .executor = executor,
            .relation_plan = undefined,
        };
        result.relation_plan = try relations.authenticate(
            allocator,
            result.relationAuthority(),
        );
        return result;
    }

    fn deinit(self: *Fixture) void {
        self.executor.deinit();
        self.binding.deinit(self.allocator);
        self.materialization_plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    fn relationAuthority(self: *const Fixture) relations.Authority {
        return .{
            .arena = &self.arena,
            .definition = self.definition,
            .spans = self.spans,
            .materialization_plan = &self.materialization_plan,
            .binding = &self.binding,
        };
    }

    fn programIdentity(self: *const Fixture) !identity.ProgramIdentity {
        return identity.ProgramIdentity.fromAuthenticated(
            &self.binding,
            &self.executor,
            &self.relation_plan,
        );
    }
};

fn distinctSpans(
    source_id: types.SourceId,
    first_line: u32,
) !poseidon.DefinitionSpans {
    var next_line = first_line;
    const declaration = try spanAt(source_id, next_line);
    next_line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, next_line);
        next_line += 1;
    }
    const initial_linear = try spanAt(source_id, next_line);
    next_line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}
