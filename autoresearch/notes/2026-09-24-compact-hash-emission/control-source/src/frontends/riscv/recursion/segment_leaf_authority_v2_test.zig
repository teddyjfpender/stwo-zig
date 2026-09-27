const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const authority = @import("mod.zig").segment_leaf_authority_v2;
const public_data_v2 = @import("../air/public_data_v2.zig");
const public_logup_v2 = @import("../air/public_logup_v2.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const relation = @import("../air/lang/relation.zig");
const support = @import("../air/public_data_v2_test_support.zig");
const frozen_v1 = @import("segment_leaf_authority.zig");

test "segment leaf V2 publishes every authenticated wire and native context word" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try authority.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );

    const preflight = try authority.preflight(&data, &keys);
    try std.testing.expect(!preflight.manifest.frozen_v1_row_compatible);
    try std.testing.expectEqual(
        authority.Activation.requires_v2_outer_manifest,
        preflight.manifest.activation,
    );
    try std.testing.expectEqual(words.len, preflight.manifest.wire_word_count);
    try std.testing.expectEqual(
        words.len + authority.CONTEXT_WORD_COUNT,
        preflight.statement_event_count,
    );
    try std.testing.expectEqual(
        preflight.manifest.trace_row_count * 4 * @sizeOf(M31),
        preflight.source_trace_storage_bytes,
    );

    var owned = try OwnedTrace.init(
        std.testing.allocator,
        preflight.manifest.trace_row_count,
    );
    defer owned.deinit();
    owned.fill(sentinelWord());
    var prepared: authority.PreparedV2 = undefined;
    try authority.prepareInto(&prepared, owned.columns(), &data, &keys);
    try prepared.validateAgainst(&data, &keys);

    try std.testing.expectEqual(words.len, prepared.performance.wire_words);
    try std.testing.expectEqual(
        authority.authorityIdentityPoseidonPermutationCount(),
        prepared.performance.authority_identity_poseidon_permutations,
    );
    try std.testing.expectEqual(
        @as(usize, 41),
        prepared.performance.authority_identity_poseidon_permutations,
    );
    try std.testing.expectEqual(@as(usize, 0), prepared.performance.heap_allocations);
    try std.testing.expectEqual(@sizeOf(authority.PreparedV2), prepared.performance.prepared_bytes);

    const context_words = try prepared.context.canonicalWords();
    for (words, 0..) |word, row| {
        try expectM31(1, owned.active[row]);
        try expectM31(authority.WIRE_SCOPE, owned.scope[row]);
        try expectM31(row, owned.index[row]);
        try std.testing.expect(word.eql(owned.value[row]));
    }
    for (context_words, 0..) |word, index| {
        const row = words.len + index;
        try expectM31(1, owned.active[row]);
        try expectM31(authority.CONTEXT_SCOPE, owned.scope[row]);
        try expectM31(index, owned.index[row]);
        try std.testing.expect(word.eql(owned.value[row]));
    }
    for (preflight.manifest.logical_row_count..preflight.manifest.trace_row_count) |row| {
        try expectM31(0, owned.active[row]);
        try expectM31(0, owned.scope[row]);
        try expectM31(0, owned.index[row]);
        try expectM31(0, owned.value[row]);
    }

    const metadata = try data.metadata();
    try std.testing.expectEqual(
        metadata.entry_continuation_root,
        prepared.context.entry_continuation_root,
    );
    try std.testing.expectEqual(
        metadata.exit_continuation_root,
        prepared.context.exit_continuation_root,
    );
    try std.testing.expect(std.meta.eql(metadata.session_id, prepared.context.session_id));
    try std.testing.expect(std.meta.eql(metadata.job_id, prepared.context.job_id));
    try std.testing.expect(std.meta.eql(metadata.lineage_id, prepared.context.lineage_id));
    try std.testing.expect(std.meta.eql(keys.identity, prepared.context.verifier_key_authority_id));

    const events = try std.testing.allocator.alloc(
        authority.StatementRelationEventV2,
        preflight.statement_event_count,
    );
    defer std.testing.allocator.free(events);
    try authority.writeStatementRelationEventsInto(&prepared, events, &data);
    for (words, 0..) |word, index| {
        try std.testing.expectEqual(relation.Domain.recursion_statement_word, events[index].domain);
        try std.testing.expectEqual(relation.Role.emit, events[index].role);
        try expectM31(authority.WIRE_SCOPE, events[index].tuple[0]);
        try expectM31(index, events[index].tuple[1]);
        try std.testing.expect(word.eql(events[index].tuple[2]));
    }
    for (context_words, 0..) |word, index| {
        const event = events[words.len + index];
        try expectM31(authority.CONTEXT_SCOPE, event.tuple[0]);
        try expectM31(index, event.tuple[1]);
        try std.testing.expect(word.eql(event.tuple[2]));
    }
    try std.testing.expectEqual(preflight.statement_event_count, prepared.statement_relation_evidence.tuple_count);
}

test "segment leaf V2 binds public LogUp and keeps native and SHA publications disjoint" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try authority.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const manifest = try authority.ManifestV2.init(words.len);
    var owned = try OwnedTrace.init(std.testing.allocator, manifest.trace_row_count);
    defer owned.deinit();
    var prepared: authority.PreparedV2 = undefined;
    try authority.prepareInto(&prepared, owned.columns(), &data, &keys);

    const relations = relations_mod.Relations.dummy();
    var publication: authority.PublicLogUpPublicationV2 = undefined;
    try authority.preparePublicLogUpInto(
        &publication,
        &prepared,
        &data,
        &relations,
    );
    try publication.validateAgainst(&prepared, &data, &relations);
    const expected = try public_logup_v2.relationSums(&data, &relations);
    try expectSums(expected, publication.sums);
    try std.testing.expect(publication.total.eql(expected.total()));

    var events: [authority.LOGUP_PUBLICATION_WORD_COUNT]authority.VerifierInputEventV2 = undefined;
    try authority.writeVerifierInputEventsInto(&publication, &events);
    const encoded = try publication.canonicalWords();
    for (events, encoded, 0..) |event, word, index| {
        try std.testing.expectEqual(relation.Domain.recursion_verifier_input_word, event.domain);
        try std.testing.expectEqual(relation.Role.consume, event.role);
        try expectM31(authority.SEGMENT_V2_VERIFIER_ID, event.tuple[0]);
        try expectM31(authority.PUBLIC_LOGUP_V2_KIND, event.tuple[1]);
        try expectM31(index, event.tuple[2]);
        try expectM31(0, event.tuple[3]);
        try std.testing.expect(word.eql(event.tuple[4]));
    }

    var handoff: authority.CohortHandoffV2 = undefined;
    try authority.publishCohortHandoffInto(
        &handoff,
        &prepared,
        &publication,
        &data,
        &relations,
    );
    try handoff.native.validate();
    try handoff.sha_closure.validate();
    try handoff.validateAgainst(&prepared, &publication, &data, &relations);
    try std.testing.expect(std.meta.eql(
        handoff.native.context.authenticated_context_id,
        prepared.context.authenticated_context_id,
    ));
    try std.testing.expect(std.meta.eql(
        handoff.native.public_logup_id,
        publication.identity,
    ));
    try std.testing.expectEqual(
        @as(usize, 19),
        authority.publicLogUpIdentityPoseidonPermutationCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        authority.cohortHandoffIdentityPoseidonPermutationCount(),
    );

    var bad_native = handoff;
    bad_native.native.context.exit_continuation_root +%= 1;
    try std.testing.expectError(
        error.ContextMismatch,
        bad_native.validateAgainst(&prepared, &publication, &data, &relations),
    );
    var bad_sha = handoff;
    bad_sha.sha_closure.statement_relation.tuple_provenance_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidPublication,
        bad_sha.validateAgainst(&prepared, &publication, &data, &relations),
    );
    comptime {
        if (@TypeOf(handoff.native.identity) != authority.Digest)
            @compileError("native temporal identity left its M31 representation");
        if (@TypeOf(handoff.sha_closure.statement_relation.source_authority_id) != [32]u8)
            @compileError("closure identity left its SHA-256 representation");
    }
}

test "segment leaf V2 admits compensated sums only with exact native verifier custody" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try authority.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const manifest = try authority.ManifestV2.init(words.len);
    var owned = try OwnedTrace.init(std.testing.allocator, manifest.trace_row_count);
    defer owned.deinit();
    var prepared: authority.PreparedV2 = undefined;
    try authority.prepareInto(&prepared, owned.columns(), &data, &keys);

    var component_descs: [statement_v1.MAX_COMPONENTS]statement_v1.FamilyComponentDesc =
        undefined;
    component_descs[0] = .{
        .family = .base_alu_imm,
        .log_size = 4,
        .n_rows = 3,
        .n_columns = 10,
    };
    var infra_descs: [statement_v1.MAX_INFRA_COMPONENTS]statement_v1.InfraComponentDesc =
        undefined;
    infra_descs[0] = .{
        .kind = .program,
        .log_size = 4,
        .n_rows = 3,
        .n_columns = 4,
    };
    const core_public = try statement_v2.canonicalCorePublicData(&data);
    const core = statement_v1.RiscVStatement{
        .n_components = 1,
        .component_descs = component_descs,
        .initial_pc = core_public.initial_pc,
        .final_pc = core_public.final_pc,
        .total_steps = core_public.clock,
        .public_data = core_public,
        .n_infra = 1,
        .infra_descs = infra_descs,
    };
    const statement = try statement_v2.RiscVStatementV2.init(core, data);
    const receipt = try statement.verifiedReceipt();
    const relations = relations_mod.Relations.dummy();
    const native_sums = try statement_v2.NativePublicSums.init(&data, &relations);

    var publication: authority.VerifiedNativePublicLogUpPublicationV2 = undefined;
    try authority.prepareVerifiedNativePublicLogUpInto(
        &publication,
        &prepared,
        &data,
        &relations,
        &native_sums,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
    );
    try publication.validateAgainst(
        &prepared,
        &data,
        &relations,
        &native_sums,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
    );
    try std.testing.expect(!publication.productionReady());
    try std.testing.expectEqual(
        authority.VERIFIED_NATIVE_LOGUP_TAG,
        publication.wire_tag,
    );
    try std.testing.expect(std.meta.eql(
        statement.authority_id,
        publication.statement_authority_id,
    ));
    try std.testing.expect(std.meta.eql(data.wireId(), publication.statement_wire_id));
    try expectSums(native_sums.sums, publication.sums);
    const encoded = try publication.canonicalWords();
    try expectM31(authority.VERIFIED_NATIVE_LOGUP_TAG, encoded[0]);

    var events: [authority.LOGUP_PUBLICATION_WORD_COUNT]authority.VerifierInputEventV2 =
        undefined;
    try authority.writeVerifiedNativeVerifierInputEventsInto(&publication, &events);
    for (events, encoded, 0..) |event, word, index| {
        try expectM31(index, event.tuple[2]);
        try std.testing.expect(word.eql(event.tuple[4]));
    }

    var wrong_geometry = core.component_descs[0];
    wrong_geometry.n_rows += 1;
    var rejected: authority.VerifiedNativePublicLogUpPublicationV2 = undefined;
    @memset(std.mem.asBytes(&rejected), 0x5a);
    const before = std.mem.asBytes(&rejected).*;
    try std.testing.expectError(
        error.NativeVerifierCustodyMismatch,
        authority.prepareVerifiedNativePublicLogUpInto(
            &rejected,
            &prepared,
            &data,
            &relations,
            &native_sums,
            &receipt,
            &.{wrong_geometry},
            core.infra_descs[0..core.n_infra],
        ),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&rejected));

    var bad_receipt = receipt;
    bad_receipt.segment_index +%= 1;
    try std.testing.expectError(
        error.InvalidVerifiedReceipt,
        authority.prepareVerifiedNativePublicLogUpInto(
            &rejected,
            &prepared,
            &data,
            &relations,
            &native_sums,
            &bad_receipt,
            core.component_descs[0..core.n_components],
            core.infra_descs[0..core.n_infra],
        ),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&rejected));

    const hash_plan = try authority.AuthorityHashPoseidonPlanV2.init(
        &data,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
    );
    try hash_plan.validateAgainst(
        &data,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
    );
    try std.testing.expectEqual(
        authority.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT +
            2 * authority.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR,
        hash_plan.preimage_word_count,
    );
    try std.testing.expectEqual(
        @as(usize, hash_plan.poseidon_call_count),
        try hash_plan.poseidonCallCount(),
    );
    try std.testing.expect(!hash_plan.productionReady());
    const calls = try std.testing.allocator.alloc(
        poseidon2_air.Call,
        hash_plan.poseidon_call_count,
    );
    defer std.testing.allocator.free(calls);
    try hash_plan.appendPoseidonCallsInto(
        calls,
        &data,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
    );
    try std.testing.expect(calls.len != 0);
    for (calls) |call| {
        try std.testing.expect(!call.wide);
        try std.testing.expect(call.io);
        try std.testing.expect(call.narrow_output == null);
    }
    const final_row = poseidon2_air.fill(calls[calls.len - 1]);
    const final_output = poseidon2_air.output(final_row);
    for (final_output[0..hash_plan.statement_authority_id.len], hash_plan.statement_authority_id) |
        actual,
        expected,
    | try expectM31(expected, actual);

    const short_calls = try std.testing.allocator.alloc(
        poseidon2_air.Call,
        calls.len - 1,
    );
    defer std.testing.allocator.free(short_calls);
    @memset(std.mem.sliceAsBytes(short_calls), 0x7b);
    const short_before = try std.testing.allocator.dupe(
        u8,
        std.mem.sliceAsBytes(short_calls),
    );
    defer std.testing.allocator.free(short_before);
    try std.testing.expectError(
        error.PoseidonCallCountMismatch,
        hash_plan.appendPoseidonCallsInto(
            short_calls,
            &data,
            &receipt,
            core.component_descs[0..core.n_components],
            core.infra_descs[0..core.n_infra],
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        short_before,
        std.mem.sliceAsBytes(short_calls),
    );
}

test "segment leaf V2 trace and relation writes fail atomically" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try authority.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const manifest = try authority.ManifestV2.init(words.len);
    var owned = try OwnedTrace.init(std.testing.allocator, manifest.trace_row_count);
    defer owned.deinit();
    owned.fill(sentinelWord());

    var destination: authority.PreparedV2 = undefined;
    @memset(std.mem.asBytes(&destination), 0xa5);
    const destination_before = std.mem.asBytes(&destination).*;
    const active_before = try std.testing.allocator.dupe(M31, owned.active);
    defer std.testing.allocator.free(active_before);
    const short_trace = authority.TraceColumnsV2{
        .active = owned.active[0 .. owned.active.len - 1],
        .scope = owned.scope,
        .index = owned.index,
        .value = owned.value,
    };
    try std.testing.expectError(
        error.InvalidTraceShape,
        authority.prepareInto(&destination, short_trace, &data, &keys),
    );
    try std.testing.expectEqualSlices(u8, &destination_before, std.mem.asBytes(&destination));
    try expectM31Slices(active_before, owned.active);
    try expectAllM31(owned.scope, sentinelWord());
    try expectAllM31(owned.index, sentinelWord());
    try expectAllM31(owned.value, sentinelWord());

    try std.testing.expectError(
        error.AliasedDestination,
        authority.prepareInto(&destination, .{
            .active = owned.active,
            .scope = owned.active,
            .index = owned.index,
            .value = owned.value,
        }, &data, &keys),
    );
    try std.testing.expectEqualSlices(u8, &destination_before, std.mem.asBytes(&destination));
    try expectM31Slices(active_before, owned.active);

    var bad_keys = keys;
    bad_keys.identity[0] +%= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        authority.prepareInto(&destination, owned.columns(), &data, &bad_keys),
    );
    try std.testing.expectEqualSlices(u8, &destination_before, std.mem.asBytes(&destination));
    try expectM31Slices(active_before, owned.active);

    try authority.prepareInto(&destination, owned.columns(), &data, &keys);
    const events = try std.testing.allocator.alloc(
        authority.StatementRelationEventV2,
        destination.manifest.logical_row_count - 1,
    );
    defer std.testing.allocator.free(events);
    @memset(std.mem.sliceAsBytes(events), 0x6d);
    const event_before = try std.testing.allocator.dupe(u8, std.mem.sliceAsBytes(events));
    defer std.testing.allocator.free(event_before);
    try std.testing.expectError(
        error.DestinationLengthMismatch,
        authority.writeStatementRelationEventsInto(&destination, events, &data),
    );
    try std.testing.expectEqualSlices(u8, event_before, std.mem.sliceAsBytes(events));

    var stale = destination;
    stale.context.exit_continuation_root +%= 1;
    owned.fill(sentinelWord());
    try std.testing.expectError(
        error.SourceMismatch,
        authority.writeTraceInto(&stale, owned.columns(), &data),
    );
    try expectAllColumns(&owned, sentinelWord());
}

test "segment leaf V2 rejects coherent backing replacement and LogUp failures atomically" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const original = try std.testing.allocator.dupe(M31, words);
    defer std.testing.allocator.free(original);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try authority.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const manifest = try authority.ManifestV2.init(words.len);
    var owned = try OwnedTrace.init(std.testing.allocator, manifest.trace_row_count);
    defer owned.deinit();

    var destination: authority.PreparedV2 = undefined;
    try authority.prepareInto(&destination, owned.columns(), &data, &keys);
    const prepared = destination;
    var alternate_source = fixture.rightSource();
    alternate_source.session_id = support.id("coherent-replacement-session");
    const alternate = try support.encode(std.testing.allocator, &alternate_source);
    defer std.testing.allocator.free(alternate);
    try std.testing.expectEqual(words.len, alternate.len);
    @memcpy(words, alternate);
    owned.fill(sentinelWord());
    @memset(std.mem.asBytes(&destination), 0xa5);
    const destination_before = std.mem.asBytes(&destination).*;
    try std.testing.expectError(
        error.SourceMutation,
        authority.prepareInto(&destination, owned.columns(), &data, &keys),
    );
    try std.testing.expectEqualSlices(u8, &destination_before, std.mem.asBytes(&destination));
    try expectAllColumns(&owned, sentinelWord());
    @memcpy(words, original);

    var zero_relations = relations_mod.Relations.dummy();
    const alpha = QM31.one();
    const zero_z = QM31.fromBase(M31.fromU64(0x1008))
        .add(alpha.mulM31(M31.fromU64(3)));
    zero_relations.registers_state = relations_mod.RelationElements(2).init(
        zero_z,
        alpha,
    );
    var publication: authority.PublicLogUpPublicationV2 = undefined;
    @memset(std.mem.asBytes(&publication), 0x39);
    const publication_before = std.mem.asBytes(&publication).*;
    try std.testing.expectError(
        error.ZeroDenominator,
        authority.preparePublicLogUpInto(
            &publication,
            &prepared,
            &data,
            &zero_relations,
        ),
    );
    try std.testing.expectEqualSlices(u8, &publication_before, std.mem.asBytes(&publication));

    const valid_relations = relations_mod.Relations.dummy();
    try authority.preparePublicLogUpInto(
        &publication,
        &prepared,
        &data,
        &valid_relations,
    );
    var short_events: [authority.LOGUP_PUBLICATION_WORD_COUNT - 1]authority.VerifierInputEventV2 = undefined;
    @memset(std.mem.asBytes(&short_events), 0x7c);
    const short_before = std.mem.asBytes(&short_events).*;
    try std.testing.expectError(
        error.DestinationLengthMismatch,
        authority.writeVerifierInputEventsInto(&publication, &short_events),
    );
    try std.testing.expectEqualSlices(u8, &short_before, std.mem.asBytes(&short_events));
}

test "segment leaf V2 is explicitly not the frozen V1 statement row" {
    try std.testing.expect(authority.FORMAT_VERSION != frozen_v1.FORMAT_VERSION);
    try std.testing.expect(!authority.FROZEN_V1_ROW_COMPATIBLE);
    try std.testing.expect(authority.REQUIRES_VERSIONED_OUTER_MANIFEST);
    try std.testing.expect(!authority.PRODUCTION_ACTIVATION);
    try std.testing.expectEqual(@as(u8, 10), authority.FROZEN_V1_ROSTER_ROW);
    try std.testing.expectEqual(@as(usize, 0), authority.HOT_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(u8, 3), authority.STATEMENT_RELATION_ARITY);
    try std.testing.expectEqual(@as(u8, 5), authority.VERIFIER_INPUT_RELATION_ARITY);
    std.testing.refAllDeclsRecursive(authority);
}

const OwnedTrace = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    active: []M31,
    scope: []M31,
    index: []M31,
    value: []M31,

    fn init(allocator: std.mem.Allocator, rows_u32: u32) !OwnedTrace {
        const rows: usize = rows_u32;
        const storage = try allocator.alloc(M31, try std.math.mul(usize, rows, 4));
        return .{
            .allocator = allocator,
            .storage = storage,
            .active = storage[0..rows],
            .scope = storage[rows .. 2 * rows],
            .index = storage[2 * rows .. 3 * rows],
            .value = storage[3 * rows .. 4 * rows],
        };
    }

    fn deinit(self: *OwnedTrace) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn columns(self: *OwnedTrace) authority.TraceColumnsV2 {
        return .{
            .active = self.active,
            .scope = self.scope,
            .index = self.index,
            .value = self.value,
        };
    }

    fn fill(self: *OwnedTrace, word: M31) void {
        @memset(self.storage, word);
    }
};

fn sentinelWord() M31 {
    return M31.fromCanonical(0x1234_5678);
}

fn expectM31(expected: anytype, actual: M31) !void {
    try std.testing.expectEqual(@as(u32, @intCast(expected)), actual.toU32());
}

fn expectM31Slices(expected: []const M31, actual: []const M31) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right| try std.testing.expect(left.eql(right));
}

fn expectAllM31(words: []const M31, expected: M31) !void {
    for (words) |word| try std.testing.expect(expected.eql(word));
}

fn expectAllColumns(trace: *const OwnedTrace, expected: M31) !void {
    try expectAllM31(trace.active, expected);
    try expectAllM31(trace.scope, expected);
    try expectAllM31(trace.index, expected);
    try expectAllM31(trace.value, expected);
}

fn expectSums(expected: public_logup_v2.Sums, actual: public_logup_v2.Sums) !void {
    try std.testing.expect(expected.registers_state.eql(actual.registers_state));
    try std.testing.expect(expected.memory_access.eql(actual.memory_access));
    try std.testing.expect(expected.program_access.eql(actual.program_access));
    try std.testing.expect(expected.merkle.eql(actual.merkle));
}
