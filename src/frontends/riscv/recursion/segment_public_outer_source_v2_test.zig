//! Focused V2 public-spine bridge, custody, and mutation gates.

const std = @import("std");
const stwo_core = @import("stwo_core");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const relation = @import("../air/lang/relation.zig");
const source_v2 = @import("segment_leaf_authority_v2.zig");
const subject = @import("segment_public_outer_source_v2.zig");
const fixture_support = @import("segment_public_outer_test_support.zig");
const control_air_v2 = @import("air/vm_public_logup_control_v2.zig");
const control_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");

const Fixture = fixture_support.Fixture;

test "V2 public spine writes exact recursion-local bridge rows" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try subject.preflight(fixture.inputs());
    try prepared.manifest.validate();
    try prepared.lowering_obligation.validate();
    try prepared.closureLedger().validate();
    try std.testing.expect(!prepared.productionReady());

    const wire = fixture.owned_public.data.words();
    const counts = prepared.counts();
    try std.testing.expectEqual(subject.PUBLICATION_HEADER_WORD_COUNT, counts.publication_header);
    try std.testing.expectEqual(subject.NATIVE_PUBLIC_SUM_WORD_COUNT, counts.native_public_sums);
    try std.testing.expectEqual(subject.PUBLICATION_SEAL_WORD_COUNT, counts.publication_seal);
    try std.testing.expectEqual(wire.len, counts.boundary_bridge);
    try std.testing.expectEqual(subject.CHALLENGE_WORD_COUNT, counts.native_challenges);
    try std.testing.expectEqual(subject.CONTROL_LOGICAL_ROW_COUNT, counts.control_relay);
    try std.testing.expectEqual(
        subject.CONTROL_RELATION_EVENT_COUNT,
        counts.control_relation_events,
    );
    try std.testing.expectEqual(
        @as(usize, prepared.authority_hash_plan.poseidon_call_count) +
            subject.AUTHORITY_BIND_EVENT_COUNT,
        counts.authority_relation_events,
    );
    try std.testing.expectEqual(
        3 * (subject.PUBLICATION_WORD_COUNT + wire.len +
            subject.CHALLENGE_WORD_COUNT) +
            counts.authority_relation_events +
            subject.CONTROL_RELATION_EVENT_COUNT,
        counts.relation_events,
    );
    try std.testing.expectEqual(@as(u8, 5), prepared.manifest.log_sizes[0]);
    try std.testing.expectEqual(@as(u8, 4), prepared.manifest.log_sizes[1]);
    try std.testing.expectEqual(@as(u8, 4), prepared.manifest.log_sizes[2]);
    try std.testing.expectEqual(@as(u8, 5), prepared.manifest.log_sizes[4]);
    try std.testing.expectEqual(@as(u8, 7), prepared.manifest.log_sizes[5]);
    try std.testing.expectEqual(
        prepared.lowering_obligation.identity,
        prepared.manifest.lowering_obligation_id,
    );
    const closure = prepared.closureLedger();
    try std.testing.expectEqual(@as(u32, 0), closure.base_domain_event_count);
    try std.testing.expectEqual(@as(u32, 0), closure.range_check_event_count);
    try std.testing.expectEqual(
        closure.source37_publication_bridge_emits,
        closure.rows12_14_publication_bridge_consumes,
    );
    try std.testing.expect(closure.source37_bridge_producer_bound);
    try std.testing.expectEqual(
        closure.row11_boundary_bridge_emits,
        closure.row15_boundary_bridge_consumes,
    );

    var published: subject.PreparedV2 = undefined;
    try subject.prepareInto(&published, fixture.inputs());
    try published.validateAgainst(fixture.inputs());
    try std.testing.expectEqualDeep(prepared, published);

    var owned = try OwnedDestinations.init(std.testing.allocator, counts);
    defer owned.deinit();
    try subject.writeInto(&prepared, owned.view(), fixture.inputs());

    for (owned.relation_events) |event| {
        try event.validate();
        try std.testing.expect(
            event.domain == .recursion_wire or
                event.domain == .recursion_relation_challenge_word,
        );
    }
    try expectCanonicalEventOrder(owned.relation_events);
    try expectEventTriplets(owned.relation_events);
    for (owned.control_relation_events) |event| try event.validate();
    try expectExactControlProjection(&owned);

    var publication_events: [source_v2.LOGUP_PUBLICATION_WORD_COUNT]source_v2.VerifierInputEventV2 = undefined;
    try source_v2.writeVerifiedNativeVerifierInputEventsInto(
        &fixture.publication,
        &publication_events,
    );
    for (publication_events, 0..) |captured, publication_index| {
        const row = publicationRow(&owned, publication_index);
        const arithmetic = publication_index >= subject.PUBLICATION_SUM_START and
            publication_index < subject.PUBLICATION_SEAL_START +
                subject.NATIVE_TOTAL_WORD_COUNT;
        const control = publication_index == subject.CONTROL_PUBLICATION_INDEX;
        try std.testing.expectEqual(subject.RelaySourceKindV2.publication_bridge, row.source_kind);
        try std.testing.expectEqual(subject.PUBLICATION_BRIDGE_CIRCUIT_ID, row.source_fields[0]);
        try std.testing.expectEqual(@as(u32, @intCast(publication_index)), row.source_fields[1]);
        try expectZeroWords(row.source_fields[2..]);
        try std.testing.expect(captured.tuple[4].eql(row.value));
        try std.testing.expectEqual(@as(u32, @intFromBool(arithmetic)), row.arithmetic_mask);
        try std.testing.expectEqual(@as(u32, @intFromBool(arithmetic)), row.arithmetic_use_count);
        try std.testing.expectEqual(@as(u32, @intFromBool(control)), row.control_mask);
        try std.testing.expectEqual(@as(u32, @intFromBool(control)), row.control_use_count);
        if (arithmetic) try std.testing.expectEqual(
            @as(u32, @intCast(wire.len + publication_index - subject.PUBLICATION_SUM_START)),
            row.arithmetic_node_id,
        );
    }

    for (owned.boundary_bridge, wire, 0..) |row, value, index| {
        try std.testing.expectEqual(subject.RelaySourceKindV2.boundary_bridge, row.source_kind);
        try std.testing.expectEqual(subject.BOUNDARY_BRIDGE_CIRCUIT_ID, row.source_fields[0]);
        try std.testing.expectEqual(@as(u32, @intCast(index)), row.source_fields[1]);
        try std.testing.expect(value.eql(row.value));
        try std.testing.expectEqual(@as(u32, 1), row.arithmetic_mask);
        try std.testing.expectEqual(@as(u32, @intCast(index)), row.arithmetic_node_id);
        try std.testing.expectEqual(@as(u32, 1), row.arithmetic_use_count);
        try std.testing.expectEqual(@as(u32, 0), row.control_mask);
    }

    for (owned.native_challenges, 0..) |row, index| {
        try std.testing.expectEqual(subject.RelaySourceKindV2.native_challenge, row.source_kind);
        try std.testing.expectEqual(subject.TRANSCRIPT_VERIFIER_ID, row.source_fields[0]);
        try std.testing.expectEqual(@as(u32, @intCast(index / 8)), row.source_fields[2]);
        try std.testing.expectEqual(@as(u32, @intCast(index % 8)), row.source_fields[3]);
        try std.testing.expectEqual(@as(u32, 1), row.arithmetic_mask);
        try std.testing.expectEqual(
            @as(u32, @intCast(wire.len + subject.ARITHMETIC_PUBLICATION_WORD_COUNT + index)),
            row.arithmetic_node_id,
        );
    }

    const control_value =
        publication_events[subject.CONTROL_PUBLICATION_INDEX].tuple[4];
    try std.testing.expect(control_value.eql(prepared.control.relay.value));
    try std.testing.expect(control_value.eql(
        owned.control_main[0][control_witness_v2.PUBLIC_TERM_COUNT],
    ));
    try std.testing.expect(control_value.eql(
        owned.control_logical_rows[control_witness_v2.PUBLIC_TERM_COUNT][0],
    ));
    for (owned.control_logical_rows[subject.CONTROL_LOGICAL_ROW_COUNT..]) |row|
        for (row) |word| try std.testing.expect(word.isZero());

    try expectExactRelationProjection(&owned, wire.len);
}

test "V2 public spine rejects omitted and aliased destinations before writes" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try subject.preflight(fixture.inputs());
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    owned.fillSentinel();
    const before = owned.digest();

    var short = owned.view();
    short.boundary_bridge = short.boundary_bridge[0 .. short.boundary_bridge.len - 1];
    try std.testing.expectError(
        error.DestinationLengthMismatch,
        subject.writeInto(&prepared, short, fixture.inputs()),
    );
    try std.testing.expectEqual(before, owned.digest());

    var aliased = owned.view();
    aliased.control.main[0] = aliased.control.preprocessed[0];
    try std.testing.expectError(
        error.AliasedDestination,
        subject.writeInto(&prepared, aliased, fixture.inputs()),
    );
    try std.testing.expectEqual(before, owned.digest());
}

test "V2 public spine rejects publication challenge and wire mutations atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try subject.preflight(fixture.inputs());
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    owned.fillSentinel();
    const before = owned.digest();

    fixture.publication.identity[0] ^= 1;
    try expectWriteFailure(&prepared, &owned, fixture.inputs());
    fixture.publication.identity[0] ^= 1;
    try std.testing.expectEqual(before, owned.digest());

    const saved_relations = fixture.relations;
    fixture.relations.registers_state.z =
        fixture.relations.registers_state.z.add(QM31.one());
    try expectWriteFailure(&prepared, &owned, fixture.inputs());
    fixture.relations = saved_relations;
    try std.testing.expectEqual(before, owned.digest());

    const last = fixture.owned_public.canonical_words.len - 1;
    const saved_word = fixture.owned_public.canonical_words[last];
    @constCast(fixture.owned_public.canonical_words)[last] =
        saved_word.add(M31.one());
    try expectWriteFailure(&prepared, &owned, fixture.inputs());
    @constCast(fixture.owned_public.canonical_words)[last] = saved_word;
    try std.testing.expectEqual(before, owned.digest());
}

test "V2 public spine rejects manifest obligation event and capability drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const prepared = try subject.preflight(fixture.inputs());
    var bad_manifest = prepared.manifest;
    bad_manifest.format_version = 1;
    try std.testing.expectError(error.InvalidManifest, bad_manifest.validate());
    bad_manifest = prepared.manifest;
    bad_manifest.lowering_obligation_id[0] ^= 1;
    try std.testing.expectError(error.InvalidManifest, bad_manifest.validate());

    var bad_obligation = prepared.lowering_obligation;
    bad_obligation.graph_bound = true;
    try std.testing.expectError(error.InvalidCapabilityLedger, bad_obligation.validate());

    var bad_ledger = subject.CAPABILITY_LEDGER;
    bad_ledger.production_ready = true;
    try std.testing.expectError(error.InvalidCapabilityLedger, bad_ledger.validate());

    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    try subject.writeInto(&prepared, owned.view(), fixture.inputs());
    var event = owned.relation_events[0];
    event.arity += 1;
    try std.testing.expectError(error.InvalidRelationEvent, event.validate());
    event = owned.relation_events[0];
    event.roster_row = subject.FIRST_ROW - 1;
    try std.testing.expectError(error.InvalidRelationEvent, event.validate());
    event = owned.relation_events[0];
    event.tuple[event.arity] = M31.one();
    try std.testing.expectError(error.InvalidRelationEvent, event.validate());
    event = owned.relation_events[0];
    event.multiplicity = m31.Modulus;
    try std.testing.expectError(error.InvalidRelationEvent, event.validate());
}

test "V2 public-spine capability ledger is explicitly source only" {
    try subject.CAPABILITY_LEDGER.validate();
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.FROZEN_V1_ROW_COMPATIBLE);
    try std.testing.expect(!subject.BASE_DOMAIN_OUTER_EVENTS_EMITTED);
    try std.testing.expect(subject.SOURCE_36_BOUNDARY_BRIDGE_AVAILABLE);
    try std.testing.expect(subject.SOURCE_37_PUBLICATION_BRIDGE_REQUIRED);
    try std.testing.expect(subject.SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE);
    try std.testing.expectEqual(@as(usize, 0), subject.HOT_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(
        @as(usize, 10),
        subject.MISSING_INTEGRATION_CAPABILITIES.len,
    );
}

const OwnedDestinations = struct {
    allocator: std.mem.Allocator,
    publication_header: []subject.RelayRowV2,
    native_public_sums: []subject.RelayRowV2,
    publication_seal: []subject.RelayRowV2,
    boundary_bridge: []subject.RelayRowV2,
    native_challenges: []subject.RelayRowV2,
    relation_events: []subject.RelationEventV2,
    control_main: [control_air_v2.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    control_preprocessed: [control_air_v2.PREPROCESSED_COLUMN_COUNT][]M31,
    control_logical_rows: []subject.ControlLogicalRowV2,
    control_relation_events: []control_witness_v2.RelationEventV2,

    fn init(allocator: std.mem.Allocator, counts: subject.CountsV2) !OwnedDestinations {
        const publication_header = try allocator.alloc(subject.RelayRowV2, counts.publication_header);
        errdefer allocator.free(publication_header);
        const native_public_sums = try allocator.alloc(subject.RelayRowV2, counts.native_public_sums);
        errdefer allocator.free(native_public_sums);
        const publication_seal = try allocator.alloc(subject.RelayRowV2, counts.publication_seal);
        errdefer allocator.free(publication_seal);
        const boundary_bridge = try allocator.alloc(subject.RelayRowV2, counts.boundary_bridge);
        errdefer allocator.free(boundary_bridge);
        const native_challenges = try allocator.alloc(subject.RelayRowV2, counts.native_challenges);
        errdefer allocator.free(native_challenges);
        const relation_events = try allocator.alloc(
            subject.RelationEventV2,
            counts.relay_relation_events,
        );
        errdefer allocator.free(relation_events);

        var control_main: [control_air_v2.PHYSICAL_MAIN_COLUMN_COUNT][]M31 =
            undefined;
        var control_main_count: usize = 0;
        errdefer while (control_main_count > 0) {
            control_main_count -= 1;
            allocator.free(control_main[control_main_count]);
        };
        for (&control_main) |*column| {
            column.* = try allocator.alloc(M31, control_witness_v2.TRACE_ROW_COUNT);
            control_main_count += 1;
        }

        var control_preprocessed: [control_air_v2.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        var control_preprocessed_count: usize = 0;
        errdefer while (control_preprocessed_count > 0) {
            control_preprocessed_count -= 1;
            allocator.free(control_preprocessed[control_preprocessed_count]);
        };
        for (&control_preprocessed) |*column| {
            column.* = try allocator.alloc(M31, control_witness_v2.TRACE_ROW_COUNT);
            control_preprocessed_count += 1;
        }
        const control_logical_rows = try allocator.alloc(
            subject.ControlLogicalRowV2,
            control_witness_v2.TRACE_ROW_COUNT,
        );
        errdefer allocator.free(control_logical_rows);
        const control_relation_events = try allocator.alloc(
            control_witness_v2.RelationEventV2,
            counts.control_relation_events,
        );
        errdefer allocator.free(control_relation_events);
        return .{
            .allocator = allocator,
            .publication_header = publication_header,
            .native_public_sums = native_public_sums,
            .publication_seal = publication_seal,
            .boundary_bridge = boundary_bridge,
            .native_challenges = native_challenges,
            .relation_events = relation_events,
            .control_main = control_main,
            .control_preprocessed = control_preprocessed,
            .control_logical_rows = control_logical_rows,
            .control_relation_events = control_relation_events,
        };
    }

    fn deinit(self: *OwnedDestinations) void {
        self.allocator.free(self.control_relation_events);
        self.allocator.free(self.control_logical_rows);
        for (self.control_preprocessed) |column| self.allocator.free(column);
        for (self.control_main) |column| self.allocator.free(column);
        self.allocator.free(self.relation_events);
        self.allocator.free(self.native_challenges);
        self.allocator.free(self.boundary_bridge);
        self.allocator.free(self.publication_seal);
        self.allocator.free(self.native_public_sums);
        self.allocator.free(self.publication_header);
        self.* = undefined;
    }

    fn view(self: *OwnedDestinations) subject.DestinationsV2 {
        return .{
            .publication_header = self.publication_header,
            .native_public_sums = self.native_public_sums,
            .publication_seal = self.publication_seal,
            .boundary_bridge = self.boundary_bridge,
            .native_challenges = self.native_challenges,
            .relation_events = self.relation_events,
            .control = .{
                .main = self.control_main,
                .preprocessed = self.control_preprocessed,
                .logical_rows = self.control_logical_rows,
                .relation_events = self.control_relation_events,
            },
        };
    }

    fn fillSentinel(self: *OwnedDestinations) void {
        @memset(std.mem.sliceAsBytes(self.publication_header), 0xa5);
        @memset(std.mem.sliceAsBytes(self.native_public_sums), 0xa5);
        @memset(std.mem.sliceAsBytes(self.publication_seal), 0xa5);
        @memset(std.mem.sliceAsBytes(self.boundary_bridge), 0xa5);
        @memset(std.mem.sliceAsBytes(self.native_challenges), 0xa5);
        @memset(std.mem.sliceAsBytes(self.relation_events), 0xa5);
        for (self.control_main) |column|
            @memset(std.mem.sliceAsBytes(column), 0xa5);
        for (self.control_preprocessed) |column|
            @memset(std.mem.sliceAsBytes(column), 0xa5);
        @memset(std.mem.sliceAsBytes(self.control_logical_rows), 0xa5);
        @memset(std.mem.sliceAsBytes(self.control_relation_events), 0xa5);
    }

    fn digest(self: *const OwnedDestinations) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(std.mem.sliceAsBytes(self.publication_header));
        hash.update(std.mem.sliceAsBytes(self.native_public_sums));
        hash.update(std.mem.sliceAsBytes(self.publication_seal));
        hash.update(std.mem.sliceAsBytes(self.boundary_bridge));
        hash.update(std.mem.sliceAsBytes(self.native_challenges));
        hash.update(std.mem.sliceAsBytes(self.relation_events));
        for (self.control_main) |column|
            hash.update(std.mem.sliceAsBytes(column));
        for (self.control_preprocessed) |column|
            hash.update(std.mem.sliceAsBytes(column));
        hash.update(std.mem.sliceAsBytes(self.control_logical_rows));
        hash.update(std.mem.sliceAsBytes(self.control_relation_events));
        return hash.finalResult();
    }
};

fn publicationRow(owned: *const OwnedDestinations, index: usize) subject.RelayRowV2 {
    if (index < subject.PUBLICATION_SUM_START)
        return owned.publication_header[index];
    if (index < subject.PUBLICATION_SEAL_START)
        return owned.native_public_sums[index - subject.PUBLICATION_SUM_START];
    return owned.publication_seal[index - subject.PUBLICATION_SEAL_START];
}

fn expectEventTriplets(events: []const subject.RelationEventV2) !void {
    try std.testing.expectEqual(@as(usize, 0), events.len % 3);
    var at: usize = 0;
    while (at < events.len) : (at += 3) {
        try std.testing.expectEqual(@as(u8, 0), events[at].event_ordinal);
        try std.testing.expectEqual(@as(u8, 1), events[at + 1].event_ordinal);
        try std.testing.expectEqual(@as(u8, 2), events[at + 2].event_ordinal);
        try std.testing.expectEqual(events[at].roster_row, events[at + 1].roster_row);
        try std.testing.expectEqual(events[at].roster_row, events[at + 2].roster_row);
        try std.testing.expectEqual(events[at].logical_row, events[at + 1].logical_row);
        try std.testing.expectEqual(events[at].logical_row, events[at + 2].logical_row);
    }
}

fn expectExactRelationProjection(owned: *const OwnedDestinations, wire_len: usize) !void {
    var source_wire_consumes: usize = 0;
    var source_challenge_consumes: usize = 0;
    var arithmetic_emits: usize = 0;
    var control_emits: usize = 0;
    for (owned.relation_events) |event| {
        if (event.event_ordinal == 0) {
            try std.testing.expectEqual(@as(u32, 1), event.multiplicity);
            if (event.domain == .recursion_wire)
                source_wire_consumes += 1
            else if (event.domain == .recursion_relation_challenge_word)
                source_challenge_consumes += 1
            else
                return error.TestUnexpectedResult;
        } else if (event.event_ordinal == 1) {
            arithmetic_emits += @intFromBool(event.multiplicity == 1);
        } else {
            control_emits += @intFromBool(event.multiplicity == 1);
        }
    }
    try std.testing.expectEqual(subject.PUBLICATION_WORD_COUNT + wire_len, source_wire_consumes);
    try std.testing.expectEqual(subject.CHALLENGE_WORD_COUNT, source_challenge_consumes);
    try std.testing.expectEqual(
        subject.ARITHMETIC_PUBLICATION_WORD_COUNT + wire_len + subject.CHALLENGE_WORD_COUNT,
        arithmetic_emits,
    );
    try std.testing.expectEqual(@as(usize, 1), control_emits);
}

fn expectExactControlProjection(owned: *const OwnedDestinations) !void {
    var step_consumes: usize = 0;
    var wire_consumes: usize = 0;
    for (owned.control_relation_events) |event| {
        try std.testing.expectEqual(relation.Role.consume, event.role);
        switch (event.domain) {
            .recursion_step => step_consumes += 1,
            .recursion_wire => wire_consumes += 1,
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(subject.CONTROL_LOGICAL_ROW_COUNT, step_consumes);
    try std.testing.expectEqual(@as(usize, 1), wire_consumes);
}

fn expectZeroWords(words: []const u32) !void {
    for (words) |word| try std.testing.expectEqual(@as(u32, 0), word);
}

fn expectWriteFailure(
    prepared: *const subject.PreparedV2,
    owned: *OwnedDestinations,
    inputs: subject.InputsV2,
) !void {
    if (subject.writeInto(prepared, owned.view(), inputs)) |_| {
        return error.TestExpectedError;
    } else |_| {}
}

fn expectCanonicalEventOrder(events: []const subject.RelationEventV2) !void {
    for (events[1..], events[0 .. events.len - 1]) |current, previous| {
        try std.testing.expect(current.roster_row >= previous.roster_row);
        if (current.roster_row == previous.roster_row) {
            try std.testing.expect(current.logical_row >= previous.logical_row);
            if (current.logical_row == previous.logical_row)
                try std.testing.expect(current.event_ordinal > previous.event_ordinal);
        }
    }
}
