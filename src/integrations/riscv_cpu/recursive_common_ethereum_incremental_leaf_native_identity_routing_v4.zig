//! Inactive source rows for the two native identity hashes. Existing statement
//! and hash-digest relations authenticate resolved values. Raw auxiliary,
//! session/identity sources remain explicit obligations. Canonical root joins
//! publish native scalar roots separately from the span's snapshot digests.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const hashes = @import("recursive_common_ethereum_incremental_leaf_native_identity_hash_v4.zig");
const publication = @import("recursive_common_ethereum_incremental_leaf_publication_hash_v4.zig");
const public_sums = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");
const raw = frontend.recursion.segment_statement_v2_transcript_layout;
const protocol_routing = frontend.recursion.ethereum_publication_routing_v1;
const preimage = frontend.air.statement_v2.authority_preimage;
const Air = frontend.recursion.air.ethereum_publication_control_v1;
const M31 = core.fields.m31.M31;
pub const Row = Air.Relation.Row;
pub const StatementWord = struct { scope: u32, index: u32 };
pub const RAW_SOURCE_SCOPE = protocol_routing.STATEMENT_SCOPE;
pub const RAW_V2_SOURCE_BASE = protocol_routing.RAW_V2_SOURCE_BASE;
pub const ROOT_SOURCE_USES = protocol_routing.ROOT_SOURCE_USES;
pub const ROOT_JOIN_ROW_COUNT = protocol_routing.ROOT_JOIN_ROW_COUNT;
pub const FIXED_INTEGRATED_ROW_COUNT: usize = 16;

pub fn integratedRowCount(plan: *const hashes.OwnedPlan) usize {
    return plan.phases()[1].preimage_word_count + FIXED_INTEGRATED_ROW_COUNT;
}

/// Each digest scalar jointly authenticates its raw split transcript frame,
/// the actual raw-wire hash output, the native authority preimage and source
/// publication. None of these four occurrences is supplied independently.
pub fn writeIntegrated(plan: *const hashes.OwnedPlan, raw_words: []const M31, statement_words: *const [412]u32, root_uses: [2]u32, destination: []Row) !void {
    if (destination.len != integratedRowCount(plan)) return error.InvalidEthereumNativeIdentityWord;
    var at: usize = 0;
    for (0..plan.phases()[1].preimage_word_count) |index| {
        const binding = try bindingForWord(plan, .native_authority, index);
        const value = M31.fromCanonical(switch (binding) {
            .protocol, .admitted_geometry => |expected| expected,
            .statement_word => |word| statement_words[word.index],
            .hash_digest => |word| plan.phases()[0].output_digest[word.limb],
            else => return error.InvalidEthereumNativeIdentityWord,
        });
        var row = try rowForBinding(binding, .native_authority, index, value);
        if (binding == .hash_digest) {
            var pp: [Air.PREPROCESSED_COLUMN_COUNT]u32 = undefined;
            for (&pp, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..][0..pp.len]) |*out, field| out.* = field.toU32();
            row = try Air.rawWordRow(value, M31.fromCanonical(value.toU32() & 65535), M31.fromCanonical(value.toU32() >> 16), true, protocol_routing.rawIndex(.wire_id, 2 * @as(u32, binding.hash_digest.limb)).?, pp);
        }
        destination[at] = row;
        at += 1;
    }
    for ([_]raw.Side{ .entry, .exit }) |side| {
        for (0..2) |limb| {
            const source = rootSource(side, @intCast(limb));
            if (source.raw_word_index >= raw_words.len) return error.InvalidEthereumNativeIdentityWord;
            destination[at] = try sourceRow(plan, .raw_wire, source.raw_word_index, raw_words[source.raw_word_index]);
            at += 1;
        }
        const first = rootSource(side, 0).raw_word_index;
        const joined = @as(u64, raw_words[first].toU32()) + @as(u64, raw_words[first + 1].toU32()) * 65536;
        if (joined >= core.fields.m31.Modulus) return error.NoncanonicalPublicationWord;
        destination[at] = try rootJoinRow(side, M31.fromCanonical(@intCast(joined)), raw_words[first], raw_words[first + 1], root_uses[@intFromEnum(side)]);
        at += 1;
    }
    for (0..2) |limb| {
        destination[at] = try cycleUpperRow(@intCast(limb), M31.fromCanonical(statement_words[cycleUpperWord(@intCast(limb)).index]));
        at += 1;
    }
    for (0..8) |limb| {
        destination[at] = nativeAuthorityDigestRow(plan, @intCast(limb));
        at += 1;
    }
    std.debug.assert(at == destination.len);
}
pub const RootCoordinate = protocol_routing.RootCoordinate;
pub const RootSource = protocol_routing.RootSource;
pub const Binding = union(enum) {
    protocol: u32,
    admitted_geometry: u32,
    statement_word: StatementWord,
    hash_digest: struct { scope: u32, limb: u3 },
    root_limb: RootCoordinate,
    unresolved_raw: raw.Data,
};

pub fn bindingForWord(plan: *const hashes.OwnedPlan, phase: hashes.Phase, index: usize) !Binding {
    return switch (try plan.sourceForWord(phase, index)) {
        .native_authority => |source| switch (source) {
            .protocol => |value| .{ .protocol = value },
            .admitted_geometry => |value| .{ .admitted_geometry = value.expected },
            .span_scalar => |value| .{ .statement_word = .{ .scope = 0, .index = hashes.spanScalarWord(value.field, value.limb) } },
            .wire_hash_digest => |limb| .{ .hash_digest = .{ .scope = hashes.hashScope(.raw_wire), .limb = limb } },
        },
        .raw_word => |source| switch (source.classification) {
            .fixed => |value| .{ .protocol = value },
            .geometry => |value| .{ .admitted_geometry = value.value },
            .data => |data| switch (data) {
                .span_word => |index_in_statement| .{ .statement_word = .{ .scope = 0, .index = index_in_statement } },
                .register_clock => |coordinate| .{ .statement_word = .{
                    .scope = frontend.recursion.ethereum_clock_routing_v1.STATEMENT_SCOPE,
                    .index = @as(u32, @intFromEnum(coordinate.side)) * 64 + @as(u32, coordinate.register) * 2 + coordinate.limb,
                } },
                .continuation_root => |coordinate| .{ .root_limb = .{ .side = coordinate.side, .limb = coordinate.limb } },
                .digest, .completion, .retained => .{ .unresolved_raw = data },
            },
        },
    };
}

/// `value` is the prospective hash preimage word, not a constant authority.
/// The row consumes its statement/digest source and emits the SAME value to
/// the hash input. Hash lookup closure detects any changed preimage word.
pub fn sourceRow(plan: *const hashes.OwnedPlan, phase: hashes.Phase, index: usize, value: M31) !Row {
    return rowForBinding(try bindingForWord(plan, phase, index), phase, index, value);
}

/// Explicitly selected alongside the admitted public-sums graph, whose
/// requireNonfinal relation excludes final leaves. Raw V2 completion is absent
/// for that profile: it is NOT the separate native unretired-fetch frame.
/// The caller must already own/validate `program`; these rows do not mint
/// program admission or establish raw V2 document validity by themselves.
pub fn sourceRowForAdmittedNonfinalProgram(
    plan: *const hashes.OwnedPlan,
    program: *const public_sums.OwnedFixedProgramV4,
    phase: hashes.Phase,
    index: usize,
    value: M31,
) !Row {
    try program.requireNonfinalProgramAdmission();
    if (program.format_version != public_sums.FORMAT_VERSION or
        program.schema_version != public_sums.SCHEMA_VERSION)
        return error.EthereumNonfinalProgramAdmissionRequired;
    const binding = try bindingForWord(plan, phase, index);
    const admitted = if (binding == .unresolved_raw and binding.unresolved_raw == .completion)
        Binding{ .admitted_geometry = nonfinalCompletionWord(binding.unresolved_raw.completion) }
    else
        binding;
    return rowForBinding(admitted, phase, index, value);
}

fn nonfinalCompletionWord(field: raw.CompletionField) u32 {
    return if (field == .tag)
        @intFromEnum(frontend.recursion.segment_statement_v2.Tag.completion_absent)
    else
        0;
}

fn rowForBinding(binding: Binding, phase: hashes.Phase, index: usize, value: M31) !Row {
    var pp = [_]u32{0} ** Air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    route(&pp, 0, hashes.hashScope(phase), @intCast(index));
    switch (binding) {
        .protocol, .admitted_geometry => |expected| {
            if (value.toU32() != expected) return error.EthereumNativeIdentityFixedWordMismatch;
            pp[30] = 1;
            pp[31] = expected;
        },
        .statement_word => |word| statement(&pp, word),
        .hash_digest => |digest| {
            pp[24] = 1;
            pp[25] = digest.scope;
            pp[26] = digest.limb;
            // Replaces old raw-publication sources24..31 on integration.
            // The raw-wire hash also binds the public source commitment.
            route(&pp, 1, publication.hashScope(.source), 24 + @as(u32, digest.limb));
        },
        .root_limb => |coordinate| {
            const source = rootSource(coordinate.side, coordinate.limb);
            return Air.rawWordRow(value, value, M31.zero(), false, source.source_index, pp);
        },
        .unresolved_raw => return error.EthereumNativeIdentityRawSourceUnresolved,
    }
    return Air.wordRow(value, pp);
}

/// Only these four raw-V2 words are admitted by this stage. Transcript rows
/// must emit each source twice: once for the raw hash word and once for its
/// canonical join. This does not admit other words under RAW_V2_SOURCE_BASE.
pub const rootSource = protocol_routing.rootSource;
pub const rootSourceForRawIndex = protocol_routing.rootSourceForRawIndex;
pub fn rootStatementWord(side: raw.Side) StatementWord {
    return .{ .scope = frontend.recursion.air.vm_statement_roots.NATIVE_CONTINUATION_SCOPE, .index = @intFromEnum(side) };
}

/// Mandatory once per side. The existing AIR consumes the same scope1114
/// limb pair as the hash-word rows, range-checks the join and rejects the M31
/// modulus alias, then publishes the scalar root in its separate namespace.
/// Snapshot digest words remain independently bound through the raw-wire hash.
pub fn rootJoinRow(side: raw.Side, statement_root: M31, low: M31, high: M31, uses: u32) !Row {
    if (uses == 0 or uses >= core.fields.m31.Modulus) return error.InvalidEthereumNativeIdentityWord;
    var pp = [_]u32{0} ** Air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    statement(&pp, rootStatementWord(side));
    // The existing consume event has a fixed, admitted coefficient. Negating
    // it publishes exactly the independently planned consumer multiplicity.
    pp[10] = core.fields.m31.Modulus - uses;
    return Air.rawWordRow(statement_root, low, high, true, rootSource(side, 0).source_index, pp);
}

/// Replaces old raw-publication sources16..23 on integration. No raw source
/// copies are accepted: kind11 binds the actual native-authority hash output.
pub fn nativeAuthorityDigestRow(plan: *const hashes.OwnedPlan, limb: u3) Row {
    var pp = [_]u32{0} ** Air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    pp[24] = 1;
    pp[25] = hashes.hashScope(.native_authority);
    pp[26] = limb;
    route(&pp, 0, publication.hashScope(.source), 16 + @as(u32, limb));
    return Air.wordRow(M31.fromCanonical(plan.phases()[1].output_digest[limb]), pp);
}

pub fn cycleUpperWord(limb: u1) StatementWord {
    return .{ .scope = 0, .index = @intCast(frontend.recursion.span_statement.canonical_layout.executed_cycle_count_start + 2 + @as(usize, limb)) };
}
/// Two mandatory AIR constraints when admitting the native authority's u32
/// cycle count from the SpanStatement's four-limb u64 count.
pub fn cycleUpperRow(limb: u1, value: M31) !Row {
    if (!value.isZero()) return error.EthereumNativeIdentityCycleOverflow;
    var pp = [_]u32{0} ** Air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    pp[30] = 1;
    pp[31] = 0;
    statement(&pp, cycleUpperWord(limb));
    return Air.wordRow(value, pp);
}
fn statement(pp: *[Air.PREPROCESSED_COLUMN_COUNT]u32, word: StatementWord) void {
    pp[10] = 1;
    pp[11] = word.scope;
    pp[12] = word.index;
}
fn route(pp: *[Air.PREPROCESSED_COLUMN_COUNT]u32, slot: usize, scope: u32, index: u32) void {
    const at = 13 + slot * 3;
    pp[at] = 1;
    pp[at + 1] = scope;
    pp[at + 2] = index;
}

test "Ethereum native identity routing closes exact authority payload and digest tuples" {
    const allocator = std.testing.allocator;
    const QM31 = core.fields.qm31.QM31;
    const interactions = frontend.recursion.air.relation_interaction;
    const HashAir = frontend.recursion.air.ethereum_publication_hash_v1;
    const Domain = @FieldType(interactions.TupleContribution, "domain");
    const mask = (@as(u64, 1) << @intFromEnum(Domain.recursion_vm_public_claim_word)) |
        (@as(u64, 1) << @intFromEnum(Domain.recursion_verifier_input_word));
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const router = try Air.Relation.authenticate(&definition);
    var hash_definition = try HashAir.build(allocator);
    defer hash_definition.deinit();
    const hash_plan = try HashAir.Relation.authenticate(&hash_definition);
    var integrated: [38]Row = undefined;
    // This fixture has zero root limbs; writeIntegrated only reads those four
    // raw coordinates. Its native authority phase uses the actual hash plan.
    const raw_roots = [_]M31{M31.zero()} ** frontend.recursion.segment_statement_v2.MIN_CANONICAL_WORDS;
    try writeIntegrated(fixture.plan, &raw_roots, &(.{0} ** 412), .{ 3, 3 }, &integrated);
    var rows: [30]Row = undefined;
    @memcpy(rows[0..22], integrated[0..22]);
    @memcpy(rows[22..30], integrated[30..38]);
    var ledger = interactions.TupleLedger.init(allocator);
    defer ledger.deinit();
    try router.appendPreparedTupleContributions(&ledger, 17, &rows, mask);
    for (fixture.plan.phases()[0].output_digest, 0..) |word, limb| for (0..2) |part| {
        const raw_index = protocol_routing.rawIndex(.wire_id, @intCast(2 * limb + part)).?;
        try ledger.append(.recursion_vm_public_claim_word, 5, 3, .emit, QM31.one(), &.{ QM31.fromU32Unchecked(RAW_SOURCE_SCOPE, 0, 0, 0), QM31.fromU32Unchecked(raw_index, 0, 0, 0), QM31.fromU32Unchecked(if (part == 0) word & 65535 else word >> 16, 0, 0, 0) });
    };
    const authority_phase = fixture.plan.phases()[1];
    try hash_plan.appendPreparedTupleContributions(&ledger, 13, fixture.plan.rows()[authority_phase.first_row..][0..authority_phase.row_count], mask);
    // Actual phase0 final AIR digest consumers, without its independent raw
    // preimage obligations: this test isolates the phase1 payload boundary.
    const wire_last = fixture.plan.phases()[0].row_count - 1;
    try hash_plan.appendPreparedTupleContributions(&ledger, 13, fixture.plan.rows()[wire_last..][0..1], @as(u64, 1) << @intFromEnum(Domain.recursion_verifier_input_word));
    // Public source hash's independent, exact16..31 input coordinates.
    for (0..16) |index| {
        const word = if (index < 8) fixture.plan.phases()[1].output_digest[index] else fixture.plan.phases()[0].output_digest[index - 8];
        try ledger.append(.recursion_vm_public_claim_word, 13, 1, .consume, QM31.one().neg(), &.{ QM31.fromU32Unchecked(1102, 0, 0, 0), QM31.fromU32Unchecked(@intCast(16 + index), 0, 0, 0), QM31.fromU32Unchecked(word, 0, 0, 0) });
    }
    try std.testing.expect(ledger.classify().isClosed());
    const original = rows[8];
    rows[8][0] = rows[8][0].add(M31.one());
    var changed = interactions.TupleLedger.init(allocator);
    defer changed.deinit();
    try router.appendPreparedTupleContributions(&changed, 17, &.{original}, mask);
    // Negate the mutated row's typed contribution to compare exact payloads.
    var mutated = interactions.TupleLedger.init(allocator);
    defer mutated.deinit();
    try router.appendPreparedTupleContributions(&mutated, 17, rows[8..9], mask);
    for (mutated.contributions.items) |contribution| {
        try changed.append(contribution.domain, contribution.component, contribution.event, .consume, contribution.signed_weight.neg(), contribution.tuple_prefix[0..contribution.arity]);
    }
    try std.testing.expectEqual(@as(usize, 2), changed.classify().unmatched_tuple_count);
}

test "Ethereum native identity routing keeps raw obligations and exact statement coordinates" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const pp = Air.PHYSICAL_MAIN_COLUMN_COUNT;
    const pc = try sourceRow(fixture.plan, .native_authority, 8, M31.zero());
    try std.testing.expectEqual(@as(u32, 0), pc[pp + 11].toU32());
    try std.testing.expectEqual(hashes.spanScalarWord(.initial_pc, 0), pc[pp + 12].toU32());
    try std.testing.expectEqual(@as(u32, 1121), pc[pp + 14].toU32());
    const clock = try sourceRow(fixture.plan, .raw_wire, raw.fixed_layout.exit_register_clocks + 3, M31.zero());
    try std.testing.expectEqual(frontend.recursion.ethereum_clock_routing_v1.STATEMENT_SCOPE, clock[pp + 11].toU32());
    try std.testing.expectEqual(@as(u32, 67), clock[pp + 12].toU32());
    try std.testing.expectEqual(@as(u32, 1120), clock[pp + 14].toU32());
    for ([_]usize{ raw.fixed_layout.session_id, raw.fixed_layout.completion }) |index|
        try std.testing.expectError(error.EthereumNativeIdentityRawSourceUnresolved, sourceRow(fixture.plan, .raw_wire, index, M31.zero()));
    try std.testing.expectError(error.EthereumNativeIdentityFixedWordMismatch, sourceRow(fixture.plan, .native_authority, 0, M31.zero()));
    try std.testing.expectError(error.EthereumNativeIdentityCycleOverflow, cycleUpperRow(0, M31.one()));
    for (0..2) |limb| {
        const row = try cycleUpperRow(@intCast(limb), M31.zero());
        try std.testing.expectEqual(cycleUpperWord(@intCast(limb)).index, row[pp + 12].toU32());
        try std.testing.expectEqual(@as(u32, 1), row[pp + 30].toU32());
        try std.testing.expectEqual(@as(u32, 0), row[pp + 31].toU32());
    }
}

test "Ethereum native identity root joins close recorded limbs and public roots" {
    const roots = [_]u32{ 0x1234_5678, core.fields.m31.Modulus - 1 };
    var fixture = try Fixture.initWithRoots(std.testing.allocator, roots);
    defer fixture.deinit();
    var rows: [6]Row = undefined;
    for (std.enums.values(raw.Side), roots, 0..) |side, root, side_index| {
        const low = M31.fromCanonical(root & 65535);
        const high = M31.fromCanonical(root >> 16);
        rows[3 * side_index] = try sourceRow(fixture.plan, .raw_wire, rootSource(side, 0).raw_word_index, low);
        rows[3 * side_index + 1] = try sourceRow(fixture.plan, .raw_wire, rootSource(side, 1).raw_word_index, high);
        rows[3 * side_index + 2] = try rootJoinRow(side, M31.fromCanonical(root), low, high, 3);
    }
    try std.testing.expectEqual(@as(usize, 0), try rootTupleResidual(fixture.plan, &rows, roots));
    try std.testing.expect((try rootTupleResidual(fixture.plan, rows[1..], roots)) != 0);
    const duplicated = rows ++ [_]Row{rows[2]};
    try std.testing.expect((try rootTupleResidual(fixture.plan, &duplicated, roots)) != 0);
    const original_join = rows[2];
    rows[2] = try rootJoinRow(.entry, M31.fromCanonical(roots[0]), M31.fromCanonical(roots[0] & 65535), M31.fromCanonical(roots[0] >> 16), 2);
    try std.testing.expect((try rootTupleResidual(fixture.plan, &rows, roots)) != 0);
    rows[2] = original_join;

    // Integrated production must obtain the root from its raw canonical limbs,
    // even when the independently bound snapshot digest has a different word0.
    var raw_words = [_]M31{M31.zero()} ** frontend.recursion.segment_statement_v2.MIN_CANONICAL_WORDS;
    var statement_words = [_]u32{0} ** 412;
    for (std.enums.values(raw.Side), roots) |side, root| {
        raw_words[rootSource(side, 0).raw_word_index] = M31.fromCanonical(root & 65535);
        raw_words[rootSource(side, 1).raw_word_index] = M31.fromCanonical(root >> 16);
        statement_words[frontend.recursion.air.vm_statement_roots.word_indices[@intFromEnum(side)]] = M31.fromCanonical(root).add(M31.one()).toU32();
    }
    var integrated: [38]Row = undefined;
    try writeIntegrated(fixture.plan, &raw_words, &statement_words, .{ 3, 3 }, &integrated);
    for (roots, 0..) |root, side| {
        const joined = integrated[fixture.plan.phases()[1].preimage_word_count + 3 * side + 2];
        try std.testing.expectEqual(root, joined[0].toU32());
        try std.testing.expectEqual(core.fields.m31.Modulus - 3, joined[Air.PHYSICAL_MAIN_COLUMN_COUNT + 10].toU32());
    }
    const original = rows[0];
    const changed_low = M31.fromCanonical((roots[0] & 65535) + 1);
    rows[0] = try sourceRow(fixture.plan, .raw_wire, 482, changed_low);
    try std.testing.expectEqual(@as(usize, 4), try rootTupleResidual(fixture.plan, &rows, roots));
    rows[0] = original;
    const pp = Air.PHYSICAL_MAIN_COLUMN_COUNT;
    rows[2][pp + 12] = M31.fromCanonical(378);
    try std.testing.expectEqual(@as(usize, 2), try rootTupleResidual(fixture.plan, &rows, roots));
}

test "Ethereum native identity root joins reject aliases and reserve only four raw sources" {
    const payload = frontend.recursion.air.ethereum_transcript_payload_raw_v1;
    try std.testing.expectEqual(payload.RAW_WIRE_SCOPE, hashes.hashScope(.raw_wire));
    try std.testing.expectEqual(protocol_routing.NATIVE_AUTHORITY_HASH_SCOPE, hashes.hashScope(.native_authority));
    try std.testing.expectEqual(payload.ROOT_SOURCE_SCOPE, RAW_SOURCE_SCOPE);
    try std.testing.expectEqual(payload.ROOT_SOURCE_BASE, RAW_V2_SOURCE_BASE);
    try std.testing.expectError(error.NoncanonicalPublicationWord, rootJoinRow(.entry, M31.zero(), M31.fromCanonical(65535), M31.fromCanonical(32767), 3));
    try std.testing.expectError(error.NoncanonicalPublicationWord, rootJoinRow(.exit, M31.one(), M31.zero(), M31.fromCanonical(32768), 3));
    try std.testing.expectError(error.NoncanonicalPublicationWord, rootJoinRow(.entry, M31.fromCanonical(10), M31.fromCanonical(11), M31.zero(), 3));
    try std.testing.expectError(error.InvalidEthereumNativeIdentityWord, rootJoinRow(.entry, M31.zero(), M31.zero(), M31.zero(), 0));
    try std.testing.expectError(error.InvalidEthereumNativeIdentityWord, rootJoinRow(.entry, M31.zero(), M31.zero(), M31.zero(), core.fields.m31.Modulus));
    const raw_indices = [_]usize{ 482, 483, 494, 495 };
    const source_indices = [_]u32{ 738, 739, 750, 751 };
    for (raw_indices, source_indices) |index, expected| {
        const source = rootSourceForRawIndex(index).?;
        try std.testing.expectEqual(expected, source.source_index);
        try std.testing.expectEqual(@as(u32, 2), source.uses);
        try std.testing.expectEqual(index, source.raw_word_index);
        const exported = payload.exportForRawWord(@intCast(index));
        try std.testing.expectEqual(RAW_SOURCE_SCOPE, exported.scope);
        try std.testing.expectEqual(source.source_index, exported.index);
        try std.testing.expectEqual(source.uses, exported.uses);
        try std.testing.expect(!payload.rawHashProvidedDirectly(@intCast(index)));
    }
    for ([_]usize{ 4, 12, 20, 481, 484, 493, 496, 644, 655 }) |index| {
        try std.testing.expect(rootSourceForRawIndex(index) == null);
        try std.testing.expect(payload.rawHashProvidedDirectly(@intCast(index)));
        const exported = payload.exportForRawWord(@intCast(index));
        try std.testing.expectEqual(hashes.hashScope(.raw_wire), exported.scope);
        try std.testing.expectEqual(index, exported.index);
        try std.testing.expectEqual(@as(u32, 1), exported.uses);
    }
    try std.testing.expectEqual(@as(u32, 0), rootStatementWord(.entry).index);
    try std.testing.expectEqual(@as(u32, 1), rootStatementWord(.exit).index);
}

/// Check only the root-routing relations; unchanged range/Poseidon AIRs have
/// their own gates. Hash consumers below come from the actual hash AIR rows.
fn rootTupleResidual(plan: *const hashes.OwnedPlan, rows: []const Row, roots: [2]u32) !usize {
    const allocator = std.testing.allocator;
    const interactions = frontend.recursion.air.relation_interaction;
    const Domain = @FieldType(interactions.TupleContribution, "domain");
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const router = try Air.Relation.authenticate(&definition);
    var ledger = interactions.TupleLedger.init(allocator);
    defer ledger.deinit();
    const mask = (@as(u64, 1) << @intFromEnum(Domain.recursion_vm_public_claim_word)) | (@as(u64, 1) << @intFromEnum(Domain.recursion_statement_word));
    try router.appendPreparedTupleContributions(&ledger, 17, rows, mask);
    for (roots, 0..) |root, side| {
        const endpoint = rootStatementWord(@enumFromInt(side));
        try ledger.append(.recursion_statement_word, 18, 0, .consume, secureField(3).neg(), &.{ secureField(endpoint.scope), secureField(endpoint.index), secureField(root) });
        for (0..2) |limb| {
            const value: u32 = @as(u16, @truncate(root >> @as(u5, @intCast(16 * limb))));
            const source = rootSource(@enumFromInt(side), @intCast(limb));
            // Two genuine recorded-source uses fixed by the source schedule.
            try ledger.append(.recursion_vm_public_claim_word, 5, 0, .emit, secureField(source.uses), &.{ secureField(RAW_SOURCE_SCOPE), secureField(source.source_index), secureField(value) });
        }
    }
    const HashAir = frontend.recursion.air.ethereum_publication_hash_v1;
    var hash_definition = try HashAir.build(allocator);
    defer hash_definition.deinit();
    const hash_plan = try HashAir.Relation.authenticate(&hash_definition);
    var hash_tuples = interactions.TupleLedger.init(allocator);
    defer hash_tuples.deinit();
    try hash_plan.appendPreparedTupleContributions(&hash_tuples, 13, plan.rows()[0..plan.phases()[0].row_count], @as(u64, 1) << @intFromEnum(Domain.recursion_vm_public_claim_word));
    for (hash_tuples.contributions.items) |tuple| {
        const index = tuple.tuple_prefix[1].toM31Array()[0].toU32();
        if (index == 482 or index == 483 or index == 494 or index == 495)
            try ledger.contributions.append(allocator, tuple);
    }
    return ledger.classify().unmatched_tuple_count;
}
fn secureField(value: u32) core.fields.qm31.QM31 {
    return core.fields.qm31.QM31.fromU32Unchecked(value, 0, 0, 0);
}

const Fixture = struct {
    plan: *hashes.OwnedPlan,
    authority_words: [22]u32,
    fn init(allocator: std.mem.Allocator) !Fixture {
        return initWithRoots(allocator, .{ 0, 0 });
    }
    fn initWithRoots(allocator: std.mem.Allocator, roots: [2]u32) !Fixture {
        return initWithCompletion(allocator, roots, false);
    }
    fn initWithCompletion(allocator: std.mem.Allocator, roots: [2]u32, absent: bool) !Fixture {
        const layout = try raw.Layout.init(.{ 0, 0, 0, 0 });
        const words = try allocator.alloc(M31, layout.wordCount());
        defer allocator.free(words);
        for (words, 0..) |*word, index| word.* = M31.fromCanonical(switch (try layout.word(index)) {
            .fixed => |value| value,
            .geometry => |value| value.value,
            .data => 0,
        });
        if (absent) for (std.enums.values(raw.CompletionField), 0..) |field, offset| {
            words[raw.fixed_layout.completion + offset] = M31.fromCanonical(nonfinalCompletionWord(field));
        };
        for (std.enums.values(raw.Side), roots) |side, root| {
            // Real snapshots carry a digest, not the native sparse-tree root.
            const snapshot_index = frontend.recursion.air.vm_statement_roots.word_indices[@intFromEnum(side)];
            words[raw.fixed_layout.base_statement + snapshot_index] = M31.fromCanonical(root).add(M31.one());
            words[rootSource(side, 0).raw_word_index] = M31.fromCanonical(root & 65535);
            words[rootSource(side, 1).raw_word_index] = M31.fromCanonical(root >> 16);
        }
        const authority = preimage.Input{ .initial_pc = 0, .final_pc = 0, .cycle_count = 0, .wire_id = frontend.recursion.poseidon2_channel.hashCanonicalWords(words, hashes.hashDomain(.raw_wire)), .component_descs = &.{}, .infra_descs = &.{} };
        var authority_words: [22]u32 = undefined;
        try preimage.write(authority, &authority_words);
        return .{ .plan = try hashes.OwnedPlan.initAdmitted(allocator, words, layout, authority, try preimage.hash(authority), 0), .authority_words = authority_words };
    }
    fn deinit(self: *Fixture) void {
        self.plan.deinit();
    }
};

test "Ethereum native identity nonfinal completion requires explicit admitted program policy" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    // This tests the profile-selection boundary, not program construction:
    // the remaining program state is never read by a source-row getter.
    var program: public_sums.OwnedFixedProgramV4 = undefined;
    program.format_version = public_sums.FORMAT_VERSION;
    program.schema_version = public_sums.SCHEMA_VERSION;
    program.admission_kind = .diagnostic;
    program.declared_program_identity_sha256 = null;
    try std.testing.expectError(error.EthereumNonfinalProgramAdmissionRequired, sourceRowForAdmittedNonfinalProgram(
        fixture.plan,
        &program,
        .raw_wire,
        raw.fixed_layout.completion,
        M31.fromCanonical(75),
    ));
    program.admission_kind = .nonfinal_declared_program_v1;
    try std.testing.expectError(error.EthereumNonfinalProgramAdmissionRequired, sourceRowForAdmittedNonfinalProgram(
        fixture.plan,
        &program,
        .raw_wire,
        raw.fixed_layout.completion,
        M31.fromCanonical(75),
    ));
    program.declared_program_identity_sha256 = [_]u8{7} ** 32;
    program.schema_version -= 1;
    try std.testing.expectError(error.EthereumNonfinalProgramAdmissionRequired, sourceRowForAdmittedNonfinalProgram(
        fixture.plan,
        &program,
        .raw_wire,
        raw.fixed_layout.completion,
        M31.fromCanonical(75),
    ));
    program.schema_version = public_sums.SCHEMA_VERSION;
    const pp = Air.PHYSICAL_MAIN_COLUMN_COUNT;
    for (std.enums.values(raw.CompletionField), 0..) |field, offset| {
        const expected = nonfinalCompletionWord(field);
        const row = try sourceRowForAdmittedNonfinalProgram(fixture.plan, &program, .raw_wire, raw.fixed_layout.completion + offset, M31.fromCanonical(expected));
        try std.testing.expectEqual(@as(u32, 1), row[pp + 30].toU32());
        try std.testing.expectEqual(expected, row[pp + 31].toU32());
        try std.testing.expectEqual(hashes.hashScope(.raw_wire), row[pp + 14].toU32());
        try std.testing.expectEqual(@as(u32, @intCast(raw.fixed_layout.completion + offset)), row[pp + 15].toU32());
        try std.testing.expectError(error.EthereumNativeIdentityFixedWordMismatch, sourceRowForAdmittedNonfinalProgram(
            fixture.plan,
            &program,
            .raw_wire,
            raw.fixed_layout.completion + offset,
            M31.fromCanonical(expected + 1),
        ));
        try std.testing.expectError(error.EthereumNativeIdentityRawSourceUnresolved, sourceRow(fixture.plan, .raw_wire, raw.fixed_layout.completion + offset, M31.fromCanonical(expected)));
    }
    // Completion-present tag76/final payload and other raw IDs are not
    // admitted by selecting this fixed nonfinal policy.
    try std.testing.expectError(error.EthereumNativeIdentityFixedWordMismatch, sourceRowForAdmittedNonfinalProgram(
        fixture.plan,
        &program,
        .raw_wire,
        raw.fixed_layout.completion,
        M31.fromCanonical(76),
    ));
    try std.testing.expectError(error.EthereumNativeIdentityRawSourceUnresolved, sourceRowForAdmittedNonfinalProgram(
        fixture.plan,
        &program,
        .raw_wire,
        raw.fixed_layout.session_id,
        M31.zero(),
    ));
}

test "Ethereum native identity nonfinal completion closes real hash consumers exactly" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.initWithCompletion(allocator, .{ 0, 0 }, true);
    defer fixture.deinit();
    var program: public_sums.OwnedFixedProgramV4 = undefined;
    program.format_version = public_sums.FORMAT_VERSION;
    program.schema_version = public_sums.SCHEMA_VERSION;
    program.admission_kind = .nonfinal_declared_program_v1;
    program.declared_program_identity_sha256 = [_]u8{7} ** 32;
    const interactions = frontend.recursion.air.relation_interaction;
    const Domain = @FieldType(interactions.TupleContribution, "domain");
    const mask = @as(u64, 1) << @intFromEnum(Domain.recursion_vm_public_claim_word);
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const router = try Air.Relation.authenticate(&definition);
    const HashAir = frontend.recursion.air.ethereum_publication_hash_v1;
    var hash_definition = try HashAir.build(allocator);
    defer hash_definition.deinit();
    const hash_router = try HashAir.Relation.authenticate(&hash_definition);
    var hash_tuples = interactions.TupleLedger.init(allocator);
    defer hash_tuples.deinit();
    try hash_router.appendPreparedTupleContributions(&hash_tuples, 13, fixture.plan.rows()[0..fixture.plan.phases()[0].row_count], mask);
    var rows: [8]Row = undefined;
    for (&rows, std.enums.values(raw.CompletionField), 0..) |*row, field, offset|
        row.* = try sourceRowForAdmittedNonfinalProgram(fixture.plan, &program, .raw_wire, raw.fixed_layout.completion + offset, M31.fromCanonical(nonfinalCompletionWord(field)));
    var ledger = interactions.TupleLedger.init(allocator);
    defer ledger.deinit();
    for (hash_tuples.contributions.items) |tuple| {
        const index = tuple.tuple_prefix[1].toM31Array()[0].toU32();
        if (index >= raw.fixed_layout.completion and index < raw.FIXED_WORD_COUNT)
            try ledger.contributions.append(allocator, tuple);
    }
    const consumers = try allocator.dupe(interactions.TupleContribution, ledger.contributions.items);
    defer allocator.free(consumers);
    const hash_count = consumers.len;
    try std.testing.expectEqual(@as(usize, 8), hash_count);
    try router.appendPreparedTupleContributions(&ledger, 17, &rows, mask);
    try std.testing.expect(ledger.classify().isClosed());
    // classify sorts in place; restore the retained consumers before each case.
    ledger.contributions.clearRetainingCapacity();
    try ledger.contributions.appendSlice(allocator, consumers);
    try router.appendPreparedTupleContributions(&ledger, 17, rows[1..], mask);
    try std.testing.expectEqual(@as(usize, 1), ledger.classify().unmatched_tuple_count);
    // classify sorts in place; restore the retained consumers before each case.
    ledger.contributions.clearRetainingCapacity();
    try ledger.contributions.appendSlice(allocator, consumers);
    try router.appendPreparedTupleContributions(&ledger, 17, &rows, mask);
    try router.appendPreparedTupleContributions(&ledger, 17, rows[0..1], mask);
    try std.testing.expectEqual(@as(usize, 1), ledger.classify().unmatched_tuple_count);
    // classify sorts in place; restore the retained consumers before each case.
    ledger.contributions.clearRetainingCapacity();
    try ledger.contributions.appendSlice(allocator, consumers);
    // A source value changed after construction cannot satisfy the unchanged
    // hash witness, independently of the fixed-value AIR constraint as well.
    rows[1][0] = M31.one();
    try router.appendPreparedTupleContributions(&ledger, 17, &rows, mask);
    try std.testing.expectEqual(@as(usize, 2), ledger.classify().unmatched_tuple_count);
}
