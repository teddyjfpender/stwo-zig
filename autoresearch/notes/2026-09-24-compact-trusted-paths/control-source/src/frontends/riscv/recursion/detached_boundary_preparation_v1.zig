//! Expected-public arithmetic for a detached SegmentV2 child. Hash permutations
//! are explicit requests to the parent's shared Poseidon IO provider. Evaluating
//! this graph is not a proof: the parent must close every exported input and
//! provider binding and authenticate the canonical Span/continuation projection.
const recursion = struct {
    const detached_parent_protocol_v1 = @import("detached_parent_protocol_v1.zig");
    const poseidon2_channel = @import("poseidon2_channel.zig");
    const protocol = @import("protocol.zig");
    const segment_leaf_authority_v2 = @import("segment_leaf_authority_v2.zig");
    const segment_public_claim_hash_authority_v2 = @import("segment_public_claim_hash_authority_v2.zig");
    const segment_statement_v2 = @import("segment_statement_v2.zig");
    const segment_transcript_outer_source_v2 = @import("segment_transcript_outer_source_v2.zig");
    const span_continuation_v1 = @import("span_continuation_v1.zig");
    const span_statement = @import("span_statement.zig");
};
const air = struct {
    const composition_circuit = @import("air/composition_circuit.zig");
    const composition_graph_recorder = @import("air/composition_graph_recorder.zig");
    const universal_challenges = @import("air/universal_challenges.zig");
    const verifier_arithmetic_lowering = @import("air/verifier_arithmetic_lowering.zig");
};
const riscv_air = struct {
    const memory_commitment = @import("../air/memory_commitment/mod.zig");
    const public_data_v2 = @import("../air/public_data_v2.zig");
    const relation = @import("../air/lang/relation.zig");
    const statement_v2 = @import("../air/statement_v2.zig");
};
const testing_support = struct {
    const public_data_v2_test_support = @import("../air/public_data_v2_test_support.zig");
};
const std = @import("std");
const core = @import("stwo_core");
const source = recursion.segment_leaf_authority_v2;
const channel = recursion.poseidon2_channel;
const poseidon = riscv_air.memory_commitment.poseidon2;
const preimage = riscv_air.statement_v2.authority_preimage;
const identity_preimage = recursion.segment_statement_v2.identity_preimage;
const call_source = recursion.segment_public_claim_hash_authority_v2;
const composition = air.composition_circuit;
const recorder = air.composition_graph_recorder;
const S = recorder.Scalar;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const rows = recursion.segment_transcript_outer_source_v2;
const prefix = @import("detached_prefix_preparation_v1.zig");
pub const SectionProfileV1 = @import("detached_section_profile_v1.zig").SectionProfileV1;
const memory_profile_mod = @import("detached_memory_profile_v1.zig");
pub const MemoryProfileV1 = memory_profile_mod.MemoryProfileV1;
const SectionV1 = @import("detached_section_profile_v1.zig").SectionV1;
const child_mod = @import("detached_child_capture_v1.zig");
const key_mod = @import("detached_segment_protocol_v1.zig");
const public_inputs = @import("detached_segment_public_inputs_v1.zig");
const boundary = @import("detached_segment_authority_boundary_v1.zig");
const wire_layout = recursion.segment_statement_v2.fixed_layout;
const span_layout = recursion.span_statement.canonical_layout;
const BASE = wire_layout.base_statement;
const Domain = riscv_air.relation.Domain;

const graph_owner = @import("detached_boundary_graph_v1.zig");
pub const InputSource = graph_owner.InputSource;
pub const InputBinding = graph_owner.InputBinding;
pub const ProviderBinding = graph_owner.ProviderBinding;
const WordCounter = graph_owner.WordCounter;
const NativeCalls = graph_owner.NativeCalls;
const NativeSponge = graph_owner.NativeSponge;
const Inputs = graph_owner.Inputs;
const base = graph_owner.base;
const U32 = graph_owner.U32;
const digestConstants = graph_owner.digestConstants;
const GraphCalls = graph_owner.GraphCalls;
const GraphSponge = graph_owner.GraphSponge;
const ContextWords = graph_owner.ContextWords;
const AuthoritySink = graph_owner.AuthoritySink;
const identity_owner = @import("detached_boundary_identity_v1.zig");
const identityOffset = identity_owner.identityOffset;
const embeddedIdentityInputs = identity_owner.embeddedIdentityInputs;
const recordEmbeddedIdentities = identity_owner.recordEmbeddedIdentities;
const recordRetainedIdentities = identity_owner.recordRetainedIdentities;
const continuation_owner = @import("detached_boundary_continuation_v1.zig");
const constrainSegmentIndexBound = continuation_owner.constrainSegmentIndexBound;
const testIndexBounds = continuation_owner.testIndexBounds;
const MemoryCounter = continuation_owner.MemoryCounter;
const NativeMemoryHasher = continuation_owner.NativeMemoryHasher;
const recordContinuationRoots = continuation_owner.recordContinuationRoots;
const recordClockCanonicality = continuation_owner.recordClockCanonicality;
const testClockCanonicality = continuation_owner.testClockCanonicality;

pub const VERSION: u16 = 1;
pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        circuit: recorder.Circuit,
        inputs: []QM31,
        bindings: []InputBinding,
        values: []QM31,
        calls: []rows.ProviderCall,
        provider_bindings: []ProviderBinding,
        span_nodes: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32,
        raw_wire_count: usize,
        sections: ?[4]SectionV1,
        raw_nodes: ?[]u32 = null,
        family: child_mod.Family = .segment,
    };
    pub fn init(allocator: std.mem.Allocator, child: *const child_mod.OwnedV1, profile: SectionProfileV1, memory_profile: MemoryProfileV1) !*OwnedV1 {
        return initExpected(allocator, child.key(), child.expected(), child.relations(), child.claims().values[36], profile, memory_profile);
    }
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        value.circuit.deinit();
        allocator.free(value.inputs);
        allocator.free(value.bindings);
        allocator.free(value.values);
        allocator.free(value.calls);
        allocator.free(value.provider_bindings);
        if (value.raw_nodes) |nodes| allocator.free(nodes);
        allocator.destroy(value);
    }
    pub fn graph(self: *const OwnedV1) composition.CircuitGraph {
        return self.storage().circuit.graph();
    }
    pub fn inputBindings(self: *const OwnedV1) []const InputBinding {
        return self.storage().bindings;
    }
    pub fn inputValues(self: *const OwnedV1) []const QM31 {
        return self.storage().inputs;
    }
    pub fn evaluatedValues(self: *const OwnedV1) []const QM31 {
        return self.storage().values;
    }
    pub fn providerCalls(self: *const OwnedV1) []const rows.ProviderCall {
        return self.storage().calls;
    }
    pub fn providerBindings(self: *const OwnedV1) []const ProviderBinding {
        return self.storage().provider_bindings;
    }
    pub fn rawWireNode(self: *const OwnedV1, word: usize) !u32 {
        if (word >= self.storage().raw_wire_count) return error.InvalidBoundaryProjection;
        return if (self.storage().raw_nodes) |nodes| nodes[word] else self.storage().bindings[word].node_id;
    }
    pub fn retainedSections(self: *const OwnedV1) ![4]SectionV1 {
        return self.storage().sections orelse error.DetachedParentHasNoNativeSections;
    }
    pub fn family(self: *const OwnedV1) child_mod.Family {
        return self.storage().family;
    }
    pub fn publicationRawWord(self: *const OwnedV1, word: usize) !usize {
        if (word < recursion.span_continuation_v1.SPAN_WORDS or word >= recursion.span_continuation_v1.WORD_COUNT) return error.InvalidBoundaryProjection;
        if (self.family() == .parent) return word;
        const starts = [_]usize{ wire_layout.session_id, wire_layout.entry_lineage_id, wire_layout.exit_lineage_id };
        const extra = word - recursion.span_continuation_v1.SPAN_WORDS;
        return starts[extra / 8] + extra % 8;
    }
    pub fn initParent(allocator: std.mem.Allocator, child: *const child_mod.ParentOwnedV1) !*OwnedV1 {
        return initParentExpected(allocator, child);
    }
    pub fn spanNodes(self: *const OwnedV1) *const [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 {
        return &self.storage().span_nodes;
    }
};

fn initExpected(
    allocator: std.mem.Allocator,
    key: *const key_mod.KeyV1,
    expected: *const riscv_air.public_data_v2.PublicDataV2,
    relations: *const air.universal_challenges.UniversalRelations,
    statement_claim: QM31,
    profile: SectionProfileV1,
    memory_profile: MemoryProfileV1,
) !*OwnedV1 {
    try key.validate();
    const metadata = try expected.metadata();
    const expected_view = try expected.authenticatedView();
    try profile.validateView(&expected_view);
    const sections = try profile.sections(expected.words().len);
    try memory_profile.validate(profile);
    try public_inputs.verifyStatementClaim(expected, &key.admitted_keys, &key.source_manifest, relations, statement_claim);
    const context = try source.nativeContext(&metadata, &key.admitted_keys, &key.source_manifest);
    var counter: WordCounter = .{};
    source.emitContextIdentity(&context, &counter);
    const wire_calls = channel.canonicalWordPermutationCount(expected.words().len);
    const context_calls = channel.canonicalWordPermutationCount(counter.count);
    const authority_calls = try key.native_descriptors.callCount();
    var embedded_calls: usize = 0;
    for (std.meta.tags(identity_preimage.Phase)) |phase| embedded_calls += channel.canonicalWordPermutationCount(identity_preimage.wordCount(phase));
    var retained_calls: usize = 0;
    for (sections) |section| retained_calls += channel.canonicalWordPermutationCount(identity_preimage.retainedWordCount(section.count));
    const native_bytes = try allocator.alloc([4]M31, @as(usize, sections[0].count) + sections[1].count);
    defer allocator.free(native_bytes);
    const addresses = [2][]const u32{ memory_profile.entry_addresses, memory_profile.exit_addresses };
    var memory_counter: MemoryCounter = .{};
    var bytes_at: usize = 0;
    for (sections[0..2], addresses) |section, fixed_addresses| {
        const bytes = native_bytes[bytes_at..][0..section.count];
        for (bytes, fixed_addresses, 0..) |*words, address, index| {
            const at = section.payload_start + index * 4;
            const pair = expected.words()[at..][0..4];
            if (pair[0].toU32() + (pair[1].toU32() << 16) != address) return error.BoundaryMemoryProfileMismatch;
            const native = pair[2].toU32() + (pair[3].toU32() << 16);
            for (words, 0..) |*word, byte| word.* = M31.fromCanonical((native >> @as(u5, @intCast(byte * 8))) & 255);
        }
        var iterator = memory_profile_mod.ByteIterator(M31).init(fixed_addresses, bytes);
        _ = recursion.segment_statement_v2.continuationSubtreeRootWithHasher(&iterator, 0, 0, recursion.segment_statement_v2.MAX_RW_ADDRESS_EXCLUSIVE, &memory_counter);
        std.debug.assert(iterator.current == null);
        bytes_at += section.count;
    }
    const call_count = wire_calls + context_calls + authority_calls + embedded_calls + retained_calls + memory_counter.count;
    const calls = try allocator.alloc(rows.ProviderCall, call_count);
    errdefer allocator.free(calls);
    const call_words = try allocator.alloc([32]M31, call_count);
    defer allocator.free(call_words);
    var native_calls = NativeCalls{ .calls = calls, .words = call_words };
    var wire_hash = NativeSponge.init(&native_calls, recursion.segment_statement_v2.WIRE_ID_DOMAIN);
    for (expected.words()) |word| wire_hash.scalar(word.toU32());
    if (!std.meta.eql(wire_hash.finish(), metadata.wire_id)) return error.InvalidBoundaryHash;
    var context_hash = NativeSponge.init(&native_calls, source.CONTEXT_ID_DOMAIN);
    source.emitContextIdentity(&context, &context_hash);
    if (!std.meta.eql(context_hash.finish(), context.authenticated_context_id)) return error.InvalidBoundaryHash;
    const public_core = try riscv_air.statement_v2.canonicalCorePublicData(expected);
    const authority_input = preimage.Input{
        .initial_pc = public_core.initial_pc,
        .final_pc = public_core.final_pc,
        .cycle_count = public_core.clock,
        .wire_id = metadata.wire_id,
        .component_descs = key.native_descriptors.components,
        .infra_descs = key.native_descriptors.infrastructure,
    };
    var authority_hash = NativeSponge.init(&native_calls, preimage.DOMAIN);
    preimage.emit(&authority_hash, authority_input);
    const authority_digest = authority_hash.finish();
    if (!std.meta.eql(authority_digest, try preimage.hash(authority_input))) return error.InvalidBoundaryHash;
    const native_identities = try embeddedIdentityInputs(&expected_view, &metadata);
    for (native_identities) |identity_input| {
        const phase = std.meta.activeTag(identity_input);
        var hash = NativeSponge.init(&native_calls, identity_preimage.domain(phase));
        identity_preimage.emit(&hash, identity_input);
        const digest = hash.finish();
        const offset = identityOffset(phase);
        for (digest, expected.words()[offset..][0..8]) |word, actual| if (word != actual.toU32()) return error.InvalidBoundaryHash;
    }
    for (sections) |section| {
        var hash = NativeSponge.init(&native_calls, section.domain);
        identity_preimage.emitRetainedSection(&hash, section.count, expected.words()[section.payload_start..][0..section.payloadWords()]);
        const digest = hash.finish();
        for (digest, expected.words()[section.digest_offset..][0..8]) |word, actual| if (word != actual.toU32()) return error.InvalidBoundaryHash;
    }
    bytes_at = 0;
    var native_memory = NativeMemoryHasher{ .calls = &native_calls };
    for (sections[0..2], addresses, [_]u32{ metadata.entry_continuation_root, metadata.exit_continuation_root }) |section, fixed_addresses, expected_root| {
        var iterator = memory_profile_mod.ByteIterator(M31).init(fixed_addresses, native_bytes[bytes_at..][0..section.count]);
        const actual = recursion.segment_statement_v2.continuationSubtreeRootWithHasher(&iterator, 0, 0, recursion.segment_statement_v2.MAX_RW_ADDRESS_EXCLUSIVE, &native_memory);
        if (actual.toU32() != expected_root or iterator.current != null) return error.InvalidBoundaryHash;
        bytes_at += section.count;
    }
    if (native_calls.at != call_count) return error.InvalidBoundaryHash;
    const hash_boundary = try boundary.derive(expected, key.native_descriptors, relations);
    const combined_boundary = (try key.wireClaim(relations)).add(hash_boundary.claimed_sum);

    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    var inputs = Inputs{ .allocator = allocator, .builder = &builder };
    defer inputs.deinit();
    const wire_count = expected.words().len;
    for (expected.words(), 0..) |word, index| _ = try inputs.add(word, .{ .transcript = prefix.inputCoordinate(.wire, @intCast(index)).? });
    const wire_id_start = inputs.values.items.len;
    for (metadata.wire_id, 0..) |word, index| for (0..2) |limb| {
        _ = try inputs.add(M31.fromCanonical((word >> @as(u5, @intCast(limb * 16))) & 65535), .{ .transcript = prefix.inputCoordinate(.wire_id, @intCast(index * 2 + limb)).? });
    };
    var claim_limbs: [2][4]S = undefined;
    for (&claim_limbs, [_]QM31{ statement_claim, combined_boundary }, 0..) |*limbs, claim, item| {
        for (limbs, claim.toM31Array(), 0..) |*limb, word, index| limb.* = try inputs.add(word, .{ .transcript = if (item == 0) prefix.inputCoordinate(.claims, @intCast(36 * 4 + index)).? else prefix.inputCoordinate(.boundary, @intCast(index)).? });
    }
    var draw_limbs: [2][2][4]S = undefined;
    const domains = [_]Domain{ source.STATEMENT_RELATION_DOMAIN, .recursion_wire };
    for (&draw_limbs, domains) |*draws, domain| {
        const challenge = try relations.getExact(domain);
        for (draws, [_]QM31{ challenge.z, challenge.alpha }, 0..) |*limbs, draw, index| {
            for (limbs, draw.toM31Array(), 0..) |*limb, word, limb_index| limb.* = try inputs.add(word, .{ .challenge = .{ .domain = domain, .draw = @intCast(index), .limb = @intCast(limb_index) } });
        }
    }
    const end_start = inputs.values.items.len;
    for (0..2) |limb| _ = try inputs.add(M31.fromCanonical((metadata.global_cycle_end >> @as(u5, @intCast(16 * limb))) & 65535), .{ .end_limb = @intCast(limb) });
    const carry_native: u32 = @intFromBool((metadata.segment_index & 65535) == 65535);
    const increment_carry = try inputs.add(M31.fromCanonical(carry_native), .increment_carry);
    const next_low_index = inputs.values.items.len;
    const next_low_hint = try inputs.add(M31.fromCanonical((metadata.segment_index + 1) & 65535), .increment_low);
    try inputs.addRange(next_low_index, 16);
    const remaining = metadata.segment_count - metadata.segment_index - 1;
    const remaining_start = inputs.values.items.len;
    var remaining_limbs: [2]S = undefined;
    for (&remaining_limbs, 0..) |*limb, offset| limb.* = try inputs.add(M31.fromCanonical((remaining >> @as(u5, @intCast(16 * offset))) & 65535), .{ .remaining_segments_limb = @intCast(offset) });
    try inputs.addRange(remaining_start, 16);
    try inputs.addRange(remaining_start + 1, 16);
    const remaining_carry = try inputs.add(M31.fromCanonical(@intFromBool(((metadata.segment_index + 1) & 65535) + (remaining & 65535) >= 65536)), .remaining_segments_carry);
    const zero_values = [_]M31{
        M31.fromCanonical(metadata.segment_index & 65535),                                                                M31.fromCanonical(metadata.segment_index >> 16),
        M31.fromCanonical((metadata.segment_count & 65535)).sub(M31.fromCanonical((metadata.segment_index + 1) & 65535)), M31.fromCanonical(metadata.segment_count >> 16).sub(M31.fromCanonical((metadata.segment_index + 1) >> 16)),
    };
    var zero_inverses: [4]S = undefined;
    for (&zero_inverses, zero_values, 0..) |*inverse, value, index| inverse.* = try inputs.add(if (value.isZero()) M31.zero() else try value.inv(), .{ .zero_inverse = @intCast(index) });
    // Only limbs used as native integers in this graph need a local range
    // decomposition. Other canonical-wire semantics belong to parent admission.
    for (0..8) |index| {
        try inputs.addRange(wire_id_start + index * 2, 16);
        try inputs.addRange(wire_id_start + index * 2 + 1, 15);
    }
    for ([_]usize{
        BASE + span_layout.first_segment_start,                                           BASE + span_layout.job_segment_count_start,
        BASE + span_layout.first_cycle_start,                                             BASE + span_layout.executed_cycle_count_start,
        BASE + span_layout.entry_state_start + span_layout.machine_state_pc_start_offset, BASE + span_layout.exit_state_start + span_layout.machine_state_pc_start_offset,
        wire_layout.entry_continuation_root,                                              wire_layout.exit_continuation_root,
    }) |start| {
        try inputs.addRange(start, 16);
        try inputs.addRange(start + 1, if (start == BASE + span_layout.first_cycle_start or start == BASE + span_layout.executed_cycle_count_start) 9 else if (start == wire_layout.entry_continuation_root or start == wire_layout.exit_continuation_root) 15 else 16);
    }
    for ([_]usize{ wire_layout.entry_register_clocks, wire_layout.exit_register_clocks }) |clocks| for (0..64) |limb| try inputs.addRange(clocks + limb, 16);
    for ([_]usize{ wire_layout.entry_snapshot_count, wire_layout.exit_snapshot_count, wire_layout.entry_memory_clock_count, wire_layout.exit_memory_clock_count }) |section_count| {
        try inputs.addRange(section_count, 16);
        try inputs.addRange(section_count + 1, 16);
    }
    for (sections) |section| for (0..section.payloadWords()) |word| try inputs.addRange(section.payload_start + word, 16);
    try inputs.addRange(end_start, 16);
    try inputs.addRange(end_start + 1, 9);
    const symbolic_calls = try allocator.alloc([32]S, call_count);
    defer allocator.free(symbolic_calls);
    const provider_bindings = try allocator.alloc(ProviderBinding, call_count);
    errdefer allocator.free(provider_bindings);
    for (symbolic_calls, provider_bindings, call_words, 0..) |*symbols, *binding, words, call| {
        for (symbols, &binding.nodes, words, 0..) |*symbol, *node, word, index| {
            node.* = @intCast(inputs.values.items.len);
            symbol.* = try inputs.add(word, .{ .provider_word = .{ .call = @intCast(call), .word = @intCast(index) } });
        }
    }
    try builder.activate();
    try inputs.constrainRanges();
    const wire = inputs.scalars.items[0..wire_count];
    const end = U32{ .limbs = inputs.scalars.items[end_start..][0..2].* };
    const index = U32{ .limbs = wire[BASE + span_layout.first_segment_start ..][0..2].* };
    const count = U32{ .limbs = wire[BASE + span_layout.job_segment_count_start ..][0..2].* };
    const start = U32{ .limbs = wire[BASE + span_layout.first_cycle_start ..][0..2].* };
    const cycles = U32{ .limbs = wire[BASE + span_layout.executed_cycle_count_start ..][0..2].* };
    for ([_]usize{ BASE + span_layout.first_cycle_start + 2, BASE + span_layout.executed_cycle_count_start + 2 }) |offset| {
        try builder.constrainZero(wire[offset]);
        try builder.constrainZero(wire[offset + 1]);
    }
    // Values are bounded below2^25, hence these additions cannot wrap M31.
    try builder.constrainZero(end.value().sub(start.value().add(cycles.value())));
    try recordClockCanonicality(&builder, &inputs, sections, end_start);
    try constrainGlobalCeiling(&builder, &inputs, end_start);
    try constrainGlobalCeiling(&builder, &inputs, BASE + span_layout.first_cycle_start);
    try constrainGlobalCeiling(&builder, &inputs, BASE + span_layout.executed_cycle_count_start);
    const interval = end.value().sub(start.value());
    try builder.constrainZero(interval.mul(interval.inverse()).sub(S.one()));
    try builder.constrainZero(increment_carry.mul(increment_carry.sub(S.one())));
    const next_low = index.limbs[0].add(S.one()).sub(increment_carry.mul(base(65536)));
    try builder.constrainZero(next_low.sub(next_low_hint));
    // The ranged low limb makes the carry unique, including at65535.
    try builder.constrainZero(increment_carry.mul(index.limbs[0].sub(base(65535))));
    const next_high = index.limbs[1].add(increment_carry);
    const next_index = U32{ .limbs = .{ next_low, next_high } };
    try constrainSegmentIndexBound(&builder, next_index, count, .{ .limbs = remaining_limbs }, remaining_carry);
    const first = (try zeroTest(&builder, index.limbs[0], zero_inverses[0])).mul(try zeroTest(&builder, index.limbs[1], zero_inverses[1]));
    const final = (try zeroTest(&builder, count.limbs[0].sub(next_low), zero_inverses[2])).mul(try zeroTest(&builder, count.limbs[1].sub(next_high), zero_inverses[3]));
    // Leaf role is fixed independently of concrete statement values.
    try builder.constrainZero(wire[BASE + span_layout.executed_segment_count_start].sub(S.one()));
    try builder.constrainZero(wire[BASE + span_layout.executed_segment_count_start + 1]);
    var graph_calls = GraphCalls{ .builder = &builder, .words = symbolic_calls };
    var graph_wire_hash = GraphSponge.init(&graph_calls, recursion.segment_statement_v2.WIRE_ID_DOMAIN);
    for (wire) |word| graph_wire_hash.scalar(word);
    const graph_wire_id = graph_wire_hash.finish();
    for (graph_wire_id, 0..) |word, word_index| {
        const pair = U32{ .limbs = inputs.scalars.items[wire_id_start + word_index * 2 ..][0..2].* };
        try builder.constrainZero(word.sub(pair.value()));
        // Split-u16 representation must exclude p, the second spelling of0.
        var all_ones = S.one();
        for (inputs.ranges.items) |range| if (range.input == wire_id_start + word_index * 2 or range.input == wire_id_start + word_index * 2 + 1) {
            for (range.bits) |bit| all_ones = all_ones.mul(bit);
        };
        try builder.constrainZero(all_ones);
    }
    try constrainCanonicalPair(&builder, &inputs, wire_layout.entry_continuation_root);
    try constrainCanonicalPair(&builder, &inputs, wire_layout.exit_continuation_root);
    var graph_context = .{
        .format_version = source.FORMAT_VERSION,
        .schema_version = source.SCHEMA_VERSION,
        .statement_version = riscv_air.public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
        .segment_index = index,
        .segment_count = count,
        .global_cycle_start = start,
        .global_cycle_end = end,
        .is_first = first,
        .is_final = final,
        .entry_continuation_root = U32{ .limbs = wire[wire_layout.entry_continuation_root..][0..2].* },
        .exit_continuation_root = U32{ .limbs = wire[wire_layout.exit_continuation_root..][0..2].* },
        .segment_format_id = digestConstants(recursion.segment_statement_v2.formatId()),
        .protocol_id = digestConstants(recursion.protocol.PROTOCOL_ID_WORDS),
        .manifest_id = digestConstants(key.source_manifest.identity),
        .statement_id = wire[wire_layout.base_statement_id..][0..8].*,
        .segment_wire_id = graph_wire_id,
        .session_id = wire[wire_layout.session_id..][0..8].*,
        .job_id = wire[wire_layout.job_id..][0..8].*,
        .position_id = wire[wire_layout.position_id..][0..8].*,
        .entry_lineage_id = wire[wire_layout.entry_lineage_id..][0..8].*,
        .exit_lineage_id = wire[wire_layout.exit_lineage_id..][0..8].*,
        .lineage_id = wire[wire_layout.lineage_id..][0..8].*,
        .verifier_key_authority_id = digestConstants(key.admitted_keys.identity),
        .segment_leaf_vk_id = digestConstants(key.admitted_keys.segment_leaf_vk_id),
        .recursive_parent_vk_id = digestConstants(key.admitted_keys.recursive_parent_vk_id),
        // This field is absent from its own identity preimage. Seed its
        // runtime type, then replace it before emitting context words.
        .authenticated_context_id = graph_wire_id,
    };
    var graph_context_hash = GraphSponge.init(&graph_calls, source.CONTEXT_ID_DOMAIN);
    source.emitContextIdentity(&graph_context, &graph_context_hash);
    graph_context.authenticated_context_id = graph_context_hash.finish();
    var context_words: ContextWords = .{};
    source.emitContextWords(&graph_context, &context_words);
    if (context_words.at != context_words.words.len) return error.InvalidBoundaryShape;
    var graph_authority_hash = GraphSponge.init(&graph_calls, preimage.DOMAIN);
    var authority_sink = AuthoritySink{ .sponge = &graph_authority_hash, .wire = wire, .wire_id = graph_wire_id };
    preimage.emit(&authority_sink, authority_input);
    _ = graph_authority_hash.finish();
    try recordEmbeddedIdentities(&graph_calls, wire, index, next_index, count, start, end);
    try recordRetainedIdentities(&graph_calls, wire, sections);
    try recordContinuationRoots(allocator, &graph_calls, &inputs, wire, sections, addresses);
    if (graph_calls.failure) |err| return err;
    if (graph_calls.at != call_count) return error.InvalidBoundaryShape;
    const statement_challenge = try recorder.ChallengeSet.Element.init(3, recorder.fromPartialEvals(draw_limbs[0][0]), recorder.fromPartialEvals(draw_limbs[0][1]));
    const wire_challenge = try recorder.ChallengeSet.Element.init(6, recorder.fromPartialEvals(draw_limbs[1][0]), recorder.fromPartialEvals(draw_limbs[1][1]));
    var statement_sink = StatementSink{ .challenge = &statement_challenge };
    try public_inputs.emitStatementTerms(wire, &context_words.words, &statement_sink);
    try builder.constrainZero(statement_sink.claim.sub(recorder.fromPartialEvals(claim_limbs[0])));
    var combined = S.zero();
    for (key.wire_terms) |term| {
        const parts = try air.verifier_arithmetic_lowering.publicTermParts(term);
        var tuple: [6]S = undefined;
        for (&tuple, parts.tuple) |*out, word| out.* = S.fromSecure(word);
        combined = combined.add(S.fromSecure(parts.numerator).mul((try wire_challenge.combine(&tuple)).inverse()));
    }
    for (symbolic_calls[wire_calls + context_calls ..][0..authority_calls], 0..) |words, call| {
        for (0..call_source.CALL_WIRE_GROUP_COUNT) |group| {
            const tuple = call_source.callWireTupleGeneric(S, S.fromBase, call, group, &words);
            combined = combined.sub((try wire_challenge.combine(&tuple)).inverse());
        }
    }
    try builder.constrainZero(combined.sub(recorder.fromPartialEvals(claim_limbs[1])));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try allocator.alloc(QM31, circuit.nodes.len);
    errdefer allocator.free(values);
    try circuit.evaluateInto(inputs.values.items, values);
    const value = try allocator.create(OwnedV1.Storage);
    errdefer allocator.destroy(value);
    const input_values = try inputs.values.toOwnedSlice(allocator);
    errdefer allocator.free(input_values);
    const bindings = try inputs.bindings.toOwnedSlice(allocator);
    errdefer allocator.free(bindings);
    var span_nodes: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&span_nodes, 0..) |*node, word| node.* = @intCast(BASE + word);
    value.* = .{ .allocator = allocator, .circuit = circuit, .inputs = input_values, .bindings = bindings, .values = values, .calls = calls, .provider_bindings = provider_bindings, .span_nodes = span_nodes, .raw_wire_count = wire_count, .sections = sections };
    return @ptrCast(value);
}

/// The parent protocol publishes canonical M31 words via split-u16 transcript
/// encoding. Constrain both limbs, exclude p as an alias of zero, and derive
/// the complete public lookup claim from the reconstructed words.
fn initParentExpected(allocator: std.mem.Allocator, child: *const child_mod.ParentOwnedV1) !*OwnedV1 {
    const protocol = recursion.detached_parent_protocol_v1;
    const expected = child.expected();
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    var inputs = Inputs{ .allocator = allocator, .builder = &builder };
    defer inputs.deinit();
    for (expected, 0..) |word, index| for (0..2) |limb| {
        _ = try inputs.add(M31.fromCanonical((word.toU32() >> @as(u5, @intCast(limb * 16))) & 65535), .{
            .transcript = prefix.inputCoordinateFor(.parent, .span_u32, @intCast(index * 2 + limb)).?,
        });
    };
    var claim: [4]S = undefined;
    const native_claim = try protocol.publicBoundary(expected, child.relations());
    for (&claim, native_claim.toM31Array(), 0..) |*limb, word, index|
        limb.* = try inputs.add(word, .{ .transcript = prefix.inputCoordinateFor(.parent, .boundary, @intCast(index)).? });
    const native_challenge = try child.relations().getExact(.recursion_statement_word);
    var draws: [2][4]S = undefined;
    for (&draws, [_]QM31{ native_challenge.z, native_challenge.alpha }, 0..) |*limbs, draw, index| {
        for (limbs, draw.toM31Array(), 0..) |*limb, word, part|
            limb.* = try inputs.add(word, .{ .challenge = .{ .domain = .recursion_statement_word, .draw = @intCast(index), .limb = @intCast(part) } });
    }
    for (0..expected.len) |word| {
        try inputs.addRange(word * 2, 16);
        try inputs.addRange(word * 2 + 1, 15);
    }
    const nodes = try allocator.alloc(u32, expected.len);
    errdefer allocator.free(nodes);
    try builder.activate();
    try inputs.constrainRanges();
    const challenge = try recorder.ChallengeSet.Element.init(3, recorder.fromPartialEvals(draws[0]), recorder.fromPartialEvals(draws[1]));
    var sink = StatementSink{ .challenge = &challenge };
    for (nodes, 0..) |*node, index| {
        try constrainCanonicalPair(&builder, &inputs, index * 2);
        const word = (U32{ .limbs = inputs.scalars.items[index * 2 ..][0..2].* }).value();
        node.* = switch (word.handle) {
            .node => |id| id,
            .constant => return error.InvalidBoundaryProjection,
        };
        try sink.term(protocol.PUBLIC_SCOPE, index, word);
    }
    try builder.constrainZero(sink.claim.sub(recorder.fromPartialEvals(claim)));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try allocator.alloc(QM31, circuit.nodes.len);
    errdefer allocator.free(values);
    try circuit.evaluateInto(inputs.values.items, values);
    const value = try allocator.create(OwnedV1.Storage);
    errdefer allocator.destroy(value);
    const input_values = try inputs.values.toOwnedSlice(allocator);
    errdefer allocator.free(input_values);
    const bindings = try inputs.bindings.toOwnedSlice(allocator);
    errdefer allocator.free(bindings);
    value.* = .{ .allocator = allocator, .circuit = circuit, .inputs = input_values, .bindings = bindings, .values = values, .calls = &.{}, .provider_bindings = &.{}, .span_nodes = nodes[0..recursion.span_continuation_v1.SPAN_WORDS].*, .raw_wire_count = expected.len, .raw_nodes = nodes, .sections = null, .family = .parent };
    return @ptrCast(value);
}

fn constrainCanonicalPair(builder: *recorder.Builder, inputs: *const Inputs, low_index: usize) !void {
    var all_ones = S.one();
    for (inputs.ranges.items) |range| if (range.input == low_index or range.input == low_index + 1) {
        for (range.bits) |bit| all_ones = all_ones.mul(bit);
    };
    try builder.constrainZero(all_ones);
}

fn constrainGlobalCeiling(builder: *recorder.Builder, inputs: *const Inputs, low_index: usize) !void {
    for (inputs.ranges.items) |range| if (range.input == low_index + 1) {
        std.debug.assert(range.bits.len == 9);
        const top = range.bits[8];
        const low = inputs.scalars.items[low_index].add(inputs.scalars.items[low_index + 1].sub(top.mul(base(256))).mul(base(65536)));
        try builder.constrainZero(top.mul(low));
        return;
    };
    return error.InvalidBoundaryRange;
}
fn zeroTest(builder: *recorder.Builder, value: S, inverse: S) !S {
    const zero = S.one().sub(value.mul(inverse));
    try builder.constrainZero(value.mul(zero));
    return zero;
}
const StatementSink = struct {
    challenge: *const recorder.ChallengeSet.Element,
    claim: S = S.zero(),
    pub fn term(self: *StatementSink, scope: u32, index: usize, value: S) !void {
        const tuple = source.statementTupleGeneric(S, S.fromBase, scope, index, value);
        self.claim = self.claim.add((try self.challenge.combine(&tuple)).inverse());
    }
};

/// Independent scalar check of the provider obligation for graph tests. This
/// is not the parent AIR: production must close these same32-word requests
/// against the shared Poseidon component before accepting a parent proof.
fn evaluateWithProviderChecks(value: *const OwnedV1.Storage, inputs: []const QM31, scratch: []QM31) !void {
    try value.circuit.evaluateInto(inputs, scratch);
    for (value.provider_bindings) |binding| {
        var state: [16]M31 = undefined;
        for (&state, binding.nodes[0..16]) |*word, node| {
            const limbs = scratch[node].toM31Array();
            if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero()) return error.InvalidBoundaryProvider;
            word.* = limbs[0];
        }
        poseidon.permute(&state);
        for (state, binding.nodes[16..32]) |word, node| if (!scratch[node].eql(QM31.fromBase(word))) return error.InvalidBoundaryProvider;
    }
}

fn exercise(value: *const OwnedV1.Storage) !void {
    const allocator = std.testing.allocator;
    const changed = try allocator.dupe(QM31, value.inputs);
    defer allocator.free(changed);
    const scratch = try allocator.alloc(QM31, value.values.len);
    defer allocator.free(scratch);
    try evaluateWithProviderChecks(value, changed, scratch);
    var mutations: usize = 0;
    for (value.bindings, 0..) |binding, index| {
        const mutate = switch (binding.source) {
            .transcript => |coordinate| coordinate.kind == .claimed_sum or
                (coordinate.kind == .statement and (coordinate.item == prefix.WIRE_ID_BASE or coordinate.item == prefix.RAW_WIRE_BASE + BASE + span_layout.first_cycle_start or coordinate.item == prefix.RAW_WIRE_BASE + wire_layout.entry_continuation_root or coordinate.item == prefix.RAW_WIRE_BASE + wire_layout.base_statement_id or coordinate.item == prefix.RAW_WIRE_BASE + wire_layout.entry_snapshot_count or coordinate.item == prefix.RAW_WIRE_BASE + wire_layout.exit_snapshot_count or coordinate.item == prefix.RAW_WIRE_BASE + wire_layout.entry_memory_clock_count or coordinate.item == prefix.RAW_WIRE_BASE + wire_layout.exit_memory_clock_count or coordinate.item == prefix.RAW_WIRE_BASE + recursion.segment_statement_v2.FIXED_CANONICAL_WORDS)),
            .end_limb, .increment_carry, .increment_low, .remaining_segments_limb, .remaining_segments_carry => true,
            .range_bit => |bit| bit.bit == 0 and value.bindings[bit.input].source == .transcript and value.bindings[bit.input].source.transcript.item == prefix.WIRE_ID_BASE,
            .provider_word => |word| (word.call == 0 or word.call + 1 == value.calls.len) and (word.word == 0 or word.word == 16 or word.word == 31),
            .challenge => |coordinate| coordinate.limb == 0,
            .zero_inverse => false, // Zero-input inverses intentionally have no semantic value.
        };
        if (!mutate) continue;
        changed[index] = changed[index].add(QM31.one());
        defer changed[index] = value.inputs[index];
        if (evaluateWithProviderChecks(value, changed, scratch)) |_| return error.TestExpectedError else |err| switch (err) {
            error.UnsatisfiedCircuit, error.InvalidBoundaryProvider => {},
            else => return err,
        }
        mutations += 1;
    }
    try std.testing.expect(mutations >= 20);
    try evaluateWithProviderChecks(value, value.inputs, scratch);
    std.debug.print("detached expected boundary: inputs={d} nodes={d} outputs={d} provider_calls={d} rejected={d}\n", .{ value.inputs.len, value.values.len, value.circuit.outputs.len, value.calls.len, mutations });
}

/// Retained genuine-child arithmetic/provider check, not recursive acceptance.
pub fn testFromVerifiedChild(allocator: std.mem.Allocator, child: *const child_mod.OwnedV1, profile: SectionProfileV1, memory_profile: MemoryProfileV1) !void {
    const value = try OwnedV1.init(allocator, child, profile, memory_profile);
    defer value.deinit();
    try exercise(value.storage());
}

pub fn testExpectedBoundary() !void {
    try testIndexBounds();
    try testClockCanonicality();
    const fixture = testing_support.public_data_v2_test_support;
    const allocator = std.testing.allocator;
    const left_fixture = try fixture.Fixture.initWithRegister7(13);
    const right_fixture = try fixture.Fixture.initWithRegister7(42);
    const left_words = try fixture.encode(allocator, &left_fixture.leftSource());
    defer allocator.free(left_words);
    const right_words = try fixture.encode(allocator, &right_fixture.leftSource());
    defer allocator.free(right_words);
    try std.testing.expectEqual(left_words.len, right_words.len);
    const left = try riscv_air.public_data_v2.PublicDataV2.authenticate(left_words);
    const right = try riscv_air.public_data_v2.PublicDataV2.authenticate(right_words);
    const key = try @import("detached_segment_protocol_fixture_v1.zig").testing.key(left_words.len, 1);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const left_claim = try public_inputs.statementClaim(&left, &key.admitted_keys, &key.source_manifest, &relations);
    const right_claim = try public_inputs.statementClaim(&right, &key.admitted_keys, &key.source_manifest, &relations);
    const a = try testing.fromExpected(allocator, &left);
    defer a.deinit();
    const b = try testing.fromExpected(allocator, &right);
    defer b.deinit();
    try std.testing.expectEqual(a.graph().identity_digest, b.graph().identity_digest);
    try std.testing.expect(!std.meta.eql(left.wireId(), right.wireId()));
    try std.testing.expect(!left_claim.eql(right_claim));
    try exercise(a.storage());
    try exercise(b.storage());
    const final_words = try fixture.encode(allocator, &right_fixture.rightSource());
    defer allocator.free(final_words);
    const final_data = try riscv_air.public_data_v2.PublicDataV2.authenticate(final_words);
    try std.testing.expect((try final_data.metadata()).is_final);
    const final_boundary = try testing.fromExpected(allocator, &final_data);
    defer final_boundary.deinit();
    try exercise(final_boundary.storage());
    var wrong_profile = try testing.profileFromExpected(&left);
    wrong_profile.counts[0] += 1;
    wrong_profile.counts[1] -= 1;
    try std.testing.expectError(error.BoundarySectionProfileMismatch, initExpected(allocator, &key, &left, &relations, left_claim, wrong_profile, .{ .entry_addresses = &.{}, .exit_addresses = &.{} }));
    // Values with different zero-byte patterns must use the identical admitted
    // sparse tree topology, graph and provider schedule.
    var memory_graph: ?[32]u8 = null;
    var memory_calls: usize = 0;
    for ([_]u32{ 13, 14, 269 }) |memory_value| {
        const words = try fixture.sparseValueCanonicalWords(allocator, memory_value);
        defer allocator.free(words);
        const data = try riscv_air.public_data_v2.PublicDataV2.authenticate(words);
        const memory_boundary = try testing.fromExpected(allocator, &data);
        defer memory_boundary.deinit();
        if (memory_graph) |identity| {
            try std.testing.expectEqual(identity, memory_boundary.graph().identity_digest);
            try std.testing.expectEqual(memory_calls, memory_boundary.providerCalls().len);
        } else {
            memory_graph = memory_boundary.graph().identity_digest;
            memory_calls = memory_boundary.providerCalls().len;
        }
        try exercise(memory_boundary.storage());
    }
    // Wire projection is a view of the authenticated transcript input nodes,
    // never a second independently supplied SpanStatement witness.
    for (a.spanNodes(), 0..) |node, index| try std.testing.expect(a.evaluatedValues()[node].eql(QM31.fromBase(left_words[BASE + index])));
}

pub const testing = if (@import("builtin").is_test) struct {
    /// Mutate every reconstructed public word with coherent range witnesses.
    /// The public claim must reject these independently of range constraints.
    pub fn parentBoundary(allocator: std.mem.Allocator, child: *const child_mod.ParentOwnedV1) !void {
        const owner = try OwnedV1.initParent(allocator, child);
        defer owner.deinit();
        const value = owner.storage();
        const changed = try allocator.dupe(QM31, value.inputs);
        defer allocator.free(changed);
        const scratch = try allocator.alloc(QM31, value.values.len);
        defer allocator.free(scratch);
        for (child.expected(), 0..) |word, index| {
            @memcpy(changed, value.inputs);
            const replacement = word.add(M31.one()).toU32();
            setParentWord(value.bindings, changed, index, replacement);
            try std.testing.expectError(error.UnsatisfiedCircuit, value.circuit.evaluateInto(changed, scratch));
        }
        // p has the same field value as zero. Coherently changing all 31 bits
        // must still fail the canonical encoding constraint.
        const zero = for (child.expected(), 0..) |word, index| {
            if (word.toU32() == 0) break index;
        } else return error.TestExpectedZeroPublicWord;
        @memcpy(changed, value.inputs);
        setParentWord(value.bindings, changed, zero, 0x7fff_ffff);
        try std.testing.expectError(error.UnsatisfiedCircuit, value.circuit.evaluateInto(changed, scratch));
        try value.circuit.evaluateInto(value.inputs, scratch);
        std.debug.print("DETACHED_PARENT_BOUNDARY rejected_public_words={d} rejected_noncanonical_zero=true\n", .{child.expected().len});
    }
    fn setParentWord(bindings: []const InputBinding, values: []QM31, word: usize, replacement: u32) void {
        values[word * 2] = QM31.fromBase(M31.fromCanonical(replacement & 65535));
        values[word * 2 + 1] = QM31.fromBase(M31.fromCanonical(replacement >> 16));
        for (bindings, 0..) |binding, index| switch (binding.source) {
            .range_bit => |bit| if (bit.input == word * 2 or bit.input == word * 2 + 1) {
                const limb = values[bit.input].toM31Array()[0].toU32();
                values[index] = QM31.fromBase(M31.fromCanonical((limb >> @as(u5, @intCast(bit.bit))) & 1));
            },
            else => {},
        };
    }
    /// Synthetic fixture profile only; production must independently admit it.
    pub fn profileFromExpected(expected: *const riscv_air.public_data_v2.PublicDataV2) !SectionProfileV1 {
        const view = try expected.authenticatedView();
        return .{ .counts = .{ view.entry_snapshot.count, view.exit_snapshot.count, view.entry_memory_clocks.count, view.exit_memory_clocks.count } };
    }
    /// Canonical-wire arithmetic fixture, not a child-proof receipt.
    pub fn fromExpected(allocator: std.mem.Allocator, expected: *const riscv_air.public_data_v2.PublicDataV2) !*OwnedV1 {
        const key = try @import("detached_segment_protocol_fixture_v1.zig").testing.key(expected.words().len, 1);
        const relations = air.universal_challenges.UniversalRelations.dummy();
        const claim = try public_inputs.statementClaim(expected, &key.admitted_keys, &key.source_manifest, &relations);
        const profile = try profileFromExpected(expected);
        const sections = try profile.sections(expected.words().len);
        const addresses = try allocator.alloc(u32, @as(usize, profile.counts[0]) + profile.counts[1]);
        defer allocator.free(addresses);
        var at: usize = 0;
        for (sections[0..2]) |section| {
            for (0..section.count) |index| {
                const pair = expected.words()[section.payload_start + index * 4 ..][0..2];
                addresses[at] = pair[0].toU32() + (pair[1].toU32() << 16);
                at += 1;
            }
        }
        return initExpected(allocator, &key, expected, &relations, claim, profile, .{ .entry_addresses = addresses[0..profile.counts[0]], .exit_addresses = addresses[profile.counts[0]..] });
    }
} else struct {};
