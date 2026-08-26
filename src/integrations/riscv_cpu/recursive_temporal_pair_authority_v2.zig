//! First honest temporal `2 -> 1` authority for two independently verified
//! SegmentV2 leaves.
//!
//! Parent slot, height, statement, session, job, leaf VK, and aggregator VK
//! are derived from the admitted children.  The only caller authority is an
//! explicit `RootVkPinV2`.  Full V2 adjacency additionally requires matching
//! cycle, continuation-root, and boundary-lineage seams; canonical V1 folding
//! alone is not treated as sufficient evidence for the retained V2 boundary.
//!
//! Cold preparation uses `temporal_pair_node.PreparedRootContextV2` exactly
//! once.  Repeated authentication then performs fixed-size equality checks,
//! zero Poseidon permutations, and zero heap allocations.  This is the
//! prepared-form seam for the known pair-node hashing optimization; it does
//! not claim that a temporal parent STARK exists.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const temporal = recursion.temporal_pair_node;
const child_authority = @import("recursive_segment_v2_temporal_child_authority.zig");

pub const Digest = channel.Digest;
pub const PreparedChild = child_authority.PreparedTemporalChildV1;
pub const RootVkPin = temporal.RootVkPinV2;

pub const FORMAT_VERSION: u16 = 1;
pub const PAIR_SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const FIRST_PARENT_HEIGHT: u8 = 1;
pub const ADJACENCY_ID_DOMAIN: u32 = 0x5356_4144; // "SVAD"
pub const PAIR_AUTHORITY_ID_DOMAIN: u32 = 0x5356_5041; // "SVPA"

pub const HEAP_ALLOCATIONS_PER_PREPARATION: usize = 0;
pub const HISTORICAL_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const ONE_PASS_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
/// Exact successful-path receipt for the former independent authority/record
/// validator. Retained for executable old-vs-new evidence only.
pub const HISTORICAL_VALIDATION_HASH_INVOCATIONS: usize = 23;
pub const HISTORICAL_VALIDATION_SCALAR_POSEIDON_PERMUTATIONS: usize = 543;
/// Exact successful-path receipt for `PreparedTemporalPairAuthorityV1.validate`.
pub const ONE_PASS_VALIDATION_HASH_INVOCATIONS: usize = 19;
pub const ONE_PASS_VALIDATION_SCALAR_POSEIDON_PERMUTATIONS: usize = 433;
pub const HOT_AUTHENTICATION_HEAP_ALLOCATIONS: usize =
    temporal.HOT_AUTHENTICATION_HEAP_ALLOCATIONS;
pub const HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS: usize =
    temporal.HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS;
pub const HISTORICAL_HOT_SNAPSHOT_EQUALITY_PASSES: usize = 3;
pub const HOT_SNAPSHOT_EQUALITY_PASSES: usize = 0;
pub const TEMPORAL_ROOT_PREPARATIONS_PER_PAIR: usize = 1;
pub const DUPLICATE_POST_PREPARATION_VALIDATIONS: usize = 0;
pub const PREPARED_PAIR_CONTEXT_AMORTIZED = true;
pub const DETACHED_PARENT_CONTEXT_ACCEPTED = false;
pub const AUTHENTICATED_PAIR_AVAILABLE = true;
pub const COMPLETE_PARENT_PROOF_AVAILABLE = false;

pub const Error = child_authority.Error || temporal.Error || error{
    AdjacencyMismatch,
    AliasedDestination,
    DuplicateChild,
    PairIdentityMismatch,
    ParentGeometryMismatch,
    UnsupportedFormat,
};

pub const PreparedTemporalPairAuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = PAIR_SCHEMA_VERSION,
    child_count: u8 = CHILD_COUNT,
    parent_proof_available: bool = COMPLETE_PARENT_PROOF_AVAILABLE,
    padding: [2]u8 = .{ 0, 0 },
    /// Compact V2-only context.  The two 412-word child statements already
    /// live in `prepared_root.authority_snapshot`; they are not copied here.
    source_bindings: [CHILD_COUNT]child_authority.SourceBindingV1,
    adjacency_id: Digest,
    prepared_root: temporal.PreparedRootContextV2,
    authority_id: Digest,

    pub fn validate(
        self: *const PreparedTemporalPairAuthorityV1,
    ) Error!void {
        try validateEnvelope(self);
        const authority = &self.prepared_root.authority_snapshot;
        const record = &self.prepared_root.record_snapshot;
        const pin = &self.prepared_root.pin_snapshot;

        // Re-derive the complete prepared capability once and compare it by
        // value. Independently validating the authority and record repeated
        // their statement/child hash trees while never proving that the
        // cached result belonged to either snapshot. One full reconstruction
        // both removes that duplicate work and rejects coherent mutations of
        // an inner snapshot, record, pin, or cached result.
        const reconstructed = try temporal.prepareRootContext(authority, pin);
        if (!std.meta.eql(reconstructed, self.prepared_root))
            return error.PairIdentityMismatch;

        for (self.source_bindings, authority.children) |binding, child|
            try child_authority.validateSourceBinding(binding, child);
        _ = try validateAdjacencyAndFold(
            self.source_bindings,
            authority.children,
        );
        if (authority.context.parent_height != FIRST_PARENT_HEIGHT or
            record.context.parent_height != FIRST_PARENT_HEIGHT)
        {
            return error.ParentGeometryMismatch;
        }
        const authenticated = reconstructed.result;
        if (!std.meta.eql(
            self.adjacency_id,
            adjacencyIdentity(
                self.source_bindings,
                authority,
                &authenticated,
            ),
        ) or !std.meta.eql(
            self.authority_id,
            pairAuthorityIdentity(self),
        )) return error.PairIdentityMismatch;
    }

    /// Constant-storage direct publication from the immutable prepared
    /// capability. Callers that cross an untrusted mutation boundary must use
    /// `validate` before entering this hot path. Passing the capability's own
    /// embedded snapshots back through the generic frontend authenticator
    /// only compared each value with itself, so it could detect no mutation
    /// and needlessly walked three large snapshots on every source call.
    pub fn authenticatePrepared(
        self: *const PreparedTemporalPairAuthorityV1,
    ) Error!temporal.RootAuthenticatedTemporalPairV2 {
        return self.prepared_root.result;
    }

    pub fn productionReady(
        _: *const PreparedTemporalPairAuthorityV1,
    ) bool {
        return false;
    }
};

fn validateEnvelope(
    self: *const PreparedTemporalPairAuthorityV1,
) Error!void {
    if (self.format_version != FORMAT_VERSION or
        self.schema_version != PAIR_SCHEMA_VERSION or
        self.child_count != CHILD_COUNT or self.parent_proof_available or
        !allZero(&self.padding))
    {
        return error.UnsupportedFormat;
    }
    try requireDigest(self.adjacency_id);
    try requireDigest(self.authority_id);
}

/// Test-only executable RED baseline retained solely to measure the exact
/// temporal hash work removed from cold prepared validation. Production has
/// no callable legacy path.
fn validateHistoricalPreOnePassImpl(
    self: *const PreparedTemporalPairAuthorityV1,
) Error!void {
    try validateEnvelope(self);
    const authority = &self.prepared_root.authority_snapshot;
    const record = &self.prepared_root.record_snapshot;
    const pin = &self.prepared_root.pin_snapshot;
    try authority.validate();
    try record.validate();
    try pin.validate();
    for (self.source_bindings, authority.children) |binding, child|
        try child_authority.validateSourceBinding(binding, child);
    _ = try validateAdjacencyAndFold(
        self.source_bindings,
        authority.children,
    );
    if (authority.context.parent_height != FIRST_PARENT_HEIGHT or
        record.context.parent_height != FIRST_PARENT_HEIGHT)
    {
        return error.ParentGeometryMismatch;
    }
    const authenticated = try temporal.authenticateRootWithPreparedContext(
        &self.prepared_root,
        authority,
        record,
        pin,
    );
    if (!std.meta.eql(authenticated, self.prepared_root.result))
        return error.PairIdentityMismatch;
    if (!std.meta.eql(
        self.adjacency_id,
        adjacencyIdentity(
            self.source_bindings,
            authority,
            &authenticated,
        ),
    ) or !std.meta.eql(
        self.authority_id,
        pairAuthorityIdentity(self),
    )) return error.PairIdentityMismatch;
}

pub const test_support = if (builtin.is_test) struct {
    pub fn validateHistoricalPreOnePass(
        value: *const PreparedTemporalPairAuthorityV1,
    ) Error!void {
        return validateHistoricalPreOnePassImpl(value);
    }
} else struct {};

/// Cold, fail-atomic preparation of the first leaf pair.  There is no parent
/// context parameter: all such fields are derived from the two child records.
pub fn prepareInto(
    destination: *PreparedTemporalPairAuthorityV1,
    left: *const PreparedChild,
    right: *const PreparedChild,
    root_pin: *const RootVkPin,
) Error!void {
    try rejectDestinationAliases(destination, left, right, root_pin);
    try left.validate();
    try right.validate();
    try root_pin.validate();
    if (std.meta.eql(left.admission_id, right.admission_id) or
        std.meta.eql(left.child_id, right.child_id) or
        std.meta.eql(left.source_publication_id, right.source_publication_id))
    {
        return error.DuplicateChild;
    }

    const source_bindings = [_]child_authority.SourceBindingV1{
        left.sourceBinding(),
        right.sourceBinding(),
    };
    const children = [_]temporal.VerifiedChildV2{ left.child, right.child };
    const parent_statement = try validateAdjacencyAndFold(
        source_bindings,
        children,
    );
    if (parent_statement.slots.height != FIRST_PARENT_HEIGHT)
        return error.ParentGeometryMismatch;
    const parent_words = try parent_statement.canonicalWords();
    var statement_probe = std.mem.zeroes(temporal.VerifiedChildV2);
    statement_probe.statement_words = parent_words;
    const parent_statement_id = try statement_probe.statementId();

    const context = temporal.VerifierContextV2{
        .session_id = children[0].session_id,
        .job_id = children[0].job_id,
        .segment_leaf_vk_id = children[0].verification_key_id,
        .aggregator_vk_id = children[0].recursive_parent_vk_id,
        .parent_node_index = parent_statement.slots.nodeIndex(),
        .parent_height = parent_statement.slots.height,
        .expected_parent_statement_id = parent_statement_id,
    };
    const authority = temporal.VerifierAuthorityV2{
        .context = context,
        .children = children,
    };
    // `prepareRootContext` is the one cold temporal validation/hash pass.  It
    // returns the canonical record snapshot; asking `recordFromAuthority`
    // first would repeat the child and statement hashes this path amortizes.
    const prepared_root = try temporal.prepareRootContext(
        &authority,
        root_pin,
    );
    const authenticated = try temporal.authenticateRootWithPreparedContext(
        &prepared_root,
        &authority,
        &prepared_root.record_snapshot,
        root_pin,
    );
    if (!std.meta.eql(authenticated, prepared_root.result))
        return error.PairIdentityMismatch;

    var staged = PreparedTemporalPairAuthorityV1{
        .source_bindings = source_bindings,
        .adjacency_id = adjacencyIdentity(
            source_bindings,
            &authority,
            &authenticated,
        ),
        .prepared_root = prepared_root,
        .authority_id = [_]u32{0} ** channel.RATE,
    };
    staged.authority_id = pairAuthorityIdentity(&staged);
    // Inputs were validated before construction and the prepared temporal
    // context performed the complete cold protocol check. `validate()` stays
    // available as an explicit hostile-mutation audit, not a duplicated mint
    // cost.
    destination.* = staged;
}

fn validateAdjacencyAndFold(
    bindings: [CHILD_COUNT]child_authority.SourceBindingV1,
    children: [CHILD_COUNT]temporal.VerifiedChildV2,
) Error!recursion.span_statement.SpanStatement {
    const left = bindings[0];
    const right = bindings[1];
    if (children[0].position != .left or children[1].position != .right or
        left.segment_index == std.math.maxInt(u32) or
        left.segment_index + 1 != right.segment_index or
        left.segment_count != right.segment_count or
        left.global_cycle_end != right.global_cycle_start or
        left.exit_continuation_root != right.entry_continuation_root or
        !std.meta.eql(left.exit_lineage_id, right.entry_lineage_id) or
        std.meta.eql(left.position_id, right.position_id) or
        std.meta.eql(left.segment_wire_id, right.segment_wire_id) or
        !std.meta.eql(children[0].session_id, children[1].session_id) or
        !std.meta.eql(children[0].job_id, children[1].job_id) or
        !std.meta.eql(
            children[0].recursive_parent_vk_id,
            children[1].recursive_parent_vk_id,
        ) or !std.meta.eql(
        children[0].verification_key_id,
        children[1].verification_key_id,
    )) {
        return error.AdjacencyMismatch;
    }
    return recursion.span_statement.SpanStatement.fold(
        try children[0].statement(),
        try children[1].statement(),
    );
}

fn adjacencyIdentity(
    bindings: [CHILD_COUNT]child_authority.SourceBindingV1,
    authority: *const temporal.VerifierAuthorityV2,
    authenticated: *const temporal.RootAuthenticatedTemporalPairV2,
) Digest {
    var hash = IdentityHasher.init(ADJACENCY_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.digest(bindings[0].source_publication_id);
    hash.digest(bindings[1].source_publication_id);
    hash.digest(bindings[0].segment_wire_id);
    hash.digest(bindings[1].segment_wire_id);
    hash.digest(bindings[0].exit_lineage_id);
    hash.addU32(bindings[0].exit_continuation_root);
    hash.addU32(bindings[0].global_cycle_end);
    hash.digest(authority.context.session_id);
    hash.digest(authority.context.job_id);
    hash.digest(authenticated.pair.parent_statement_id);
    return hash.finalize();
}

fn pairAuthorityIdentity(
    value: *const PreparedTemporalPairAuthorityV1,
) Digest {
    const result = &value.prepared_root.result.pair;
    var hash = IdentityHasher.init(PAIR_AUTHORITY_ID_DOMAIN);
    hash.addU32(value.format_version);
    hash.addU32(value.schema_version);
    hash.addU32(value.child_count);
    hash.addU32(@intFromBool(value.parent_proof_available));
    hash.digest(value.source_bindings[0].admission_id);
    hash.digest(value.source_bindings[1].admission_id);
    hash.digest(value.adjacency_id);
    hash.digest(result.context_id);
    hash.digest(result.node_id);
    hash.digest(result.record_id);
    hash.digest(result.aggregator_vk_id);
    hash.digest(result.parent_statement_id);
    return hash.finalize();
}

fn rejectDestinationAliases(
    destination: *PreparedTemporalPairAuthorityV1,
    left: *const PreparedChild,
    right: *const PreparedChild,
    root_pin: *const RootVkPin,
) Error!void {
    const target = std.mem.asBytes(destination);
    if (overlap(target, std.mem.asBytes(left)) or
        overlap(target, std.mem.asBytes(right)) or
        overlap(target, std.mem.asBytes(root_pin)))
    {
        return error.AliasedDestination;
    }
}

fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.PairIdentityMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.PairIdentityMismatch;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *IdentityHasher, value: anytype) void {
        const exact: u32 = @intCast(value);
        std.debug.assert(exact < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(exact)};
        self.inner.update(&words);
    }

    fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.addU32(word);
    }

    fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("temporal pair authority retains a pointer"),
        .optional => |optional| assertPointerFree(optional.child),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (CHILD_COUNT != 2 or FIRST_PARENT_HEIGHT != 1 or
        HEAP_ALLOCATIONS_PER_PREPARATION != 0 or
        HISTORICAL_VALIDATION_HEAP_ALLOCATIONS != 0 or
        ONE_PASS_VALIDATION_HEAP_ALLOCATIONS != 0 or
        HOT_AUTHENTICATION_HEAP_ALLOCATIONS != 0 or
        HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS != 0 or
        HISTORICAL_HOT_SNAPSHOT_EQUALITY_PASSES != 3 or
        HOT_SNAPSHOT_EQUALITY_PASSES != 0 or
        TEMPORAL_ROOT_PREPARATIONS_PER_PAIR != 1 or
        DUPLICATE_POST_PREPARATION_VALIDATIONS != 0 or
        !PREPARED_PAIR_CONTEXT_AMORTIZED or DETACHED_PARENT_CONTEXT_ACCEPTED or
        !AUTHENTICATED_PAIR_AVAILABLE or COMPLETE_PARENT_PROOF_AVAILABLE)
    {
        @compileError("first temporal pair authority ABI drifted");
    }
    if (HISTORICAL_VALIDATION_HASH_INVOCATIONS <=
        ONE_PASS_VALIDATION_HASH_INVOCATIONS or
        HISTORICAL_VALIDATION_SCALAR_POSEIDON_PERMUTATIONS <=
            ONE_PASS_VALIDATION_SCALAR_POSEIDON_PERMUTATIONS)
    {
        @compileError("one-pass temporal pair validation must reduce hash work");
    }
    assertPointerFree(PreparedTemporalPairAuthorityV1);
}

test "first temporal pair uses prepared zero-hash authentication" {
    try std.testing.expect(PREPARED_PAIR_CONTEXT_AMORTIZED);
    try std.testing.expectEqual(
        @as(usize, 0),
        HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS,
    );
    try std.testing.expect(!DETACHED_PARENT_CONTEXT_ACCEPTED);
    try std.testing.expect(!COMPLETE_PARENT_PROOF_AVAILABLE);
}
