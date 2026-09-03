//! Exact structural witness for one freshly verified full-Ethereum leaf.
//!
//! This module does not admit transport custody.  Construction borrows the
//! live `VerifiedPoseidonV4` capture already revalidated by `FreshIngressV1`,
//! rebuilds the fixed link program and dynamic child-field program, and emits
//! the four parameter-distinct hash lanes consumed by the compact h1 wrapper.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const ingress_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");

const recursion = frontend.recursion;
const link_program_mod = recursion.ethereum_leaf_link_program_v1;
const child_program_mod = recursion.ethereum_leaf_child_field_program_v1;
const child_witness_mod = recursion.ethereum_leaf_child_field_witness_v1;
const leaf_v2 = recursion.segment_leaf_authority_v2;
const source_air = recursion.air.ethereum_leaf_link_source_v1;
const projection_air = recursion.air.ethereum_leaf_link_projection_v1;
const router_air = recursion.air.ethereum_leaf_child_field_router_v1;
const hash_air = recursion.air.vm_public_claim_hash;
const hash_witness = recursion.air.vm_public_claim_hash_witness;
const channel = recursion.poseidon2_channel;
const public_data_v2 = frontend.air.public_data_v2;
const statement_v1 = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;

const M31 = stwo_core.fields.m31.M31;
pub const HashRow = [hash_air.LOGICAL_INPUT_COUNT]M31;

/// Minimal borrowed algebraic view required by the wrapper rows.  Freshness
/// is deliberately established by the caller's verifier-minted ingress
/// authority, not by this pointer bundle.  Both the default V4 verifier and a
/// future projected-candidate verifier can expose this same exact view after
/// their distinct cold verification succeeds.
pub const FreshCaptureViewV1 = struct {
    public_data: *const public_data_v2.PublicDataV2,
    receipt: *const statement_v2.VerifiedReceipt,
    tree0_root: channel.Digest,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
};

pub const HashLaneV1 = struct {
    logical_rows: []HashRow,
    poseidon_calls: []hash_witness.PoseidonCall,

    fn deinit(self: *HashLaneV1, allocator: std.mem.Allocator) void {
        allocator.free(self.poseidon_calls);
        allocator.free(self.logical_rows);
        self.* = undefined;
    }
};

pub const WitnessV1 = struct {
    allocator: std.mem.Allocator,
    child_program: child_program_mod.ProgramV1,
    child_witness: child_witness_mod.WitnessV1,
    keys: leaf_v2.VerifierKeyAuthorityV2,
    manifest: leaf_v2.ManifestV2,
    context: leaf_v2.NativeTemporalContextV2,
    source_rows: []source_air.Row,
    projection_rows: []projection_air.Row,
    child_router_rows: []router_air.Row,
    metadata_hash: HashLaneV1,
    link_hash: HashLaneV1,
    authority_hash: []HashRow,
    receipt_hash: []HashRow,

    pub fn init(
        allocator: std.mem.Allocator,
        link_program: *const link_program_mod.ProgramV1,
        input: ingress_mod.FreshLeafInputV1,
        authority: *const ingress_mod.LeafAuthorityV1,
        h1_profile: *const ingress_mod.H1ProfileBindingV1,
    ) !WitnessV1 {
        try link_program.validate();
        try input.verified.validateAgainst(input.source);
        return initFromFreshCapture(
            allocator,
            link_program,
            captureViewFromDefault(input),
            authority,
            h1_profile,
        );
    }

    /// Shared materialization core.  It cannot mint ingress freshness and is
    /// safe to reuse only after a concrete verifier capability has admitted
    /// the supplied view and the matching pointer-free leaf authority.
    pub fn initFromFreshCapture(
        allocator: std.mem.Allocator,
        link_program: *const link_program_mod.ProgramV1,
        capture: FreshCaptureViewV1,
        authority: *const ingress_mod.LeafAuthorityV1,
        h1_profile: *const ingress_mod.H1ProfileBindingV1,
    ) !WitnessV1 {
        try link_program.validate();
        try authority.validate();
        try h1_profile.validate();
        var child_program = try child_program_mod.ProgramV1.init(
            allocator,
            capture.component_descs,
            capture.infra_descs,
        );
        errdefer child_program.deinit();

        const manifest = try leaf_v2.ManifestV2.init(
            capture.public_data.words().len,
        );
        // The verifier-program authority is the exact dynamic leaf verifier
        // key; the h1 profile's verification key is the key selected for this
        // leaf's immediate recursive parent.
        const keys = try leaf_v2.VerifierKeyAuthorityV2.init(
            authority.vm_field_authority.verifier_program_authority,
            h1_profile.verification_key_id,
        );
        const metadata = try capture.public_data.metadata();
        const context = try leaf_v2.nativeContext(&metadata, &keys, &manifest);
        var child_witness = try child_witness_mod.WitnessV1.init(
            allocator,
            &child_program,
            .{
                .public_data = capture.public_data,
                .context = &context,
                .receipt = capture.receipt,
                .tree0_root = capture.tree0_root,
                .component_descs = capture.component_descs,
                .infra_descs = capture.infra_descs,
            },
        );
        errdefer child_witness.deinit();

        const source_rows = try materializeSourceRows(
            allocator,
            link_program,
            authority,
        );
        errdefer allocator.free(source_rows);
        const projection_rows = try materializeProjectionRows(
            allocator,
            link_program,
            authority,
        );
        errdefer allocator.free(projection_rows);
        const child_router_rows = try allocator.dupe(
            router_air.Row,
            child_witness.router_rows,
        );
        errdefer allocator.free(child_router_rows);

        const metadata_digest = channel.hashCanonicalWords(
            &authority.metadata_words,
            recursion.segment_leaf_local_authority_v3.METADATA_ID_DOMAIN,
        );
        const link_digest = channel.hashCanonicalWords(
            &authority.verified_link_words,
            recursion.segment_leaf_local_verified_link_v3.IDENTITY_DOMAIN,
        );
        var metadata_hash = try materializeHashLane(
            allocator,
            &link_program.metadata_hash,
            &authority.metadata_words,
            metadata_digest,
        );
        errdefer metadata_hash.deinit(allocator);
        var link_hash = try materializeHashLane(
            allocator,
            &link_program.link_hash,
            &authority.verified_link_words,
            link_digest,
        );
        errdefer link_hash.deinit(allocator);

        const authority_hash = try allocator.alloc(
            HashRow,
            child_program.authority_hash.rows.len,
        );
        errdefer allocator.free(authority_hash);
        for (authority_hash, 0..) |*row, index|
            row.* = try child_witness.authorityHashLogicalRow(
                &child_program,
                index,
            );
        const receipt_hash = try allocator.alloc(
            HashRow,
            child_program.receipt_hash.rows.len,
        );
        errdefer allocator.free(receipt_hash);
        for (receipt_hash, 0..) |*row, index|
            row.* = try child_witness.receiptHashLogicalRow(
                &child_program,
                index,
            );

        return .{
            .allocator = allocator,
            .child_program = child_program,
            .child_witness = child_witness,
            .keys = keys,
            .manifest = manifest,
            .context = context,
            .source_rows = source_rows,
            .projection_rows = projection_rows,
            .child_router_rows = child_router_rows,
            .metadata_hash = metadata_hash,
            .link_hash = link_hash,
            .authority_hash = authority_hash,
            .receipt_hash = receipt_hash,
        };
    }

    pub fn deinit(self: *WitnessV1) void {
        self.allocator.free(self.receipt_hash);
        self.allocator.free(self.authority_hash);
        self.link_hash.deinit(self.allocator);
        self.metadata_hash.deinit(self.allocator);
        self.allocator.free(self.child_router_rows);
        self.allocator.free(self.projection_rows);
        self.allocator.free(self.source_rows);
        self.child_witness.deinit();
        self.child_program.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const WitnessV1,
        link_program: *const link_program_mod.ProgramV1,
        input: ingress_mod.FreshLeafInputV1,
        authority: *const ingress_mod.LeafAuthorityV1,
        h1_profile: *const ingress_mod.H1ProfileBindingV1,
    ) !void {
        try input.verified.validateAgainst(input.source);
        return self.validateAgainstFreshCapture(
            link_program,
            captureViewFromDefault(input),
            authority,
            h1_profile,
        );
    }

    pub fn validateAgainstFreshCapture(
        self: *const WitnessV1,
        link_program: *const link_program_mod.ProgramV1,
        capture: FreshCaptureViewV1,
        authority: *const ingress_mod.LeafAuthorityV1,
        h1_profile: *const ingress_mod.H1ProfileBindingV1,
    ) !void {
        try authority.validate();
        try h1_profile.validate();
        try self.keys.validate();
        try self.manifest.validate();
        const metadata = try capture.public_data.metadata();
        try self.context.validate(&metadata, &self.keys, &self.manifest);
        try self.child_program.validateAgainst(
            capture.component_descs,
            capture.infra_descs,
        );
        try self.child_witness.validateAgainst(&self.child_program, .{
            .public_data = capture.public_data,
            .context = &self.context,
            .receipt = capture.receipt,
            .tree0_root = capture.tree0_root,
            .component_descs = capture.component_descs,
            .infra_descs = capture.infra_descs,
        });
        var expected = try WitnessV1.initFromFreshCapture(
            self.allocator,
            link_program,
            capture,
            authority,
            h1_profile,
        );
        defer expected.deinit();
        if (!rowsEqual(source_air.Row, self.source_rows, expected.source_rows) or
            !rowsEqual(
                projection_air.Row,
                self.projection_rows,
                expected.projection_rows,
            ) or !rowsEqual(
            router_air.Row,
            self.child_router_rows,
            expected.child_router_rows,
        ) or !hashLaneEqual(&self.metadata_hash, &expected.metadata_hash) or
            !hashLaneEqual(&self.link_hash, &expected.link_hash) or
            !rowsEqual(HashRow, self.authority_hash, expected.authority_hash) or
            !rowsEqual(HashRow, self.receipt_hash, expected.receipt_hash))
        {
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        }
    }

    pub fn appendPoseidonCallsInto(
        self: *const WitnessV1,
        destination: []hash_witness.PoseidonCall,
    ) !void {
        const expected = self.poseidonCallCount();
        if (destination.len != expected)
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        var at: usize = 0;
        inline for (.{
            self.metadata_hash.poseidon_calls,
            self.link_hash.poseidon_calls,
            self.child_witness.authority_hash.poseidon_calls,
            self.child_witness.receipt_hash.poseidon_calls,
        }) |calls| {
            @memcpy(destination[at..][0..calls.len], calls);
            at += calls.len;
        }
        std.debug.assert(at == destination.len);
    }

    pub fn poseidonCallCount(self: *const WitnessV1) usize {
        return self.metadata_hash.poseidon_calls.len +
            self.link_hash.poseidon_calls.len +
            self.child_witness.authority_hash.poseidon_calls.len +
            self.child_witness.receipt_hash.poseidon_calls.len;
    }
};

pub fn captureViewFromDefault(
    input: ingress_mod.FreshLeafInputV1,
) FreshCaptureViewV1 {
    const capture = &input.verified.capture;
    const core_statement = &capture.core_statement.core;
    return .{
        .public_data = &capture.base.public_data.data,
        .receipt = &capture.base.receipt,
        .tree0_root = capture.base.proof.commitments[0],
        .component_descs = core_statement.component_descs[0..@as(
            usize,
            @intCast(core_statement.n_components),
        )],
        .infra_descs = core_statement.infra_descs[0..@as(
            usize,
            @intCast(core_statement.n_infra),
        )],
    };
}

fn materializeSourceRows(
    allocator: std.mem.Allocator,
    program: *const link_program_mod.ProgramV1,
    authority: *const ingress_mod.LeafAuthorityV1,
) ![]source_air.Row {
    const result = try allocator.alloc(source_air.Row, program.source_rows.len);
    errdefer allocator.free(result);
    for (program.source_rows, result) |schedule, *row|
        row.* = schedule.logical(try sourceValue(schedule, authority));
    return result;
}

fn materializeProjectionRows(
    allocator: std.mem.Allocator,
    program: *const link_program_mod.ProgramV1,
    authority: *const ingress_mod.LeafAuthorityV1,
) ![]projection_air.Row {
    const result = try allocator.alloc(
        projection_air.Row,
        program.projection_rows.len,
    );
    errdefer allocator.free(result);
    for (program.projection_rows, result) |schedule, *row|
        row.* = schedule.logical(try projectionValue(schedule, authority));
    return result;
}

fn sourceValue(
    row: link_program_mod.SourceScheduleRowV1,
    authority: *const ingress_mod.LeafAuthorityV1,
) !M31 {
    if (row.raw_mask == 1) return rawWord(authority, row.scope, row.index_0);
    if (row.transcript_mask == 1) {
        if (row.kind != source_air.TRANSCRIPT_CLAIM_KIND or
            row.index_0 >= authority.transcript_claimed_sums.len or
            row.index_1 >= 4)
        {
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        }
        return authority.transcript_claimed_sums[@intCast(row.index_0)]
            .toM31Array()[@intCast(row.index_1)];
    }
    if (row.verifier_mask == 1) {
        const digest = if (row.kind == source_air.METADATA_DIGEST_KIND)
            channel.hashCanonicalWords(
                &authority.metadata_words,
                recursion.segment_leaf_local_authority_v3.METADATA_ID_DOMAIN,
            )
        else if (row.kind == source_air.LINK_DIGEST_KIND)
            channel.hashCanonicalWords(
                &authority.verified_link_words,
                recursion.segment_leaf_local_verified_link_v3.IDENTITY_DOMAIN,
            )
        else
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        if (row.index_0 != 0 or row.index_1 >= digest.len)
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        return M31.fromCanonical(digest[@intCast(row.index_1)]);
    }
    return error.EthereumPoseidonH1LeafWitnessMismatch;
}

fn projectionValue(
    row: link_program_mod.ProjectionScheduleRowV1,
    authority: *const ingress_mod.LeafAuthorityV1,
) !M31 {
    if (row.raw_mask == 1)
        return rawWord(authority, row.raw_scope, row.raw_index);
    if (row.constant_source_mask == 1)
        return M31.fromCanonical(row.expected);
    if (row.verifier_mask == 1) {
        const digest_index = publicDigestIndex(row.verifier_kind) orelse
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        if (row.verifier_index_0 != 0 or row.verifier_index_1 >= 8)
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        return M31.fromCanonical(
            authority.public_authority_digests[digest_index][
                @intCast(
                    row.verifier_index_1,
                )
            ],
        );
    }
    return error.EthereumPoseidonH1LeafWitnessMismatch;
}

fn rawWord(
    authority: *const ingress_mod.LeafAuthorityV1,
    scope: u32,
    raw_index: u32,
) !M31 {
    const index: usize = raw_index;
    if (scope == source_air.METADATA_SCOPE) {
        if (index >= authority.metadata_words.len)
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        return authority.metadata_words[index];
    }
    if (scope == source_air.LINK_SCOPE) {
        if (index >= authority.verified_link_words.len)
            return error.EthereumPoseidonH1LeafWitnessMismatch;
        return authority.verified_link_words[index];
    }
    return error.EthereumPoseidonH1LeafWitnessMismatch;
}

fn publicDigestIndex(kind: u32) ?usize {
    return switch (kind) {
        source_air.LINK_DIGEST_KIND => 0,
        source_air.PROGRAM_AUTHORITY_KIND => 1,
        source_air.PREPROCESSED_ROOT_KIND => 2,
        source_air.PROVIDER_RELATION_CONTEXT_KIND => 3,
        source_air.PROVIDER_CORE_CLAIM_KIND => 4,
        source_air.PROVIDER_MANIFEST_KIND => 5,
        source_air.PROVIDER_CANCELLATION_KIND => 6,
        else => null,
    };
}

fn materializeHashLane(
    allocator: std.mem.Allocator,
    schedule: *const link_program_mod.HashScheduleV1,
    words: []const M31,
    expected_digest: channel.Digest,
) !HashLaneV1 {
    if (words.len != schedule.word_count)
        return error.EthereumPoseidonH1LeafWitnessMismatch;
    const logical = try allocator.alloc(HashRow, schedule.rows.len);
    errdefer allocator.free(logical);
    const calls = try allocator.alloc(
        hash_witness.PoseidonCall,
        schedule.rows.len,
    );
    errdefer allocator.free(calls);
    var state = [_]M31{M31.zero()} ** hash_witness.STATE_WIDTH;
    state[hash_witness.STATE_WIDTH - 1] = M31.fromCanonical(schedule.domain);
    for (schedule.rows, logical, calls) |preprocessed, *row, *call| {
        const main = hash_witness.materialize(preprocessed, words, state);
        row.* = main.values() ++ preprocessed.values() ++ .{
            M31.one(),
            M31.fromCanonical(schedule.domain),
            M31.fromCanonical(schedule.scope),
            M31.fromCanonical(source_air.VERIFIER_ID),
            M31.fromCanonical(schedule.digest_kind),
        };
        call.* = hash_witness.callFor(main);
        state = main.output;
    }
    for (expected_digest, state[0..8]) |expected, actual|
        if (actual.toU32() != expected)
            return error.EthereumPoseidonH1LeafWitnessMismatch;
    return .{ .logical_rows = logical, .poseidon_calls = calls };
}

fn rowsEqual(comptime T: type, left: []const T, right: []const T) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!std.meta.eql(lhs, rhs)) return false;
    return true;
}

fn hashLaneEqual(left: *const HashLaneV1, right: *const HashLaneV1) bool {
    return rowsEqual(HashRow, left.logical_rows, right.logical_rows) and
        rowsEqual(
            hash_witness.PoseidonCall,
            left.poseidon_calls,
            right.poseidon_calls,
        );
}
