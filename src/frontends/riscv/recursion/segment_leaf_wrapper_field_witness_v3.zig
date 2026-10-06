//! Verifier-owned field inputs staged for a future base-RV32 V3 wrapper.
//!
//! The native half begins with the successfully verified SegmentV2 capture,
//! never detached recursive proof bytes. The provider half begins with the
//! freshly verified 39-row outer publication and its retained proof capture.
//! Both halves have canonical fixed-word lookup contributions. No wrapper
//! proof consumes them yet, so production activation remains disabled.

const std = @import("std");
const core = @import("stwo_core");
const program_field = @import("transcript_program_v2_field_authority_v1.zig");
const provider_field = @import("segment_outer_shared_provider_field_authority_v1.zig");
const words_mod = @import("transcript_program_v2_field_word_witness_v1.zig");
const hash_mod = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const lookup_mod = @import("segment_leaf_wrapper_field_lookup_v3.zig");
const word_source = @import("air/transcript_program_v2_field_source_v1.zig");
const leaf_source = @import("air/ethereum_leaf_link_source_v1.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const universal = @import("air/universal_challenges.zig");
const verified = @import("segment_verified_artifact_v2.zig");
const channel = @import("poseidon2_channel.zig");
const native_receipt = @import("../air/statement_v2.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const PROGRAM_SCOPE = word_source.PROGRAM_WORD_SCOPE;
pub const PROVIDER_SCOPE = word_source.PROVIDER_WORD_SCOPE;
pub const TREE0_VERIFIER_ID: u32 = 0;
pub const TREE0_INPUT_KIND: u32 = @import("air/merkle_root_witness.zig").COMMITMENT_INPUT_KIND;
pub const TREE0_ITEM: u32 = 0;
pub const TREE0_WORD_COUNT: usize = 8;

/// Native SegmentV2 child values. `Prepared` is the successful native-verifier
/// preparation owner and validates all captured transcript challenges before
/// its ProgramV2 or commitment root is read.
pub const NativeV1 = struct {
    program: program_field.AuthorityV1,
    program_words: words_mod.WordsV1,
    program_hash: hash_mod.HashV1,
    tree0_root: channel.Digest,

    pub fn initFromPrepared(allocator: std.mem.Allocator, prepared: anytype) !NativeV1 {
        try prepared.validate();
        const root = try nativeTree0(prepared);
        var program = try program_field.AuthorityV1.init(
            allocator,
            &prepared.transcript_program,
            &prepared.vm_plan,
            prepared.pcs_config,
            &prepared.capture.public_data.data,
            prepared.capture.vm_air.component_descs,
            prepared.capture.vm_air.infra_descs,
        );
        errdefer program.deinit();
        var program_words = try words_mod.WordsV1.init(
            allocator,
            program.words,
            PROGRAM_SCOPE,
        );
        errdefer program_words.deinit();
        var program_hash = try hash_mod.HashV1.init(
            allocator,
            program.words,
            program_field.PROGRAM_DOMAIN,
            PROGRAM_SCOPE,
            leaf_source.PROGRAM_AUTHORITY_KIND,
            hash_mod.PROGRAM_STEP_BASE,
            program.digest,
        );
        errdefer program_hash.deinit();
        _ = try lookup_mod.verifyExact(allocator, &program_words, &program_hash);
        return .{
            .program = program,
            .program_words = program_words,
            .program_hash = program_hash,
            .tree0_root = root,
        };
    }

    pub fn deinit(self: *NativeV1) void {
        self.program_hash.deinit();
        self.program_words.deinit();
        self.program.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const NativeV1, prepared: anytype) !void {
        try prepared.validate();
        try self.program.validateAgainst(
            &prepared.transcript_program,
            &prepared.vm_plan,
            prepared.pcs_config,
            &prepared.capture.public_data.data,
            prepared.capture.vm_air.component_descs,
            prepared.capture.vm_air.infra_descs,
        );
        try self.program_words.validateAgainst(self.program.words, PROGRAM_SCOPE);
        try self.program_hash.validateAgainst(
            self.program.words,
            program_field.PROGRAM_DOMAIN,
            PROGRAM_SCOPE,
            leaf_source.PROGRAM_AUTHORITY_KIND,
            hash_mod.PROGRAM_STEP_BASE,
            self.program.digest,
        );
        _ = try lookup_mod.verifyExact(
            self.program.allocator,
            &self.program_words,
            &self.program_hash,
        );
        if (!std.meta.eql(self.tree0_root, try nativeTree0(prepared)))
            return error.Tree0FieldRootMismatch;
    }

    /// Tuple consumed by existing Merkle-root and leaf-child router AIR:
    /// `(segment verifier, commitment kind, tree 0, limb, value)`.
    pub fn tree0VerifierTuple(self: *const NativeV1, limb: usize) ![5]core.fields.m31.M31 {
        if (limb >= TREE0_WORD_COUNT or self.tree0_root[limb] >= core.fields.m31.Modulus)
            return error.Tree0FieldRootMismatch;
        const M31 = core.fields.m31.M31;
        return .{
            M31.fromCanonical(TREE0_VERIFIER_ID),
            M31.fromCanonical(TREE0_INPUT_KIND),
            M31.fromCanonical(TREE0_ITEM),
            M31.fromCanonical(@intCast(limb)),
            M31.fromCanonical(self.tree0_root[limb]),
        };
    }
};

/// Shared provider authority retained by the separate verified 39-row outer
/// transaction. The recursive witness owns all 39 sums, 94 draws, and two
/// ordered Poseidon partials; this source replays them into canonical words.
pub const ProviderV1 = struct {
    authority: provider_field.AuthorityV1,
    words: words_mod.WordsV1,
    hash: hash_mod.HashV1,

    pub fn initFromVerified(
        allocator: std.mem.Allocator,
        capture: *const verified.OuterProofCapture,
        publication: *const verified.Publication,
        witness: *const verified.RecursiveWitnessV1,
        manifest: *const manifest_mod.Manifest,
    ) !ProviderV1 {
        try verified.preflight(capture, publication, witness, manifest);
        var claims = try claimsFromWitness(witness, manifest);
        const relations = universal.UniversalRelations.fromDraws(&witness.relation_draws);
        var authority = try provider_field.AuthorityV1.init(
            allocator,
            manifest,
            &claims,
            &relations,
            witness.poseidon2_partials,
        );
        errdefer authority.deinit();
        var words = try words_mod.WordsV1.init(
            allocator,
            authority.words,
            PROVIDER_SCOPE,
        );
        errdefer words.deinit();
        var hash = try hash_mod.HashV1.init(
            allocator,
            authority.words,
            provider_field.DOMAIN,
            PROVIDER_SCOPE,
            hash_mod.PROVIDER_FIELD_DIGEST_KIND,
            hash_mod.PROVIDER_STEP_BASE,
            authority.digest,
        );
        errdefer hash.deinit();
        _ = try lookup_mod.verifyExact(allocator, &words, &hash);
        return .{ .authority = authority, .words = words, .hash = hash };
    }

    pub fn deinit(self: *ProviderV1) void {
        self.hash.deinit();
        self.words.deinit();
        self.authority.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const ProviderV1,
        capture: *const verified.OuterProofCapture,
        publication: *const verified.Publication,
        witness: *const verified.RecursiveWitnessV1,
        manifest: *const manifest_mod.Manifest,
    ) !void {
        try verified.preflight(capture, publication, witness, manifest);
        var claims = try claimsFromWitness(witness, manifest);
        const relations = universal.UniversalRelations.fromDraws(&witness.relation_draws);
        try self.authority.validateAgainst(
            manifest,
            &claims,
            &relations,
            witness.poseidon2_partials,
        );
        try self.words.validateAgainst(self.authority.words, PROVIDER_SCOPE);
        try self.hash.validateAgainst(
            self.authority.words,
            provider_field.DOMAIN,
            PROVIDER_SCOPE,
            hash_mod.PROVIDER_FIELD_DIGEST_KIND,
            hash_mod.PROVIDER_STEP_BASE,
            self.authority.digest,
        );
        _ = try lookup_mod.verifyExact(
            self.authority.allocator,
            &self.words,
            &self.hash,
        );
    }
};

/// Both independently verified proof transactions must describe the same
/// bounded local V2 leaf before their field witnesses share one V3 wrapper.
pub const BundleV3 = struct {
    native: NativeV1,
    provider: ProviderV1,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: anytype,
        outer_capture: *const verified.OuterProofCapture,
        publication: *const verified.Publication,
        recursive_witness: *const verified.RecursiveWitnessV1,
        manifest: *const manifest_mod.Manifest,
    ) !BundleV3 {
        var native = try NativeV1.initFromPrepared(allocator, prepared);
        errdefer native.deinit();
        var provider = try ProviderV1.initFromVerified(
            allocator,
            outer_capture,
            publication,
            recursive_witness,
            manifest,
        );
        errdefer provider.deinit();
        try requireSameLocalLeaf(&prepared.capture.receipt, publication);
        return .{ .native = native, .provider = provider };
    }

    pub fn deinit(self: *BundleV3) void {
        self.provider.deinit();
        self.native.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const BundleV3,
        prepared: anytype,
        outer_capture: *const verified.OuterProofCapture,
        publication: *const verified.Publication,
        recursive_witness: *const verified.RecursiveWitnessV1,
        manifest: *const manifest_mod.Manifest,
    ) !void {
        try self.native.validateAgainst(prepared);
        try self.provider.validateAgainst(
            outer_capture,
            publication,
            recursive_witness,
            manifest,
        );
        try requireSameLocalLeaf(&prepared.capture.receipt, publication);
    }
};

pub fn requireSameLocalLeaf(
    receipt: *const native_receipt.VerifiedReceipt,
    publication: *const verified.Publication,
) !void {
    if (!std.meta.eql(receipt.wire_id, publication.segment_wire_id) or
        !std.meta.eql(receipt.session_id, publication.session_id) or
        !std.meta.eql(receipt.job_id, publication.job_id) or
        !std.meta.eql(receipt.position_id, publication.position_id) or
        !std.meta.eql(receipt.lineage_id, publication.lineage_id) or
        receipt.segment_index != publication.segment_index or
        receipt.segment_count != publication.segment_count or
        receipt.global_cycle_start != publication.global_cycle_start or
        receipt.global_cycle_end != publication.global_cycle_end)
        return error.NativeOuterLeafMismatch;
}

fn nativeTree0(prepared: anytype) !channel.Digest {
    const captured = prepared.capture.proof.commitments;
    const mirrored = prepared.captured_fri.trace_roots;
    if (captured.len == 0 or mirrored.len == 0 or
        !std.meta.eql(captured[0], mirrored[0]))
        return error.Tree0FieldRootMismatch;
    const root: channel.Digest = captured[0];
    for (root) |word| if (word >= core.fields.m31.Modulus)
        return error.Tree0FieldRootMismatch;
    return root;
}

fn claimsFromWitness(
    witness: *const verified.RecursiveWitnessV1,
    manifest: *const manifest_mod.Manifest,
) !manifest_mod.ClaimVector {
    var claims = try manifest_mod.ClaimVector.init(manifest);
    for (witness.claimed_sums, 0..) |value, index|
        try claims.bind(@enumFromInt(index), value);
    try claims.sealClaims(manifest);
    return claims;
}

test "Tree0 field tuple keeps verifier kind tree index and canonical limb" {
    var source = NativeV1{
        .program = undefined,
        .program_words = undefined,
        .program_hash = undefined,
        .tree0_root = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
    };
    const tuple = try source.tree0VerifierTuple(3);
    try std.testing.expectEqual(@as(u32, 0), tuple[0].toU32());
    try std.testing.expectEqual(TREE0_INPUT_KIND, tuple[1].toU32());
    try std.testing.expectEqual(@as(u32, 0), tuple[2].toU32());
    try std.testing.expectEqual(@as(u32, 3), tuple[3].toU32());
    try std.testing.expectEqual(@as(u32, 4), tuple[4].toU32());
    source.tree0_root[3] = core.fields.m31.Modulus;
    try std.testing.expectError(error.Tree0FieldRootMismatch, source.tree0VerifierTuple(3));
}

test "provider field witness cannot accept an unverified publication" {
    const capture: verified.OuterProofCapture = undefined;
    var publication: verified.Publication = undefined;
    publication.format_version = 0;
    const witness: verified.RecursiveWitnessV1 = undefined;
    const manifest: manifest_mod.Manifest = undefined;
    try std.testing.expectError(
        error.UnsupportedFormat,
        ProviderV1.initFromVerified(
            std.testing.allocator,
            &capture,
            &publication,
            &witness,
            &manifest,
        ),
    );
}

test "native and outer field witnesses reject a different local leaf" {
    var receipt: native_receipt.VerifiedReceipt = undefined;
    var publication: verified.Publication = undefined;
    const digest_value: channel.Digest = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    receipt.wire_id = digest_value;
    receipt.session_id = digest_value;
    receipt.job_id = digest_value;
    receipt.position_id = digest_value;
    receipt.lineage_id = digest_value;
    receipt.segment_index = 1;
    receipt.segment_count = 2;
    receipt.global_cycle_start = 0;
    receipt.global_cycle_end = 5;
    publication.segment_wire_id = digest_value;
    publication.session_id = digest_value;
    publication.job_id = digest_value;
    publication.position_id = digest_value;
    publication.lineage_id = digest_value;
    publication.segment_index = 1;
    publication.segment_count = 2;
    publication.global_cycle_start = 0;
    publication.global_cycle_end = 5;
    try requireSameLocalLeaf(&receipt, &publication);
    publication.global_cycle_end += 1;
    try std.testing.expectError(
        error.NativeOuterLeafMismatch,
        requireSameLocalLeaf(&receipt, &publication),
    );
}
