//! Verifier-bound universal rows 12--15 for a schema-3 role-0 wrapper.
//!
//! The fixed VM claim is encoded directly from the cold stage-101 role-aware
//! public value.  A kind-3 completion is not relabelled as the legacy JAL
//! sentinel: it remains separately constrained by the V4 completion program,
//! while this owner preserves the frozen claim bytes and their exact claim/I/O
//! Poseidon hashes.  Row 15 consumes the same 412-word source statement and
//! both digests, so neither a caller hash nor a second public-data projection
//! can shadow the verified child.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const vm_claim = recursion.vm_public_claim;
const semantics = recursion.vm_public_semantics_circuit;
const claim_input = recursion.air.vm_public_claim_input_witness;
const claim_hash = recursion.air.vm_public_claim_hash_witness;
const io_hash = recursion.air.vm_public_io_hash_witness;
const poseidon_call = frontend.air.memory_commitment.poseidon2_air.Call;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 12;
pub const LAST_ROW: usize = 15;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const CLAIM_CIRCUIT_ID: u32 = recursion.segment_public_outer_source
    .CLAIM_CIRCUIT_ID;
pub const ROWS_12_THROUGH_15_AVAILABLE = true;
pub const LEGACY_COMPLETION_RELABEL_ADMITTED = false;
pub const DIGEST_ONLY_CONSTRUCTION = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-child-public/v4-schema3\x00";
const BINDING_DOMAIN =
    "stwo-zig/common-ethereum-incremental-child-public-binding/v4-schema3\x00";

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalChildPublicMismatchV4,
};

pub const LogSizesV4 = [ROW_COUNT]u32;

/// Pointer-free cross-row receipt. It is descriptive only: construction of
/// the live owner below still requires the verifier-owned campaign capture.
pub const ChildPublicBindingV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    stage101_capability_identity_sha256: [32]u8,
    role_io_identity_sha256: [32]u8,
    field_source_digest: recursion.poseidon2_channel.Digest,
    statement_words_identity_sha256: [32]u8,
    claim_words_identity_sha256: [32]u8,
    claim_digest: vm_claim.Digest,
    claim_hash_output_digest: vm_claim.Digest,
    public_input_digest: vm_claim.Digest,
    public_output_digest: vm_claim.Digest,
    io_hash_output_digests: [2]vm_claim.Digest,
    child_claim_hash_call_count: u32,
    child_io_hash_call_count: u32,
    identity_sha256: [32]u8,

    pub fn validate(self: ChildPublicBindingV4) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.child_claim_hash_call_count == 0 or
            self.child_io_hash_call_count == 0 or
            std.mem.allEqual(
                u8,
                &self.stage101_capability_identity_sha256,
                0,
            ) or std.mem.allEqual(u8, &self.role_io_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.statement_words_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.claim_words_identity_sha256, 0) or
            !std.meta.eql(self.claim_digest, self.claim_hash_output_digest) or
            !std.meta.eql(
                self.io_hash_output_digests,
                [2]vm_claim.Digest{
                    self.public_input_digest,
                    self.public_output_digest,
                },
            ) or !digestCanonical(self.field_source_digest) or
            !digestCanonical(self.claim_digest) or
            !digestCanonical(self.public_input_digest) or
            !digestCanonical(self.public_output_digest) or
            !std.mem.eql(u8, &self.identity_sha256, &bindingIdentity(self)))
        {
            return error.EthereumIncrementalChildPublicMismatchV4;
        }
    }
};

/// Stable heap owner. Row references retain pointers into their preprocessing
/// and graph allocations, so moving an aggregate after construction would be
/// unsound.
pub fn OwnerV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);

    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
        ) !*Self {
            try materialized.validate();
            const public_value = &materialized.base.input.stage101
                .role_aware_public.value;
            const completion = public_value.completion orelse
                return error.EthereumIncrementalChildPublicMismatchV4;
            const shape = try vm_claim.defaultShape();

            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);

            var claim_reference = try semantics.ClaimReference.init(
                allocator,
                shape,
                CLAIM_CIRCUIT_ID,
            );
            var claim_reference_owned = true;
            errdefer if (claim_reference_owned) claim_reference.deinit();
            var claim_hash_preprocessing = try claim_hash.Preprocessed.init(
                allocator,
                &claim_reference.claim_preprocessing,
            );
            var claim_hash_preprocessing_owned = true;
            errdefer if (claim_hash_preprocessing_owned)
                claim_hash_preprocessing.deinit();
            var io_hash_preprocessing = try io_hash.Preprocessed.init(
                allocator,
                &claim_reference.claim_preprocessing,
            );
            var io_hash_preprocessing_owned = true;
            errdefer if (io_hash_preprocessing_owned)
                io_hash_preprocessing.deinit();

            var claim_value = try vm_claim.encodeWithBoundCompletionV4(
                allocator,
                public_value,
                shape,
                completion,
            );
            var claim_owned = true;
            errdefer if (claim_owned) claim_value.deinit();
            var claim_input_main = try claim_input.MainWitness.init(
                allocator,
                &claim_reference.claim_preprocessing,
                .{ .segment_leaf = claim_value.words },
            );
            var claim_input_owned = true;
            errdefer if (claim_input_owned) claim_input_main.deinit();
            var claim_hash_main = try claim_hash.MainWitness.init(
                allocator,
                &claim_hash_preprocessing,
                .{ .segment_leaf = claim_value.words },
            );
            var claim_hash_owned = true;
            errdefer if (claim_hash_owned) claim_hash_main.deinit();
            var io_hash_main = try io_hash.MainWitness.init(
                allocator,
                &io_hash_preprocessing,
                .{ .segment_leaf = claim_value.words },
            );
            var io_hash_owned = true;
            errdefer if (io_hash_owned) io_hash_main.deinit();

            var statement_words: recursion.span_statement.StatementWords =
                undefined;
            for (
                &statement_words,
                materialized.base.input.statement_words,
            ) |*destination, word| destination.* = M31.fromCanonical(word);
            var semantics_prepared = try claim_reference.prepare(
                allocator,
                .{
                    .segment_selected = true,
                    .claim_words = claim_value.words,
                    .statement_words = &statement_words,
                    .input_digest = claim_value.public_input_digest,
                    .output_digest = claim_value.public_output_digest,
                },
            );
            var semantics_prepared_owned = true;
            errdefer if (semantics_prepared_owned) semantics_prepared.deinit();

            backing.* = .{
                .allocator = allocator,
                .materialized = materialized,
                .shape = shape,
                .statement_words = statement_words,
                .claim_reference = claim_reference,
                .claim_hash_preprocessing = claim_hash_preprocessing,
                .io_hash_preprocessing = io_hash_preprocessing,
                .claim = claim_value,
                .claim_input_main = claim_input_main,
                .claim_hash_main = claim_hash_main,
                .io_hash_main = io_hash_main,
                .semantics_prepared = semantics_prepared,
                .binding = undefined,
                .identity_sha256 = undefined,
            };
            claim_reference_owned = false;
            claim_hash_preprocessing_owned = false;
            io_hash_preprocessing_owned = false;
            claim_owned = false;
            claim_input_owned = false;
            claim_hash_owned = false;
            io_hash_owned = false;
            semantics_prepared_owned = false;
            errdefer backing.destroy();
            backing.binding = try bindingFromStorage(backing);
            backing.identity_sha256 = try ownerIdentity(backing);
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn logSizes(self: *const Self) !LogSizesV4 {
            try self.validate();
            const value = storageConst(self);
            return .{
                value.claim_reference.claim_preprocessing.log_size,
                value.claim_hash_preprocessing.log_size,
                value.io_hash_preprocessing.log_size,
                value.claim_reference.row_preprocessing.log_size,
            };
        }

        pub fn claimHashCalls(
            self: *const Self,
        ) ![]const poseidon_call {
            try self.validate();
            return storageConst(self).claim_hash_main.poseidon_calls;
        }

        pub fn ioHashCalls(
            self: *const Self,
        ) ![]const poseidon_call {
            try self.validate();
            return storageConst(self).io_hash_main.poseidon_calls;
        }

        pub fn binding(self: *const Self) !ChildPublicBindingV4 {
            try self.validate();
            return storageConst(self).binding;
        }

        pub fn claimReference(
            self: *const Self,
        ) !*const semantics.ClaimReference {
            try self.validate();
            return &storageConst(self).claim_reference;
        }

        pub fn claimInputMain(
            self: *const Self,
        ) !*const claim_input.MainWitness {
            try self.validate();
            return &storageConst(self).claim_input_main;
        }

        pub fn claimHashMain(
            self: *const Self,
        ) !*const claim_hash.MainWitness {
            try self.validate();
            return &storageConst(self).claim_hash_main;
        }

        pub fn claimHashPreprocessing(
            self: *const Self,
        ) !*const claim_hash.Preprocessed {
            try self.validate();
            return &storageConst(self).claim_hash_preprocessing;
        }

        pub fn ioHashMain(
            self: *const Self,
        ) !*const io_hash.MainWitness {
            try self.validate();
            return &storageConst(self).io_hash_main;
        }

        pub fn ioHashPreprocessing(
            self: *const Self,
        ) !*const io_hash.Preprocessed {
            try self.validate();
            return &storageConst(self).io_hash_preprocessing;
        }

        pub fn semanticsPrepared(
            self: *const Self,
        ) !*const semantics.ClaimPrepared {
            try self.validate();
            return &storageConst(self).semantics_prepared;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            shape: vm_claim.Shape,
            statement_words: recursion.span_statement.StatementWords,
            claim_reference: semantics.ClaimReference,
            claim_hash_preprocessing: claim_hash.Preprocessed,
            io_hash_preprocessing: io_hash.Preprocessed,
            claim: vm_claim.Encoded,
            claim_input_main: claim_input.MainWitness,
            claim_hash_main: claim_hash.MainWitness,
            io_hash_main: io_hash.MainWitness,
            semantics_prepared: semantics.ClaimPrepared,
            binding: ChildPublicBindingV4,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.materialized.validate();
                const public_value = &self.materialized.base.input.stage101
                    .role_aware_public.value;
                const completion = public_value.completion orelse
                    return error.EthereumIncrementalChildPublicMismatchV4;
                try self.claim.validateAgainstBoundCompletionV4(
                    public_value,
                    completion,
                );
                try self.claim_reference.validate();
                try self.claim_hash_preprocessing.validateAgainst(
                    &self.claim_reference.claim_preprocessing,
                );
                try self.io_hash_preprocessing.validateAgainst(
                    &self.claim_reference.claim_preprocessing,
                );
                try self.claim_input_main.validateAgainst(
                    &self.claim_reference.claim_preprocessing,
                );
                try self.claim_hash_main.validateAgainstSource(
                    &self.claim_hash_preprocessing,
                    .{ .segment_leaf = self.claim.words },
                );
                try self.claim_hash_main.validateDigest(
                    &self.claim_hash_preprocessing,
                    self.claim.digest,
                );
                try self.io_hash_main.validateAgainstSource(
                    &self.io_hash_preprocessing,
                    .{ .segment_leaf = self.claim.words },
                );
                try self.io_hash_main.validateDigest(
                    &self.io_hash_preprocessing,
                    .{
                        self.claim.public_input_digest,
                        self.claim.public_output_digest,
                    },
                );
                try self.semantics_prepared.validateAgainst(
                    &self.claim_reference,
                );
                for (
                    self.statement_words,
                    self.materialized.base.input.statement_words,
                ) |felt, word| if (felt.toU32() != word)
                    return error.EthereumIncrementalChildPublicMismatchV4;
                const expected_binding = try bindingFromStorage(self);
                if (!std.meta.eql(self.binding, expected_binding) or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &(try ownerIdentity(self)),
                    ))
                {
                    return error.EthereumIncrementalChildPublicMismatchV4;
                }
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.semantics_prepared.deinit();
                self.io_hash_main.deinit();
                self.claim_hash_main.deinit();
                self.claim_input_main.deinit();
                self.claim.deinit();
                self.io_hash_preprocessing.deinit();
                self.claim_hash_preprocessing.deinit();
                self.claim_reference.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        fn handle(value: *Storage) *Self {
            return @ptrCast(value);
        }

        fn storage(value: *Self) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn storageConst(value: *const Self) *const Storage {
            return @ptrCast(@alignCast(value));
        }
    };
}

fn bindingFromStorage(value: anytype) !ChildPublicBindingV4 {
    var result = ChildPublicBindingV4{
        .stage101_capability_identity_sha256 = value.materialized.base.input.capability_identity_sha256,
        .role_io_identity_sha256 = value.materialized.role_aware_io
            .identity_sha256,
        .field_source_digest = value.materialized.schedule.source.source_digest,
        .statement_words_identity_sha256 = statementWordsIdentity(
            value.materialized.base.input.statement_words,
        ),
        .claim_words_identity_sha256 = value.claim_hash_main
            .claim_words_digest,
        .claim_digest = value.claim.digest,
        .claim_hash_output_digest = value.claim_hash_main.output_digest,
        .public_input_digest = value.claim.public_input_digest,
        .public_output_digest = value.claim.public_output_digest,
        .io_hash_output_digests = value.io_hash_main.output_digests,
        .child_claim_hash_call_count = std.math.cast(
            u32,
            value.claim_hash_main.poseidon_calls.len,
        ) orelse return error.ArithmeticOverflow,
        .child_io_hash_call_count = std.math.cast(
            u32,
            value.io_hash_main.poseidon_calls.len,
        ) orelse return error.ArithmeticOverflow,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = bindingIdentity(result);
    try result.validate();
    return result;
}

fn ownerIdentity(value: anytype) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.materialized.identity_sha256);
    hash.update(&value.binding.identity_sha256);
    hash.update(&value.claim_reference.authority_digest);
    hash.update(&value.claim_hash_preprocessing.authority_digest);
    hash.update(&value.io_hash_preprocessing.authority_digest);
    hash.update(&value.claim_input_main.authority_digest);
    hash.update(&value.claim_hash_main.authority_digest);
    hash.update(&value.io_hash_main.authority_digest);
    hash.update(&value.semantics_prepared.authority_digest);
    return hash.finalResult();
}

fn statementWordsIdentity(words: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/common-ethereum-incremental-child-statement/v4\x00");
    for (words) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn bindingIdentity(value: ChildPublicBindingV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BINDING_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.stage101_capability_identity_sha256);
    hash.update(&value.role_io_identity_sha256);
    hashDigest(&hash, value.field_source_digest);
    hash.update(&value.statement_words_identity_sha256);
    hash.update(&value.claim_words_identity_sha256);
    hashDigest(&hash, value.claim_digest);
    hashDigest(&hash, value.claim_hash_output_digest);
    hashDigest(&hash, value.public_input_digest);
    hashDigest(&hash, value.public_output_digest);
    for (value.io_hash_output_digests) |digest| hashDigest(&hash, digest);
    hashInt(&hash, u32, value.child_claim_hash_call_count);
    hashInt(&hash, u32, value.child_io_hash_call_count);
    return hash.finalResult();
}

fn digestCanonical(value: recursion.poseidon2_channel.Digest) bool {
    for (value) |word| if (word >= m31.Modulus) return false;
    return true;
}

fn hashDigest(hash: anytype, value: recursion.poseidon2_channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

/// Mutation-only facade. It is absent from non-test builds and cannot mint a
/// live row owner or any verifier capability.
pub const testing = if (builtin.is_test) struct {
    pub fn resealBinding(
        value: ChildPublicBindingV4,
    ) ChildPublicBindingV4 {
        var result = value;
        result.identity_sha256 = bindingIdentity(result);
        return result;
    }
} else struct {};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 12 or
        LAST_ROW != 15 or ROW_COUNT != 4 or CLAIM_CIRCUIT_ID != 40 or
        !ROWS_12_THROUGH_15_AVAILABLE or LEGACY_COMPLETION_RELABEL_ADMITTED or
        DIGEST_ONLY_CONSTRUCTION or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental child-public V4 drifted");
    }
}
