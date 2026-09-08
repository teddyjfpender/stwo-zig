//! Verifier-bound universal rows 12--15 under schema-4 child-public admission.
//!
//! The fixed VM claim is encoded directly from the cold stage-101 role-aware
//! public value.  A kind-3 completion is not relabelled as the legacy JAL
//! sentinel: it remains separately constrained by the V4 completion program,
//! while this owner preserves the frozen claim bytes and their exact I/O
//! Poseidon hashes. The legacy claim digest has no native Ethereum transcript
//! endpoint, so its redundant hash rows are absent. Row 15 consumes the same
//! 412-word source statement and both I/O digests; no second public projection
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
const io_hash = recursion.air.vm_public_io_hash_witness;
const poseidon_call = frontend.air.memory_commitment.poseidon2_air.Call;
const public_data = frontend.air.public_data;
const SOURCE_STATEMENT_WORD_COUNT = @import("recursive_common_ethereum_incremental_leaf_input_v4.zig").STATEMENT_WORD_COUNT;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 4;
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
    "stwo-zig/common-ethereum-incremental-child-public/v4-schema4\x00";
const BINDING_DOMAIN =
    "stwo-zig/common-ethereum-incremental-child-public-binding/v4-schema4\x00";

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
    public_input_digest: vm_claim.Digest,
    public_output_digest: vm_claim.Digest,
    io_hash_output_digests: [2]vm_claim.Digest,
    child_io_hash_call_count: u32,
    identity_sha256: [32]u8,

    pub fn validate(self: ChildPublicBindingV4) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.child_io_hash_call_count == 0 or
            std.mem.allEqual(
                u8,
                &self.stage101_capability_identity_sha256,
                0,
            ) or std.mem.allEqual(u8, &self.role_io_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.statement_words_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.claim_words_identity_sha256, 0) or
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

// Actual source expectations, privately retained by the opaque child owner.
// The only slices in this projection are PublicData's two I/O word arrays;
// SourceSnapshot deep-copies both before any local preparation is published.
const SourceValues = struct {
    materialized_identity: [32]u8,
    capability_identity: [32]u8,
    role_io_identity: [32]u8,
    field_source_digest: recursion.poseidon2_channel.Digest,
    statement_words: [SOURCE_STATEMENT_WORD_COUNT]u32,
    public_value: public_data.PublicData,
    shape: vm_claim.Shape,
    native_roots: bool,
    initial_inputs: bool,

    fn fromMaterialized(materialized: anytype, shape: vm_claim.Shape) SourceValues {
        return .{
            .materialized_identity = materialized.identity_sha256,
            .capability_identity = materialized.base.input.capability_identity_sha256,
            .role_io_identity = materialized.role_aware_io.identity_sha256,
            .field_source_digest = materialized.schedule.source.source_digest,
            .statement_words = materialized.base.input.statement_words,
            .public_value = materialized.base.input.stage101.role_aware_public.value,
            .shape = shape,
            .native_roots = materialized.base.input.stage101.profile.usesFieldTranscript(),
            .initial_inputs = materialized.initial_input_admission != null,
        };
    }
};

const SourceSnapshot = struct {
    allocator: std.mem.Allocator,
    values: SourceValues,

    fn init(allocator: std.mem.Allocator, values: SourceValues) !SourceSnapshot {
        const inputs = try allocator.dupe(u32, values.public_value.io_entries.input_words);
        errdefer allocator.free(inputs);
        const outputs = try allocator.dupe(public_data.OutputWord, values.public_value.io_entries.output_words);
        var result = SourceSnapshot{ .allocator = allocator, .values = values };
        result.values.public_value.io_entries.input_words = inputs;
        result.values.public_value.io_entries.output_words = outputs;
        return result;
    }

    fn deinit(self: *SourceSnapshot) void {
        self.allocator.free(self.values.public_value.io_entries.output_words);
        self.allocator.free(self.values.public_value.io_entries.input_words);
        self.* = undefined;
    }

    fn validateAgainst(self: *const SourceSnapshot, candidate: SourceValues) !void {
        // Compare contents, not slice addresses. The zeroed slice fields leave
        // every remaining public scalar and admission value in the comparison.
        var expected = self.values;
        var actual = candidate;
        const expected_io = expected.public_value.io_entries;
        const actual_io = actual.public_value.io_entries;
        expected.public_value.io_entries.input_words = &.{};
        expected.public_value.io_entries.output_words = &.{};
        actual.public_value.io_entries.input_words = &.{};
        actual.public_value.io_entries.output_words = &.{};
        if (!std.meta.eql(expected, actual) or
            !std.mem.eql(u32, expected_io.input_words, actual_io.input_words) or
            expected_io.output_words.len != actual_io.output_words.len)
            return error.EthereumIncrementalChildPublicMismatchV4;
        for (expected_io.output_words, actual_io.output_words) |left, right|
            if (!std.meta.eql(left, right)) return error.EthereumIncrementalChildPublicMismatchV4;
    }
};

fn assertPointerFreeSourceField(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .error_union => @compileError("child-public source snapshot contains unowned dynamic state: " ++ @typeName(T)),
        .optional => |optional| assertPointerFreeSourceField(optional.child),
        .array => |array| assertPointerFreeSourceField(array.child),
        .vector => |vector| assertPointerFreeSourceField(vector.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFreeSourceField(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFreeSourceField(field.type),
        else => {},
    }
}

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
            const shape = try materialized.claimShape();
            var source = try SourceSnapshot.init(allocator, SourceValues.fromMaterialized(materialized, shape));
            var source_owned = true;
            errdefer if (source_owned) source.deinit();
            const public_value = &source.values.public_value;
            const completion = public_value.completion orelse
                return error.EthereumIncrementalChildPublicMismatchV4;

            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);

            const native_roots = source.values.native_roots;
            var claim_reference = if (source.values.initial_inputs)
                try semantics.ClaimReference.initForEthereumInitialInputs(allocator, shape, CLAIM_CIRCUIT_ID)
            else if (native_roots)
                try semantics.ClaimReference.initForEthereumNativeRoots(allocator, shape, CLAIM_CIRCUIT_ID)
            else
                try semantics.ClaimReference.initForSegmentV2(allocator, shape, CLAIM_CIRCUIT_ID);
            var claim_reference_owned = true;
            errdefer if (claim_reference_owned) claim_reference.deinit();
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
                source.values.statement_words,
            ) |*destination, word| destination.* = M31.fromCanonical(word);
            var semantics_prepared = try claim_reference.prepare(
                allocator,
                .{
                    .segment_selected = true,
                    .claim_words = claim_value.words,
                    .statement_words = &statement_words,
                    .input_digest = claim_value.public_input_digest,
                    .output_digest = claim_value.public_output_digest,
                    .native_continuation_roots = if (native_roots) .{
                        M31.fromCanonical(public_value.initial_rw_root orelse return error.EthereumIncrementalChildPublicMismatchV4),
                        M31.fromCanonical(public_value.final_rw_root orelse return error.EthereumIncrementalChildPublicMismatchV4),
                    } else null,
                },
            );
            var semantics_prepared_owned = true;
            errdefer if (semantics_prepared_owned) semantics_prepared.deinit();

            backing.* = .{
                .allocator = allocator,
                .materialized = materialized,
                .source = source,
                .shape = shape,
                .statement_words = statement_words,
                .claim_reference = claim_reference,
                .io_hash_preprocessing = io_hash_preprocessing,
                .claim = claim_value,
                .claim_input_main = claim_input_main,
                .io_hash_main = io_hash_main,
                .semantics_prepared = semantics_prepared,
                .binding = undefined,
                .identity_sha256 = undefined,
            };
            source_owned = false;
            claim_reference_owned = false;
            io_hash_preprocessing_owned = false;
            claim_owned = false;
            claim_input_owned = false;
            io_hash_owned = false;
            semantics_prepared_owned = false;
            // Outer errdefer owns the Storage allocation; this owns contents.
            errdefer backing.destroyContents();
            backing.binding = try bindingFromStorage(backing);
            backing.identity_sha256 = try ownerIdentity(backing);
            try backing.validatePreparedData();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn logSizes(self: *const Self) !LogSizesV4 {
            try storageConst(self).validatePreparedData();
            const value = storageConst(self);
            return .{
                value.claim_reference.claim_preprocessing.log_size,
                0, // Row 13 is sized by the five publication hashes in the parent owner.
                value.io_hash_preprocessing.log_size,
                value.claim_reference.row_preprocessing.log_size,
            };
        }

        pub fn ioHashCalls(
            self: *const Self,
        ) ![]const poseidon_call {
            try storageConst(self).validatePreparedData();
            return storageConst(self).io_hash_main.poseidon_calls;
        }

        /// Value-only construction admission; full source acceptance is validate().
        pub fn binding(self: *const Self) !ChildPublicBindingV4 {
            return storageConst(self).binding;
        }

        pub fn claimReference(
            self: *const Self,
        ) !*const semantics.ClaimReference {
            try storageConst(self).validatePreparedData();
            return &storageConst(self).claim_reference;
        }

        pub fn claimInputMain(
            self: *const Self,
        ) !*const claim_input.MainWitness {
            try storageConst(self).validatePreparedData();
            return &storageConst(self).claim_input_main;
        }

        pub fn ioHashMain(
            self: *const Self,
        ) !*const io_hash.MainWitness {
            try storageConst(self).validatePreparedData();
            return &storageConst(self).io_hash_main;
        }

        pub fn ioHashPreprocessing(
            self: *const Self,
        ) !*const io_hash.Preprocessed {
            try storageConst(self).validatePreparedData();
            return &storageConst(self).io_hash_preprocessing;
        }

        pub fn semanticsPrepared(
            self: *const Self,
        ) !*const semantics.ClaimPrepared {
            try storageConst(self).validatePreparedData();
            return &storageConst(self).semantics_prepared;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            source: SourceSnapshot,
            shape: vm_claim.Shape,
            statement_words: recursion.span_statement.StatementWords,
            claim_reference: semantics.ClaimReference,
            io_hash_preprocessing: io_hash.Preprocessed,
            claim: vm_claim.Encoded,
            claim_input_main: claim_input.MainWitness,
            io_hash_main: io_hash.MainWitness,
            semantics_prepared: semantics.ClaimPrepared,
            binding: ChildPublicBindingV4,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.materialized.validate();
                try self.source.validateAgainst(SourceValues.fromMaterialized(self.materialized, try self.materialized.claimShape()));
                try self.validatePreparedData();
            }

            // Mutable witness views can escape through legacy typed getters.
            // Recheck those witnesses against our private source values; reads
            // never reinterpret changed caller input as a new admission.
            fn validatePreparedData(self: *const Storage) !void {
                const public_value = &self.source.values.public_value;
                const completion = public_value.completion orelse
                    return error.EthereumIncrementalChildPublicMismatchV4;
                try self.claim.validateAgainstBoundCompletionV4(
                    public_value,
                    completion,
                );
                try self.claim_reference.validate();
                try self.io_hash_preprocessing.validateAgainst(
                    &self.claim_reference.claim_preprocessing,
                );
                try self.claim_input_main.validateAgainst(
                    &self.claim_reference.claim_preprocessing,
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
                    self.source.values.statement_words,
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

            fn destroyContents(self: *Storage) void {
                self.semantics_prepared.deinit();
                self.io_hash_main.deinit();
                self.claim_input_main.deinit();
                self.claim.deinit();
                self.io_hash_preprocessing.deinit();
                self.claim_reference.deinit();
                self.source.deinit();
                self.* = undefined;
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.destroyContents();
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
        .stage101_capability_identity_sha256 = value.source.values.capability_identity,
        .role_io_identity_sha256 = value.source.values.role_io_identity,
        .field_source_digest = value.source.values.field_source_digest,
        .statement_words_identity_sha256 = statementWordsIdentity(
            value.source.values.statement_words,
        ),
        .claim_words_identity_sha256 = claimWordsIdentity(value.claim.words),
        .claim_digest = value.claim.digest,
        .public_input_digest = value.claim.public_input_digest,
        .public_output_digest = value.claim.public_output_digest,
        .io_hash_output_digests = value.io_hash_main.output_digests,
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
    hash.update(&value.source.values.materialized_identity);
    hash.update(&value.binding.identity_sha256);
    hash.update(&value.claim_reference.authority_digest);
    hash.update(&value.io_hash_preprocessing.authority_digest);
    hash.update(&value.claim_input_main.authority_digest);
    hash.update(&value.io_hash_main.authority_digest);
    hash.update(&value.semantics_prepared.authority_digest);
    return hash.finalResult();
}

fn claimWordsIdentity(words: []const M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum-child-claim-words/v4-schema4\x00");
    for (words) |word| hashInt(&hash, u32, word.toU32());
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
    hashDigest(&hash, value.public_input_digest);
    hashDigest(&hash, value.public_output_digest);
    for (value.io_hash_output_digests) |digest| hashDigest(&hash, digest);
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
    /// Exercises the exact deep-copy/check/free implementation without
    /// constructing a native proof or minting a child-public owner.
    pub fn exerciseSourceSnapshot(allocator: std.mem.Allocator) !void {
        var input_words = [_]u32{ 17, 29 };
        var output_words = [_]public_data.OutputWord{
            .{ .addr = 4096, .value = 4, .clock = 1 },
            .{ .addr = 4100, .value = 43, .clock = 2 },
        };
        const original_inputs = input_words;
        const original_outputs = output_words;
        const source = SourceValues{
            .materialized_identity = @splat(1),
            .capability_identity = @splat(2),
            .role_io_identity = @splat(3),
            .field_source_digest = @splat(4),
            .statement_words = @splat(5),
            .public_value = .{
                .initial_pc = 0,
                .final_pc = 4,
                .clock = 2,
                .initial_regs = @splat(0),
                .final_regs = @splat(0),
                .reg_last_clock = @splat(0),
                .program_root = 7,
                .initial_rw_root = 11,
                .final_rw_root = 13,
                .completion = public_data.Completion.unretiredProgramFetch(4, 19),
                .io_entries = .{
                    .input_start = 8192,
                    .input_len = 8,
                    .input_words = &input_words,
                    .output_len = 4,
                    .output_len_addr = 4096,
                    .output_data_addr = 4100,
                    .output_words = &output_words,
                },
            },
            .shape = try vm_claim.defaultShape(),
            .native_roots = true,
            .initial_inputs = false,
        };
        var snapshot = try SourceSnapshot.init(allocator, source);
        defer snapshot.deinit();
        try snapshot.validateAgainst(source);
        try std.testing.expect(snapshot.values.public_value.io_entries.input_words.ptr != source.public_value.io_entries.input_words.ptr);
        try std.testing.expect(snapshot.values.public_value.io_entries.output_words.ptr != source.public_value.io_entries.output_words.ptr);
        input_words[0] += 1;
        try std.testing.expectError(error.EthereumIncrementalChildPublicMismatchV4, snapshot.validateAgainst(source));
        try std.testing.expectEqualSlices(u32, &original_inputs, snapshot.values.public_value.io_entries.input_words);
        input_words = original_inputs;
        output_words[1].clock += 1;
        try std.testing.expectError(error.EthereumIncrementalChildPublicMismatchV4, snapshot.validateAgainst(source));
        try std.testing.expectEqualDeep(original_outputs[1], snapshot.values.public_value.io_entries.output_words[1]);
        output_words = original_outputs;
        var changed = source;
        changed.public_value.final_regs[3] += 1;
        try std.testing.expectError(error.EthereumIncrementalChildPublicMismatchV4, snapshot.validateAgainst(changed));
        changed = source;
        changed.public_value.completion.?.value += 1;
        try std.testing.expectError(error.EthereumIncrementalChildPublicMismatchV4, snapshot.validateAgainst(changed));
        changed = source;
        changed.statement_words[10] += 1;
        try std.testing.expectError(error.EthereumIncrementalChildPublicMismatchV4, snapshot.validateAgainst(changed));
        changed = source;
        changed.materialized_identity[0] ^= 1;
        try std.testing.expectError(error.EthereumIncrementalChildPublicMismatchV4, snapshot.validateAgainst(changed));
        changed = source;
        changed.initial_inputs = true;
        try std.testing.expectError(error.EthereumIncrementalChildPublicMismatchV4, snapshot.validateAgainst(changed));
        changed = source;
        changed.public_value.io_entries.input_words = &original_inputs;
        changed.public_value.io_entries.output_words = &original_outputs;
        try snapshot.validateAgainst(changed); // Equal values, different owners.
    }

    pub fn resealBinding(
        value: ChildPublicBindingV4,
    ) ChildPublicBindingV4 {
        var result = value;
        result.identity_sha256 = bindingIdentity(result);
        return result;
    }
} else struct {};

comptime {
    // Only these two exact paths may contain slices; SourceSnapshot.init owns
    // both. Future public-data or projection fields must not silently borrow.
    if (@FieldType(SourceValues, "public_value") != public_data.PublicData or
        @FieldType(public_data.PublicData, "io_entries") != public_data.IoEntries or
        @FieldType(public_data.IoEntries, "input_words") != []const u32 or
        @FieldType(public_data.IoEntries, "output_words") != []const public_data.OutputWord)
        @compileError("child-public copied IO source paths changed");
    for (@typeInfo(SourceValues).@"struct".fields) |field|
        if (!std.mem.eql(u8, field.name, "public_value")) assertPointerFreeSourceField(field.type);
    for (@typeInfo(public_data.PublicData).@"struct".fields) |field|
        if (!std.mem.eql(u8, field.name, "io_entries")) assertPointerFreeSourceField(field.type);
    for (@typeInfo(public_data.IoEntries).@"struct".fields) |field|
        if (!std.mem.eql(u8, field.name, "input_words") and !std.mem.eql(u8, field.name, "output_words")) assertPointerFreeSourceField(field.type);
    assertPointerFreeSourceField(public_data.OutputWord);

    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 4 or FIRST_ROW != 12 or
        LAST_ROW != 15 or ROW_COUNT != 4 or CLAIM_CIRCUIT_ID != 40 or
        !ROWS_12_THROUGH_15_AVAILABLE or LEGACY_COMPLETION_RELABEL_ADMITTED or
        DIGEST_ONLY_CONSTRUCTION or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental child-public V4 drifted");
    }
}
