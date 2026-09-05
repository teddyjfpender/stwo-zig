//! Verifier-owned universal row-16 source for an Ethereum V4 leaf wrapper.
//!
//! The source is a lossless projection of the fixed schema-3 public-sum
//! circuit owned by `native_core_v4`.  It does not rebuild values from the
//! statement, nor accept caller-authored node identifiers or use counts.
//! Row 16 owns only the segment selector and four relation-challenge pairs;
//! authenticated statement/role-I/O inputs remain on rows 11 and 15.  This
//! prevents a second caller-shaped claim vector from shadowing the real child
//! public authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const native_core =
    @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
const public_sums =
    @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const witness = frontend.recursion.air.vm_public_logup_input_witness;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const UNIVERSAL_ROW: usize = 16;
pub const RELATION_CHALLENGE_COUNT: usize = 4;
pub const CHALLENGE_WORD_COUNT: usize = 8;
pub const INPUT_COUNT: usize =
    1 + RELATION_CHALLENGE_COUNT * CHALLENGE_WORD_COUNT;
pub const CLAIMED_SUM_COUNT: u32 = 0;
pub const ROW_16_SOURCE_AVAILABLE = true;
pub const CALLER_AUTHORED_GRAPH_METADATA_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-logup-input/v4-schema3\x00";

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalPublicLogupInputMismatchV4,
};

/// Stable heap owner because `Reference` borrows `claim_kinds` and `bindings`.
pub fn OwnerV4(comptime NativeOwner: type) type {
    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            native: *const NativeOwner,
        ) !*Self {
            try native.validate();
            const view = try native.publicInputView();
            try view.validate();
            const split = try classifyLayout(view.bindings);

            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            const claim_kinds = try allocator.alloc(witness.ClaimKind, 0);
            errdefer allocator.free(claim_kinds);
            const bindings = try allocator.alloc(witness.Binding, INPUT_COUNT);
            errdefer allocator.free(bindings);
            const values = try allocator.alloc(M31, INPUT_COUNT);
            errdefer allocator.free(values);

            for (values, 0..) |*destination, index| {
                const source = view.values[sourceIndex(split, index)];
                const limbs = source.toM31Array();
                if (!limbs[1].isZero() or !limbs[2].isZero() or
                    !limbs[3].isZero())
                {
                    return error.EthereumIncrementalPublicLogupInputMismatchV4;
                }
                destination.* = limbs[0];
            }
            try fillBindings(view, bindings, split);
            const reference_value = try witness.Reference.seal(
                view.circuit_id,
                claim_kinds,
                CLAIMED_SUM_COUNT,
                bindings,
            );
            var preprocessing_value = try witness.Preprocessed.init(
                allocator,
                reference_value,
            );
            var preprocessing_owned = true;
            errdefer if (preprocessing_owned) preprocessing_value.deinit();
            var main_value = try witness.MainWitness.init(
                allocator,
                &preprocessing_value,
                reference_value,
                values,
                .segment_leaf,
            );
            var main_owned = true;
            errdefer if (main_owned) main_value.deinit();

            backing.* = .{
                .allocator = allocator,
                .native = native,
                .claim_kinds = claim_kinds,
                .bindings = bindings,
                .values = values,
                .reference = reference_value,
                .preprocessing = preprocessing_value,
                .main = main_value,
                .native_program_identity_sha256 = view.program_identity_sha256,
                .native_evaluation_identity_sha256 = view.evaluation_identity_sha256,
                .identity_sha256 = undefined,
            };
            preprocessing_owned = false;
            main_owned = false;
            backing.identity_sha256 = backing.computeIdentity();
            errdefer backing.destroy();
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn logSize(self: *const Self) !u32 {
            try self.validate();
            return storageConst(self).preprocessing.log_size;
        }

        pub fn reference(self: *const Self) !witness.Reference {
            try self.validate();
            return storageConst(self).reference;
        }

        pub fn preprocessing(self: *const Self) !*const witness.Preprocessed {
            try self.validate();
            return &storageConst(self).preprocessing;
        }

        pub fn mainWitness(self: *const Self) !*const witness.MainWitness {
            try self.validate();
            return &storageConst(self).main;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            try self.validate();
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            native: *const NativeOwner,
            claim_kinds: []witness.ClaimKind,
            bindings: []witness.Binding,
            values: []M31,
            reference: witness.Reference,
            preprocessing: witness.Preprocessed,
            main: witness.MainWitness,
            native_program_identity_sha256: [32]u8,
            native_evaluation_identity_sha256: [32]u8,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.native.validate();
                const view = try self.native.publicInputView();
                try view.validate();
                const split = try classifyLayout(view.bindings);
                if (self.claim_kinds.len != 0 or
                    self.bindings.len != INPUT_COUNT or
                    self.values.len != INPUT_COUNT or
                    self.reference.claim_kinds.ptr != self.claim_kinds.ptr or
                    self.reference.bindings.ptr != self.bindings.ptr or
                    self.reference.claimed_sum_count != CLAIMED_SUM_COUNT or
                    !std.mem.eql(
                        u8,
                        &self.native_program_identity_sha256,
                        &view.program_identity_sha256,
                    ) or
                    !std.mem.eql(
                        u8,
                        &self.native_evaluation_identity_sha256,
                        &view.evaluation_identity_sha256,
                    ))
                {
                    return error.EthereumIncrementalPublicLogupInputMismatchV4;
                }
                for (self.values, 0..) |actual, index| {
                    const expected = view.values[sourceIndex(split, index)];
                    const limbs = expected.toM31Array();
                    if (!limbs[1].isZero() or !limbs[2].isZero() or
                        !limbs[3].isZero() or !actual.eql(limbs[0]))
                    {
                        return error.EthereumIncrementalPublicLogupInputMismatchV4;
                    }
                }
                try validateBindings(view, self.bindings, split);
                try self.reference.validate();
                try self.preprocessing.validateAgainst(self.reference);
                try self.main.validateAgainst(&self.preprocessing);
                if (!std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &self.computeIdentity(),
                )) return error.EthereumIncrementalPublicLogupInputMismatchV4;
            }

            fn computeIdentity(self: *const Storage) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hashInt(&hash, u32, UNIVERSAL_ROW);
                hash.update(&self.native_program_identity_sha256);
                hash.update(&self.native_evaluation_identity_sha256);
                hash.update(&self.reference.authority_digest);
                hashInt(&hash, u32, @as(u32, @intCast(self.values.len)));
                for (self.values) |value| hashInt(&hash, u32, value.toU32());
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.main.deinit();
                self.preprocessing.deinit();
                allocator.free(self.values);
                allocator.free(self.bindings);
                allocator.free(self.claim_kinds);
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

const Layout = struct { challenge_start: usize };

fn classifyLayout(bindings: []const public_sums.InputSourceV4) Error!Layout {
    const challenge_count = RELATION_CHALLENGE_COUNT * CHALLENGE_WORD_COUNT;
    const fixed = std.math.add(usize, challenge_count, 1) catch
        return error.ArithmeticOverflow;
    if (bindings.len < fixed or
        std.meta.activeTag(bindings[0]) != .segment_selector)
    {
        return error.EthereumIncrementalPublicLogupInputMismatchV4;
    }
    const challenge_start = bindings.len - challenge_count;
    for (bindings[1..challenge_start]) |source| if (std.meta.activeTag(source) == .segment_selector or
        std.meta.activeTag(source) == .relation_challenge_word)
    {
        return error.EthereumIncrementalPublicLogupInputMismatchV4;
    };
    var at = challenge_start;
    for (0..RELATION_CHALLENGE_COUNT) |challenge| {
        for (0..CHALLENGE_WORD_COUNT) |word_index| {
            const expected = challengeSource(challenge, word_index);
            if (!std.meta.eql(bindings[at], expected))
                return error.EthereumIncrementalPublicLogupInputMismatchV4;
            at += 1;
        }
    }
    if (at != bindings.len)
        return error.EthereumIncrementalPublicLogupInputMismatchV4;
    return .{ .challenge_start = challenge_start };
}

fn fillBindings(
    view: native_core.PublicInputViewV4,
    destination: []witness.Binding,
    layout: Layout,
) Error!void {
    if (destination.len != INPUT_COUNT or
        view.use_counts.len != view.bindings.len)
    {
        return error.EthereumIncrementalPublicLogupInputMismatchV4;
    }
    for (destination, 0..) |*binding, index| {
        const source_index = sourceIndex(layout, index);
        const node_id = std.math.cast(u32, source_index) orelse
            return error.ArithmeticOverflow;
        binding.* = .{
            .node_id = node_id,
            .use_count = view.use_counts[source_index],
            .source = if (index == 0)
                .segment_selector
            else
                .{ .relation_challenge_word = .{
                    .challenge = @intCast((index - 1) / CHALLENGE_WORD_COUNT),
                    .word_index = @intCast((index - 1) % CHALLENGE_WORD_COUNT),
                } },
        };
    }
}

fn validateBindings(
    view: native_core.PublicInputViewV4,
    bindings: []const witness.Binding,
    layout: Layout,
) Error!void {
    if (bindings.len != INPUT_COUNT or
        view.use_counts.len != view.bindings.len)
    {
        return error.EthereumIncrementalPublicLogupInputMismatchV4;
    }
    for (bindings, 0..) |binding, index| {
        const source_index = sourceIndex(layout, index);
        const expected_source: witness.Source = if (index == 0)
            .segment_selector
        else
            .{ .relation_challenge_word = .{
                .challenge = @intCast((index - 1) / CHALLENGE_WORD_COUNT),
                .word_index = @intCast((index - 1) % CHALLENGE_WORD_COUNT),
            } };
        if (@as(usize, binding.node_id) != source_index or
            binding.use_count != view.use_counts[source_index] or
            !std.meta.eql(binding.source, expected_source))
        {
            return error.EthereumIncrementalPublicLogupInputMismatchV4;
        }
    }
}

fn sourceIndex(layout: Layout, projected_index: usize) usize {
    return if (projected_index == 0)
        0
    else
        layout.challenge_start + projected_index - 1;
}

fn challengeSource(
    challenge: usize,
    word_index: usize,
) public_sums.InputSourceV4 {
    return .{ .relation_challenge_word = .{
        .domain = @enumFromInt(challenge),
        .alpha = word_index >= 4,
        .limb = @intCast(word_index % 4),
    } };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or UNIVERSAL_ROW != 16 or
        RELATION_CHALLENGE_COUNT != 4 or CHALLENGE_WORD_COUNT != 8 or
        INPUT_COUNT != 33 or
        CLAIMED_SUM_COUNT != 0 or !ROW_16_SOURCE_AVAILABLE or
        CALLER_AUTHORED_GRAPH_METADATA_ADMITTED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental public LogUp input V4 drifted");
    }
}
