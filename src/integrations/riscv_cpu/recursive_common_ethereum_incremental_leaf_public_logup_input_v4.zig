//! Verifier-owned universal row-16 source for an Ethereum V4 leaf wrapper.
//!
//! The source projects the selector and challenges of the fixed public-sum
//! circuit owned by `native_core_v4`.  It does not rebuild values from the
//! statement, nor accept caller-authored node identifiers or use counts.
//! Row 16 owns the segment selector, four relation-challenge pairs and all
//! canonical component claim limbs used by the cancellation endpoint;
//! its admitted statement-routing plan also supplies rows 10/11. Role inputs
//! have explicit claim sources or pointwise arithmetic constraints, and share
//! their publication hash values. Clock limbs are retained for rows10/11.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const native_core =
    @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
const public_sums =
    @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");

const role_routing = @import("recursive_common_ethereum_incremental_leaf_role_input_routing_v4.zig");
const statement_routing = @import("recursive_common_ethereum_incremental_leaf_statement_routing_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const witness = frontend.recursion.air.vm_public_logup_input_witness;
const clocks = frontend.recursion.ethereum_clock_routing_v1;
const CLOCK_INPUT_START: usize = 1 + statement_routing.WORD_COUNT;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 7;
pub const UNIVERSAL_ROW: usize = 16;
pub const RELATION_CHALLENGE_COUNT: usize = 4;
pub const CHALLENGE_WORD_COUNT: usize = 8;
pub const CLAIMED_SUM_COUNT: u32 = public_sums.CANONICAL_CLAIM_COUNT;
pub const CLAIMED_SUM_WORD_COUNT: usize = CLAIMED_SUM_COUNT * 4;
pub const INPUT_COUNT: usize =
    1 + RELATION_CHALLENGE_COUNT * CHALLENGE_WORD_COUNT + CLAIMED_SUM_WORD_COUNT;
pub const ROW_16_SOURCE_AVAILABLE = true;
pub const CALLER_AUTHORED_GRAPH_METADATA_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-logup-input/v4-schema7\x00";

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
            // The native getter authenticates both its owner and returned view.
            const view = try native.publicInputView();
            const split = try classifyLayout(view.bindings);
            const routing = try statement_routing.Plan.init(view.bindings, view.use_counts, view.program_identity_sha256);
            const clock_values = try copyClockValues(view);
            var roles = try role_routing.Prepared.init(allocator, view);
            var roles_owned = true;
            errdefer if (roles_owned) roles.deinit();

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
                .routing = routing,
                .clock_values = clock_values,
                .native_root_values = try copyNativeRootValues(view),
                .roles = roles,
                .preprocessing = preprocessing_value,
                .main = main_value,
                .native_program_identity_sha256 = view.program_identity_sha256,
                .native_evaluation_identity_sha256 = view.evaluation_identity_sha256,
                .identity_sha256 = undefined,
            };
            backing.identity_sha256 = backing.computeIdentity();
            try backing.validate();
            roles_owned = false;
            preprocessing_owned = false;
            main_owned = false;
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        /// Immutable fixed schedule, admitted and copied at construction.
        pub fn statementRouting(self: *const Self) *const statement_routing.Plan {
            return &storageConst(self).routing;
        }

        /// Values were narrowed and copied at admission. Internal readers
        /// borrow immutable storage without repeating hierarchy validation.
        pub fn clockWords(self: *const Self) *const [clocks.WORD_COUNT]M31 {
            return &storageConst(self).clock_values;
        }

        pub fn nativeRootWords(self: *const Self) []const M31 {
            const owned = storageConst(self);
            return owned.native_root_values[0..if (owned.routing.usesNativeRoots()) @as(usize, 2) else 0];
        }

        pub fn logSize(self: *const Self) !u32 {
            try self.validate();
            const value = storageConst(self);
            const count = std.math.cast(u32, value.preprocessing.rows.len + value.roles.rows.len) orelse return error.ArithmeticOverflow;
            return @max(value.preprocessing.log_size, std.math.log2_int_ceil(u32, count));
        }

        pub fn roleRouting(self: *const Self) *const role_routing.Prepared {
            return &storageConst(self).roles;
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
            routing: statement_routing.Plan,
            clock_values: [clocks.WORD_COUNT]M31,
            native_root_values: [2]M31,
            roles: role_routing.Prepared,
            preprocessing: witness.Preprocessed,
            main: witness.MainWitness,
            native_program_identity_sha256: [32]u8,
            native_evaluation_identity_sha256: [32]u8,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                // This getter includes the complete native and view checks.
                const view = try self.native.publicInputView();
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
                const routing = try statement_routing.Plan.init(view.bindings, view.use_counts, view.program_identity_sha256);
                const clock_values = try copyClockValues(view);
                if (!std.meta.eql(self.routing, routing) or !std.meta.eql(self.clock_values, clock_values) or !std.meta.eql(self.native_root_values, try copyNativeRootValues(view)))
                    return error.EthereumIncrementalPublicLogupInputMismatchV4;
                try self.roles.validate(view);
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
                hash.update(&self.routing.identity());
                self.roles.hashInto(&hash);
                hashInt(&hash, u32, @as(u32, @intCast(self.values.len)));
                for (self.values) |value| hashInt(&hash, u32, value.toU32());
                for (self.clock_values) |value| hashInt(&hash, u32, value.toU32());
                if (self.routing.usesNativeRoots()) for (self.native_root_values) |value| hashInt(&hash, u32, value.toU32());
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.roles.deinit();
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

fn copyNativeRootValues(view: native_core.PublicInputViewV4) Error![2]M31 {
    var result = [_]M31{M31.zero()} ** 2;
    var count: usize = 0;
    for (view.bindings, view.values) |source, value| if (source == .native_continuation_root) {
        if (count >= 2 or source.native_continuation_root != count) return error.EthereumIncrementalPublicLogupInputMismatchV4;
        const limbs = value.toM31Array();
        if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero()) return error.EthereumIncrementalPublicLogupInputMismatchV4;
        result[count] = limbs[0];
        count += 1;
    };
    if (count != 0 and count != 2) return error.EthereumIncrementalPublicLogupInputMismatchV4;
    return result;
}

/// Narrow the exact admitted clock segment, never caller-supplied node IDs.
fn copyClockValues(view: native_core.PublicInputViewV4) Error![clocks.WORD_COUNT]M31 {
    const end = CLOCK_INPUT_START + clocks.WORD_COUNT;
    if (view.values.len < end or view.bindings.len < end)
        return error.EthereumIncrementalPublicLogupInputMismatchV4;
    var result: [clocks.WORD_COUNT]M31 = undefined;
    for (view.bindings[CLOCK_INPUT_START..end], view.values[CLOCK_INPUT_START..end], &result, 0..) |binding, value, *destination, index| {
        const expected = public_sums.InputSourceV4{ .register_clock_limb = .{
            .boundary = @enumFromInt(index / 64),
            .register = @intCast((index / 2) % 32),
            .limb = @intCast(index % 2),
        } };
        const words = value.toM31Array();
        if (!std.meta.eql(binding, expected) or !words[1].isZero() or !words[2].isZero() or !words[3].isZero())
            return error.EthereumIncrementalPublicLogupInputMismatchV4;
        destination.* = words[0];
    }
    return result;
}

const Layout = struct { challenge_start: usize };

fn classifyLayout(bindings: []const public_sums.InputSourceV4) Error!Layout {
    const challenge_count = RELATION_CHALLENGE_COUNT * CHALLENGE_WORD_COUNT;
    const fixed = std.math.add(usize, challenge_count + CLAIMED_SUM_WORD_COUNT, 1) catch
        return error.ArithmeticOverflow;
    if (bindings.len < fixed or
        std.meta.activeTag(bindings[0]) != .segment_selector)
    {
        return error.EthereumIncrementalPublicLogupInputMismatchV4;
    }
    const challenge_start = bindings.len - challenge_count - CLAIMED_SUM_WORD_COUNT;
    for (bindings[1..challenge_start]) |source| if (std.meta.activeTag(source) == .segment_selector or
        std.meta.activeTag(source) == .relation_challenge_word or
        std.meta.activeTag(source) == .canonical_claim_word)
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
    for (0..CLAIMED_SUM_COUNT) |item| for (0..4) |limb| {
        if (!std.meta.eql(bindings[at], public_sums.InputSourceV4{ .canonical_claim_word = .{
            .item = @intCast(item),
            .limb = @intCast(limb),
        } })) return error.EthereumIncrementalPublicLogupInputMismatchV4;
        at += 1;
    };
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
            .source = projectedSource(index),
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
        const expected_source = projectedSource(index);
        if (@as(usize, binding.node_id) != source_index or
            binding.use_count != view.use_counts[source_index] or
            !std.meta.eql(binding.source, expected_source))
        {
            return error.EthereumIncrementalPublicLogupInputMismatchV4;
        }
    }
}

fn projectedSource(index: usize) witness.Source {
    if (index == 0) return .segment_selector;
    const offset = index - 1;
    const challenge_words = RELATION_CHALLENGE_COUNT * CHALLENGE_WORD_COUNT;
    if (offset < challenge_words) return .{ .relation_challenge_word = .{
        .challenge = @intCast(offset / CHALLENGE_WORD_COUNT),
        .word_index = @intCast(offset % CHALLENGE_WORD_COUNT),
    } };
    const claim_word = offset - challenge_words;
    return .{ .claimed_sum_word = .{
        .item_index = @intCast(claim_word / 4),
        .limb_index = @intCast(claim_word % 4),
    } };
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
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 7 or UNIVERSAL_ROW != 16 or
        RELATION_CHALLENGE_COUNT != 4 or CHALLENGE_WORD_COUNT != 8 or
        INPUT_COUNT != 205 or
        CLAIMED_SUM_COUNT != 43 or !ROW_16_SOURCE_AVAILABLE or
        CALLER_AUTHORED_GRAPH_METADATA_ADMITTED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental public LogUp input V4 drifted");
    }
}

test "role0 clock input custody copies limbs and rejects malformed coordinates" {
    const QM31 = stwo_core.fields.qm31.QM31;
    const count = CLOCK_INPUT_START + clocks.WORD_COUNT;
    var bindings = [_]public_sums.InputSourceV4{.segment_selector} ** count;
    var values = [_]QM31{QM31.zero()} ** count;
    const uses = [_]u32{1} ** count;
    for (0..clocks.WORD_COUNT) |index| {
        bindings[CLOCK_INPUT_START + index] = .{ .register_clock_limb = .{
            .boundary = @enumFromInt(index / 64),
            .register = @intCast((index / 2) % 32),
            .limb = @intCast(index % 2),
        } };
        values[CLOCK_INPUT_START + index] = QM31.fromBase(M31.fromU64(1000 + index));
    }
    var view = native_core.PublicInputViewV4{
        .circuit_id = public_sums.CIRCUIT_ID,
        .bindings = &bindings,
        .values = &values,
        .use_counts = &uses,
        .program_identity_sha256 = .{1} ** 32,
        .evaluation_identity_sha256 = .{2} ** 32,
    };
    const copied = try copyClockValues(view);
    for (copied, 0..) |value, index| try std.testing.expectEqual(@as(u32, @intCast(1000 + index)), value.toU32());
    values[CLOCK_INPUT_START] = QM31.fromBase(M31.one());
    try std.testing.expectEqual(@as(u32, 1000), copied[0].toU32());
    try std.testing.expectEqual(@as(u32, 1), (try copyClockValues(view))[0].toU32());
    values[CLOCK_INPUT_START] = QM31.fromU32Unchecked(1, 1, 0, 0);
    try std.testing.expectError(error.EthereumIncrementalPublicLogupInputMismatchV4, copyClockValues(view));
    values[CLOCK_INPUT_START] = QM31.one();
    bindings[CLOCK_INPUT_START].register_clock_limb.register = 1;
    try std.testing.expectError(error.EthereumIncrementalPublicLogupInputMismatchV4, copyClockValues(view));
    bindings[CLOCK_INPUT_START].register_clock_limb.register = 0;
    view.values = values[0 .. count - 1];
    try std.testing.expectError(error.EthereumIncrementalPublicLogupInputMismatchV4, copyClockValues(view));
}

test "Ethereum canonical claim routing closes both composition and public cancellation consumers" {
    const allocator = std.testing.allocator;
    const air = frontend.recursion.air;
    const sums = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
    const transcript = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
    const types = @import("recursive_common_ethereum_incremental_leaf_transcript_program_types_v4.zig");
    var program = try sums.build(allocator, 1);
    defer program.deinit(allocator);
    const layout = try classifyLayout(program.bindings);
    const values = try allocator.alloc(stwo_core.fields.qm31.QM31, program.bindings.len);
    defer allocator.free(values);
    @memset(values, stwo_core.fields.qm31.QM31.zero());
    const view = native_core.PublicInputViewV4{
        .circuit_id = public_sums.CIRCUIT_ID,
        .bindings = program.bindings,
        .values = values,
        .use_counts = program.circuit.useCounts()[0..program.bindings.len],
        .program_identity_sha256 = .{1} ** 32,
        .evaluation_identity_sha256 = .{2} ** 32,
    };
    var bindings: [INPUT_COUNT]witness.Binding = undefined;
    try fillBindings(view, &bindings, layout);
    try validateBindings(view, &bindings, layout);
    const reference_value = try witness.Reference.seal(public_sums.CIRCUIT_ID, &.{}, CLAIMED_SUM_COUNT, &bindings);
    var preprocessing_value = try witness.Preprocessed.init(allocator, reference_value);
    defer preprocessing_value.deinit();
    var provider_definition = try air.transcript_payload_clocks_v2.build(allocator);
    defer provider_definition.deinit();
    const provider = try air.universal_relation_binding.Binding(air.transcript_payload_clocks_v2).authenticate(&provider_definition);
    var vm_definition = try air.vm_air_composition_input.build(allocator);
    defer vm_definition.deinit();
    const vm = try air.vm_air_composition_input_relation.authenticate(&vm_definition);
    var sum_definition = try air.vm_public_logup_input.build(allocator);
    defer sum_definition.deinit();
    const sum_plan = try air.vm_public_logup_input_relation.authenticate(&sum_definition);
    var ledger = air.relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    for (0..CLAIMED_SUM_WORD_COUNT) |index| {
        const item: u32 = @intCast(index / 4);
        const limb: u32 = @intCast(index % 4);
        const value = M31.fromU64(100 + index);
        const operation = types.OperationV4{
            .recording_index = 0,
            .context = .interaction_claims,
            .context_ordinal = 0,
            .effect = .mix,
            .verifier_sequence = 7,
            .tag = 0,
            .args = .{ 0, 0, 0, 0 },
            .payload = .{ .transcript_claimed_sum = item },
            .draw = .none,
        };
        const source = try transcript.metadata(operation, limb);
        try std.testing.expectEqual(sums.CANONICAL_CLAIM_TRANSCRIPT_USE_COUNT, source.input_use_count);
        const row: air.transcript_payload_witness.Row = .{
            .row_mask = 1,
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 7,
            .tag = 0,
            .args = .{ 0, 0, 0, 0 },
            .payload_index = limb,
            .source_kind = .claimed_sum,
            .item_index = item,
            .limb_index = limb,
            .constant_mask = 0,
            .input_use_count = source.input_use_count,
            .constant_value = 0,
            .source_hash_id = 0,
            .source_word_index = @as(u32, @intCast(frontend.recursion.poseidon2_channel.RATE)) + limb,
        };
        const supplied = provider.preparedEntries(try air.transcript_payload_clocks_v2.logicalRow(row, value));
        const vm_row: air.vm_air_composition_input_witness.Row = .{
            .classification = .{ .vm_input = .{ .transcript_claimed_sum = .{ .item_index = item, .word_index = limb } } },
            .circuit_id = 7,
            .node_id = @intCast(1 + index),
            .use_count = 1,
        };
        const composed = vm.preparedEntries(try air.vm_air_composition_input_witness.logicalRow(vm_row, value, .segment_leaf));
        const public_row = preprocessing_value.rows[1 + RELATION_CHALLENGE_COUNT * CHALLENGE_WORD_COUNT + index];
        const cancelled = sum_plan.preparedEntries(witness.logicalInputs(
            .{ .value = value },
            public_row,
            .segment_leaf,
            M31.fromCanonical(air.vm_public_claim_input.VM_PUBLIC_LOGUP_SCOPE),
            M31.zero(),
            M31.fromCanonical(air.relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE),
            M31.fromCanonical(@intFromEnum(air.transcript_payload.VerifierInputKind.claimed_sum)),
        ));
        for ([_][]const air.relation_interaction.Entry{ &supplied, &composed, &cancelled }, [_]u8{ 5, 18, 16 }) |entries, component| for (entries) |entry| {
            if (entry.domain == .recursion_verifier_input_word)
                try ledger.append(entry.domain, component, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
        };
    }
    try std.testing.expect(ledger.classify().isClosed());
    const first_claim = 1 + RELATION_CHALLENGE_COUNT * CHALLENGE_WORD_COUNT;
    bindings[first_claim].source.claimed_sum_word.item_index = 1;
    try std.testing.expectError(error.EthereumIncrementalPublicLogupInputMismatchV4, validateBindings(view, &bindings, layout));
    const final_binding = program.bindings[program.bindings.len - 1];
    program.bindings[program.bindings.len - 1] = .{ .canonical_claim_word = .{ .item = 41, .limb = 3 } };
    try std.testing.expectError(error.EthereumIncrementalPublicLogupInputMismatchV4, classifyLayout(program.bindings));
    program.bindings[program.bindings.len - 1] = final_binding;
}
