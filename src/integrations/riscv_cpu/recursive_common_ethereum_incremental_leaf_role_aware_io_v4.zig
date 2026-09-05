//! Field-native role-aware public-I/O witness for the stage-102 V4 leaf.
//! One retained two-limb stream owns padding, Poseidon2, and relation sums;
//! per-leaf capacity is audit-only until the 210-leaf maximum is cold-frozen.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const public_logup_v2 = frontend.air.public_logup_v2;
const public_logup_v4 = frontend.air.incremental_public_logup_v4;
const relations_mod = frontend.air.relation_challenges;
const program_decode = frontend.air.program.decode;
const statement_v2 = frontend.air.statement_v2;
const poseidon = frontend.air.memory_commitment.poseidon2;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;
const channel = frontend.recursion.poseidon2_channel;
const support =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4_support.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const STREAM_DOMAIN_WORD: u32 = 0x494f_5634; // "IOV4"
pub const COMMITMENT_DOMAIN: u32 = 0x494f_4333; // "IOC3"
pub const HEADER_WORD_COUNT: usize = 6;
pub const MAX_RELATION_ARITY: usize = 7;
pub const LIMBS_PER_FIELD: usize = 2;
pub const TUPLE_LIMB_COUNT: usize = MAX_RELATION_ARITY * LIMBS_PER_FIELD;
pub const TUPLE_WORD_COUNT: usize = 4 + TUPLE_LIMB_COUNT;

pub const CAMPAIGN_CAPACITY_FROZEN = false;
pub const PRODUCTION_ACTIVATION = false;
pub const CALLER_DIGEST_IS_AUTHORITY = false;
pub const ACTIVE_PREFIX_ENFORCED = true;
pub const ZERO_PADDING_ENFORCED = true;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-role-aware-io/v4-schema3\x00";
const PROGRAM_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-role-aware-io-program/v4-schema3\x00";

pub const Error = public_data.ValidationError || statement_v2.Error ||
    std.mem.Allocator.Error ||
    error{
        ArithmeticOverflow,
        ClockOverflow,
        IncrementalPublicAuthorityMismatchV4,
        IncrementalPublicCompletionMismatchV4,
        InvalidRoleAwareIoCommitmentV4,
        InvalidRoleAwareIoTupleV4,
        MissingCompletion,
        RoleAwareIoCapacityNotFrozenV4,
        RoleAwareIoClaimMismatchV4,
        RoleAwareIoWitnessMismatchV4,
        ZeroDenominator,
    };

pub const RelationV4 = enum(u32) {
    padding = 0,
    memory_access = 1,
    program_access = 2,
};

pub const DirectionV4 = enum(u32) {
    padding = 0,
    emit = 1,
    consume = 2,
};

/// Canonical order: inputs, outputs, then the optional completion correction.
pub const TupleKindV4 = enum(u32) {
    padding = 0,
    input_memory = 1,
    output_memory = 2,
    halt_memory = 3,
    program_completion = 4,
};

/// One relation tuple with two u16 limbs per unrestricted RV32 word; unused
/// program-tuple limbs are canonical zero.
pub const TupleV4 = struct {
    kind: TupleKindV4,
    relation: RelationV4,
    direction: DirectionV4,
    arity: u32,
    value_limbs: [MAX_RELATION_ARITY][LIMBS_PER_FIELD]u32,

    pub fn init(
        kind: TupleKindV4,
        raw_values: []const u32,
    ) Error!TupleV4 {
        if (kind == .padding) return error.InvalidRoleAwareIoTupleV4;
        const expected = expectedMetadata(kind);
        if (raw_values.len != expected.arity)
            return error.InvalidRoleAwareIoTupleV4;
        var result = TupleV4{
            .kind = kind,
            .relation = expected.relation,
            .direction = expected.direction,
            .arity = expected.arity,
            .value_limbs = .{.{ 0, 0 }} ** MAX_RELATION_ARITY,
        };
        for (raw_values, 0..) |value, index|
            result.value_limbs[index] = support.splitU32(value);
        try result.validate();
        return result;
    }

    pub fn zero() TupleV4 {
        return .{
            .kind = .padding,
            .relation = .padding,
            .direction = .padding,
            .arity = 0,
            .value_limbs = .{.{ 0, 0 }} ** MAX_RELATION_ARITY,
        };
    }

    pub fn isZero(self: TupleV4) bool {
        return std.mem.allEqual(u8, std.mem.asBytes(&self), 0);
    }

    pub fn validate(self: TupleV4) Error!void {
        if (self.kind == .padding)
            return error.InvalidRoleAwareIoTupleV4;
        const expected = expectedMetadata(self.kind);
        if (self.relation != expected.relation or
            self.direction != expected.direction or
            self.arity != expected.arity)
        {
            return error.InvalidRoleAwareIoTupleV4;
        }
        for (self.value_limbs, 0..) |limbs, index| {
            if (limbs[0] > std.math.maxInt(u16) or
                limbs[1] > std.math.maxInt(u16) or
                (index >= self.arity and (limbs[0] != 0 or limbs[1] != 0)))
            {
                return error.InvalidRoleAwareIoTupleV4;
            }
        }
    }

    pub fn values(self: TupleV4) Error![MAX_RELATION_ARITY]u32 {
        try self.validate();
        var result = [_]u32{0} ** MAX_RELATION_ARITY;
        for (&result, self.value_limbs) |*destination, limbs|
            destination.* = support.joinU32(limbs);
        return result;
    }

    pub fn words(self: TupleV4) Error![TUPLE_WORD_COUNT]u32 {
        try self.validate();
        var result: [TUPLE_WORD_COUNT]u32 = undefined;
        result[0..4].* = .{
            @intFromEnum(self.kind),
            @intFromEnum(self.relation),
            @intFromEnum(self.direction),
            self.arity,
        };
        var at: usize = 4;
        for (self.value_limbs) |limbs| for (limbs) |limb| {
            result[at] = limb;
            at += 1;
        };
        std.debug.assert(at == result.len);
        return result;
    }
};

pub const RelationClaimsV4 = struct {
    memory_access: QM31,
    program_access: QM31,

    pub fn total(self: RelationClaimsV4) QM31 {
        return self.memory_access.add(self.program_access);
    }

    pub fn validateAgainstAudit(
        self: RelationClaimsV4,
        audit: public_logup_v4.ReplacementAuditV4,
    ) Error!void {
        if (!self.memory_access.eql(audit.added_role_aware_io) or
            !self.program_access.eql(audit.added_role_program_fetch))
        {
            return error.RoleAwareIoClaimMismatchV4;
        }
    }
};

/// Exact four-domain recursive public row plus its aggregate, derived using
/// the replacement claims from this witness.
pub const PublicSumRowV4 = struct {
    registers_state: QM31,
    memory_access: QM31,
    program_access: QM31,
    merkle: QM31,
    total: QM31,

    pub fn values(self: PublicSumRowV4) [5]QM31 {
        return .{
            self.registers_state,
            self.memory_access,
            self.program_access,
            self.merkle,
            self.total,
        };
    }

    pub fn validateAgainstAudit(
        self: PublicSumRowV4,
        audit: public_logup_v4.ReplacementAuditV4,
    ) Error!void {
        if (!self.registers_state.eql(audit.result.registers_state) or
            !self.memory_access.eql(audit.result.memory_access) or
            !self.program_access.eql(audit.result.program_access) or
            !self.merkle.eql(audit.result.merkle) or
            !self.total.eql(audit.result.total()))
        {
            return error.RoleAwareIoClaimMismatchV4;
        }
    }

    pub fn validateAgainstVerified(
        self: PublicSumRowV4,
        verified: *const public_logup_v4.VerifiedPublicSumsV4,
    ) Error!void {
        if (!self.registers_state.eql(verified.sums.registers_state) or
            !self.memory_access.eql(verified.sums.memory_access) or
            !self.program_access.eql(verified.sums.program_access) or
            !self.merkle.eql(verified.sums.merkle) or
            !self.total.eql(verified.total))
        {
            return error.RoleAwareIoClaimMismatchV4;
        }
    }
};

/// Per-leaf measurement, never a common-manifest authority by itself.
pub const LiveMetricsV4 = struct {
    active_tuple_count: u32,
    padded_tuple_capacity: u32,
    canonical_word_count: u32,
    commitment_call_count: u32,
    combined_provider_call_count: u32,
    combined_provider_log_size: u32,
};

pub const OwnedWitnessV4 = struct {
    allocator: std.mem.Allocator,
    active_tuple_count: u32,
    padded_tuple_capacity: u32,
    tuples: []TupleV4,
    canonical_words: []u32,
    poseidon_calls: []poseidon_air.Call,
    commitment: channel.Digest,
    claims: RelationClaimsV4,
    public_sum_row: PublicSumRowV4,
    identity_sha256: [32]u8,

    /// Derives an audit-only smallest power-of-two capacity for one cold leaf.
    pub fn initLive(
        allocator: std.mem.Allocator,
        native: *const public_data_v2.PublicDataV2,
        role_aware: *const public_data.PublicData,
        relations: *const relations_mod.Relations,
    ) Error!OwnedWitnessV4 {
        const count = try tupleCount(native, role_aware);
        const capacity = try support.liveCapacity(count);
        return initUnfrozenForAudit(
            allocator,
            native,
            role_aware,
            relations,
            capacity,
        );
    }

    /// Explicit-capacity audit seam; never a frozen campaign authority.
    pub fn initUnfrozenForAudit(
        allocator: std.mem.Allocator,
        native: *const public_data_v2.PublicDataV2,
        role_aware: *const public_data.PublicData,
        relations: *const relations_mod.Relations,
        capacity: u32,
    ) Error!OwnedWitnessV4 {
        try public_logup_v4.validateSharedAuthority(native, role_aware);
        const active_count = try tupleCount(native, role_aware);
        try validateCapacity(active_count, capacity);

        const tuples = try allocator.alloc(TupleV4, capacity);
        errdefer allocator.free(tuples);
        @memset(tuples, TupleV4.zero());
        try fillActiveTuples(native, role_aware, tuples[0..active_count]);
        try testingValidateTupleSequence(tuples, active_count);

        const words = try testingCanonicalWordsAlloc(
            allocator,
            tuples,
            active_count,
        );
        errdefer allocator.free(words);
        const provider_calls = try testingBuildCallsAlloc(allocator, words);
        errdefer allocator.free(provider_calls);
        const commitment = testingDigestFromCalls(provider_calls);
        if (!std.meta.eql(
            commitment,
            channel.hashCanonicalU32s(words, COMMITMENT_DOMAIN),
        )) return error.InvalidRoleAwareIoCommitmentV4;

        const claims = try testingClaimsFromTuples(
            tuples[0..active_count],
            relations,
        );
        const audit = try public_logup_v4.audit(
            native,
            role_aware,
            relations,
        );
        try claims.validateAgainstAudit(audit);
        const public_sum_row = try derivePublicSumRow(
            native,
            relations,
            claims,
        );
        try public_sum_row.validateAgainstAudit(audit);
        var result = OwnedWitnessV4{
            .allocator = allocator,
            .active_tuple_count = active_count,
            .padded_tuple_capacity = capacity,
            .tuples = tuples,
            .canonical_words = words,
            .poseidon_calls = provider_calls,
            .commitment = commitment,
            .claims = claims,
            .public_sum_row = public_sum_row,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validateAgainst(native, role_aware, relations);
        return result;
    }

    pub fn deinit(self: *OwnedWitnessV4) void {
        self.allocator.free(self.poseidon_calls);
        self.allocator.free(self.canonical_words);
        self.allocator.free(self.tuples);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedWitnessV4,
        native: *const public_data_v2.PublicDataV2,
        role_aware: *const public_data.PublicData,
        relations: *const relations_mod.Relations,
    ) Error!void {
        try public_logup_v4.validateSharedAuthority(native, role_aware);
        const active_count = try tupleCount(native, role_aware);
        try validateCapacity(active_count, self.padded_tuple_capacity);
        if (self.active_tuple_count != active_count or
            self.tuples.len != self.padded_tuple_capacity)
        {
            return error.RoleAwareIoWitnessMismatchV4;
        }
        const expected_active = try self.allocator.alloc(TupleV4, active_count);
        defer self.allocator.free(expected_active);
        try fillActiveTuples(native, role_aware, expected_active);
        if (!std.mem.eql(
            u8,
            std.mem.sliceAsBytes(self.tuples[0..active_count]),
            std.mem.sliceAsBytes(expected_active),
        )) return error.RoleAwareIoWitnessMismatchV4;
        try testingValidateTupleSequence(self.tuples, active_count);

        const expected_word_count = try canonicalWordCount(
            self.padded_tuple_capacity,
        );
        if (self.canonical_words.len != expected_word_count or
            self.poseidon_calls.len !=
                channel.canonicalWordPermutationCount(expected_word_count))
        {
            return error.RoleAwareIoWitnessMismatchV4;
        }
        const expected_words = try testingCanonicalWordsAlloc(
            self.allocator,
            self.tuples,
            active_count,
        );
        defer self.allocator.free(expected_words);
        if (!std.mem.eql(u32, self.canonical_words, expected_words))
            return error.RoleAwareIoWitnessMismatchV4;
        const expected_calls = try testingBuildCallsAlloc(
            self.allocator,
            expected_words,
        );
        defer self.allocator.free(expected_calls);
        if (!support.callsEql(self.poseidon_calls, expected_calls) or
            !std.meta.eql(
                self.commitment,
                testingDigestFromCalls(expected_calls),
            ) or
            !std.meta.eql(
                self.commitment,
                channel.hashCanonicalU32s(expected_words, COMMITMENT_DOMAIN),
            ))
        {
            return error.InvalidRoleAwareIoCommitmentV4;
        }
        const expected_claims = try testingClaimsFromTuples(
            self.tuples[0..active_count],
            relations,
        );
        if (!support.claimsEql(self.claims, expected_claims))
            return error.RoleAwareIoClaimMismatchV4;
        const audit = try public_logup_v4.audit(
            native,
            role_aware,
            relations,
        );
        try self.claims.validateAgainstAudit(audit);
        const expected_public_sum_row = try derivePublicSumRow(
            native,
            relations,
            expected_claims,
        );
        if (!support.publicSumRowEql(
            self.public_sum_row,
            expected_public_sum_row,
        ))
            return error.RoleAwareIoClaimMismatchV4;
        try self.public_sum_row.validateAgainstAudit(audit);
        if (!std.mem.eql(u8, &self.identity_sha256, &identity(self)))
            return error.RoleAwareIoWitnessMismatchV4;
    }

    pub fn calls(self: *const OwnedWitnessV4) []const poseidon_air.Call {
        return self.poseidon_calls;
    }

    pub fn metrics(
        self: *const OwnedWitnessV4,
        fixed_stage102_calls: u32,
    ) Error!LiveMetricsV4 {
        const commitment_calls = std.math.cast(
            u32,
            self.poseidon_calls.len,
        ) orelse return error.ArithmeticOverflow;
        const combined = std.math.add(
            u32,
            fixed_stage102_calls,
            commitment_calls,
        ) catch return error.ArithmeticOverflow;
        return .{
            .active_tuple_count = self.active_tuple_count,
            .padded_tuple_capacity = self.padded_tuple_capacity,
            .canonical_word_count = std.math.cast(
                u32,
                self.canonical_words.len,
            ) orelse return error.ArithmeticOverflow,
            .commitment_call_count = commitment_calls,
            .combined_provider_call_count = combined,
            .combined_provider_log_size = try providerLogSize(combined),
        };
    }
};

pub fn requireFrozenCampaignCapacity() Error!void {
    return error.RoleAwareIoCapacityNotFrozenV4;
}

/// Static program identity; never an admitted witness.
pub fn programIdentity() [32]u8 {
    return support.programIdentity(
        PROGRAM_IDENTITY_DOMAIN,
        FORMAT_VERSION,
        SCHEMA_VERSION,
        &.{
            STREAM_DOMAIN_WORD,
            COMMITMENT_DOMAIN,
            HEADER_WORD_COUNT,
            MAX_RELATION_ARITY,
            LIMBS_PER_FIELD,
            TUPLE_WORD_COUNT,
            @intFromEnum(RelationV4.memory_access),
            @intFromEnum(RelationV4.program_access),
            @intFromEnum(DirectionV4.emit),
            @intFromEnum(DirectionV4.consume),
            @intFromEnum(TupleKindV4.input_memory),
            @intFromEnum(TupleKindV4.output_memory),
            @intFromEnum(TupleKindV4.halt_memory),
            @intFromEnum(TupleKindV4.program_completion),
        },
    );
}

pub fn tupleCount(
    native: *const public_data_v2.PublicDataV2,
    role_aware: *const public_data.PublicData,
) Error!u32 {
    try public_logup_v4.validateSharedAuthority(native, role_aware);
    const metadata = try native.metadata();
    var result = std.math.cast(
        u32,
        role_aware.io_entries.input_words.len,
    ) orelse return error.ArithmeticOverflow;
    result = std.math.add(
        u32,
        result,
        std.math.cast(u32, role_aware.io_entries.output_words.len) orelse
            return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
    const completion = role_aware.completion orelse
        return error.RoleAwareIoWitnessMismatchV4;
    result = std.math.add(
        u32,
        result,
        @intFromBool(completion.kind == .halt_flag),
    ) catch return error.ArithmeticOverflow;
    result = std.math.add(
        u32,
        result,
        @intFromBool(metadata.completion == null),
    ) catch return error.ArithmeticOverflow;
    return result;
}

pub fn providerLogSize(call_count: u32) Error!u32 {
    if (call_count == 0) return error.RoleAwareIoWitnessMismatchV4;
    const padded = std.math.ceilPowerOfTwo(u32, call_count) catch
        return error.ArithmeticOverflow;
    const result = @max(@as(u32, 4), std.math.log2_int(u32, padded));
    if (result >= 30) return error.ArithmeticOverflow;
    return result;
}

fn fillActiveTuples(
    native: *const public_data_v2.PublicDataV2,
    role_aware: *const public_data.PublicData,
    destination: []TupleV4,
) Error!void {
    if (destination.len != try tupleCount(native, role_aware))
        return error.RoleAwareIoWitnessMismatchV4;
    var at: usize = 0;
    for (role_aware.io_entries.input_words, 0..) |word, index| {
        const address = try role_aware.io_entries.inputWordAddress(index);
        destination[at] = try TupleV4.init(.input_memory, &memoryValues(
            address,
            0,
            word,
        ));
        at += 1;
    }
    for (role_aware.io_entries.output_words) |word| {
        destination[at] = try TupleV4.init(.output_memory, &memoryValues(
            word.addr,
            word.clock,
            word.value,
        ));
        at += 1;
    }
    const completion = role_aware.completion orelse
        return error.RoleAwareIoWitnessMismatchV4;
    if (completion.kind == .halt_flag) {
        destination[at] = try TupleV4.init(.halt_memory, &memoryValues(
            completion.address,
            completion.clock,
            completion.value,
        ));
        at += 1;
    }
    const metadata = try native.metadata();
    if (metadata.completion == null) {
        const decoded = program_decode.decodeProgramWordForProfile(
            .rv32im_zkvm_ethereum_v1,
            completion.value,
        ) catch return error.InvalidRoleAwareIoTupleV4;
        destination[at] = try TupleV4.init(.program_completion, &.{
            completion.address,
            decoded[0],
            decoded[1],
            decoded[2],
            decoded[3],
        });
        at += 1;
    }
    std.debug.assert(at == destination.len);
}

pub fn testingValidateTupleSequence(
    tuples: []const TupleV4,
    active_count: u32,
) Error!void {
    if (active_count > tuples.len)
        return error.RoleAwareIoWitnessMismatchV4;
    var previous: u32 = 0;
    for (tuples[0..active_count]) |tuple| {
        try tuple.validate();
        const current = @intFromEnum(tuple.kind);
        if (current < previous)
            return error.RoleAwareIoWitnessMismatchV4;
        previous = current;
    }
    for (tuples[active_count..]) |tuple| if (!tuple.isZero())
        return error.RoleAwareIoWitnessMismatchV4;
}

pub fn testingCanonicalWordsAlloc(
    allocator: std.mem.Allocator,
    tuples: []const TupleV4,
    active_count: u32,
) Error![]u32 {
    const capacity = std.math.cast(u32, tuples.len) orelse
        return error.ArithmeticOverflow;
    try validateCapacity(active_count, capacity);
    try testingValidateTupleSequence(tuples, active_count);
    const words = try allocator.alloc(u32, try canonicalWordCount(capacity));
    var at: usize = 0;
    for ([_]u32{
        STREAM_DOMAIN_WORD,
        FORMAT_VERSION,
        SCHEMA_VERSION,
        active_count,
        capacity,
        TUPLE_WORD_COUNT,
    }) |word| {
        words[at] = word;
        at += 1;
    }
    for (tuples) |tuple| {
        if (tuple.isZero()) {
            @memset(words[at..][0..TUPLE_WORD_COUNT], 0);
        } else {
            const tuple_words = try tuple.words();
            @memcpy(words[at..][0..TUPLE_WORD_COUNT], &tuple_words);
        }
        at += TUPLE_WORD_COUNT;
    }
    std.debug.assert(at == words.len);
    for (words) |word| if (word >= m31.Modulus)
        return error.InvalidRoleAwareIoTupleV4;
    return words;
}

pub fn testingBuildCallsAlloc(
    allocator: std.mem.Allocator,
    words: []const u32,
) Error![]poseidon_air.Call {
    const call_count = channel.canonicalWordPermutationCount(words.len);
    const calls = try allocator.alloc(poseidon_air.Call, call_count);
    var cursor: usize = 0;
    var state = [_]M31{M31.zero()} ** poseidon.WIDTH;
    state[poseidon.WIDTH - 1] = M31.fromCanonical(COMMITMENT_DOMAIN);
    var filled: usize = 0;
    for (words) |word| {
        if (word >= m31.Modulus) return error.InvalidRoleAwareIoTupleV4;
        absorbWord(calls, &cursor, &state, &filled, word);
    }
    absorbWord(calls, &cursor, &state, &filled, 1);
    if (filled != 0) appendPermutation(calls, &cursor, &state);
    std.debug.assert(cursor == calls.len);
    return calls;
}

pub fn testingDigestFromCalls(
    calls: []const poseidon_air.Call,
) channel.Digest {
    std.debug.assert(calls.len != 0);
    var state: [poseidon.WIDTH]M31 = undefined;
    for (&state, calls[calls.len - 1].input) |*destination, word|
        destination.* = M31.fromCanonical(word);
    poseidon.permute(&state);
    var result: channel.Digest = undefined;
    for (&result, state[0..channel.RATE]) |*destination, word|
        destination.* = word.toU32();
    return result;
}

fn absorbWord(
    calls: []poseidon_air.Call,
    cursor: *usize,
    state: *[poseidon.WIDTH]M31,
    filled: *usize,
    word: u32,
) void {
    state[filled.*] = state[filled.*].add(M31.fromCanonical(word));
    filled.* += 1;
    if (filled.* == channel.RATE) {
        appendPermutation(calls, cursor, state);
        filled.* = 0;
    }
}

fn appendPermutation(
    calls: []poseidon_air.Call,
    cursor: *usize,
    state: *[poseidon.WIDTH]M31,
) void {
    std.debug.assert(cursor.* < calls.len);
    var input: [poseidon.WIDTH]u32 = undefined;
    for (&input, state) |*destination, word| destination.* = word.toU32();
    calls[cursor.*] = .{
        .input = input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
    cursor.* += 1;
    poseidon.permute(state);
}

pub fn testingClaimsFromTuples(
    tuples: []const TupleV4,
    relations: *const relations_mod.Relations,
) Error!RelationClaimsV4 {
    var result = RelationClaimsV4{
        .memory_access = QM31.zero(),
        .program_access = QM31.zero(),
    };
    for (tuples) |tuple| {
        const raw = try tuple.values();
        var values: [MAX_RELATION_ARITY]M31 = undefined;
        for (&values, raw) |*destination, value|
            destination.* = M31.fromU64(value);
        const denominator = switch (tuple.relation) {
            .padding => return error.InvalidRoleAwareIoTupleV4,
            .memory_access => relations.memory_access.combineBase(values),
            .program_access => relations.program_access.combineBase(
                values[0..5].*,
            ),
        };
        const inverse = denominator.inv() catch return error.ZeroDenominator;
        const destination = switch (tuple.relation) {
            .padding => return error.InvalidRoleAwareIoTupleV4,
            .memory_access => &result.memory_access,
            .program_access => &result.program_access,
        };
        destination.* = switch (tuple.direction) {
            .padding => return error.InvalidRoleAwareIoTupleV4,
            .emit => destination.add(inverse),
            .consume => destination.sub(inverse),
        };
    }
    return result;
}

fn derivePublicSumRow(
    native: *const public_data_v2.PublicDataV2,
    relations: *const relations_mod.Relations,
    replacements: RelationClaimsV4,
) Error!PublicSumRowV4 {
    var sums = try statement_v2.nativeRelationSums(native, relations);
    sums.memory_access = sums.memory_access
        .sub(try public_logup_v2.rwMemoryAccessSum(native, relations))
        .add(replacements.memory_access);
    sums.merkle = sums.merkle.sub(
        try statement_v2.sparseContinuationTreeCompensation(
            native,
            relations,
        ),
    );
    sums.program_access = sums.program_access.add(
        replacements.program_access,
    );
    return .{
        .registers_state = sums.registers_state,
        .memory_access = sums.memory_access,
        .program_access = sums.program_access,
        .merkle = sums.merkle,
        .total = sums.total(),
    };
}

fn expectedMetadata(kind: TupleKindV4) struct {
    relation: RelationV4,
    direction: DirectionV4,
    arity: u32,
} {
    return switch (kind) {
        .padding => unreachable,
        .input_memory => .{
            .relation = .memory_access,
            .direction = .emit,
            .arity = 7,
        },
        .output_memory, .halt_memory => .{
            .relation = .memory_access,
            .direction = .consume,
            .arity = 7,
        },
        .program_completion => .{
            .relation = .program_access,
            .direction = .consume,
            .arity = 5,
        },
    };
}

fn memoryValues(address: u32, clock: u32, value: u32) [7]u32 {
    return .{
        1,
        address,
        clock,
        @as(u8, @truncate(value)),
        @as(u8, @truncate(value >> 8)),
        @as(u8, @truncate(value >> 16)),
        @as(u8, @truncate(value >> 24)),
    };
}

fn validateCapacity(active: u32, capacity: u32) Error!void {
    try support.validateCapacity(
        active,
        capacity,
        m31.Modulus,
        HEADER_WORD_COUNT,
        TUPLE_WORD_COUNT,
    );
}

fn canonicalWordCount(capacity: u32) Error!usize {
    return support.canonicalWordCount(
        capacity,
        HEADER_WORD_COUNT,
        TUPLE_WORD_COUNT,
    );
}

fn identity(value: *const OwnedWitnessV4) [32]u8 {
    return support.witnessIdentity(
        value,
        IDENTITY_DOMAIN,
        FORMAT_VERSION,
        SCHEMA_VERSION,
    );
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        HEADER_WORD_COUNT != 6 or MAX_RELATION_ARITY != 7 or
        TUPLE_LIMB_COUNT != 14 or TUPLE_WORD_COUNT != 18 or
        CAMPAIGN_CAPACITY_FROZEN or PRODUCTION_ACTIVATION or
        CALLER_DIGEST_IS_AUTHORITY or !ACTIVE_PREFIX_ENFORCED or
        !ZERO_PADDING_ENFORCED)
    {
        @compileError("role-aware I/O witness V4 schema3 drifted");
    }
}
