//! Schema-3 field-native public authority for the stage-102 V4 wrapper.
//!
//! Schema 2 remains a diagnostic description of the cold stage-101 capture.
//! This additive authority binds its complete projection together with the
//! count and Poseidon2 commitment of the raw role-aware replacement tuples.
//! The dynamic commitment calls are prepended to the one shared provider
//! schedule; the provider log is derived from the live call count and is not
//! frozen here as campaign geometry.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const schema2 =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const node_public_mod = @import("recursive_field_node_public_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const channel = frontend.recursion.poseidon2_channel;
const poseidon = frontend.air.memory_commitment.poseidon2;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;

pub const FORMAT_VERSION: u32 = 4;
pub const SCHEMA_VERSION: u32 = 3;
pub const SOURCE_KIND_ETHEREUM_INCREMENTAL_LEAF_V4: u32 = 4;
pub const CIRCUIT_ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const SOURCE_DIGEST_DOMAIN: u32 = 0x4549_5333; // "EIS3"
pub const IO_COMMITMENT_DOMAIN: u32 = role_io.COMMITMENT_DOMAIN;
pub const IO_BINDING_WORD_COUNT: usize = 10;
pub const SOURCE_PREIMAGE_WORD_COUNT: usize =
    schema2.SOURCE_PREIMAGE_WORD_COUNT + IO_BINDING_WORD_COUNT;
pub const STATEMENT_WORD_COUNT: usize = schema2.STATEMENT_WORD_COUNT;
pub const HEADER_WORD_COUNT: usize = schema2.HEADER_WORD_COUNT;
pub const AIR_WORD_COUNT: usize = schema2.AIR_WORD_COUNT;
pub const FIXED_PROVIDER_CALL_COUNT: usize =
    schema2.STATEMENT_CALL_COUNT +
    channel.canonicalWordPermutationCount(SOURCE_PREIMAGE_WORD_COUNT) +
    schema2.SUBTREE_CALL_COUNT + schema2.OUTPUT_CALL_COUNT;
pub const MINIMUM_IO_COMMITMENT_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(
        role_io.HEADER_WORD_COUNT + role_io.TUPLE_WORD_COUNT,
    );
pub const MINIMUM_PROVIDER_ACTIVE_ROW_COUNT: usize =
    FIXED_PROVIDER_CALL_COUNT + MINIMUM_IO_COMMITMENT_CALL_COUNT;
pub const MINIMUM_PROVIDER_LOG_SIZE: u32 =
    std.math.log2_int_ceil(usize, MINIMUM_PROVIDER_ACTIVE_ROW_COUNT);

pub const PRODUCTION_ACTIVATION = false;
pub const CAMPAIGN_PROVIDER_GEOMETRY_FROZEN = false;
pub const SCHEMA2_REMAINS_DIAGNOSTIC = true;
pub const DIGEST_ONLY_CONSTRUCTION = false;

const SCHEDULE_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-field-public/v4-schema3\x00";

pub const Error = schema2.Error || role_io.Error || std.mem.Allocator.Error ||
    error{
        ArithmeticOverflow,
        EthereumIncrementalFieldAuthorityMismatchV4Schema3,
        EthereumIncrementalFieldScheduleMismatchV4Schema3,
    };

pub const PhaseV4 = enum(u8) {
    io_stream = 0,
    statement = 1,
    source = 2,
    subtree = 3,
    output = 4,
};

pub const PhaseRangeV4 = struct {
    phase: PhaseV4,
    first_call: u32,
    call_count: u32,
    output_digest: channel.Digest,
};

/// Per-leaf provider measurement derived from the owned source and call
/// schedule. It is not the campaign maximum and therefore cannot activate a
/// common proof manifest by itself.
pub const LiveProviderGeometryV4 = struct {
    format_version: u32 = FORMAT_VERSION,
    schema_version: u32 = SCHEMA_VERSION,
    role_io_tuple_count: u32,
    role_io_tuple_capacity: u32,
    role_io_word_count: u32,
    role_io_call_count: u32,
    fixed_call_count: u32 = FIXED_PROVIDER_CALL_COUNT,
    provider_active_row_count: u32,
    provider_log_size: u32,
    provider_row_capacity: u32,

    pub fn validate(self: LiveProviderGeometryV4) Error!void {
        const expected_words = std.math.add(
            usize,
            role_io.HEADER_WORD_COUNT,
            std.math.mul(
                usize,
                self.role_io_tuple_capacity,
                role_io.TUPLE_WORD_COUNT,
            ) catch return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        const expected_calls = channel.canonicalWordPermutationCount(
            expected_words,
        );
        const expected_active = std.math.add(
            usize,
            FIXED_PROVIDER_CALL_COUNT,
            expected_calls,
        ) catch return error.ArithmeticOverflow;
        const expected_words_u32 = std.math.cast(u32, expected_words) orelse
            return error.ArithmeticOverflow;
        const expected_calls_u32 = std.math.cast(u32, expected_calls) orelse
            return error.ArithmeticOverflow;
        const expected_active_u32 = std.math.cast(u32, expected_active) orelse
            return error.ArithmeticOverflow;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.role_io_tuple_capacity == 0 or
            !std.math.isPowerOfTwo(self.role_io_tuple_capacity) or
            self.role_io_tuple_count > self.role_io_tuple_capacity or
            self.role_io_word_count != expected_words_u32 or
            self.role_io_call_count != expected_calls_u32 or
            self.fixed_call_count != FIXED_PROVIDER_CALL_COUNT or
            self.provider_active_row_count != expected_active_u32 or
            self.provider_log_size != try role_io.providerLogSize(
                self.provider_active_row_count,
            ) or self.provider_log_size >= 31 or
            self.provider_row_capacity !=
                (@as(u32, 1) << @intCast(self.provider_log_size)) or
            self.provider_active_row_count > self.provider_row_capacity)
        {
            return error.EthereumIncrementalFieldScheduleMismatchV4Schema3;
        }
    }
};

/// Pointer-free field authority.  The nested schema-2 projection is not an
/// admission token: `seal` still requires the live cold capture and the owned
/// raw tuple witness.
pub const SourceAuthorityV4 = struct {
    format_version: u32 = FORMAT_VERSION,
    schema_version: u32 = SCHEMA_VERSION,
    source_kind: u32 = SOURCE_KIND_ETHEREUM_INCREMENTAL_LEAF_V4,
    circuit_role: registry_mod.CircuitRoleV4 = CIRCUIT_ROLE,
    base: schema2.SourceAuthorityV4,
    role_io_tuple_count: u32,
    role_io_tuple_capacity: u32,
    role_io_commitment: channel.Digest,
    source_digest: channel.Digest,

    pub fn seal(
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
        witness: *const role_io.OwnedWitnessV4,
    ) !SourceAuthorityV4 {
        comptime requirePoseidonEngine(Engine);
        try input.validate();
        try witness.validateAgainst(
            &input.stage101.public_data.data,
            &input.stage101.role_aware_public.value,
            &input.stage101.relations.base,
        );
        var result = SourceAuthorityV4{
            .base = try schema2.SourceAuthorityV4.seal(Engine, input),
            .role_io_tuple_count = witness.active_tuple_count,
            .role_io_tuple_capacity = witness.padded_tuple_capacity,
            .role_io_commitment = witness.commitment,
            .source_digest = undefined,
        };
        result.source_digest = try projectedSourceDigest(&result);
        try result.validateStructure();
        return result;
    }

    pub fn validateAgainst(
        self: *const SourceAuthorityV4,
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
        witness: *const role_io.OwnedWitnessV4,
    ) !void {
        const expected = try seal(Engine, input, witness);
        if (!std.meta.eql(self.*, expected))
            return error.EthereumIncrementalFieldAuthorityMismatchV4Schema3;
    }

    pub fn validateStructure(self: *const SourceAuthorityV4) Error!void {
        try validateProjectedFields(self);
        if (!std.meta.eql(self.source_digest, try projectedSourceDigest(self)))
            return error.EthereumIncrementalFieldAuthorityMismatchV4Schema3;
    }

    pub fn preimage(
        self: *const SourceAuthorityV4,
    ) Error![SOURCE_PREIMAGE_WORD_COUNT]u32 {
        try self.validateStructure();
        return sourcePreimageUnchecked(self);
    }
};

pub fn projectedSourceDigest(
    value: *const SourceAuthorityV4,
) Error!channel.Digest {
    try validateProjectedFields(value);
    return channel.hashCanonicalU32s(
        &sourcePreimageUnchecked(value),
        SOURCE_DIGEST_DOMAIN,
    );
}

/// Owned because the I/O commitment phase has a live, capacity-dependent
/// call count.  Every call remains an ordinary request to the existing
/// authenticated universal Poseidon2 provider.
pub const OwnedPoseidonScheduleV4 = struct {
    allocator: std.mem.Allocator,
    source: SourceAuthorityV4,
    node_public: node_public_mod.NodePublicV2,
    phases: [5]PhaseRangeV4,
    calls: []poseidon_air.Call,
    provider_log_size: u32,
    identity_sha256: [32]u8,

    pub fn init(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        input: *const input_mod.FreshInputV4(Engine),
        witness: *const role_io.OwnedWitnessV4,
    ) !OwnedPoseidonScheduleV4 {
        const source = try SourceAuthorityV4.seal(Engine, input, witness);
        var result = try buildFromAuthority(
            allocator,
            input.statement_words,
            source,
            witness.calls(),
        );
        errdefer result.deinit();
        try result.validateAgainst(Engine, input, witness);
        return result;
    }

    pub fn deinit(self: *OwnedPoseidonScheduleV4) void {
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedPoseidonScheduleV4,
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
        witness: *const role_io.OwnedWitnessV4,
    ) !void {
        try self.source.validateAgainst(Engine, input, witness);
        try self.node_public.validateLeafSource(self.source.source_digest);
        var expected = try buildFromAuthority(
            self.allocator,
            input.statement_words,
            self.source,
            witness.calls(),
        );
        defer expected.deinit();
        if (!scheduleEql(self, &expected))
            return error.EthereumIncrementalFieldScheduleMismatchV4Schema3;
    }

    pub fn callsSlice(
        self: *const OwnedPoseidonScheduleV4,
    ) []const poseidon_air.Call {
        return self.calls;
    }

    pub fn liveProviderGeometry(
        self: *const OwnedPoseidonScheduleV4,
    ) Error!LiveProviderGeometryV4 {
        const io_phase = self.phases[@intFromEnum(PhaseV4.io_stream)];
        const result = LiveProviderGeometryV4{
            .role_io_tuple_count = self.source.role_io_tuple_count,
            .role_io_tuple_capacity = self.source.role_io_tuple_capacity,
            .role_io_word_count = std.math.cast(
                u32,
                role_io.HEADER_WORD_COUNT +
                    @as(usize, self.source.role_io_tuple_capacity) *
                        role_io.TUPLE_WORD_COUNT,
            ) orelse return error.ArithmeticOverflow,
            .role_io_call_count = io_phase.call_count,
            .provider_active_row_count = std.math.cast(
                u32,
                self.calls.len,
            ) orelse return error.ArithmeticOverflow,
            .provider_log_size = self.provider_log_size,
            .provider_row_capacity = @as(u32, 1) <<
                @intCast(self.provider_log_size),
        };
        try result.validate();
        return result;
    }
};

pub fn deriveNodePublic(
    comptime Engine: type,
    input: *const input_mod.FreshInputV4(Engine),
    witness: *const role_io.OwnedWitnessV4,
) !node_public_mod.NodePublicV2 {
    const source = try SourceAuthorityV4.seal(Engine, input, witness);
    const result = try node_public_mod.NodePublicV2.initLeaf(
        input.coordinate,
        input.statement_words,
        source.source_digest,
    );
    try result.validateLeafSource(source.source_digest);
    return result;
}

pub const testing = struct {
    pub fn buildFromProjectedAuthority(
        allocator: std.mem.Allocator,
        statement_words: [STATEMENT_WORD_COUNT]u32,
        source: SourceAuthorityV4,
        io_calls: []const poseidon_air.Call,
    ) !OwnedPoseidonScheduleV4 {
        try source.validateStructure();
        if (io_calls.len == 0 or !std.meta.eql(
            source.role_io_commitment,
            role_io.testingDigestFromCalls(io_calls),
        )) return error.EthereumIncrementalFieldScheduleMismatchV4Schema3;
        var result = try buildFromAuthority(
            allocator,
            statement_words,
            source,
            io_calls,
        );
        errdefer result.deinit();
        _ = try result.liveProviderGeometry();
        return result;
    }

    pub fn validateProjectedSchedule(
        schedule: *const OwnedPoseidonScheduleV4,
        statement_words: [STATEMENT_WORD_COUNT]u32,
        source: SourceAuthorityV4,
        io_calls: []const poseidon_air.Call,
    ) !void {
        var expected = try buildFromProjectedAuthority(
            schedule.allocator,
            statement_words,
            source,
            io_calls,
        );
        defer expected.deinit();
        if (!scheduleEql(schedule, &expected))
            return error.EthereumIncrementalFieldScheduleMismatchV4Schema3;
    }
};

fn buildFromAuthority(
    allocator: std.mem.Allocator,
    statement_words: [STATEMENT_WORD_COUNT]u32,
    source: SourceAuthorityV4,
    io_calls: []const poseidon_air.Call,
) Error!OwnedPoseidonScheduleV4 {
    try source.validateStructure();
    if (io_calls.len == 0)
        return error.EthereumIncrementalFieldScheduleMismatchV4Schema3;
    const total_calls = std.math.add(
        usize,
        FIXED_PROVIDER_CALL_COUNT,
        io_calls.len,
    ) catch return error.ArithmeticOverflow;
    const calls = try allocator.alloc(poseidon_air.Call, total_calls);
    errdefer allocator.free(calls);
    const node_public = try node_public_mod.NodePublicV2.initLeaf(
        source.base.coordinate,
        statement_words,
        source.source_digest,
    );
    var result = OwnedPoseidonScheduleV4{
        .allocator = allocator,
        .source = source,
        .node_public = node_public,
        .phases = undefined,
        .calls = calls,
        .provider_log_size = try role_io.providerLogSize(@intCast(total_calls)),
        .identity_sha256 = undefined,
    };
    var cursor: usize = 0;
    @memcpy(result.calls[0..io_calls.len], io_calls);
    result.phases[@intFromEnum(PhaseV4.io_stream)] = .{
        .phase = .io_stream,
        .first_call = 0,
        .call_count = @intCast(io_calls.len),
        .output_digest = source.role_io_commitment,
    };
    cursor += io_calls.len;
    result.phases[@intFromEnum(PhaseV4.statement)] = appendHash(
        result.calls,
        &cursor,
        .statement,
        &statement_words,
        node_public_mod.STATEMENT_DIGEST_DOMAIN,
    );
    const source_preimage = try source.preimage();
    result.phases[@intFromEnum(PhaseV4.source)] = appendHash(
        result.calls,
        &cursor,
        .source,
        &source_preimage,
        SOURCE_DIGEST_DOMAIN,
    );
    const subtree_preimage = subtreePreimage(&node_public);
    result.phases[@intFromEnum(PhaseV4.subtree)] = appendHash(
        result.calls,
        &cursor,
        .subtree,
        &subtree_preimage,
        node_public_mod.SUBTREE_DIGEST_DOMAIN,
    );
    const output_preimage = outputPreimage(&node_public);
    result.phases[@intFromEnum(PhaseV4.output)] = appendHash(
        result.calls,
        &cursor,
        .output,
        &output_preimage,
        node_public_mod.OUTPUT_DIGEST_DOMAIN,
    );
    if (cursor != result.calls.len or
        !std.meta.eql(
            result.phases[@intFromEnum(PhaseV4.statement)].output_digest,
            node_public.statement_digest,
        ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV4.source)].output_digest,
        node_public.source_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV4.subtree)].output_digest,
        node_public.subtree_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV4.output)].output_digest,
        node_public.output_digest,
    )) return error.EthereumIncrementalFieldScheduleMismatchV4Schema3;
    result.identity_sha256 = scheduleIdentity(&result);
    return result;
}

fn validateProjectedFields(value: *const SourceAuthorityV4) Error!void {
    try value.base.validateStructure();
    if (value.format_version != FORMAT_VERSION or
        value.schema_version != SCHEMA_VERSION or
        value.source_kind != SOURCE_KIND_ETHEREUM_INCREMENTAL_LEAF_V4 or
        value.circuit_role != CIRCUIT_ROLE or
        value.base.circuit_role != CIRCUIT_ROLE or
        value.role_io_tuple_capacity == 0 or
        !std.math.isPowerOfTwo(value.role_io_tuple_capacity) or
        value.role_io_tuple_count > value.role_io_tuple_capacity)
    {
        return error.EthereumIncrementalFieldAuthorityMismatchV4Schema3;
    }
    try validateDigest(value.role_io_commitment);
}

fn sourcePreimageUnchecked(
    value: *const SourceAuthorityV4,
) [SOURCE_PREIMAGE_WORD_COUNT]u32 {
    var result: [SOURCE_PREIMAGE_WORD_COUNT]u32 = undefined;
    const base_preimage = value.base.preimage() catch unreachable;
    @memcpy(result[0..base_preimage.len], &base_preimage);
    var at = base_preimage.len;
    result[at] = value.role_io_tuple_count;
    at += 1;
    result[at] = value.role_io_tuple_capacity;
    at += 1;
    @memcpy(result[at..][0..channel.RATE], &value.role_io_commitment);
    at += channel.RATE;
    std.debug.assert(at == result.len);
    return result;
}

fn headerWords(
    value: *const node_public_mod.NodePublicV2,
) [HEADER_WORD_COUNT]u32 {
    return .{
        value.format_version,
        value.schema_version,
        @intFromEnum(value.node_kind),
        value.coordinate.height,
        value.coordinate.index,
        value.coordinate.global_ordinal,
    };
}

fn subtreePreimage(
    value: *const node_public_mod.NodePublicV2,
) [HEADER_WORD_COUNT + 2 * channel.RATE]u32 {
    return headerWords(value) ++ value.statement_digest ++ value.source_digest;
}

fn outputPreimage(
    value: *const node_public_mod.NodePublicV2,
) [HEADER_WORD_COUNT + STATEMENT_WORD_COUNT + 3 * channel.RATE]u32 {
    return headerWords(value) ++ value.statement_words ++
        value.statement_digest ++ value.source_digest ++ value.subtree_digest;
}

fn appendHash(
    calls: []poseidon_air.Call,
    cursor: *usize,
    phase: PhaseV4,
    words: []const u32,
    capacity_tag: u32,
) PhaseRangeV4 {
    const first_call = cursor.*;
    var state = [_]M31{M31.zero()} ** poseidon.WIDTH;
    state[poseidon.WIDTH - 1] = M31.fromCanonical(capacity_tag);
    var filled: usize = 0;
    for (words) |word| absorbWord(calls, cursor, &state, &filled, word);
    absorbWord(calls, cursor, &state, &filled, 1);
    if (filled != 0) appendPermutation(calls, cursor, &state);
    var output: channel.Digest = undefined;
    for (&output, state[0..channel.RATE]) |*destination, word|
        destination.* = word.toU32();
    return .{
        .phase = phase,
        .first_call = @intCast(first_call),
        .call_count = @intCast(cursor.* - first_call),
        .output_digest = output,
    };
}

fn absorbWord(
    calls: []poseidon_air.Call,
    cursor: *usize,
    state: *[poseidon.WIDTH]M31,
    filled: *usize,
    word: u32,
) void {
    std.debug.assert(word < m31.Modulus);
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

fn scheduleEql(
    left: *const OwnedPoseidonScheduleV4,
    right: *const OwnedPoseidonScheduleV4,
) bool {
    if (!std.meta.eql(left.source, right.source) or
        !std.meta.eql(left.node_public, right.node_public) or
        !std.meta.eql(left.phases, right.phases) or
        left.provider_log_size != right.provider_log_size or
        !std.mem.eql(u8, &left.identity_sha256, &right.identity_sha256) or
        left.calls.len != right.calls.len)
    {
        return false;
    }
    for (left.calls, right.calls) |actual, expected|
        if (!std.meta.eql(actual, expected)) return false;
    return true;
}

fn scheduleIdentity(value: *const OwnedPoseidonScheduleV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SCHEDULE_IDENTITY_DOMAIN);
    hashInt(&hash, u32, FORMAT_VERSION);
    hashInt(&hash, u32, SCHEMA_VERSION);
    for (value.source.source_digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, value.provider_log_size);
    hashInt(&hash, u64, value.calls.len);
    for (value.phases) |phase| {
        hashInt(&hash, u8, @intFromEnum(phase.phase));
        hashInt(&hash, u32, phase.first_call);
        hashInt(&hash, u32, phase.call_count);
        for (phase.output_digest) |word| hashInt(&hash, u32, word);
    }
    for (value.calls) |call| {
        for (call.input) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
        hashInt(&hash, u8, @intFromBool(call.narrow_output != null));
        if (call.narrow_output) |word| hashInt(&hash, u32, word);
    }
    return hash.finalResult();
}

fn validateDigest(digest: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus)
            return error.EthereumIncrementalFieldAuthorityMismatchV4Schema3;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.EthereumIncrementalFieldAuthorityMismatchV4Schema3;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn requirePoseidonEngine(comptime Engine: type) void {
    if (Engine.Hasher.Hash != channel.Digest or Engine.Channel != channel.Channel)
        @compileError("stage-102 V4 schema3 requires the q193 Poseidon2 engine");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        @intFromEnum(CIRCUIT_ROLE) != 0 or IO_BINDING_WORD_COUNT != 10 or
        SOURCE_PREIMAGE_WORD_COUNT != 104 or FIXED_PROVIDER_CALL_COUNT != 125 or
        MINIMUM_IO_COMMITMENT_CALL_COUNT != 4 or
        MINIMUM_PROVIDER_ACTIVE_ROW_COUNT != 129 or
        MINIMUM_PROVIDER_LOG_SIZE != 8 or AIR_WORD_COUNT != 450 or
        PRODUCTION_ACTIVATION or CAMPAIGN_PROVIDER_GEOMETRY_FROZEN or
        !SCHEMA2_REMAINS_DIAGNOSTIC or DIGEST_ONLY_CONSTRUCTION)
    {
        @compileError("Ethereum incremental field-public V4 schema3 drifted");
    }
}
