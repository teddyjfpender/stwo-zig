//! Allocation-free witness authority for the isolated SegmentV2 row-13 AIR.
//!
//! Cold preparation retains only the value-only authority-hash plan.  The hot
//! writer replays that plan into caller-owned call scratch, validates all
//! sixteen graph-bound native-sum relays, and only then commits logical rows
//! and the active Poseidon/protocol relation events.  Thus attacker-controlled
//! witness storage never becomes preprocessing authority merely because it
//! contains a valid Poseidon permutation.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;

const poseidon2 = @import("../air/memory_commitment/poseidon2.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const relation = @import("../air/lang/relation.zig");
const authority = @import("segment_leaf_authority_v2.zig");
const public_source = @import("segment_public_outer_source_v2.zig");
const air = @import("air/vm_public_claim_hash_authority_v2.zig");
const roster = @import("air/universal_roster.zig");
const universal = @import("air/universal_challenges.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const RELAY_ROW_COUNT: usize = public_source.NATIVE_PUBLIC_SUM_WORD_COUNT;
pub const ROSTER_ROW: u8 = @intFromEnum(roster.Component.vm_public_claim_hash);
pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const COLD_DUPLICATE_SCALAR_PERMUTATIONS_PER_CALL: usize = 1;
pub const HOT_WRITES_FAIL_BEFORE_FIRST_DESTINATION_WRITE = true;
pub const IDENTITY_DOMAIN =
    "stwo-zig/typed-air/segment-public-claim-hash-authority-v2/v1\x00";

pub const LogicalRowV2 = [air.LOGICAL_INPUT_COUNT]M31;
pub const RelationEventV2 = public_source.RelationEventV2;

pub const Error = public_source.Error || authority.Error || error{
    AliasedDestination,
    ArithmeticOverflow,
    BufferLengthMismatch,
    InvalidAuthorityCall,
    InvalidPreparedSource,
    InvalidRelayRow,
};

/// Pointer-free source seal. The canonical calls are deliberately regenerated
/// from `InputsV2` into retained workspace scratch on every hot materialization.
pub const PreparedV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    public_source_id: public_source.Digest,
    public_manifest_id: public_source.Digest,
    statement_authority_id: public_source.Digest,
    receipt_id: public_source.Digest,
    plan: authority.AuthorityHashPoseidonPlanV2,
    logical_row_count: u32,
    log_size: u8,
    identity: [32]u8,

    pub fn init(
        public_prepared: *const public_source.PreparedV2,
        inputs: public_source.InputsV2,
    ) Error!PreparedV2 {
        try public_prepared.validateAgainst(inputs);
        const result = try initFromPublic(public_prepared);
        try result.validateAgainst(public_prepared, inputs);
        return result;
    }

    pub fn initFromPublic(
        public_prepared: *const public_source.PreparedV2,
    ) Error!PreparedV2 {
        try public_prepared.manifest.validate();
        const plan = public_prepared.authority_hash_plan;
        try plan.validate();
        const call_count = try plan.poseidonCallCount();
        const logical_count = @max(RELAY_ROW_COUNT, call_count);
        var result = PreparedV2{
            .public_source_id = public_prepared.source_id,
            .public_manifest_id = public_prepared.manifest.identity,
            .statement_authority_id = plan.statement_authority_id,
            .receipt_id = plan.receipt_id,
            .plan = plan,
            .logical_row_count = std.math.cast(u32, logical_count) orelse
                return error.ArithmeticOverflow,
            .log_size = try traceLogSize(logical_count),
            .identity = undefined,
        };
        result.identity = preparedIdentity(&result);
        try result.validate();
        if (result.logical_row_count !=
            public_prepared.manifest.logical_rows[1] or
            result.log_size != public_prepared.manifest.log_sizes[1] or
            !std.meta.eql(
                result.plan.identity,
                public_prepared.manifest.authority_hash_plan_id,
            )) return error.InvalidPreparedSource;
        return result;
    }

    pub fn callCount(self: *const PreparedV2) Error!usize {
        try self.validate();
        return self.plan.poseidonCallCount();
    }

    pub fn eventCount(self: *const PreparedV2) Error!usize {
        return try checkedAdd(try self.callCount(), 1);
    }

    pub fn validate(self: *const PreparedV2) Error!void {
        try self.plan.validate();
        const calls = try self.plan.poseidonCallCount();
        const logical_count = @max(RELAY_ROW_COUNT, calls);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.logical_row_count != logical_count or
            self.log_size != try traceLogSize(logical_count) or
            !std.meta.eql(
                self.statement_authority_id,
                self.plan.statement_authority_id,
            ) or !std.meta.eql(self.receipt_id, self.plan.receipt_id) or
            allZeroDigest(self.public_source_id) or
            allZeroDigest(self.public_manifest_id) or
            !std.mem.eql(u8, &self.identity, &preparedIdentity(self)))
        {
            return error.InvalidPreparedSource;
        }
    }

    pub fn validateAgainst(
        self: *const PreparedV2,
        public_prepared: *const public_source.PreparedV2,
        inputs: public_source.InputsV2,
    ) Error!void {
        try self.validate();
        try public_prepared.validateAgainst(inputs);
        try self.plan.validateAgainst(
            &inputs.owned_public_data.data,
            inputs.verified_receipt,
            inputs.component_descs,
            inputs.infra_descs,
        );
        if (!std.meta.eql(self.public_source_id, public_prepared.source_id) or
            !std.meta.eql(
                self.public_manifest_id,
                public_prepared.manifest.identity,
            ) or !std.meta.eql(
            self.statement_authority_id,
            public_prepared.statement_authority_id,
        ) or !std.meta.eql(self.receipt_id, public_prepared.receipt_id)) {
            return error.InvalidPreparedSource;
        }
    }

    pub fn productionReady(_: *const PreparedV2) bool {
        return false;
    }
};

pub const RowV2 = struct {
    relay_value: M31,
    row_mask: u32 = 1,
    relay_mask: u32,
    authority_mask: u32,
    bind_mask: u32,
    source_fields: [5]u32,
    arithmetic_circuit_id: u32,
    arithmetic_node_id: u32,
    arithmetic_use_count: u32,
    control_circuit_id: u32,
    control_node_id: u32,
    control_use_count: u32,
    poseidon_tuple: [air.POSEIDON_TUPLE_WIDTH]M31,

    pub fn values(self: RowV2) LogicalRowV2 {
        var result: LogicalRowV2 = undefined;
        result[0] = felt(self.row_mask);
        result[1] = self.relay_value;
        result[2] = felt(self.row_mask);
        result[3] = felt(self.relay_mask);
        result[4] = felt(self.authority_mask);
        result[5] = felt(self.bind_mask);
        for (self.source_fields, 0..) |word, index| result[6 + index] = felt(word);
        result[11] = felt(self.arithmetic_circuit_id);
        result[12] = felt(self.arithmetic_node_id);
        result[13] = felt(self.arithmetic_use_count);
        result[14] = felt(self.control_circuit_id);
        result[15] = felt(self.control_node_id);
        result[16] = felt(self.control_use_count);
        @memcpy(result[17 .. 17 + air.POSEIDON_TUPLE_WIDTH], &self.poseidon_tuple);
        result[result.len - 1] = M31.zero();
        return result;
    }
};

/// Disposable call scratch may change on failure. Logical rows and relation
/// events are byte-for-byte unchanged unless every authority check succeeds.
pub fn writeInto(
    prepared: *const PreparedV2,
    public_prepared: *const public_source.PreparedV2,
    inputs: public_source.InputsV2,
    relays: []const public_source.RelayRowV2,
    call_scratch: []poseidon2_air.Call,
    logical_rows: []LogicalRowV2,
    relation_events: []RelationEventV2,
) Error!void {
    try validateGeometry(
        prepared,
        relays,
        call_scratch,
        logical_rows,
        relation_events,
    );
    try rejectAliases(
        prepared,
        public_prepared,
        inputs,
        relays,
        call_scratch,
        logical_rows,
        relation_events,
    );
    try prepared.validateAgainst(public_prepared, inputs);
    try prepared.plan.appendPoseidonCallsInto(
        call_scratch,
        &inputs.owned_public_data.data,
        inputs.verified_receipt,
        inputs.component_descs,
        inputs.infra_descs,
    );
    try validateRelays(public_prepared, relays);
    for (call_scratch) |call| try validateCall(call);

    const zero_tuple = [_]M31{M31.zero()} ** air.POSEIDON_TUPLE_WIDTH;
    var event_at: usize = 0;
    for (logical_rows, 0..) |*destination, index| {
        const relay_active = index < relays.len;
        const authority_active = index < call_scratch.len;
        const relay = if (relay_active) relays[index] else zeroRelay();
        const poseidon_tuple = if (authority_active)
            tupleForCall(call_scratch[index])
        else
            zero_tuple;
        const row = RowV2{
            .relay_value = relay.value,
            .relay_mask = @intFromBool(relay_active),
            .authority_mask = @intFromBool(authority_active),
            .bind_mask = @intFromBool(index == 0),
            .source_fields = relay.source_fields,
            .arithmetic_circuit_id = relay.arithmetic_circuit_id,
            .arithmetic_node_id = relay.arithmetic_node_id,
            .arithmetic_use_count = relay.arithmetic_use_count,
            .control_circuit_id = relay.control_circuit_id,
            .control_node_id = relay.control_node_id,
            .control_use_count = relay.control_use_count,
            .poseidon_tuple = poseidon_tuple,
        };
        destination.* = row.values();
        if (authority_active) {
            relation_events[event_at] = relationEvent(
                index,
                3,
                .poseidon2_io,
                .request,
                &poseidon_tuple,
            );
            event_at += 1;
        }
        if (index == 0) {
            const bind_tuple = [_]M31{
                M31.zero(),
                M31.zero(),
                M31.one(),
                M31.zero(),
                M31.zero(),
                M31.zero(),
                M31.zero(),
            };
            relation_events[event_at] = relationEvent(
                index,
                4,
                .recursion_step,
                .consume,
                &bind_tuple,
            );
            event_at += 1;
        }
    }
    std.debug.assert(event_at == relation_events.len);
}

fn validateGeometry(
    prepared: *const PreparedV2,
    relays: []const public_source.RelayRowV2,
    calls: []const poseidon2_air.Call,
    logical_rows: []const LogicalRowV2,
    relation_events: []const RelationEventV2,
) Error!void {
    const call_count = try prepared.callCount();
    if (relays.len != RELAY_ROW_COUNT or calls.len != call_count or
        logical_rows.len != prepared.logical_row_count or
        relation_events.len != try prepared.eventCount())
    {
        return error.BufferLengthMismatch;
    }
}

fn validateRelays(
    prepared: *const public_source.PreparedV2,
    relays: []const public_source.RelayRowV2,
) Error!void {
    const expected_values = prepared.public_sums.registers_state.toM31Array() ++
        prepared.public_sums.memory_access.toM31Array() ++
        prepared.public_sums.program_access.toM31Array() ++
        prepared.public_sums.merkle.toM31Array();
    for (relays, expected_values, 0..) |row, expected, index| {
        const expected_node = std.math.add(
            u32,
            prepared.manifest.wire_word_count,
            @intCast(index),
        ) catch return error.ArithmeticOverflow;
        if (row.enabler != 1 or row.source_kind != .publication_bridge or
            row.source_fields[0] != public_source.PUBLICATION_BRIDGE_CIRCUIT_ID or
            row.source_fields[1] != public_source.PUBLICATION_SUM_START + index or
            !allZero(row.source_fields[2..]) or !row.value.eql(expected) or
            row.arithmetic_mask != 1 or
            row.arithmetic_circuit_id != public_source.NATIVE_SUM_CIRCUIT_ID or
            row.arithmetic_node_id != expected_node or
            row.arithmetic_use_count >= m31.Modulus or row.control_mask != 0 or
            row.control_circuit_id != public_source.CONTROL_RELAY_CIRCUIT_ID or
            row.control_node_id != 0 or row.control_use_count != 0)
        {
            return error.InvalidRelayRow;
        }
    }
}

fn validateCall(call: poseidon2_air.Call) Error!void {
    if (call.wide or !call.io or call.narrow_output != null)
        return error.InvalidAuthorityCall;
    for (call.input) |word| if (word >= m31.Modulus)
        return error.InvalidAuthorityCall;
}

fn tupleForCall(call: poseidon2_air.Call) [air.POSEIDON_TUPLE_WIDTH]M31 {
    var input: [poseidon2_air.WIDTH]M31 = undefined;
    for (&input, call.input) |*destination, word|
        destination.* = M31.fromCanonical(word);
    var output = input;
    poseidon2.permute(&output);
    return input ++ output;
}

fn zeroRelay() public_source.RelayRowV2 {
    return .{
        .enabler = 0,
        .source_kind = .publication_bridge,
        .value = M31.zero(),
        .arithmetic_circuit_id = 0,
        .control_circuit_id = 0,
    };
}

fn relationEvent(
    logical_row: usize,
    ordinal: u8,
    domain: relation.Domain,
    role: relation.Role,
    values: []const M31,
) RelationEventV2 {
    var tuple = [_]M31{M31.zero()} ** universal.MAX_ARITY;
    @memcpy(tuple[0..values.len], values);
    return .{
        .roster_row = ROSTER_ROW,
        .logical_row = @intCast(logical_row),
        .event_ordinal = ordinal,
        .domain = domain,
        .role = role,
        .multiplicity = 1,
        .arity = @intCast(values.len),
        .tuple = tuple,
    };
}

fn rejectAliases(
    prepared: *const PreparedV2,
    public_prepared: *const public_source.PreparedV2,
    inputs: public_source.InputsV2,
    relays: []const public_source.RelayRowV2,
    calls: []poseidon2_air.Call,
    rows: []LogicalRowV2,
    events: []RelationEventV2,
) Error!void {
    const call_bytes = std.mem.sliceAsBytes(calls);
    const row_bytes = std.mem.sliceAsBytes(rows);
    const event_bytes = std.mem.sliceAsBytes(events);
    const relay_bytes = std.mem.sliceAsBytes(relays);
    if (overlap(call_bytes, row_bytes) or overlap(call_bytes, event_bytes) or
        overlap(call_bytes, relay_bytes) or overlap(row_bytes, event_bytes) or
        overlap(row_bytes, relay_bytes) or overlap(event_bytes, relay_bytes))
    {
        return error.AliasedDestination;
    }
    const fixed_sources = [_][]const u8{
        std.mem.asBytes(prepared),
        std.mem.asBytes(public_prepared),
        std.mem.asBytes(inputs.statement_source),
        std.mem.asBytes(inputs.owned_public_data),
        std.mem.asBytes(&inputs.owned_public_data.data),
        std.mem.sliceAsBytes(inputs.owned_public_data.data.words()),
        std.mem.asBytes(inputs.publication),
        std.mem.asBytes(inputs.native_public_sums),
        std.mem.asBytes(inputs.verified_receipt),
        std.mem.asBytes(inputs.relations),
        std.mem.sliceAsBytes(inputs.component_descs),
        std.mem.sliceAsBytes(inputs.infra_descs),
        std.mem.asBytes(inputs.vm_plan),
        std.mem.sliceAsBytes(inputs.vm_plan.steps),
    };
    inline for (.{ call_bytes, row_bytes, event_bytes }) |output|
        for (fixed_sources) |source_bytes| if (overlap(output, source_bytes))
            return error.AliasedDestination;
}

fn preparedIdentity(prepared: *const PreparedV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, prepared.format_version);
    hashInt(&hash, u16, prepared.schema_version);
    for (prepared.public_source_id) |word| hashInt(&hash, u32, word);
    for (prepared.public_manifest_id) |word| hashInt(&hash, u32, word);
    for (prepared.statement_authority_id) |word| hashInt(&hash, u32, word);
    for (prepared.receipt_id) |word| hashInt(&hash, u32, word);
    for (prepared.plan.identity) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, prepared.logical_row_count);
    hashInt(&hash, u8, prepared.log_size);
    return hash.finalResult();
}

fn traceLogSize(count: usize) Error!u8 {
    if (count == 0) return error.InvalidPreparedSource;
    const rounded = std.math.ceilPowerOfTwo(usize, count) catch
        return error.ArithmeticOverflow;
    const log_size: u8 = @intCast(@ctz(rounded));
    if (log_size < public_source.MIN_LOG_SIZE or
        log_size > public_source.MAX_LOG_SIZE)
    {
        return error.InvalidPreparedSource;
    }
    return log_size;
}

fn checkedAdd(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

fn allZero(values: []const u32) bool {
    for (values) |value| if (value != 0) return false;
    return true;
}

fn allZeroDigest(value: public_source.Digest) bool {
    return allZero(&value);
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn felt(value: anytype) M31 {
    const canonical: u32 = @intCast(value);
    std.debug.assert(canonical < m31.Modulus);
    return M31.fromCanonical(canonical);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (ROSTER_ROW != 13 or RELAY_ROW_COUNT != 16 or
        air.POSEIDON_TUPLE_WIDTH != 32 or HOT_HEAP_ALLOCATIONS != 0)
    {
        @compileError("SegmentV2 row-13 authority witness geometry drifted");
    }
}
