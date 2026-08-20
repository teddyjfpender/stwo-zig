//! Allocation-free V2 witness source for recursion roster row 17.
//!
//! Cold preparation validates and snapshots the exact verifier-owned VM
//! schedule.  Hot materialization accepts only that immutable snapshot, checks
//! it completely before the first store, and writes a fixed 128-row trace plus
//! the 72 active relation events (71 schedule consumes and one wire consume).

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;

const relation = @import("../../air/lang/relation.zig");
const air = @import("vm_public_logup_control_v2.zig");
const schedule = @import("verifier_schedule.zig");
const universal = @import("universal_challenges.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROSTER_ROW: u8 = 17;
pub const VERIFIER_ID: u32 = 0;
pub const PUBLIC_TERM_COUNT: usize = schedule.VM_PUBLIC_LOGUP_FIXED_TERM_COUNT;
pub const LOGICAL_ROW_COUNT: usize = PUBLIC_TERM_COUNT + 1;
pub const TRACE_LOG_SIZE: u32 = 7;
pub const TRACE_ROW_COUNT: usize = @as(usize, 1) << TRACE_LOG_SIZE;
pub const ACTIVE_RELATION_EVENT_COUNT: usize = LOGICAL_ROW_COUNT + 1;
pub const PUBLIC_PHASE_FIRST_SEQUENCE: u32 = 19;
pub const GLOBAL_ASSERT_SEQUENCE: u32 =
    PUBLIC_PHASE_FIRST_SEQUENCE + @as(u32, @intCast(PUBLIC_TERM_COUNT));
pub const ACCUMULATE_TAG: u32 = 11;
pub const GLOBAL_ASSERT_TAG: u32 = 12;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;

pub const Error = schedule.Error || error{
    AliasedDestination,
    AssertionBeforeAllTerms,
    DestinationLengthMismatch,
    DuplicateGlobalAssertion,
    InvalidControlRelay,
    InvalidPlanProfile,
    InvalidPreparedSource,
    InvalidRelationEvent,
    MissingGlobalAssertion,
    NonCanonicalTerm,
    PublicStepAfterAssertion,
    SequenceOutOfRange,
    TermCountMismatch,
};

/// The already-published control wire.  The fixed circuit and node coordinates
/// make it impossible to accidentally close a neighbouring arithmetic wire.
pub const ControlRelayV2 = struct {
    circuit_id: u32 = air.CONTROL_RELAY_CIRCUIT_ID,
    node_id: u32 = air.CONTROL_RELAY_NODE_ID,
    value: M31,

    pub fn validate(self: ControlRelayV2) Error!void {
        if (self.circuit_id != air.CONTROL_RELAY_CIRCUIT_ID or
            self.node_id != air.CONTROL_RELAY_NODE_ID)
        {
            return error.InvalidControlRelay;
        }
    }
};

pub const RowV2 = struct {
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    control_mask: u32,
    control_value: M31,

    pub fn values(self: RowV2) airRow() {
        return .{
            self.control_value,
            M31.one(),
            felt(self.control_mask),
            felt(self.verifier_id),
            felt(self.sequence),
            felt(self.tag),
            felt(self.args[0]),
            felt(self.args[1]),
            felt(self.args[2]),
            felt(self.args[3]),
        };
    }
};

pub const PreparedV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    schedule_format_version: u16 = schedule.FORMAT_VERSION,
    schedule_digest: [8]u32,
    protocol_id: [8]u32,
    shape_id: [8]u32,
    relay: ControlRelayV2,
    rows: [LOGICAL_ROW_COUNT]RowV2,
    identity: [32]u8,

    /// Allocation-free integrity check used by the hot writer.
    pub fn validate(self: *const PreparedV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.schedule_format_version != schedule.FORMAT_VERSION)
        {
            return error.InvalidPreparedSource;
        }
        try self.relay.validate();
        try validateCanonicalDigest(self.schedule_digest);
        try validateCanonicalDigest(self.protocol_id);
        try validateCanonicalDigest(self.shape_id);

        for (self.rows[0..PUBLIC_TERM_COUNT], 0..) |row, term| {
            if (row.verifier_id != VERIFIER_ID or
                row.sequence != PUBLIC_PHASE_FIRST_SEQUENCE +
                    @as(u32, @intCast(term)) or
                row.tag != ACCUMULATE_TAG or
                row.args[0] != term or
                !allZero(row.args[1..]) or
                row.control_mask != 0 or
                !row.control_value.isZero())
            {
                return error.InvalidPreparedSource;
            }
        }
        const assertion = self.rows[PUBLIC_TERM_COUNT];
        if (assertion.verifier_id != VERIFIER_ID or
            assertion.sequence != GLOBAL_ASSERT_SEQUENCE or
            assertion.tag != GLOBAL_ASSERT_TAG or
            !allZero(&assertion.args) or
            assertion.control_mask != 1 or
            !assertion.control_value.eql(self.relay.value) or
            !std.mem.eql(u8, &preparedIdentity(self), &self.identity))
        {
            return error.InvalidPreparedSource;
        }
    }

    /// Cold revalidation against the original schedule and relay custody.
    pub fn validateAgainst(
        self: *const PreparedV2,
        plan: *const schedule.Plan,
        relay: *const ControlRelayV2,
    ) Error!void {
        const expected = try derivePrepared(plan, relay);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidPreparedSource;
    }
};

pub const RelationEventV2 = struct {
    roster_row: u8,
    logical_row: u32,
    event_ordinal: u8,
    domain: relation.Domain,
    role: relation.Role,
    multiplicity: u32,
    arity: u8,
    tuple: [universal.MAX_ARITY]M31,

    pub fn validate(self: RelationEventV2) Error!void {
        if (self.roster_row != ROSTER_ROW or
            self.logical_row >= LOGICAL_ROW_COUNT or
            self.role != .consume or self.multiplicity != 1 or
            self.arity != relation.universalDescriptor(self.domain).arity)
        {
            return error.InvalidRelationEvent;
        }
        const expected_shape = if (self.event_ordinal == 0)
            self.domain == .recursion_step and self.arity == 7
        else if (self.event_ordinal == 1)
            self.domain == .recursion_wire and self.arity == 6 and
                self.logical_row == PUBLIC_TERM_COUNT
        else
            false;
        if (!expected_shape) return error.InvalidRelationEvent;
        for (self.tuple[self.arity..]) |word| if (!word.isZero())
            return error.InvalidRelationEvent;
    }
};

pub const DestinationsV2 = struct {
    main: [air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    preprocessed: [air.PREPROCESSED_COLUMN_COUNT][]M31,
    logical_rows: []airRow(),
    relation_events: []RelationEventV2,
};

pub fn preflight(
    plan: *const schedule.Plan,
    relay: *const ControlRelayV2,
) Error!PreparedV2 {
    return derivePrepared(plan, relay);
}

pub fn prepareInto(
    destination: *PreparedV2,
    plan: *const schedule.Plan,
    relay: *const ControlRelayV2,
) Error!void {
    const output = std.mem.asBytes(destination);
    if (overlap(output, std.mem.asBytes(plan)) or
        overlap(output, std.mem.sliceAsBytes(plan.steps)) or
        overlap(output, std.mem.asBytes(relay)))
    {
        return error.AliasedDestination;
    }
    const staged = try derivePrepared(plan, relay);
    destination.* = staged;
}

/// Exact-size, failure-atomic and allocation-free hot materialization.
pub fn writeInto(
    prepared: *const PreparedV2,
    destinations: DestinationsV2,
) Error!void {
    try validateDestinationGeometry(destinations);
    try rejectDestinationAliases(destinations, prepared);
    prepared.validate() catch return error.InvalidPreparedSource;

    const zero = M31.zero();
    for (destinations.main) |column| @memset(column, zero);
    for (destinations.preprocessed) |column| @memset(column, zero);
    const zero_row = [_]M31{M31.zero()} ** air.LOGICAL_INPUT_COUNT;
    for (destinations.logical_rows) |*row| row.* = zero_row;

    var event_at: usize = 0;
    for (prepared.rows, 0..) |row, logical_row| {
        const values = row.values();
        destinations.main[0][logical_row] = values[0];
        inline for (0..air.PREPROCESSED_COLUMN_COUNT) |column|
            destinations.preprocessed[column][logical_row] = values[1 + column];
        destinations.logical_rows[logical_row] = values;

        destinations.relation_events[event_at] = stepEvent(row, logical_row);
        event_at += 1;
        if (row.control_mask == 1) {
            destinations.relation_events[event_at] = controlEvent(row, logical_row);
            event_at += 1;
        }
    }
    std.debug.assert(event_at == destinations.relation_events.len);
}

fn derivePrepared(
    plan: *const schedule.Plan,
    relay: *const ControlRelayV2,
) Error!PreparedV2 {
    try plan.validate();
    try relay.validate();
    if (plan.schema != .vm or !std.meta.eql(plan.spec, schedule.VM_PROGRAM_SPEC_V1))
        return error.InvalidPlanProfile;
    try validateCanonicalDigest(plan.authority_digest);
    try validateCanonicalDigest(plan.protocol_id);
    try validateCanonicalDigest(plan.shape_id);

    var result = PreparedV2{
        .schedule_digest = plan.authority_digest,
        .protocol_id = plan.protocol_id,
        .shape_id = plan.shape_id,
        .relay = relay.*,
        .rows = undefined,
        .identity = undefined,
    };
    var row_at: usize = 0;
    var asserted = false;
    var bind_protocol_count: usize = 0;
    for (plan.steps, 0..) |step, sequence| {
        switch (step) {
            .bind_protocol => {
                bind_protocol_count += 1;
                if (sequence != 0) return error.InvalidPlanProfile;
            },
            .accumulate_public_logup_term => |item| {
                if (asserted) return error.PublicStepAfterAssertion;
                if (row_at >= PUBLIC_TERM_COUNT)
                    return error.TermCountMismatch;
                if (item.term != row_at) return error.NonCanonicalTerm;
                const expected_sequence = PUBLIC_PHASE_FIRST_SEQUENCE +
                    @as(u32, @intCast(row_at));
                if (sequence != expected_sequence)
                    return error.InvalidPlanProfile;
                const encoded = step.encode();
                result.rows[row_at] = try rowFromStep(
                    sequence,
                    encoded,
                    0,
                    M31.zero(),
                );
                row_at += 1;
            },
            .assert_global_logup_zero => {
                if (asserted) return error.DuplicateGlobalAssertion;
                if (row_at != PUBLIC_TERM_COUNT)
                    return error.AssertionBeforeAllTerms;
                if (sequence != GLOBAL_ASSERT_SEQUENCE)
                    return error.InvalidPlanProfile;
                const encoded = step.encode();
                result.rows[row_at] = try rowFromStep(
                    sequence,
                    encoded,
                    1,
                    relay.value,
                );
                row_at += 1;
                asserted = true;
            },
            else => {},
        }
    }
    if (bind_protocol_count != 1) return error.InvalidPlanProfile;
    if (!asserted) return error.MissingGlobalAssertion;
    if (row_at != LOGICAL_ROW_COUNT) return error.TermCountMismatch;
    result.identity = preparedIdentity(&result);
    try result.validate();
    return result;
}

fn rowFromStep(
    sequence: usize,
    encoded: schedule.EncodedStep,
    control_mask: u32,
    control_value: M31,
) Error!RowV2 {
    const sequence_u32 = std.math.cast(u32, sequence) orelse
        return error.SequenceOutOfRange;
    if (sequence_u32 >= m31.Modulus or encoded.tag >= m31.Modulus)
        return error.SequenceOutOfRange;
    for (encoded.args) |arg| if (arg >= m31.Modulus)
        return error.SequenceOutOfRange;
    return .{
        .verifier_id = VERIFIER_ID,
        .sequence = sequence_u32,
        .tag = encoded.tag,
        .args = encoded.args,
        .control_mask = control_mask,
        .control_value = control_value,
    };
}

fn stepEvent(row: RowV2, logical_row: usize) RelationEventV2 {
    var tuple = [_]M31{M31.zero()} ** universal.MAX_ARITY;
    const values = [_]M31{
        felt(row.verifier_id),
        felt(row.sequence),
        felt(row.tag),
        felt(row.args[0]),
        felt(row.args[1]),
        felt(row.args[2]),
        felt(row.args[3]),
    };
    @memcpy(tuple[0..values.len], &values);
    return .{
        .roster_row = ROSTER_ROW,
        .logical_row = @intCast(logical_row),
        .event_ordinal = 0,
        .domain = .recursion_step,
        .role = .consume,
        .multiplicity = 1,
        .arity = values.len,
        .tuple = tuple,
    };
}

fn controlEvent(row: RowV2, logical_row: usize) RelationEventV2 {
    var tuple = [_]M31{M31.zero()} ** universal.MAX_ARITY;
    const values = [_]M31{
        felt(air.CONTROL_RELAY_CIRCUIT_ID),
        felt(air.CONTROL_RELAY_NODE_ID),
        row.control_value,
        M31.zero(),
        M31.zero(),
        M31.zero(),
    };
    @memcpy(tuple[0..values.len], &values);
    return .{
        .roster_row = ROSTER_ROW,
        .logical_row = @intCast(logical_row),
        .event_ordinal = 1,
        .domain = .recursion_wire,
        .role = .consume,
        .multiplicity = 1,
        .arity = values.len,
        .tuple = tuple,
    };
}

fn validateDestinationGeometry(destinations: DestinationsV2) Error!void {
    for (destinations.main) |column| if (column.len != TRACE_ROW_COUNT)
        return error.DestinationLengthMismatch;
    for (destinations.preprocessed) |column| if (column.len != TRACE_ROW_COUNT)
        return error.DestinationLengthMismatch;
    if (destinations.logical_rows.len != TRACE_ROW_COUNT or
        destinations.relation_events.len != ACTIVE_RELATION_EVENT_COUNT)
    {
        return error.DestinationLengthMismatch;
    }
}

fn rejectDestinationAliases(
    destinations: DestinationsV2,
    prepared: *const PreparedV2,
) Error!void {
    var outputs: [
        air.PHYSICAL_MAIN_COLUMN_COUNT +
            air.PREPROCESSED_COLUMN_COUNT + 2
    ][]u8 = undefined;
    var at: usize = 0;
    for (destinations.main) |column| {
        outputs[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    for (destinations.preprocessed) |column| {
        outputs[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    outputs[at] = std.mem.sliceAsBytes(destinations.logical_rows);
    at += 1;
    outputs[at] = std.mem.sliceAsBytes(destinations.relation_events);
    at += 1;
    std.debug.assert(at == outputs.len);

    const prepared_bytes = std.mem.asBytes(prepared);
    for (outputs, 0..) |left, left_index| {
        if (overlap(left, prepared_bytes)) return error.AliasedDestination;
        for (outputs[left_index + 1 ..]) |right| if (overlap(left, right))
            return error.AliasedDestination;
    }
}

fn preparedIdentity(prepared: *const PreparedV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/recursion/vm-public-logup-control-v2\x00");
    hashInt(&hash, u16, prepared.format_version);
    hashInt(&hash, u16, prepared.schema_version);
    hashInt(&hash, u16, prepared.schedule_format_version);
    for (prepared.schedule_digest) |word| hashInt(&hash, u32, word);
    for (prepared.protocol_id) |word| hashInt(&hash, u32, word);
    for (prepared.shape_id) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, prepared.relay.circuit_id);
    hashInt(&hash, u32, prepared.relay.node_id);
    hashInt(&hash, u32, prepared.relay.value.toU32());
    for (prepared.rows) |row| {
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.sequence);
        hashInt(&hash, u32, row.tag);
        for (row.args) |arg| hashInt(&hash, u32, arg);
        hashInt(&hash, u32, row.control_mask);
        hashInt(&hash, u32, row.control_value.toU32());
    }
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn validateCanonicalDigest(value: [8]u32) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidPreparedSource;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidPreparedSource;
}

fn allZero(values: []const u32) bool {
    return std.mem.allEqual(u32, values, 0);
}

fn felt(value: u32) M31 {
    std.debug.assert(value < m31.Modulus);
    return M31.fromCanonical(value);
}

fn airRow() type {
    return [air.LOGICAL_INPUT_COUNT]M31;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (PUBLIC_TERM_COUNT != 70 or LOGICAL_ROW_COUNT != 71 or
        TRACE_ROW_COUNT != 128 or ACTIVE_RELATION_EVENT_COUNT != 72 or
        HOT_HEAP_ALLOCATIONS != 0 or air.LOGICAL_INPUT_COUNT != 10)
    {
        @compileError("VM public-LogUp V2 witness geometry drifted");
    }
}
