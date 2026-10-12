//! Allocation-free dormant V6 witness source for recursion roster row 17.
//!
//! Cold preparation validates and snapshots the exact verifier-owned VM
//! schedule.  Hot materialization accepts only that immutable snapshot, checks
//! it completely before the first store, and writes a fixed 128-row trace plus
//! one verifier-schedule-derived active prefix and its exact relation events.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;

const relation = @import("../../air/lang/relation.zig");
const air = @import("vm_public_logup_control_v6.zig");
const schedule = @import("verifier_schedule.zig");
const universal = @import("universal_challenges.zig");

pub const FORMAT_VERSION: u16 = 6;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROOF_ACTIVATION = false;
pub const ROSTER_ROW: u8 = 17;
pub const VERIFIER_ID: u32 = 0;
pub const MIN_PUBLIC_TERM_COUNT = air.MIN_PUBLIC_TERM_COUNT;
pub const MAX_PUBLIC_TERM_COUNT = air.MAX_PUBLIC_TERM_COUNT;
pub const TRACE_LOG_SIZE = air.TRACE_LOG_SIZE;
pub const TRACE_ROW_COUNT = air.TRACE_ROW_COUNT;
pub const PUBLIC_PHASE_FIRST_SEQUENCE: u32 = 19;
pub const ACCUMULATE_TAG: u32 = 11;
pub const GLOBAL_ASSERT_TAG: u32 = 12;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;

pub const Error = schedule.Error || error{
    AliasedDestination,
    AssertionBeforeAllTerms,
    DestinationLengthMismatch,
    DuplicateGlobalAssertion,
    InvalidControlRelay,
    InvalidPublicTermCount,
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
pub const ControlRelayV6 = struct {
    circuit_id: u32 = air.CONTROL_RELAY_CIRCUIT_ID,
    node_id: u32 = air.CONTROL_RELAY_NODE_ID,
    value: M31,

    pub fn validate(self: ControlRelayV6) Error!void {
        if (self.circuit_id != air.CONTROL_RELAY_CIRCUIT_ID or
            self.node_id != air.CONTROL_RELAY_NODE_ID)
        {
            return error.InvalidControlRelay;
        }
    }
};

pub const RowV6 = struct {
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    control_mask: u32,
    control_value: M31,

    pub fn values(self: RowV6) airRow() {
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

const ZERO_ROW = RowV6{
    .verifier_id = 0,
    .sequence = 0,
    .tag = 0,
    .args = .{0} ** 4,
    .control_mask = 0,
    .control_value = M31.zero(),
};

pub const PreparedV6 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    schedule_format_version: u16 = schedule.FORMAT_VERSION,
    schedule_digest: [8]u32,
    protocol_id: [8]u32,
    shape_id: [8]u32,
    relay: ControlRelayV6,
    term_count: u16,
    rows: [TRACE_ROW_COUNT]RowV6,
    identity: [32]u8,

    /// Allocation-free integrity check used by the hot writer.
    pub fn validate(self: *const PreparedV6) Error!void {
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
        const count: usize = self.term_count;
        const logical_count = air.logicalRowCount(count) catch return error.InvalidPublicTermCount;

        for (self.rows[0..count], 0..) |row, term| {
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
        const assertion = self.rows[count];
        if (assertion.verifier_id != VERIFIER_ID or
            assertion.sequence != PUBLIC_PHASE_FIRST_SEQUENCE + @as(u32, @intCast(count)) or
            assertion.tag != GLOBAL_ASSERT_TAG or
            !allZero(&assertion.args) or
            assertion.control_mask != 1 or
            !assertion.control_value.eql(self.relay.value) or
            !std.mem.eql(u8, &preparedIdentity(self), &self.identity))
        {
            return error.InvalidPreparedSource;
        }
        for (self.rows[logical_count..]) |row| {
            if (!std.meta.eql(row, ZERO_ROW)) return error.InvalidPreparedSource;
        }
    }

    /// Cold revalidation against the original schedule and relay custody.
    pub fn validateAgainst(
        self: *const PreparedV6,
        plan: *const schedule.Plan,
        relay: *const ControlRelayV6,
    ) Error!void {
        const expected = try derivePrepared(plan, relay);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidPreparedSource;
    }
};

pub const RelationEventV6 = struct {
    roster_row: u8,
    logical_row: u32,
    event_ordinal: u8,
    domain: relation.Domain,
    role: relation.Role,
    multiplicity: u32,
    arity: u8,
    tuple: [universal.MAX_ARITY]M31,

    pub fn validate(self: RelationEventV6) Error!void {
        if (self.roster_row != ROSTER_ROW or
            self.logical_row >= TRACE_ROW_COUNT or
            self.role != .consume or self.multiplicity != 1 or
            self.arity != relation.universalDescriptor(self.domain).arity)
        {
            return error.InvalidRelationEvent;
        }
        const expected_shape = if (self.event_ordinal == 0)
            self.domain == .recursion_step and self.arity == 7
        else if (self.event_ordinal == 1)
            self.domain == .recursion_wire and self.arity == 6 and
                self.logical_row >= MIN_PUBLIC_TERM_COUNT and
                self.logical_row <= MAX_PUBLIC_TERM_COUNT
        else
            false;
        if (!expected_shape) return error.InvalidRelationEvent;
        for (self.tuple[self.arity..]) |word| if (!word.isZero())
            return error.InvalidRelationEvent;
    }
};

pub const DestinationsV6 = struct {
    main: [air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    preprocessed: [air.PREPROCESSED_COLUMN_COUNT][]M31,
    logical_rows: []airRow(),
    relation_events: []RelationEventV6,
};

pub fn preflight(
    plan: *const schedule.Plan,
    relay: *const ControlRelayV6,
) Error!PreparedV6 {
    return derivePrepared(plan, relay);
}

pub fn prepareInto(
    destination: *PreparedV6,
    plan: *const schedule.Plan,
    relay: *const ControlRelayV6,
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
    prepared: *const PreparedV6,
    destinations: DestinationsV6,
) Error!void {
    prepared.validate() catch return error.InvalidPreparedSource;
    try validateDestinationGeometry(destinations, prepared.term_count);
    try rejectDestinationAliases(destinations, prepared);

    const zero = M31.zero();
    for (destinations.main) |column| @memset(column, zero);
    for (destinations.preprocessed) |column| @memset(column, zero);
    const zero_row = [_]M31{M31.zero()} ** air.LOGICAL_INPUT_COUNT;
    for (destinations.logical_rows) |*row| row.* = zero_row;

    var event_at: usize = 0;
    for (prepared.rows[0 .. @as(usize, prepared.term_count) + 1], 0..) |row, logical_row| {
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
    relay: *const ControlRelayV6,
) Error!PreparedV6 {
    try plan.validate();
    try relay.validate();
    if (plan.schema != .vm or
        plan.spec.schema != .vm or
        plan.spec.relation_challenge_count != schedule.VM_PROGRAM_SPEC_V1.relation_challenge_count or
        plan.spec.air_instruction_count != schedule.VM_PROGRAM_SPEC_V1.air_instruction_count or
        plan.spec.relation_closure_count != schedule.VM_PROGRAM_SPEC_V1.relation_closure_count)
        return error.InvalidPlanProfile;
    const term_count: usize = plan.spec.public_logup_term_count;
    _ = air.logicalRowCount(term_count) catch return error.InvalidPublicTermCount;
    try validateCanonicalDigest(plan.authority_digest);
    try validateCanonicalDigest(plan.protocol_id);
    try validateCanonicalDigest(plan.shape_id);

    var result = PreparedV6{
        .schedule_digest = plan.authority_digest,
        .protocol_id = plan.protocol_id,
        .shape_id = plan.shape_id,
        .relay = relay.*,
        .term_count = @intCast(term_count),
        .rows = [_]RowV6{ZERO_ROW} ** TRACE_ROW_COUNT,
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
                if (row_at >= term_count)
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
                if (row_at != term_count)
                    return error.AssertionBeforeAllTerms;
                if (sequence != PUBLIC_PHASE_FIRST_SEQUENCE + @as(u32, @intCast(term_count)))
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
    if (row_at != term_count + 1) return error.TermCountMismatch;
    result.identity = preparedIdentity(&result);
    try result.validate();
    return result;
}

fn rowFromStep(
    sequence: usize,
    encoded: schedule.EncodedStep,
    control_mask: u32,
    control_value: M31,
) Error!RowV6 {
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

fn stepEvent(row: RowV6, logical_row: usize) RelationEventV6 {
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

fn controlEvent(row: RowV6, logical_row: usize) RelationEventV6 {
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

fn validateDestinationGeometry(destinations: DestinationsV6, term_count: usize) Error!void {
    for (destinations.main) |column| if (column.len != TRACE_ROW_COUNT)
        return error.DestinationLengthMismatch;
    for (destinations.preprocessed) |column| if (column.len != TRACE_ROW_COUNT)
        return error.DestinationLengthMismatch;
    if (destinations.logical_rows.len != TRACE_ROW_COUNT or
        destinations.relation_events.len != (air.activeRelationEventCount(term_count) catch
            return error.InvalidPublicTermCount))
    {
        return error.DestinationLengthMismatch;
    }
}

fn rejectDestinationAliases(
    destinations: DestinationsV6,
    prepared: *const PreparedV6,
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

fn preparedIdentity(prepared: *const PreparedV6) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/recursion/vm-public-logup-control-v6\x00");
    hashInt(&hash, u16, prepared.format_version);
    hashInt(&hash, u16, prepared.schema_version);
    hashInt(&hash, u16, prepared.schedule_format_version);
    for (prepared.schedule_digest) |word| hashInt(&hash, u32, word);
    for (prepared.protocol_id) |word| hashInt(&hash, u32, word);
    for (prepared.shape_id) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, prepared.relay.circuit_id);
    hashInt(&hash, u32, prepared.relay.node_id);
    hashInt(&hash, u32, prepared.relay.value.toU32());
    hashInt(&hash, u16, prepared.term_count);
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
    if (MIN_PUBLIC_TERM_COUNT != 70 or MAX_PUBLIC_TERM_COUNT != 127 or
        TRACE_ROW_COUNT != 128 or
        HOT_HEAP_ALLOCATIONS != 0 or air.LOGICAL_INPUT_COUNT != 10)
    {
        @compileError("VM public-LogUp V6 witness geometry drifted");
    }
}
