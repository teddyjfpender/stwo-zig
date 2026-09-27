//! Lane-specific trace-Merkle authority for transparent recursive children.
//!
//! V1 authenticates one recursive trace profile and applies it to both child
//! lanes.  Dynamic native child proofs can share the same PCS security policy
//! while committing different column inventories.  V2 therefore retains the
//! left and right tree profiles and verifier schedules independently.  It
//! reuses the exact V1 row encoder and AIR binding; no V1 identity changes.

const std = @import("std");
const stwo_core = @import("stwo_core");
const base = @import("trace_merkle_witness.zig");
const contract = @import("trace_merkle_witness_contract.zig");
const implementation = @import("trace_merkle_witness_preprocessed.zig");
const component = @import("trace_merkle.zig");
const query_mapping_v2 = @import("query_mapping_witness_heterogeneous_v2.zig");
const schedule = @import("verifier_schedule.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");

const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-trace-merkle-reference/v2\x00";
const ROWS_DOMAIN =
    "stwo-zig/typed-air/recursion-trace-merkle-rows/v2\x00";

pub const Error = base.Error || query_mapping_v2.Error || error{
    InvalidHeterogeneousTraceAuthority,
};

pub const Lane = struct {
    verifier_id: u32,
    profile: base.LaneProfile,
    control_start: u32,
    schedule_digest: [8]u32,
};

/// Borrowed, pointer-free-in-identity reference to one VM capacity lane and
/// two independently compiled recursive verifier lanes.
pub const Reference = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    lanes: [LANE_COUNT]Lane,
    authority_sha256: [32]u8,

    pub fn seal(
        vm: base.LaneProfile,
        vm_plan: *const schedule.Plan,
        left: base.LaneProfile,
        left_plan: *const schedule.Plan,
        right: base.LaneProfile,
        right_plan: *const schedule.Plan,
    ) Error!Reference {
        try contract.validateProfiles(vm, left);
        try contract.validateProfiles(vm, right);
        var result = Reference{
            .lanes = .{
                try lane(vm, vm_plan, base.SEGMENT_VERIFIER_ID, .vm),
                try lane(left, left_plan, base.LEFT_RECURSION_VERIFIER_ID, left_plan.schema),
                try lane(right, right_plan, base.RIGHT_RECURSION_VERIFIER_ID, right_plan.schema),
            },
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = referenceIdentity(&result);
        try result.validateAgainst(vm_plan, left_plan, right_plan);
        return result;
    }

    pub fn validateAgainst(
        self: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidHeterogeneousTraceAuthority;
        }
        try contract.validateProfiles(self.lanes[0].profile, self.lanes[1].profile);
        try contract.validateProfiles(self.lanes[0].profile, self.lanes[2].profile);
        const plans = [LANE_COUNT]*const schedule.Plan{
            vm_plan,
            left_plan,
            right_plan,
        };
        if (vm_plan.schema != .vm)
            return error.InvalidHeterogeneousTraceAuthority;
        const schemas = [LANE_COUNT]schedule.Schema{
            .vm,
            left_plan.schema,
            right_plan.schema,
        };
        const ids = [LANE_COUNT]u32{
            base.SEGMENT_VERIFIER_ID,
            base.LEFT_RECURSION_VERIFIER_ID,
            base.RIGHT_RECURSION_VERIFIER_ID,
        };
        for (self.lanes, plans, schemas, ids) |retained, plan, schema, verifier_id| {
            const expected = try lane(retained.profile, plan, verifier_id, schema);
            if (!std.meta.eql(expected, retained))
                return error.InvalidHeterogeneousTraceAuthority;
        }
        if (!std.mem.eql(
            u8,
            &self.authority_sha256,
            &referenceIdentity(self),
        )) return error.InvalidHeterogeneousTraceAuthority;
    }

    /// Query routing does not depend on committed column count.  It still
    /// must match both lanes' query count, lifting domain, tree heights, and
    /// fold schedule exactly.
    pub fn validateQueryMapping(
        self: *const Reference,
        mapping: *const query_mapping_v2.Reference,
    ) Error!void {
        try mapping.validate();
        for (self.lanes, mapping.lanes) |trace_lane, mapping_lane| {
            if (trace_lane.verifier_id != mapping_lane.verifier_id)
                return error.InvalidHeterogeneousTraceAuthority;
            try contract.laneMatchesMapping(trace_lane.profile, mapping_lane.profile);
        }
    }
};

/// Opaque, process-local result of the cold row reconstruction.  The token is
/// deliberately address-bound: it is an execution capability, never part of
/// a proof-visible identity.  Moving or mutating the owner invalidates it.
pub const Prepared = struct {
    owner: *const Preprocessed,
    reference_sha256: [32]u8,
    authority_sha256: [32]u8,

    fn validateFor(
        self: Prepared,
        preprocessing: *const Preprocessed,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
    ) Error!void {
        if (self.owner != preprocessing or
            !std.mem.eql(u8, &self.reference_sha256, &reference.authority_sha256) or
            !std.mem.eql(u8, &self.authority_sha256, &preprocessing.authority_sha256))
        {
            return error.InvalidHeterogeneousTraceAuthority;
        }
        try preprocessing.validateAgainstAuthority(
            reference,
            vm_plan,
            left_plan,
            right_plan,
        );
    }
};

/// Owned row authority.  The direct writers reuse V1's exact row materializer
/// and therefore retain its allocation-free hot path.
pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    log_size: u32,
    rows: []base.Row,
    reference_sha256: [32]u8,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
    ) Error!Preprocessed {
        try reference.validateAgainst(vm_plan, left_plan, right_plan);
        const row_count = try totalRows(reference);
        const log_size = try implementation.traceLogSize(row_count);
        const rows = try allocator.alloc(base.Row, row_count);
        errdefer allocator.free(rows);
        const maximum_columns = maximumColumns(reference);
        const order = try allocator.alloc(u32, maximum_columns);
        defer allocator.free(order);
        var cursor: usize = 0;
        for (reference.lanes) |retained| try implementation.fillLaneRows(
            rows,
            &cursor,
            retained.profile,
            retained.control_start,
            retained.verifier_id,
            @intFromBool(retained.verifier_id == base.SEGMENT_VERIFIER_ID),
            @intFromBool(retained.verifier_id != base.SEGMENT_VERIFIER_ID),
            order,
        );
        if (cursor != rows.len)
            return error.InvalidHeterogeneousTraceAuthority;
        var result = Preprocessed{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .reference_sha256 = reference.authority_sha256,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = rowsIdentity(&result);
        try result.validateAgainst(reference, vm_plan, left_plan, right_plan);
        return result;
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
    ) Error!void {
        try reference.validateAgainst(vm_plan, left_plan, right_plan);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.rows.len != try totalRows(reference) or
            self.log_size != try implementation.traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_sha256, &reference.authority_sha256) or
            !std.mem.eql(u8, &self.authority_sha256, &rowsIdentity(self)))
        {
            return error.InvalidHeterogeneousTraceAuthority;
        }
    }

    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
    ) Error!void {
        try self.validateAgainst(reference, vm_plan, left_plan, right_plan);
        const order = try self.allocator.alloc(u32, maximumColumns(reference));
        defer self.allocator.free(order);
        var cursor: usize = 0;
        for (reference.lanes) |retained| try contract.validateLaneRows(
            self.rows,
            &cursor,
            retained.profile,
            retained.control_start,
            retained.verifier_id,
            @intFromBool(retained.verifier_id == base.SEGMENT_VERIFIER_ID),
            @intFromBool(retained.verifier_id != base.SEGMENT_VERIFIER_ID),
            order,
        );
        if (cursor != self.rows.len)
            return error.InvalidHeterogeneousTraceAuthority;
    }

    /// Mints the only proof-time generation capability after independently
    /// reconstructing every retained row from the trusted plans and profiles.
    pub fn prepare(
        self: *const Preprocessed,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
    ) Error!Prepared {
        try self.validateAgainstAuthority(reference, vm_plan, left_plan, right_plan);
        return .{
            .owner = self,
            .reference_sha256 = reference.authority_sha256,
            .authority_sha256 = self.authority_sha256,
        };
    }

    /// Public recomputation exists for diagnostics and serialized custody; it
    /// is intentionally insufficient to mint `Prepared` after row mutation.
    pub fn computedAuthoritySha256(self: *const Preprocessed) [32]u8 {
        return rowsIdentity(self);
    }

    pub fn validatePrepared(
        self: *const Preprocessed,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
        prepared: Prepared,
    ) Error!void {
        return prepared.validateFor(self, reference, vm_plan, left_plan, right_plan);
    }

    pub fn generatePreprocessedInto(
        self: *const Preprocessed,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
        prepared: Prepared,
        executor: *const base.Executor,
        columns: *[base.PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try prepared.validateFor(self, reference, vm_plan, left_plan, right_plan);
        return direct.generateMainInto(
            M31,
            base.Row,
            base.PREPROCESSED_COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            executor,
            implementation.validateRowDirect,
            implementation.writePreprocessedRow,
        );
    }

    pub fn generateMainInto(
        self: *const Preprocessed,
        reference: *const Reference,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
        prepared: Prepared,
        executor: *const base.Executor,
        columns: *[base.MAIN_COLUMN_COUNT][]M31,
        witness: base.OpeningWitness,
    ) Error!void {
        try prepared.validateFor(self, reference, vm_plan, left_plan, right_plan);
        try validateWitness(reference, witness);
        _ = try preflightMain(columns, self, witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        var state = [_]M31{M31.zero()} ** component.STATE_WIDTH;
        for (self.rows, 0..) |row, logical_row| {
            const opening = implementation.selectOpening(row.verifier_id, witness) orelse
                continue;
            if (row.first == 1) {
                state = [_]M31{M31.zero()} ** component.STATE_WIDTH;
                state[component.STATE_WIDTH - 1] = M31.fromCanonical(base.LEAF_TAG);
            }
            const value = contract.materialize(row, opening, state);
            state = value.output;
            contract.writeMainRow(columns, logical_row, value);
        }
    }
};

fn lane(
    profile: base.LaneProfile,
    plan: *const schedule.Plan,
    verifier_id: u32,
    schema: schedule.Schema,
) Error!Lane {
    return .{
        .verifier_id = verifier_id,
        .profile = profile,
        .control_start = try contract.validatePlan(profile, plan, schema),
        .schedule_digest = plan.authority_digest,
    };
}

fn totalRows(reference: *const Reference) Error!usize {
    var result: usize = 0;
    for (reference.lanes) |retained| result = std.math.add(
        usize,
        result,
        try contract.rowsForLane(retained.profile),
    ) catch return error.ArithmeticOverflow;
    return result;
}

fn maximumColumns(reference: *const Reference) usize {
    var result: usize = 0;
    for (reference.lanes) |retained|
        result = @max(result, contract.maximumTreeColumns(retained.profile));
    return result;
}

fn validateWitness(reference: *const Reference, witness: base.OpeningWitness) Error!void {
    switch (witness) {
        .segment_leaf => |opening| try implementation.validateOpening(
            reference.lanes[0].profile,
            opening,
        ),
        .binary_node => |opening| {
            try implementation.validateOpening(reference.lanes[1].profile, opening.left);
            try implementation.validateOpening(reference.lanes[2].profile, opening.right);
        },
        .empty_leaf => {},
    }
}

fn preflightMain(
    columns: *const [base.MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    witness: base.OpeningWitness,
    executor: *const base.Executor,
) direct.Error!usize {
    if (preprocessing.log_size >= @bitSizeOf(usize))
        return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    var destinations: [base.MAIN_COLUMN_COUNT]implementation.AddressRange = undefined;
    for (columns, 0..) |column, index| {
        if (column.len != size) return error.InvalidTraceShape;
        destinations[index] = try implementation.sliceRange(M31, column);
        for (destinations[0..index]) |previous| {
            if (destinations[index].start < previous.end and
                previous.start < destinations[index].end)
            {
                return error.AliasedDestination;
            }
        }
    }
    const protected = [_]implementation.AddressRange{
        try implementation.objectRange(columns),
        try implementation.objectRange(preprocessing),
        try implementation.objectRange(executor),
    };
    const rows = try implementation.sliceRange(base.Row, preprocessing.rows);
    for (destinations) |destination| {
        for (protected) |source| if (destination.start < source.end and
            source.start < destination.end) return error.AliasedDestination;
        if (destination.start < rows.end and rows.start < destination.end)
            return error.AliasedInput;
    }
    switch (witness) {
        .segment_leaf => |opening| try implementation.rejectOpeningAlias(
            destinations,
            opening,
        ),
        .binary_node => |opening| {
            try implementation.rejectOpeningAlias(destinations, opening.left);
            try implementation.rejectOpeningAlias(destinations, opening.right);
        },
        .empty_leaf => {},
    }
    return size;
}

fn referenceIdentity(reference: *const Reference) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, reference.format_version);
    hashInt(&hash, u16, reference.schema_version);
    for (reference.lanes) |retained| {
        hashInt(&hash, u32, retained.verifier_id);
        contract.hashLane(&hash, retained.profile);
        hashInt(&hash, u32, retained.control_start);
        for (retained.schedule_digest) |word| hashInt(&hash, u32, word);
    }
    return hash.finalResult();
}

fn rowsIdentity(preprocessing: *const Preprocessed) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u16, preprocessing.format_version);
    hashInt(&hash, u16, preprocessing.schema_version);
    hashInt(&hash, u32, preprocessing.log_size);
    hash.update(&preprocessing.reference_sha256);
    hash.update(&implementation.rowsDigest(preprocessing.rows));
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3)
        @compileError("heterogeneous trace-Merkle contract drifted");
}
