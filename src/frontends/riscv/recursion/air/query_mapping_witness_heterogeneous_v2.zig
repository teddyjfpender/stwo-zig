//! Three-lane query-route authority for heterogeneous recursive children.
//!
//! V1 applies one recursive mapping profile to both child verifiers.  V2 binds
//! VM, left, and right lifting domains, trace-tree heights, and FRI schedules
//! independently while reusing the exact V1 row encoder and typed AIR.

const std = @import("std");
const stwo_core = @import("stwo_core");
const base = @import("query_mapping_witness.zig");
const source = @import("query_mapping_witness_preprocessed_source.zig");
const implementation = @import("query_mapping_witness_preprocessed.zig");
const query_bits_v2 = @import("query_bits_witness_heterogeneous_v2.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");

const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-query-mapping-reference/v2\x00";
const ROWS_DOMAIN =
    "stwo-zig/typed-air/recursion-query-mapping-rows/v2\x00";

pub const Error = base.Error || query_bits_v2.Error || error{
    InvalidHeterogeneousMappingAuthority,
};

pub const Lane = struct {
    verifier_id: u32,
    profile: base.LaneProfile,
};

pub const Reference = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    lanes: [LANE_COUNT]Lane,
    authority_sha256: [32]u8,

    pub fn seal(
        vm: base.LaneProfile,
        left: base.LaneProfile,
        right: base.LaneProfile,
    ) Error!Reference {
        try source.validateProfiles(vm, left);
        try source.validateProfiles(vm, right);
        var result = Reference{
            .lanes = .{
                .{ .verifier_id = base.SEGMENT_VERIFIER_ID, .profile = vm },
                .{ .verifier_id = base.LEFT_RECURSION_VERIFIER_ID, .profile = left },
                .{ .verifier_id = base.RIGHT_RECURSION_VERIFIER_ID, .profile = right },
            },
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = referenceIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Reference) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.lanes[0].verifier_id != base.SEGMENT_VERIFIER_ID or
            self.lanes[1].verifier_id != base.LEFT_RECURSION_VERIFIER_ID or
            self.lanes[2].verifier_id != base.RIGHT_RECURSION_VERIFIER_ID)
        {
            return error.InvalidHeterogeneousMappingAuthority;
        }
        try source.validateProfiles(self.lanes[0].profile, self.lanes[1].profile);
        try source.validateProfiles(self.lanes[0].profile, self.lanes[2].profile);
        if (!std.mem.eql(
            u8,
            &self.authority_sha256,
            &referenceIdentity(self),
        )) return error.InvalidHeterogeneousMappingAuthority;
    }

    /// Derives row 20 from the same three lane profiles retained by row 21.
    /// This is the only compiler path from query routing to query-bit masks;
    /// callers never supply the counts or lifting domains a second time.
    pub fn queryBitsReference(self: *const Reference) Error!query_bits_v2.Reference {
        try self.validate();
        return query_bits_v2.Reference.seal(
            queryBitsProfile(self.lanes[0].profile),
            queryBitsProfile(self.lanes[1].profile),
            queryBitsProfile(self.lanes[2].profile),
        );
    }
};

const Prepared = struct {
    owner: *const Preprocessed,
    reference_sha256: [32]u8,
    authority_sha256: [32]u8,

    fn validateFor(
        self: Prepared,
        preprocessing: *const Preprocessed,
        reference: *const Reference,
    ) Error!void {
        if (self.owner != preprocessing or
            !std.mem.eql(u8, &self.reference_sha256, &reference.authority_sha256) or
            !std.mem.eql(u8, &self.authority_sha256, &preprocessing.authority_sha256))
        {
            return error.InvalidHeterogeneousMappingAuthority;
        }
        try preprocessing.validateAgainstAuthority(reference);
    }
};

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
    ) Error!Preprocessed {
        try reference.validate();
        const row_count = try totalRows(reference);
        const rows = try allocator.alloc(base.Row, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        for (reference.lanes) |retained| try source.fillProfileRows(
            rows,
            &cursor,
            retained.profile,
            retained.verifier_id,
            @intFromBool(retained.verifier_id == base.SEGMENT_VERIFIER_ID),
            @intFromBool(retained.verifier_id != base.SEGMENT_VERIFIER_ID),
        );
        if (cursor != rows.len)
            return error.InvalidHeterogeneousMappingAuthority;
        var result = Preprocessed{
            .allocator = allocator,
            .log_size = try implementation.traceLogSize(row_count),
            .rows = rows,
            .reference_sha256 = reference.authority_sha256,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = rowsIdentity(&result);
        try result.validateAgainst(reference);
        return result;
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        reference: *const Reference,
    ) Error!void {
        try reference.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.rows.len != try totalRows(reference) or
            self.log_size != try implementation.traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_sha256, &reference.authority_sha256) or
            !std.mem.eql(u8, &self.authority_sha256, &rowsIdentity(self)))
        {
            return error.InvalidHeterogeneousMappingAuthority;
        }
    }

    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        reference: *const Reference,
    ) Error!void {
        try self.validateAgainst(reference);
        var cursor: usize = 0;
        for (reference.lanes) |retained| try implementation.validateProfileRows(
            self.rows,
            &cursor,
            retained.profile,
            retained.verifier_id,
            @intFromBool(retained.verifier_id == base.SEGMENT_VERIFIER_ID),
            @intFromBool(retained.verifier_id != base.SEGMENT_VERIFIER_ID),
        );
        if (cursor != self.rows.len)
            return error.InvalidHeterogeneousMappingAuthority;
    }

    pub fn prepare(
        self: *const Preprocessed,
        reference: *const Reference,
    ) Error!Prepared {
        try self.validateAgainstAuthority(reference);
        return .{
            .owner = self,
            .reference_sha256 = reference.authority_sha256,
            .authority_sha256 = self.authority_sha256,
        };
    }

    pub fn computedAuthoritySha256(self: *const Preprocessed) [32]u8 {
        return rowsIdentity(self);
    }

    pub fn validatePrepared(
        self: *const Preprocessed,
        reference: *const Reference,
        prepared: Prepared,
    ) Error!void {
        return prepared.validateFor(self, reference);
    }

    pub fn generatePreprocessedInto(
        self: *const Preprocessed,
        reference: *const Reference,
        prepared: Prepared,
        executor: *const base.Executor,
        columns: *[base.PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try prepared.validateFor(self, reference);
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
        prepared: Prepared,
        executor: *const base.Executor,
        columns: *[base.MAIN_COLUMN_COUNT][]M31,
        witness: base.QueryWitness,
    ) Error!void {
        try prepared.validateFor(self, reference);
        try validateWitness(reference, witness);
        _ = try preflightMain(columns, self, witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, logical_row| {
            const word = implementation.queryWordAssumeValid(row, witness) orelse continue;
            implementation.writeActiveMainRow(columns, logical_row, row, word);
        }
    }
};

fn totalRows(reference: *const Reference) Error!usize {
    var result: usize = 0;
    for (reference.lanes) |retained| result = std.math.add(
        usize,
        result,
        try source.laneRows(retained.profile),
    ) catch return error.ArithmeticOverflow;
    return result;
}

fn queryBitsProfile(profile: base.LaneProfile) query_bits_v2.LaneProfile {
    return .{
        .query_count = profile.query_count,
        .lifting_log_size = profile.lifting_log_size,
        .trace_tree_count = @intCast(profile.tree_heights.len),
        .fri_layer_count = @intCast(profile.fri_fold_widths.len),
    };
}

fn validateWitness(reference: *const Reference, witness: base.QueryWitness) Error!void {
    switch (witness) {
        .segment_leaf => |queries| if (queries.len != reference.lanes[0].profile.query_count)
            return error.QueryCountMismatch,
        .binary_node => |queries| if (queries.left.len != reference.lanes[1].profile.query_count or
            queries.right.len != reference.lanes[2].profile.query_count)
        {
            return error.QueryCountMismatch;
        },
        .empty_leaf => {},
    }
}

fn preflightMain(
    columns: *const [base.MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    witness: base.QueryWitness,
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
        for (protected) |item| if (destination.start < item.end and
            item.start < destination.end) return error.AliasedDestination;
        if (destination.start < rows.end and rows.start < destination.end)
            return error.AliasedInput;
    }
    switch (witness) {
        .segment_leaf => |queries| try implementation.rejectSourceAlias(destinations, queries),
        .binary_node => |queries| {
            try implementation.rejectSourceAlias(destinations, queries.left);
            try implementation.rejectSourceAlias(destinations, queries.right);
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
        source.hashProfile(&hash, retained.profile);
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
        @compileError("heterogeneous query-mapping contract drifted");
}
