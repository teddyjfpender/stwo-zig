//! Internal shard of binary_fri_outer_bundle.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_bundle_adapters_for_manifest.zig");

const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const source_mod = dependency_0.source_mod;
const digest = dependency_0.digest;
const logup = dependency_0.logup;
const poseidon_air = dependency_0.poseidon_air;
const shared_provider = dependency_0.shared_provider;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const PROTOCOL_SUBSTRATE_ONLY = dependency_0.PROTOCOL_SUBSTRATE_ONLY;
const FIRST_ROW = dependency_0.FIRST_ROW;
const ROW_COUNT = dependency_0.ROW_COUNT;
const PREPROCESSED_COLUMNS_PER_ROW = dependency_0.PREPROCESSED_COLUMNS_PER_ROW;
const MAIN_COLUMNS_PER_ROW = dependency_0.MAIN_COLUMNS_PER_ROW;
const INTERACTION_COLUMNS_PER_ROW = dependency_0.INTERACTION_COLUMNS_PER_ROW;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const INTERACTION_COLUMN_COUNT = dependency_0.INTERACTION_COLUMN_COUNT;
const BUNDLE_ID_DOMAIN = dependency_0.BUNDLE_ID_DOMAIN;
const Claims = dependency_0.Claims;
const DomainAudits = dependency_0.DomainAudits;

pub fn bindOwnedColumns(
    comptime manifest_contract: type,
    comptime tree: usize,
    comptime total: usize,
    comptime counts: [ROW_COUNT]usize,
    logs: [ROW_COUNT]u32,
    manifest: *const manifest_contract.Manifest,
    destination: [][]M31,
) ![total][]M31 {
    try manifest.validate();
    const expected_total = switch (tree) {
        manifest_contract.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_contract.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_contract.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => return error.InvalidTraceShape,
    };
    if (destination.len != expected_total) return error.InvalidTraceShape;
    var result: [total][]M31 = undefined;
    var at: usize = 0;
    inline for (counts, logs, FIRST_ROW..) |count, log_size, row_index| {
        const row: manifest_contract.ComponentKey = @enumFromInt(row_index);
        const placement = try manifest.placement(row);
        const actual_count: usize = switch (tree) {
            manifest_contract.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
            manifest_contract.MAIN_TREE_INDEX => placement.geometry.main_columns,
            manifest_contract.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
            else => unreachable,
        };
        const offset: usize = switch (tree) {
            manifest_contract.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
            manifest_contract.MAIN_TREE_INDEX => placement.main_offset,
            manifest_contract.INTERACTION_TREE_INDEX => placement.interaction_offset,
            else => unreachable,
        };
        if (placement.geometry.log_size != log_size or actual_count != count or
            offset + count > destination.len) return error.InvalidTraceShape;
        for (0..count) |local| {
            result[at] = destination[offset + local];
            at += 1;
        }
    }
    std.debug.assert(at == total);
    return result;
}

pub fn preflightFreshColumns(columns: []const []M31) !void {
    var ranges: [
        @max(PREPROCESSED_COLUMN_COUNT, @max(
            MAIN_COLUMN_COUNT,
            INTERACTION_COLUMN_COUNT,
        ))
    ]AddressRange = undefined;
    for (columns, 0..) |column, index| {
        for (column) |value| if (!value.isZero())
            return error.DestinationNotZero;
        ranges[index] = try sliceRange(M31, column);
        for (ranges[0..index]) |prior| if (prior.overlaps(ranges[index]))
            return error.DestinationAlias;
    }
}

pub fn clearColumns(columns: []const []M31) void {
    for (columns) |column| @memset(column, M31.zero());
}

pub fn parametersFromRows(comptime Adapter: type, rows: anytype) ![Adapter.PARAMETER_COLUMN_COUNT]M31 {
    const Result = [Adapter.PARAMETER_COLUMN_COUNT]M31;
    if (rows.len == 0) return error.ParameterMismatch;
    const Row = @TypeOf(rows[0]);
    const row_len = @typeInfo(Row).array.len;
    if (Adapter.PARAMETER_COLUMN_COUNT > row_len) return error.ParameterMismatch;
    const start = row_len - Adapter.PARAMETER_COLUMN_COUNT;
    var result: Result = undefined;
    if (Adapter.PARAMETER_COLUMN_COUNT != 0)
        @memcpy(&result, rows[0][start..]);
    for (rows[1..]) |row| for (result, row[start..]) |expected, actual|
        if (!expected.eql(actual)) return error.ParameterMismatch;
    return result;
}

pub fn providerScratchByteCount(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    const rows = @as(usize, 1) << @intCast(log_size);
    // The native serial generator currently retains its pair matrix, two
    // per-batch temporary pair slabs, two cumulative sums, eight output
    // columns, and one bit-reversal table in its arena. Keep explicit margin
    // for allocator alignment without placing any heap allocation on Tree 2.
    const per_row = @sizeOf([poseidon_air.N_SUMS]logup.RowPair) +
        poseidon_air.N_SUMS * @sizeOf(logup.RowPair) +
        poseidon_air.N_SUMS * @sizeOf(QM31) +
        poseidon_air.N_INTERACTION_COLUMNS * @sizeOf(M31) +
        @sizeOf(usize);
    const bytes = std.math.mul(usize, rows, per_row) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, bytes, 4096) catch error.ArithmeticOverflow;
}

pub fn traceLogSize(row_count: usize) !u32 {
    if (row_count == 0) return error.InvalidTraceShape;
    const log_size: u32 = @intCast(std.math.log2_int_ceil(usize, row_count));
    if (log_size == 0 or log_size >= 31)
        return error.InvalidTraceShape;
    return log_size;
}

pub fn committedRow(logical_row: usize, log_size: u32) usize {
    return stwo_core.utils.bitReverseIndex(
        stwo_core.utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

pub fn validateClaims(claims: Claims) !void {
    for (claims.typed_rows) |value| try requireCanonical(value);
    for (claims.poseidon2_partials) |value| try requireCanonical(value);
}

pub fn validateAudits(audits: DomainAudits, claims: Claims) !void {
    try validateClaims(claims);
    for (audits.typed_rows, claims.typed_rows) |audit, claim| {
        var total = QM31.zero();
        for (audit.values) |value| {
            try requireCanonical(value);
            total = total.add(value);
        }
        try requireCanonical(audit.total);
        if (!total.eql(audit.total) or !audit.total.eql(claim))
            return error.ProviderClaimMismatch;
    }
    try audits.poseidon2.validate(claims);
}

pub fn bundleIdentity(bundle: anytype) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BUNDLE_ID_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&bundle.source.source_authority_digest);
    hash.update(&bundle.source_authority.identity_digest);
    for (bundle.composition_workspace.log_sizes) |value| hashInt(&hash, u32, value);
    for (bundle.fri_workspace.log_sizes) |value| hashInt(&hash, u32, value);
    for (bundle.arithmetic_workspace.log_sizes) |value| hashInt(&hash, u32, value);
    hashInt(&hash, u32, bundle.merkle_workspace.log_size);
    hashInt(&hash, u32, bundle.merkle_workspace.provider_log_size);
    hashInt(&hash, u8, @intFromEnum(bundle.provider_custody));
    hashInt(&hash, u32, bundle.provider_log_size);
    hashInt(&hash, u64, bundle.providerCallCount());
    if (bundle.shared_layout) |layout| {
        hash.update(&layout.identity);
        hash.update(&layout.call_buffer_id);
    } else {
        hash.update(&([_]u8{0} ** 32));
        hash.update(&([_]u8{0} ** 32));
    }
    hash.update(&bundle.poseidon_program_id.combined_digest);
    hashInt(&hash, u64, bundle.provider_scratch.len);
    hashInt(&hash, u8, @intFromBool(PROTOCOL_SUBSTRATE_ONLY));
    return hash.finalResult();
}

pub fn hashClaims(hash: anytype, claims: Claims) void {
    for (claims.typed_rows) |value| hashSecure(hash, value);
    for (claims.poseidon2_partials) |value| hashSecure(hash, value);
}

pub fn hashSecure(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

pub fn requireCanonical(value: QM31) !void {
    for (value.toM31Array()) |word| if (word.v >= @import("stwo_core").fields.m31.Modulus)
        return error.NonCanonicalField;
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

pub fn poseidonCallSlicesEqual(
    left: []const poseidon_air.Call,
    right: []const poseidon_air.Call,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (a.wide != b.wide or a.io != b.io or
            a.narrow_output != b.narrow_output or
            !std.mem.eql(u32, &a.input, &b.input))
        {
            return false;
        }
    }
    return true;
}

pub fn sum(comptime values: []const usize) usize {
    var result: usize = 0;
    for (values) |value| result += value;
    return result;
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn sliceRange(comptime T: type, values: []const T) !AddressRange {
    const bytes = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.ArithmeticOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, bytes) catch
            return error.ArithmeticOverflow,
    };
}

comptime {
    if (PREPROCESSED_COLUMNS_PER_ROW.len != ROW_COUNT or
        MAIN_COLUMNS_PER_ROW.len != ROW_COUNT or
        INTERACTION_COLUMNS_PER_ROW.len != ROW_COUNT or
        source_mod.POSEIDON2_PARTIAL_COUNT != poseidon_air.N_SUMS or
        shared_provider.POSEIDON_MAIN_COLUMN_COUNT != poseidon_air.N_MAIN_COLUMNS or
        shared_provider.POSEIDON_INTERACTION_COLUMN_COUNT !=
            poseidon_air.N_INTERACTION_COLUMNS)
    {
        @compileError("binary FRI outer bundle geometry drifted");
    }
}
