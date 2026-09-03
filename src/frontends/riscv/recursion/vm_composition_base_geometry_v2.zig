//! Proof-independent OODS sample geometry for an authenticated VM ProfileV2.
//!
//! ProfileV2 owns physical component placement. This companion authority
//! expands that placement into the exact per-column mask order consumed by
//! the row-18 composition compiler. It contains no sampled values, claims, or
//! transcript draws.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const verifier_types = @import("stwo_core").verifier_types;
const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement_mod = @import("../air/statement.zig");
const profile_mod = @import("vm_air_profile_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const TREE_COUNT: usize = 4;
pub const PREPROCESSED_TREE: usize = 0;
pub const MAIN_TREE: usize = 1;
pub const INTERACTION_TREE: usize = 2;
pub const COMPOSITION_TREE: usize = 3;
pub const MAX_SAMPLES_PER_COLUMN: usize = 2;
pub const IDENTITY_DOMAIN =
    "stwo-zig/riscv/recursion/vm-composition-base-geometry/v2\x00";

pub const Error = std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    InvalidColumnGeometry,
    InvalidGeometryIdentity,
    InvalidGeometryVersion,
    InvalidProfileAuthority,
    SampledValueCountMismatch,
};

pub const RowOffset = enum(i8) {
    current = 0,
    previous = -1,
};

pub const ColumnV2 = struct {
    log_size: u32,
    sample_count: u8,
    samples: [MAX_SAMPLES_PER_COLUMN]RowOffset = .{
        .current,
        .current,
    },

    pub fn validate(self: ColumnV2, tree: usize) Error!void {
        if (self.log_size == 0 or self.log_size >= 31 or
            self.sample_count == 0 or
            self.sample_count > MAX_SAMPLES_PER_COLUMN)
        {
            return error.InvalidColumnGeometry;
        }
        const expected: u8 = if (tree == INTERACTION_TREE) 2 else 1;
        if (self.sample_count != expected or
            self.samples[0] != .current or
            (expected == 2 and self.samples[1] != .previous))
        {
            return error.InvalidColumnGeometry;
        }
    }
};

pub const GeometryV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    profile_identity: [32]u8,
    columns: [TREE_COUNT][]ColumnV2,
    tree_value_offsets: [TREE_COUNT + 1]u32,
    sampled_value_count: u32,
    composition_log_size: u32,
    composition_log_split: u32,
    identity_sha256: [32]u8,

    pub fn deinit(self: *GeometryV2) void {
        for (self.columns) |tree| self.allocator.free(tree);
        self.* = undefined;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        profile: *const profile_mod.ProfileV2,
    ) !GeometryV2 {
        try profile.validate();
        const composition_columns = verifier_types.compositionColumnCount(
            profile.composition_log_split,
            qm31.SECURE_EXTENSION_DEGREE,
        ) orelse return error.InvalidColumnGeometry;
        const counts = [TREE_COUNT]usize{
            profile.preprocessed_column_count,
            profile.main_column_count,
            profile.interaction_column_count,
            composition_columns,
        };
        var columns: [TREE_COUNT][]ColumnV2 = undefined;
        var initialized: usize = 0;
        errdefer for (columns[0..initialized]) |tree| allocator.free(tree);
        for (&columns, counts) |*tree, count| {
            tree.* = try allocator.alloc(ColumnV2, count);
            @memset(tree.*, .{ .log_size = 0, .sample_count = 0 });
            initialized += 1;
        }

        for (profile.entries) |entry| {
            try installSpan(
                columns[PREPROCESSED_TREE],
                entry.preprocessed,
                entry.log_size,
                false,
            );
            try installSpan(
                columns[MAIN_TREE],
                entry.main,
                entry.log_size,
                false,
            );
            try installSpan(
                columns[INTERACTION_TREE],
                entry.interaction,
                entry.log_size,
                true,
            );
        }
        const composition_log_size = profile.composition_log_degree_bound -
            profile.composition_log_split;
        for (columns[COMPOSITION_TREE]) |*column| column.* = .{
            .log_size = composition_log_size,
            .sample_count = 1,
        };

        var offsets: [TREE_COUNT + 1]u32 = .{0} ** (TREE_COUNT + 1);
        var value_count: u32 = 0;
        for (columns, 0..) |tree, tree_index| {
            offsets[tree_index] = value_count;
            for (tree) |column| {
                try column.validate(tree_index);
                value_count = std.math.add(
                    u32,
                    value_count,
                    column.sample_count,
                ) catch return error.ArithmeticOverflow;
            }
        }
        offsets[TREE_COUNT] = value_count;
        if (value_count != profile.input_profile.sampled_value_count)
            return error.SampledValueCountMismatch;

        var result = GeometryV2{
            .allocator = allocator,
            .profile_identity = profile.identity_digest,
            .columns = columns,
            .tree_value_offsets = offsets,
            .sampled_value_count = value_count,
            .composition_log_size = composition_log_size,
            .composition_log_split = profile.composition_log_split,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = result.computeIdentity();
        try result.validate();
        if (!std.mem.eql(
            u8,
            &result.profile_identity,
            &profile.identity_digest,
        ) or result.sampled_value_count !=
            profile.input_profile.sampled_value_count)
        {
            return error.InvalidProfileAuthority;
        }
        return result;
    }

    pub fn validate(self: *const GeometryV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidGeometryVersion;
        }
        if (allZero(self.profile_identity) or
            self.composition_log_size <= self.composition_log_split or
            self.tree_value_offsets[0] != 0)
        {
            return error.InvalidColumnGeometry;
        }
        var cursor: u32 = 0;
        for (self.columns, 0..) |tree, tree_index| {
            if (self.tree_value_offsets[tree_index] != cursor)
                return error.InvalidColumnGeometry;
            for (tree) |column| {
                try column.validate(tree_index);
                cursor = std.math.add(
                    u32,
                    cursor,
                    column.sample_count,
                ) catch return error.ArithmeticOverflow;
            }
        }
        if (cursor != self.sampled_value_count or
            self.tree_value_offsets[TREE_COUNT] != cursor)
        {
            return error.SampledValueCountMismatch;
        }
        const actual = self.computeIdentity();
        if (!std.mem.eql(u8, &actual, &self.identity_sha256))
            return error.InvalidGeometryIdentity;
    }

    pub fn validateAgainst(
        self: *const GeometryV2,
        profile: *const profile_mod.ProfileV2,
    ) !void {
        try self.validate();
        var expected = try init(self.allocator, profile);
        defer expected.deinit();
        if (!geometriesEqual(self, &expected))
            return error.InvalidProfileAuthority;
    }

    pub fn flatSampleIndex(
        self: *const GeometryV2,
        tree: usize,
        column: usize,
        sample: usize,
    ) Error!u32 {
        if (tree >= TREE_COUNT or column >= self.columns[tree].len or
            sample >= self.columns[tree][column].sample_count)
        {
            return error.InvalidColumnGeometry;
        }
        var result = self.tree_value_offsets[tree];
        for (self.columns[tree][0..column]) |item| result += item.sample_count;
        return std.math.add(u32, result, @intCast(sample)) catch
            return error.ArithmeticOverflow;
    }

    fn computeIdentity(self: *const GeometryV2) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(IDENTITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hash.update(&self.profile_identity);
        hashInt(&hash, u32, self.sampled_value_count);
        hashInt(&hash, u32, self.composition_log_size);
        hashInt(&hash, u32, self.composition_log_split);
        for (self.columns, 0..) |tree, tree_index| {
            hashInt(&hash, u8, tree_index);
            hashInt(&hash, u32, tree.len);
            for (tree) |column| {
                hashInt(&hash, u32, column.log_size);
                hashInt(&hash, u8, column.sample_count);
                for (column.samples[0..column.sample_count]) |sample|
                    hashInt(&hash, i8, @intFromEnum(sample));
            }
        }
        return hash.finalResult();
    }
};

/// Computes the one aggregate count needed before ProfileV2 itself is minted.
/// Full geometry is still reconstructed and checked by `GeometryV2.init`.
pub fn expectedSampledValueCount(
    statement: *const statement_mod.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
) !u32 {
    try manifest.validate();
    var interaction: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        interaction = std.math.add(
            u32,
            interaction,
            manifest.entryForFamily(descriptor.family)
                .lookup_authority.interaction_column_count,
        ) catch return error.ArithmeticOverflow;
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        interaction = std.math.add(
            u32,
            interaction,
            statement_mod.nInteractionColsForInfra(descriptor.kind),
        ) catch return error.ArithmeticOverflow;
    }
    const composition = verifier_types.compositionColumnCount(
        verifier_types.COMPOSITION_LOG_SPLIT,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidColumnGeometry;
    var total = std.math.add(
        u32,
        statement.nPreprocessedColumns(),
        statement.nMainColumns(),
    ) catch return error.ArithmeticOverflow;
    total = std.math.add(
        u32,
        total,
        std.math.mul(u32, interaction, 2) catch
            return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
    return std.math.add(u32, total, @intCast(composition)) catch
        return error.ArithmeticOverflow;
}

fn installSpan(
    columns: []ColumnV2,
    span: profile_mod.TreeSpanV2,
    log_size: u32,
    interaction: bool,
) Error!void {
    const end = std.math.add(u32, span.offset, span.sampled_columns) catch
        return error.ArithmeticOverflow;
    if (end > columns.len) return error.InvalidColumnGeometry;
    for (columns[@intCast(span.offset)..@intCast(end)]) |*column| {
        const expected = ColumnV2{
            .log_size = log_size,
            .sample_count = if (interaction) 2 else 1,
            .samples = if (interaction)
                .{ .current, .previous }
            else
                .{ .current, .current },
        };
        if (column.sample_count == 0) {
            column.* = expected;
        } else if (!std.meta.eql(column.*, expected)) {
            return error.InvalidColumnGeometry;
        }
    }
}

fn geometriesEqual(left: *const GeometryV2, right: *const GeometryV2) bool {
    if (left.format_version != right.format_version or
        left.schema_version != right.schema_version or
        !std.mem.eql(u8, &left.profile_identity, &right.profile_identity) or
        !std.meta.eql(left.tree_value_offsets, right.tree_value_offsets) or
        left.sampled_value_count != right.sampled_value_count or
        left.composition_log_size != right.composition_log_size or
        left.composition_log_split != right.composition_log_split or
        !std.mem.eql(u8, &left.identity_sha256, &right.identity_sha256))
    {
        return false;
    }
    for (left.columns, right.columns) |a, b| {
        if (a.len != b.len) return false;
        for (a, b) |x, y| if (!std.meta.eql(x, y)) return false;
    }
    return true;
}

fn allZero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn reseal(value: *GeometryV2) void {
        value.identity_sha256 = value.computeIdentity();
    }
};

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or TREE_COUNT != 4 or
        MAX_SAMPLES_PER_COLUMN != 2)
    {
        @compileError("VM composition base geometry V2 contract drifted");
    }
}
