//! Shared proof-independent graph-recording support for Ethereum VM leaves.
//!
//! PCS samples are ordered tree-major, with the dynamic ProfileV2 columns
//! followed by the fourteen Ethereum component columns in each committed
//! tree.  The retained geometry is the sole source of sample offsets; callers
//! never transcribe a second mask inventory.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circle = stwo_core.circle;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const qm31 = stwo_core.fields.qm31;
const canonic = stwo_core.poly.circle.canonic;
const verifier_types = stwo_core.verifier_types;

const graph_mod = @import("air/composition_circuit.zig");
const logup = @import("../air/logup.zig");
const base_geometry = @import("vm_composition_base_geometry_v2.zig");
const extension_geometry =
    @import("ethereum_composition_extension_geometry_v2.zig");
const circuit = @import("vm_air_composition_circuit.zig");

pub const Scalar = circuit.Scalar;
pub const Builder = circuit.Builder;
pub const TREE_COUNT: usize = base_geometry.TREE_COUNT;
pub const EXTENSION_TREE_COUNT: usize = extension_geometry.TREE_COUNT;

pub const Error = std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    InvalidCompositionGeometry,
    InvalidSampleGeometry,
};

pub const SampleLayoutV2 = struct {
    allocator: std.mem.Allocator,
    base: *const base_geometry.GeometryV2,
    extension: *const extension_geometry.GeometryV2,
    values: []const Scalar,
    tree_offsets: [TREE_COUNT + 1]u32,
    base_offsets: [TREE_COUNT][]u32,
    extension_offsets: [EXTENSION_TREE_COUNT][]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        base: *const base_geometry.GeometryV2,
        extension: *const extension_geometry.GeometryV2,
        values: []const Scalar,
    ) !SampleLayoutV2 {
        try base.validate();
        try extension.validate();
        if (!std.mem.eql(
            u8,
            &base.profile_identity,
            &extension.base_profile_identity,
        )) return error.InvalidSampleGeometry;

        var base_offsets: [TREE_COUNT][]u32 = undefined;
        var base_initialized: usize = 0;
        errdefer for (base_offsets[0..base_initialized]) |offsets|
            allocator.free(offsets);
        for (&base_offsets, base.columns) |*offsets, columns| {
            offsets.* = try columnOffsets(allocator, columns);
            base_initialized += 1;
        }

        var extension_offsets: [EXTENSION_TREE_COUNT][]u32 = undefined;
        var extension_initialized: usize = 0;
        errdefer for (extension_offsets[0..extension_initialized]) |offsets|
            allocator.free(offsets);
        for (&extension_offsets, extension.columns) |*offsets, columns| {
            offsets.* = try columnOffsets(allocator, columns);
            extension_initialized += 1;
        }

        var tree_offsets: [TREE_COUNT + 1]u32 = .{0} ** (TREE_COUNT + 1);
        var cursor: u32 = 0;
        for (0..TREE_COUNT) |tree| {
            tree_offsets[tree] = cursor;
            cursor = try add(cursor, last(base_offsets[tree]));
            if (tree < EXTENSION_TREE_COUNT)
                cursor = try add(cursor, last(extension_offsets[tree]));
        }
        tree_offsets[TREE_COUNT] = cursor;
        if (@as(usize, cursor) != values.len or
            cursor != base.sampled_value_count + extension.sampled_value_count)
        {
            return error.InvalidSampleGeometry;
        }
        return .{
            .allocator = allocator,
            .base = base,
            .extension = extension,
            .values = values,
            .tree_offsets = tree_offsets,
            .base_offsets = base_offsets,
            .extension_offsets = extension_offsets,
        };
    }

    pub fn deinit(self: *SampleLayoutV2) void {
        for (self.extension_offsets) |offsets| self.allocator.free(offsets);
        for (self.base_offsets) |offsets| self.allocator.free(offsets);
        self.* = undefined;
    }

    pub fn atBase(
        self: *const SampleLayoutV2,
        tree: usize,
        column: usize,
        sample: usize,
    ) Error!Scalar {
        if (tree >= TREE_COUNT or column >= self.base.columns[tree].len)
            return error.InvalidSampleGeometry;
        const offsets = self.base_offsets[tree];
        const start = offsets[column];
        const end = offsets[column + 1];
        if (sample >= end - start) return error.InvalidSampleGeometry;
        return self.values[try index(self.tree_offsets[tree], start, sample)];
    }

    pub fn atExtension(
        self: *const SampleLayoutV2,
        tree: usize,
        column: usize,
        row_offset: i8,
    ) Error!Scalar {
        if (tree >= EXTENSION_TREE_COUNT or
            column >= self.extension.columns[tree].len)
        {
            return error.InvalidSampleGeometry;
        }
        const geometry = self.extension.columns[tree][column];
        var sample: ?usize = null;
        for (geometry.row_offsets[0..geometry.sample_count], 0..) |value, at| {
            if (value == row_offset) {
                sample = at;
                break;
            }
        }
        const selected = sample orelse return error.InvalidSampleGeometry;
        const base_count = last(self.base_offsets[tree]);
        const start = self.extension_offsets[tree][column];
        return self.values[
            try index(
                try add(self.tree_offsets[tree], base_count),
                start,
                selected,
            )
        ];
    }

    pub fn sampledBaseSecure(
        self: *const SampleLayoutV2,
        column: usize,
        sample: usize,
    ) Error!Scalar {
        var coordinates: [4]Scalar = undefined;
        for (&coordinates, 0..) |*value, coordinate| value.* = try self.atBase(
            base_geometry.INTERACTION_TREE,
            column + coordinate,
            sample,
        );
        return fromPartialEvals(coordinates);
    }

    pub fn sampledExtensionSecure(
        self: *const SampleLayoutV2,
        column: usize,
        row_offset: i8,
    ) Error!Scalar {
        var coordinates: [4]Scalar = undefined;
        for (&coordinates, 0..) |*value, coordinate| {
            value.* = try self.atExtension(2, column + coordinate, row_offset);
        }
        return fromPartialEvals(coordinates);
    }
};

pub fn secureInput(
    builder: *Builder,
    comptime tag: enum { sampled_value, claimed_sum, transcript_claimed_sum },
    item_index: u32,
) !Scalar {
    var words: [4]Scalar = undefined;
    for (&words, 0..) |*word, word_index| {
        const coordinate = graph_mod.SecureCoordinate{
            .item_index = item_index,
            .word_index = @intCast(word_index),
        };
        word.* = try builder.input(@unionInit(
            graph_mod.VmSource,
            @tagName(tag),
            coordinate,
        ));
    }
    return secureFromWords(words);
}

pub fn challengeInput(
    builder: *Builder,
    challenge: u32,
    word_offset: u32,
) !Scalar {
    var words: [4]Scalar = undefined;
    for (&words, 0..) |*word, word_index| word.* = try builder.input(.{
        .relation_challenge = .{
            .challenge = challenge,
            .word_index = word_offset + @as(u32, @intCast(word_index)),
        },
    });
    return secureFromWords(words);
}

pub fn scalarInput(
    builder: *Builder,
    comptime tag: enum { composition_randomness, oods_point },
) !Scalar {
    var words: [4]Scalar = undefined;
    for (&words, 0..) |*word, word_index| word.* = try builder.input(@unionInit(
        graph_mod.VmSource,
        @tagName(tag),
        @as(u32, @intCast(word_index)),
    ));
    return secureFromWords(words);
}

pub fn pointFromSeed(seed: Scalar) circle.CirclePoint(Scalar) {
    const square = seed.square();
    const inverse = square.add(Scalar.one()).inverse();
    return .{
        .x = Scalar.one().sub(square).mul(inverse),
        .y = seed.add(seed).mul(inverse),
    };
}

pub fn quotientDenominator(
    log_size: u32,
    max_log_degree_bound: u32,
    point: circle.CirclePoint(Scalar),
    cache: *[31]?Scalar,
) Scalar {
    std.debug.assert(log_size < cache.len and max_log_degree_bound >= log_size);
    if (cache[log_size]) |cached| return cached;
    const coset = canonic.CanonicCoset.new(log_size).coset();
    const folded = point.repeatedDouble(max_log_degree_bound - log_size);
    const shifted = folded.sub(.{
        .x = Scalar.fromBase(coset.initial.x),
        .y = Scalar.fromBase(coset.initial.y),
    }).add(.{
        .x = Scalar.fromBase(coset.half_step.x),
        .y = Scalar.fromBase(coset.half_step.y),
    });
    var x = shifted.x;
    var round: u32 = 1;
    while (round < coset.log_size) : (round += 1)
        x = circle.CirclePoint(Scalar).doubleX(x);
    const inverse = x.inverse();
    cache[log_size] = inverse;
    return inverse;
}

pub fn accumulate(
    accumulation: *Scalar,
    randomness: Scalar,
    constraint: Scalar,
    denominator: Scalar,
) void {
    accumulation.* = accumulation.mul(randomness)
        .add(constraint.mul(denominator));
}

pub fn reconstructComposition(
    layout: *const SampleLayoutV2,
    point: circle.CirclePoint(Scalar),
    composition_log_size: u32,
    split_depth: u32,
) Error!Scalar {
    const chunk_count = verifier_types.compositionChunkCount(split_depth) orelse
        return error.InvalidCompositionGeometry;
    const expected_columns = verifier_types.compositionColumnCount(
        split_depth,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidCompositionGeometry;
    if (layout.base.columns[3].len != expected_columns or
        composition_log_size <= split_depth)
    {
        return error.InvalidCompositionGeometry;
    }
    var chunks: [
        @as(usize, 1) <<
            verifier_types.MAX_COMPOSITION_LOG_SPLIT
    ]Scalar = undefined;
    for (chunks[0..chunk_count], 0..) |*chunk, chunk_index| {
        var coordinates: [4]Scalar = undefined;
        for (&coordinates, 0..) |*coordinate, coordinate_index| {
            coordinate.* = try layout.atBase(
                3,
                chunk_index * 4 + coordinate_index,
                0,
            );
        }
        chunk.* = fromPartialEvals(coordinates);
    }
    var active = chunk_count;
    var parent_log = composition_log_size - split_depth + 1;
    while (active > 1) {
        const factor = point.repeatedDouble(parent_log - 2).x;
        var output: usize = 0;
        var input: usize = 0;
        while (input < active) : (input += 2) {
            chunks[output] = chunks[input].add(factor.mul(chunks[input + 1]));
            output += 1;
        }
        active /= 2;
        parent_log += 1;
    }
    return chunks[0];
}

pub fn fromPartialEvals(values: [4]Scalar) Scalar {
    return values[0]
        .add(values[1].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 1, 0, 0))))
        .add(values[2].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 0, 1, 0))))
        .add(values[3].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 0, 0, 1))));
}

fn secureFromWords(words: [4]Scalar) Scalar {
    return fromPartialEvals(words);
}

fn columnOffsets(allocator: std.mem.Allocator, columns: anytype) ![]u32 {
    const result = try allocator.alloc(u32, columns.len + 1);
    errdefer allocator.free(result);
    var cursor: u32 = 0;
    for (columns, 0..) |column, column_index| {
        result[column_index] = cursor;
        cursor = try add(cursor, column.sample_count);
    }
    result[columns.len] = cursor;
    return result;
}

fn last(values: []const u32) u32 {
    std.debug.assert(values.len != 0);
    return values[values.len - 1];
}

fn add(left: u32, right: anytype) Error!u32 {
    return std.math.add(u32, left, @intCast(right)) catch
        return error.ArithmeticOverflow;
}

fn index(base: u32, offset: u32, sample: usize) Error!usize {
    const before_sample = try add(base, offset);
    return @intCast(try add(before_sample, sample));
}

comptime {
    if (TREE_COUNT != 4 or EXTENSION_TREE_COUNT != 3)
        @compileError("Ethereum VM composition tree inventory drifted");
}
