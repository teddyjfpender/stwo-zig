const std = @import("std");
const eval_program = @import("eval_program.zig");

pub const magic = "STWZEVA\x00".*;
pub const version: u32 = 1;
pub const projected_version: u32 = 2;

pub const TraceSpan = struct { tree: u32, start: u32, end: u32 };

pub const ExtSource = union(enum) {
    constant: [4]u32,
    lookup_z,
    lookup_alpha_power: u32,
    claimed_sum_scaled,
    lookup_alpha_power_scaled: struct { power: u32, scale: u32 },
};

pub const Part = struct {
    rc_base: u32,
    semantic_hash: u64,
    program: eval_program.Program,
};

pub const Component = struct {
    label: []u8,
    instance: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    n_constraints: u32,
    random_coefficient_offset: u32,
    trace_spans: []TraceSpan,
    preprocessed_indices: []u32,
    denominator_inverses: []u32,
    ext_sources: []ExtSource,
    parts: []Part,
};

pub const Bundle = struct {
    allocator: std.mem.Allocator,
    format_version: u32 = version,
    max_kernel_instructions: u32,
    total_constraints: u64,
    max_evaluation_log_size: u32,
    plan_hash: u64,
    components: []Component,

    /// The unsplit composition evaluation log is one above the degree bound
    /// of its two committed halves in both captured and projected formats.
    pub fn verifierMaxLogDegreeBound(self: Bundle) !u32 {
        const bound = switch (self.format_version) {
            version, projected_version => std.math.sub(
                u32,
                self.max_evaluation_log_size,
                1,
            ) catch return error.InvalidVerifierMaxLogDegreeBound,
            else => return error.UnsupportedVersion,
        };
        if (bound == 0 or bound > 31) return error.InvalidVerifierMaxLogDegreeBound;
        return bound;
    }

    pub fn readFile(allocator: std.mem.Allocator, path: []const u8) !Bundle {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 512 * 1024 * 1024);
        defer allocator.free(bytes);
        return parse(allocator, bytes);
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Bundle {
        var reader = Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try reader.slice(8), &magic)) return error.InvalidMagic;
        const encoded_version = try reader.int(u32);
        if (encoded_version != version and encoded_version != projected_version)
            return error.UnsupportedVersion;
        const max_instructions = try reader.int(u32);
        const total_constraints = try reader.int(u64);
        const max_eval_log = try reader.int(u32);
        const count = try reader.int(u32);
        const plan_hash = try reader.int(u64);
        if (max_instructions == 0 or max_instructions > 1_000_000 or total_constraints == 0 or
            max_eval_log > 31 or count == 0 or count > 4096 or plan_hash == 0)
            return error.InvalidHeader;
        const components = try allocator.alloc(Component, count);
        errdefer allocator.free(components);
        var initialized: usize = 0;
        errdefer for (components[0..initialized]) |*component| deinitComponent(allocator, component);
        while (initialized < components.len) : (initialized += 1) {
            const label_len = try reader.int(u16);
            if (label_len == 0 or label_len > 256 or try reader.int(u16) != 0) return error.InvalidComponent;
            const instance = try reader.int(u32);
            const trace_log = try reader.int(u32);
            const eval_log = try reader.int(u32);
            const n_constraints = try reader.int(u32);
            const random_offset = try reader.int(u32);
            const span_count = try reader.int(u32);
            const preprocessed_count = try reader.int(u32);
            const denom_count = try reader.int(u32);
            const ext_count = try reader.int(u32);
            const part_count = try reader.int(u32);
            if (trace_log == 0 or trace_log > eval_log or eval_log > max_eval_log or n_constraints == 0 or
                span_count == 0 or span_count > 64 or preprocessed_count > 4096 or denom_count == 0 or
                denom_count > 65536 or ext_count > 65536 or part_count == 0 or part_count > n_constraints)
                return error.InvalidComponent;
            const label = try allocator.dupe(u8, try reader.slice(label_len));
            errdefer allocator.free(label);
            const spans = try allocator.alloc(TraceSpan, span_count);
            errdefer allocator.free(spans);
            for (spans) |*span| {
                span.* = .{ .tree = try reader.int(u32), .start = try reader.int(u32), .end = try reader.int(u32) };
                if (span.tree >= 3 or span.start > span.end) return error.InvalidTraceSpan;
            }
            const preprocessed = try allocator.alloc(u32, preprocessed_count);
            errdefer allocator.free(preprocessed);
            for (preprocessed) |*index| index.* = try reader.int(u32);
            const denominators = try allocator.alloc(u32, denom_count);
            errdefer allocator.free(denominators);
            for (denominators) |*value| {
                value.* = try reader.int(u32);
                if (value.* >= eval_program.m31_prime) return error.InvalidFieldElement;
            }
            const ext_sources = try allocator.alloc(ExtSource, ext_count);
            errdefer allocator.free(ext_sources);
            for (ext_sources) |*source| {
                const tag = try reader.int(u32);
                const power = try reader.int(u32);
                const scale = try reader.int(u32);
                if (try reader.int(u32) != 0) return error.InvalidReserved;
                var value: [4]u32 = undefined;
                for (&value) |*coordinate| {
                    coordinate.* = try reader.int(u32);
                    if (coordinate.* >= eval_program.m31_prime) return error.InvalidFieldElement;
                }
                source.* = switch (tag) {
                    0 => blk: {
                        if (power != 0 or scale != 0) return error.InvalidExtSource;
                        break :blk .{ .constant = value };
                    },
                    1 => blk: {
                        if (power != 0 or scale != 0 or !allZero(value)) return error.InvalidExtSource;
                        break :blk .lookup_z;
                    },
                    2 => blk: {
                        if (power == 0 or scale != 0 or !allZero(value)) return error.InvalidExtSource;
                        break :blk .{ .lookup_alpha_power = power };
                    },
                    3 => blk: {
                        if (power != 0 or scale != 0 or !allZero(value)) return error.InvalidExtSource;
                        break :blk .claimed_sum_scaled;
                    },
                    4 => blk: {
                        if (power == 0 or scale <= 1 or scale >= eval_program.m31_prime or !allZero(value)) return error.InvalidExtSource;
                        break :blk .{ .lookup_alpha_power_scaled = .{ .power = power, .scale = scale } };
                    },
                    else => return error.InvalidExtSource,
                };
            }
            const parts = try allocator.alloc(Part, part_count);
            errdefer allocator.free(parts);
            var parts_initialized: usize = 0;
            errdefer for (parts[0..parts_initialized]) |*part| part.program.deinit();
            var next_root: u32 = 0;
            while (parts_initialized < parts.len) : (parts_initialized += 1) {
                const rc_base = try reader.int(u32);
                const program_len = try reader.int(u32);
                const semantic_hash = try reader.int(u64);
                if (rc_base != next_root or program_len < eval_program.header_bytes or program_len > 256 * 1024 * 1024)
                    return error.InvalidPart;
                var program = try eval_program.Program.parse(allocator, try reader.slice(program_len));
                errdefer program.deinit();
                if (program.header.semantic_hash != semantic_hash or program.header.n_interactions != 3 or
                    program.header.domain_log_size != trace_log or program.header.n_ext_params != ext_count)
                    return error.InvalidPart;
                next_root = std.math.add(u32, next_root, program.header.n_constraints) catch return error.InvalidPart;
                parts[parts_initialized] = .{ .rc_base = rc_base, .semantic_hash = semantic_hash, .program = program };
            }
            if (next_root != n_constraints) return error.InvalidConstraintCount;
            const expected_denoms: u64 = @as(u64, 1) << @intCast(eval_log - trace_log);
            if (denom_count != expected_denoms) return error.InvalidDenominatorCount;
            components[initialized] = .{
                .label = label,
                .instance = instance,
                .trace_log_size = trace_log,
                .evaluation_log_size = eval_log,
                .n_constraints = n_constraints,
                .random_coefficient_offset = random_offset,
                .trace_spans = spans,
                .preprocessed_indices = preprocessed,
                .denominator_inverses = denominators,
                .ext_sources = ext_sources,
                .parts = parts,
            };
        }
        if (reader.cursor != bytes.len) return error.TrailingData;
        if (encoded_version == projected_version and plan_hash != projectedPlanHash(bytes))
            return error.InvalidPlanHash;
        var next_constraint: u64 = 0;
        var found_max_log: u32 = 0;
        for (components) |component| {
            if (component.random_coefficient_offset != next_constraint) return error.InvalidConstraintOrder;
            next_constraint += component.n_constraints;
            found_max_log = @max(found_max_log, component.evaluation_log_size);
        }
        if (next_constraint != total_constraints or found_max_log != max_eval_log) return error.InvalidHeader;
        return .{
            .allocator = allocator,
            .format_version = encoded_version,
            .max_kernel_instructions = max_instructions,
            .total_constraints = total_constraints,
            .max_evaluation_log_size = max_eval_log,
            .plan_hash = plan_hash,
            .components = components,
        };
    }

    pub fn deinit(self: *Bundle) void {
        for (self.components) |*component| deinitComponent(self.allocator, component);
        self.allocator.free(self.components);
        self.* = undefined;
    }
};

fn projectedPlanHash(bytes: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (bytes, 0..) |byte, index| {
        hash ^= if (index >= 32 and index < 40) 0 else byte;
        hash *%= 0x100000001b3;
    }
    return hash;
}

fn deinitComponent(allocator: std.mem.Allocator, component: *Component) void {
    allocator.free(component.label);
    allocator.free(component.trace_spans);
    allocator.free(component.preprocessed_indices);
    allocator.free(component.denominator_inverses);
    allocator.free(component.ext_sources);
    for (component.parts) |*part| part.program.deinit();
    allocator.free(component.parts);
}

fn allZero(value: [4]u32) bool {
    for (value) |coordinate| if (coordinate != 0) return false;
    return true;
}

const Reader = struct {
    bytes: []const u8,
    cursor: usize = 0,

    fn slice(self: *Reader, len: usize) ![]const u8 {
        const end = std.math.add(usize, self.cursor, len) catch return error.TruncatedBundle;
        if (end > self.bytes.len) return error.TruncatedBundle;
        defer self.cursor = end;
        return self.bytes[self.cursor..end];
    }

    fn int(self: *Reader, comptime T: type) !T {
        return std.mem.readInt(T, (try self.slice(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
};

test "Cairo composition bundle: header rejects empty plans" {
    var bytes = [_]u8{0} ** 40;
    @memcpy(bytes[0..8], &magic);
    std.mem.writeInt(u32, bytes[8..12], version, .little);
    try std.testing.expectError(error.InvalidHeader, Bundle.parse(std.testing.allocator, &bytes));
}

test "Cairo composition bundle: exact SN2 AIR programs load and validate" {
    var bundle = try Bundle.readFile(std.testing.allocator, "vectors/cairo/sn_pie_2_composition.bin");
    defer bundle.deinit();
    try std.testing.expectEqual(@as(u32, 512), bundle.max_kernel_instructions);
    try std.testing.expectEqual(version, bundle.format_version);
    try std.testing.expectEqual(@as(u64, 1325), bundle.total_constraints);
    try std.testing.expectEqual(@as(u32, 24), bundle.max_evaluation_log_size);
    try std.testing.expectEqual(@as(u32, 23), try bundle.verifierMaxLogDegreeBound());
    try std.testing.expectEqual(@as(usize, 58), bundle.components.len);
    try std.testing.expectEqual(@as(u64, 10359646181791462711), bundle.plan_hash);
    var parts: usize = 0;
    var programs: usize = 0;
    for (bundle.components) |component| {
        parts += component.parts.len;
        for (component.parts) |part| programs += part.program.base_insts.len + part.program.ext_insts.len;
    }
    try std.testing.expectEqual(@as(usize, 279), parts);
    try std.testing.expectEqual(@as(usize, 112_956), programs);
}

test "Cairo composition bundle: projected plans authenticate their complete encoding" {
    const allocator = std.testing.allocator;
    var bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/cairo/sn_pie_2_composition.bin", 4 * 1024 * 1024);
    defer allocator.free(bytes);
    std.mem.writeInt(u32, bytes[8..12], projected_version, .little);
    std.mem.writeInt(u64, bytes[32..40], projectedPlanHash(bytes), .little);

    var bundle = try Bundle.parse(allocator, bytes);
    try std.testing.expectEqual(projected_version, bundle.format_version);
    try std.testing.expectEqual(@as(u32, 23), try bundle.verifierMaxLogDegreeBound());
    bundle.deinit();
    bytes[32] ^= 1;
    try std.testing.expectError(error.InvalidPlanHash, Bundle.parse(allocator, bytes));
}

test "Cairo composition bundle: captured and projected plans use split degree bounds" {
    const base = Bundle{
        .allocator = undefined,
        .max_kernel_instructions = 1,
        .total_constraints = 1,
        .max_evaluation_log_size = 24,
        .plan_hash = 1,
        .components = &.{},
    };
    try std.testing.expectEqual(@as(u32, 23), try base.verifierMaxLogDegreeBound());

    var projected = base;
    projected.format_version = projected_version;
    projected.max_evaluation_log_size = 21;
    try std.testing.expectEqual(@as(u32, 20), try projected.verifierMaxLogDegreeBound());

    projected.max_evaluation_log_size = 1;
    try std.testing.expectError(
        error.InvalidVerifierMaxLogDegreeBound,
        projected.verifierMaxLogDegreeBound(),
    );
    projected.format_version = 3;
    try std.testing.expectError(error.UnsupportedVersion, projected.verifierMaxLogDegreeBound());
}
