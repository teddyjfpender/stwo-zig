//! Cold, proof-independent mask geometry for the fourteen Ethereum AIRs.
//!
//! Geometry is obtained from the production component `maskPoints` vtables at
//! a deterministic point and classified back to row offsets. This avoids a
//! second handwritten mask inventory while retaining a pointer-free authority
//! that a fresh verifier can reconstruct before accepting instance values.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circle = stwo_core.circle;
const canonic = stwo_core.poly.circle.canonic;
const QM31 = stwo_core.fields.qm31.QM31;

const logup = @import("../air/logup.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const keccak_component =
    @import("../air/guest_precompile/keccakf_component.zig");
const keccak_relations =
    @import("../air/guest_precompile/keccakf_relations.zig");
const keccak_table =
    @import("../air/guest_precompile/keccakf_table_component.zig");
const keccak_tables =
    @import("../air/guest_precompile/keccakf_tables.zig");
const secp_bundle =
    @import("../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_component =
    @import("../air/guest_precompile/secp256k1_component.zig");
const secp_config =
    @import("../air/guest_precompile/secp256k1_component_config.zig");
const secp_relations =
    @import("../air/guest_precompile/secp256k1_relations.zig");
const base_statement = @import("../air/statement.zig");
const profile_mod = @import("vm_air_profile_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Point = circle.CirclePointQM31;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const TREE_COUNT: usize = 3;
pub const MAX_SAMPLES_PER_COLUMN: usize = 6;
pub const IDENTITY_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-composition-extension-geometry/v2\x00";

pub const Error = std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    InvalidComponentGeometry,
    InvalidExtensionAuthority,
    InvalidGeometryIdentity,
    InvalidGeometryVersion,
    InvalidMaskOffset,
    InvalidMaskShape,
};

pub const ColumnV2 = struct {
    log_size: u32,
    sample_count: u8,
    row_offsets: [MAX_SAMPLES_PER_COLUMN]i8 = .{0} **
        MAX_SAMPLES_PER_COLUMN,

    pub fn validate(self: ColumnV2) Error!void {
        if (self.log_size == 0 or self.log_size >= 31 or
            self.sample_count == 0 or
            self.sample_count > MAX_SAMPLES_PER_COLUMN)
        {
            return error.InvalidMaskShape;
        }
        if (self.row_offsets[0] != 0) return error.InvalidMaskOffset;
        for (self.row_offsets[0..self.sample_count], 0..) |offset, index| {
            for (self.row_offsets[0..index]) |prior| {
                if (offset == prior) return error.InvalidMaskOffset;
            }
            if (!validOffset(offset)) return error.InvalidMaskOffset;
        }
    }
};

pub const SpanV2 = struct {
    offset: u32,
    column_count: u32,
};

pub const ComponentV2 = struct {
    kind: ethereum_statement.Kind,
    log_size: u32,
    n_rows: u32,
    spans: [TREE_COUNT]SpanV2,
    direct_constraint_count: u32,
    interaction_batch_count: u32,
};

pub const GeometryV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    base_profile_identity: [32]u8,
    extension_semantic_digest: [32]u8,
    base_column_counts: [TREE_COUNT]u32,
    components: [ethereum_statement.component_count]ComponentV2,
    columns: [TREE_COUNT][]ColumnV2,
    sampled_value_count: u32,
    detailed_claim_count: u32,
    air_instruction_count: u32,
    max_log_degree_bound: u32,
    identity_sha256: [32]u8,

    pub fn deinit(self: *GeometryV2) void {
        for (self.columns) |tree| self.allocator.free(tree);
        self.* = undefined;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        profile: *const profile_mod.ProfileV2,
        core: *const base_statement.RiscVStatement,
        extension: *const ethereum_statement.Statement,
    ) !GeometryV2 {
        try profile.validate();
        try extension.validateStructure(core);
        const base_counts = [TREE_COUNT]u32{
            profile.preprocessed_column_count,
            profile.main_column_count,
            profile.interaction_column_count,
        };
        var extension_counts = [TREE_COUNT]u32{ 0, 0, 0 };
        for (extension.components) |descriptor| {
            extension_counts[0] = try add(
                extension_counts[0],
                descriptor.preprocessed_columns,
            );
            extension_counts[1] = try add(
                extension_counts[1],
                descriptor.main_columns,
            );
            extension_counts[2] = try add(
                extension_counts[2],
                descriptor.interaction_columns,
            );
        }
        var columns: [TREE_COUNT][]ColumnV2 = undefined;
        var initialized: usize = 0;
        errdefer for (columns[0..initialized]) |tree| allocator.free(tree);
        for (&columns, extension_counts) |*tree, count| {
            tree.* = try allocator.alloc(ColumnV2, count);
            initialized += 1;
        }

        var result = GeometryV2{
            .allocator = allocator,
            .base_profile_identity = profile.identity_digest,
            .extension_semantic_digest = extension.semantic_digest,
            .base_column_counts = base_counts,
            .components = undefined,
            .columns = columns,
            .sampled_value_count = 0,
            .detailed_claim_count = 0,
            .air_instruction_count = 0,
            .max_log_degree_bound = profile.composition_log_degree_bound,
            .identity_sha256 = undefined,
        };
        errdefer result.deinit();
        try result.installFromProductionComponents(extension);
        result.identity_sha256 = result.computeIdentity();
        try result.validate();
        return result;
    }

    pub fn validate(self: *const GeometryV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidGeometryVersion;
        }
        if (allZero(self.base_profile_identity) or
            allZero(self.extension_semantic_digest) or
            self.sampled_value_count == 0 or
            self.detailed_claim_count == 0 or
            self.air_instruction_count == 0)
        {
            return error.InvalidComponentGeometry;
        }
        var cursors = [TREE_COUNT]u32{ 0, 0, 0 };
        var sampled: u32 = 0;
        var claims: u32 = 0;
        var instructions: u32 = 0;
        for (self.components, 0..) |component, index| {
            if (@intFromEnum(component.kind) != index + 1 or
                component.log_size == 0 or component.log_size >= 31 or
                component.n_rows > (@as(u32, 1) << @intCast(component.log_size)))
            {
                return error.InvalidComponentGeometry;
            }
            for (component.spans, 0..) |span, tree| {
                if (span.offset != cursors[tree])
                    return error.InvalidComponentGeometry;
                cursors[tree] = try add(cursors[tree], span.column_count);
            }
            claims = try add(claims, component.interaction_batch_count);
            instructions = try add(
                instructions,
                try add(
                    component.direct_constraint_count,
                    component.interaction_batch_count,
                ),
            );
        }
        for (self.columns, cursors) |tree, cursor| {
            if (tree.len != cursor) return error.InvalidComponentGeometry;
            for (tree) |column| {
                try column.validate();
                sampled = try add(sampled, column.sample_count);
            }
        }
        if (sampled != self.sampled_value_count or
            claims != self.detailed_claim_count or
            instructions != self.air_instruction_count)
        {
            return error.InvalidComponentGeometry;
        }
        if (!std.mem.eql(u8, &self.computeIdentity(), &self.identity_sha256))
            return error.InvalidGeometryIdentity;
    }

    pub fn validateAgainst(
        self: *const GeometryV2,
        profile: *const profile_mod.ProfileV2,
        core: *const base_statement.RiscVStatement,
        extension: *const ethereum_statement.Statement,
    ) !void {
        try self.validate();
        var expected = try init(self.allocator, profile, core, extension);
        defer expected.deinit();
        if (!equal(self, &expected)) return error.InvalidExtensionAuthority;
    }

    fn installFromProductionComponents(
        self: *GeometryV2,
        extension: *const ethereum_statement.Statement,
    ) !void {
        const max_log = maximumLogDegreeBound(extension, self.max_log_degree_bound);
        self.max_log_degree_bound = max_log;
        const point = logup.liftPoint(canonic.CanonicCoset.new(max_log).coset().initial);
        var cursors = [TREE_COUNT]u32{ 0, 0, 0 };
        const keccak_native = keccak_relations.Relations.dummy();
        const secp_native = secp_relations.Relations.dummy();
        const keccak_claim = keccak_component.Claim{
            .log_size = extension.components[0].log_size,
            .n_rows = extension.components[0].n_rows,
            .first_call_index = 0,
            .call_count = extension.counts.keccak_calls,
            .batch_sums = @splat(QM31.zero()),
            .component_sum = QM31.zero(),
        };
        var keccak = try keccak_component.KeccakShardComponent.initVerifier(
            keccak_claim,
            .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 },
            &keccak_native,
        );
        try self.install(0, extension.components[0], &keccak, point, &cursors);

        inline for (.{ keccak_tables.Kind.chi, keccak_tables.Kind.xor5 }, 1..) |kind, index| {
            var tuples: [keccak_tables.arity]usize = undefined;
            for (&tuples, 0..) |*value, field| value.* = field + 1;
            var component = try keccak_table.KeccakTableComponent.initVerifier(
                kind,
                .{
                    .is_first_col_idx = 0,
                    .tuple_col_indices = tuples,
                    .main_col_offset = 0,
                    .interaction_col_offset = 0,
                },
                &keccak_native,
                QM31.zero(),
            );
            try self.install(index, extension.components[index], &component, point, &cursors);
        }
        inline for (.{
            secp_bundle.ProductBase,
            secp_bundle.ProductScalar,
            secp_bundle.LinearBase,
            secp_bundle.LinearScalar,
            secp_config.Point,
            secp_config.Split,
            secp_config.ScalarProgram,
            secp_config.Table,
            secp_config.Recovery,
            secp_config.ByteTable,
            secp_config.RecoveryCaller,
        }, 3..) |Config, index| {
            const descriptor = extension.components[index];
            const claim = secp_component.Claim(Config){
                .log_size = descriptor.log_size,
                .n_rows = descriptor.n_rows,
                .batch_sums = @splat(QM31.zero()),
                .component_sum = QM31.zero(),
            };
            var component = try secp_component.Component(Config).init(
                claim,
                .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 },
                &secp_native,
            );
            try self.install(index, descriptor, &component, point, &cursors);
        }
        for (self.columns, cursors) |tree, cursor| {
            if (tree.len != cursor) return error.InvalidComponentGeometry;
        }
    }

    fn install(
        self: *GeometryV2,
        index: usize,
        descriptor: ethereum_statement.Descriptor,
        component: anytype,
        point: Point,
        cursors: *[TREE_COUNT]u32,
    ) !void {
        var mask = try component.maskPoints(
            self.allocator,
            point,
            self.max_log_degree_bound,
        );
        defer mask.deinitDeep(self.allocator);
        if (mask.items.len != TREE_COUNT) return error.InvalidMaskShape;
        const expected_counts = [TREE_COUNT]u32{
            descriptor.preprocessed_columns,
            descriptor.main_columns,
            descriptor.interaction_columns,
        };
        var spans: [TREE_COUNT]SpanV2 = undefined;
        for (mask.items, expected_counts, 0..) |tree, expected, tree_index| {
            if (tree.len != expected) return error.InvalidMaskShape;
            spans[tree_index] = .{
                .offset = cursors[tree_index],
                .column_count = expected,
            };
            for (tree) |points| {
                const destination = &self.columns[tree_index][cursors[tree_index]];
                destination.* = try classifyColumn(
                    descriptor.log_size,
                    self.max_log_degree_bound,
                    point,
                    points,
                );
                self.sampled_value_count = try add(
                    self.sampled_value_count,
                    destination.sample_count,
                );
                cursors[tree_index] += 1;
            }
        }
        const facts = semanticFacts(descriptor.kind);
        self.components[index] = .{
            .kind = descriptor.kind,
            .log_size = descriptor.log_size,
            .n_rows = descriptor.n_rows,
            .spans = spans,
            .direct_constraint_count = facts.direct,
            .interaction_batch_count = facts.batches,
        };
        self.detailed_claim_count = try add(
            self.detailed_claim_count,
            facts.batches,
        );
        self.air_instruction_count = try add(
            self.air_instruction_count,
            try add(facts.direct, facts.batches),
        );
    }

    fn computeIdentity(self: *const GeometryV2) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(IDENTITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hash.update(&self.base_profile_identity);
        hash.update(&self.extension_semantic_digest);
        for (self.base_column_counts) |count| hashInt(&hash, u32, count);
        hashInt(&hash, u32, self.sampled_value_count);
        hashInt(&hash, u32, self.detailed_claim_count);
        hashInt(&hash, u32, self.air_instruction_count);
        hashInt(&hash, u32, self.max_log_degree_bound);
        for (self.components) |component| {
            hashInt(&hash, u8, @intFromEnum(component.kind));
            hashInt(&hash, u32, component.log_size);
            hashInt(&hash, u32, component.n_rows);
            for (component.spans) |span| {
                hashInt(&hash, u32, span.offset);
                hashInt(&hash, u32, span.column_count);
            }
            hashInt(&hash, u32, component.direct_constraint_count);
            hashInt(&hash, u32, component.interaction_batch_count);
        }
        for (self.columns, 0..) |tree, tree_index| {
            hashInt(&hash, u8, tree_index);
            hashInt(&hash, u32, tree.len);
            for (tree) |column| {
                hashInt(&hash, u32, column.log_size);
                hashInt(&hash, u8, column.sample_count);
                for (column.row_offsets[0..column.sample_count]) |offset|
                    hashInt(&hash, i8, offset);
            }
        }
        return hash.finalResult();
    }
};

const Facts = struct { direct: u32, batches: u32 };

fn semanticFacts(kind: ethereum_statement.Kind) Facts {
    return switch (kind) {
        .keccak_shard_v1 => .{
            .direct = keccak_component.direct_constraint_count,
            .batches = keccak_component.interaction_constraint_count,
        },
        // Each fixed table exposes one LogUp constraint total. It has no
        // separate direct AIR constraint.
        .keccak_chi_table_v2, .keccak_xor5_table_v2 => .{ .direct = 0, .batches = 1 },
        .secp_product_base_v1 => configFacts(secp_bundle.ProductBase),
        .secp_product_scalar_v1 => configFacts(secp_bundle.ProductScalar),
        .secp_linear_base_v1 => configFacts(secp_bundle.LinearBase),
        .secp_linear_scalar_v1 => configFacts(secp_bundle.LinearScalar),
        .secp_point_v1 => configFacts(secp_config.Point),
        .secp_split_v1 => configFacts(secp_config.Split),
        .secp_scalar_program_v1 => configFacts(secp_config.ScalarProgram),
        .secp_signed_table_v1 => configFacts(secp_config.Table),
        .secp_recovery_v1 => configFacts(secp_config.Recovery),
        .secp_byte_table_v1 => configFacts(secp_config.ByteTable),
        .secp_recovery_caller_v1 => configFacts(secp_config.RecoveryCaller),
    };
}

fn configFacts(comptime Config: type) Facts {
    return .{
        .direct = Config.direct_constraint_count,
        .batches = Config.batch_count,
    };
}

fn classifyColumn(
    log_size: u32,
    max_log: u32,
    point: Point,
    points: []const Point,
) Error!ColumnV2 {
    if (points.len == 0 or points.len > MAX_SAMPLES_PER_COLUMN)
        return error.InvalidMaskShape;
    var result = ColumnV2{
        .log_size = log_size,
        .sample_count = @intCast(points.len),
    };
    for (points, 0..) |sample, index| {
        result.row_offsets[index] = try pointOffset(max_log, point, sample);
    }
    try result.validate();
    return result;
}

fn pointOffset(max_log: u32, point: Point, sample: Point) Error!i8 {
    inline for ([_]i8{ 0, -1, 1, -2, 2, 27 }) |offset| {
        const expected = shiftedPoint(max_log, point, offset);
        if (sample.eql(expected)) return offset;
    }
    return error.InvalidMaskOffset;
}

fn shiftedPoint(log_size: u32, point: Point, offset: i8) Point {
    const step = logup.liftPoint(canonic.CanonicCoset.new(log_size).coset_value.step);
    return point.add(step.mulSigned(offset));
}

fn maximumLogDegreeBound(
    extension: *const ethereum_statement.Statement,
    base: u32,
) u32 {
    var result = base;
    for (extension.components) |descriptor| result = @max(
        result,
        descriptor.log_size + 1,
    );
    return result;
}

fn validOffset(value: i8) bool {
    return switch (value) {
        -2, -1, 0, 1, 2, 27 => true,
        else => false,
    };
}

fn equal(left: *const GeometryV2, right: *const GeometryV2) bool {
    if (left.format_version != right.format_version or
        left.schema_version != right.schema_version or
        !std.mem.eql(u8, &left.base_profile_identity, &right.base_profile_identity) or
        !std.mem.eql(u8, &left.extension_semantic_digest, &right.extension_semantic_digest) or
        !std.meta.eql(left.base_column_counts, right.base_column_counts) or
        !std.meta.eql(left.components, right.components) or
        left.sampled_value_count != right.sampled_value_count or
        left.detailed_claim_count != right.detailed_claim_count or
        left.air_instruction_count != right.air_instruction_count or
        left.max_log_degree_bound != right.max_log_degree_bound or
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

fn add(left: u32, right: anytype) Error!u32 {
    return std.math.add(u32, left, @intCast(right)) catch
        error.ArithmeticOverflow;
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
    if (TREE_COUNT != 3 or MAX_SAMPLES_PER_COLUMN != 6 or
        ethereum_statement.component_count != 14)
    {
        @compileError("Ethereum extension geometry inventory drifted");
    }
}
