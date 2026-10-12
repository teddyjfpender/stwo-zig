//! Candidate exact fixed Tree0 writer for FRI-circuit input row 29.
//!
//! V9's verifier-owned transcript shape and core FRI profile compile the
//! canonical arithmetic graph and its complete input-use multiplicities.
//! The same graph serves all three lanes with the pinned distinct circuit
//! IDs. A child proof contributes no topology or fixed value. V9 does not
//! yet seal this row's full fixed digest or corrected geometry, so template
//! admission remains deliberately unavailable.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const template = @import("air/segment_leaf_wrapper_template_v9.zig");
const fixed_profile = @import("fixed_profile.zig");
const protocol = @import("protocol.zig");
const circuit_mod = @import("air/fri_verifier_circuit.zig");
const witness = @import("air/fri_verifier_input_witness.zig");
const air = @import("air/fri_verifier_input.zig");
const geometry_mod = @import("air/universal_manifest_contract.zig");
const typed_geometry = @import("air/universal_typed_geometry.zig");
const framework = @import("air/framework_interaction.zig");
// Direct-leaf FRI circuit IDs are pinned by detached_fri_core_part_01.zig.
// The binary outer source uses a separate 401/402/403 namespace and cannot
// supply the fixed columns for this direct-leaf roster.
const SEGMENT_CIRCUIT_ID: u32 = 301;
const LEFT_CIRCUIT_ID: u32 = 302;
const RIGHT_CIRCUIT_ID: u32 = 303;

pub const ROW: u8 = 29;
pub const FIXED_COLUMNS_DOMAIN = "stwo-zig/riscv-v9-row29-complete-fixed-columns/v1\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TEMPLATE_ADMISSION_AVAILABLE = false;

pub const FixedDescriptor = struct {
    v9_template_seal: [32]u8,
    graph_identity: [32]u8,
    geometry: geometry_mod.Geometry,
    fixed_columns_id: [32]u8,
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    key_seal: [32]u8,
    circuit: *circuit_mod.Circuit,
    reference: witness.Reference,
    preprocessing: witness.Preprocessed,

    pub fn initFromVerifierTemplate(allocator: std.mem.Allocator, key: *const template.TemplateManifestV9) !Writer {
        try key.validate();
        var widths: [circuit_mod.MAX_FRI_LAYERS]u32 = undefined;
        const profile = try profileFromTemplate(key, &widths);
        const circuit = try allocator.create(circuit_mod.Circuit);
        errdefer allocator.destroy(circuit);
        circuit.* = try circuit_mod.build(allocator, profile);
        errdefer circuit.deinit();
        const reference = try witness.Reference.seal(.{
            .{ .verifier_id = witness.SEGMENT_VERIFIER_ID, .circuit_id = SEGMENT_CIRCUIT_ID, .circuit = circuit },
            .{ .verifier_id = witness.LEFT_RECURSION_VERIFIER_ID, .circuit_id = LEFT_CIRCUIT_ID, .circuit = circuit },
            .{ .verifier_id = witness.RIGHT_RECURSION_VERIFIER_ID, .circuit_id = RIGHT_CIRCUIT_ID, .circuit = circuit },
        });
        const preprocessing = try witness.Preprocessed.init(allocator, reference);
        return .{
            .allocator = allocator,
            .key_seal = key.seal,
            .circuit = circuit,
            .reference = reference,
            .preprocessing = preprocessing,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.preprocessing.deinit();
        self.circuit.deinit();
        self.allocator.destroy(self.circuit);
        self.* = undefined;
    }

    pub fn geometry(self: *const Writer) geometry_mod.Geometry {
        return typed_geometry.manifestGeometryForAir(air, geometry_mod, .fri_verifier_input, self.preprocessing.log_size);
    }

    pub fn requireTemplateAdmission(_: *const Writer) error{CoreFriInputFixedKeyNotInTemplateV9}!void {
        return error.CoreFriInputFixedKeyNotInTemplateV9;
    }

    pub fn writePhysical(self: *const Writer, key: *const template.TemplateManifestV9, geometry_value: geometry_mod.Geometry, columns: [][]M31) !void {
        if (!std.meta.eql(geometry_value, self.geometry()) or
            geometry_value.log_size >= @bitSizeOf(usize) or
            columns.len != air.PREPROCESSED_COLUMN_COUNT)
            return error.CoreFriInputFixedGeometryMismatchV9;
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const protected = try addressRange(witness.Row, self.preprocessing.rows);
        for (columns, 0..) |column, index| {
            if (column.len != capacity) return error.CoreFriInputFixedGeometryMismatchV9;
            const destination = try addressRange(M31, column);
            if (destination.overlaps(protected)) return error.CoreFriInputFixedAliasedDestinationV9;
            for (columns[0..index]) |prior| if (destination.overlaps(try addressRange(M31, prior)))
                return error.CoreFriInputFixedAliasedDestinationV9;
            for (column) |word| if (!word.isZero()) return error.CoreFriInputFixedDestinationNotFreshV9;
        }
        try key.validate();
        if (!std.meta.eql(key.seal, self.key_seal)) return error.CoreFriInputTemplateMismatchV9;
        var widths: [circuit_mod.MAX_FRI_LAYERS]u32 = undefined;
        const profile = try profileFromTemplate(key, &widths);
        if (!std.meta.eql(profile.identityDigest(), self.circuit.profile_digest))
            return error.CoreFriInputGraphProfileMismatchV9;
        try self.reference.validateAuthority();
        try self.preprocessing.validateAgainstAuthority(self.allocator, self.reference);
        if (self.preprocessing.rows.len > capacity) return error.CoreFriInputFixedGeometryMismatchV9;
        for (self.preprocessing.rows, 0..) |row, logical| {
            const committed = framework.committedRow(logical, geometry_value.log_size);
            const values = row.values();
            for (columns, values) |column, value| column[committed] = value;
        }
    }

    pub fn descriptor(self: *const Writer, key: *const template.TemplateManifestV9) !FixedDescriptor {
        const geometry_value = self.geometry();
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const columns = try self.allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
        defer self.allocator.free(columns);
        for (columns) |*column| {
            column.* = try self.allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        defer for (columns) |column| self.allocator.free(column);
        try self.writePhysical(key, geometry_value, columns);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(FIXED_COLUMNS_DOMAIN);
        hashInt(&hash, u8, ROW);
        hashInt(&hash, u32, geometry_value.log_size);
        hashInt(&hash, u16, geometry_value.preprocessed_columns);
        hash.update(&air.SEMANTIC_DIGEST);
        for (columns) |column| for (column) |word| hashInt(&hash, u32, word.toU32());
        return .{
            .v9_template_seal = self.key_seal,
            .graph_identity = self.circuit.identity_digest,
            .geometry = geometry_value,
            .fixed_columns_id = hash.finalResult(),
        };
    }
};

fn profileFromTemplate(key: *const template.TemplateManifestV9, widths: *[circuit_mod.MAX_FRI_LAYERS]u32) !circuit_mod.Profile {
    const shape = key.schedule_shape;
    const core_profile = key.v8_template.v7_template.v6_template.shape.core_profile;
    if (shape.fri.count == 0 or shape.fri.terminal_evaluation_log < protocol.FRI_LOG_BLOWUP_FACTOR)
        return error.CoreFriInputProfileMismatchV9;
    for (shape.fri.active(), 0..) |round, index| widths[index] = round.fold_width;
    // `Profile` borrows caller-owned storage until the circuit is built.
    const profile = circuit_mod.Profile{
        .lifting_log_size = core_profile.vm.lifting_log_size,
        .log_blowup_factor = protocol.FRI_LOG_BLOWUP_FACTOR,
        .log_last_layer_degree_bound = shape.fri.terminal_evaluation_log - protocol.FRI_LOG_BLOWUP_FACTOR,
        .fold_widths = widths[0..shape.fri.count],
        .query_count = shape.query_count,
    };
    try profile.validate();
    var config = protocol.PCS_CONFIG.fri_config;
    config.log_blowup_factor = profile.log_blowup_factor;
    config.log_last_layer_degree_bound = profile.log_last_layer_degree_bound;
    config.n_queries = profile.query_count;
    config.fold_step = std.math.log2_int(u32, widths[0]);
    const expected = try fixed_profile.FriSchedule.init(profile.lifting_log_size - profile.log_blowup_factor, config);
    if (!std.meta.eql(expected, shape.fri)) return error.CoreFriInputProfileMismatchV9;
    return profile;
}

const AddressRange = struct {
    start: usize,
    end: usize,
    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn addressRange(comptime T: type, values: []const T) !AddressRange {
    const start = @intFromPtr(values.ptr);
    const size = try std.math.mul(usize, values.len, @sizeOf(T));
    return .{ .start = start, .end = try std.math.add(usize, start, size) };
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V9 row29 q193 fixed columns match native circuit-input writer at every cell" {
    const allocator = std.testing.allocator;
    const key = try testKey(allocator);
    var writer = try Writer.initFromVerifierTemplate(allocator, &key);
    defer writer.deinit();
    try std.testing.expectEqualDeep([_]u32{ 301, 302, 303 }, [_]u32{
        writer.reference.lanes[0].circuit_id,
        writer.reference.lanes[1].circuit_id,
        writer.reference.lanes[2].circuit_id,
    });
    const geometry_value = writer.geometry();
    const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
    const columns = try allocColumns(allocator, capacity);
    defer freeColumns(allocator, columns);
    try writer.writePhysical(&key, geometry_value, columns);
    var definition = try air.build(allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var logical: [air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&logical) |*column| column.* = try allocator.alloc(M31, capacity);
    defer for (logical) |column| allocator.free(column);
    try executor.generatePreprocessedInto(&writer.preprocessing, writer.reference, &logical);
    for (logical, columns) |native_column, physical_column|
        for (native_column, 0..) |value, row|
            try std.testing.expectEqual(value, physical_column[framework.committedRow(row, geometry_value.log_size)]);
    const descriptor = try writer.descriptor(&key);
    try std.testing.expectEqualDeep(writer.circuit.identity_digest, descriptor.graph_identity);
    try std.testing.expectEqualDeep(geometry_value, descriptor.geometry);
    try std.testing.expectError(error.CoreFriInputFixedKeyNotInTemplateV9, writer.requireTemplateAdmission());
    try std.testing.expectError(error.CoreFriInputFixedDestinationNotFreshV9, writer.writePhysical(&key, geometry_value, columns));
    for (columns) |column| @memset(column, M31.zero());
    const alias = try allocator.dupe([]M31, columns);
    defer allocator.free(alias);
    alias[1] = alias[0];
    try std.testing.expectError(error.CoreFriInputFixedAliasedDestinationV9, writer.writePhysical(&key, geometry_value, alias));
    var changed = geometry_value;
    changed.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.CoreFriInputFixedGeometryMismatchV9, writer.writePhysical(&key, changed, columns));
    changed = geometry_value;
    changed.protocol_constraint_degree += 1;
    try std.testing.expectError(error.CoreFriInputFixedGeometryMismatchV9, writer.writePhysical(&key, changed, columns));
}

test "V9 row29 rejects graph, use-count and key mutation before fixed writes" {
    const allocator = std.testing.allocator;
    const key = try testKey(allocator);
    var writer = try Writer.initFromVerifierTemplate(allocator, &key);
    defer writer.deinit();
    const geometry_value = writer.geometry();
    const columns = try allocColumns(allocator, @as(usize, 1) << @intCast(geometry_value.log_size));
    defer freeColumns(allocator, columns);
    writer.preprocessing.rows[0].use_count += 1;
    try std.testing.expectError(error.AuthorityMismatch, writer.writePhysical(&key, geometry_value, columns));
    writer.preprocessing.rows[0].use_count -= 1;
    writer.circuit.identity_digest[0] ^= 1;
    if (writer.writePhysical(&key, geometry_value, columns)) |_| return error.TestExpectedError else |_| {}
    writer.circuit.identity_digest[0] ^= 1;
    var wrong_key = key;
    wrong_key.seal[0] ^= 1;
    if (writer.writePhysical(&wrong_key, geometry_value, columns)) |_| return error.TestExpectedError else |_| {}
    for (columns) |column| for (column) |word| try std.testing.expect(word.isZero());
}

fn testKey(allocator: std.mem.Allocator) !template.TemplateManifestV9 {
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const v6 = @import("air/segment_leaf_wrapper_template_v6.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const shape_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const profile = try v6.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const instructions = try @import("transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const wrapper_shape = shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    return template.TemplateManifestV9.build(
        allocator,
        &source_catalog,
        wrapper_shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
        try @import("segment_profile.zig").transcriptShape(),
    );
}

fn allocColumns(allocator: std.mem.Allocator, capacity: usize) ![][]M31 {
    const columns = try allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
    errdefer allocator.free(columns);
    var made: usize = 0;
    errdefer for (columns[0..made]) |column| allocator.free(column);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
        made += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
