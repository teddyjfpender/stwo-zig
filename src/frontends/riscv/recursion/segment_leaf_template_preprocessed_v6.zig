//! Verifier-side fixed preprocessing for the eleven appended direct-leaf rows.
//! No child proof, transcript execution, leaf identity, or witness is accepted.
//! Base rows remain unavailable until their own fixed writers are qualified.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
const template_mod = @import("air/segment_leaf_wrapper_template_v6.zig");
const roster = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const statement = @import("../air/statement.zig");
const native_schedule = @import("air/verifier_schedule.zig");
const link_program = @import("ethereum_leaf_link_program_v3.zig");
const child_program = @import("ethereum_leaf_child_field_program_v1.zig");
const row4_template = @import("transcript_word_template_v6.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");
const projection_air = @import("air/ethereum_leaf_link_projection_v1.zig");
const arithmetic_air = @import("air/ethereum_leaf_link_arithmetic_v1.zig");
const arithmetic_witness = @import("air/ethereum_leaf_link_arithmetic_witness_v1.zig");
const words_air = @import("air/transcript_program_v2_field_bridge_v5.zig");
const word_template_mod = @import("transcript_program_v2_template_words_v6.zig");
const security = @import("segment_v3_production_security_policy.zig");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_witness = @import("air/vm_public_claim_hash_witness.zig");
const program_hash = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const tree0_air = @import("air/segment_v2_tree0_field_link_direct_v4.zig");
const router_air = @import("air/ethereum_leaf_child_field_router_v1.zig");
const framework = @import("air/framework_interaction.zig");
const channel = @import("poseidon2_channel.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const FIRST_ROW: u8 = 39;
pub const LAST_ROW: u8 = 49;
pub const QUALIFIED_ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;

pub const Writer = struct {
    allocator: std.mem.Allocator,
    manifest: template_mod.TemplateManifestV6,
    link: link_program.ProgramV3,
    child: child_program.ProgramV1,
    frame: row4_template.Template,
    program_words: word_template_mod.Template,

    pub fn init(
        allocator: std.mem.Allocator,
        base_catalog: *const catalog_mod.Catalog,
        shape: roster.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const native_schedule.Plan,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
    ) !Writer {
        const manifest = try template_mod.TemplateManifestV6.build(
            allocator,
            base_catalog,
            shape,
            component_descs,
            infra_descs,
            native_plan,
            native_wire_word_count,
            native_lookup_enabled,
        );
        var link = try link_program.ProgramV3.init(allocator);
        errdefer link.deinit();
        var child = try child_program.ProgramV1.init(allocator, component_descs, infra_descs);
        errdefer child.deinit();
        var frame = try row4_template.Template.buildFromAdmittedShape(
            allocator,
            native_plan,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
        );
        errdefer frame.deinit();
        var program_words = try word_template_mod.Template.initFromShape(
            allocator,
            native_plan,
            security.REQUIRED_PCS_CONFIG,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
        );
        errdefer program_words.deinit();
        if (program_words.words.len != manifest.shape.program_words)
            return error.FixedRowGeometryMismatchV6;
        return .{ .allocator = allocator, .manifest = manifest, .link = link, .child = child, .frame = frame, .program_words = program_words };
    }

    pub fn deinit(self: *Writer) void {
        self.program_words.deinit();
        self.frame.deinit();
        self.child.deinit();
        self.link.deinit();
        self.* = undefined;
    }

    /// Writes only one independently compiled row, using canonical committed
    /// row order. Destination is row-local, zeroed, and exact-width.
    pub fn writeRow(self: *const Writer, row: u8, destination: [][]M31) !void {
        if (row < FIRST_ROW or row > LAST_ROW) return error.UnqualifiedFixedRowV6;
        const geometry = self.manifest.placements[row].geometry;
        if (geometry.preprocessed_columns != destination.len or geometry.log_size >= @bitSizeOf(usize))
            return error.FixedRowGeometryMismatchV6;
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        for (destination) |column| {
            if (column.len != capacity) return error.FixedRowGeometryMismatchV6;
            for (column) |value| if (!value.isZero()) return error.FixedRowDestinationNotFreshV6;
        }
        switch (row) {
            39 => {
                try requireWidth(geometry.preprocessed_columns, source_air.PREPROCESSED_COLUMN_COUNT);
                for (self.link.source_rows, 0..) |fixed, index| {
                    const logical = fixed.logical(M31.zero());
                    try put(destination, geometry.log_size, index, logical[source_air.PHYSICAL_MAIN_COLUMN_COUNT..]);
                }
            },
            40 => {
                try requireWidth(geometry.preprocessed_columns, projection_air.PREPROCESSED_COLUMN_COUNT);
                for (self.link.projection_rows, 0..) |fixed, index| {
                    const logical = fixed.logical(M31.zero());
                    try put(destination, geometry.log_size, index, logical[projection_air.PHYSICAL_MAIN_COLUMN_COUNT..]);
                }
            },
            41 => {
                try requireWidth(geometry.preprocessed_columns, arithmetic_air.PREPROCESSED_COLUMN_COUNT);
                const kinds = [_]arithmetic_air.Kind{ .entry_root, .exit_root, .completion, .position };
                for (kinds, 0..) |kind, index| {
                    const logical = try arithmetic_witness.logicalRow(kind, 0, false, 0, 0);
                    try put(destination, geometry.log_size, index, logical[arithmetic_air.PHYSICAL_MAIN_COLUMN_COUNT..]);
                }
            },
            42 => {
                try requireWidth(geometry.preprocessed_columns, words_air.PREPROCESSED_COLUMN_COUNT);
                const fixed = try words_air.FixedSchedule.init(self.manifest.shape.program_words);
                if (fixed.log_size != geometry.log_size) return error.FixedRowGeometryMismatchV6;
                for (0..capacity) |index| {
                    const values = if (index < self.program_words.words.len)
                        try self.program_words.preprocessedRow(index)
                    else
                        [_]M31{M31.zero()} ** words_air.PREPROCESSED_COLUMN_COUNT;
                    try put(destination, geometry.log_size, index, &values);
                }
            },
            43 => {
                try requireWidth(geometry.preprocessed_columns, hash_air.PREPROCESSED_COLUMN_COUNT);
                const word_count = self.manifest.shape.program_words;
                const count = try std.math.divCeil(usize, @as(usize, word_count) + 1, hash_witness.RATE);
                for (0..count) |index| {
                    var fixed = try hash_witness.expectedRow(word_count, count, index);
                    fixed.step += program_hash.PROGRAM_STEP_BASE;
                    const values = fixed.values();
                    try put(destination, geometry.log_size, index, &values);
                }
            },
            44 => {
                try requireWidth(geometry.preprocessed_columns, tree0_air.PREPROCESSED_COLUMN_COUNT);
                for (0..8) |limb| {
                    const logical = tree0_air.logicalRow(M31.zero(), M31.zero(), 1, @intCast(limb), self.frame.tree0_hash_id, @intCast(channel.RATE + limb));
                    try put(destination, geometry.log_size, limb, logical[tree0_air.PHYSICAL_MAIN_COLUMN_COUNT..]);
                }
            },
            45, 46 => {
                try requireWidth(geometry.preprocessed_columns, hash_air.PREPROCESSED_COLUMN_COUNT);
                const rows = if (row == 45) self.link.metadata_hash.rows else self.link.link_hash.rows;
                for (rows, 0..) |fixed, index| {
                    const values = fixed.values();
                    try put(destination, geometry.log_size, index, &values);
                }
            },
            47 => {
                try requireWidth(geometry.preprocessed_columns, router_air.PREPROCESSED_COLUMN_COUNT);
                const active = self.child.router_rows.len - @import("segment_leaf_wrapper_local_identity_v5.zig").REMOVED_TREE0_FORWARD_ROWS;
                for (self.child.router_rows[0..active], 0..) |fixed, index| {
                    const values = fixed.preprocessed();
                    var felts: [router_air.PREPROCESSED_COLUMN_COUNT]M31 = undefined;
                    for (values, &felts) |value, *felt| felt.* = M31.fromCanonical(value);
                    try put(destination, geometry.log_size, index, &felts);
                }
            },
            48, 49 => {
                try requireWidth(geometry.preprocessed_columns, hash_air.PREPROCESSED_COLUMN_COUNT);
                const rows = if (row == 48) self.child.authority_hash.rows else self.child.receipt_hash.rows;
                for (rows, 0..) |fixed, index| {
                    const values = fixed.values();
                    try put(destination, geometry.log_size, index, &values);
                }
            },
            else => unreachable,
        }
    }

    pub fn requireCompletePreprocessing(_: *const Writer) error{UnqualifiedFixedRowsV6}!void {
        return error.UnqualifiedFixedRowsV6;
    }
};

fn requireWidth(actual: usize, expected: usize) !void {
    if (actual != expected) return error.FixedRowGeometryMismatchV6;
}

fn put(destination: [][]M31, log_size: u32, logical: usize, values: []const M31) !void {
    if (values.len != destination.len or logical >= @as(usize, 1) << @intCast(log_size))
        return error.FixedRowGeometryMismatchV6;
    const committed = framework.committedRow(logical, log_size);
    for (values, destination) |value, column| column[committed] = value;
}

test "V6 appended rows rebuild fixed columns without either leaf source identity" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const v2_manifest = @import("air/segment_outer_adapter_manifest_v2.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const base_catalog = try catalog_mod.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const instructions = try @import("transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const shape = roster.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    var first = try Writer.init(allocator, &base_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, false);
    defer first.deinit();
    var second = try Writer.init(allocator, &base_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, false);
    defer second.deinit();
    const first_v2 = try v2_manifest.assemble(&base_catalog, fixture.authorityIds());
    var changed_ids = fixture.authorityIds();
    changed_ids.transcript_manifest_id[0] += 1;
    const second_v2 = try v2_manifest.assemble(&base_catalog, changed_ids);
    try std.testing.expect(!std.meta.eql(first_v2.seal, second_v2.seal));
    try std.testing.expectEqualDeep(first.manifest.seal, second.manifest.seal);
    for (FIRST_ROW..LAST_ROW + 1) |row| {
        const geometry = first.manifest.placements[row].geometry;
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const left = try a.alloc([]M31, geometry.preprocessed_columns);
        const right = try a.alloc([]M31, geometry.preprocessed_columns);
        for (left, right) |*x, *y| {
            x.* = try a.alloc(M31, capacity);
            y.* = try a.alloc(M31, capacity);
            @memset(x.*, M31.zero());
            @memset(y.*, M31.zero());
        }
        try first.writeRow(@intCast(row), left);
        try second.writeRow(@intCast(row), right);
        for (left, right) |x, y| try std.testing.expectEqualDeep(x, y);
        try std.testing.expectError(error.FixedRowDestinationNotFreshV6, first.writeRow(@intCast(row), left));
    }
    try std.testing.expectError(error.UnqualifiedFixedRowV6, first.writeRow(38, &.{}));
    try std.testing.expectError(error.UnqualifiedFixedRowsV6, first.requireCompletePreprocessing());
}
