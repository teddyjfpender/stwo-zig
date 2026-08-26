//! Versioned typed row-window IR for the opcode-family compatibility shadow.
//!
//! This layer turns compat-v1's descriptive window annotations into compiler-
//! owned columns, shifted-column nodes, component ownership, first-row boundary
//! policy, degree context, and concrete PCS mask points. The full plan remains
//! a cold compatibility/compiler artifact; the live opcode LogUp component
//! consumes its compact authenticated `ComponentMaskBinding` projection.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const compat_layout = @import("compat_layout.zig");
const expr = @import("expr.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const protocol_degree = @import("protocol_degree.zig");
const shadow_program = @import("shadow_program.zig");
const static_registry = @import("static_profile_registry.zig");
const trace = @import("../../runner/trace.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const format_id = "stwo.typed-air.row-window-v1";
pub const format_version: u16 = 1;
pub const digest_domain = "stwo-zig/typed-air/row-window-plan/v1\x00";
pub const Digest = [32]u8;
pub const EXPECTED_NATIVE_PLAN_DIGEST_HEX = [_][]const u8{
    "bdf9e1a872586a9cd2e757525f3999a5dd399bd552684a8cc43573954506c636",
    "6af575f69bdd9e2437d6e7aec5056cd230aa000002c2f3f2508904cf644e29d6",
    "dd6d8909ee1fd18a487b2777162cd062e331592833ac729416cb2e6d50159a3d",
    "91e56b3b0bd9c4d770c944c7d324635518a0440c3f0ad91c1d841b452e1bc9f8",
    "433785230ac74aa7e820348d5cc2bcee0db845e854d3ea64b32de3d9503c9316",
    "51d1aeda45f142f7eb37c0b164b1713d19ef0a34c865b17a34c78c51b05a9629",
    "d645e166f71828ae6cf8b4448983b6e9ee38ca658c51f95eb9b5160410e03e0b",
    "ab4cec9f954470e0f1d3c7a7ef20f62ca08a2742f0342735fdb04aa79e6ec8f7",
    "2224cfaa2175e583cf14d71916a64d31dfd51a17647698e0e85d58e6656be2d5",
    "d99f53669161b0917aecf4c80b25850eb106485471df8b325c476926157e60d6",
    "c53ef9458e16494f44e64cd46aa87389c0deeac03ab3138589c80a83c91648de",
    "7ea0fe73f1c1a8b483ae37076f1647ead1bbb99d982b98044f858006b7e38861",
    "8cc99a1260301e73188995ee51ec66bc477c4113df72802749d21f36e2a135af",
    "7ecea862497778e3390157e0d8ebc9511a9f0ba7c95370d85b41d3ba51fc3b77",
    "59093f40f58a284919a70cc2e1e291b0ec97ef554d68944ca62404456bda5434",
    "4c31252a61ae21966430a8d41fcaaa2d7ee94fb04533a9f2453afb448556e7e8",
    "12d359cacf944c7676aa9f8c8fbe8abaf5d10b13de37078b8b9ee6575beaf414",
};
pub const component_binding_domain =
    "stwo-zig/typed-air/component-mask-binding/v1\x00";
pub const semantic_component_binding_domain =
    "stwo-zig/typed-air/semantic-mask-binding/v1\x00";

pub const ComponentKind = enum(u8) {
    semantic,
    interaction,
};

/// Stable owner identity. `instance` is explicit so future multi-instance
/// components cannot accidentally alias the current singleton placement.
pub const Owner = struct {
    family: trace.OpcodeFamily,
    component: ComponentKind,
    instance: u32,
};

pub fn ownerFor(
    family: trace.OpcodeFamily,
    component: ComponentKind,
) Owner {
    return .{ .family = family, .component = component, .instance = 0 };
}

pub const ColumnId = types.TraceColumnId;
pub const ShiftedColumnId = types.ShiftedColumnId;
pub const WindowId = types.RowWindowId;

pub const first_selector_window: WindowId = @enumFromInt(0);
pub const active_selector_window: WindowId = @enumFromInt(1);
pub const semantic_window: WindowId = @enumFromInt(2);
pub const interaction_window: WindowId = @enumFromInt(3);

/// Trace-order offsets supported by the first format. PCS point order is
/// canonicalized separately as current, then previous.
pub const RowOffset = expr.RowOffset;

/// Physical committed columns are base-field polynomials. Interaction columns
/// additionally retain their coordinate type so four unrelated columns cannot
/// be silently reassembled as one secure-field value.
pub const ColumnType = union(enum) {
    base_field,
    secure_coordinate: compat_layout.SecureCoordinate,
};

pub const Range = struct {
    start: u32,
    len: u32,

    pub fn end(self: Range) error{CountOverflow}!usize {
        return std.math.add(
            usize,
            @as(usize, self.start),
            @as(usize, self.len),
        ) catch return error.CountOverflow;
    }
};

pub const FirstRowClaim = struct {
    owner: Owner,
    selector: ColumnId,
    claim_count: u32,
    coordinates_per_claim: u8,
};

/// Fixed, allocation-free projection consumed by the live lookup component.
/// Compatibility bindings source their geometry from a pinned full row-window
/// plan. Compiler-selected research bindings instead source their interaction
/// width from the authenticated lookup partition while retaining the same
/// semantic main-layout authority.
pub const ComponentMaskBinding = struct {
    pub const Mode = enum(u8) {
        compatibility = 0,
        compiler_selected = 1,
    };

    schema_version: u16 = format_version,
    family: trace.OpcodeFamily,
    mode: Mode,
    semantic_program_digest: Digest,
    witness_layout_digest: Digest,
    geometry_source_digest: Digest,
    preprocessed_current_columns: u8,
    borrowed_main_current_columns: u32,
    owned_interaction_current_previous_columns: u32,
    binding_digest: Digest,

    pub fn initCompatibility(
        family: trace.OpcodeFamily,
    ) Error!ComponentMaskBinding {
        const family_index: usize = @intFromEnum(family);
        if (family_index >= static_registry.DESCRIPTORS.len)
            return error.InvalidOwner;
        var result = ComponentMaskBinding{
            .family = family,
            .mode = .compatibility,
            .semantic_program_digest = static_registry.DESCRIPTORS[family_index].semantic_program_digest,
            .witness_layout_digest = witness_layout.digest(),
            .geometry_source_digest = try runtime.digestFromHex(
                EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
            ),
            .preprocessed_current_columns = 1,
            .borrowed_main_current_columns = @intCast(
                trace.nColumnsForFamily(family),
            ),
            .owned_interaction_current_previous_columns = @intCast(
                opcode_entries.interactionColumnCount(family),
            ),
            .binding_digest = .{0} ** 32,
        };
        result.binding_digest = result.identityDigest();
        try result.validate();
        return result;
    }

    pub fn initCompilerSelected(
        family: trace.OpcodeFamily,
        selected_plan_digest: Digest,
        interaction_columns: usize,
    ) Error!ComponentMaskBinding {
        const family_index: usize = @intFromEnum(family);
        if (family_index >= static_registry.DESCRIPTORS.len)
            return error.InvalidOwner;
        const interaction_count = std.math.cast(
            u32,
            interaction_columns,
        ) orelse return error.CountOverflow;
        var result = ComponentMaskBinding{
            .family = family,
            .mode = .compiler_selected,
            .semantic_program_digest = static_registry.DESCRIPTORS[family_index].semantic_program_digest,
            .witness_layout_digest = witness_layout.digest(),
            .geometry_source_digest = selected_plan_digest,
            .preprocessed_current_columns = 1,
            .borrowed_main_current_columns = @intCast(
                trace.nColumnsForFamily(family),
            ),
            .owned_interaction_current_previous_columns = interaction_count,
            .binding_digest = .{0} ** 32,
        };
        result.binding_digest = result.identityDigest();
        try result.validate();
        return result;
    }

    pub fn validate(self: *const ComponentMaskBinding) Error!void {
        const family_index: usize = @intFromEnum(self.family);
        if (family_index >= static_registry.DESCRIPTORS.len)
            return error.InvalidOwner;
        const descriptor = static_registry.DESCRIPTORS[family_index];
        const expected_witness_layout = witness_layout.digest();
        if (self.schema_version != format_version or
            descriptor.family != self.family or
            !std.mem.eql(
                u8,
                &self.semantic_program_digest,
                &descriptor.semantic_program_digest,
            ) or
            !std.mem.eql(
                u8,
                &self.witness_layout_digest,
                &expected_witness_layout,
            ) or
            self.preprocessed_current_columns != 1 or
            self.borrowed_main_current_columns !=
                trace.nColumnsForFamily(self.family) or
            self.owned_interaction_current_previous_columns == 0 or
            self.owned_interaction_current_previous_columns %
                qm31.SECURE_EXTENSION_DEGREE != 0 or
            self.owned_interaction_current_previous_columns >
                compat_layout.MAX_INTERACTION_COLUMNS or
            runtime.digestIsZero(self.geometry_source_digest))
        {
            return error.InvalidWindowDigest;
        }
        switch (self.mode) {
            .compatibility => {
                if (self.owned_interaction_current_previous_columns !=
                    opcode_entries.interactionColumnCount(self.family))
                {
                    return error.InvalidWindowDigest;
                }
                const expected_plan = try runtime.digestFromHex(
                    EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
                );
                if (!std.mem.eql(
                    u8,
                    &self.geometry_source_digest,
                    &expected_plan,
                )) return error.InvalidWindowDigest;
            },
            .compiler_selected => {},
        }
        const actual = self.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest))
            return error.InvalidWindowDigest;
    }

    pub fn identityDigest(self: *const ComponentMaskBinding) Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(component_binding_domain);
        runtime.hashInteger(&hash, u16, self.schema_version);
        runtime.hashInteger(&hash, u8, @intFromEnum(self.family));
        runtime.hashInteger(&hash, u8, @intFromEnum(self.mode));
        hash.update(&self.semantic_program_digest);
        hash.update(&self.witness_layout_digest);
        hash.update(&self.geometry_source_digest);
        runtime.hashInteger(&hash, u8, self.preprocessed_current_columns);
        runtime.hashInteger(&hash, u32, self.borrowed_main_current_columns);
        runtime.hashInteger(
            &hash,
            u32,
            self.owned_interaction_current_previous_columns,
        );
        return hash.finalResult();
    }
};

/// Fixed projection consumed by the live semantic component. This retires its
/// independent mask-width table: the semantic adapter now derives the same
/// current-row Tree-0/Tree-1 geometry from the pinned row-window authority as
/// the lookup adapter, while owning no Tree-2 columns.
pub const SemanticMaskBinding = struct {
    schema_version: u16 = format_version,
    family: trace.OpcodeFamily,
    semantic_program_digest: Digest,
    witness_layout_digest: Digest,
    geometry_source_digest: Digest,
    preprocessed_current_columns: u8,
    owned_main_current_columns: u32,
    owned_interaction_columns: u8,
    binding_digest: Digest,

    pub fn init(family: trace.OpcodeFamily) Error!SemanticMaskBinding {
        const family_index: usize = @intFromEnum(family);
        if (family_index >= static_registry.DESCRIPTORS.len)
            return error.InvalidOwner;
        var result = SemanticMaskBinding{
            .family = family,
            .semantic_program_digest = static_registry.DESCRIPTORS[
                family_index
            ].semantic_program_digest,
            .witness_layout_digest = witness_layout.digest(),
            .geometry_source_digest = try runtime.digestFromHex(
                EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
            ),
            .preprocessed_current_columns = 1,
            .owned_main_current_columns = @intCast(
                trace.nColumnsForFamily(family),
            ),
            .owned_interaction_columns = 0,
            .binding_digest = .{0} ** 32,
        };
        result.binding_digest = result.identityDigest();
        try result.validate();
        return result;
    }

    pub fn validate(self: *const SemanticMaskBinding) Error!void {
        const family_index: usize = @intFromEnum(self.family);
        if (family_index >= static_registry.DESCRIPTORS.len)
            return error.InvalidOwner;
        const descriptor = static_registry.DESCRIPTORS[family_index];
        const expected_witness_layout = witness_layout.digest();
        const expected_plan = try runtime.digestFromHex(
            EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
        );
        if (self.schema_version != format_version or
            descriptor.family != self.family or
            !std.mem.eql(
                u8,
                &self.semantic_program_digest,
                &descriptor.semantic_program_digest,
            ) or
            !std.mem.eql(
                u8,
                &self.witness_layout_digest,
                &expected_witness_layout,
            ) or
            !std.mem.eql(
                u8,
                &self.geometry_source_digest,
                &expected_plan,
            ) or
            self.preprocessed_current_columns != 1 or
            self.owned_main_current_columns !=
                trace.nColumnsForFamily(self.family) or
            self.owned_interaction_columns != 0)
        {
            return error.InvalidWindowDigest;
        }
        const actual = self.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest))
            return error.InvalidWindowDigest;
    }

    pub fn identityDigest(self: *const SemanticMaskBinding) Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(semantic_component_binding_domain);
        runtime.hashInteger(&hash, u16, self.schema_version);
        runtime.hashInteger(&hash, u8, @intFromEnum(self.family));
        hash.update(&self.semantic_program_digest);
        hash.update(&self.witness_layout_digest);
        hash.update(&self.geometry_source_digest);
        runtime.hashInteger(&hash, u8, self.preprocessed_current_columns);
        runtime.hashInteger(&hash, u32, self.owned_main_current_columns);
        runtime.hashInteger(&hash, u8, self.owned_interaction_columns);
        return hash.finalResult();
    }
};

/// The previous row is cyclic at the PCS layer. At logical row zero, the
/// public cumulative claim corrects that wraparound exactly as LogUp requires.
pub const Boundary = union(enum) {
    none,
    cyclic_first_row_claim: FirstRowClaim,
};

pub const RowWindow = struct {
    id: WindowId,
    owner: Owner,
    columns: Range,
    offsets: [2]RowOffset,
    offset_count: u8,
    boundary: Boundary,

    pub fn offsetSlice(self: *const RowWindow) ?[]const RowOffset {
        if (self.offset_count == 0 or self.offset_count > self.offsets.len)
            return null;
        return self.offsets[0..self.offset_count];
    }
};

pub const MaskColumn = struct {
    id: ColumnId,
    owner: Owner,
    reference: compat_layout.ColumnRef,
    value_type: ColumnType,
    window: WindowId,
    shifted: Range,
};

/// A typed committed-column read at one trace-order offset.
pub const ShiftedColumn = struct {
    id: ShiftedColumnId,
    owner: Owner,
    column: ColumnId,
    window: WindowId,
    offset: RowOffset,
};

pub const Error = std.mem.Allocator.Error || compat_layout.Error || error{
    CountOverflow,
    DegreeOverflow,
    InvalidBoundary,
    InvalidColumn,
    InvalidFormat,
    InvalidOwner,
    InvalidRow,
    InvalidShiftedColumn,
    InvalidTreeShape,
    InvalidWindow,
    InvalidWindowDigest,
    LogDegreeUnderflow,
};

/// Owned, canonical compiler output. Columns are ordered by commitment tree
/// then local column index; shifted nodes are contiguous per column.
pub const Plan = struct {
    allocator: std.mem.Allocator,
    schema_version: u16,
    family: trace.OpcodeFamily,
    semantic_program_digest: Digest,
    witness_layout_digest: Digest,
    tree_column_counts: [3]u32,
    windows: []RowWindow,
    columns: []MaskColumn,
    shifted_columns: []ShiftedColumn,
    plan_digest: Digest,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.shifted_columns);
        self.allocator.free(self.columns);
        self.allocator.free(self.windows);
        self.* = undefined;
    }

    pub fn column(self: *const Plan, id: ColumnId) ?*const MaskColumn {
        const index: usize = @intFromEnum(id);
        if (index >= self.columns.len) return null;
        return &self.columns[index];
    }

    pub fn shiftedColumn(
        self: *const Plan,
        id: ShiftedColumnId,
    ) ?*const ShiftedColumn {
        const index: usize = @intFromEnum(id);
        if (index >= self.shifted_columns.len) return null;
        return &self.shifted_columns[index];
    }

    /// Every committed shifted-column node remains algebraic degree one.
    pub fn shiftedDegree(
        self: *const Plan,
        id: ShiftedColumnId,
    ) Error!protocol_degree.Degree {
        const shifted = self.shiftedColumn(id) orelse
            return error.InvalidShiftedColumn;
        if (shifted.id != id) return error.InvalidShiftedColumn;
        return 1;
    }

    /// Resolve a typed shift to a cyclic trace-row index. This is the domain
    /// counterpart of `emitMaskPoints` and is useful to differential-test the
    /// compiler plan before production activation.
    pub fn sampleRowIndex(
        self: *const Plan,
        id: ShiftedColumnId,
        row_count: usize,
        row: usize,
    ) Error!usize {
        const shifted = self.shiftedColumn(id) orelse
            return error.InvalidShiftedColumn;
        if (shifted.id != id) return error.InvalidShiftedColumn;
        if (row_count == 0 or row >= row_count) return error.InvalidRow;
        return switch (shifted.offset) {
            .current => row,
            .previous => if (row == 0) row_count - 1 else row - 1,
        };
    }

    /// Re-establish every format, layout, owner, boundary, type, order, and
    /// coverage invariant without allocating.
    pub fn validate(
        self: *const Plan,
        imported: *const shadow_program.ImportedProgram,
        layout: *const compat_layout.Layout,
    ) Error!void {
        try layout.validate(imported);
        if (self.schema_version != format_version) return error.InvalidFormat;
        if (self.family != imported.family or self.family != layout.family)
            return error.InvalidOwner;
        const family_index: usize = @intFromEnum(self.family);
        if (family_index >= static_registry.DESCRIPTORS.len)
            return error.InvalidOwner;
        const descriptor = static_registry.DESCRIPTORS[family_index];
        const expected_witness_layout = witness_layout.digest();
        if (descriptor.family != self.family or
            !std.mem.eql(
                u8,
                &self.semantic_program_digest,
                &descriptor.semantic_program_digest,
            ) or
            !std.mem.eql(
                u8,
                &self.witness_layout_digest,
                &expected_witness_layout,
            ))
        {
            return error.InvalidWindowDigest;
        }

        const main_count = try runtime.countU32(layout.main().len);
        const interaction_count = try runtime.countU32(layout.interactions().len);
        const column_count = try runtime.addCount(
            compat_layout.PREPROCESSED_COLUMN_COUNT,
            try runtime.addCount(layout.main().len, layout.interactions().len),
        );
        const shifted_count = try runtime.addCount(column_count, layout.interactions().len);
        if (!std.meta.eql(self.tree_column_counts, [3]u32{
            compat_layout.PREPROCESSED_COLUMN_COUNT,
            main_count,
            interaction_count,
        })) return error.InvalidTreeShape;
        if (self.windows.len != 4 or
            self.columns.len != column_count or
            self.shifted_columns.len != shifted_count)
        {
            return error.InvalidTreeShape;
        }

        const semantic_owner = ownerFor(self.family, .semantic);
        const interaction_owner = ownerFor(self.family, .interaction);
        const main_start: u32 = compat_layout.PREPROCESSED_COLUMN_COUNT;
        const interaction_start = std.math.add(u32, main_start, main_count) catch
            return error.CountOverflow;
        const claim_count = try runtime.countU32(imported.batchCount());
        const expected_windows = [_]RowWindow{
            .{
                .id = first_selector_window,
                .owner = interaction_owner,
                .columns = .{ .start = 0, .len = 1 },
                .offsets = .{ .current, .current },
                .offset_count = 1,
                .boundary = .none,
            },
            .{
                .id = active_selector_window,
                .owner = semantic_owner,
                .columns = .{ .start = 1, .len = 1 },
                .offsets = .{ .current, .current },
                .offset_count = 1,
                .boundary = .none,
            },
            .{
                .id = semantic_window,
                .owner = semantic_owner,
                .columns = .{ .start = main_start, .len = main_count },
                .offsets = .{ .current, .current },
                .offset_count = 1,
                .boundary = .none,
            },
            .{
                .id = interaction_window,
                .owner = interaction_owner,
                .columns = .{ .start = interaction_start, .len = interaction_count },
                .offsets = .{ .current, .previous },
                .offset_count = 2,
                .boundary = .{ .cyclic_first_row_claim = .{
                    .owner = interaction_owner,
                    .selector = @enumFromInt(0),
                    .claim_count = claim_count,
                    .coordinates_per_claim = qm31.SECURE_EXTENSION_DEGREE,
                } },
            },
        };
        for (self.windows, expected_windows) |actual, expected|
            try runtime.validateWindow(actual, expected);

        var column_cursor: usize = 0;
        var shifted_cursor: usize = 0;
        try self.expectColumn(
            &column_cursor,
            &shifted_cursor,
            interaction_owner,
            layout.preprocessed[0].reference,
            .base_field,
            first_selector_window,
        );
        try self.expectColumn(
            &column_cursor,
            &shifted_cursor,
            semantic_owner,
            layout.preprocessed[1].reference,
            .base_field,
            active_selector_window,
        );
        for (layout.main()) |mapped_column| {
            try self.expectColumn(
                &column_cursor,
                &shifted_cursor,
                semantic_owner,
                mapped_column.reference,
                .base_field,
                semantic_window,
            );
        }
        for (layout.interactions()) |mapped_column| {
            try self.expectColumn(
                &column_cursor,
                &shifted_cursor,
                interaction_owner,
                mapped_column.reference,
                .{ .secure_coordinate = mapped_column.coordinate },
                interaction_window,
            );
        }
        if (column_cursor != self.columns.len or
            shifted_cursor != self.shifted_columns.len)
        {
            return error.InvalidTreeShape;
        }
        const actual_digest = self.identityDigest();
        if (!std.mem.eql(u8, &actual_digest, &self.plan_digest))
            return error.InvalidWindowDigest;
        const actual_hex = std.fmt.bytesToHex(actual_digest, .lower);
        if (!std.mem.eql(
            u8,
            &actual_hex,
            EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
        )) return error.InvalidWindowDigest;
    }

    /// Allocation-free canonical identity of semantic/layout authority and
    /// every typed owner, window, boundary, physical column, and shifted read.
    /// Caller-owned allocation addresses and source locations are excluded.
    pub fn identityDigest(self: *const Plan) Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(digest_domain);
        runtime.hashInteger(&hash, u16, self.schema_version);
        runtime.hashInteger(&hash, u8, @intFromEnum(self.family));
        hash.update(&self.semantic_program_digest);
        hash.update(&self.witness_layout_digest);
        for (self.tree_column_counts) |count|
            runtime.hashInteger(&hash, u32, count);

        runtime.hashCount(&hash, self.windows.len);
        for (self.windows) |window| {
            runtime.hashInteger(&hash, u32, @intFromEnum(window.id));
            runtime.hashOwner(&hash, window.owner);
            runtime.hashInteger(&hash, u32, window.columns.start);
            runtime.hashInteger(&hash, u32, window.columns.len);
            runtime.hashInteger(&hash, u8, window.offset_count);
            const offset_count = @min(
                @as(usize, window.offset_count),
                window.offsets.len,
            );
            for (window.offsets[0..offset_count]) |offset|
                runtime.hashInteger(&hash, u8, @bitCast(@intFromEnum(offset)));
            switch (window.boundary) {
                .none => runtime.hashInteger(&hash, u8, 0),
                .cyclic_first_row_claim => |claim| {
                    runtime.hashInteger(&hash, u8, 1);
                    runtime.hashOwner(&hash, claim.owner);
                    runtime.hashInteger(&hash, u32, @intFromEnum(claim.selector));
                    runtime.hashInteger(&hash, u32, claim.claim_count);
                    runtime.hashInteger(&hash, u8, claim.coordinates_per_claim);
                },
            }
        }

        runtime.hashCount(&hash, self.columns.len);
        for (self.columns) |mask_column| {
            runtime.hashInteger(&hash, u32, @intFromEnum(mask_column.id));
            runtime.hashOwner(&hash, mask_column.owner);
            runtime.hashInteger(&hash, u8, @intFromEnum(mask_column.reference.tree));
            runtime.hashInteger(&hash, u32, mask_column.reference.local_index);
            switch (mask_column.value_type) {
                .base_field => runtime.hashInteger(&hash, u8, 0),
                .secure_coordinate => |coordinate| {
                    runtime.hashInteger(&hash, u8, 1);
                    runtime.hashInteger(&hash, u8, @intFromEnum(coordinate));
                },
            }
            runtime.hashInteger(&hash, u32, @intFromEnum(mask_column.window));
            runtime.hashInteger(&hash, u32, mask_column.shifted.start);
            runtime.hashInteger(&hash, u32, mask_column.shifted.len);
        }

        runtime.hashCount(&hash, self.shifted_columns.len);
        for (self.shifted_columns) |shifted| {
            runtime.hashInteger(&hash, u32, @intFromEnum(shifted.id));
            runtime.hashOwner(&hash, shifted.owner);
            runtime.hashInteger(&hash, u32, @intFromEnum(shifted.column));
            runtime.hashInteger(&hash, u32, @intFromEnum(shifted.window));
            runtime.hashInteger(
                &hash,
                u8,
                @bitCast(@intFromEnum(shifted.offset)),
            );
        }
        return hash.finalResult();
    }

    fn expectColumn(
        self: *const Plan,
        column_cursor: *usize,
        shifted_cursor: *usize,
        expected_owner: Owner,
        expected_reference: compat_layout.ColumnRef,
        expected_type: ColumnType,
        expected_window: WindowId,
    ) Error!void {
        if (column_cursor.* >= self.columns.len) return error.InvalidColumn;
        const mask_column = self.columns[column_cursor.*];
        const expected_id: ColumnId = @enumFromInt(try runtime.countU32(column_cursor.*));
        if (!std.meta.eql(mask_column.owner, expected_owner)) return error.InvalidOwner;
        if (mask_column.id != expected_id or
            !std.meta.eql(mask_column.reference, expected_reference) or
            !std.meta.eql(mask_column.value_type, expected_type) or
            mask_column.window != expected_window)
        {
            return error.InvalidColumn;
        }
        const window_index: usize = @intFromEnum(expected_window);
        if (window_index >= self.windows.len) return error.InvalidWindow;
        const offsets = self.windows[window_index].offsetSlice() orelse
            return error.InvalidWindow;
        if (mask_column.shifted.start != try runtime.countU32(shifted_cursor.*) or
            mask_column.shifted.len != try runtime.countU32(offsets.len))
        {
            return error.InvalidShiftedColumn;
        }
        for (offsets) |offset| {
            if (shifted_cursor.* >= self.shifted_columns.len)
                return error.InvalidShiftedColumn;
            const shifted = self.shifted_columns[shifted_cursor.*];
            const expected_shifted_id: ShiftedColumnId =
                @enumFromInt(try runtime.countU32(shifted_cursor.*));
            if (!std.meta.eql(shifted.owner, expected_owner))
                return error.InvalidOwner;
            if (shifted.id != expected_shifted_id or
                shifted.column != expected_id or
                shifted.window != expected_window or
                shifted.offset != offset)
            {
                return error.InvalidShiftedColumn;
            }
            shifted_cursor.* += 1;
        }
        column_cursor.* += 1;
    }
};

/// Compile the exact compat-v1 component split into the versioned typed IR.
const runtime = @import("row_window_runtime.zig").Runtime(.{
    .std = std,
    .core_air_components = core_air_components,
    .qm31 = qm31,
    .canonic = canonic,
    .compat_layout = compat_layout,
    .protocol_degree = protocol_degree,
    .shadow_program = shadow_program,
    .static_registry = static_registry,
    .witness_layout = witness_layout,
    .CirclePointQM31 = CirclePointQM31,
    .format_version = format_version,
    .Digest = Digest,
    .Owner = Owner,
    .ownerFor = ownerFor,
    .ColumnId = ColumnId,
    .WindowId = WindowId,
    .first_selector_window = first_selector_window,
    .active_selector_window = active_selector_window,
    .semantic_window = semantic_window,
    .interaction_window = interaction_window,
    .ColumnType = ColumnType,
    .RowWindow = RowWindow,
    .MaskColumn = MaskColumn,
    .ShiftedColumn = ShiftedColumn,
    .Error = Error,
    .Plan = Plan,
});

/// Compile the exact compat-v1 component split into the versioned typed IR.
pub fn build(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) Error!Plan {
    return runtime.build(allocator, imported, layout);
}

/// Propagate typed shifted-column and first-row boundary degrees into the exact
/// pairs-batched LogUp recurrence.
pub fn lowerInteractionDegree(
    plan: *const Plan,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
    first: protocol_degree.FractionDegree,
    second: ?protocol_degree.FractionDegree,
) Error!protocol_degree.InteractionTerms {
    return runtime.lowerInteractionDegree(
        plan,
        imported,
        layout,
        first,
        second,
    );
}

/// Emit the full local compat layout as concrete PCS mask points. The ordering
/// is exactly tree/local-column order, with current then previous samples.
pub fn emitMaskPoints(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
    point: CirclePointQM31,
    trace_log_size: u32,
    max_log_degree_bound: u32,
) Error!core_air_components.MaskPoints {
    return runtime.emitMaskPoints(
        allocator,
        plan,
        imported,
        layout,
        point,
        trace_log_size,
        max_log_degree_bound,
    );
}

/// Trace-order predecessor mask point, kept local so the typed authoring
/// kernel does not acquire a prover-engine dependency through production
/// LogUp's domain-evaluation tests.
pub fn previousRowPoint(
    log_size: u32,
    point: CirclePointQM31,
) CirclePointQM31 {
    return runtime.previousRowPoint(log_size, point);
}
