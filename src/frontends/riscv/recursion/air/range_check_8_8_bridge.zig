//! Authenticated universal-row bridge for Stark-V's shared `(8, 8)` table.
//!
//! Universal roster row 35 is not a second range-check implementation.  It is
//! the existing VM preprocessed table and multiplicity component, admitted at
//! the recursive-verifier boundary with its exact source geometry.  This file
//! gives that bridge three deliberately separate seals:
//!
//! * a source authority pins the Stark-V revision and the three owning files;
//! * a typed relation-only program pins `-multiplicity / range_8_8(l0,l1)`;
//! * a witness binding pins the physical main/preprocessed projection.
//!
//! Prepared batches snapshot the real production lookup counter in one cold
//! allocation.  All hot writers validate shape, seal, canonical field words,
//! and aliases before their first store, then fill the complete fixed 2^16
//! domain without allocation or fallible work.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const core_utils = stwo_core.utils;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const relation = @import("../../air/lang/relation.zig");
const lookup_component = @import("../../air/lookups/tables/component.zig");
const lookup_counter = @import("../../air/lookups/tables/counter.zig");
const lookup_interaction = @import("../../air/lookups/tables/interaction.zig");
const lookup_relations = @import("../../air/relation_challenges.zig");
const lookup_schema = @import("../../air/lookups/tables/schema.zig");
const relation_interaction = @import("relation_interaction.zig");

const contract = @import("range_check_8_8_contract.zig");
pub const STABLE_NAME = contract.STABLE_NAME;
pub const TABLE_KIND = contract.TABLE_KIND;
pub const LOG_SIZE = contract.LOG_SIZE;
pub const TABLE_SIZE = contract.TABLE_SIZE;
pub const TUPLE_ARITY = contract.TUPLE_ARITY;
pub const PHYSICAL_MAIN_COLUMN_COUNT = contract.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = contract.PREPROCESSED_COLUMN_COUNT;
pub const FRAMEWORK_PREPROCESSED_COLUMN_COUNT = contract.FRAMEWORK_PREPROCESSED_COLUMN_COUNT;
pub const LOGICAL_INPUT_COUNT = contract.LOGICAL_INPUT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = contract.DIRECT_CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT = contract.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE = contract.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = contract.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = contract.INTERACTION_COLUMN_COUNT;
pub const FRAMEWORK_CONSTRAINT_COUNT = contract.FRAMEWORK_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_LOG_DEGREE_BOUND = contract.MAXIMUM_CONSTRAINT_LOG_DEGREE_BOUND;
pub const SOURCE_RELATION_ROLE = contract.SOURCE_RELATION_ROLE;
pub const BASE_ABI_RELATION_ROLE = contract.BASE_ABI_RELATION_ROLE;
pub const STARK_V_REVISION = contract.STARK_V_REVISION;
pub const STARK_V_SCHEMA_PATH = contract.STARK_V_SCHEMA_PATH;
pub const STARK_V_TABLE_PATH = contract.STARK_V_TABLE_PATH;
pub const STARK_V_COMPONENT_MACRO_PATH = contract.STARK_V_COMPONENT_MACRO_PATH;
pub const STARK_V_SCHEMA_SHA256 = contract.STARK_V_SCHEMA_SHA256;
pub const STARK_V_TABLE_SHA256 = contract.STARK_V_TABLE_SHA256;
pub const STARK_V_COMPONENT_MACRO_SHA256 = contract.STARK_V_COMPONENT_MACRO_SHA256;
pub const SOURCE_AUTHORITY_FORMAT_VERSION = contract.SOURCE_AUTHORITY_FORMAT_VERSION;
pub const SOURCE_AUTHORITY_DOMAIN = contract.SOURCE_AUTHORITY_DOMAIN;
pub const SOURCE_AUTHORITY_DIGEST_HEX = contract.SOURCE_AUTHORITY_DIGEST_HEX;
pub const SOURCE_AUTHORITY_DIGEST = contract.SOURCE_AUTHORITY_DIGEST;
pub const SourceAuthority = contract.SourceAuthority;
pub const SEMANTIC_DIGEST_HEX = contract.SEMANTIC_DIGEST_HEX;
pub const SEMANTIC_DIGEST = contract.SEMANTIC_DIGEST;
pub const MAIN_COLUMN_NAMES = contract.MAIN_COLUMN_NAMES;
pub const PREPROCESSED_COLUMN_NAMES = contract.PREPROCESSED_COLUMN_NAMES;
pub const MainColumns = contract.MainColumns;
pub const PreprocessedColumns = contract.PreprocessedColumns;
pub const DefinitionError = contract.DefinitionError;
pub const Definition = contract.Definition;
pub const build = contract.build;
pub const identity = contract.identity;
pub const MainSource = contract.MainSource;
pub const PreprocessedSource = contract.PreprocessedSource;
pub const Slot = contract.Slot;
pub const BINDING_FORMAT_VERSION = contract.BINDING_FORMAT_VERSION;
pub const BINDING_DOMAIN = contract.BINDING_DOMAIN;
pub const BINDING_DIGEST_HEX = contract.BINDING_DIGEST_HEX;
pub const BINDING_DIGEST = contract.BINDING_DIGEST;
pub const Binding = contract.Binding;

pub const RelationRuntime = relation_interaction.Runtime(
    LOGICAL_INPUT_COUNT,
    RELATION_EVENT_COUNT,
    LOOKUP_BATCH_SIZE,
);
pub const RelationPlan = RelationRuntime.Plan;
pub const RelationRow = RelationRuntime.Row;
pub const RelationEntry = relation_interaction.Entry;

pub fn authenticateRelation(definition: *const Definition) !RelationPlan {
    try definition.validate();
    return RelationRuntime.authenticate(
        &definition.arena,
        SEMANTIC_DIGEST,
        definition.events,
    );
}

pub const Error = direct.Error || lookup_schema.Error || std.mem.Allocator.Error || error{
    AuthorityMismatch,
    InvalidCounterKind,
    InvalidCounterShape,
    InvalidFieldElement,
    InvalidWitnessBinding,
    RowOutOfRange,
};

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const Definition,
        supplied: *const Binding,
    ) !Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn validate(self: *const Executor) Error!void {
        const actual = self.binding.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest) or
            !std.mem.eql(u8, &actual, &BINDING_DIGEST) or
            !std.mem.eql(
                u8,
                &self.binding.source_authority_digest,
                &SOURCE_AUTHORITY_DIGEST,
            ))
        {
            return error.InvalidWitnessBinding;
        }
    }

    /// Fills Tree-1 multiplicity and the two Tree-0 tuple columns in their
    /// exact committed circle-domain order.  Every destination is checked as
    /// one transaction so cross-tree aliasing cannot expose a partial prefix.
    pub fn generateTraceInto(
        self: *const Executor,
        batch: *const PreparedBatch,
        main: *[PHYSICAL_MAIN_COLUMN_COUNT][]M31,
        preprocessed: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try batch.validate();
        const destinations = main.* ++ preprocessed.*;
        try preflightColumns(destinations[0..], main, preprocessed, self, batch);
        for (batch.counter.values, 0..) |multiplicity, logical_row| {
            const destination = committedRow(logical_row);
            main[0][destination] = multiplicity;
            preprocessed[0][destination] = M31.fromCanonical(
                @intCast(logical_row & 0xff),
            );
            preprocessed[1][destination] = M31.fromCanonical(
                @intCast(logical_row >> 8),
            );
        }
    }

    pub fn generateMainInto(
        self: *const Executor,
        batch: *const PreparedBatch,
        main: *[PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try batch.validate();
        try preflightColumns(main[0..], main, null, self, batch);
        for (batch.counter.values, 0..) |multiplicity, logical_row|
            main[0][committedRow(logical_row)] = multiplicity;
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        batch: *const PreparedBatch,
        preprocessed: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try batch.validate();
        try preflightColumns(preprocessed[0..], preprocessed, null, self, batch);
        for (0..TABLE_SIZE) |logical_row| {
            const destination = committedRow(logical_row);
            preprocessed[0][destination] = M31.fromCanonical(
                @intCast(logical_row & 0xff),
            );
            preprocessed[1][destination] = M31.fromCanonical(
                @intCast(logical_row >> 8),
            );
        }
    }

    /// Optional materialization seam for the generic interaction compiler.
    /// Concrete adapters should normally call `preparedRelationRow` directly
    /// and avoid this 3-column AoS buffer.
    pub fn generateRelationRowsInto(
        self: *const Executor,
        batch: *const PreparedBatch,
        rows: []RelationRow,
    ) Error!void {
        try self.validate();
        try batch.validate();
        if (rows.len != TABLE_SIZE) return error.InvalidTraceShape;
        const destination = (try sliceRange(RelationRow, rows)).?;
        const batch_header = try objectRange(batch);
        const executor_header = try objectRange(self);
        const source_values = (try sliceRange(M31, batch.counter.values)).?;
        if (destination.overlaps(batch_header) or
            destination.overlaps(executor_header))
        {
            return error.AliasedDestination;
        }
        if (destination.overlaps(source_values)) return error.AliasedInput;
        for (rows, batch.counter.values, 0..) |*row, multiplicity, logical_row|
            row.* = relationRow(multiplicity, logical_row);
    }
};

pub const PREPARED_BATCH_FORMAT_VERSION: u16 = 1;
pub const PREPARED_BATCH_DOMAIN =
    "stwo-zig/typed-air/recursion-range-check-8-8-batch/v1\x00";

/// One-allocation immutable snapshot of the real VM lookup counter.
pub const PreparedBatch = struct {
    allocator: std.mem.Allocator,
    counter: lookup_counter.Counter,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        source_counter: *const lookup_counter.Counter,
    ) Error!PreparedBatch {
        try SourceAuthority.pinned().validate();
        try validateCounter(source_counter);
        const values = try allocator.dupe(M31, source_counter.values);
        errdefer allocator.free(values);
        const counter = lookup_counter.Counter{
            .kind = TABLE_KIND,
            .values = values,
        };
        return .{
            .allocator = allocator,
            .counter = counter,
            .authority_digest = batchDigest(&counter),
        };
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.counter.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn validate(self: *const PreparedBatch) Error!void {
        try SourceAuthority.pinned().validate();
        try validateCounter(&self.counter);
        const actual = batchDigest(&self.counter);
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstSource(
        self: *const PreparedBatch,
        source_counter: *const lookup_counter.Counter,
    ) Error!void {
        try self.validate();
        try validateCounter(source_counter);
        for (self.counter.values, source_counter.values) |snapshot, source_value| {
            if (!snapshot.eql(source_value)) return error.AuthorityMismatch;
        }
    }

    /// Borrowed view consumed directly by the existing native table component
    /// and interaction generator; no semantic conversion or tuple copy occurs.
    pub fn nativeCounter(self: *const PreparedBatch) *const lookup_counter.Counter {
        return &self.counter;
    }

    pub fn row(self: *const PreparedBatch, logical_row: usize) Error!RelationRow {
        try self.validate();
        if (logical_row >= TABLE_SIZE) return error.RowOutOfRange;
        return relationRow(self.counter.values[logical_row], logical_row);
    }

    /// Hot row seam. The caller must have authenticated this batch once with
    /// `validate`; it performs only fixed integer decomposition and three
    /// scalar stores in the returned value.
    pub inline fn preparedRelationRow(
        self: *const PreparedBatch,
        logical_row: usize,
    ) RelationRow {
        std.debug.assert(logical_row < TABLE_SIZE);
        return relationRow(self.counter.values[logical_row], logical_row);
    }

    pub fn generateNativeInteraction(
        self: *const PreparedBatch,
        allocator: std.mem.Allocator,
        relations: *const lookup_relations.Relations,
    ) !lookup_interaction.Result {
        try self.validate();
        return lookup_interaction.generate(allocator, &self.counter, relations);
    }

    /// Allocation-free provider interaction for parent/cohort writers which
    /// already own their Tree-2 columns and bounded inversion workspace.
    /// Validation is failure-atomic in the shared table implementation.
    pub fn generateNativeInteractionInto(
        self: *const PreparedBatch,
        relations: *const lookup_relations.Relations,
        columns: *[lookup_interaction.N_COLUMNS][]M31,
        denominators: []QM31,
        inverses: []QM31,
    ) !QM31 {
        try self.validate();
        return lookup_interaction.generateInto(
            &self.counter,
            relations,
            columns,
            denominators,
            inverses,
        );
    }
};

pub inline fn relationRow(
    signed_multiplicity: M31,
    logical_row: usize,
) RelationRow {
    std.debug.assert(logical_row < TABLE_SIZE);
    return .{
        signed_multiplicity,
        M31.fromCanonical(@intCast(logical_row & 0xff)),
        M31.fromCanonical(@intCast(logical_row >> 8)),
    };
}

pub inline fn committedRow(logical_row: usize) usize {
    std.debug.assert(logical_row < TABLE_SIZE);
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, LOG_SIZE),
        LOG_SIZE,
    );
}

fn validateCounter(counter: *const lookup_counter.Counter) Error!void {
    if (counter.kind != TABLE_KIND) return error.InvalidCounterKind;
    if (counter.values.len != TABLE_SIZE) return error.InvalidCounterShape;
    for (counter.values) |value| if (value.v >= m31.Modulus)
        return error.InvalidFieldElement;
}

fn batchDigest(counter: *const lookup_counter.Counter) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPARED_BATCH_DOMAIN);
    hashInt(&hash, u16, PREPARED_BATCH_FORMAT_VERSION);
    hash.update(&SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u8, @intFromEnum(counter.kind));
    hashInt(&hash, u32, LOG_SIZE);
    hashInt(&hash, u64, counter.values.len);
    for (counter.values) |value| hashInt(&hash, u32, value.v);
    return hash.finalResult();
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn preflightColumns(
    destinations: []const []M31,
    descriptor_a: anytype,
    descriptor_b: anytype,
    executor: *const Executor,
    batch: *const PreparedBatch,
) direct.Error!void {
    var ranges: [PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT]AddressRange =
        undefined;
    std.debug.assert(destinations.len <= ranges.len);
    const descriptor_a_range = try objectRange(descriptor_a);
    const descriptor_b_range: ?AddressRange = if (comptime @TypeOf(descriptor_b) == @TypeOf(null))
        null
    else
        try objectRange(descriptor_b);
    const executor_range = try objectRange(executor);
    const batch_range = try objectRange(batch);
    const source_range = (try sliceRange(M31, batch.counter.values)).?;
    for (destinations, 0..) |destination, index| {
        if (destination.len != TABLE_SIZE) return error.InvalidTraceShape;
        ranges[index] = (try sliceRange(M31, destination)).?;
        if (ranges[index].overlaps(descriptor_a_range) or
            (descriptor_b_range != null and ranges[index].overlaps(descriptor_b_range.?)) or
            ranges[index].overlaps(executor_range) or
            ranges[index].overlaps(batch_range))
        {
            return error.AliasedDestination;
        }
        if (ranges[index].overlaps(source_range)) return error.AliasedInput;
        for (ranges[0..index]) |previous| if (ranges[index].overlaps(previous))
            return error.AliasedDestination;
    }
}

fn sliceRange(comptime T: type, values: []const T) direct.Error!?AddressRange {
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.AddressOverflow,
    };
}

fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected storage must be a single-item pointer");
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
            return error.AddressOverflow,
    };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (TABLE_SIZE != 65_536 or TUPLE_ARITY != 2 or
        PHYSICAL_MAIN_COLUMN_COUNT != 1 or
        PREPROCESSED_COLUMN_COUNT != 2 or
        FRAMEWORK_PREPROCESSED_COLUMN_COUNT != 3 or
        LOGICAL_INPUT_COUNT != 3 or
        DIRECT_CONSTRAINT_COUNT != 0 or
        RELATION_EVENT_COUNT != 1 or
        LOOKUP_BATCH_SIZE != 2 or
        INTERACTION_BATCH_COUNT != 1 or
        INTERACTION_COLUMN_COUNT != 4 or
        FRAMEWORK_CONSTRAINT_COUNT != 1 or
        MAXIMUM_CONSTRAINT_LOG_DEGREE_BOUND != 17 or
        RelationRuntime.BATCH_COUNT != INTERACTION_BATCH_COUNT or
        RelationRuntime.INTERACTION_COLUMN_COUNT != INTERACTION_COLUMN_COUNT)
    {
        @compileError("universal range-check (8,8) geometry drifted");
    }
}

const backend_programs = @import("stwo_prover_engine").air.component_prover;
const framework_export = @import("framework_polynomial_export_v1.zig");
const direct_program = @import("direct_constraint_program.zig");

/// Cold export from the already admitted native range component. Its typed
/// bridge supplies the relation; the native component supplies exact committed
/// coordinates. The selector is a framework input, outside the typed tuple.
pub fn exportFrameworkProgram(
    allocator: std.mem.Allocator,
    component: *const lookup_component.LookupTableComponent,
    tree_column_counts: []const usize,
) !backend_programs.OwnedFrameworkPolynomialProgramV1 {
    try validateFrameworkComponent(component);
    var definition = try build(allocator);
    defer definition.deinit();
    const relations = try authenticateRelation(&definition);
    const constraints = try direct_program.authenticate(&definition.arena, SEMANTIC_DIGEST, LOGICAL_INPUT_COUNT);
    const inputs = [_]backend_programs.TypedPolynomialInputV1{
        .{ .trace_column = .{ .tree_index = 1, .column_index = try frameworkColumn(component.main_col_offset) } },
        .{ .trace_column = .{ .tree_index = 0, .column_index = try frameworkColumn(component.tuple_col_indices[0]) } },
        .{ .trace_column = .{ .tree_index = 0, .column_index = try frameworkColumn(component.tuple_col_indices[1]) } },
        .{ .trace_column = .{ .tree_index = 0, .column_index = try frameworkColumn(component.is_first_col_idx) } },
    };
    var interaction_columns: [INTERACTION_COLUMN_COUNT]backend_programs.TypedPolynomialColumnV1 = undefined;
    for (&interaction_columns, 0..) |*column, index| column.* = .{
        .tree_index = 2,
        .column_index = try frameworkColumn(try std.math.add(usize, component.interaction_col_offset, index)),
    };
    return framework_export.exportIndependentPrepared(@This(), allocator, &constraints, &relations, &inputs, &interaction_columns, tree_column_counts);
}

pub fn exportFrameworkParameters(
    allocator: std.mem.Allocator,
    component: *const lookup_component.LookupTableComponent,
) !backend_programs.OwnedFrameworkPolynomialParametersV1 {
    try validateFrameworkComponent(component);
    const element = component.relations.range_check_8_8;
    try requireCanonicalFrameworkValue(element.z);
    try requireCanonicalFrameworkValue(element.alpha);
    for (element.alpha_powers) |power| try requireCanonicalFrameworkValue(power);
    const expected = lookup_relations.RelationElements(TUPLE_ARITY).init(element.z, element.alpha);
    for (element.alpha_powers, expected.alpha_powers) |actual, canonical| {
        if (!actual.eql(canonical)) return error.AuthorityMismatch;
    }
    const profile_values = try allocator.alloc(M31, 0);
    errdefer allocator.free(profile_values);
    const relation_values = try allocator.alloc(QM31, 1 + TUPLE_ARITY);
    errdefer allocator.free(relation_values);
    relation_values[0] = element.z;
    @memcpy(relation_values[1..], &element.alpha_powers);
    const claims = try allocator.dupe(QM31, &.{component.claim});
    errdefer allocator.free(claims);
    for (relation_values) |value| try requireCanonicalFrameworkValue(value);
    try requireCanonicalFrameworkValue(component.claim);
    return .{ .allocator = allocator, .values = .{
        .profile_values = profile_values,
        .relation_values = relation_values,
        .trace_log_size = LOG_SIZE,
        .claimed_sum = QM31.zero(),
        .batch_claims = claims,
    } };
}

pub fn frameworkCapability() backend_programs.FrameworkPolynomialCapabilityV1 {
    const Callbacks = struct {
        fn program(ctx: *const anyopaque, allocator: std.mem.Allocator, counts: []const usize) !backend_programs.OwnedFrameworkPolynomialProgramV1 {
            return exportFrameworkProgram(allocator, @ptrCast(@alignCast(ctx)), counts);
        }
        fn parameters(ctx: *const anyopaque, allocator: std.mem.Allocator) !backend_programs.OwnedFrameworkPolynomialParametersV1 {
            return exportFrameworkParameters(allocator, @ptrCast(@alignCast(ctx)));
        }
    };
    return .{ .trace_log_size = LOG_SIZE, .export_program = Callbacks.program, .export_parameters = Callbacks.parameters };
}

fn validateFrameworkComponent(component: *const lookup_component.LookupTableComponent) !void {
    if (component.kind != TABLE_KIND or component.tuple_col_indices[0] != try std.math.add(usize, component.is_first_col_idx, 1) or
        component.tuple_col_indices[1] != try std.math.add(usize, component.is_first_col_idx, 2))
        return error.AuthorityMismatch;
    for (component.tuple_col_indices[TUPLE_ARITY..]) |column| if (column != 0) return error.AuthorityMismatch;
}
fn frameworkColumn(index: usize) !u32 {
    return std.math.cast(u32, index) orelse error.InvalidFrameworkPolynomialInput;
}
fn requireCanonicalFrameworkValue(value: QM31) !void {
    for (value.toM31Array()) |coordinate| if (coordinate.toU32() >= m31.Modulus)
        return error.InvalidFrameworkPolynomialParameters;
}
