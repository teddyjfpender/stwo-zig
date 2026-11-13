//! Typed base/lookup polynomial programs and backend capability contracts.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const node_programs = @import("component_program_nodes.zig");
const lookup_v2 = @import("component_lookup_program_v2.zig");
pub const BasePolynomialOp = node_programs.BasePolynomialOp;
pub const BasePolynomialNode = node_programs.BasePolynomialNode;
pub const OwnedBasePolynomialProgram = node_programs.OwnedBasePolynomialProgram;
pub const BasePolynomialCapabilityV1 = node_programs.BasePolynomialCapabilityV1;
pub const MAX_LOOKUP_POLYNOMIAL_ARITY = node_programs.MAX_LOOKUP_POLYNOMIAL_ARITY;
pub const LookupPolynomialEntry = node_programs.LookupPolynomialEntry;
pub const OwnedLookupPolynomialProgram = node_programs.OwnedLookupPolynomialProgram;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION = lookup_v2.LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE = lookup_v2.LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES = lookup_v2.LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE = lookup_v2.LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN = lookup_v2.LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN;
pub const LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN = lookup_v2.LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN;
pub const LookupPolynomialIdentity = lookup_v2.LookupPolynomialIdentity;
pub const LookupPolynomialProgramV2Error = lookup_v2.LookupPolynomialProgramV2Error;
pub const LookupPolynomialEventDegreeV2 = lookup_v2.LookupPolynomialEventDegreeV2;
pub const LookupPolynomialBatchV2 = lookup_v2.LookupPolynomialBatchV2;
pub const LookupPolynomialLayoutV2 = lookup_v2.LookupPolynomialLayoutV2;
pub const LookupPolynomialAuthorityV2 = lookup_v2.LookupPolynomialAuthorityV2;
pub const OwnedLookupPolynomialProgramV2 = lookup_v2.OwnedLookupPolynomialProgramV2;

/// Pairs-batched LogUp transition constraints whose base tuple expressions are
/// exported from a production typed builder. Parameter order is canonical:
/// for every entry, `(z, alpha^0, ..., alpha^(arity-1))`, followed by one
/// claimed sum per batch.
pub const LookupPolynomialCapabilityV1 = struct {
    program_id: u64,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    interaction_tree_index: usize,
    first_interaction_column: usize,
    interaction_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedLookupPolynomialProgram,
    export_parameters: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]QM31,
};

/// One contiguous constraint interval owned by a resident sub-program. The
/// interval is expressed in the component's canonical constraint order; the
/// backend remains responsible for mapping it onto the corresponding random
/// coefficient slice.
pub const ComponentConstraintRangeV1 = struct {
    start: usize,
    count: usize,
};

pub const MAX_BASE_POLYNOMIAL_PARTITIONS_V1: usize = 8;

pub const BasePolynomialPartitionV1 = struct {
    capability: BasePolynomialCapabilityV1,
    constraints: ComponentConstraintRangeV1,
};

/// A component whose complete constraint relation is partitioned between one
/// or more direct base-polynomial programs and one pairs-batched LogUp program.
/// This is deliberately a cold exported value rather than another large inline
/// union payload: dormant support must not inflate every `ComponentProver`
/// copied by the generic prover.
pub const BaseLookupPolynomialCapabilitiesV1 = struct {
    base_partitions: [MAX_BASE_POLYNOMIAL_PARTITIONS_V1]BasePolynomialPartitionV1 = undefined,
    base_partition_count: usize,
    lookup: LookupPolynomialCapabilityV1,
    lookup_constraints: ComponentConstraintRangeV1,

    pub fn validate(self: @This(), total_constraints: usize) !void {
        if (self.base_partition_count == 0 or
            self.base_partition_count > self.base_partitions.len or
            self.lookup_constraints.count == 0)
        {
            return error.InvalidBackendCompositionPartition;
        }
        const lookup_end = std.math.add(
            usize,
            self.lookup_constraints.start,
            self.lookup_constraints.count,
        ) catch return error.InvalidBackendCompositionPartition;
        if (lookup_end > total_constraints) return error.InvalidBackendCompositionPartition;
        var covered = self.lookup_constraints.count;
        for (self.base_partitions[0..self.base_partition_count], 0..) |partition, index| {
            const range = partition.constraints;
            const range_end = std.math.add(usize, range.start, range.count) catch
                return error.InvalidBackendCompositionPartition;
            if (range.count == 0 or range_end > total_constraints or
                (range.start < lookup_end and self.lookup_constraints.start < range_end))
                return error.InvalidBackendCompositionPartition;
            for (self.base_partitions[0..index]) |prior| {
                const prior_end = prior.constraints.start + prior.constraints.count;
                if (range.start < prior_end and prior.constraints.start < range_end)
                    return error.InvalidBackendCompositionPartition;
            }
            covered = std.math.add(usize, covered, range.count) catch
                return error.InvalidBackendCompositionPartition;
        }
        if (covered != total_constraints) return error.InvalidBackendCompositionPartition;
    }
};

pub const BaseLookupPolynomialCapabilityV1 = struct {
    export_capabilities: *const fn (
        ctx: *const anyopaque,
    ) anyerror!BaseLookupPolynomialCapabilitiesV1,
};

/// Variable singleton/pair lookup capability authenticated by a pointer-free
/// compiler authority. This is append-only beside V1: a component must opt in
/// explicitly, and existing backends may decline it through their ordinary
/// capability fallback until they implement the V2 partition.
pub const LookupPolynomialCapabilityV2 = struct {
    /// Borrowed from the same stable owner as `ComponentProver.ctx` and copied
    /// into backend preparation before any worker can start.
    authority: *const LookupPolynomialAuthorityV2,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    interaction_tree_index: usize,
    first_interaction_column: usize,
    interaction_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedLookupPolynomialProgramV2,
    export_parameters: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]QM31,
};

comptime {
    if (@sizeOf(LookupPolynomialCapabilityV2) >
        @sizeOf(LookupPolynomialCapabilityV1))
    {
        @compileError("dormant lookup-polynomial V2 must not inflate every production component");
    }
}

/// Reviewed semantic contracts that a backend may accelerate without
/// identifying a workload or trusting a coincidental vtable address. Each
/// variant names the complete AIR relation implemented by the accelerated
/// kernel; unmarked components always use the reference evaluator.
pub const BackendCompositionCapability = union(enum) {
    /// For one trace tree with columns `[a, b, c, ...]`, contributes one
    /// constraint per consecutive triple: `c - (a^2 + b^2)`, in canonical
    /// component constraint order, divided by the trace-coset vanishing
    /// polynomial.
    quadratic_sum_squares_v1: struct {
        trace_tree_index: usize,
        first_column: usize,
    },
    /// Direct base-field constraints exported from the frontend's production
    /// typed AIR builder. Random-coefficient order and vanishing denominators
    /// remain owned by the generic prover.
    base_polynomial_v1: BasePolynomialCapabilityV1,
    /// Pairs-batched LogUp transition constraints over production-exported
    /// base tuple expressions and committed secure cumulative columns.
    lookup_polynomial_v1: LookupPolynomialCapabilityV1,
    /// Authenticated variable singleton/pair partition used by the versioned
    /// SegmentV2 statement and proof layout.
    lookup_polynomial_v2: LookupPolynomialCapabilityV2,
    /// Complete component relation split between independently authenticated
    /// direct and LogUp sub-programs. Backends that do not implement the split
    /// decline it and retain the reference whole-component evaluator.
    base_lookup_polynomial_v1: BaseLookupPolynomialCapabilityV1,
    /// Complete typed recursive AIR, including same-row framework LogUp prefixes.
    /// Backends must explicitly implement this distinct recurrence or decline.
    framework_polynomial_v1: FrameworkPolynomialCapabilityV1,
};

/// Arbitrary admitted PCS input coordinates. Unlike the legacy resident
/// contracts, preprocessing need not be one selector beside a main slab.
pub const TypedPolynomialColumnV1 = struct { tree_index: u8, column_index: u32 };
pub const TypedPolynomialInputV1 = union(enum) {
    trace_column: TypedPolynomialColumnV1,
    profile_parameter: u32,
};

/// Recursive framework relations include the 33-word atomic Poseidon tuple.
/// Keep this geometry separate from the already admitted V1/V2 lookup ABI.
pub const FRAMEWORK_LOOKUP_MAX_ARITY_V1: usize = 33;
pub const FrameworkLookupEntryV1 = struct {
    domain: u16,
    schema_version: u16,
    numerator: u32,
    values: [FRAMEWORK_LOOKUP_MAX_ARITY_V1]u32 = @splat(0),
    arity: u8,
};
pub const FrameworkLookupBatchV1 = struct {
    first_entry: u32,
    entry_count: u8,
    interaction_column_start: u32,
};

/// Each non-final batch stores a same-row cumulative sum. Only the final
/// batch has a previous-row dependency, and its difference includes one
/// claimed_sum / trace_size shift. This is not the V1/V2 independent-prefix
/// recurrence and cannot be dispatched through those capability tags.
pub const FrameworkLookupLayoutV1 = enum(u16) {
    same_row_prefix_v1 = 1,
    /// Each batch has its own previous-row sum and public claim. The selector
    /// multiplies that claim; there is no same-row prefix or average shift.
    independent_prefix_v1 = 2,
};
pub const FRAMEWORK_POLYNOMIAL_PROGRAM_DOMAIN_V1 =
    "stwo/prover/framework-polynomial-program/v1\x00";

pub const OwnedFrameworkPolynomialProgramV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = 1,
    semantic_digest: [32]u8,
    registry_order_digest: [32]u8,
    direct: OwnedBasePolynomialProgram,
    lookup_nodes: []BasePolynomialNode,
    entries: []FrameworkLookupEntryV1,
    batches: []FrameworkLookupBatchV1,
    inputs: []TypedPolynomialInputV1,
    interaction_columns: []TypedPolynomialColumnV1,
    profile_parameter_count: u32,
    layout: FrameworkLookupLayoutV1 = .same_row_prefix_v1,
    is_first_input: ?u32 = null,
    identity: [32]u8,

    pub fn deinit(self: *OwnedFrameworkPolynomialProgramV1) void {
        self.direct.deinit();
        self.allocator.free(self.lookup_nodes);
        self.allocator.free(self.entries);
        self.allocator.free(self.batches);
        self.allocator.free(self.inputs);
        self.allocator.free(self.interaction_columns);
        self.* = undefined;
    }

    pub fn lookupParameterCount(self: *const OwnedFrameworkPolynomialProgramV1) usize {
        var count: usize = 0;
        for (self.entries) |entry| count += 1 + @as(usize, entry.arity);
        return count;
    }

    /// Cold backend admission. Column bounds are the proof's actual tree
    /// geometry, not capacities supplied by a producer-generated program.
    pub fn validate(self: *const OwnedFrameworkPolynomialProgramV1, tree_column_counts: []const usize) !void {
        if (self.format_version != 1 or self.direct.column_count != self.inputs.len or
            self.entries.len == 0 or self.batches.len == 0 or
            self.interaction_columns.len != 4 * self.batches.len or
            self.profile_parameter_count > self.inputs.len)
            return error.InvalidFrameworkPolynomialProgram;
        switch (self.layout) {
            .same_row_prefix_v1 => {
                if (self.is_first_input != null) return error.InvalidFrameworkPolynomialInput;
            },
            .independent_prefix_v1 => {
                const selector = self.is_first_input orelse return error.InvalidFrameworkPolynomialInput;
                if (selector >= self.inputs.len or self.inputs[selector] != .trace_column or
                    self.inputs[selector].trace_column.tree_index != 0)
                    return error.InvalidFrameworkPolynomialInput;
            },
        }
        // Relation-only components have no direct graph in either layout.
        // Lookup entries and batches remain mandatory and are validated below.
        if (self.direct.roots.len == 0) {
            if (self.direct.nodes.len != 0) return error.InvalidFrameworkPolynomialProgram;
        } else try self.direct.validate();
        var lookup_root = [_]u32{self.entries[0].numerator};
        try (OwnedBasePolynomialProgram{ .allocator = self.allocator, .nodes = self.lookup_nodes, .roots = &lookup_root, .column_count = self.inputs.len }).validate();
        for (self.inputs) |input| switch (input) {
            .trace_column => |column| try validateTypedColumn(column, tree_column_counts),
            .profile_parameter => |index| if (index >= self.profile_parameter_count) return error.InvalidFrameworkPolynomialInput,
        };
        for (self.interaction_columns) |column| try validateTypedColumn(column, tree_column_counts);
        for (self.entries) |entry| {
            if (entry.arity == 0 or entry.arity > FRAMEWORK_LOOKUP_MAX_ARITY_V1 or entry.numerator >= self.lookup_nodes.len)
                return error.InvalidFrameworkPolynomialEntry;
            for (entry.values[0..entry.arity]) |value| if (value >= self.lookup_nodes.len) return error.InvalidFrameworkPolynomialEntry;
            for (entry.values[entry.arity..]) |value| if (value != 0) return error.InvalidFrameworkPolynomialEntry;
        }
        var next_entry: usize = 0;
        for (self.batches, 0..) |batch, index| {
            if (batch.first_entry != next_entry or batch.entry_count == 0 or batch.entry_count > 4 or
                batch.interaction_column_start != 4 * index) return error.InvalidFrameworkPolynomialBatch;
            next_entry += batch.entry_count;
        }
        if (next_entry != self.entries.len) return error.InvalidFrameworkPolynomialBatch;
        for ([_][]const BasePolynomialNode{ self.direct.nodes, self.lookup_nodes }) |nodes| for (nodes) |node| {
            if (node.op == .constant and node.value >= m31.Modulus) return error.InvalidFrameworkPolynomialConstant;
        };
        if (!std.mem.eql(u8, &self.identity, &self.identityDigest())) return error.InvalidFrameworkPolynomialIdentity;
    }

    /// Program identity binds equations, order, layout and source coordinates.
    /// Runtime profile words, relation challenges and claimed sums stay outside
    /// this identity: they are authenticated invocation inputs, not constants.
    pub fn identityDigest(self: *const OwnedFrameworkPolynomialProgramV1) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(FRAMEWORK_POLYNOMIAL_PROGRAM_DOMAIN_V1);
        frameworkHashInt(&hash, u16, self.format_version);
        hash.update(&self.semantic_digest);
        hash.update(&self.registry_order_digest);
        frameworkHashInt(&hash, u16, @intFromEnum(self.layout));
        // Append-only encoding: existing layout1 identities stay byte-exact.
        if (self.layout == .independent_prefix_v1)
            frameworkHashInt(&hash, u32, self.is_first_input orelse std.math.maxInt(u32));
        frameworkHashInt(&hash, u32, self.profile_parameter_count);
        for ([_][]const BasePolynomialNode{ self.direct.nodes, self.lookup_nodes }) |nodes| {
            frameworkHashInt(&hash, u32, nodes.len);
            for (nodes) |node| {
                frameworkHashInt(&hash, u8, @intFromEnum(node.op));
                frameworkHashInt(&hash, u32, node.lhs);
                frameworkHashInt(&hash, u32, node.rhs);
                frameworkHashInt(&hash, u32, node.value);
            }
        }
        frameworkHashInt(&hash, u32, self.direct.roots.len);
        for (self.direct.roots) |root| frameworkHashInt(&hash, u32, root);
        frameworkHashInt(&hash, u32, self.inputs.len);
        for (self.inputs) |input| switch (input) {
            .trace_column => |column| {
                frameworkHashInt(&hash, u8, 0);
                frameworkHashInt(&hash, u8, column.tree_index);
                frameworkHashInt(&hash, u32, column.column_index);
            },
            .profile_parameter => |index| {
                frameworkHashInt(&hash, u8, 1);
                frameworkHashInt(&hash, u32, index);
            },
        };
        frameworkHashInt(&hash, u32, self.interaction_columns.len);
        for (self.interaction_columns) |column| {
            frameworkHashInt(&hash, u8, column.tree_index);
            frameworkHashInt(&hash, u32, column.column_index);
        }
        frameworkHashInt(&hash, u32, self.entries.len);
        for (self.entries) |entry| {
            frameworkHashInt(&hash, u16, entry.domain);
            frameworkHashInt(&hash, u16, entry.schema_version);
            frameworkHashInt(&hash, u32, entry.numerator);
            frameworkHashInt(&hash, u8, entry.arity);
            for (entry.values[0..entry.arity]) |value| frameworkHashInt(&hash, u32, value);
        }
        frameworkHashInt(&hash, u32, self.batches.len);
        for (self.batches) |batch| {
            frameworkHashInt(&hash, u32, batch.first_entry);
            frameworkHashInt(&hash, u8, batch.entry_count);
            frameworkHashInt(&hash, u32, batch.interaction_column_start);
        }
        return hash.finalResult();
    }
};

pub const FrameworkPolynomialParametersV1 = struct {
    profile_values: []const M31,
    /// Canonical per-entry (z, alpha^0, ..., alpha^(arity-1)).
    relation_values: []const QM31,
    /// These are admitted component invocation inputs. The backend must match
    /// trace_log_size to the proof's component geometry, never candidate data.
    trace_log_size: u32,
    claimed_sum: QM31,
    batch_claims: []const QM31 = &.{},

    /// Payload after relation parameters: the legacy average shift, or one
    /// unscaled public claim per independent batch. Validate at admission.
    pub fn claimPayloadCount(self: FrameworkPolynomialParametersV1, program: *const OwnedFrameworkPolynomialProgramV1) usize {
        return switch (program.layout) {
            .same_row_prefix_v1 => 1,
            .independent_prefix_v1 => self.batch_claims.len,
        };
    }

    pub fn claimPayload(self: FrameworkPolynomialParametersV1, program: *const OwnedFrameworkPolynomialProgramV1, index: usize) !QM31 {
        return switch (program.layout) {
            .same_row_prefix_v1 => if (index == 0) self.claimedSumShift() else error.InvalidFrameworkPolynomialParameters,
            .independent_prefix_v1 => if (index < self.batch_claims.len) self.batch_claims[index] else error.InvalidFrameworkPolynomialParameters,
        };
    }

    pub fn claimedSumShift(self: FrameworkPolynomialParametersV1) !QM31 {
        if (self.trace_log_size == 0 or self.trace_log_size >= @import("stwo_core").circle.M31_CIRCLE_LOG_ORDER)
            return error.InvalidFrameworkPolynomialParameters;
        return self.claimed_sum.divM31(M31.fromU64(@as(u64, 1) << @intCast(self.trace_log_size)));
    }

    pub fn validate(self: FrameworkPolynomialParametersV1, program: *const OwnedFrameworkPolynomialProgramV1) !void {
        if (self.profile_values.len != program.profile_parameter_count or self.relation_values.len != program.lookupParameterCount())
            return error.InvalidFrameworkPolynomialParameters;
        for (self.profile_values) |value| if (value.toU32() >= m31.Modulus) return error.InvalidFrameworkPolynomialParameters;
        for (self.relation_values) |value| for (value.toM31Array()) |coordinate| {
            if (coordinate.toU32() >= m31.Modulus) return error.InvalidFrameworkPolynomialParameters;
        };
        for (self.claimed_sum.toM31Array()) |coordinate| if (coordinate.toU32() >= m31.Modulus) return error.InvalidFrameworkPolynomialParameters;
        switch (program.layout) {
            .same_row_prefix_v1 => if (self.batch_claims.len != 0) return error.InvalidFrameworkPolynomialParameters,
            .independent_prefix_v1 => {
                if (!self.claimed_sum.isZero() or self.batch_claims.len != program.batches.len)
                    return error.InvalidFrameworkPolynomialParameters;
                for (self.batch_claims) |claim| for (claim.toM31Array()) |coordinate| {
                    if (coordinate.toU32() >= m31.Modulus) return error.InvalidFrameworkPolynomialParameters;
                };
            },
        }
        _ = try self.claimedSumShift();
    }
};

fn validateTypedColumn(column: TypedPolynomialColumnV1, counts: []const usize) !void {
    if (column.tree_index >= counts.len or column.column_index >= counts[column.tree_index]) return error.InvalidFrameworkPolynomialInput;
}
fn frameworkHashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

/// Cold export callbacks from one admitted immutable component. Runtime values
/// stay outside program identity; the backend binds the invocation log size to
/// this admitted trace geometry before dispatch, and owns exports for the job.
pub const FrameworkPolynomialCapabilityV1 = struct {
    trace_log_size: u32,
    export_program: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator, tree_column_counts: []const usize) anyerror!OwnedFrameworkPolynomialProgramV1,
    export_parameters: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator) anyerror!OwnedFrameworkPolynomialParametersV1,
};

pub const OwnedFrameworkPolynomialParametersV1 = struct {
    allocator: std.mem.Allocator,
    values: FrameworkPolynomialParametersV1,

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.values.profile_values);
        self.allocator.free(self.values.relation_values);
        if (self.values.batch_claims.len != 0) self.allocator.free(self.values.batch_claims);
        self.* = undefined;
    }
};
