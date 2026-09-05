//! Append-only lower-width Poseidon2-M31 candidate authority.
//!
//! This module is deliberately disjoint from the frozen Stark-V compatibility
//! component. It does not change `poseidon2_air.zig`, `HashComponent`, any V1
//! identity, or any production dispatch. Instead it cold-builds the canonical
//! typed Poseidon semantic graph, applies the reviewed degree-bounded
//! materializer, and owns an independently named physical row plus direct
//! polynomial program. A future production integration must mint a distinct
//! component/profile identity and independently reconstruct this authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const digest_mod = @import("digest.zig");
const direct = @import("materialization_cost_direct.zig");
const direct_program_mod = @import("materialization_direct_program.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const format_version: u16 = 1;
pub const identity_domain =
    "stwo-zig/riscv/poseidon2-degree-bounded-candidate/v1";
pub const component_family =
    "stwo.riscv.poseidon2-m31.degree-bounded-candidate";
pub const WIDTH: usize = poseidon.WIDTH;
pub const BASE_MAIN_COLUMNS: usize = 1 + WIDTH + 2;
pub const MATERIALIZATION_COLUMN_START: usize = 1 + WIDTH;
pub const INTERACTION_COLUMNS: usize = production.N_INTERACTION_COLUMNS;
pub const NARROW_SHELL_DIRECT_CONSTRAINTS: u8 = 3;
pub const INTERACTION_CONSTRAINTS: u8 = production.N_SUMS;
pub const SECURE_EXTENSION_DEGREE: u8 = 4;

const materialized_column_namespace: u64 = @as(u64, 1) << 63;
const no_column = std.math.maxInt(u32);

pub const Profile = enum(u8) {
    degree5 = 5,
    degree6 = 6,

    pub fn maximumConstraintDegree(self: Profile) u8 {
        return @intFromEnum(self);
    }

    pub fn expected(self: Profile) ExpectedGeometry {
        return switch (self) {
            .degree5 => .{
                .materialization_columns = 220,
                .main_columns = 239,
                .direct_constraints = 224,
                .direct_nodes = 2_842,
                .direct_multiplications = 874,
                .streaming_peak_live_nodes = 39,
            },
            .degree6 => .{
                .materialization_columns = 142,
                .main_columns = 161,
                .direct_constraints = 146,
                .direct_nodes = 2_608,
                .direct_multiplications = 796,
                .streaming_peak_live_nodes = 38,
            },
        };
    }

    /// Exact quotient-domain expansion after division by the trace-domain
    /// vanishing polynomial: a degree-d constraint has quotient degree less
    /// than `(d - 1) * N`, requiring `ceil(log2(d - 1))` extra bits.
    pub fn quotientExpansionBits(self: Profile) u8 {
        return ceilLog2(self.maximumConstraintDegree() - 1);
    }

    /// Split the quotient composition back to the trace degree.  Keeping a
    /// fixed split of one is only valid for degree-three AIRs; higher-degree
    /// candidates require one split level per quotient-expansion bit.
    pub fn compositionLogSplit(self: Profile) u8 {
        return self.quotientExpansionBits();
    }

    pub fn compositionColumns(self: Profile) u8 {
        return (@as(u8, 1) << @intCast(self.compositionLogSplit())) *
            SECURE_EXTENSION_DEGREE;
    }

    pub fn maxConstraintLogDegreeBound(
        self: Profile,
        trace_log_size: u32,
    ) error{LogDegreeOverflow}!u32 {
        return std.math.add(
            u32,
            trace_log_size,
            self.quotientExpansionBits(),
        ) catch error.LogDegreeOverflow;
    }

    /// Composition chunks are committed at the trace log after splitting the
    /// full quotient by the profile's exact expansion depth.
    pub fn compositionColumnLogSize(
        self: Profile,
        trace_log_size: u32,
    ) error{LogDegreeOverflow}!u32 {
        const bound = try self.maxConstraintLogDegreeBound(trace_log_size);
        return std.math.sub(u32, bound, self.compositionLogSplit()) catch
            error.LogDegreeOverflow;
    }
};

pub const ExpectedGeometry = struct {
    materialization_columns: u16,
    main_columns: u16,
    direct_constraints: u16,
    direct_nodes: u16,
    direct_multiplications: u16,
    streaming_peak_live_nodes: u8,
};

pub const Geometry = struct {
    materialization_columns: u16,
    main_columns: u16,
    interaction_columns: u8,
    permutation_direct_constraints: u16,
    narrow_shell_direct_constraints: u8,
    component_direct_constraints: u16,
    interaction_constraints: u8,
    maximum_constraint_degree: u8,
    quotient_expansion_bits: u8,
    composition_log_split: u8,
    composition_columns: u8,
    direct_nodes: u16,
    direct_multiplications: u16,
    streaming_peak_live_nodes: u8,
};

pub const RowFailure = struct {
    root_index: u16,
    residual: M31,
};

pub const ValidationError = error{
    CandidateIdentityMismatch,
    CandidateProfileMismatch,
    DirectProgramMismatch,
    InvalidCommittedColumn,
    InvalidDirectNode,
    InvalidFixedColumn,
    InvalidGeometry,
    InvalidMaterializationSet,
    InvalidRowShape,
    UnsupportedExpression,
    UnsupportedRowMask,
};

/// Owned, candidate-only physical authority. It is intentionally unsuitable
/// for direct serialization or production admission: the public identity is a
/// compiler candidate identity, not an activated AIR-program identity.
pub const Candidate = struct {
    allocator: std.mem.Allocator,
    profile: Profile,
    arena: ir.Arena,
    definition: poseidon.Definition,
    gate: types.ValueId,
    plan: materializer.Plan,
    selected_values: []types.ValueId,
    direct_program: direct_program_mod.Program,
    semantic_scratch: []M31,
    direct_scratch: []M31,
    semantic_columns: []u32,
    geometry: Geometry,
    direct_program_digest: [32]u8,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        profile: Profile,
    ) !Candidate {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        const gate = try arena.input(
            "riscv.poseidon2_m31.degree_bounded.enabled",
            .selector,
            generated,
        );
        const definition = try poseidon.define(
            &arena,
            poseidon.DefinitionSpans.uniform(generated),
        );
        const roots = poseidon.values(definition.outputs);
        var plan = try materializer.plan(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
            .policy = .{
                .maximum_constraint_degree = profile.maximumConstraintDegree(),
            },
        });
        errdefer plan.deinit();

        const selected_values = try allocator.alloc(
            types.ValueId,
            plan.materializations.len,
        );
        errdefer allocator.free(selected_values);
        for (plan.materializations, selected_values) |entry, *value| {
            value.* = entry.source_value;
        }
        std.mem.sort(
            types.ValueId,
            selected_values,
            {},
            valueLessThan,
        );

        var direct_program = try direct_program_mod.extractValidated(
            allocator,
            &arena,
            .{
                .gate = gate,
                .policy = plan.policy,
                .selected = selected_values,
                .materialization_column_start = MATERIALIZATION_COLUMN_START,
                .fixed_direct_program = poseidon_fixed.program,
            },
        );
        errdefer direct_program.deinit();

        const semantic_scratch = try allocator.alloc(M31, arena.nodeCount());
        errdefer allocator.free(semantic_scratch);
        const direct_scratch = try allocator.alloc(
            M31,
            direct_program.nodes().len,
        );
        errdefer allocator.free(direct_scratch);
        const semantic_columns = try allocator.alloc(u32, arena.nodeCount());
        errdefer allocator.free(semantic_columns);
        @memset(semantic_columns, no_column);
        semantic_columns[types.idIndex(gate)] = 0;
        const input_values = poseidon.values(definition.inputs);
        for (input_values, 0..) |value, lane| {
            semantic_columns[types.idIndex(value)] = @intCast(1 + lane);
        }
        for (selected_values, 0..) |value, ordinal| {
            semantic_columns[types.idIndex(value)] =
                @intCast(MATERIALIZATION_COLUMN_START + ordinal);
        }

        const expected = profile.expected();
        const geometry = Geometry{
            .materialization_columns = @intCast(selected_values.len),
            .main_columns = @intCast(BASE_MAIN_COLUMNS + selected_values.len),
            .interaction_columns = INTERACTION_COLUMNS,
            .permutation_direct_constraints = @intCast(
                direct_program.roots().len,
            ),
            .narrow_shell_direct_constraints = NARROW_SHELL_DIRECT_CONSTRAINTS,
            .component_direct_constraints = @intCast(
                direct_program.roots().len + NARROW_SHELL_DIRECT_CONSTRAINTS,
            ),
            .interaction_constraints = INTERACTION_CONSTRAINTS,
            .maximum_constraint_degree = profile.maximumConstraintDegree(),
            .quotient_expansion_bits = profile.quotientExpansionBits(),
            .composition_log_split = profile.compositionLogSplit(),
            .composition_columns = profile.compositionColumns(),
            .direct_nodes = @intCast(direct_program.counts.nodes),
            .direct_multiplications = @intCast(
                direct_program.counts.multiplications,
            ),
            .streaming_peak_live_nodes = @intCast(
                direct_program.counts.streaming_peak_live_nodes,
            ),
        };
        if (!geometryMatchesExpected(geometry, expected))
            return error.InvalidGeometry;
        const direct_program_digest = direct_program.programDigest();

        var result = Candidate{
            .allocator = allocator,
            .profile = profile,
            .arena = arena,
            .definition = definition,
            .gate = gate,
            .plan = plan,
            .selected_values = selected_values,
            .direct_program = direct_program,
            .semantic_scratch = semantic_scratch,
            .direct_scratch = direct_scratch,
            .semantic_columns = semantic_columns,
            .geometry = geometry,
            .direct_program_digest = direct_program_digest,
            .identity = [_]u8{0} ** 32,
        };
        result.identity = result.computeIdentity();
        try result.validate();
        return result;
    }

    pub fn deinit(self: *Candidate) void {
        self.allocator.free(self.semantic_columns);
        self.allocator.free(self.direct_scratch);
        self.allocator.free(self.semantic_scratch);
        self.direct_program.deinit();
        self.allocator.free(self.selected_values);
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn mainColumnCount(self: *const Candidate) usize {
        return self.geometry.main_columns;
    }

    pub fn validate(self: *const Candidate) !void {
        if (self.plan.policy.maximum_constraint_degree !=
            self.profile.maximumConstraintDegree() or
            self.plan.policy.row_mask_degree != 0)
        {
            return error.CandidateProfileMismatch;
        }
        try self.plan.validate(self.allocator, &self.arena);
        try self.direct_program.authenticate(self.direct_program_digest);
        if (self.direct_scratch.len != self.direct_program.nodes().len or
            self.semantic_scratch.len != self.arena.nodeCount() or
            self.semantic_columns.len != self.arena.nodeCount())
        {
            return error.InvalidGeometry;
        }
        try self.validateSelectionAndGeometry();
        if (!std.mem.eql(u8, &self.identity, &self.computeIdentity()))
            return error.CandidateIdentityMismatch;
    }

    /// Per-shard hot-path check for an already validated, process-local
    /// candidate.  It rebinds the identity to the profile, policy, program
    /// digests, geometry, and selection exactly like `validate`, but skips
    /// re-deriving the materializer plan: that recursive degree analysis is
    /// construction-time authority and was costing several seconds per leaf
    /// when repeated for every shard, export, and trace.  Cold entry points
    /// keep calling `validate`.
    pub fn validateRetained(self: *const Candidate) !void {
        if (self.plan.policy.maximum_constraint_degree !=
            self.profile.maximumConstraintDegree() or
            self.plan.policy.row_mask_degree != 0)
        {
            return error.CandidateProfileMismatch;
        }
        try self.direct_program.authenticate(self.direct_program_digest);
        if (self.direct_scratch.len != self.direct_program.nodes().len or
            self.semantic_scratch.len != self.arena.nodeCount() or
            self.semantic_columns.len != self.arena.nodeCount())
        {
            return error.InvalidGeometry;
        }
        try self.validateSelectionAndGeometry();
        if (!std.mem.eql(u8, &self.identity, &self.computeIdentity()))
            return error.CandidateIdentityMismatch;
    }

    /// Writes one logical row in candidate-native order:
    /// enabler, 16 inputs, canonical selected values, wide, io.
    pub fn fillRow(
        self: *Candidate,
        row: []M31,
        call: production.Call,
    ) !void {
        if (row.len != self.mainColumnCount()) return error.InvalidRowShape;
        try self.evaluateSemantic(call.input);
        row[0] = M31.one();
        for (call.input, 0..) |value, lane| {
            row[1 + lane] = M31.fromU64(value);
        }
        for (self.selected_values, 0..) |value, ordinal| {
            row[MATERIALIZATION_COLUMN_START + ordinal] =
                self.semantic_scratch[types.idIndex(value)];
        }
        row[row.len - 2] = M31.fromU64(@intFromBool(call.wide));
        row[row.len - 1] = M31.fromU64(@intFromBool(call.io));
    }

    pub fn outputs(
        self: *const Candidate,
        row: []const M31,
    ) ValidationError![WIDTH]M31 {
        if (row.len != self.mainColumnCount()) return error.InvalidRowShape;
        var result: [WIDTH]M31 = undefined;
        const output_values = poseidon.values(self.definition.outputs);
        for (output_values, &result) |value, *output| {
            const column = self.semanticColumn(value) orelse
                return error.InvalidCommittedColumn;
            output.* = row[column];
        }
        return result;
    }

    /// Compiler-owned main-column projection used by the ordered provider
    /// accumulator: all sixteen inputs followed by narrow output lane zero.
    /// Lower-width proof paths bind these exact columns in their AIR-program
    /// identity instead of borrowing the legacy 445-column offsets.
    pub fn narrowProviderOrderColumns(
        self: *const Candidate,
    ) ValidationError![WIDTH + 1]u16 {
        var result: [WIDTH + 1]u16 = undefined;
        for (poseidon.values(self.definition.inputs), 0..) |value, lane| {
            result[lane] = std.math.cast(
                u16,
                self.semanticColumn(value) orelse
                    return error.InvalidCommittedColumn,
            ) orelse return error.InvalidCommittedColumn;
        }
        const output = poseidon.values(self.definition.outputs)[0];
        result[WIDTH] = std.math.cast(
            u16,
            self.semanticColumn(output) orelse
                return error.InvalidCommittedColumn,
        ) orelse return error.InvalidCommittedColumn;
        return result;
    }

    /// Replays the canonical direct-polynomial DAG and returns its first
    /// nonzero constraint root. A null result is exact direct-AIR acceptance.
    pub fn diagnoseRow(
        self: *Candidate,
        row: []const M31,
    ) ValidationError!?RowFailure {
        if (row.len != self.mainColumnCount()) return error.InvalidRowShape;
        for (self.direct_program.nodes(), 0..) |node, index| {
            self.direct_scratch[index] = switch (node.op) {
                .constant => M31.fromU64(node.value),
                .committed => try self.readCommitted(row, node.value),
                .fixed_committed => blk: {
                    if (node.lhs != @intFromEnum(
                        direct_program_mod.CommitmentTree.main,
                    ) or node.value >= row.len) {
                        return error.InvalidFixedColumn;
                    }
                    break :blk row[@intCast(node.value)];
                },
                .row_mask => return error.UnsupportedRowMask,
                .add => try self.binaryValue(node, index, .add),
                .sub => try self.binaryValue(node, index, .sub),
                .neg => blk: {
                    if (node.lhs >= index) return error.InvalidDirectNode;
                    break :blk self.direct_scratch[node.lhs].neg();
                },
                .mul => try self.binaryValue(node, index, .mul),
            };
        }
        for (self.direct_program.roots(), 0..) |root, root_index| {
            if (root.node >= self.direct_scratch.len)
                return error.InvalidDirectNode;
            const residual = self.direct_scratch[root.node];
            if (!residual.isZero()) return .{
                .root_index = @intCast(root_index),
                .residual = residual,
            };
        }
        return null;
    }

    pub fn validateRow(
        self: *Candidate,
        row: []const M31,
    ) ValidationError!void {
        if (try self.diagnoseRow(row) != null)
            return error.DirectProgramMismatch;
    }

    /// Exact `HashComponent(.poseidon2, .narrow_memory)` shell around the
    /// candidate permutation: committed enabler equals the independently
    /// supplied active selector, and both wide/io mode columns are zero.
    pub fn validateNarrowRow(
        self: *Candidate,
        row: []const M31,
        active_selector: M31,
    ) ValidationError!void {
        try self.validateRow(row);
        if (row[0].toU32() != active_selector.toU32() or
            !row[row.len - 2].isZero() or
            !row[row.len - 1].isZero())
        {
            return error.DirectProgramMismatch;
        }
    }

    fn validateSelectionAndGeometry(self: *const Candidate) !void {
        const expected = self.profile.expected();
        if (!geometryMatchesExpected(self.geometry, expected) or
            self.geometry.interaction_columns != INTERACTION_COLUMNS or
            self.geometry.narrow_shell_direct_constraints !=
                NARROW_SHELL_DIRECT_CONSTRAINTS or
            self.geometry.component_direct_constraints !=
                self.geometry.permutation_direct_constraints +
                    @as(u16, NARROW_SHELL_DIRECT_CONSTRAINTS) or
            self.geometry.interaction_constraints != INTERACTION_CONSTRAINTS or
            self.geometry.maximum_constraint_degree !=
                self.profile.maximumConstraintDegree() or
            self.geometry.quotient_expansion_bits !=
                self.profile.quotientExpansionBits() or
            self.geometry.composition_log_split !=
                self.profile.compositionLogSplit() or
            self.geometry.composition_columns !=
                self.profile.compositionColumns() or
            self.selected_values.len != self.plan.materializations.len)
        {
            return error.InvalidGeometry;
        }
        var previous: ?usize = null;
        for (self.selected_values, 0..) |value, ordinal| {
            const index = types.idIndex(value);
            if (previous) |prior| if (index <= prior)
                return error.InvalidMaterializationSet;
            previous = index;
            var found = false;
            for (self.plan.materializations) |entry| {
                if (entry.source_value == value) {
                    found = true;
                    break;
                }
            }
            if (!found or self.semantic_columns[index] !=
                MATERIALIZATION_COLUMN_START + ordinal)
            {
                return error.InvalidMaterializationSet;
            }
        }
        var maximum_constraint_degree: u64 = 0;
        for (self.plan.materializations) |entry| {
            maximum_constraint_degree = @max(
                maximum_constraint_degree,
                entry.constraint_degree,
            );
        }
        if (maximum_constraint_degree != self.profile.maximumConstraintDegree())
            return error.CandidateProfileMismatch;
    }

    fn evaluateSemantic(self: *Candidate, input: [WIDTH]u32) !void {
        const input_values = poseidon.values(self.definition.inputs);
        for (self.arena.nodesView(), 0..) |node, index| {
            self.semantic_scratch[index] = switch (node.key.op) {
                .constant => |constant| switch (constant) {
                    .field => |value| M31.fromCanonical(value),
                    .unsigned => |value| M31.fromU64(value),
                },
                .input => blk: {
                    const value: types.ValueId = @enumFromInt(index);
                    if (value == self.gate) break :blk M31.one();
                    for (input_values, 0..) |candidate_input, lane| {
                        if (value == candidate_input)
                            break :blk M31.fromU64(input[lane]);
                    }
                    return error.UnsupportedExpression;
                },
                .add => |binary| self.semanticValue(binary.lhs).add(
                    self.semanticValue(binary.rhs),
                ),
                .sub => |binary| self.semanticValue(binary.lhs).sub(
                    self.semanticValue(binary.rhs),
                ),
                .mul => |binary| self.semanticValue(binary.lhs).mul(
                    self.semanticValue(binary.rhs),
                ),
                .neg => |operand| self.semanticValue(operand).neg(),
                .select => |selection| if (!self.semanticValue(
                    selection.selector,
                ).isZero())
                    self.semanticValue(selection.when_true)
                else
                    self.semanticValue(selection.when_false),
                .hint_output, .call_output, .machine_derived => return error.UnsupportedExpression,
            };
        }
    }

    inline fn semanticValue(
        self: *const Candidate,
        value: types.ValueId,
    ) M31 {
        return self.semantic_scratch[types.idIndex(value)];
    }

    fn semanticColumn(
        self: *const Candidate,
        value: types.ValueId,
    ) ?usize {
        const index = types.idIndex(value);
        if (index >= self.semantic_columns.len) return null;
        const column = self.semantic_columns[index];
        if (column == no_column or column >= self.mainColumnCount()) return null;
        return column;
    }

    fn readCommitted(
        self: *const Candidate,
        row: []const M31,
        encoded_value: u64,
    ) ValidationError!M31 {
        if (encoded_value & ~(materialized_column_namespace |
            std.math.maxInt(u32)) != 0)
        {
            return error.InvalidCommittedColumn;
        }
        const value: types.ValueId = @enumFromInt(
            @as(u32, @intCast(encoded_value & std.math.maxInt(u32))),
        );
        const column = self.semanticColumn(value) orelse
            return error.InvalidCommittedColumn;
        const is_materialized = encoded_value & materialized_column_namespace != 0;
        if (is_materialized != (column >= MATERIALIZATION_COLUMN_START and
            column < self.mainColumnCount() - 2))
        {
            return error.InvalidCommittedColumn;
        }
        return row[column];
    }

    const BinaryOp = enum { add, sub, mul };

    fn binaryValue(
        self: *const Candidate,
        node: direct.Node,
        index: usize,
        op: BinaryOp,
    ) ValidationError!M31 {
        if (node.lhs >= index or node.rhs >= index)
            return error.InvalidDirectNode;
        const lhs = self.direct_scratch[node.lhs];
        const rhs = self.direct_scratch[node.rhs];
        return switch (op) {
            .add => lhs.add(rhs),
            .sub => lhs.sub(rhs),
            .mul => lhs.mul(rhs),
        };
    }

    fn computeIdentity(self: *const Candidate) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(identity_domain);
        hashInt(&hash, u16, format_version);
        hash.update(component_family);
        hashInt(&hash, u8, @intFromEnum(self.profile));
        hashInt(&hash, u16, self.plan.program_digest_format);
        hash.update(&self.plan.program_digest);
        hashInt(&hash, u16, materializer.policy_version);
        hashInt(&hash, u64, self.plan.policy.maximum_constraint_degree);
        hashInt(&hash, u64, self.plan.policy.row_mask_degree);
        hashInt(&hash, u32, @intFromEnum(self.gate));
        hash.update(&poseidon_fixed.canonical_digest);
        hash.update(&self.direct_program_digest);
        hashInt(&hash, u16, self.geometry.materialization_columns);
        hashInt(&hash, u16, self.geometry.main_columns);
        hashInt(&hash, u8, self.geometry.interaction_columns);
        hashInt(&hash, u16, self.geometry.permutation_direct_constraints);
        hashInt(&hash, u8, self.geometry.narrow_shell_direct_constraints);
        hashInt(&hash, u16, self.geometry.component_direct_constraints);
        hashInt(&hash, u8, self.geometry.interaction_constraints);
        hashInt(&hash, u8, self.geometry.maximum_constraint_degree);
        hashInt(&hash, u8, self.geometry.quotient_expansion_bits);
        hashInt(&hash, u8, self.geometry.composition_log_split);
        hashInt(&hash, u8, self.geometry.composition_columns);
        hashInt(&hash, u16, self.geometry.direct_nodes);
        hashInt(&hash, u16, self.geometry.direct_multiplications);
        hashInt(&hash, u8, self.geometry.streaming_peak_live_nodes);
        hashInt(&hash, u32, @intCast(self.selected_values.len));
        for (self.selected_values) |value| {
            hashInt(&hash, u32, @intFromEnum(value));
        }
        return hash.finalResult();
    }
};

fn geometryMatchesExpected(
    actual: Geometry,
    expected: ExpectedGeometry,
) bool {
    return actual.materialization_columns == expected.materialization_columns and
        actual.main_columns == expected.main_columns and
        actual.permutation_direct_constraints == expected.direct_constraints and
        actual.direct_nodes == expected.direct_nodes and
        actual.direct_multiplications == expected.direct_multiplications and
        actual.streaming_peak_live_nodes == expected.streaming_peak_live_nodes;
}

fn valueLessThan(_: void, lhs: types.ValueId, rhs: types.ValueId) bool {
    return @intFromEnum(lhs) < @intFromEnum(rhs);
}

fn ceilLog2(value: u8) u8 {
    std.debug.assert(value != 0);
    var remaining = value - 1;
    var result: u8 = 0;
    while (remaining != 0) : (remaining >>= 1) result += 1;
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (WIDTH != production.WIDTH or
        INTERACTION_COLUMNS != 8 or
        BASE_MAIN_COLUMNS != 19 or
        MATERIALIZATION_COLUMN_START != 17 or
        Profile.degree5.compositionColumns() != 16 or
        Profile.degree6.compositionColumns() != 32)
    {
        @compileError("degree-bounded candidate base geometry drifted");
    }
    _ = digest_mod;
    _ = expr;
}
