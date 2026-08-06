//! Benchmark-only execution of an authenticated H-009 Poseidon2 proposal.
//!
//! This module is deliberately absent from `mod.zig` and every production
//! product root. It owns no Poseidon permutation: construction creates the
//! canonical H-005 witness executor, authenticates an H-009 `CutSet` and
//! `STWAIRM` proposal against the same arena, then maps the proposal's selected
//! `ValueId`s onto H-005's already-compiled semantic instruction closure.
//!
//! The proposal-native 445-column layout is enabler, 16 inputs, 426 selected
//! values in canonical `ValueId` order, wide, and io. It is experimental and
//! must not be confused with the legacy temporary order used by production.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const core_utils = @import("stwo_core").utils;
const compat = @import("typed_poseidon2_compat.zig");
const cut_set = @import("materialization_cut_set.zig");
const frontier = @import("materialization_frontier_manifest.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const validation = @import("typed_poseidon2_layout_executor_validate.zig");
const witness = @import("typed_poseidon2_witness.zig");

pub const WIDTH: usize = compat.WIDTH;
pub const N_MATERIALIZATIONS: usize = compat.N_MATERIALIZATIONS;
pub const N_MAIN_COLUMNS: usize = compat.N_MAIN_COLUMNS;
pub const Call = production.Call;
pub const LAYOUT_DIGEST_FORMAT_VERSION = validation.LAYOUT_DIGEST_FORMAT_VERSION;
pub const LAYOUT_DIGEST_DOMAIN_SEPARATOR = validation.LAYOUT_DIGEST_DOMAIN_SEPARATOR;
pub const ROOT_RESIDUAL_DIGEST_DOMAIN_SEPARATOR =
    validation.ROOT_RESIDUAL_DIGEST_DOMAIN_SEPARATOR;

pub const ProposalSelection = union(enum) {
    baseline,
    frontier: usize,
};

pub const ConstructionError = witness.ConstructionError || cut_set.Error ||
    frontier.ManifestError || validation.ConstructionError || error{ProposalNotFound};

pub const ExecutionError = witness.ExecutionError || validation.IntegrityError;

/// All identities needed to reproduce one benchmark layout. The H-005 digest
/// authenticates executable semantics; the H-009 fields authenticate proposal
/// selection and cost-frontier context; `layout_digest` binds their mapping.
pub const Identity = struct {
    semantic_execution_digest: frontier.Digest,
    frontier_identity_digest: frontier.Digest,
    cost_model_digest: frontier.Digest,
    cut_digest: frontier.Digest,
    proposal_digest: frontier.Digest,
    layout_digest: frontier.Digest,
};

pub const StorageProfile = struct {
    main_columns: usize,
    materializations: usize,
    semantic_instructions: usize,
    semantic_scratch_elements: usize,
    field_element_bytes: usize,
};

pub const MaterializationRole = struct {
    ordinal: u16,
    value_id: u32,
};

pub const FailureRole = union(enum) {
    enabler,
    input: u8,
    materialization: MaterializationRole,
    wide,
    io,
};

/// First mismatch in physical proposal-column order.
pub const Failure = struct {
    column: u16,
    role: FailureRole,
    expected: M31,
    actual: M31,
};

/// Capability produced only after executor authentication plus complete trace
/// shape and alias validation. It owns nothing and remains valid only while
/// the executor, calls, and column descriptors are unchanged. Its sole purpose
/// is to keep those checks outside an isolated benchmark hot loop. This is a
/// timing capability inside a tool-only module, not an authority or memory-
/// safety boundary, and must never be exported by the production facade.
pub const PreparedMain = struct {
    executor: *Executor,
    columns: *[N_MAIN_COLUMNS][]M31,
    calls: []const Call,
    log_size: u32,
    trace_size: usize,

    pub fn execute(self: PreparedMain) void {
        self.executor.executePreparedMain(self);
    }
};

/// CPU-only executor for one fully authenticated proposal layout.
///
/// It owns H-005 and therefore owns its scratch. Like H-005, one instance is
/// intentionally non-reentrant; create one per benchmark worker.
pub const Executor = struct {
    semantic: witness.Executor,
    frontier_identity_digest: frontier.Digest,
    cost_model_digest: frontier.Digest,
    cut_digest: frontier.Digest,
    proposal_digest: frontier.Digest,
    layout_digest: frontier.Digest,
    selected_values: [N_MATERIALIZATIONS]u32,
    selected_slots: [N_MATERIALIZATIONS]u32,
    root_ordinals: [WIDTH]u16,

    pub fn init(
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        definition: poseidon.Definition,
        spans: poseidon.DefinitionSpans,
        canonical_plan: *const materializer.Plan,
        canonical_binding: *const compat.OwnedBinding,
        proposal_cut: *const cut_set.CutSet,
        manifest: frontier.Manifest,
        selection: ProposalSelection,
    ) ConstructionError!Executor {
        try frontier.validateCanonical(manifest);
        const proposal = try selectProposal(manifest, selection);
        try validation.validateGeometry(manifest, proposal);

        const roots = poseidon.values(definition.outputs);
        const request = materializer.Request{
            .roots = &roots,
            .gate = canonical_plan.gate,
            .policy = canonical_plan.policy,
        };
        try proposal_cut.validateAgainst(allocator, arena, request);
        try validation.validateProposalCut(proposal_cut, manifest, proposal);

        var semantic = try witness.Executor.init(
            allocator,
            arena,
            definition,
            spans,
            canonical_plan,
            canonical_binding,
        );
        errdefer semantic.deinit();
        const semantic_identity = semantic.identitySnapshot() catch
            return error.InstructionClosureMismatch;
        const semantic_execution_digest = semantic.identityDigest() catch
            return error.InstructionClosureMismatch;
        try validation.validateSemanticIdentity(semantic_identity, manifest.identity);

        var selected_values: [N_MATERIALIZATIONS]u32 = undefined;
        @memcpy(&selected_values, proposal.selected_values);
        const selected_slots = try validation.compileSelectedSlots(
            allocator,
            arena,
            semantic_identity.outputs,
            &selected_values,
            semantic.instructionCount(),
        );
        var root_ordinals: [WIDTH]u16 = undefined;
        for (semantic_identity.outputs, &root_ordinals) |root, *ordinal| {
            ordinal.* = @intCast(validation.indexOf(&selected_values, @intFromEnum(root)) orelse
                return error.ProposalMismatch);
        }

        const layout_digest = validation.computeLayoutDigest(
            semantic_execution_digest,
            manifest.identity.identity_digest,
            manifest.cost_model.cost_model_digest,
            proposal.cut_digest,
            proposal.proposal_digest,
            &selected_values,
            &selected_slots,
            &root_ordinals,
        );
        return .{
            .semantic = semantic,
            .frontier_identity_digest = manifest.identity.identity_digest,
            .cost_model_digest = manifest.cost_model.cost_model_digest,
            .cut_digest = proposal.cut_digest,
            .proposal_digest = proposal.proposal_digest,
            .layout_digest = layout_digest,
            .selected_values = selected_values,
            .selected_slots = selected_slots,
            .root_ordinals = root_ordinals,
        };
    }

    pub fn deinit(self: *Executor) void {
        self.semantic.deinit();
        self.* = undefined;
    }

    pub fn identity(self: *const Executor) ExecutionError!Identity {
        return self.validateIntegrity();
    }

    pub fn storageProfile(self: *const Executor) StorageProfile {
        return .{
            .main_columns = N_MAIN_COLUMNS,
            .materializations = N_MATERIALIZATIONS,
            .semantic_instructions = self.semantic.instructions.len,
            .semantic_scratch_elements = self.semantic.scratch.len,
            .field_element_bytes = @sizeOf(M31),
        };
    }

    /// Returns the proposal ordinal for an authenticated semantic `ValueId`.
    pub fn materializationOrdinal(self: *const Executor, value_id: u32) ?u16 {
        return @intCast(validation.indexOf(&self.selected_values, value_id) orelse return null);
    }

    /// Writes one logical (un-bit-reversed) proposal row directly.
    pub fn fillRow(
        self: *Executor,
        destination: *[N_MAIN_COLUMNS]M31,
        call: Call,
    ) ExecutionError!void {
        _ = try self.validateIntegrity();
        try self.preflightWritableRow(destination);

        // No fallible operation is allowed after this point.
        self.evaluate(call.input);
        destination[compat.ENABLER_COLUMN] = M31.one();
        for (self.semantic.input_slots, 0..) |slot, lane| {
            destination[compat.INPUT_START + lane] = self.semantic.scratch[slot];
        }
        for (self.selected_slots, 0..) |slot, ordinal| {
            destination[compat.TEMPORARY_START + ordinal] = self.semantic.scratch[slot];
        }
        destination[compat.WIDE_COLUMN] = M31.fromU64(@intFromBool(call.wide));
        destination[compat.IO_COLUMN] = M31.fromU64(@intFromBool(call.io));
    }

    /// Writes final column-major storage using production's bit-reversal map.
    /// Every digest, shape, and alias check completes before the first byte is
    /// changed; execution and padding allocate nothing.
    pub fn generateMainInto(
        self: *Executor,
        columns: *[N_MAIN_COLUMNS][]M31,
        calls: []const Call,
        log_size: u32,
    ) ExecutionError!void {
        (try self.prepareMain(columns, calls, log_size)).execute();
    }

    /// Authenticates this executor and validates the complete destination,
    /// input, shape, and alias boundary before returning a hot-loop capability.
    pub fn prepareMain(
        self: *Executor,
        columns: *[N_MAIN_COLUMNS][]M31,
        calls: []const Call,
        log_size: u32,
    ) ExecutionError!PreparedMain {
        _ = try self.validateIntegrity();
        const trace_size = try self.preflightColumns(columns, calls, log_size);
        return .{
            .executor = self,
            .columns = columns,
            .calls = calls,
            .log_size = log_size,
            .trace_size = trace_size,
        };
    }

    fn executePreparedMain(self: *Executor, prepared: PreparedMain) void {
        // No fallible operation is allowed after this point.
        std.debug.assert(prepared.executor == self);
        std.debug.assert(prepared.columns[0].len == prepared.trace_size);
        for (prepared.columns) |column| @memset(column, M31.zero());
        for (prepared.calls, 0..) |call, logical_row| {
            self.evaluate(call.input);
            const committed_row = committedRow(logical_row, prepared.log_size);
            prepared.columns[compat.ENABLER_COLUMN][committed_row] = M31.one();
            for (self.semantic.input_slots, 0..) |slot, lane| {
                prepared.columns[compat.INPUT_START + lane][committed_row] =
                    self.semantic.scratch[slot];
            }
            for (self.selected_slots, 0..) |slot, ordinal| {
                prepared.columns[compat.TEMPORARY_START + ordinal][committed_row] =
                    self.semantic.scratch[slot];
            }
            prepared.columns[compat.WIDE_COLUMN][committed_row] =
                M31.fromU64(@intFromBool(call.wide));
            prepared.columns[compat.IO_COLUMN][committed_row] =
                M31.fromU64(@intFromBool(call.io));
        }
    }

    /// Reads the 16 authenticated roots from a proposal-native row.
    pub fn outputs(
        self: *const Executor,
        row: *const [N_MAIN_COLUMNS]M31,
    ) ExecutionError![WIDTH]M31 {
        _ = try self.validateIntegrity();
        var result: [WIDTH]M31 = undefined;
        for (self.root_ordinals, &result) |ordinal, *value| {
            value.* = row[compat.TEMPORARY_START + ordinal];
        }
        return result;
    }

    /// Re-evaluates H-005 and returns expected-minus-committed root values.
    pub fn rootResiduals(
        self: *Executor,
        call: Call,
        row: *const [N_MAIN_COLUMNS]M31,
    ) ExecutionError![WIDTH]M31 {
        _ = try self.validateIntegrity();
        try self.preflightReadableRow(row);
        self.evaluate(call.input);
        var result: [WIDTH]M31 = undefined;
        for (self.root_ordinals, &result) |ordinal, *residual| {
            const index = @as(usize, ordinal);
            residual.* = self.semantic.scratch[self.selected_slots[index]].sub(
                row[compat.TEMPORARY_START + index],
            );
        }
        return result;
    }

    pub fn rootResidualDigest(
        self: *Executor,
        call: Call,
        row: *const [N_MAIN_COLUMNS]M31,
    ) ExecutionError!frontier.Digest {
        const residuals = try self.rootResiduals(call, row);
        return validation.computeRootResidualDigest(self.layout_digest, residuals);
    }

    /// Returns the first mismatch in proposal physical-column order.
    pub fn diagnoseRow(
        self: *Executor,
        call: Call,
        row: *const [N_MAIN_COLUMNS]M31,
    ) ExecutionError!?Failure {
        _ = try self.validateIntegrity();
        try self.preflightReadableRow(row);
        self.evaluate(call.input);

        if (mismatch(M31.one(), row[compat.ENABLER_COLUMN])) return .{
            .column = compat.ENABLER_COLUMN,
            .role = .enabler,
            .expected = M31.one(),
            .actual = row[compat.ENABLER_COLUMN],
        };
        for (self.semantic.input_slots, 0..) |slot, lane| {
            const column = compat.INPUT_START + lane;
            const expected = self.semantic.scratch[slot];
            if (mismatch(expected, row[column])) return .{
                .column = @intCast(column),
                .role = .{ .input = @intCast(lane) },
                .expected = expected,
                .actual = row[column],
            };
        }
        for (self.selected_slots, self.selected_values, 0..) |slot, value_id, ordinal| {
            const column = compat.TEMPORARY_START + ordinal;
            const expected = self.semantic.scratch[slot];
            if (mismatch(expected, row[column])) return .{
                .column = @intCast(column),
                .role = .{ .materialization = .{
                    .ordinal = @intCast(ordinal),
                    .value_id = value_id,
                } },
                .expected = expected,
                .actual = row[column],
            };
        }
        const expected_wide = M31.fromU64(@intFromBool(call.wide));
        if (mismatch(expected_wide, row[compat.WIDE_COLUMN])) return .{
            .column = compat.WIDE_COLUMN,
            .role = .wide,
            .expected = expected_wide,
            .actual = row[compat.WIDE_COLUMN],
        };
        const expected_io = M31.fromU64(@intFromBool(call.io));
        if (mismatch(expected_io, row[compat.IO_COLUMN])) return .{
            .column = compat.IO_COLUMN,
            .role = .io,
            .expected = expected_io,
            .actual = row[compat.IO_COLUMN],
        };
        return null;
    }

    fn validateIntegrity(self: *const Executor) ExecutionError!Identity {
        const semantic_execution_digest = try self.semantic.identityDigest();
        try validation.validateIntegrity(
            self.semantic.identity,
            semantic_execution_digest,
            self.frontier_identity_digest,
            self.cost_model_digest,
            self.cut_digest,
            self.proposal_digest,
            self.layout_digest,
            &self.selected_values,
            &self.selected_slots,
            &self.root_ordinals,
            self.semantic.instructions.len,
        );
        return .{
            .semantic_execution_digest = semantic_execution_digest,
            .frontier_identity_digest = self.frontier_identity_digest,
            .cost_model_digest = self.cost_model_digest,
            .cut_digest = self.cut_digest,
            .proposal_digest = self.proposal_digest,
            .layout_digest = self.layout_digest,
        };
    }

    inline fn evaluate(self: *Executor, input: [WIDTH]u32) void {
        // These are H-005's authenticated instructions and H-005's scratch.
        // This loop is an execution engine over that authority, not a second
        // Poseidon description.
        for (self.semantic.instructions, 0..) |instruction, index| {
            self.semantic.scratch[index] = switch (instruction) {
                .constant => |value| value,
                .input => |lane| M31.fromU64(input[lane]),
                .add => |operands| self.semantic.scratch[operands.lhs].add(
                    self.semantic.scratch[operands.rhs],
                ),
                .sub => |operands| self.semantic.scratch[operands.lhs].sub(
                    self.semantic.scratch[operands.rhs],
                ),
                .mul => |operands| self.semantic.scratch[operands.lhs].mul(
                    self.semantic.scratch[operands.rhs],
                ),
                .neg => |operand| self.semantic.scratch[operand].neg(),
                .select => |selection| if (!self.semantic.scratch[selection.selector].isZero())
                    self.semantic.scratch[selection.when_true]
                else
                    self.semantic.scratch[selection.when_false],
            };
        }
    }

    fn preflightWritableRow(
        self: *const Executor,
        row: *[N_MAIN_COLUMNS]M31,
    ) ExecutionError!void {
        const destination = try objectRange(row);
        const descriptors = try objectRange(self);
        const instructions = try sliceRange(self.semantic.instructions);
        const scratch = try sliceRange(self.semantic.scratch);
        if (destination.overlaps(descriptors) or
            (instructions != null and destination.overlaps(instructions.?)) or
            (scratch != null and destination.overlaps(scratch.?)))
        {
            return error.AliasedDestination;
        }
    }

    fn preflightReadableRow(
        self: *const Executor,
        row: *const [N_MAIN_COLUMNS]M31,
    ) ExecutionError!void {
        const input = try objectRange(row);
        const executor = try objectRange(self);
        const instructions = try sliceRange(self.semantic.instructions);
        const scratch = try sliceRange(self.semantic.scratch);
        if (input.overlaps(executor) or
            (instructions != null and input.overlaps(instructions.?)) or
            (scratch != null and input.overlaps(scratch.?)))
        {
            return error.AliasedInput;
        }
    }

    fn preflightColumns(
        self: *const Executor,
        columns: *const [N_MAIN_COLUMNS][]M31,
        calls: []const Call,
        log_size: u32,
    ) ExecutionError!usize {
        if (log_size >= @bitSizeOf(usize) - 1) return error.InvalidTraceShape;
        const size = @as(usize, 1) << @intCast(log_size);
        if (calls.len > size) return error.InvalidTraceShape;

        var destinations: [N_MAIN_COLUMNS]AddressRange = undefined;
        for (columns, 0..) |column, index| {
            if (column.len != size) return error.InvalidTraceShape;
            destinations[index] = (try sliceRange(column)).?;
        }
        const descriptors = try objectRange(columns);
        const executor = try objectRange(self);
        const instructions = try sliceRange(self.semantic.instructions);
        const scratch = try sliceRange(self.semantic.scratch);
        const call_storage = try sliceRange(calls);

        if (call_storage) |input| {
            if (input.overlaps(descriptors) or input.overlaps(executor) or
                (instructions != null and input.overlaps(instructions.?)) or
                (scratch != null and input.overlaps(scratch.?)))
            {
                return error.AliasedInput;
            }
        }
        for (destinations, 0..) |destination, index| {
            if (destination.overlaps(descriptors) or destination.overlaps(executor) or
                (instructions != null and destination.overlaps(instructions.?)) or
                (scratch != null and destination.overlaps(scratch.?)) or
                (call_storage != null and destination.overlaps(call_storage.?)))
            {
                return if (call_storage != null and
                    destination.overlaps(call_storage.?))
                    error.AliasedInput
                else
                    error.AliasedDestination;
            }
            for (destinations[0..index]) |previous| if (destination.overlaps(previous))
                return error.AliasedDestination;
        }
        return size;
    }
};

fn selectProposal(
    manifest: frontier.Manifest,
    selection: ProposalSelection,
) ConstructionError!frontier.Proposal {
    return switch (selection) {
        .baseline => manifest.baseline,
        .frontier => |ordinal| if (ordinal < manifest.frontier.len)
            manifest.frontier[ordinal]
        else
            error.ProposalNotFound,
    };
}

fn mismatch(expected: M31, actual: M31) bool {
    return expected.toU32() != actual.toU32();
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn sliceRange(values: anytype) ExecutionError!?AddressRange {
    const Slice = @TypeOf(values);
    const info = @typeInfo(Slice);
    if (info != .pointer or info.pointer.size != .slice)
        @compileError("sliceRange requires a slice");
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn objectRange(pointer: anytype) ExecutionError!AddressRange {
    const Pointer = @TypeOf(pointer);
    const info = @typeInfo(Pointer);
    if (info != .pointer or info.pointer.size != .one)
        @compileError("objectRange requires a single-item pointer");
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

comptime {
    if (N_MAIN_COLUMNS != production.N_MAIN_COLUMNS or
        N_MATERIALIZATIONS != production.N_TEMPORARIES or WIDTH != production.WIDTH or
        compat.ENABLER_COLUMN != 0 or compat.INPUT_START != 1 or
        compat.TEMPORARY_START != compat.INPUT_START + WIDTH or
        compat.WIDE_COLUMN != compat.TEMPORARY_START + N_MATERIALIZATIONS or
        compat.IO_COLUMN != compat.WIDE_COLUMN + 1 or N_MAIN_COLUMNS != 445 or
        N_MATERIALIZATIONS != 426)
    {
        @compileError("Poseidon proposal-layout geometry drifted");
    }
}
