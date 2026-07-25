//! Compact mixed-height Cairo trace commitment on resident CUDA storage.
//!
//! Trace writers target their final packed coefficient spans. Each contiguous
//! equal-height cohort is transformed in place and extended into a packed LDE
//! cohort. The shared progressive Blake builder then lifts those cohorts into
//! the tree's maximum leaf domain without a dense max-height expansion.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("../../../backends/cuda/abi/field.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const stages = @import("../../../backends/cuda/runtime/stages/mod.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const commit_tree = @import("../../native_cuda/common/commit_tree.zig");
const resident_plan = @import("resident_plan.zig");
const trace_schedule = @import("trace_schedule.zig");
const trace_types = @import("trace_commit/types.zig");
const geometry_compiler = @import("trace_commit/geometry.zig");
const commit_identity = @import("trace_commit/identity.zig");

pub const production_ready = false;

const NativeOps = struct {
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
};

pub const Cohort = trace_types.Cohort;
pub const WriterSpan = trace_types.WriterSpan;
pub const InputForm = trace_types.InputForm;
pub const Slots = trace_types.Slots;

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    tree_ordinal: u32,
    tree_size: u32,
    input_form: InputForm,
    stage: telemetry.Stage,
    cohorts: []Cohort,
    writer_spans: []WriterSpan,
    column_logs: []u32,
    column_offsets: []u32,
    layers: []field.MerkleLayerDescriptor,
    slots: Slots,
    identity: proof_ir.Digest,

    pub fn initMain(
        allocator: std.mem.Allocator,
        program: proof_ir.ProofProgram,
        plan: resident_plan.Plan,
        schedule: trace_schedule.Schedule,
    ) !Prepared {
        return init(
            allocator,
            program,
            plan,
            .main,
            schedule,
        );
    }

    /// Compiles the same compact resident PCS path for a tree whose
    /// coefficients are produced by a stage controller rather than by the
    /// authenticated base-writer schedule.
    pub fn initProduced(
        allocator: std.mem.Allocator,
        program: proof_ir.ProofProgram,
        plan: resident_plan.Plan,
        role: proof_ir.CommitmentRole,
    ) !Prepared {
        if (role == .main)
            return error.InvalidTraceCommitRole;
        return init(
            allocator,
            program,
            plan,
            role,
            null,
        );
    }

    fn init(
        allocator: std.mem.Allocator,
        program: proof_ir.ProofProgram,
        plan: resident_plan.Plan,
        role: proof_ir.CommitmentRole,
        schedule: ?trace_schedule.Schedule,
    ) !Prepared {
        try program.validate();
        if (std.mem.allEqual(u8, &plan.identity, 0) or
            (schedule != null and
                (std.mem.allEqual(u8, &schedule.?.identity, 0) or
                    schedule.?.entries.len !=
                        trace_schedule.expected_entry_count)))
        {
            return error.InvalidTraceCommitPlan;
        }
        if ((role == .main) != (schedule != null))
            return error.InvalidTraceCommitRole;
        const input_form: InputForm = switch (role) {
            .main, .interaction => .evaluations,
            .preprocessed, .composition => .coefficients,
            .fri => return error.InvalidTraceCommitRole,
        };
        const stage: telemetry.Stage = if (role == .composition)
            .constraint_evaluation
        else
            .trace_commit;
        const located = findTree(program, role) orelse
            return error.InvalidTraceCommitPlan;
        const tree = located.tree;
        const tree_ordinal: u32 = @intCast(located.ordinal);
        const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
        if (role == .main and !mixedHeight(columns))
            return error.TraceCommitTreeNotMixedHeight;

        const geometry = try geometry_compiler.compile(allocator, columns, tree);
        errdefer geometry.deinit(allocator);
        const writers = if (schedule) |writer_schedule|
            try geometry_compiler.compileWriterSpans(
                allocator,
                columns,
                geometry.column_offsets,
                writer_schedule,
            )
        else
            try allocator.alloc(WriterSpan, 0);
        errdefer allocator.free(writers);
        const layers = try merkleLayers(allocator, tree.evaluation_log_rows);
        errdefer allocator.free(layers);
        const tree_size = try pow2u32(tree.evaluation_log_rows);
        const slots = try locateSlots(
            plan,
            tree_ordinal,
            role,
            stage,
            requiresProgressive(geometry.cohorts, tree_size),
        );
        try validateSlotExtents(plan, slots, geometry, layers.len);
        return .{
            .allocator = allocator,
            .tree_ordinal = tree_ordinal,
            .tree_size = tree_size,
            .input_form = input_form,
            .stage = stage,
            .cohorts = geometry.cohorts,
            .writer_spans = writers,
            .column_logs = geometry.column_logs,
            .column_offsets = geometry.column_offsets,
            .layers = layers,
            .slots = slots,
            .identity = commit_identity.compute(
                program,
                plan.identity,
                if (schedule) |writer_schedule|
                    writer_schedule.identity
                else
                    [_]u8{0} ** 32,
                tree_ordinal,
                input_form,
                stage,
                geometry.cohorts,
                writers,
                geometry.column_logs,
                geometry.column_offsets,
                layers,
                slots,
            ),
        };
    }

    pub fn validateMainAuthority(
        self: Prepared,
        program: proof_ir.ProofProgram,
        plan: resident_plan.Plan,
        schedule: trace_schedule.Schedule,
    ) !void {
        try program.validate();
        if (self.tree_ordinal >= program.commitments.len or
            program.commitments[self.tree_ordinal].role != .main or
            self.input_form != .evaluations or
            self.stage != .trace_commit or
            std.mem.allEqual(u8, &plan.identity, 0) or
            std.mem.allEqual(u8, &schedule.identity, 0))
        {
            return error.InvalidTraceCommitAuthority;
        }
        const expected_slots = try locateSlots(
            plan,
            self.tree_ordinal,
            .main,
            self.stage,
            requiresProgressive(self.cohorts, self.tree_size),
        );
        if (!std.meta.eql(expected_slots, self.slots) or
            !std.mem.eql(
                u8,
                &self.identity,
                &commit_identity.compute(
                    program,
                    plan.identity,
                    schedule.identity,
                    self.tree_ordinal,
                    self.input_form,
                    self.stage,
                    self.cohorts,
                    self.writer_spans,
                    self.column_logs,
                    self.column_offsets,
                    self.layers,
                    self.slots,
                ),
            ))
        {
            return error.InvalidTraceCommitAuthority;
        }
    }

    pub fn validateProducedAuthority(
        self: Prepared,
        program: proof_ir.ProofProgram,
        plan: resident_plan.Plan,
        role: proof_ir.CommitmentRole,
    ) !void {
        try program.validate();
        const expected_form: InputForm = switch (role) {
            .interaction => .evaluations,
            .preprocessed, .composition => .coefficients,
            .main, .fri => return error.InvalidTraceCommitRole,
        };
        const expected_stage: telemetry.Stage =
            if (role == .composition)
                .constraint_evaluation
            else
                .trace_commit;
        if (self.tree_ordinal >= program.commitments.len or
            program.commitments[self.tree_ordinal].role != role or
            self.input_form != expected_form or
            self.stage != expected_stage or
            self.writer_spans.len != 0 or
            std.mem.allEqual(u8, &plan.identity, 0))
        {
            return error.InvalidTraceCommitAuthority;
        }
        const expected_slots = try locateSlots(
            plan,
            self.tree_ordinal,
            role,
            self.stage,
            requiresProgressive(self.cohorts, self.tree_size),
        );
        if (!std.meta.eql(expected_slots, self.slots) or
            !std.mem.eql(
                u8,
                &self.identity,
                &commit_identity.compute(
                    program,
                    plan.identity,
                    [_]u8{0} ** 32,
                    self.tree_ordinal,
                    self.input_form,
                    self.stage,
                    self.cohorts,
                    self.writer_spans,
                    self.column_logs,
                    self.column_offsets,
                    self.layers,
                    self.slots,
                ),
            ))
        {
            return error.InvalidTraceCommitAuthority;
        }
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.layers);
        self.allocator.free(self.writer_spans);
        self.allocator.free(self.column_offsets);
        self.allocator.free(self.column_logs);
        self.allocator.free(self.cohorts);
        self.* = undefined;
    }

    pub fn uploadMetadata(
        self: Prepared,
        uploader: anytype,
    ) !void {
        try uploader.upload(u32, self.slots.column_logs, self.column_logs);
        try uploader.upload(u32, self.slots.column_offsets, self.column_offsets);
        try uploader.upload(
            field.MerkleLayerDescriptor,
            self.slots.merkle_layers,
            self.layers,
        );
    }
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    prepared: *const Prepared,
    coefficients: common.Words,
    evaluations: common.Words,
    column_logs: common.Words,
    merkle_hashes: common.Hashes,
    merkle_layers: common.MerkleLayers,
    progressive_states: ?common.ProgressiveStates,
    root: common.Hashes,
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
    lifted_segments: []commit_tree.LiftedSegment,
    base_evaluations_materialized: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const Prepared,
        provider: anytype,
    ) !Bound {
        if (std.mem.allEqual(u8, &prepared.identity, 0))
            return error.InvalidTraceCommitPlan;
        const coefficients = try exactWords(
            provider,
            prepared.slots.coefficients,
            totalCohortWords(prepared.cohorts, false),
        );
        const evaluations = try exactWords(
            provider,
            prepared.slots.evaluations,
            totalCohortWords(prepared.cohorts, true),
        );
        const segments = try allocator.alloc(
            commit_tree.LiftedSegment,
            prepared.cohorts.len,
        );
        errdefer allocator.free(segments);
        for (prepared.cohorts, segments) |cohort, *segment| {
            segment.* = .{
                .columns = .{
                    .storage = try evaluations.sub(
                        cohort.evaluation_offset_words,
                        cohort.evaluation_words,
                    ),
                    .column_stride_words = @as(usize, 1) << @intCast(cohort.evaluation_log_rows),
                },
                .source_size = try pow2u32(cohort.evaluation_log_rows),
            };
        }
        return .{
            .allocator = allocator,
            .prepared = prepared,
            .coefficients = coefficients,
            .evaluations = evaluations,
            .column_logs = try exactWords(
                provider,
                prepared.slots.column_logs,
                prepared.column_logs.len,
            ),
            .merkle_hashes = try exactAs(
                provider,
                field.Blake2sHash,
                prepared.slots.merkle_hashes,
                try merkleHashCount(prepared.tree_size),
            ),
            .merkle_layers = try exactAs(
                provider,
                field.MerkleLayerDescriptor,
                prepared.slots.merkle_layers,
                prepared.layers.len,
            ),
            .progressive_states = if (prepared.slots.progressive_states) |slot| try prefixAs(
                provider,
                field.ProgressiveBlake2sState,
                slot,
                prepared.tree_size,
            ) else null,
            .root = try exactAs(
                provider,
                field.Blake2sHash,
                prepared.slots.root,
                1,
            ),
            .twiddles_forward = try prefixWords(
                provider,
                prepared.slots.twiddles_forward,
                prepared.tree_size / 2,
            ),
            .twiddles_inverse = try prefixWords(
                provider,
                prepared.slots.twiddles_inverse,
                prepared.tree_size / 2,
            ),
            .lifted_segments = segments,
        };
    }

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.lifted_segments);
        self.* = undefined;
    }

    /// Final resident destination for one authenticated base writer.
    pub fn writerOutput(
        self: Bound,
        schedule_ordinal: u32,
    ) !common.WordMatrix {
        for (self.prepared.writer_spans) |span| {
            if (span.schedule_ordinal != schedule_ordinal) continue;
            return .{
                .storage = try self.coefficients.sub(
                    span.coefficient_offset_words,
                    span.coefficient_words,
                ),
                .column_stride_words = @as(usize, 1) << @intCast(span.trace_log_rows),
            };
        }
        return error.UnknownTraceWriter;
    }

    pub fn execute(
        self: *Bound,
        session: anytype,
    ) !void {
        return self.executeWith(NativeOps, session);
    }

    /// Materializes compact base-domain evaluations before trace generation.
    /// Fixed-table writers consume these immutable preprocessed columns. The
    /// compact image occupies the front of each already allocated LDE cohort;
    /// trace commitment later overwrites it with the full extended domain.
    pub fn materializeBaseEvaluations(
        self: *Bound,
        session: anytype,
        stage: telemetry.Stage,
    ) !void {
        if (self.prepared.input_form != .coefficients or
            self.base_evaluations_materialized)
        {
            return error.InvalidTraceCommitState;
        }
        for (self.prepared.cohorts) |cohort| {
            try NativeOps.Transform.extend(
                session,
                stage,
                .{
                    .storage = try self.coefficients.sub(
                        cohort.coefficient_offset_words,
                        cohort.coefficient_words,
                    ),
                    .column_stride_words = @as(usize, 1) << @intCast(cohort.trace_log_rows),
                },
                try self.column_logs.sub(
                    cohort.first_column,
                    cohort.column_count,
                ),
                .{
                    .storage = try self.evaluations.sub(
                        cohort.evaluation_offset_words,
                        cohort.coefficient_words,
                    ),
                    .column_stride_words = @as(usize, 1) << @intCast(cohort.trace_log_rows),
                },
                cohort.trace_log_rows,
                self.twiddles_forward,
                false,
            );
        }
        self.base_evaluations_materialized = true;
    }

    pub fn preprocessedBaseEvaluation(
        self: Bound,
        column_ordinal: u32,
    ) !common.Words {
        if (!self.base_evaluations_materialized)
            return error.InvalidTraceCommitState;
        for (self.prepared.cohorts) |cohort| {
            const end = std.math.add(
                u32,
                cohort.first_column,
                cohort.column_count,
            ) catch return error.InvalidTraceCommitPlan;
            if (column_ordinal < cohort.first_column or
                column_ordinal >= end)
            {
                continue;
            }
            const stride =
                @as(usize, 1) << @intCast(cohort.trace_log_rows);
            const local = column_ordinal - cohort.first_column;
            const offset = std.math.add(
                usize,
                cohort.evaluation_offset_words,
                std.math.mul(
                    usize,
                    local,
                    stride,
                ) catch return error.InvalidTraceCommitPlan,
            ) catch return error.InvalidTraceCommitPlan;
            return self.evaluations.sub(offset, stride);
        }
        return error.InvalidTraceCommitPlan;
    }

    pub fn executeWith(
        self: *Bound,
        comptime Ops: type,
        session: anytype,
    ) !void {
        for (self.prepared.cohorts) |cohort| {
            const coefficients = common.WordMatrix{
                .storage = try self.coefficients.sub(
                    cohort.coefficient_offset_words,
                    cohort.coefficient_words,
                ),
                .column_stride_words = @as(usize, 1) << @intCast(cohort.trace_log_rows),
            };
            const evaluations = common.WordMatrix{
                .storage = try self.evaluations.sub(
                    cohort.evaluation_offset_words,
                    cohort.evaluation_words,
                ),
                .column_stride_words = @as(usize, 1) << @intCast(cohort.evaluation_log_rows),
            };
            const logs = try self.column_logs.sub(
                cohort.first_column,
                cohort.column_count,
            );
            if (self.prepared.input_form == .evaluations) {
                try Ops.Transform.inverseCompact(
                    session,
                    self.prepared.stage,
                    coefficients,
                    coefficients,
                    cohort.trace_log_rows,
                    self.twiddles_inverse,
                );
            }
            try Ops.Transform.extend(
                session,
                self.prepared.stage,
                coefficients,
                logs,
                evaluations,
                cohort.evaluation_log_rows,
                self.twiddles_forward,
                false,
            );
        }
        const Builder = commit_tree.BuilderFor(Ops.Commitment);
        const root = if (self.progressive_states) |states|
            try Builder.baseFieldLiftedSegmented(
                session,
                self.prepared.stage,
                self.prepared.tree_size,
                self.lifted_segments,
                states,
                self.merkle_hashes,
                self.prepared.layers,
            )
        else
            try Builder.baseField(
                session,
                self.prepared.stage,
                self.prepared.tree_size,
                .{
                    .storage = self.evaluations,
                    .column_stride_words = self.prepared.tree_size,
                },
                self.merkle_hashes,
                self.prepared.layers,
            );
        try session.context.copyDeviceSlice(u32, try self.root.cast(u32), try root.cast(u32));
    }
};

fn locateSlots(
    plan: resident_plan.Plan,
    ordinal: u32,
    role: proof_ir.CommitmentRole,
    stage: telemetry.Stage,
    needs_progressive: bool,
) !Slots {
    return .{
        .coefficients = try slotId(
            plan,
            if (role == .composition)
                .constraint_composition_output
            else
                .trace_coefficients,
            ordinal,
        ),
        .evaluations = try slotId(plan, .trace_evaluations, ordinal),
        .column_logs = try slotId(plan, .trace_column_logs, ordinal),
        .column_offsets = try slotId(plan, .trace_column_offsets, ordinal),
        .merkle_hashes = try slotId(plan, .trace_merkle_hashes, ordinal),
        .merkle_layers = try slotId(plan, .trace_merkle_layers, ordinal),
        .progressive_states = if (needs_progressive)
            try slotId(
                plan,
                .trace_progressive_states,
                if (stage == .constraint_evaluation) 1 else 0,
            )
        else
            null,
        .root = try slotId(plan, .trace_root, ordinal),
        .twiddles_forward = try slotId(plan, .twiddles_forward, 0),
        .twiddles_inverse = try slotId(plan, .twiddles_inverse, 0),
    };
}

fn validateSlotExtents(
    plan: resident_plan.Plan,
    slots: Slots,
    geometry: geometry_compiler.Geometry,
    layer_count: usize,
) !void {
    try exactSlot(plan, slots.coefficients, totalCohortWords(geometry.cohorts, false));
    try exactSlot(plan, slots.evaluations, totalCohortWords(geometry.cohorts, true));
    try exactSlot(plan, slots.column_logs, geometry.column_logs.len);
    try exactSlot(plan, slots.column_offsets, geometry.column_offsets.len);
    try exactSlot(
        plan,
        slots.merkle_layers,
        try mul(layer_count, @sizeOf(field.MerkleLayerDescriptor) / @sizeOf(u32)),
    );
    try exactSlot(plan, slots.root, @sizeOf(field.Blake2sHash) / @sizeOf(u32));
}

fn merkleLayers(
    allocator: std.mem.Allocator,
    log_rows: u32,
) ![]field.MerkleLayerDescriptor {
    const output = try allocator.alloc(
        field.MerkleLayerDescriptor,
        @as(usize, log_rows) + 1,
    );
    var count = try pow2usize(log_rows);
    var offset: usize = 0;
    for (output) |*layer| {
        layer.* = .{
            .offset_hashes = offset,
            .hash_count = @intCast(count),
        };
        offset = try add(offset, count);
        count = @max(count / 2, 1);
    }
    return output;
}

fn findTree(
    program: proof_ir.ProofProgram,
    role: proof_ir.CommitmentRole,
) ?struct { ordinal: usize, tree: proof_ir.CommitmentTree } {
    for (program.commitments, 0..) |tree, ordinal| {
        if (tree.role == role) return .{ .ordinal = ordinal, .tree = tree };
    }
    return null;
}

fn mixedHeight(columns: []const proof_ir.TraceColumn) bool {
    if (columns.len < 2) return false;
    for (columns[1..]) |trace_column| {
        if (trace_column.log_rows != columns[0].log_rows) return true;
    }
    return false;
}

fn requiresProgressive(
    cohorts: []const Cohort,
    tree_size: u32,
) bool {
    return cohorts.len != 1 or
        (@as(u64, 1) << @intCast(
            cohorts[0].evaluation_log_rows,
        )) != tree_size;
}

fn slotId(
    plan: resident_plan.Plan,
    kind: resident_plan.SlotKind,
    ordinal: u32,
) !u32 {
    return (plan.slot(kind, ordinal) orelse
        return error.MissingResidentSlot).id;
}

fn exactSlot(plan: resident_plan.Plan, id: u32, words: usize) !void {
    for (plan.slots) |slot| {
        if (slot.id != id) continue;
        if (slot.words != words) return error.InvalidResidentSlotExtent;
        return;
    }
    return error.MissingResidentSlot;
}

fn exactWords(provider: anytype, id: u32, words: usize) !common.Words {
    const output = try provider.slot(id);
    if (output.len != words) return error.InvalidResidentSlotExtent;
    return output;
}

fn prefixWords(provider: anytype, id: u32, words: usize) !common.Words {
    const output = try provider.slot(id);
    if (output.len < words) return error.InvalidResidentSlotExtent;
    return output.sub(0, words);
}

fn exactAs(
    provider: anytype,
    comptime F: type,
    id: u32,
    count: usize,
) !column.DeviceSlice(F) {
    const words = try exactWords(
        provider,
        id,
        try mul(count, @sizeOf(F) / @sizeOf(u32)),
    );
    const output = try words.cast(F);
    if (output.len != count) return error.InvalidResidentSlotExtent;
    return output;
}

fn prefixAs(
    provider: anytype,
    comptime F: type,
    id: u32,
    count: usize,
) !column.DeviceSlice(F) {
    const words = try prefixWords(
        provider,
        id,
        try mul(count, @sizeOf(F) / @sizeOf(u32)),
    );
    const output = try words.cast(F);
    if (output.len != count) return error.InvalidResidentSlotExtent;
    return output;
}

fn totalCohortWords(cohorts: []const Cohort, evaluations: bool) usize {
    if (cohorts.len == 0) return 0;
    const last = cohorts[cohorts.len - 1];
    return if (evaluations)
        last.evaluation_offset_words + last.evaluation_words
    else
        last.coefficient_offset_words + last.coefficient_words;
}

fn merkleHashCount(tree_size: u32) !usize {
    return std.math.sub(
        usize,
        try mul(tree_size, 2),
        1,
    ) catch error.TraceCommitGeometryOverflow;
}

fn pow2usize(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.TraceCommitGeometryOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn pow2u32(log_rows: u32) !u32 {
    if (log_rows >= 32) return error.TraceCommitGeometryOverflow;
    return @as(u32, 1) << @intCast(log_rows);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch
        error.TraceCommitGeometryOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.TraceCommitGeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.TraceCommitGeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch
        error.TraceCommitGeometryOverflow;
}

test "mixed geometry stays compact and preserves canonical cohort order" {
    const columns = [_]proof_ir.TraceColumn{
        .{ .id = 0, .component = 0, .ordinal = 0, .log_rows = 3, .role = .main },
        .{ .id = 1, .component = 0, .ordinal = 1, .log_rows = 3, .role = .main },
        .{ .id = 2, .component = 1, .ordinal = 0, .log_rows = 2, .role = .main },
        .{ .id = 3, .component = 2, .ordinal = 0, .log_rows = 4, .role = .main },
    };
    const tree = proof_ir.CommitmentTree{
        .id = 1,
        .role = .main,
        .first_column = 0,
        .column_count = columns.len,
        .evaluation_log_rows = 5,
        .log_rows_per_leaf = 5,
        .retain_openings = true,
    };
    const geometry = try geometry_compiler.compile(
        std.testing.allocator,
        &columns,
        tree,
    );
    defer geometry.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), geometry.cohorts.len);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0, 8, 16, 20, 36 },
        geometry.column_offsets,
    );
    try std.testing.expectEqual(@as(usize, 36), totalCohortWords(geometry.cohorts, false));
    try std.testing.expectEqual(@as(usize, 72), totalCohortWords(geometry.cohorts, true));
    try std.testing.expectEqual(@as(u32, 3), geometry.cohorts[0].trace_log_rows);
    try std.testing.expectEqual(@as(u32, 2), geometry.cohorts[1].trace_log_rows);
    try std.testing.expectEqual(@as(u32, 4), geometry.cohorts[2].trace_log_rows);
}
