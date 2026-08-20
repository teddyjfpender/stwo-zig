//! Source-exact interaction layout for Stark-V framework components.
//!
//! `relation_interaction.zig` authenticates and evaluates the typed relation
//! DAG. This module owns the distinct commitment geometry used by the pinned
//! constraint framework:
//!
//! * every non-final secure column is the same-row cumulative sum of relation
//!   batches seen so far;
//! * the final secure column is the inclusive cross-row prefix of the sum of
//!   every batch, after subtracting `claimed_sum / trace_size` on every row.
//!
//! The compatibility generator performs exactly two allocations: one reusable
//! `[numerator | cumulative | inverse]` workspace and one final M31 commitment
//! slab. Callers which retain `Runtime.Workspace` and own their destination
//! columns use `generatePreparedInto`, whose hot path is allocation free. All
//! fallible relation evaluation, inversion, claim computation, and prefix
//! closure checks complete before the first destination cell is written.

const std = @import("std");
const stwo_core = @import("stwo_core");
const fields = stwo_core.fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const utils = stwo_core.utils;
const logup = @import("../../air/logup.zig");
const universal = @import("universal_challenges.zig");

pub const Error = std.mem.Allocator.Error || universal.Error || QM31.Error || error{
    InteractionColumnMismatch,
    InteractionGeometryMismatch,
    InvalidTraceShape,
    ClaimMismatch,
    PrefixClosureMismatch,
    DestinationAlias,
    WorkspaceCapacityMismatch,
    ZeroDenominator,
};

/// Instantiates the framework trace writer for one authenticated relation
/// runtime from `relation_interaction.Runtime`.
pub fn Runtime(comptime RelationRuntime: type) type {
    comptime {
        if (RelationRuntime.BATCH_COUNT == 0)
            @compileError("framework LogUp requires at least one batch");
        if (RelationRuntime.INTERACTION_COLUMN_COUNT !=
            4 * RelationRuntime.BATCH_COUNT)
        {
            @compileError("framework LogUp secure-column geometry drifted");
        }
    }

    return struct {
        const Self = @This();

        pub const BATCH_COUNT = RelationRuntime.BATCH_COUNT;
        pub const INTERACTION_COLUMN_COUNT = 4 * BATCH_COUNT;
        pub const Row = RelationRuntime.Row;
        pub const Plan = RelationRuntime.Plan;

        pub const Interaction = struct {
            columns: [INTERACTION_COLUMN_COUNT][]M31,
            claimed_sum: QM31,
            storage: []M31,

            pub fn deinit(
                self: *Interaction,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.storage);
                self.* = undefined;
            }
        };

        /// Exact decomposition of one generated component claim by universal
        /// relation domain. The audited generator below derives this from the
        /// same inverse plane as the committed interaction, so asking for
        /// custody evidence does not add another batch inversion.
        pub const DomainClaims = struct {
            claimed_sum: QM31,
            by_domain: [universal.RELATION_COUNT]QM31,
        };

        /// Worker-private reusable inversion and commit-preparation storage.
        /// A workspace may serve any trace no larger than `capacity_log_size`;
        /// its exact allocation geometry is validated on every public entry.
        pub const Workspace = struct {
            allocator: std.mem.Allocator,
            capacity_log_size: u32,
            scratch: []QM31,

            pub fn init(
                allocator: std.mem.Allocator,
                capacity_log_size: u32,
            ) Error!Workspace {
                const scratch_count = try requiredScratchElementCount(
                    capacity_log_size,
                );
                return .{
                    .allocator = allocator,
                    .capacity_log_size = capacity_log_size,
                    .scratch = try allocator.alloc(QM31, scratch_count),
                };
            }

            pub fn deinit(self: *Workspace) void {
                self.allocator.free(self.scratch);
                self.* = undefined;
            }

            fn validateFor(self: *const Workspace, log_size: u32) Error!void {
                const capacity_count = try requiredScratchElementCount(
                    self.capacity_log_size,
                );
                const required_count = try requiredScratchElementCount(log_size);
                if (self.scratch.len != capacity_count or
                    log_size > self.capacity_log_size or
                    self.scratch.len < required_count)
                {
                    return error.WorkspaceCapacityMismatch;
                }
            }
        };

        /// Canonical workspace geometry for this relation runtime. Keeping the
        /// arithmetic here prevents allocating and caller-owned paths from
        /// silently disagreeing about scratch layout.
        pub fn requiredScratchElementCount(log_size: u32) Error!usize {
            const size = try traceSize(log_size);
            const term_count = std.math.mul(usize, BATCH_COUNT, size) catch
                return error.InvalidTraceShape;
            return std.math.mul(usize, term_count, 3) catch
                return error.InvalidTraceShape;
        }

        /// Canonical contiguous output geometry for one interaction trace.
        pub fn requiredStorageElementCount(log_size: u32) Error!usize {
            return std.math.mul(
                usize,
                INTERACTION_COLUMN_COUNT,
                try traceSize(log_size),
            ) catch return error.InvalidTraceShape;
        }

        /// Generates the pinned framework layout from a plan and challenge
        /// bundle authenticated once at component construction.
        pub fn generatePrepared(
            allocator: std.mem.Allocator,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
        ) Error!Interaction {
            const size = try traceSize(log_size);
            const storage_len = try requiredStorageElementCount(log_size);
            const storage = try allocator.alloc(M31, storage_len);
            errdefer allocator.free(storage);
            var columns: [INTERACTION_COLUMN_COUNT][]M31 = undefined;
            for (&columns, 0..) |*column, index|
                column.* = storage[index * size ..][0..size];
            var workspace = try Workspace.init(allocator, log_size);
            defer workspace.deinit();
            const claimed_sum = try generatePreparedInto(
                &workspace,
                plan,
                rows,
                log_size,
                relations,
                &columns,
            );
            return .{
                .columns = columns,
                .claimed_sum = claimed_sum,
                .storage = storage,
            };
        }

        /// Generates directly into caller-owned columns using retained
        /// workspace. Destination shape and all relevant memory ranges are
        /// admitted before scratch or output mutation. The destination remains
        /// byte-for-byte unchanged on every returned error.
        pub fn generatePreparedInto(
            workspace: *Workspace,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            destination: *[INTERACTION_COLUMN_COUNT][]M31,
        ) Error!QM31 {
            return (try generatePreparedIntoInternal(
                false,
                workspace,
                plan,
                rows,
                log_size,
                relations,
                destination,
            )).claimed_sum;
        }

        /// Generates the same pinned interaction while returning exact
        /// per-domain claims. This is the allocation-free soundness path for
        /// mixed-domain batches: it replays the already-authenticated row plan
        /// after the single bulk inversion and attributes each paired term
        /// with that retained inverse. All checks still precede trace writes.
        pub fn generatePreparedIntoWithDomainSums(
            workspace: *Workspace,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            destination: *[INTERACTION_COLUMN_COUNT][]M31,
        ) Error!DomainClaims {
            return generatePreparedIntoInternal(
                true,
                workspace,
                plan,
                rows,
                log_size,
                relations,
                destination,
            );
        }

        fn generatePreparedIntoInternal(
            comptime decompose_domains: bool,
            workspace: *Workspace,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            destination: *[INTERACTION_COLUMN_COUNT][]M31,
        ) Error!DomainClaims {
            try relations.validate();
            const size = try traceSize(log_size);
            if (rows.len > size) return error.InvalidTraceShape;
            try workspace.validateFor(log_size);
            try validateMemoryContract(
                workspace,
                plan,
                rows,
                relations,
                destination,
                size,
            );

            const term_count = std.math.mul(usize, BATCH_COUNT, size) catch
                return error.InvalidTraceShape;
            const scratch_count = try requiredScratchElementCount(log_size);
            const scratch = workspace.scratch[0..scratch_count];
            const numerators = scratch[0..term_count];
            const cumulative = scratch[term_count .. 2 * term_count];
            const inverses = scratch[2 * term_count .. 3 * term_count];

            for (0..size) |logical_row| {
                const pairs = if (logical_row < rows.len)
                    try plan.preparedRowPairs(rows[logical_row], relations)
                else
                    paddingPairs();
                for (pairs, 0..) |pair, batch| {
                    const index = batch * size + logical_row;
                    numerators[index] = pair.n1.mul(pair.d2)
                        .add(pair.n2.mul(pair.d1));
                    cumulative[index] = pair.d1.mul(pair.d2);
                }
            }
            fields.batchInverseInPlace(QM31, cumulative, inverses) catch
                return error.ZeroDenominator;

            var claimed_sum = QM31.zero();
            var by_domain = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
            for (0..size) |logical_row| {
                var within_row = QM31.zero();
                for (0..BATCH_COUNT) |batch| {
                    const index = batch * size + logical_row;
                    within_row = within_row.add(
                        numerators[index].mul(inverses[index]),
                    );
                    // Denominators are dead after the one bulk inversion. Keep
                    // every same-row cumulative value here until commit.
                    cumulative[index] = within_row;
                }
                claimed_sum = claimed_sum.add(within_row);

                if (comptime decompose_domains) {
                    const pairs = if (logical_row < rows.len)
                        try plan.preparedRowPairs(rows[logical_row], relations)
                    else
                        paddingPairs();
                    for (pairs, plan.batches, 0..) |pair, batch_plan, batch| {
                        const inverse = inverses[batch * size + logical_row];
                        const first_domain = @intFromEnum(
                            plan.events[batch_plan.first].domain,
                        );
                        by_domain[first_domain] = by_domain[first_domain].add(
                            pair.n1.mul(pair.d2).mul(inverse),
                        );
                        if (batch_plan.second) |second| {
                            const second_domain = @intFromEnum(
                                plan.events[second].domain,
                            );
                            by_domain[second_domain] = by_domain[second_domain].add(
                                pair.n2.mul(pair.d1).mul(inverse),
                            );
                        }
                    }
                }
            }

            if (comptime decompose_domains) {
                var decomposed_sum = QM31.zero();
                for (by_domain) |domain_claim|
                    decomposed_sum = decomposed_sum.add(domain_claim);
                if (!decomposed_sum.eql(claimed_sum))
                    return error.ClaimMismatch;
            }

            const shift = try claimed_sum.divM31(M31.fromU64(size));
            var prefix = QM31.zero();
            for (0..size) |logical_row| {
                const final_index = (BATCH_COUNT - 1) * size + logical_row;
                prefix = prefix.add(cumulative[final_index]).sub(shift);
                // The first numerator plane is dead and has exactly one slot
                // per logical row, so it retains the checked final prefix.
                numerators[logical_row] = prefix;
            }
            if (!prefix.isZero()) return error.PrefixClosureMismatch;

            // Infallible commit: every possible error above precedes this loop.
            for (0..size) |logical_row| {
                const committed_row = committedRow(logical_row, log_size);
                for (0..BATCH_COUNT - 1) |batch| {
                    writeSecure(
                        destination,
                        batch,
                        committed_row,
                        cumulative[batch * size + logical_row],
                    );
                }
                writeSecure(
                    destination,
                    BATCH_COUNT - 1,
                    committed_row,
                    numerators[logical_row],
                );
            }
            return .{
                .claimed_sum = claimed_sum,
                .by_domain = by_domain,
            };
        }

        fn validateMemoryContract(
            workspace: *const Workspace,
            plan: *const Plan,
            rows: []const Row,
            relations: *const universal.UniversalRelations,
            destination: *const [INTERACTION_COLUMN_COUNT][]M31,
            size: usize,
        ) Error!void {
            const workspace_header = std.mem.asBytes(workspace);
            const destination_header = std.mem.asBytes(destination);
            const plan_bytes = std.mem.asBytes(plan);
            const relation_bytes = std.mem.asBytes(relations);

            if (try slicesOverlap(QM31, workspace.scratch, Row, rows) or
                try slicesOverlap(QM31, workspace.scratch, u8, workspace_header) or
                try slicesOverlap(QM31, workspace.scratch, u8, destination_header) or
                try slicesOverlap(QM31, workspace.scratch, u8, plan_bytes) or
                try slicesOverlap(QM31, workspace.scratch, u8, relation_bytes))
            {
                return error.DestinationAlias;
            }

            for (destination, 0..) |current, index| {
                if (current.len != size)
                    return error.InteractionGeometryMismatch;
                if (try slicesOverlap(M31, current, QM31, workspace.scratch) or
                    try slicesOverlap(M31, current, Row, rows) or
                    try slicesOverlap(M31, current, u8, workspace_header) or
                    try slicesOverlap(M31, current, u8, destination_header) or
                    try slicesOverlap(M31, current, u8, plan_bytes) or
                    try slicesOverlap(M31, current, u8, relation_bytes))
                {
                    return error.DestinationAlias;
                }
                for (destination[0..index]) |prior| {
                    if (try slicesOverlap(M31, current, M31, prior))
                        return error.DestinationAlias;
                }
            }
        }

        /// Cold mutation/admission check. Production hot paths call
        /// `generatePrepared` only after authenticating the plan itself.
        pub fn validatePrepared(
            allocator: std.mem.Allocator,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            actual: *const Interaction,
        ) Error!void {
            const size = try traceSize(log_size);
            const storage_len = std.math.mul(
                usize,
                INTERACTION_COLUMN_COUNT,
                size,
            ) catch return error.InvalidTraceShape;
            if (actual.storage.len != storage_len)
                return error.InteractionGeometryMismatch;
            for (actual.columns) |column| if (column.len != size)
                return error.InteractionGeometryMismatch;

            var expected = try generatePrepared(
                allocator,
                plan,
                rows,
                log_size,
                relations,
            );
            defer expected.deinit(allocator);
            if (!actual.claimed_sum.eql(expected.claimed_sum))
                return error.ClaimMismatch;
            for (actual.columns, expected.columns) |got, wanted| {
                for (got, wanted) |got_value, wanted_value| {
                    if (!got_value.eql(wanted_value))
                        return error.InteractionColumnMismatch;
                }
            }
        }

        fn paddingPairs() [BATCH_COUNT]logup.RowPair {
            return [_]logup.RowPair{.{
                .n1 = QM31.zero(),
                .d1 = QM31.one(),
                .n2 = QM31.zero(),
                .d2 = QM31.one(),
            }} ** BATCH_COUNT;
        }
    };
}

inline fn writeSecure(
    columns: anytype,
    secure_column: usize,
    row: usize,
    value: QM31,
) void {
    const coordinates = value.toM31Array();
    for (coordinates, 0..) |coordinate, coordinate_index| {
        columns[secure_column * 4 + coordinate_index][row] = coordinate;
    }
}

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return utils.bitReverseIndex(
        utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

fn traceSize(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize) or log_size >= 31)
        return error.InvalidTraceShape;
    return @as(usize, 1) << @intCast(log_size);
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn slicesOverlap(
    comptime Left: type,
    left: []const Left,
    comptime Right: type,
    right: []const Right,
) Error!bool {
    if (left.len == 0 or right.len == 0) return false;
    return (try sliceRange(Left, left)).overlaps(try sliceRange(Right, right));
}

fn sliceRange(comptime T: type, values: []const T) Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.InvalidTraceShape;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.InvalidTraceShape,
    };
}

test "R-012 framework interaction is source-exact, two-allocation, and failure atomic" {
    const std_testing = std.testing;
    const control = @import("control.zig");
    const control_relation = @import("control_relation.zig");
    const control_witness = @import("control_witness.zig");
    const proof_kind = @import("proof_kind.zig");

    var definition = try control.build(std_testing.allocator);
    defer definition.deinit();
    const plan = try control_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const rows = [_]control_relation.Row{
        control_witness.logicalRow(.{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 0,
            .tag = 7,
            .args = .{ 11, 13, 17, 19 },
            .terminal_mask = 0,
        }, proof_kind.ProofKind.segment_leaf),
        control_witness.logicalRow(.{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 1,
            .tag = 23,
            .args = .{ 29, 31, 37, 41 },
            .terminal_mask = 1,
        }, proof_kind.ProofKind.segment_leaf),
    };
    const Framework = Runtime(control_relation.Runtime);

    var measured = std_testing.FailingAllocator.init(std_testing.allocator, .{});
    {
        var generated = try Framework.generatePrepared(
            measured.allocator(),
            &plan,
            &rows,
            4,
            &relations,
        );
        defer generated.deinit(measured.allocator());
        try std_testing.expectEqual(@as(usize, 2), measured.alloc_index);
        try Framework.validatePrepared(
            std_testing.allocator,
            &plan,
            &rows,
            4,
            &relations,
            &generated,
        );

        // Non-final columns are same-row partial sums. The final column is the
        // shifted prefix and therefore closes to zero on the final logical row.
        const first_pairs = try plan.preparedRowPairs(rows[0], &relations);
        const first_expected = try pairValue(first_pairs[0]);
        try std_testing.expect(secureAt(
            &generated.columns,
            0,
            committedRow(0, 4),
        ).eql(first_expected));
        try std_testing.expect(secureAt(
            &generated.columns,
            Framework.BATCH_COUNT - 1,
            committedRow(15, 4),
        ).isZero());

        generated.columns[0][committedRow(0, 4)] =
            generated.columns[0][committedRow(0, 4)].add(M31.one());
        try std_testing.expectError(
            error.InteractionColumnMismatch,
            Framework.validatePrepared(
                std_testing.allocator,
                &plan,
                &rows,
                4,
                &relations,
                &generated,
            ),
        );
    }
    try std_testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std_testing.checkAllAllocationFailures(
        std_testing.allocator,
        frameworkFailureCase,
        .{ &plan, &rows, &relations },
    );
}

test "R-012 framework workspace is equivalent, zero-allocation, fail-atomic, and alias-safe" {
    const std_testing = std.testing;
    const control = @import("control.zig");
    const control_relation = @import("control_relation.zig");
    const control_witness = @import("control_witness.zig");
    const proof_kind = @import("proof_kind.zig");
    const Framework = Runtime(control_relation.Runtime);
    const log_size: u32 = 4;
    const size: usize = 1 << log_size;

    var definition = try control.build(std_testing.allocator);
    defer definition.deinit();
    const plan = try control_relation.authenticate(&definition);
    var relations = universal.UniversalRelations.dummy();
    const rows = [_]control_relation.Row{
        control_witness.logicalRow(.{
            .segment_mask = 0,
            .binary_mask = 1,
            .verifier_id = 1,
            .sequence = 0,
            .tag = 43,
            .args = .{ 47, 53, 59, 61 },
            .terminal_mask = 0,
        }, proof_kind.ProofKind.binary_node),
        control_witness.logicalRow(.{
            .segment_mask = 0,
            .binary_mask = 1,
            .verifier_id = 1,
            .sequence = 1,
            .tag = 67,
            .args = .{ 71, 73, 79, 83 },
            .terminal_mask = 1,
        }, proof_kind.ProofKind.binary_node),
    };

    var expected = try Framework.generatePrepared(
        std_testing.allocator,
        &plan,
        &rows,
        log_size,
        &relations,
    );
    defer expected.deinit(std_testing.allocator);

    var fixed_storage: [64 * 1024]u8 align(@alignOf(QM31)) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&fixed_storage);
    var workspace = try Framework.Workspace.init(fixed.allocator(), log_size);
    defer workspace.deinit();

    const sentinel = M31.fromCanonical(0x5a5a);
    var output = [_]M31{sentinel} ** (Framework.INTERACTION_COLUMN_COUNT * size);
    var columns: [Framework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = output[index * size ..][0..size];

    const allocation_cursor = fixed.end_index;
    const actual_claim = try Framework.generatePreparedInto(
        &workspace,
        &plan,
        &rows,
        log_size,
        &relations,
        &columns,
    );
    try std_testing.expectEqual(allocation_cursor, fixed.end_index);
    try std_testing.expect(actual_claim.eql(expected.claimed_sum));
    try std_testing.expectEqualSlices(M31, expected.storage, &output);

    // A second proof reuses the same scratch without growing the allocator.
    @memset(&output, sentinel);
    const second_claim = try Framework.generatePreparedInto(
        &workspace,
        &plan,
        &rows,
        log_size,
        &relations,
        &columns,
    );
    try std_testing.expectEqual(allocation_cursor, fixed.end_index);
    try std_testing.expect(second_claim.eql(expected.claimed_sum));
    try std_testing.expectEqualSlices(M31, expected.storage, &output);

    // Force a denominator to zero only after row evaluation has begun. The
    // full caller destination must retain its exact pre-call bytes.
    const first_pairs = try plan.preparedRowPairs(rows[0], &relations);
    const first_domain = @intFromEnum(plan.events[plan.batches[0].first].domain);
    relations.elements[first_domain].z = relations.elements[first_domain].z.add(
        first_pairs[0].d1,
    );
    @memset(&output, sentinel);
    try std_testing.expectError(
        error.ZeroDenominator,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    try std_testing.expectEqualSlices(
        M31,
        &([_]M31{sentinel} ** output.len),
        &output,
    );
    relations = universal.UniversalRelations.dummy();

    // Pairwise destination overlap is rejected before scratch or output work.
    const second_column = columns[1];
    columns[1] = columns[0];
    try std_testing.expectError(
        error.DestinationAlias,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    columns[1] = second_column;
    try std_testing.expectEqualSlices(
        M31,
        &([_]M31{sentinel} ** output.len),
        &output,
    );

    // A destination may not borrow the workspace's QM31 backing storage.
    const first_column = columns[0];
    columns[0] = @as([*]M31, @ptrCast(workspace.scratch.ptr))[0..size];
    try std_testing.expectError(
        error.DestinationAlias,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    columns[0] = first_column;

    // Geometry tampering fails closed without making the retained workspace
    // impossible to deinitialize after the admission check.
    const full_scratch = workspace.scratch;
    workspace.scratch = workspace.scratch[0 .. workspace.scratch.len - 1];
    try std_testing.expectError(
        error.WorkspaceCapacityMismatch,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    workspace.scratch = full_scratch;
}

fn pairValue(pair: logup.RowPair) !QM31 {
    return pair.n1.mul(try pair.d1.inv())
        .add(pair.n2.mul(try pair.d2.inv()));
}

fn secureAt(
    columns: anytype,
    secure_column: usize,
    row: usize,
) QM31 {
    return QM31.fromM31Array(.{
        columns[secure_column * 4][row],
        columns[secure_column * 4 + 1][row],
        columns[secure_column * 4 + 2][row],
        columns[secure_column * 4 + 3][row],
    });
}

fn frameworkFailureCase(
    allocator: std.mem.Allocator,
    plan: *const @import("control_relation.zig").Plan,
    rows: []const @import("control_relation.zig").Row,
    relations: *const universal.UniversalRelations,
) !void {
    const Framework = Runtime(@import("control_relation.zig").Runtime);
    var generated = try Framework.generatePrepared(
        allocator,
        plan,
        rows,
        4,
        relations,
    );
    defer generated.deinit(allocator);
}
