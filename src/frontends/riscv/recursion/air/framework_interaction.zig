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

/// Default upper bound for an owned writer's inversion window (8192 rows).
pub const OWNED_TILE_LOG_SIZE: u32 = 13;

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

        /// Independently owned columns, suitable for direct PCS ownership transfer.
        pub const OwnedColumns = struct {
            columns: [INTERACTION_COLUMN_COUNT][]M31,
            claimed_sum: QM31,
            pub fn deinit(self: *OwnedColumns, allocator: std.mem.Allocator) void {
                for (self.columns) |column| allocator.free(column);
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
            return generatePreparedWithPadding(allocator, plan, rows, log_size, relations, null);
        }

        /// Repeats an explicitly supplied typed row beyond the live prefix.
        /// Its actual lookup pairs are evaluated once, including nonzero padding events.
        pub const ColumnRows = struct {
            columns: [@typeInfo(Row).array.len][]const M31,
            first: usize = 0,
            count: usize,
            main_count: usize = @typeInfo(Row).array.len,
            metadata: ?[]const Row = null,
            /// Row-major fixed tails; excludes the main columns already retained.
            compact_metadata: ?[]const M31 = null,
            pub fn validate(self: @This(), log: u32) Error!void {
                const size = try traceSize(log);
                if (self.first > size or self.count > size - self.first or self.main_count > @typeInfo(Row).array.len) return error.InvalidTraceShape;
                if (self.metadata != null and self.compact_metadata != null) return error.InvalidTraceShape;
                if (self.compact_metadata) |fixed| {
                    const needed = std.math.mul(usize, self.count, @typeInfo(Row).array.len - self.main_count) catch return error.InvalidTraceShape;
                    if (fixed.len != needed) return error.InvalidTraceShape;
                } else if (self.metadata) |fixed| {
                    if (fixed.len < self.count) return error.InvalidTraceShape;
                } else if (self.main_count != @typeInfo(Row).array.len) return error.InvalidTraceShape;
                for (self.columns[0..self.main_count]) |column| if (column.len != size) return error.InvalidTraceShape;
            }
            /// The caller validates the view and bounds index by count.
            pub fn read(self: @This(), index: usize, log: u32) Row {
                var row: Row = if (self.metadata) |fixed| fixed[index] else undefined;
                if (self.compact_metadata) |fixed| {
                    const width = @typeInfo(Row).array.len - self.main_count;
                    @memcpy(row[self.main_count..], fixed[index * width ..][0..width]);
                }
                const source = committedRow(self.first + index, log);
                for (row[0..self.main_count], self.columns[0..self.main_count]) |*value, column| value.* = column[source];
                return row;
            }
        };
        pub fn generatePreparedFromColumns(allocator: std.mem.Allocator, plan: *const Plan, columns: ColumnRows, log_size: u32, relations: *const universal.UniversalRelations, padding: ?Row) Error!Interaction {
            return generateSource(allocator, plan, &.{}, log_size, relations, padding, columns, null);
        }
        pub fn generatePreparedWithPadding(
            allocator: std.mem.Allocator,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            padding: ?Row,
        ) Error!Interaction {
            return generateSource(allocator, plan, rows, log_size, relations, padding, null, null);
        }
        /// Output uses allocator; inversion scratch is borrowed for this call only.
        /// The caller retains ownership of workspace and its exact scratch slice.
        pub fn generatePreparedFromColumnsWithWorkspace(allocator: std.mem.Allocator, workspace: *Workspace, plan: *const Plan, columns: ColumnRows, log_size: u32, relations: *const universal.UniversalRelations, padding: ?Row) Error!Interaction {
            return generateSource(allocator, plan, &.{}, log_size, relations, padding, columns, workspace);
        }
        /// Uses the same admitted, fail-atomic generator but allocates each
        /// output column independently. Scratch remains caller-owned; PCS may
        /// consume the outputs without detaching a shared slab or arena.
        pub fn generatePreparedOwnedColumnsWithWorkspace(allocator: std.mem.Allocator, workspace: *Workspace, plan: *const Plan, source: ColumnRows, log_size: u32, relations: *const universal.UniversalRelations, padding: ?Row) Error!OwnedColumns {
            const size = try traceSize(log_size);
            var result = OwnedColumns{ .columns = @splat(&.{}), .claimed_sum = undefined };
            errdefer result.deinit(allocator);
            for (&result.columns) |*column| column.* = try allocator.alloc(M31, size);
            result.claimed_sum = (try generatePreparedIntoInternal(false, workspace, plan, &.{}, log_size, relations, &result.columns, padding, source)).claimed_sum;
            return result;
        }
        /// Bounded inversion scratch for exclusively owned output columns.
        /// Errors destroy all partial outputs; borrowed destination APIs retain
        /// their separate fail-atomic contract. The final column temporarily
        /// holds row totals, then becomes the shifted global prefix in place.
        pub fn generatePreparedOwnedColumnsTiledWithWorkspace(allocator: std.mem.Allocator, workspace: *Workspace, plan: *const Plan, source: ColumnRows, log_size: u32, relations: *const universal.UniversalRelations, padding: ?Row) Error!OwnedColumns {
            return generatePreparedOwnedColumnsScheduled(allocator, &.{workspace}, plan, source, log_size, relations, padding, SerialTiles{});
        }
        const SerialTiles = struct {
            pub fn run(_: @This(), contexts: anytype) void {
                for (contexts) |*context| context.run();
            }
        };
        /// Workspaces are worker-private; the scheduler must drain all jobs before
        /// returning. Every worker writes disjoint logical rows directly into the
        /// final layout. Only the global prefix depends on the completed row sums.
        pub fn generatePreparedOwnedColumnsScheduled(allocator: std.mem.Allocator, workspaces: []const *Workspace, plan: *const Plan, source: ColumnRows, log_size: u32, relations: *const universal.UniversalRelations, padding: ?Row, scheduler: anytype) Error!OwnedColumns {
            try relations.validate();
            if (workspaces.len == 0) return error.WorkspaceCapacityMismatch;
            const size = try traceSize(log_size);
            const tile_log = @min(log_size, workspaces[0].capacity_log_size);
            try source.validate(log_size);
            const tile_size = try traceSize(tile_log);
            const tile_count = size / tile_size;
            if (workspaces.len > tile_count) return error.WorkspaceCapacityMismatch;
            var result = OwnedColumns{ .columns = @splat(&.{}), .claimed_sum = QM31.zero() };
            errdefer result.deinit(allocator);
            for (&result.columns) |*column| column.* = try allocator.alloc(M31, size);
            for (workspaces, 0..) |workspace, i| {
                try workspace.validateFor(tile_log);
                try validateMemoryContract(workspace, plan, &.{}, relations, &result.columns, size);
                try validateColumnSource(source, log_size, workspace, &result.columns);
                for (workspaces[0..i]) |other| {
                    const begin = @intFromPtr(workspace.scratch.ptr);
                    const other_begin = @intFromPtr(other.scratch.ptr);
                    if (begin < other_begin + other.scratch.len * @sizeOf(QM31) and other_begin < begin + workspace.scratch.len * @sizeOf(QM31)) return error.DestinationAlias;
                }
            }
            const absent_pairs = if (padding) |row| try plan.preparedRowPairs(row, relations) else paddingPairs();
            const contexts = try allocator.alloc(TileWorker, workspaces.len);
            defer allocator.free(contexts);
            for (contexts, workspaces, 0..) |*context, workspace, i| context.* = .{
                .workspace = workspace,
                .plan = plan,
                .source = source,
                .log_size = log_size,
                .relations = relations,
                .columns = &result.columns,
                .absent_pairs = absent_pairs,
                .tile_size = tile_size,
                .first = tile_count * i / contexts.len * tile_size,
                .end = tile_count * (i + 1) / contexts.len * tile_size,
            };
            scheduler.run(contexts);
            for (contexts) |context| {
                if (context.failure) |err| return err;
                result.claimed_sum = result.claimed_sum.add(context.sum);
            }
            const shift = try result.claimed_sum.divM31(M31.fromU64(size));
            var prefix = QM31.zero();
            for (0..size) |logical_row| {
                const row = committedRow(logical_row, log_size);
                prefix = prefix.add(secureAt(&result.columns, BATCH_COUNT - 1, row)).sub(shift);
                writeSecure(&result.columns, BATCH_COUNT - 1, row, prefix);
            }
            if (!prefix.isZero()) return error.PrefixClosureMismatch;
            return result;
        }
        const TileWorker = struct {
            workspace: *Workspace,
            plan: *const Plan,
            source: ColumnRows,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            columns: *[INTERACTION_COLUMN_COUNT][]M31,
            absent_pairs: [BATCH_COUNT]logup.RowPair,
            tile_size: usize,
            first: usize,
            end: usize,
            sum: QM31 = QM31.zero(),
            failure: ?Error = null,
            pub fn run(self: *@This()) void {
                self.generate() catch |err| {
                    self.failure = err;
                };
            }
            fn generate(self: *@This()) Error!void {
                const tile_size = self.tile_size;
                const term_count = BATCH_COUNT * tile_size;
                const numerators = self.workspace.scratch[0..term_count];
                const denominators = self.workspace.scratch[term_count .. 2 * term_count];
                const inverses = self.workspace.scratch[2 * term_count .. 3 * term_count];
                const source = self.source;
                const log_size = self.log_size;
                const plan = self.plan;
                const relations = self.relations;
                const absent_pairs = self.absent_pairs;
                var first: usize = self.first;
                while (first < self.end) : (first += tile_size) {
                    // Both domain and window are powers of two, so every tile is full.
                    for (0..tile_size) |offset| {
                        const logical_row = first + offset;
                        const pairs = if (logical_row < source.count)
                            try plan.preparedRowPairs(source.read(logical_row, log_size), relations)
                        else
                            absent_pairs;
                        for (pairs, 0..) |pair, batch| {
                            const index = batch * tile_size + offset;
                            numerators[index] = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
                            denominators[index] = pair.d1.mul(pair.d2);
                        }
                    }
                    fields.batchInverseInPlace(QM31, denominators, inverses) catch return error.ZeroDenominator;
                    for (0..tile_size) |offset| {
                        var within_row = QM31.zero();
                        for (0..BATCH_COUNT) |batch| {
                            const index = batch * tile_size + offset;
                            within_row = within_row.add(numerators[index].mul(inverses[index]));
                            writeSecure(self.columns, batch, committedRow(first + offset, log_size), within_row);
                        }
                        self.sum = self.sum.add(within_row);
                    }
                }
            }
        };
        fn generateSource(allocator: std.mem.Allocator, plan: *const Plan, rows: []const Row, log_size: u32, relations: *const universal.UniversalRelations, padding: ?Row, columns_source: ?ColumnRows, borrowed_workspace: ?*Workspace) Error!Interaction {
            const size = try traceSize(log_size);
            const storage_len = try requiredStorageElementCount(log_size);
            const storage = try allocator.alloc(M31, storage_len);
            errdefer allocator.free(storage);
            var columns: [INTERACTION_COLUMN_COUNT][]M31 = undefined;
            for (&columns, 0..) |*column, index|
                column.* = storage[index * size ..][0..size];
            var owned_workspace: ?Workspace = if (borrowed_workspace == null) try Workspace.init(allocator, log_size) else null;
            defer if (owned_workspace) |*workspace| workspace.deinit();
            const workspace = borrowed_workspace orelse &owned_workspace.?;
            const claims = try generatePreparedIntoInternal(
                false,
                workspace,
                plan,
                rows,
                log_size,
                relations,
                &columns,
                padding,
                columns_source,
            );
            return .{
                .columns = columns,
                .claimed_sum = claims.claimed_sum,
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
                null,
                null,
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
                null,
                null,
            );
        }

        /// Admit the same shape and memory contract before an alternative
        /// writer touches scratch or caller-owned columns.
        pub fn preflightPreparedInto(
            workspace: *Workspace,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            destination: *[INTERACTION_COLUMN_COUNT][]M31,
        ) Error!usize {
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

            return size;
        }

        fn generatePreparedIntoInternal(
            comptime decompose_domains: bool,
            workspace: *Workspace,
            plan: *const Plan,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
            destination: *[INTERACTION_COLUMN_COUNT][]M31,
            padding: ?Row,
            columns_source: ?ColumnRows,
        ) Error!DomainClaims {
            const size = try preflightPreparedInto(workspace, plan, rows, log_size, relations, destination);
            if (columns_source) |source| try validateColumnSource(source, log_size, workspace, destination);
            const row_count = if (columns_source) |source| source.count else rows.len;
            const absent_pairs = if (padding) |row| try plan.preparedRowPairs(row, relations) else paddingPairs();

            const term_count = std.math.mul(usize, BATCH_COUNT, size) catch
                return error.InvalidTraceShape;
            const scratch_count = try requiredScratchElementCount(log_size);
            const scratch = workspace.scratch[0..scratch_count];
            const numerators = scratch[0..term_count];
            const cumulative = scratch[term_count .. 2 * term_count];
            const inverses = scratch[2 * term_count .. 3 * term_count];

            for (0..size) |logical_row| {
                const pairs = if (logical_row < row_count)
                    try plan.preparedRowPairs(if (columns_source) |source| source.read(logical_row, log_size) else rows[logical_row], relations)
                else
                    absent_pairs;
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

                if (comptime decompose_domains and RelationRuntime.BATCH_SIZE > 2) {
                    const row = if (logical_row < row_count)
                        (if (columns_source) |source| source.read(logical_row, log_size) else rows[logical_row])
                    else (padding orelse continue);
                    for (plan.preparedEntries(row)) |entry| {
                        const denominator = try entry.denominator(relations);
                        if (denominator.eql(QM31.zero())) return error.ZeroDenominator;
                        const domain = @intFromEnum(entry.domain);
                        by_domain[domain] = by_domain[domain].add(entry.numerator.mul((denominator.inv() catch return error.ZeroDenominator)));
                    }
                } else if (comptime decompose_domains) {
                    const pairs = if (logical_row < row_count)
                        try plan.preparedRowPairs(if (columns_source) |source| source.read(logical_row, log_size) else rows[logical_row], relations)
                    else
                        absent_pairs;
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

        fn validateColumnSource(source: ColumnRows, log_size: u32, workspace: *const Workspace, destination: *const [INTERACTION_COLUMN_COUNT][]M31) Error!void {
            try source.validate(log_size);
            if (source.metadata) |fixed| {
                if (try slicesOverlap(Row, fixed, QM31, workspace.scratch)) return error.DestinationAlias;
                for (destination) |output| if (try slicesOverlap(Row, fixed, M31, output)) return error.DestinationAlias;
            }
            if (source.compact_metadata) |fixed| {
                if (try slicesOverlap(M31, fixed, QM31, workspace.scratch)) return error.DestinationAlias;
                for (destination) |output| if (try slicesOverlap(M31, fixed, M31, output)) return error.DestinationAlias;
            }
            for (source.columns[0..source.main_count]) |column| {
                if (try slicesOverlap(M31, column, QM31, workspace.scratch)) return error.DestinationAlias;
                for (destination) |output| if (try slicesOverlap(M31, column, M31, output)) return error.DestinationAlias;
            }
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

    // Domain decomposition reuses the same scratch and matches the independent
    // cold audit, including padding, without changing any committed column.
    @memset(&output, sentinel);
    const second_claim = try Framework.generatePreparedIntoWithDomainSums(
        &workspace,
        &plan,
        &rows,
        log_size,
        &relations,
        &columns,
    );
    try std_testing.expectEqual(allocation_cursor, fixed.end_index);
    try std_testing.expect(second_claim.claimed_sum.eql(expected.claimed_sum));
    const domain_audit = try plan.auditPreparedDomainSums(
        std_testing.allocator,
        &rows,
        &relations,
        expected.claimed_sum,
    );
    try std_testing.expectEqualDeep(domain_audit.values, second_claim.by_domain);
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
    try std_testing.expectError(
        error.ZeroDenominator,
        Framework.generatePreparedIntoWithDomainSums(
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

test "R-012 framework tiled owned output preserves columns and releases partial allocations" {
    const a = std.testing.allocator;
    const control = @import("control.zig");
    const relation = @import("control_relation.zig");
    const witness = @import("control_witness.zig");
    const kind = @import("proof_kind.zig").ProofKind;
    const F = Runtime(relation.Runtime);
    var definition = try control.build(a);
    defer definition.deinit();
    const plan = try relation.authenticate(&definition);
    const rows = [_]relation.Row{
        witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 0, .tag = 7, .args = .{ 11, 13, 17, 19 }, .terminal_mask = 0 }, kind.segment_leaf),
        witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 1, .tag = 23, .args = .{ 29, 31, 37, 41 }, .terminal_mask = 1 }, kind.segment_leaf),
    };
    var relations = universal.UniversalRelations.dummy();
    var oracle = try F.generatePrepared(a, &plan, &rows, 4, &relations);
    defer oracle.deinit(a);
    const view = F.ColumnRows{ .columns = @splat(&.{}), .count = rows.len, .main_count = 0, .metadata = &rows };
    for (0..5) |tile_log| {
        var workspace = try F.Workspace.init(a, @intCast(tile_log));
        defer workspace.deinit();
        try std.testing.checkAllAllocationFailures(a, tiledFailureCase, .{ &workspace, &plan, view, &relations, &oracle });
    }
    var workspace = try F.Workspace.init(a, 0);
    defer workspace.deinit();
    var helper = try F.Workspace.init(a, 0);
    defer helper.deinit();
    const workers = [_]*F.Workspace{ &workspace, &helper };
    try std.testing.checkAllAllocationFailures(a, scheduledFailureCase, .{ &workers, &plan, view, &relations, &oracle });
    try std.testing.expectError(error.DestinationAlias, F.generatePreparedOwnedColumnsScheduled(a, &.{ &workspace, &workspace }, &plan, view, 4, &relations, null, ReverseTiles{}));
    const pairs = try plan.preparedRowPairs(rows[0], &relations);
    const domain = @intFromEnum(plan.events[plan.batches[0].first].domain);
    relations.elements[domain].z = relations.elements[domain].z.add(pairs[0].d1);
    try std.testing.expectError(error.ZeroDenominator, F.generatePreparedOwnedColumnsTiledWithWorkspace(a, &workspace, &plan, view, 4, &relations, null));
    try std.testing.expectError(error.ZeroDenominator, F.generatePreparedOwnedColumnsScheduled(a, &workers, &plan, view, 4, &relations, null, ReverseTiles{}));
}
fn tiledFailureCase(a: std.mem.Allocator, workspace: *Runtime(@import("control_relation.zig").Runtime).Workspace, plan: *const @import("control_relation.zig").Plan, view: Runtime(@import("control_relation.zig").Runtime).ColumnRows, relations: *const universal.UniversalRelations, oracle: *const Runtime(@import("control_relation.zig").Runtime).Interaction) !void {
    const F = Runtime(@import("control_relation.zig").Runtime);
    var actual = try F.generatePreparedOwnedColumnsTiledWithWorkspace(a, workspace, plan, view, 4, relations, null);
    defer actual.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(actual.claimed_sum));
    for (oracle.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M31, left, right);
}

// Reverse completion order checks that prefix construction cannot depend on
// scheduling order. Production pool execution is also checked by proof parity.
const ReverseTiles = struct {
    pub fn run(_: @This(), contexts: anytype) void {
        var i = contexts.len;
        while (i != 0) {
            i -= 1;
            contexts[i].run();
        }
    }
};
fn scheduledFailureCase(a: std.mem.Allocator, workspaces: []const *Runtime(@import("control_relation.zig").Runtime).Workspace, plan: *const @import("control_relation.zig").Plan, view: Runtime(@import("control_relation.zig").Runtime).ColumnRows, relations: *const universal.UniversalRelations, oracle: *const Runtime(@import("control_relation.zig").Runtime).Interaction) !void {
    const F = Runtime(@import("control_relation.zig").Runtime);
    var actual = try F.generatePreparedOwnedColumnsScheduled(a, workspaces, plan, view, 4, relations, null, ReverseTiles{});
    defer actual.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(actual.claimed_sum));
    for (oracle.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M31, left, right);
}
