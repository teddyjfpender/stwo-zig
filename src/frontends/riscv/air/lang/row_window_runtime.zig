//! Row-window construction, interaction-degree lowering, and mask emission.

pub fn Runtime(comptime contract: anytype) type {
    return struct {
        const std = contract.std;
        const core_air_components = contract.core_air_components;
        const qm31 = contract.qm31;
        const canonic = contract.canonic;
        const compat_layout = contract.compat_layout;
        const protocol_degree = contract.protocol_degree;
        const shadow_program = contract.shadow_program;
        const static_registry = contract.static_registry;
        const witness_layout = contract.witness_layout;
        const CirclePointQM31 = contract.CirclePointQM31;
        const format_version = contract.format_version;
        const Digest = contract.Digest;
        const Owner = contract.Owner;
        const ownerFor = contract.ownerFor;
        const ColumnId = contract.ColumnId;
        const WindowId = contract.WindowId;
        const first_selector_window = contract.first_selector_window;
        const active_selector_window = contract.active_selector_window;
        const semantic_window = contract.semantic_window;
        const interaction_window = contract.interaction_window;
        const ColumnType = contract.ColumnType;
        const RowWindow = contract.RowWindow;
        const MaskColumn = contract.MaskColumn;
        const ShiftedColumn = contract.ShiftedColumn;
        const Error = contract.Error;
        const Plan = contract.Plan;

        pub fn build(
            allocator: std.mem.Allocator,
            imported: *const shadow_program.ImportedProgram,
            layout: *const compat_layout.Layout,
        ) Error!Plan {
            try layout.validate(imported);
            const main_count = layout.main().len;
            const interaction_count = layout.interactions().len;
            const column_count = try addCount(
                compat_layout.PREPROCESSED_COLUMN_COUNT,
                try addCount(main_count, interaction_count),
            );
            const shifted_count = try addCount(column_count, interaction_count);
            const main_count_u32 = try countU32(main_count);
            const interaction_count_u32 = try countU32(interaction_count);
            const interaction_start = std.math.add(
                u32,
                compat_layout.PREPROCESSED_COLUMN_COUNT,
                main_count_u32,
            ) catch return error.CountOverflow;

            var result_owns_allocations = false;
            const windows = try allocator.alloc(RowWindow, 4);
            errdefer if (!result_owns_allocations) allocator.free(windows);
            const columns = try allocator.alloc(MaskColumn, column_count);
            errdefer if (!result_owns_allocations) allocator.free(columns);
            const shifted_columns = try allocator.alloc(ShiftedColumn, shifted_count);
            errdefer if (!result_owns_allocations) allocator.free(shifted_columns);

            const semantic_owner = ownerFor(imported.family, .semantic);
            const interaction_owner = ownerFor(imported.family, .interaction);
            windows[0] = .{
                .id = first_selector_window,
                .owner = interaction_owner,
                .columns = .{ .start = 0, .len = 1 },
                .offsets = .{ .current, .current },
                .offset_count = 1,
                .boundary = .none,
            };
            windows[1] = .{
                .id = active_selector_window,
                .owner = semantic_owner,
                .columns = .{ .start = 1, .len = 1 },
                .offsets = .{ .current, .current },
                .offset_count = 1,
                .boundary = .none,
            };
            windows[2] = .{
                .id = semantic_window,
                .owner = semantic_owner,
                .columns = .{
                    .start = compat_layout.PREPROCESSED_COLUMN_COUNT,
                    .len = main_count_u32,
                },
                .offsets = .{ .current, .current },
                .offset_count = 1,
                .boundary = .none,
            };
            windows[3] = .{
                .id = interaction_window,
                .owner = interaction_owner,
                .columns = .{
                    .start = interaction_start,
                    .len = interaction_count_u32,
                },
                .offsets = .{ .current, .previous },
                .offset_count = 2,
                .boundary = .{ .cyclic_first_row_claim = .{
                    .owner = interaction_owner,
                    .selector = @enumFromInt(0),
                    .claim_count = try countU32(imported.batchCount()),
                    .coordinates_per_claim = qm31.SECURE_EXTENSION_DEGREE,
                } },
            };

            var column_cursor: usize = 0;
            var shifted_cursor: usize = 0;
            try appendColumn(
                columns,
                shifted_columns,
                &column_cursor,
                &shifted_cursor,
                windows,
                interaction_owner,
                layout.preprocessed[0].reference,
                .base_field,
                first_selector_window,
            );
            try appendColumn(
                columns,
                shifted_columns,
                &column_cursor,
                &shifted_cursor,
                windows,
                semantic_owner,
                layout.preprocessed[1].reference,
                .base_field,
                active_selector_window,
            );
            for (layout.main()) |column| {
                try appendColumn(
                    columns,
                    shifted_columns,
                    &column_cursor,
                    &shifted_cursor,
                    windows,
                    semantic_owner,
                    column.reference,
                    .base_field,
                    semantic_window,
                );
            }
            for (layout.interactions()) |column| {
                try appendColumn(
                    columns,
                    shifted_columns,
                    &column_cursor,
                    &shifted_cursor,
                    windows,
                    interaction_owner,
                    column.reference,
                    .{ .secure_coordinate = column.coordinate },
                    interaction_window,
                );
            }
            if (column_cursor != columns.len or shifted_cursor != shifted_columns.len)
                return error.InvalidTreeShape;

            var result = Plan{
                .allocator = allocator,
                .schema_version = format_version,
                .family = imported.family,
                .semantic_program_digest = static_registry.DESCRIPTORS[
                    @intFromEnum(imported.family)
                ].semantic_program_digest,
                .witness_layout_digest = witness_layout.digest(),
                .tree_column_counts = .{
                    compat_layout.PREPROCESSED_COLUMN_COUNT,
                    main_count_u32,
                    interaction_count_u32,
                },
                .windows = windows,
                .columns = columns,
                .shifted_columns = shifted_columns,
                .plan_digest = .{0} ** 32,
            };
            result.plan_digest = result.identityDigest();
            result_owns_allocations = true;
            errdefer result.deinit();
            try result.validate(imported, layout);
            return result;
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
            try plan.validate(imported, layout);
            const window = plan.windows[@intFromEnum(interaction_window)];
            const column_end = try window.columns.end();
            if (column_end > plan.columns.len) return error.InvalidWindow;
            var row_window_degree: protocol_degree.Degree = 0;
            for (plan.columns[window.columns.start..column_end]) |column| {
                const shifted_end = try column.shifted.end();
                if (shifted_end > plan.shifted_columns.len)
                    return error.InvalidShiftedColumn;
                for (plan.shifted_columns[column.shifted.start..shifted_end]) |shifted| {
                    row_window_degree = @max(
                        row_window_degree,
                        try plan.shiftedDegree(shifted.id),
                    );
                }
            }

            const boundary = switch (window.boundary) {
                .none => return error.InvalidBoundary,
                .cyclic_first_row_claim => |item| item,
            };
            const selector = plan.column(boundary.selector) orelse
                return error.InvalidBoundary;
            const selector_end = try selector.shifted.end();
            if (selector_end > plan.shifted_columns.len)
                return error.InvalidBoundary;
            var selector_degree: protocol_degree.Degree = 0;
            for (plan.shifted_columns[selector.shifted.start..selector_end]) |shifted| {
                if (shifted.offset == .current)
                    selector_degree = @max(
                        selector_degree,
                        try plan.shiftedDegree(shifted.id),
                    );
            }
            if (row_window_degree == 0 or selector_degree == 0)
                return error.InvalidBoundary;
            return protocol_degree.interactionTermsWithContext(first, second, .{
                .row_window = row_window_degree,
                .boundary_selector = selector_degree,
                .boundary_claim = 0,
            });
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
            try plan.validate(imported, layout);
            if (max_log_degree_bound < trace_log_size)
                return error.LogDegreeUnderflow;
            const previous = previousRowPoint(max_log_degree_bound, point);
            const trees = try allocator.alloc([][]CirclePointQM31, 3);
            var initialized: usize = 0;
            errdefer {
                for (trees[0..initialized]) |columns| freePointColumns(allocator, columns);
                allocator.free(trees);
            }
            for (0..trees.len) |tree_index| {
                const tree: compat_layout.Tree = @enumFromInt(tree_index);
                trees[tree_index] = try emitTree(
                    allocator,
                    plan,
                    tree,
                    point,
                    previous,
                );
                initialized += 1;
            }
            return core_air_components.MaskPoints.initOwned(trees);
        }

        fn appendColumn(
            columns: []MaskColumn,
            shifted_columns: []ShiftedColumn,
            column_cursor: *usize,
            shifted_cursor: *usize,
            windows: []const RowWindow,
            owner: Owner,
            reference: compat_layout.ColumnRef,
            value_type: ColumnType,
            window_id: WindowId,
        ) Error!void {
            if (column_cursor.* >= columns.len) return error.InvalidColumn;
            const window_index: usize = @intFromEnum(window_id);
            if (window_index >= windows.len) return error.InvalidWindow;
            const offsets = windows[window_index].offsetSlice() orelse
                return error.InvalidWindow;
            const column_id: ColumnId = @enumFromInt(try countU32(column_cursor.*));
            columns[column_cursor.*] = .{
                .id = column_id,
                .owner = owner,
                .reference = reference,
                .value_type = value_type,
                .window = window_id,
                .shifted = .{
                    .start = try countU32(shifted_cursor.*),
                    .len = try countU32(offsets.len),
                },
            };
            for (offsets) |offset| {
                if (shifted_cursor.* >= shifted_columns.len)
                    return error.InvalidShiftedColumn;
                shifted_columns[shifted_cursor.*] = .{
                    .id = @enumFromInt(try countU32(shifted_cursor.*)),
                    .owner = owner,
                    .column = column_id,
                    .window = window_id,
                    .offset = offset,
                };
                shifted_cursor.* += 1;
            }
            column_cursor.* += 1;
        }

        pub fn validateWindow(actual: RowWindow, expected: RowWindow) Error!void {
            if (!std.meta.eql(actual.owner, expected.owner)) return error.InvalidOwner;
            if (actual.id != expected.id or
                !std.meta.eql(actual.columns, expected.columns) or
                actual.offset_count != expected.offset_count or
                !std.meta.eql(actual.offsets, expected.offsets))
            {
                return error.InvalidWindow;
            }
            switch (expected.boundary) {
                .none => switch (actual.boundary) {
                    .none => {},
                    else => return error.InvalidBoundary,
                },
                .cyclic_first_row_claim => |expected_claim| switch (actual.boundary) {
                    .none => return error.InvalidBoundary,
                    .cyclic_first_row_claim => |actual_claim| {
                        if (!std.meta.eql(actual_claim.owner, expected_claim.owner))
                            return error.InvalidOwner;
                        if (actual_claim.selector != expected_claim.selector or
                            actual_claim.claim_count != expected_claim.claim_count or
                            actual_claim.coordinates_per_claim !=
                                expected_claim.coordinates_per_claim)
                        {
                            return error.InvalidBoundary;
                        }
                    },
                },
            }
        }

        fn emitTree(
            allocator: std.mem.Allocator,
            plan: *const Plan,
            tree: compat_layout.Tree,
            point: CirclePointQM31,
            previous: CirclePointQM31,
        ) Error![][]CirclePointQM31 {
            const tree_index: usize = @intFromEnum(tree);
            const count: usize = plan.tree_column_counts[tree_index];
            const columns = try allocator.alloc([]CirclePointQM31, count);
            var initialized: usize = 0;
            errdefer {
                for (columns[0..initialized]) |samples| allocator.free(samples);
                allocator.free(columns);
            }
            const start = treeColumnStart(plan, tree);
            for (columns, 0..) |*samples, local_index| {
                const plan_index = std.math.add(usize, start, local_index) catch
                    return error.CountOverflow;
                if (plan_index >= plan.columns.len) return error.InvalidColumn;
                const column = plan.columns[plan_index];
                if (column.reference.tree != tree or
                    column.reference.local_index != local_index)
                {
                    return error.InvalidColumn;
                }
                const shifted_end = try column.shifted.end();
                if (shifted_end > plan.shifted_columns.len)
                    return error.InvalidShiftedColumn;
                samples.* = try allocator.alloc(CirclePointQM31, column.shifted.len);
                initialized += 1;
                for (
                    plan.shifted_columns[column.shifted.start..shifted_end],
                    samples.*,
                ) |shifted, *sample| {
                    sample.* = switch (shifted.offset) {
                        .current => point,
                        .previous => previous,
                    };
                }
            }
            return columns;
        }

        fn treeColumnStart(plan: *const Plan, tree: compat_layout.Tree) usize {
            return switch (tree) {
                .preprocessed => 0,
                .main => plan.tree_column_counts[@intFromEnum(compat_layout.Tree.preprocessed)],
                .interaction => @as(usize, plan.tree_column_counts[@intFromEnum(compat_layout.Tree.preprocessed)]) +
                    @as(usize, plan.tree_column_counts[@intFromEnum(compat_layout.Tree.main)]),
            };
        }

        fn freePointColumns(
            allocator: std.mem.Allocator,
            columns: [][]CirclePointQM31,
        ) void {
            for (columns) |samples| allocator.free(samples);
            allocator.free(columns);
        }

        /// Trace-order predecessor mask point, kept local so the typed authoring
        /// kernel does not acquire a prover-engine dependency through production
        /// LogUp's domain-evaluation tests.
        pub fn previousRowPoint(
            log_size: u32,
            point: CirclePointQM31,
        ) CirclePointQM31 {
            const step = canonic.CanonicCoset.new(log_size).coset_value.step;
            return point.sub(.{
                .x = qm31.QM31.fromBase(step.x),
                .y = qm31.QM31.fromBase(step.y),
            });
        }

        pub fn countU32(value: usize) error{CountOverflow}!u32 {
            return std.math.cast(u32, value) orelse error.CountOverflow;
        }

        pub fn addCount(lhs: usize, rhs: usize) error{CountOverflow}!usize {
            return std.math.add(usize, lhs, rhs) catch error.CountOverflow;
        }

        pub fn hashOwner(hash: anytype, owner: Owner) void {
            hashInteger(hash, u8, @intFromEnum(owner.family));
            hashInteger(hash, u8, @intFromEnum(owner.component));
            hashInteger(hash, u32, owner.instance);
        }

        pub fn hashCount(hash: anytype, value: usize) void {
            // All plan lengths have already been bounded by fixed production maxima;
            // this cast cannot truncate a valid plan and remains deterministic for a
            // malformed host value presented directly to `identityDigest`.
            hashInteger(hash, u64, value);
        }

        pub fn hashInteger(hash: anytype, comptime T: type, value: T) void {
            var bytes: [@sizeOf(T)]u8 = undefined;
            std.mem.writeInt(T, &bytes, value, .little);
            hash.update(&bytes);
        }

        pub fn digestFromHex(hex: []const u8) error{InvalidWindowDigest}!Digest {
            if (hex.len != 2 * @sizeOf(Digest)) return error.InvalidWindowDigest;
            var result: Digest = undefined;
            _ = std.fmt.hexToBytes(&result, hex) catch
                return error.InvalidWindowDigest;
            return result;
        }

        pub fn digestIsZero(value: Digest) bool {
            var combined: u8 = 0;
            for (value) |byte| combined |= byte;
            return combined == 0;
        }
    };
}
