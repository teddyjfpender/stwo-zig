//! Exact mixed-height geometry for the pinned upstream Blake AIR.

const std = @import("std");
const cpu_blake = @import("../../../../examples/blake.zig");
const constants = cpu_blake.constants;
const air_geometry = cpu_blake.geometry;
const exact_input = cpu_blake.exact_input;
const pcs = @import("stwo_core").pcs;

pub const protocol_name = air_geometry.PROTOCOL_NAME;
pub const component_count = air_geometry.COMPONENT_COUNT;
pub const trace_tree_count: usize = air_geometry.PROOF_COMMITMENTS;
pub const preprocessed_columns = air_geometry.PREPROCESSED_COLUMNS;
pub const main_columns = air_geometry.MAIN_COLUMNS;
pub const interaction_columns = air_geometry.INTERACTION_COLUMNS;
pub const composition_columns: usize = 8;
pub const composition_split: u32 = 1;
pub const constraint_count = air_geometry.CONSTRAINT_COUNT;
pub const relation_pair_count: usize = 7;
pub const claimed_sum_count: usize = component_count;
pub const statement0_words: usize = 2;
pub const statement1_words: usize = claimed_sum_count * 4;
pub const relation_element_words: usize = relation_pair_count * 2 * 4;
pub const composition_coordinate_count: usize = 4;
pub const previous_row_sample_columns: usize = component_count * 4;
pub const sampled_value_count: usize =
    preprocessed_columns +
    main_columns +
    interaction_columns +
    previous_row_sample_columns +
    composition_columns;
pub const source_column_count: usize =
    preprocessed_columns +
    main_columns +
    interaction_columns +
    composition_columns;

pub const Component = enum(u8) {
    scheduler,
    round_split_3,
    round_split_1,
    xor_12,
    xor_9,
    xor_8,
    xor_7,
    xor_4,
};

pub const component_order = [_]Component{
    .scheduler,
    .round_split_3,
    .round_split_1,
    .xor_12,
    .xor_9,
    .xor_8,
    .xor_7,
    .xor_4,
};

pub const Tree = enum(u8) {
    preprocessed,
    main,
    interaction,
    composition,
};

pub const Request = struct {
    statement: cpu_blake.Request,
    protocol: pcs.PcsConfig,
};

pub const Error = exact_input.Error || error{
    GeometryOverflow,
    UnsupportedProtocol,
};

pub const Geometry = struct {
    statement: cpu_blake.Request,
    protocol: pcs.PcsConfig,
    component_logs: [component_count]u32,
    max_trace_log: u32,
    composition_log: u32,
    composition_column_log: u32,
    query_log: u32,
    fri_tree_count: u32,
    decommit_tree_count: usize,
    trace_words: usize,
    main_words: usize,
    interaction_words: usize,
    composition_words: usize,

    pub fn treeColumnCount(_: Geometry, tree: Tree) usize {
        return switch (tree) {
            .preprocessed => preprocessed_columns,
            .main => main_columns,
            .interaction => interaction_columns,
            .composition => composition_columns,
        };
    }

    pub fn treeCommitmentLog(self: Geometry, tree: Tree) u32 {
        return switch (tree) {
            .preprocessed => air_geometry.XOR_TABLES[0].logSize() +
                self.protocol.fri_config.log_blowup_factor,
            .main, .interaction => self.max_trace_log +
                self.protocol.fri_config.log_blowup_factor,
            .composition => self.composition_log,
        };
    }

    pub fn treeWords(self: Geometry, tree: Tree) usize {
        return switch (tree) {
            .preprocessed => self.trace_words -
                self.main_words -
                self.interaction_words,
            .main => self.main_words,
            .interaction => self.interaction_words,
            .composition => self.composition_words,
        };
    }
};

pub fn admit(request: Request) Error!Geometry {
    try exact_input.validate(request.statement);
    if (!supportedProtocol(request.protocol)) return error.UnsupportedProtocol;

    const logs = componentLogs(request.statement.log_n_rows);
    var max_trace_log: u32 = 0;
    for (logs) |log_size| max_trace_log = @max(max_trace_log, log_size);
    const variable_composition_log = std.math.add(
        u32,
        request.statement.log_n_rows,
        constants.ROUND_LOG_SPLIT[0] + 1,
    ) catch return error.GeometryOverflow;
    const fixed_composition_log =
        air_geometry.XOR_TABLES[0].logSize() + 1;
    const composition_log = @max(
        variable_composition_log,
        fixed_composition_log,
    );
    const composition_column_log = composition_log - composition_split;
    const query_log = composition_log;
    if (query_log <= 1) return error.GeometryOverflow;
    // The first FRI root commits the circle quotient at `query_log`; inner
    // line roots then cover every log through 2 before the size-two last
    // layer is interpolated and mixed separately.
    const fri_tree_count = query_log - 1;

    const main_words = try groupWords(logs, mainWidths());
    const interaction_words = try groupWords(logs, interactionWidths());
    const preprocessed_words = try groupWords(
        xorLogs(),
        [_]usize{3} ** air_geometry.XOR_TABLES.len,
    );
    const trace_words = try sum3(
        preprocessed_words,
        main_words,
        interaction_words,
    );
    const composition_words = try wordsAtLog(
        composition_columns,
        composition_column_log,
    );

    return .{
        .statement = request.statement,
        .protocol = request.protocol,
        .component_logs = logs,
        .max_trace_log = max_trace_log,
        .composition_log = composition_log,
        .composition_column_log = composition_column_log,
        .query_log = query_log,
        .fri_tree_count = fri_tree_count,
        .decommit_tree_count = trace_tree_count + fri_tree_count,
        .trace_words = trace_words,
        .main_words = main_words,
        .interaction_words = interaction_words,
        .composition_words = composition_words,
    };
}

pub fn componentLogs(log_n_rows: u32) [component_count]u32 {
    return .{
        log_n_rows,
        log_n_rows + constants.ROUND_LOG_SPLIT[0],
        log_n_rows + constants.ROUND_LOG_SPLIT[1],
        air_geometry.XOR_TABLES[0].logSize(),
        air_geometry.XOR_TABLES[1].logSize(),
        air_geometry.XOR_TABLES[2].logSize(),
        air_geometry.XOR_TABLES[3].logSize(),
        air_geometry.XOR_TABLES[4].logSize(),
    };
}

pub fn mainWidths() [component_count]usize {
    return .{
        air_geometry.SCHEDULER_MAIN_COLUMNS,
        air_geometry.ROUND_MAIN_COLUMNS,
        air_geometry.ROUND_MAIN_COLUMNS,
        air_geometry.XOR_TABLES[0].multiplicityColumns(),
        air_geometry.XOR_TABLES[1].multiplicityColumns(),
        air_geometry.XOR_TABLES[2].multiplicityColumns(),
        air_geometry.XOR_TABLES[3].multiplicityColumns(),
        air_geometry.XOR_TABLES[4].multiplicityColumns(),
    };
}

pub fn interactionWidths() [component_count]usize {
    return .{
        4 * air_geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS,
        4 * air_geometry.ROUND_INTERACTION_SECURE_COLUMNS,
        4 * air_geometry.ROUND_INTERACTION_SECURE_COLUMNS,
        4 * air_geometry.XOR_TABLES[0].interactionSecureColumns(),
        4 * air_geometry.XOR_TABLES[1].interactionSecureColumns(),
        4 * air_geometry.XOR_TABLES[2].interactionSecureColumns(),
        4 * air_geometry.XOR_TABLES[3].interactionSecureColumns(),
        4 * air_geometry.XOR_TABLES[4].interactionSecureColumns(),
    };
}

pub fn xorLogs() [air_geometry.XOR_TABLES.len]u32 {
    var logs: [air_geometry.XOR_TABLES.len]u32 = undefined;
    for (air_geometry.XOR_TABLES, 0..) |table, index| {
        logs[index] = table.logSize();
    }
    return logs;
}

fn groupWords(logs: anytype, widths: [logs.len]usize) Error!usize {
    var total: usize = 0;
    for (logs, widths) |log_size, width| {
        total = std.math.add(
            usize,
            total,
            try wordsAtLog(width, log_size),
        ) catch return error.GeometryOverflow;
    }
    return total;
}

fn wordsAtLog(columns: usize, log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return std.math.mul(
        usize,
        columns,
        @as(usize, 1) << @intCast(log_size),
    ) catch error.GeometryOverflow;
}

fn sum3(a: usize, b: usize, c: usize) Error!usize {
    const ab = std.math.add(usize, a, b) catch
        return error.GeometryOverflow;
    return std.math.add(usize, ab, c) catch error.GeometryOverflow;
}

fn supportedProtocol(value: pcs.PcsConfig) bool {
    const fri = value.fri_config;
    return value.pow_bits == 10 and
        fri.log_blowup_factor == 1 and
        fri.log_last_layer_degree_bound == 0 and
        fri.n_queries == 3 and
        fri.fold_step == 1 and
        value.lifting_log_size == null;
}

test "exact CUDA Blake geometry has four trees and eight mixed-height components" {
    const geometry = try admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = pcs.PcsConfig.default(),
    });
    try std.testing.expectEqual(
        [component_count]u32{ 4, 7, 5, 16, 14, 12, 10, 8 },
        geometry.component_logs,
    );
    try std.testing.expectEqual(@as(u32, 17), geometry.composition_log);
    try std.testing.expectEqual(@as(u32, 16), geometry.composition_column_log);
    try std.testing.expectEqual(@as(u32, 17), geometry.query_log);
    try std.testing.expectEqual(@as(u32, 16), geometry.fri_tree_count);
    try std.testing.expectEqual(@as(usize, 20), geometry.decommit_tree_count);
    try std.testing.expectEqual(
        @as(usize, 51_736_576),
        geometry.trace_words,
    );
    try std.testing.expectEqual(
        @as(usize, 524_288),
        geometry.composition_words,
    );
    try std.testing.expectEqual(@as(usize, 2_668), sampled_value_count);
}

test "exact CUDA Blake admission rejects legacy rounds and protocol drift" {
    const protocol = pcs.PcsConfig.default();
    try std.testing.expectError(
        error.InvalidNRounds,
        admit(.{
            .statement = .{ .log_n_rows = 4, .n_rounds = 9 },
            .protocol = protocol,
        }),
    );
    var changed = protocol;
    changed.pow_bits += 1;
    try std.testing.expectError(
        error.UnsupportedProtocol,
        admit(.{
            .statement = .{ .log_n_rows = 4 },
            .protocol = changed,
        }),
    );
}
