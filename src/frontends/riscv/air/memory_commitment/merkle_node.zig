//! Exact Stark-V Section 19 sparse-Merkle node AIR.
//!
//! Each row emits two child claims, consumes one parent claim, emits the
//! 16-lane Poseidon2 input, and consumes the narrow one-lane output. The
//! separate Poseidon2 component proves the permutation and cancels the latter
//! two terms.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const infra = @import("../../infra_trace.zig");
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const poseidon2_air = @import("poseidon2_air.zig");
const sparse_merkle = @import("sparse_merkle.zig");

/// enabler, index, depth, lhs, rhs, cur, lhs_mult, rhs_mult, cur_mult, root.
pub const N_MAIN_COLUMNS: usize = 10;
/// Exact schema pairing: children; parent + Poseidon input; Poseidon output.
pub const N_SUMS: usize = 3;
pub const N_INTERACTION_COLUMNS: usize = N_SUMS * 4;
pub const N_CONSTRAINTS: usize = N_SUMS + 7;
const INV2: QM31 = QM31.fromBase(M31.fromU64(1073741824));

pub const NodeRow = struct {
    index: u32,
    depth: u32,
    lhs: u32,
    rhs: u32,
    cur: u32,
    lhs_mult: u8,
    rhs_mult: u8,
    cur_mult: u8,
    root: u32,

    pub fn fromNode(node: sparse_merkle.Node, root: u32) NodeRow {
        return .{
            .index = node.index,
            .depth = node.depth,
            .lhs = node.left.value,
            .rhs = node.right.value,
            .cur = node.current.value,
            .lhs_mult = node.left.multiplicity,
            .rhs_mult = node.right.multiplicity,
            .cur_mult = node.current.multiplicity,
            .root = root,
        };
    }

    pub fn poseidonCall(self: NodeRow) poseidon2_air.Call {
        return poseidon2_air.Call.narrowWithOutput(self.lhs, self.rhs, self.cur);
    }
};

pub const Columns = struct {
    values: [N_MAIN_COLUMNS][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.values);
        self.* = undefined;
    }
};

pub const Claims = struct {
    sums: [N_SUMS]QM31,

    pub fn total(self: Claims) QM31 {
        var result = QM31.zero();
        for (self.sums) |sum| result = result.add(sum);
        return result;
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,

    pub fn deinit(self: *Interaction, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        self.* = undefined;
    }
};

pub fn generateMain(
    allocator: std.mem.Allocator,
    rows: []const NodeRow,
    log_size: u32,
) !Columns {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    var columns = try allocateColumns(allocator, N_MAIN_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    for (&columns) |column| @memset(column, M31.zero());
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (rows, 0..) |row, index| {
        const dst = table.map(index);
        const values = mainValues(row);
        for (values, 0..) |value, column| columns[column][dst] = value;
    }
    return .{ .values = columns };
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    rows: []const NodeRow,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    const pairs = try allocator.alloc([N_SUMS]logup.RowPair, size);
    defer allocator.free(pairs);
    for (0..size) |index| pairs[index] = if (index < rows.len)
        rowPairsFromNode(rows[index], relations)
    else
        paddingPairs();

    var cumulative: [N_SUMS]logup.CumulativeColumn = undefined;
    var initialized: usize = 0;
    defer for (cumulative[0..initialized]) |*column| column.deinit(allocator);
    for (&cumulative, 0..) |*column, sum_index| {
        const row_pairs = try allocator.alloc(logup.RowPair, size);
        defer allocator.free(row_pairs);
        for (pairs, row_pairs) |row, *pair| pair.* = row[sum_index];
        column.* = try logup.cumulativeColumn(allocator, row_pairs);
        initialized += 1;
    }

    var columns = try allocateColumns(allocator, N_INTERACTION_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (0..size) |row| {
        const dst = table.map(row);
        for (0..N_SUMS) |sum_index| {
            const current = cumulative[sum_index].sums[row].toM31Array();
            for (0..4) |coordinate| {
                columns[sum_index * 4 + coordinate][dst] = current[coordinate];
            }
        }
    }
    return .{
        .columns = columns,
        .claims = .{ .sums = .{
            cumulative[0].claimed,
            cumulative[1].claimed,
            cumulative[2].claimed,
        } },
    };
}

/// Parallel cache-bounded interaction generation for production-sized trees.
/// Rows remain in canonical trace order until the final disjoint transpose,
/// avoiding the full-domain pair matrix and repeated bit-reversed scattering
/// in the scalar compatibility path above.
pub fn generateInteractionParallel(
    allocator: std.mem.Allocator,
    rows: []const NodeRow,
    log_size: u32,
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    const generated = try logup.generateParallelColumns(
        N_SUMS,
        allocator,
        InteractionContext{ .rows = rows, .relations = relations },
        log_size,
        pool,
    );
    return .{
        .columns = generated.columns,
        .claims = .{ .sums = generated.claims },
    };
}

const InteractionContext = struct {
    rows: []const NodeRow,
    relations: *const relations_mod.Relations,

    pub fn rowPairsAt(self: @This(), row: usize) [N_SUMS]logup.RowPair {
        if (row < self.rows.len) return rowPairsFromNode(self.rows[row], self.relations);
        return paddingPairs();
    }
};

pub fn evaluate(
    main: [N_MAIN_COLUMNS]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_CONSTRAINTS]QM31 {
    const pairs = rowPairs(main, relations);
    var result: [N_CONSTRAINTS]QM31 = undefined;
    for (0..N_SUMS) |index| {
        result[index] = logup.pairConstraint(
            sums[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }
    const enabler = main[0];
    result[N_SUMS] = enabler.sub(is_active);
    result[N_SUMS + 1] = multiplicityConstraint(main[6]);
    result[N_SUMS + 2] = multiplicityConstraint(main[7]);
    result[N_SUMS + 3] = multiplicityConstraint(main[8]);
    const is_padding = QM31.one().sub(is_active);
    result[N_SUMS + 4] = main[6].mul(is_padding);
    result[N_SUMS + 5] = main[7].mul(is_padding);
    result[N_SUMS + 6] = main[8].mul(is_padding);
    return result;
}

pub fn rowPairsFromNode(row: NodeRow, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const values = mainValues(row);
    var secure: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&secure, values) |*dst, value| dst.* = QM31.fromBase(value);
    return rowPairs(secure, relations);
}

pub fn rowPairs(main: [N_MAIN_COLUMNS]QM31, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const list = entries(main);
    return .{
        list.pair(0, relations) catch unreachable,
        list.pair(1, relations) catch unreachable,
        list.pair(2, relations) catch unreachable,
    };
}

pub fn entries(main: [N_MAIN_COLUMNS]QM31) lookup_entry.List {
    const enabler = main[0];
    const index = main[1];
    const depth = main[2];
    const lhs = main[3];
    const rhs = main[4];
    const cur = main[5];
    const root = main[9];
    const one = QM31.one();
    var poseidon_input = [_]QM31{QM31.zero()} ** poseidon2_air.WIDTH;
    poseidon_input[0] = lhs;
    poseidon_input[1] = rhs;
    var poseidon_output = [_]QM31{QM31.zero()} ** poseidon2_air.WIDTH;
    poseidon_output[0] = cur;
    var list = lookup_entry.List{};
    append(&list, .merkle, main[6], .{ index, depth, lhs, root });
    append(&list, .merkle, main[7], .{ index.add(one), depth, rhs, root });
    append(&list, .merkle, main[8].neg(), .{ index.mul(INV2), depth.sub(one), cur, root });
    append(&list, .poseidon2, enabler, poseidon_input);
    append(&list, .poseidon2, enabler.neg(), poseidon_output);
    return list;
}

pub fn paddingPairs() [N_SUMS]logup.RowPair {
    const zero = QM31.zero();
    const one = QM31.one();
    return .{
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
    };
}

pub fn calls(
    allocator: std.mem.Allocator,
    rows: []const NodeRow,
) ![]poseidon2_air.Call {
    const result = try allocator.alloc(poseidon2_air.Call, rows.len);
    for (rows, result) |row, *call| call.* = row.poseidonCall();
    return result;
}

/// Verify the combined memory-tree relation. Exact pair batching mixes Merkle
/// and Poseidon terms, so cancellation is checked over the coupled domain.
pub fn verifyCancellation(
    node_claims: Claims,
    poseidon_claims: poseidon2_air.Claims,
    leaf_claim: QM31,
    public_root_emit: QM31,
) error{LogupSumNonZero}!void {
    const total = node_claims.total().add(poseidon_claims.total())
        .add(leaf_claim).add(public_root_emit);
    if (!total.isZero()) return error.LogupSumNonZero;
}

fn mainValues(row: NodeRow) [N_MAIN_COLUMNS]M31 {
    return .{
        M31.one(),
        M31.fromU64(row.index),
        M31.fromU64(row.depth),
        M31.fromU64(row.lhs),
        M31.fromU64(row.rhs),
        M31.fromU64(row.cur),
        M31.fromU64(row.lhs_mult),
        M31.fromU64(row.rhs_mult),
        M31.fromU64(row.cur_mult),
        M31.fromU64(row.root),
    };
}

fn multiplicityConstraint(value: QM31) QM31 {
    const one = QM31.one();
    const two = QM31.fromBase(M31.fromU64(2));
    return value.mul(value.sub(one)).mul(value.sub(two));
}

fn allocateColumns(allocator: std.mem.Allocator, comptime n: usize, len: usize) ![n][]M31 {
    var columns: [n][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, len);
        initialized += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

fn append(list: *lookup_entry.List, domain: lookup_entry.Domain, numerator: QM31, values: anytype) void {
    var item = lookup_entry.Entry{ .domain = domain, .numerator = numerator, .arity = values.len };
    inline for (values, 0..) |value, index| item.values[index] = value;
    list.append(item);
}

fn rootEmit(tree: sparse_merkle.Tree, relations: *const relations_mod.Relations) !QM31 {
    const root = QM31.fromBase(M31.fromU64(tree.root));
    return try relations.merkle.combineSecure(.{ QM31.zero(), QM31.zero(), root, root }).inv();
}

fn expectCancellationFails(
    rows: []const NodeRow,
    honest_calls: []const poseidon2_air.Call,
    leaf_claim: QM31,
    public_emit: QM31,
    relations: *const relations_mod.Relations,
) !void {
    const log_size: u32 = @max(4, std.math.log2_int_ceil(usize, rows.len));
    var nodes = try generateInteraction(std.testing.allocator, rows, log_size, relations);
    defer nodes.deinit(std.testing.allocator);
    var hashes = try poseidon2_air.generateInteraction(
        std.testing.allocator,
        honest_calls,
        log_size,
        relations,
    );
    defer hashes.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyCancellation(nodes.claims, hashes.claims, leaf_claim, public_emit),
    );
}

test "Merkle node AIR: leaves, nodes, hashes, and public root cancel" {
    const boundary = @import("boundary.zig");
    const memory_interaction = @import("interaction.zig");
    const relations = relations_mod.Relations.dummy();
    var boundary_claims = try boundary.build(std.testing.allocator, &.{.{
        .addr = 0x1000,
        .initial_word = 0x11223344,
        .final_word = 0x55667788,
        .final_clock = 9,
    }});
    defer boundary_claims.deinit(std.testing.allocator);
    const tree = boundary_claims.initial_tree.?;

    const rows = try std.testing.allocator.alloc(NodeRow, tree.nodes.len);
    defer std.testing.allocator.free(rows);
    for (tree.nodes, rows) |node, *row| row.* = NodeRow.fromNode(node, tree.root);
    const hash_calls = try calls(std.testing.allocator, rows);
    defer std.testing.allocator.free(hash_calls);
    const log_size: u32 = @max(4, std.math.log2_int_ceil(usize, rows.len));
    var nodes = try generateInteraction(std.testing.allocator, rows, log_size, &relations);
    defer nodes.deinit(std.testing.allocator);
    var hashes = try poseidon2_air.generateInteraction(
        std.testing.allocator,
        hash_calls,
        log_size,
        &relations,
    );
    defer hashes.deinit(std.testing.allocator);
    var leaves = try memory_interaction.generate(
        std.testing.allocator,
        boundary_claims.rows[0..1],
        4,
        &relations,
    );
    defer leaves.deinit(std.testing.allocator);
    const leaf_claim = try memory_interaction.diagnosticSum(
        boundary_claims.rows[0..1],
        .merkle,
        &relations,
    );
    try verifyCancellation(
        nodes.claims,
        hashes.claims,
        leaf_claim,
        try rootEmit(tree, &relations),
    );

    inline for (.{ "lhs", "rhs", "index", "cur", "root" }) |mutation| {
        const bad_rows = try std.testing.allocator.dupe(NodeRow, rows);
        defer std.testing.allocator.free(bad_rows);
        if (std.mem.eql(u8, mutation, "lhs")) bad_rows[0].lhs ^= 1;
        if (std.mem.eql(u8, mutation, "rhs")) bad_rows[0].rhs ^= 1;
        if (std.mem.eql(u8, mutation, "index")) bad_rows[0].index ^= 1;
        if (std.mem.eql(u8, mutation, "cur")) bad_rows[0].cur ^= 1;
        if (std.mem.eql(u8, mutation, "root")) bad_rows[0].root ^= 1;
        try expectCancellationFails(
            bad_rows,
            hash_calls,
            leaf_claim,
            try rootEmit(tree, &relations),
            &relations,
        );
    }
}

test "Merkle node AIR: inactive rows cannot inject un-hashed tree edges" {
    const zero = QM31.zero();
    const relations = relations_mod.Relations.dummy();
    var main = [_]QM31{zero} ** N_MAIN_COLUMNS;
    main[6] = QM31.one();
    main[7] = QM31.one();
    main[8] = QM31.fromBase(M31.fromU64(2));

    const constraints = evaluate(
        main,
        zero,
        zero,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try std.testing.expect(!constraints[N_SUMS + 4].isZero());
    try std.testing.expect(!constraints[N_SUMS + 5].isZero());
    try std.testing.expect(!constraints[N_SUMS + 6].isZero());

    main[6] = zero;
    main[7] = zero;
    main[8] = zero;
    const padding = evaluate(
        main,
        zero,
        zero,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    for (padding[N_SUMS + 4 ..]) |constraint| try std.testing.expect(constraint.isZero());
}
