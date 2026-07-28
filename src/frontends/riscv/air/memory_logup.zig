//! Exact `memory_access` LogUp generation over full access witnesses.
//!
//! Each enabled access consumes its previous tuple and emits its next tuple at
//! its derived strict access subclock. Claims from arbitrary component shards cancel
//! against `public_logup.relationSums(...).memory_access`. Ordinary RW memory
//! that is neither public input nor public output still needs the committed
//! memory-boundary table and its Merkle leaf rows; this module does not invent
//! those missing claims.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../infra_trace.zig");
const access_clock = @import("../access_clock.zig");
const common = @import("semantics/common.zig");
const public_data = @import("public_data.zig");
const public_logup = @import("public_logup.zig");
const relation_challenges = @import("relation_challenges.zig");

pub const Error = error{
    InvalidLogSize,
    TooManyAccesses,
    ZeroDenominator,
    LogupSumNonZero,
    OutOfMemory,
};

pub const AccessWitness = struct {
    addr_space: QM31,
    addr: QM31,
    previous_clock: QM31,
    previous: [4]QM31,
    clock: QM31,
    next: [4]QM31,
    enabler: QM31,

    pub fn fromAccess(
        addr_space: u1,
        access: common.Qm31.Access,
        clock: QM31,
        enabler: QM31,
    ) AccessWitness {
        return .{
            .addr_space = base(addr_space),
            .addr = access.addr,
            .previous_clock = access.previous_clock,
            .previous = access.previous,
            .clock = clock,
            .next = access.next,
            .enabler = enabler,
        };
    }

    pub fn previousTuple(self: AccessWitness) [7]QM31 {
        return .{
            self.addr_space,
            self.addr,
            self.previous_clock,
            self.previous[0],
            self.previous[1],
            self.previous[2],
            self.previous[3],
        };
    }

    pub fn nextTuple(self: AccessWitness) [7]QM31 {
        return .{
            self.addr_space,
            self.addr,
            self.clock,
            self.next[0],
            self.next[1],
            self.next[2],
            self.next[3],
        };
    }
};

/// Pair-batched row fraction `-enabler/previous + enabler/next`.
pub const RowPair = struct {
    previous_denominator: QM31,
    next_denominator: QM31,
    enabler: QM31,
};

pub fn rowPair(
    relation: *const relation_challenges.RelationElements(7),
    access: AccessWitness,
) RowPair {
    return .{
        .previous_denominator = relation.combineSecure(access.previousTuple()),
        .next_denominator = relation.combineSecure(access.nextTuple()),
        .enabler = access.enabler,
    };
}

pub fn pairConstraint(
    sum_value: QM31,
    previous_sum: QM31,
    is_first: QM31,
    claimed: QM31,
    pair: RowPair,
) QM31 {
    const delta = sum_value.sub(previous_sum).add(is_first.mul(claimed));
    const expected_numerator = pair.enabler.neg().mul(pair.next_denominator)
        .add(pair.enabler.mul(pair.previous_denominator));
    return delta.mul(pair.previous_denominator).mul(pair.next_denominator)
        .sub(expected_numerator);
}

/// Four bit-reversed committed coordinates and their trace-order predecessor
/// mask. The predecessor columns are evaluator inputs and are not committed.
pub const CumulativeColumns = struct {
    columns: [4][]M31,
    previous_columns: [4][]M31,
    claimed: QM31,

    pub fn deinit(self: *CumulativeColumns, allocator: std.mem.Allocator) void {
        for (&self.columns) |column| allocator.free(column);
        for (&self.previous_columns) |column| allocator.free(column);
        self.* = undefined;
    }
};

/// Generates a shard-local cumulative column over the `2^log_size` domain.
/// Padding copies the prior sum without evaluating a denominator, so arbitrary
/// zero-filled padding cannot introduce inversion failures or change the claim.
/// Returned columns use the exact bit-reversed order expected by the PCS.
pub fn generate(
    allocator: std.mem.Allocator,
    accesses: []const AccessWitness,
    log_size: u32,
    relation: *const relation_challenges.RelationElements(7),
) Error!CumulativeColumns {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    if (accesses.len > domain_size) return error.TooManyAccesses;

    const trace_sums = try allocator.alloc(QM31, domain_size);
    defer allocator.free(trace_sums);

    var accumulator = QM31.zero();
    for (0..domain_size) |row| {
        if (row < accesses.len and !accesses[row].enabler.isZero()) {
            const pair = rowPair(relation, accesses[row]);
            const previous_inverse = pair.previous_denominator.inv() catch
                return error.ZeroDenominator;
            const next_inverse = pair.next_denominator.inv() catch
                return error.ZeroDenominator;
            accumulator = accumulator
                .sub(pair.enabler.mul(previous_inverse))
                .add(pair.enabler.mul(next_inverse));
        }
        trace_sums[row] = accumulator;
    }

    var columns = try allocateColumns(allocator, domain_size);
    errdefer freeColumns(allocator, &columns);
    var previous_columns = try allocateColumns(allocator, domain_size);
    errdefer freeColumns(allocator, &previous_columns);
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);

    for (0..domain_size) |row| {
        const destination = table.map(row);
        const current = trace_sums[row].toM31Array();
        const previous = trace_sums[(row + domain_size - 1) % domain_size].toM31Array();
        for (0..4) |coordinate| {
            columns[coordinate][destination] = current[coordinate];
            previous_columns[coordinate][destination] = previous[coordinate];
        }
    }
    return .{
        .columns = columns,
        .previous_columns = previous_columns,
        .claimed = accumulator,
    };
}

/// Memory claims cancel only against the public memory-access boundary. The
/// CPU and Merkle public sums are separate relation domains by construction.
pub fn verifyCancellation(
    shard_claims: []const QM31,
    public_memory_boundary: QM31,
) Error!void {
    var total = public_memory_boundary;
    for (shard_claims) |claim| total = total.add(claim);
    if (!total.isZero()) return error.LogupSumNonZero;
}

fn base(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn allocateColumns(allocator: std.mem.Allocator, len: usize) Error![4][]M31 {
    var columns: [4][]M31 = undefined;
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

fn limbs(value: u32) [4]QM31 {
    return .{
        base(@as(u8, @truncate(value))),
        base(@as(u8, @truncate(value >> 8))),
        base(@as(u8, @truncate(value >> 16))),
        base(@as(u8, @truncate(value >> 24))),
    };
}

fn witness(
    addr_space: u1,
    addr: u32,
    previous_clock: u32,
    previous_value: u32,
    clock: u32,
    next_value: u32,
) AccessWitness {
    return .{
        .addr_space = base(addr_space),
        .addr = base(addr),
        .previous_clock = base(previous_clock),
        .previous = limbs(previous_value),
        .clock = base(clock),
        .next = limbs(next_value),
        .enabler = QM31.one(),
    };
}

fn boundaryData() public_data.PublicData {
    return .{
        .initial_pc = 0,
        .final_pc = 0,
        .clock = 0,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = public_data.Completion.canonicalSelfLoop(0),
        .io_entries = .{
            .input_start = 0,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 0,
            .output_data_addr = 0,
            .output_words = &.{},
        },
    };
}

test "memory LogUp: aliased register accesses chain across strict subclocks and shards" {
    const relations = relation_challenges.Relations.dummy();
    var data = boundaryData();
    data.clock = 1;
    data.initial_regs[1] = 5;
    data.final_regs[1] = 6;
    const source_clock = access_clock.encode(1, .first);
    const destination_clock = access_clock.encode(1, .second);
    data.reg_last_clock[1] = destination_clock;

    // ADDI x1,x1,1: source read then destination write. The intermediate
    // tuple at the first subclock must cancel even when the accesses are sharded.
    const accesses = [_]AccessWitness{
        witness(0, 1, 0, 5, source_clock, 5),
        witness(0, 1, source_clock, 5, destination_clock, 6),
    };
    var first = try generate(std.testing.allocator, accesses[0..1], 1, &relations.memory_access);
    defer first.deinit(std.testing.allocator);
    var second = try generate(std.testing.allocator, accesses[1..2], 1, &relations.memory_access);
    defer second.deinit(std.testing.allocator);
    const public_sums = try public_logup.relationSums(&data, &relations);
    try verifyCancellation(&.{ first.claimed, second.claimed }, public_sums.memory_access);
}

test "memory LogUp: load then store closes public input and output boundaries" {
    const relations = relation_challenges.Relations.dummy();
    const addr: u32 = 0x0018_0000;
    const initial: u32 = 0x0403_0201;
    const final: u32 = 0x0807_0605;
    const input_words = [_]u32{initial};
    const output_words = [_]public_data.OutputWord{.{
        .addr = addr,
        .value = final,
        .clock = 2,
    }};
    var data = boundaryData();
    data.io_entries = .{
        .input_start = addr,
        .input_len = 4,
        .input_words = &input_words,
        .output_len = 4,
        .output_len_addr = addr,
        .output_data_addr = addr,
        .output_words = &output_words,
    };

    const accesses = [_]AccessWitness{
        witness(1, addr, 0, initial, 1, initial), // load
        witness(1, addr, 1, initial, 2, final), // store
    };
    var generated = try generate(std.testing.allocator, &accesses, 2, &relations.memory_access);
    defer generated.deinit(std.testing.allocator);
    const public_sums = try public_logup.relationSums(&data, &relations);
    try verifyCancellation(&.{generated.claimed}, public_sums.memory_access);

    // Padding rows repeat the final cumulative value exactly.
    for (0..4) |coordinate| {
        try std.testing.expectEqual(
            generated.columns[coordinate][1].toU32(),
            generated.columns[coordinate][3].toU32(),
        );
    }
}

test "memory LogUp: tuple mutations cannot be repaired by the public boundary" {
    const relations = relation_challenges.Relations.dummy();
    var data = boundaryData();
    data.initial_regs[2] = 9;
    data.final_regs[2] = 10;
    data.reg_last_clock[2] = 3;
    const public_sums = try public_logup.relationSums(&data, &relations);

    var honest = witness(0, 2, 0, 9, 3, 10);
    var generated = try generate(std.testing.allocator, &.{honest}, 0, &relations.memory_access);
    defer generated.deinit(std.testing.allocator);
    try verifyCancellation(&.{generated.claimed}, public_sums.memory_access);

    honest.previous[0] = base(8);
    var bad_value = try generate(std.testing.allocator, &.{honest}, 0, &relations.memory_access);
    defer bad_value.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyCancellation(&.{bad_value.claimed}, public_sums.memory_access),
    );

    honest = witness(0, 2, 0, 9, 4, 10);
    var bad_clock = try generate(std.testing.allocator, &.{honest}, 0, &relations.memory_access);
    defer bad_clock.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyCancellation(&.{bad_clock.claimed}, public_sums.memory_access),
    );

    honest = witness(1, 2, 0, 9, 3, 10);
    var bad_space = try generate(std.testing.allocator, &.{honest}, 0, &relations.memory_access);
    defer bad_space.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyCancellation(&.{bad_space.claimed}, public_sums.memory_access),
    );
}

test "memory LogUp: disabled rows are padding-safe" {
    const relations = relation_challenges.Relations.dummy();
    var disabled = witness(0, 1, 0, 1, 1, 2);
    disabled.enabler = QM31.zero();
    var generated = try generate(std.testing.allocator, &.{disabled}, 2, &relations.memory_access);
    defer generated.deinit(std.testing.allocator);
    try std.testing.expect(generated.claimed.isZero());
    for (generated.columns) |column| {
        for (column) |value| try std.testing.expect(value.isZero());
    }
}

test "memory LogUp: generated rows satisfy the pair-batched AIR recurrence" {
    const relations = relation_challenges.Relations.dummy();
    const accesses = [_]AccessWitness{
        witness(0, 4, 0, 11, 1, 11),
        witness(0, 4, 1, 11, 2, 12),
    };
    var generated = try generate(std.testing.allocator, &accesses, 2, &relations.memory_access);
    defer generated.deinit(std.testing.allocator);

    var previous_sum = generated.claimed;
    const table = try infra.BitReversalTable.init(std.testing.allocator, 2);
    defer table.deinit(std.testing.allocator);
    for (0..4) |row| {
        const committed_row = table.map(row);
        const sum_value = QM31.fromM31(
            generated.columns[0][committed_row],
            generated.columns[1][committed_row],
            generated.columns[2][committed_row],
            generated.columns[3][committed_row],
        );
        const stored_previous = QM31.fromM31(
            generated.previous_columns[0][committed_row],
            generated.previous_columns[1][committed_row],
            generated.previous_columns[2][committed_row],
            generated.previous_columns[3][committed_row],
        );
        try std.testing.expect(stored_previous.eql(previous_sum));
        const pair = if (row < accesses.len)
            rowPair(&relations.memory_access, accesses[row])
        else
            rowPair(&relations.memory_access, .{
                .addr_space = QM31.zero(),
                .addr = QM31.zero(),
                .previous_clock = QM31.zero(),
                .previous = .{QM31.zero()} ** 4,
                .clock = QM31.zero(),
                .next = .{QM31.zero()} ** 4,
                .enabler = QM31.zero(),
            });
        const constraint = pairConstraint(
            sum_value,
            previous_sum,
            if (row == 0) QM31.one() else QM31.zero(),
            generated.claimed,
            pair,
        );
        try std.testing.expect(constraint.isZero());
        previous_sum = sum_value;
    }
}
