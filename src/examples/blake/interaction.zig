//! Exact eight-component Blake interaction trace.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("stwo_prover_engine").transaction;
const builder = @import("interaction_builder.zig");
const constants = @import("constants.zig");
const geometry = @import("geometry.zig");
const input = @import("exact_input.zig");
const round_trace = @import("round_trace.zig");
const scheduler_trace = @import("scheduler_trace.zig");
const statement_mod = @import("statement.zig");
const xor_tables = @import("xor_tables.zig");

pub const PreparedInteraction = struct {
    columns: prover_transaction.OwnedColumns,
    elements: statement_mod.AllElements,
    statement: statement_mod.PreparedStatement,

    pub fn deinit(self: *PreparedInteraction, allocator: std.mem.Allocator) void {
        self.columns.deinit(allocator);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    channel: anytype,
    prepared: *const input.PreparedInput,
) !PreparedInteraction {
    try input.validate(prepared.request);
    const elements = try statement_mod.AllElements.draw(allocator, channel);
    var columns = std.ArrayList(prover_pcs.ColumnEvaluation).empty;
    errdefer {
        for (columns.items) |column| allocator.free(column.values);
        columns.deinit(allocator);
    }

    const scheduler = try generateScheduler(
        allocator,
        prepared.request.log_n_rows,
        &elements,
    );
    try appendOutput(allocator, &columns, scheduler);

    var round_claims: [constants.ROUND_LOG_SPLIT.len]QM31 = undefined;
    for (constants.ROUND_LOG_SPLIT, 0..) |split, component_index| {
        const output = try generateRound(
            allocator,
            prepared.request.log_n_rows,
            component_index,
            &elements,
        );
        round_claims[component_index] = output.claimed_sum;
        try appendOutput(allocator, &columns, output);
        std.debug.assert(
            columns.items.len ==
                geometry.ROUND_INTERACTION_OFFSETS[component_index] +
                    4 * geometry.ROUND_INTERACTION_SECURE_COLUMNS,
        );
        _ = split;
    }

    var accumulator = try xor_tables.Accumulator.init(allocator);
    defer accumulator.deinit(allocator);
    try input.populateXorAccumulator(prepared.request.log_n_rows, &accumulator);

    var xor_claims: [geometry.XOR_TABLES.len]QM31 = undefined;
    for (0..geometry.XOR_TABLES.len) |table_index| {
        const output = try generateXorTable(
            allocator,
            table_index,
            &accumulator,
            &elements,
        );
        xor_claims[table_index] = output.claimed_sum;
        try appendOutput(allocator, &columns, output);
    }
    if (columns.items.len != geometry.INTERACTION_COLUMNS)
        return error.InvalidPreparedGeometry;

    const prepared_statement = statement_mod.PreparedStatement{
        .stmt0 = .{ .log_size = prepared.request.log_n_rows },
        .stmt1 = .{
            .scheduler_claimed_sum = scheduler.claimed_sum,
            .round_claimed_sums = round_claims,
            .xor_claimed_sums = xor_claims,
        },
    };
    try statement_mod.verify(prepared_statement);
    return .{
        .columns = prover_transaction.OwnedColumns.init(
            try columns.toOwnedSlice(allocator),
        ),
        .elements = elements,
        .statement = prepared_statement,
    };
}

fn appendOutput(
    allocator: std.mem.Allocator,
    columns: *std.ArrayList(prover_pcs.ColumnEvaluation),
    output: builder.Output,
) !void {
    var moved = false;
    defer if (!moved) {
        for (output.columns) |column| allocator.free(column.values);
        allocator.free(output.columns);
    };
    try columns.appendSlice(allocator, output.columns);
    allocator.free(output.columns);
    moved = true;
}

const SchedulerContext = struct {
    log_size: u32,
    elements: *const statement_mod.AllElements,

    fn fill(
        self: @This(),
        storage: usize,
        fractions: []builder.Fraction,
    ) !void {
        if (fractions.len != geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS)
            return error.InvalidPreparedGeometry;
        const scheduler_input =
            scheduler_trace.inputForPackedLane(storage / 16, storage % 16);
        const output = scheduler_trace.generate(scheduler_input);
        var denominators: [constants.N_ROUNDS]QM31 = undefined;
        for (0..constants.N_ROUNDS) |round_index| {
            var tuple: [constants.N_ROUND_INPUT_FELTS]M31 = undefined;
            var tuple_index: usize = 0;
            const round_input = output.round_inputs[round_index];
            appendWords(&tuple, &tuple_index, round_input.state);
            const output_state = if (round_index + 1 < constants.N_ROUNDS)
                output.round_inputs[round_index + 1].state
            else
                output.final_state;
            appendWords(&tuple, &tuple_index, output_state);
            appendWords(&tuple, &tuple_index, round_input.message);
            denominators[round_index] = self.elements.round.combineBase(&tuple);
        }
        for (0..constants.N_ROUNDS / 2) |batch| {
            const p0 = denominators[2 * batch];
            const p1 = denominators[2 * batch + 1];
            fractions[batch] = .{
                .numerator = p0.add(p1),
                .denominator = p0.mul(p1),
            };
        }

        var blake_tuple: [constants.N_ROUND_INPUT_FELTS]M31 = undefined;
        var tuple_index: usize = 0;
        appendWords(&blake_tuple, &tuple_index, scheduler_input.state);
        appendWords(&blake_tuple, &tuple_index, output.final_state);
        appendWords(&blake_tuple, &tuple_index, scheduler_input.message);
        fractions[constants.N_ROUNDS / 2] = .{
            .numerator = QM31.zero(),
            .denominator = self.elements.blake.combineBase(&blake_tuple),
        };
    }
};

fn generateScheduler(
    allocator: std.mem.Allocator,
    log_size: u32,
    elements: *const statement_mod.AllElements,
) !builder.Output {
    return builder.build(
        allocator,
        log_size,
        geometry.SCHEDULER_INTERACTION_SECURE_COLUMNS,
        SchedulerContext{ .log_size = log_size, .elements = elements },
        SchedulerContext.fill,
    );
}

const XorLookup = struct {
    width: u5,
    a: u32,
    b: u32,
    c: u32,
};

const LookupObserver = struct {
    lookups: *[128]XorLookup,
    count: usize = 0,

    pub fn record(self: *@This(), width: u5, a: u32, b: u32, c: u32) void {
        self.lookups[self.count] = .{ .width = width, .a = a, .b = b, .c = c };
        self.count += 1;
    }
};

const RoundContext = struct {
    base_log_size: u32,
    component_index: usize,
    elements: *const statement_mod.AllElements,

    fn fill(
        self: @This(),
        storage: usize,
        fractions: []builder.Fraction,
    ) !void {
        if (fractions.len != geometry.ROUND_INTERACTION_SECURE_COLUMNS)
            return error.InvalidPreparedGeometry;
        const round_input = try input.roundInputForStorage(
            self.base_log_size,
            self.component_index,
            storage,
        );
        var lookups: [128]XorLookup = undefined;
        var observer = LookupObserver{ .lookups = &lookups };
        const output = round_trace.generate(
            round_input.state,
            round_input.message,
            &observer,
        );
        if (observer.count != lookups.len) return error.InvalidPreparedGeometry;

        for (0..lookups.len / 2) |batch| {
            const first = lookups[2 * batch];
            const second = lookups[2 * batch + 1];
            const p0 = xorDenominator(self.elements, first);
            const p1 = xorDenominator(self.elements, second);
            fractions[batch] = .{
                .numerator = p0.add(p1),
                .denominator = p0.mul(p1),
            };
        }

        var tuple: [constants.N_ROUND_INPUT_FELTS]M31 = undefined;
        var tuple_index: usize = 0;
        appendWords(&tuple, &tuple_index, round_input.state);
        appendWords(&tuple, &tuple_index, output.output_state);
        appendWords(&tuple, &tuple_index, round_input.message);
        fractions[lookups.len / 2] = .{
            .numerator = QM31.one().neg(),
            .denominator = self.elements.round.combineBase(&tuple),
        };
    }
};

fn generateRound(
    allocator: std.mem.Allocator,
    base_log_size: u32,
    component_index: usize,
    elements: *const statement_mod.AllElements,
) !builder.Output {
    return builder.build(
        allocator,
        base_log_size + constants.ROUND_LOG_SPLIT[component_index],
        geometry.ROUND_INTERACTION_SECURE_COLUMNS,
        RoundContext{
            .base_log_size = base_log_size,
            .component_index = component_index,
            .elements = elements,
        },
        RoundContext.fill,
    );
}

const XorTableContext = struct {
    table_index: usize,
    accumulator: *const xor_tables.Accumulator,
    elements: *const statement_mod.AllElements,

    fn fill(
        self: @This(),
        storage: usize,
        fractions: []builder.Fraction,
    ) !void {
        const table = geometry.XOR_TABLES[self.table_index];
        if (fractions.len != table.interactionSecureColumns())
            return error.InvalidPreparedGeometry;
        const multiplicities = self.accumulator.tables[self.table_index];
        const limb_bits = table.limbBits();
        const limb_mask = (@as(u32, 1) << @intCast(limb_bits)) - 1;
        const row: u32 = @intCast(storage);
        const al = row >> @intCast(limb_bits);
        const bl = row & limb_mask;

        for (fractions, 0..) |*fraction, batch| {
            const first_index = 2 * batch;
            const second_index = first_index + 1;
            const first = tableEntry(table, first_index, al, bl);
            const p0 = self.elements.xor[self.table_index].combineBase(&first);
            const m0 = multiplicities[first_index][storage];
            if (second_index < multiplicities.len) {
                const second = tableEntry(table, second_index, al, bl);
                const p1 = self.elements.xor[self.table_index].combineBase(&second);
                const m1 = multiplicities[second_index][storage];
                fraction.* = .{
                    .numerator = p1.mulM31(m0)
                        .add(p0.mulM31(m1))
                        .neg(),
                    .denominator = p0.mul(p1),
                };
            } else {
                fraction.* = .{
                    .numerator = QM31.fromBase(m0).neg(),
                    .denominator = p0,
                };
            }
        }
    }
};

fn generateXorTable(
    allocator: std.mem.Allocator,
    table_index: usize,
    accumulator: *const xor_tables.Accumulator,
    elements: *const statement_mod.AllElements,
) !builder.Output {
    const table = geometry.XOR_TABLES[table_index];
    return builder.build(
        allocator,
        table.logSize(),
        table.interactionSecureColumns(),
        XorTableContext{
            .table_index = table_index,
            .accumulator = accumulator,
            .elements = elements,
        },
        XorTableContext.fill,
    );
}

fn tableEntry(
    table: geometry.XorTable,
    column: usize,
    al: u32,
    bl: u32,
) [3]M31 {
    const ah: u32 = @intCast(column >> @intCast(table.expand_bits));
    const bh: u32 = @intCast(
        column & ((@as(usize, 1) << @intCast(table.expand_bits)) - 1),
    );
    const a = (ah << @intCast(table.limbBits())) | al;
    const b = (bh << @intCast(table.limbBits())) | bl;
    return .{
        M31.fromCanonical(a),
        M31.fromCanonical(b),
        M31.fromCanonical(a ^ b),
    };
}

fn xorDenominator(
    elements: *const statement_mod.AllElements,
    lookup: XorLookup,
) QM31 {
    return elements.xorForWidth(lookup.width).combineBase(&.{
        M31.fromCanonical(lookup.a),
        M31.fromCanonical(lookup.b),
        M31.fromCanonical(lookup.c),
    });
}

fn appendWords(
    output: *[constants.N_ROUND_INPUT_FELTS]M31,
    index: *usize,
    words: [constants.STATE_SIZE]u32,
) void {
    for (words) |word| {
        output[index.*] = M31.fromCanonical(word & 0xffff);
        index.* += 1;
        output[index.*] = M31.fromCanonical(word >> 16);
        index.* += 1;
    }
}

test "exact Blake interaction closes all eight component claims" {
    const allocator = std.testing.allocator;
    var prepared = try input.prepare(allocator, .{ .log_n_rows = 4 });
    defer prepared.deinit(allocator);

    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    var output = try generate(allocator, &channel, &prepared);
    defer output.deinit(allocator);

    const columns = output.columns.columns.?;
    try std.testing.expectEqual(geometry.INTERACTION_COLUMNS, columns.len);
    try std.testing.expect(output.statement.stmt1.totalClaimedSum().isZero());
    try std.testing.expectEqual(@as(u32, 4), columns[0].log_size);
    try std.testing.expectEqual(
        @as(u32, 7),
        columns[geometry.ROUND_INTERACTION_OFFSETS[0]].log_size,
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        columns[geometry.ROUND_INTERACTION_OFFSETS[1]].log_size,
    );
    try std.testing.expectEqual(
        geometry.XOR_TABLES[0].logSize(),
        columns[geometry.XOR_INTERACTION_OFFSET].log_size,
    );
}
