//! Hostile tests for the binary-only universal row-35 request ledger.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const authority_mod = @import("outer_parent_range_authority.zig");
const circuit_mod = @import("statement_semantics_circuit.zig");
const row11 = @import("air/statement_semantics_input_witness.zig");
const statement = @import("span_statement.zig");

test "outer parent range authority derives exactly binary row-11 requests" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const authority = authority_mod.SourceAuthority.pinned();
    try authority.validate();

    var workspace = try authority_mod.Workspace.init(std.testing.allocator);
    defer workspace.deinit(std.testing.allocator);
    var prepared = try authority_mod.Prepared.init(
        std.testing.allocator,
        &workspace,
        fixture.sources(),
    );
    defer prepared.deinit();

    try prepared.validateAgainst(&workspace, fixture.sources());
    try prepared.provider().validate();
    try std.testing.expectEqual(
        fixture.preprocessing.activeIntegerCount(.binary_node),
        prepared.request_count,
    );

    try std.testing.expect(
        prepared.provider().counter.signedTotal().eql(
            M31.zero().sub(M31.fromU64(prepared.request_count)),
        ),
    );
}

test "outer parent range authority rejects detached statement values before mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var workspace = try authority_mod.Workspace.init(std.testing.allocator);
    defer workspace.deinit(std.testing.allocator);

    @memset(workspace.counter.values, M31.fromCanonical(73));
    workspace.request_count = 91;
    const counter_snapshot = try std.testing.allocator.dupe(
        M31,
        workspace.counter.values,
    );
    defer std.testing.allocator.free(counter_snapshot);

    const row_index = firstActiveStatementRow(
        fixture.preprocessing.rows,
        authority_mod.StatementWords,
    );
    fixture.statement_values[row_index] = fixture.statement_values[row_index].add(M31.one());
    try std.testing.expectError(
        error.StatementAuthorityMismatch,
        workspace.derive(fixture.sources()),
    );
    try expectM31SlicesEqual(counter_snapshot, workspace.counter.values);
    try std.testing.expectEqual(@as(u64, 91), workspace.request_count);
}

test "outer parent range prepared snapshot detects source and authority mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var workspace = try authority_mod.Workspace.init(std.testing.allocator);
    defer workspace.deinit(std.testing.allocator);
    var prepared = try authority_mod.Prepared.init(
        std.testing.allocator,
        &workspace,
        fixture.sources(),
    );
    defer prepared.deinit();

    prepared.source_authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        prepared.validateAgainst(&workspace, fixture.sources()),
    );
    prepared.source_authority_digest = authority_mod.SourceAuthority.pinned().identityDigest();

    prepared.range_check.counter.values[0] =
        prepared.range_check.counter.values[0].add(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        prepared.validateAgainst(&workspace, fixture.sources()),
    );
}

const Fixture = struct {
    circuit: circuit_mod.Circuit,
    preprocessing: row11.Preprocessed,
    left: authority_mod.StatementWords,
    right: authority_mod.StatementWords,
    parent: authority_mod.StatementWords,
    circuit_inputs: []QM31,
    circuit_values: []QM31,
    statement_values: []M31,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var circuit = try circuit_mod.build(allocator);
        errdefer circuit.deinit();
        var preprocessing = try row11.Preprocessed.init(
            allocator,
            11,
            circuit.inputBindings(),
        );
        errdefer preprocessing.deinit();

        const triple = try twoExecuted();
        const left = try triple.left.canonicalWords();
        const right = try triple.right.canonicalWords();
        const parent = try triple.parent.canonicalWords();
        const circuit_inputs = try allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
        errdefer allocator.free(circuit_inputs);
        const circuit_values = try allocator.alloc(QM31, circuit.nodeCount());
        errdefer allocator.free(circuit_values);
        try circuit.evaluateIntoAssumeValid(
            circuit_mod.Witness.forBinary(&left, &right, &parent),
            circuit_inputs,
            circuit_values,
        );
        const statement_values = try allocator.alloc(M31, circuit_mod.INPUT_COUNT);
        errdefer allocator.free(statement_values);
        for (circuit_inputs, statement_values) |input, *output| {
            const words = input.toM31Array();
            if (!words[1].isZero() or !words[2].isZero() or !words[3].isZero())
                return error.NonBaseCircuitInput;
            output.* = words[0];
        }
        return .{
            .circuit = circuit,
            .preprocessing = preprocessing,
            .left = left,
            .right = right,
            .parent = parent,
            .circuit_inputs = circuit_inputs,
            .circuit_values = circuit_values,
            .statement_values = statement_values,
        };
    }

    fn deinit(self: *Fixture) void {
        const allocator = self.circuit.allocator;
        allocator.free(self.statement_values);
        allocator.free(self.circuit_values);
        allocator.free(self.circuit_inputs);
        self.preprocessing.deinit();
        self.circuit.deinit();
        self.* = undefined;
    }

    fn sources(self: *const Fixture) authority_mod.Sources {
        return .{
            .preprocessing = &self.preprocessing,
            .values = self.statement_values,
            .left = &self.left,
            .right = &self.right,
            .parent = &self.parent,
        };
    }
};

const Triple = struct {
    left: statement.SpanStatement,
    right: statement.SpanStatement,
    parent: statement.SpanStatement,
};

fn twoExecuted() !Triple {
    const job = try fixtureJob(2, 10);
    const left = try fixtureLeaf(
        job,
        0,
        0,
        4,
        try fixtureState(0),
        try fixtureState(1),
    );
    const right = try fixtureLeaf(
        job,
        1,
        4,
        6,
        try fixtureState(1),
        try fixtureState(2),
    );
    return .{
        .left = left,
        .right = right,
        .parent = try statement.SpanStatement.fold(left, right),
    };
}

fn fixtureJob(segment_count: u32, total_cycles: u64) !statement.JobContext {
    const complete = try statement.CompleteExecution.init(
        fixtureDigest(1),
        fixtureDigest(2),
        try fixtureState(0),
        try fixtureState(segment_count),
        fixtureDigest(3),
        fixtureDigest(4),
        total_cycles,
    );
    return statement.JobContext.init(complete, segment_count);
}

fn fixtureLeaf(
    job: statement.JobContext,
    index: u32,
    first_cycle: u64,
    cycle_count: u64,
    entry: statement.MachineState,
    exit_state: statement.MachineState,
) !statement.SpanStatement {
    const input = if (index == 0)
        try statement.EdgeClaim.present(job.complete.public_input)
    else
        statement.EdgeClaim.absent();
    const output = if (@as(u64, index) + 1 == job.segment_count)
        try statement.EdgeClaim.present(job.complete.public_output)
    else
        statement.EdgeClaim.absent();
    const span = try statement.ExecutedSpan.init(
        index,
        1,
        first_cycle,
        cycle_count,
        entry,
        exit_state,
        input,
        output,
    );
    return statement.SpanStatement.segmentLeaf(job, index, span);
}

fn fixtureState(seed: u32) !statement.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = seed;
    return statement.MachineState.init(
        seed *% 4,
        registers,
        fixtureDigest(seed + 10),
        fixtureDigest(seed + 20),
    );
}

fn fixtureDigest(seed: u32) statement.Digest {
    var result: statement.Digest = undefined;
    for (&result, 0..) |*value, index| value.* =
        seed + @as(u32, @intCast(index));
    return result;
}

fn firstActiveStatementRow(
    rows: []const row11.Row,
    comptime Words: type,
) usize {
    _ = Words;
    for (rows, 0..) |row, index| {
        if (row.source == .statement and row.active_kinds.contains(.binary_node))
            return index;
    }
    unreachable;
}

fn expectM31SlicesEqual(expected: []const M31, actual: []const M31) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));
}
