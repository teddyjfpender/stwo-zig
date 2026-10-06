//! Fixed CX/CCX circuit geometry for a single public test vector.
//! This is an experimental proof route, not the complete QEC benchmark.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const M31 = core.fields.m31.M31;

pub const Kind = enum { cx, ccx };

pub const Gate = struct {
    kind: Kind,
    control1: usize,
    control2: usize,
    target_before: usize,
    output: usize,
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    hash: [32]u8,
    width: usize,
    challenge: Challenge,
    first_batch: [64]Challenge,
    gates: []Gate,
    final_columns: []usize,

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.gates);
        self.allocator.free(self.final_columns);
        self.* = undefined;
    }

    pub fn columnCount(self: Program) usize {
        return self.final_columns.len + self.gates.len;
    }
};

pub const Statement = struct {
    circuit_hash: [32]u8,
    width: u16,
    gate_count: u32,
    target: u256,
    offset: u256,
    log_rows: u32 = 4,
};

pub const Challenge = struct { target: u256, offset: u256 };

pub fn parse(allocator: std.mem.Allocator, text: []const u8) !Program {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &hash, .{});
    var gates: std.ArrayList(Gate) = .empty;
    errdefer gates.deinit(allocator);
    var register_sizes = [2]usize{ 0, 0 };
    var register_seen = [2]bool{ false, false };
    var max_qubit: usize = 0;
    var gate_count: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var tokens = std.mem.tokenizeAny(u8, line, " \t\r");
        const name = tokens.next() orelse continue;
        if (name[0] == '#') continue;
        if (std.mem.eql(u8, name, "APPEND_TO_REGISTER")) {
            const qubit = try parseIndex(tokens.next() orelse return error.InvalidCircuit, 'q');
            const register = try parseIndex(tokens.next() orelse return error.InvalidCircuit, 'r');
            if (register >= 2 or qubit != register_sizes[0] + register_sizes[1] or tokens.next() != null)
                return error.InvalidCircuit;
            register_sizes[register] += 1;
            max_qubit = @max(max_qubit, qubit + 1);
        } else if (std.mem.eql(u8, name, "REGISTER")) {
            const register = try parseIndex(tokens.next() orelse return error.InvalidCircuit, 'r');
            if (register >= 2 or register_seen[register] or tokens.next() != null) return error.InvalidCircuit;
            register_seen[register] = true;
        } else if (std.mem.eql(u8, name, "CX") or std.mem.eql(u8, name, "CCX")) {
            gate_count += 1;
            const controls: usize = if (std.mem.eql(u8, name, "CX")) 1 else 2;
            for (0..controls + 1) |_| {
                const qubit = try parseIndex(tokens.next() orelse return error.InvalidCircuit, 'q');
                max_qubit = @max(max_qubit, qubit + 1);
            }
            if (tokens.next()) |tail| if (tail[0] != '#') return error.InvalidCircuit;
        } else return error.UnsupportedOperation;
    }
    if (!register_seen[0] or !register_seen[1] or register_sizes[0] == 0 or
        register_sizes[0] != register_sizes[1] or max_qubit != register_sizes[0] * 2 or
        register_sizes[0] > 256) return error.InvalidCircuit;

    const columns = try allocator.alloc(usize, max_qubit);
    errdefer allocator.free(columns);
    for (columns, 0..) |*column, index| column.* = index;
    lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var tokens = std.mem.tokenizeAny(u8, line, " \t\r");
        const name = tokens.next() orelse continue;
        if (name[0] == '#' or std.mem.eql(u8, name, "APPEND_TO_REGISTER") or
            std.mem.eql(u8, name, "REGISTER")) continue;
        const kind: Kind = if (std.mem.eql(u8, name, "CX")) .cx else .ccx;
        const c1 = try parseIndex(tokens.next().?, 'q');
        const c2 = if (kind == .ccx) try parseIndex(tokens.next().?, 'q') else c1;
        const target = try parseIndex(tokens.next().?, 'q');
        if (c1 >= max_qubit or c2 >= max_qubit or target >= max_qubit or
            c1 == target or c2 == target or (kind == .ccx and c1 == c2)) return error.InvalidCircuit;
        const output = max_qubit + gates.items.len;
        try gates.append(allocator, .{
            .kind = kind,
            .control1 = columns[c1],
            .control2 = columns[c2],
            .target_before = columns[target],
            .output = output,
        });
        columns[target] = output;
    }
    if (gates.items.len != gate_count) return error.InvalidCircuit;
    return .{
        .allocator = allocator,
        .hash = hash,
        .width = register_sizes[0],
        .challenge = firstChallenge(text, register_sizes[0]),
        .first_batch = firstBatchChallenges(text, register_sizes[0]),
        .gates = try gates.toOwnedSlice(allocator),
        .final_columns = columns,
    };
}

fn parseIndex(token: []const u8, prefix: u8) !usize {
    if (token.len < 2 or token[0] != prefix) return error.InvalidCircuit;
    return std.fmt.parseInt(usize, token[1..], 10) catch error.InvalidCircuit;
}

pub fn firstChallenge(text: []const u8, width: usize) Challenge {
    var xof = std.crypto.hash.sha3.Shake256.init(.{});
    xof.update(text);
    var bytes: [64]u8 = undefined;
    xof.squeeze(&bytes);
    const mask: u256 = if (width == 256) std.math.maxInt(u256) else (@as(u256, 1) << @intCast(width)) - 1;
    return .{
        .target = std.mem.readInt(u256, bytes[0..32], .little) & mask,
        .offset = std.mem.readInt(u256, bytes[32..64], .little) & mask,
    };
}

pub fn firstBatchChallenges(text: []const u8, width: usize) [64]Challenge {
    var xof = std.crypto.hash.sha3.Shake256.init(.{});
    xof.update(text);
    const mask: u256 = if (width == 256) std.math.maxInt(u256) else (@as(u256, 1) << @intCast(width)) - 1;
    var result: [64]Challenge = undefined;
    for (&result) |*challenge| {
        var bytes: [64]u8 = undefined;
        xof.squeeze(&bytes);
        challenge.* = .{
            .target = std.mem.readInt(u256, bytes[0..32], .little) & mask,
            .offset = std.mem.readInt(u256, bytes[32..64], .little) & mask,
        };
    }
    return result;
}

pub fn pinChallenge(challenge: Challenge, width: usize, qubit: usize, final: bool) M31 {
    const mask: u256 = if (width == 256) std.math.maxInt(u256) else (@as(u256, 1) << @intCast(width)) - 1;
    const value = if (qubit < width)
        (if (final) (challenge.target +% challenge.offset) & mask else challenge.target)
    else
        challenge.offset;
    const bit_index: u8 = @intCast(if (qubit < width) qubit else qubit - width);
    return M31.fromCanonical(@intCast((value >> bit_index) & 1));
}

pub fn statement(program: *const Program, challenge: Challenge) Statement {
    return .{
        .circuit_hash = program.hash,
        .width = @intCast(program.width),
        .gate_count = @intCast(program.gates.len),
        .target = challenge.target,
        .offset = challenge.offset,
    };
}

pub fn pin(statement_value: Statement, qubit: usize, final: bool) M31 {
    return pinChallenge(.{ .target = statement_value.target, .offset = statement_value.offset }, statement_value.width, qubit, final);
}

pub fn generate(allocator: std.mem.Allocator, program: *const Program, statement_value: Statement) ![]prover.pcs.ColumnEvaluation {
    if (statement_value.log_rows < 4 or statement_value.log_rows > 16 or
        statement_value.width != program.width or statement_value.gate_count != program.gates.len or
        !std.mem.eql(u8, &statement_value.circuit_hash, &program.hash)) return error.InvalidStatement;
    const row_count: usize = @as(usize, 1) << @intCast(statement_value.log_rows);
    const columns = try allocator.alloc(prover.pcs.ColumnEvaluation, program.columnCount());
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = .{ .log_size = statement_value.log_rows, .values = try allocator.alloc(M31, row_count) };
        initialized += 1;
    }
    for (0..program.final_columns.len) |q| @memset(@constCast(columns[q].values), pin(statement_value, q, false));
    for (program.gates) |gate| {
        const c1 = columns[gate.control1].values[0].v;
        const c2 = columns[gate.control2].values[0].v;
        const before = columns[gate.target_before].values[0].v;
        const toggle = c1 & (if (gate.kind == .ccx) c2 else @as(u32, 1));
        @memset(@constCast(columns[gate.output].values), M31.fromCanonical(before ^ toggle));
    }
    return columns;
}

test "public iadd256 fixture parses into static gate wiring and exact SHAKE challenge" {
    const bytes = @embedFile("fixtures/iadd256.kmx");
    var program = try parse(std.testing.allocator, bytes);
    defer program.deinit();
    try std.testing.expectEqual(@as(usize, 256), program.width);
    try std.testing.expectEqual(@as(usize, 2547), program.gates.len);
    try std.testing.expectEqual(@as(usize, 3059), program.columnCount());
    const challenge = firstChallenge(bytes, program.width);
    const s = statement(&program, challenge);
    const columns = try generate(std.testing.allocator, &program, s);
    defer {
        for (columns) |col| std.testing.allocator.free(col.values);
        std.testing.allocator.free(columns);
    }
    for (program.final_columns, 0..) |index, q| {
        try std.testing.expect(columns[index].values[0].eql(pin(s, q, true)));
    }
}
