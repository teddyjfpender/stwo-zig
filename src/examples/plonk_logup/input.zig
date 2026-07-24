//! Exact pinned-Stwo Fibonacci Plonk witness and owned trace preparation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_impl").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");

pub const Request = struct {
    log_n_rows: u32,
};

pub const CircuitView = struct {
    mult: []const M31,
    a_wire: []const M31,
    b_wire: []const M31,
    c_wire: []const M31,
    op: []const M31,
    a_val: []const M31,
    b_val: []const M31,
    c_val: []const M31,
};

pub const Trace = struct {
    preprocessed: [4][]M31,
    main: [4][]M31,

    pub fn view(self: *const Trace) CircuitView {
        return .{
            .mult = self.main[0],
            .a_wire = self.preprocessed[0],
            .b_wire = self.preprocessed[1],
            .c_wire = self.preprocessed[2],
            .op = self.preprocessed[3],
            .a_val = self.main[1],
            .b_val = self.main[2],
            .c_val = self.main[3],
        };
    }
};

pub const PreparedInput = struct {
    request: Request,
    trace: prover_transaction.PreparedTrace,
    circuit: CircuitView,

    pub fn deinit(self: *PreparedInput, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        self.* = undefined;
    }
};

pub const Error = prover_transaction.Error || error{
    InvalidLogSize,
};

/// The pinned SIMD example requires at least one full 16-lane packed row.
pub fn validate(request: Request) Error!void {
    if (request.log_n_rows < 4 or request.log_n_rows >= 31)
        return error.InvalidLogSize;
}

pub fn genTrace(
    allocator: std.mem.Allocator,
    request: Request,
) (std.mem.Allocator.Error || Error)!Trace {
    try validate(request);
    const n = @as(usize, 1) << @intCast(request.log_n_rows);

    var preprocessed = try allocColumnSet(allocator, n);
    errdefer freeColumnSet(allocator, preprocessed);
    var main = try allocColumnSet(allocator, n);
    errdefer freeColumnSet(allocator, main);

    const fib = try allocator.alloc(M31, n + 2);
    defer allocator.free(fib);
    fib[0] = M31.one();
    fib[1] = M31.one();
    for (2..fib.len) |i| fib[i] = fib[i - 1].add(fib[i - 2]);

    for (0..n) |i| {
        preprocessed[0][i] = M31.fromU64(i);
        preprocessed[1][i] = M31.fromU64(i + 1);
        preprocessed[2][i] = M31.fromU64(i + 2);
        preprocessed[3][i] = M31.one();

        main[0][i] = M31.fromCanonical(2);
        main[1][i] = fib[i];
        main[2][i] = fib[i + 1];
        main[3][i] = fib[i + 2];
    }
    main[0][n - 2] = M31.one();
    main[0][n - 1] = M31.zero();

    return .{ .preprocessed = preprocessed, .main = main };
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: *Trace) void {
    freeColumnSet(allocator, trace.preprocessed);
    freeColumnSet(allocator, trace.main);
    trace.* = undefined;
}

pub fn prepare(
    allocator: std.mem.Allocator,
    request: Request,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    const generated = try genTrace(allocator, request);
    const circuit = generated.view();
    var preprocessed_moved = false;
    var main_moved = false;
    defer {
        if (!preprocessed_moved) freeColumnSet(allocator, generated.preprocessed);
        if (!main_moved) freeColumnSet(allocator, generated.main);
    }

    const preprocessed = try columnsFromSet(
        allocator,
        request.log_n_rows,
        generated.preprocessed,
    );
    var preprocessed_owner = prover_transaction.OwnedColumns.init(preprocessed);
    errdefer preprocessed_owner.deinit(allocator);
    preprocessed_moved = true;

    const main = try columnsFromSet(allocator, request.log_n_rows, generated.main);
    var main_owner = prover_transaction.OwnedColumns.init(main);
    errdefer main_owner.deinit(allocator);
    main_moved = true;

    return .{
        .request = request,
        .trace = try prover_transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed_owner.take(),
            main_owner.take(),
        ),
        .circuit = circuit,
    };
}

fn columnsFromSet(
    allocator: std.mem.Allocator,
    log_size: u32,
    values: [4][]M31,
) std.mem.Allocator.Error![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, values.len);
    for (values, 0..) |column, index| {
        columns[index] = .{ .log_size = log_size, .values = column };
    }
    return columns;
}

fn allocColumnSet(allocator: std.mem.Allocator, n: usize) ![4][]M31 {
    var columns: [4][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, n);
        initialized += 1;
    }
    return columns;
}

fn freeColumnSet(allocator: std.mem.Allocator, columns: [4][]M31) void {
    for (columns) |column| allocator.free(column);
}

test "exact Plonk input matches pinned multiplicity and Fibonacci semantics" {
    var trace = try genTrace(std.testing.allocator, .{ .log_n_rows = 4 });
    defer deinitTrace(std.testing.allocator, &trace);

    try std.testing.expect(trace.main[0][0].eql(M31.fromCanonical(2)));
    try std.testing.expect(trace.main[0][14].eql(M31.one()));
    try std.testing.expect(trace.main[0][15].eql(M31.zero()));
    try std.testing.expect(trace.main[3][0].eql(M31.fromCanonical(2)));
}
