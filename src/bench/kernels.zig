const std = @import("std");
const circle = @import("../core/circle.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const canonic = @import("../core/poly/circle/canonic.zig");
const poly_utils = @import("../core/poly/utils.zig");
const prover_poly = @import("../prover/poly/circle/poly.zig");
const twiddles = @import("../prover/poly/twiddles.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CircleCoefficients = prover_poly.CircleCoefficients;

const Kernel = enum {
    eval_at_point,
    eval_at_point_by_folding,
    fft,
};

const KERNEL_NAMES = [_][]const u8{
    "eval_at_point",
    "eval_at_point_by_folding",
    "fft",
};

const BenchResult = struct {
    kernel: []const u8,
    log_size: u32,
    iterations: usize,
    seconds: f64,
    checksum: [4]u32,
};

pub fn listKernels(writer: anytype) !void {
    const rendered = try std.json.Stringify.valueAlloc(std.heap.page_allocator, KERNEL_NAMES, .{});
    defer std.heap.page_allocator.free(rendered);
    try writer.writeAll(rendered);
    try writer.writeAll("\n");
}

fn parseKernel(name: []const u8) !Kernel {
    if (std.mem.eql(u8, name, "eval_at_point")) return .eval_at_point;
    if (std.mem.eql(u8, name, "eval_at_point_by_folding")) return .eval_at_point_by_folding;
    if (std.mem.eql(u8, name, "fft")) return .fft;
    return error.InvalidKernel;
}

fn parseU32(raw: []const u8) !u32 {
    return std.fmt.parseInt(u32, raw, 10);
}

fn parseUsize(raw: []const u8) !usize {
    return std.fmt.parseInt(usize, raw, 10);
}

fn checksumFromQM31(value: QM31) [4]u32 {
    const terms = value.toM31Array();
    return .{ terms[0].toU32(), terms[1].toU32(), terms[2].toU32(), terms[3].toU32() };
}

fn benchEvalAtPoint(allocator: std.mem.Allocator, log_size: u32, iterations: usize) !BenchResult {
    const n = @as(usize, 1) << @intCast(log_size);
    const coeffs = try allocator.alloc(M31, n);
    defer allocator.free(coeffs);

    for (coeffs, 0..) |*coeff, i| {
        const value: u32 = @intCast((i * 17 + 11) % m31.Modulus);
        coeff.* = M31.fromCanonical(value);
    }

    const poly = try CircleCoefficients.initBorrowed(coeffs);
    var acc = QM31.zero();

    const start_ns = std.time.nanoTimestamp();
    var iter: usize = 0;
    while (iter < iterations) : (iter += 1) {
        const mul_factor: u64 = @intCast(iter *% 13 +% 7);
        const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(mul_factor);
        acc = acc.add(poly.evalAtPoint(point));
    }
    const end_ns = std.time.nanoTimestamp();

    return .{
        .kernel = "eval_at_point",
        .log_size = log_size,
        .iterations = iterations,
        .seconds = @as(f64, @floatFromInt(end_ns - start_ns)) / 1_000_000_000.0,
        .checksum = checksumFromQM31(acc),
    };
}

fn benchEvalAtPointByFolding(
    allocator: std.mem.Allocator,
    log_size: u32,
    iterations: usize,
) !BenchResult {
    const n = @as(usize, 1) << @intCast(log_size);
    const values = try allocator.alloc(M31, n);
    defer allocator.free(values);

    for (values, 0..) |*value, i| {
        const canonical: u32 = @intCast((i * 29 + 5) % m31.Modulus);
        value.* = M31.fromCanonical(canonical);
    }

    const base_factors = try allocator.alloc(M31, log_size);
    defer allocator.free(base_factors);
    const runtime_factors = try allocator.alloc(M31, log_size);
    defer allocator.free(runtime_factors);

    for (base_factors, 0..) |*factor, i| {
        const canonical: u32 = @intCast((i * 31 + 17) % (m31.Modulus - 1) + 1);
        factor.* = M31.fromCanonical(canonical);
    }

    var acc = M31.zero();

    const start_ns = std.time.nanoTimestamp();
    var iter: usize = 0;
    while (iter < iterations) : (iter += 1) {
        @memcpy(runtime_factors, base_factors);
        const tweak = M31.fromCanonical(@intCast((iter % (m31.Modulus - 1)) + 1));
        runtime_factors[0] = runtime_factors[0].add(tweak);
        const folded = poly_utils.fold(M31, values, runtime_factors);
        acc = acc.add(folded);
    }
    const end_ns = std.time.nanoTimestamp();

    return .{
        .kernel = "eval_at_point_by_folding",
        .log_size = log_size,
        .iterations = iterations,
        .seconds = @as(f64, @floatFromInt(end_ns - start_ns)) / 1_000_000_000.0,
        .checksum = .{ acc.toU32(), 0, 0, 0 },
    };
}

fn benchFft(allocator: std.mem.Allocator, log_size: u32, iterations: usize) !BenchResult {
    const n = @as(usize, 1) << @intCast(log_size);
    const coeffs = try allocator.alloc(M31, n);
    defer allocator.free(coeffs);

    for (coeffs, 0..) |*coeff, i| {
        const canonical: u32 = @intCast((i * 19 + 3) % m31.Modulus);
        coeff.* = M31.fromCanonical(canonical);
    }

    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    var twiddle_tree = try twiddles.precomputeM31(allocator, domain.half_coset);
    defer twiddles.deinitM31(allocator, &twiddle_tree);

    var acc = QM31.zero();

    const start_ns = std.time.nanoTimestamp();
    var iter: usize = 0;
    while (iter < iterations) : (iter += 1) {
        coeffs[0] = coeffs[0].add(M31.one());
        const poly = try CircleCoefficients.initBorrowed(coeffs);
        const evaluation = try poly.evaluateWithTwiddles(
            allocator,
            domain,
            .{
                .root_coset = twiddle_tree.root_coset,
                .twiddles = twiddle_tree.twiddles,
                .itwiddles = twiddle_tree.itwiddles,
            },
        );

        var interpolated = try prover_poly.interpolateFromEvaluationWithTwiddles(
            allocator,
            evaluation,
            .{
                .root_coset = twiddle_tree.root_coset,
                .twiddles = twiddle_tree.twiddles,
                .itwiddles = twiddle_tree.itwiddles,
            },
        );

        acc = acc.add(QM31.fromBase(interpolated.coefficients()[0]));
        interpolated.deinit(allocator);
        allocator.free(@constCast(evaluation.values));
    }
    const end_ns = std.time.nanoTimestamp();

    return .{
        .kernel = "fft",
        .log_size = log_size,
        .iterations = iterations,
        .seconds = @as(f64, @floatFromInt(end_ns - start_ns)) / 1_000_000_000.0,
        .checksum = checksumFromQM31(acc),
    };
}

fn benchKernel(
    allocator: std.mem.Allocator,
    kernel: Kernel,
    log_size: u32,
    iterations: usize,
) !BenchResult {
    return switch (kernel) {
        .eval_at_point => try benchEvalAtPoint(allocator, log_size, iterations),
        .eval_at_point_by_folding => try benchEvalAtPointByFolding(allocator, log_size, iterations),
        .fft => try benchFft(allocator, log_size, iterations),
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var mode: ?[]const u8 = null;
    var kernel_name: ?[]const u8 = null;
    var log_size: u32 = 11;
    var iterations: usize = 200;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!std.mem.startsWith(u8, arg, "--")) return error.InvalidArgument;
        if (i + 1 >= args.len) return error.MissingArgumentValue;
        const value = args[i + 1];
        i += 1;

        if (std.mem.eql(u8, arg, "--mode")) {
            mode = value;
        } else if (std.mem.eql(u8, arg, "--kernel")) {
            kernel_name = value;
        } else if (std.mem.eql(u8, arg, "--log-size")) {
            log_size = try parseU32(value);
        } else if (std.mem.eql(u8, arg, "--iterations")) {
            iterations = try parseUsize(value);
        } else {
            return error.InvalidArgument;
        }
    }

    const selected_mode = mode orelse return error.MissingMode;
    if (std.mem.eql(u8, selected_mode, "list-kernels")) {
        try listKernels(std.fs.File.stdout());
        return;
    }

    if (!std.mem.eql(u8, selected_mode, "bench")) return error.InvalidMode;
    if (iterations == 0) return error.InvalidIterations;
    if (log_size == 0 or log_size > 20) return error.InvalidLogSize;

    const selected_kernel_name = kernel_name orelse return error.MissingKernel;
    const kernel = try parseKernel(selected_kernel_name);
    const result = try benchKernel(allocator, kernel, log_size, iterations);

    const rendered = try std.json.Stringify.valueAlloc(allocator, result, .{});
    defer allocator.free(rendered);
    try std.fs.File.stdout().writeAll(rendered);
    try std.fs.File.stdout().writeAll("\n");
}

test "bench kernels: kernel list is stable and unique" {
    try std.testing.expectEqual(@as(usize, 3), KERNEL_NAMES.len);
    for (KERNEL_NAMES, 0..) |lhs, i| {
        for (KERNEL_NAMES[(i + 1)..]) |rhs| {
            try std.testing.expect(!std.mem.eql(u8, lhs, rhs));
        }
    }
}
