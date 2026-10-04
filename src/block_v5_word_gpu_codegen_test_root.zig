//! Explicit CPU-only tests for typed schema and real Metal/CUDA source.
//! Running this root never creates a GPU session or proves a STARK.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const gpu_program = @import("frontends/riscv/prover/block_v5_word_gpu_program_v1.zig");
const protocol = @import("frontends/riscv/prover/block_v5_word_memory_protocol_v1.zig");
const Range = @import("frontends/riscv/prover/block_v5_range16_component_v1.zig").Spec;
const metal = @import("backends/metal/runtime/secure_polynomial_codegen_v1.zig");
const cuda = @import("backends/cuda/secure_polynomial_codegen_v1.zig");
comptime {
    _ = @import("frontends/riscv/prover/tests/block_v5_word_gpu_program_test.zig");
}
test "secure GPU codegen binds typed source and reuses executable across dynamic public values" {
    const a = std.testing.allocator;
    var c: protocol.Challenges = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
    const s = Range{ .claim = .{ .sum = Q.fromU32Unchecked(3, 5, 7, 11), .count = 17 }, .challenges = &c };
    var equations = try gpu_program.rangeEquations(a, s);
    defer equations.deinit();
    var changed = s;
    changed.claim.sum = changed.claim.sum.add(Q.one());
    changed.claim.count += 1;
    var second = try gpu_program.rangeEquations(a, changed);
    defer second.deinit();
    var fractions = try gpu_program.rangeFractions(a, s);
    defer fractions.deinit();
    const first_source = try metal.generateLibrary(a, &.{ &equations, &fractions });
    defer a.free(first_source);
    const second_source = try metal.generateLibrary(a, &.{ &second, &fractions });
    defer a.free(second_source);
    try std.testing.expectEqualSlices(u8, first_source, second_source);
    try std.testing.expectEqualSlices(u8, &try metal.identity(&equations), &try metal.identity(&second));
    try std.testing.expect(!std.mem.eql(u8, &try metal.identity(&equations), &try cuda.identity(&equations)));
    const cuda_source = try cuda.generateLibrary(a, &.{ &equations, &fractions });
    defer a.free(cuda_source);
    try std.testing.expect(std.mem.indexOf(u8, cuda_source, "extern \"C\" __global__ void") != null);
    try std.testing.expect(std.mem.indexOf(u8, cuda_source, "[[buffer(") == null);
    try std.testing.expect(std.mem.indexOf(u8, first_source, metal.mean_symbol) != null);
    for (metal.scan_symbols) |symbol| try std.testing.expect(std.mem.indexOf(u8, first_source, symbol) != null);
    for (metal.witness_symbols) |symbol| try std.testing.expect(std.mem.indexOf(u8, first_source, symbol) != null);
    try std.testing.expect(std.mem.indexOf(u8, first_source, "riscv_load_qm31(range_inverses,4u*v") != null);
    try std.testing.expect(std.mem.indexOf(u8, cuda_source, "stwo_cuda_range16_inverse_table_v1") != null);
    equations.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidSecurePolynomialIdentity, metal.generateLibrary(a, &.{&equations}));
    try std.testing.expectError(error.InvalidSecurePolynomialIdentity, cuda.generateLibrary(a, &.{&equations}));
    equations.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidSecureKernelCatalog, metal.generateLibrary(a, &.{}));
    const excessive = [_]*const gpu_program.ir.Program{&equations} ** 17;
    try std.testing.expectError(error.InvalidSecureKernelCatalog, cuda.generateLibrary(a, &excessive));
}
test "secure GPU schema rejects forbidden fraction equations and cross-builder inputs" {
    const a = std.testing.allocator;
    var b = gpu_program.ir.Builder.init(a);
    defer b.deinit();
    var other = gpu_program.ir.Builder.init(a);
    defer other.deinit();
    const first = b.input(.{ .tree = 0, .column = 0 });
    const foreign = other.input(.{ .tree = 1, .column = 0 });
    const mixed = first.add(foreign);
    try std.testing.expectError(error.ForeignSecurePolynomialExpression, b.finish(.range16_equations_v4, gpu_program.authority(), &.{ mixed, first }));
    var clean = gpu_program.ir.Builder.init(a);
    defer clean.deinit();
    const numerator = clean.input(.{ .tree = 1, .column = 0 });
    const fraction = gpu_program.ir.Expr.fraction(numerator, gpu_program.ir.Expr.one());
    try std.testing.expectError(error.InvalidSecurePolynomialSchema, clean.finish(.range16_equations_v4, gpu_program.authority(), &.{ fraction, numerator }));
    var ranges = gpu_program.ir.Builder.init(a);
    defer ranges.deinit();
    const range_value = ranges.input(.{ .tree = 0, .column = 0 });
    const weight = ranges.input(.{ .tree = 1, .column = 0 });
    const left = gpu_program.ir.Expr.rangeFraction(weight, range_value, ranges.parameter(Q.one()));
    const right = gpu_program.ir.Expr.rangeFraction(weight, range_value, ranges.parameter(Q.one().add(Q.one())));
    var mismatch = try ranges.finish(.range16_fractions_v4, gpu_program.authority(), &.{ left, right });
    defer mismatch.deinit();
    try std.testing.expectError(error.SecureRangeChallengeMismatch, mismatch.rangeChallenge());
}
