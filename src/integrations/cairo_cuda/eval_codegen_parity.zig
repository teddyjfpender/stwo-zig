//! Local device differential for scalar specialization and register rewrites.
const std = @import("std");
const eval = @import("stwo_cairo_frontend").witness.eval_program;
const codegen = @import("eval_codegen.zig");

pub fn generate(allocator: std.mem.Allocator, output: []const u8) !void {
    var base = [_]eval.BaseInst{
        .{ .op = .constant, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 1, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 2, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 0, .dst = 3, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 4, .a = 3, .b = 1, .imm = 0 },
        .{ .op = .add, .interaction = 0, .dst = 5, .a = 4, .b = 2, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 5, .a = 5, .b = 1, .imm = 0 },
    };
    var extended = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 5, .b = 0, .c = 0, .d = 0 },
        .{ .op = .param, .dst = 1, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .constant, .dst = 2, .a = 1, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 3, .a = 0, .b = 1, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 4, .a = 3, .b = 2, .c = 0, .d = 0 },
        .{ .op = .constant, .dst = 5, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 6, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .add, .dst = 3, .a = 3, .b = 1, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 7, .a = 5, .b = 1, .c = 0, .d = 0 },
        .{ .op = .sub, .dst = 8, .a = 3, .b = 1, .c = 0, .d = 0 },
        .{ .op = .constant, .dst = 9, .a = 11, .b = 13, .c = 17, .d = 19 },
        .{ .op = .add, .dst = 10, .a = 8, .b = 9, .c = 0, .d = 0 },
    };
    var roots = [_]u32{ 4, 3, 6, 5, 7, 10 };
    var program = eval.Program{
        .allocator = allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0, .capability_bits = eval.Capability.ext_mul | eval.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 1, .n_constraints = 6, .max_base_regs = 6, .max_ext_regs = 11, .domain_log_size = 4 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &extended,
        .constraint_roots = &roots,
    };
    program.header.semantic_hash = program.semanticHash();
    const source = try codegen.generateParametric(allocator, program, &.{ false, false, true });
    defer allocator.free(source);
    const name = try std.fmt.allocPrint(allocator, "stwo_cairo_cuda_eval_v6_{x:0>16}", .{program.header.semantic_hash});
    defer allocator.free(name);
    try std.fs.cwd().makePath(output);
    var directory = try std.fs.cwd().openDir(output, .{});
    defer directory.close();
    try directory.writeFile(.{ .sub_path = "kernel.cu", .data = source });
    var receipt = std.Io.Writer.Allocating.init(allocator);
    defer receipt.deinit();
    try std.json.Stringify.value(.{
        .schema = "stwo-cairo-cuda-parametric-parity-fixture-v1",
        .kernel = name,
        .source_sha256 = std.fmt.bytesToHex(codegen.sourceIdentity(source), .lower),
        .evidence = "synthetic-register-rewrite-differential",
        .full_proof_verified = false,
    }, .{ .whitespace = .indent_2 }, &receipt.writer);
    try directory.writeFile(.{ .sub_path = "receipt.json", .data = receipt.written() });
    const stored = try codegen.generateMaterializedParity(allocator, program, &.{ false, false, true });
    defer allocator.free(stored);
    try directory.makePath("materialized");
    var child = try directory.openDir("materialized", .{});
    defer child.close();
    try child.writeFile(.{ .sub_path = "kernel.cu", .data = stored });
    receipt.clearRetainingCapacity();
    try std.json.Stringify.value(.{
        .schema = "stwo-cairo-cuda-parametric-parity-fixture-v1",
        .kernel = name,
        .source_sha256 = std.fmt.bytesToHex(codegen.sourceIdentity(stored), .lower),
        .evidence = "synthetic-materialized-register-rewrite-differential",
        .full_proof_verified = false,
    }, .{ .whitespace = .indent_2 }, &receipt.writer);
    try child.writeFile(.{ .sub_path = "receipt.json", .data = receipt.written() });
}
