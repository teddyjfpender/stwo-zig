//! Product expected-image admission over the canonical native receipt codec.
const std = @import("std");
const N = @import("stwo_riscv_cpu_integration").rv64_execution;
const P = N.word16.protocol;
const Mat = N.word16.setup;
const E = N.word16.proof;
const Memory = N.memory.statement;
const Image = @import("expected_image.zig");
const receipt = @import("stwo_riscv_cpu_integration").rv64_execution.word16.receipt;
const Cells = receipt.cells;
pub const Bundle = receipt.Bundle;
pub const writeJson = receipt.writeJson;
pub const publish = receipt.publish;
pub fn admission(image: *const Image.Owner) E.Admission {
    return .{ .image = Memory.fromOwner(image), .image_identity = image.identity, .initial_pc = image.initial_pc, .initial_registers = image.initial_registers, .max_prefix_steps = image.max_prefix_steps };
}
pub fn verifyDirectory(a: std.mem.Allocator, image: *const Image.Owner, path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const data = try dir.readFileAlloc(a, "statement.json", 128 * 1024);
    defer a.free(data);
    const parsed = try std.json.parseFromSlice(Bundle, a, data, .{});
    defer parsed.deinit();
    const b = parsed.value;
    if (b.schema != P.SCHEMA) return error.InvalidExecutionBundle;
    try admission(image).validateCpu(b.geometry, b.cpu);
    try E.Admission.validateCounts(b.geometry, b.cpu.steps, b.ls_count, b.memory_words);
    try P.validateDivisionClass(b.geometry, b.division_requests, b.claims.division);
    try P.validateLsTailClass(b.geometry, b.ls_count, b.claims.ls_tail);
    try P.validateProviderTailClaims(b.geometry, b.claims);
    try b.claims.validate();
    if (b.epoch != 1 or b.cpu.initial_pc != image.initial_pc or !std.mem.eql(u64, &b.cpu.initial_registers, &image.initial_registers)) return error.UntrustedWord16InitialCpu;
    const cells = try Cells.read(a, dir, b.memory_words);
    defer cells.deinit(a);
    const request = P.Request{ .cpu = b.cpu, .epoch = b.epoch, .division_requests = b.division_requests, .multiplication_requests = b.multiplication_requests, .memory = .{ .initial = cells.initial, .terminal = cells.terminal, .epoch = b.epoch, .ls_count = b.ls_count } };
    try admission(image).validateGeometry(b.geometry, request);
    const bytes = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(bytes);
    var setup = try Mat.Setup.initWithAuthority(a, &image.authority, b.geometry);
    defer setup.deinit();
    try E.verify(a, &setup, admission(image), .{ .bytes = bytes, .claims = b.claims, .request = request });
}
