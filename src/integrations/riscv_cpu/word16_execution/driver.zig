//! Durable native execution receipt. The receiver reconstructs its own image
//! and immutable key; serialized claims and geometry grant no authority.
const std = @import("std");
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const E = @import("execution.zig");
const Image = @import("expected_image.zig");
const Memory = @import("memory/statement.zig");
const Cells = @import("cells_wire.zig");
const Receipt = @import("../rv64_ethereum_batch_receipt.zig");
pub const Bundle = struct {
    schema: u32 = 2,
    geometry: Mat.Geometry,
    cpu: @FieldType(P.Request, "cpu"),
    epoch: u16,
    division_requests: u32,
    multiplication_requests: u32,
    ls_count: u32,
    memory_words: u32,
    claims: P.Claims,
};
pub fn admission(image: *const Image.Owner) E.Admission {
    return .{ .image = Memory.fromOwner(image), .image_identity = image.identity, .initial_pc = image.initial_pc, .initial_registers = image.initial_registers, .max_prefix_steps = image.max_prefix_steps };
}
pub fn writeJson(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try Receipt.writeExclusive(dir, name, bytes);
}
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, setup: *const Mat.Setup, encoded: E.Encoded) !void {
    try Receipt.writeExclusive(dir, "proof.bin", encoded.bytes);
    const r = encoded.request;
    try Cells.write(dir, r.memory.initial, r.memory.terminal);
    try writeJson(a, dir, "statement.json", Bundle{ .geometry = setup.materials.geometry, .cpu = r.cpu, .epoch = r.epoch, .division_requests = r.division_requests, .multiplication_requests = r.multiplication_requests, .ls_count = r.memory.ls_count, .memory_words = @intCast(r.memory.initial.len), .claims = encoded.claims });
    try std.posix.fsync(dir.fd);
}
pub fn verifyDirectory(a: std.mem.Allocator, image: *const Image.Owner, path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const data = try dir.readFileAlloc(a, "statement.json", 128 * 1024);
    defer a.free(data);
    const parsed = try std.json.parseFromSlice(Bundle, a, data, .{});
    defer parsed.deinit();
    const b = parsed.value;
    if (b.schema != 2) return error.InvalidExecutionBundle;
    try admission(image).validateCpu(b.geometry, b.cpu);
    try E.Admission.validateCounts(b.geometry, b.cpu.steps, b.ls_count, b.memory_words);
    try P.validateDivisionClass(b.geometry, b.division_requests, b.claims.division);
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
