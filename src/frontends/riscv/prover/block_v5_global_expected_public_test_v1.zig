//! Pure independently expected PUBLIC proposals and storage ownership tests.
//! No literal data below is accepted as a native/recursive proof receipt.
const std = @import("std");
const P = @import("../air/public_data.zig");
const Job = @import("../recursion/block_v5_global_expected_public_job_v1.zig");
const File = @import("block_v5_global_expected_public_file_v1.zig");
const Windows = @import("block_v5_register_windows_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Fixture = struct {
    input: [2]u32 = .{ 0xfefd1234, 0x80000000 },
    windows: [2]Job.Window = undefined,
    registers: [2]Windows.Window = undefined,
    fn init(self: *@This()) void {
        var data = P.Blake3PublicData{ .initial_pc = 0x1000, .final_pc = 0x1004, .clock = 2, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(0xA5) }, .initial_rw_root = .{ .bytes = @splat(0x11) }, .final_rw_root = .{ .bytes = @splat(0x22) }, .completion = P.Completion.canonicalSelfLoop(0x1004), .io_entries = .{ .input_start = 0x10000, .input_len = 8, .input_words = &self.input, .output_len = 0, .output_len_addr = 0x20000, .output_data_addr = 0x20004, .output_words = &.{} } };
        data.initial_regs[1] = 0xffee12a5;
        data.final_regs[1] = data.initial_regs[1];
        for (&self.windows, &self.registers, 0..) |*window, *register, index| {
            const first: u64 = @as(u64, @intCast(index)) * 2 + 1;
            data.initial_pc = 0x1000 + @as(u32, @intCast(index)) * 4;
            data.final_pc = data.initial_pc + 4;
            data.completion = P.Completion.canonicalSelfLoop(data.final_pc);
            window.* = .{ .profile = .rv32im_zkvm_v1, .first_cycle = first, .last_cycle = first + 1, .data = Job.Data.fromPublic(&data) };
            register.* = Windows.Window.fromPublic(@intCast(index), first, &data);
        }
    }
    fn expected(self: *const @This()) Job.Expected {
        return .{ .coverage_digest = @splat(0xA1), .seal_digest = @splat(0xB1), .recipe = 1, .input_words = &self.input, .windows = &self.windows, .register_plan = .{ .version = Windows.LOCAL_ZERO_VERSION, .initial_registers = self.registers[0].initial_registers, .final_registers = self.registers[1].final_registers, .windows = &self.registers } };
    }
};
fn codecFixture(a: std.mem.Allocator) !void {
    var fixture: Fixture = .{};
    fixture.init();
    const expected = fixture.expected();
    const raw = try File.encode(a, expected, .{});
    defer a.free(raw);
    const pin = File.Pin{ .byte_len = raw.len, .sha256 = Files.hash(raw) };
    const owner = try File.decode(a, raw, pin, expected, .{});
    defer owner.deinit();
    try owner.validate(expected);
    try std.testing.expect(owner.expected().input_words.ptr != fixture.input[0..].ptr);
    const first = owner.parsed.value.windows[0].data.publicData(owner.expected().input_words);
    const second = owner.parsed.value.windows[1].data.publicData(owner.expected().input_words);
    try std.testing.expect(first.io_entries.input_words.ptr == second.io_entries.input_words.ptr);
    const occurrence = std.mem.count(u8, raw, "\"input_words\"");
    try std.testing.expectEqual(@as(usize, 1), occurrence);
}
test "global expected public: one durable input survives full window roundtrip" {
    try codecFixture(std.testing.allocator);
}
test "global expected public: equal storage hash cannot admit changed expected completion or raw bytes" {
    var fixture: Fixture = .{};
    fixture.init();
    const expected = fixture.expected();
    const raw = try File.encode(std.testing.allocator, expected, .{});
    defer std.testing.allocator.free(raw);
    const pin = File.Pin{ .byte_len = raw.len, .sha256 = Files.hash(raw) };
    var changed = fixture;
    changed.init();
    changed.input[0] ^= 1;
    try std.testing.expectError(error.UntrustedExpectedPublicJob, File.decode(std.testing.allocator, raw, pin, changed.expected(), .{}));
    changed.init();
    changed.windows[0].data.completion = P.Completion.unretiredProgramFetch(0x1004, 0x00000013);
    try std.testing.expectError(error.UntrustedExpectedPublicJob, File.decode(std.testing.allocator, raw, pin, changed.expected(), .{}));
    changed.init();
    changed.windows[0].profile = .rv32im_zkvm_ethereum_v1;
    try std.testing.expectError(error.UntrustedExpectedPublicJob, File.decode(std.testing.allocator, raw, pin, changed.expected(), .{}));
}
test "global expected public: counted output and parse heap caps reject before success" {
    var fixture: Fixture = .{};
    fixture.init();
    try std.testing.expectError(error.ExpectedPublicJobResourceLimit, File.encode(std.testing.allocator, fixture.expected(), .{ .max_file_bytes = 1 }));
    try std.testing.expectError(error.ExpectedPublicJobResourceLimit, File.encode(std.testing.allocator, fixture.expected(), .{ .job = .{ .max_input_words = 1 } }));
    const raw = try File.encode(std.testing.allocator, fixture.expected(), .{});
    defer std.testing.allocator.free(raw);
    const pin = File.Pin{ .byte_len = raw.len, .sha256 = Files.hash(raw) };
    if (File.decode(std.testing.allocator, raw, pin, fixture.expected(), .{ .max_owned_bytes = 1 })) |owner| {
        owner.deinit();
        return error.ExpectedParseCapRejection;
    } else |failure| {
        try std.testing.expectEqual(error.OutOfMemory, failure);
    }
}
test "global expected public: immutable retained owner outlives original publication session" {
    var fixture: Fixture = .{};
    fixture.init();
    const raw = try File.encode(std.testing.allocator, fixture.expected(), .{});
    defer std.testing.allocator.free(raw);
    const owner = try File.decode(std.testing.allocator, raw, .{ .byte_len = raw.len, .sha256 = Files.hash(raw) }, fixture.expected(), .{});
    const retained = try owner.retain();
    owner.deinit();
    defer retained.deinit();
    fixture.input[0] = 0;
    try std.testing.expectEqual(@as(u32, 0xfefd1234), retained.expected().input_words[0]);
    try std.testing.expectEqual(@as(usize, 1), retained.references.load(.acquire));
}
test "global expected public: original raw field mutation cannot reuse independent job admission" {
    var fixture: Fixture = .{};
    fixture.init();
    const raw = try File.encode(std.testing.allocator, fixture.expected(), .{});
    defer std.testing.allocator.free(raw);
    const owner = try File.decode(std.testing.allocator, raw, .{ .byte_len = raw.len, .sha256 = Files.hash(raw) }, fixture.expected(), .{});
    defer owner.deinit();
    const windows = @constCast(owner.parsed.value.windows);
    windows[0].data.initial_pc += 4;
    try std.testing.expectError(error.UntrustedExpectedPublicJob, owner.validate(fixture.expected()));
}
test "global expected public: encode parse and owner construction exhaustively roll back" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, codecFixture, .{});
}
test "global expected public: durable publisher is exclusive and failed reopen stays terminal" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture: Fixture = .{};
    fixture.init();
    const pin = try File.write(std.testing.allocator, directory.dir, fixture.expected(), .{});
    try std.testing.expectError(error.ExistingV5BundleArtifact, File.write(std.testing.allocator, directory.dir, fixture.expected(), .{}));
    var changed = fixture;
    changed.init();
    changed.input[0] ^= 1;
    try std.testing.expectError(error.UntrustedExpectedPublicJob, File.read(std.testing.allocator, directory.dir, pin, changed.expected(), .{}));
    const owner = try File.read(std.testing.allocator, directory.dir, pin, fixture.expected(), .{});
    defer owner.deinit();
    try owner.validate(fixture.expected());
}

test "global expected public: decoded job retains actual aggregate allocator through final owner teardown" {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    var fixture: Fixture = .{};
    fixture.init();
    const raw = try File.encode(std.testing.allocator, fixture.expected(), .{});
    defer std.testing.allocator.free(raw);
    const shared = try Budget.create(std.testing.allocator, 1 << 20);
    const owner = File.decode(shared.allocator(), raw, .{ .byte_len = raw.len, .sha256 = Files.hash(raw) }, fixture.expected(), .{}) catch |failure| {
        shared.destroy();
        return failure;
    };
    shared.destroy();
    defer owner.deinit();
    try owner.validate(fixture.expected());
    try std.testing.expect(owner.parent_owner != null);
    try std.testing.expect(owner.parent_owner.?.snapshot().live_bytes > 0);
}
