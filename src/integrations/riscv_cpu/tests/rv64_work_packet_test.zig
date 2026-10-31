const std = @import("std");
const W = @import("../rv64_prepared_work_packet.zig");
const A = @import("../rv64_authenticated_execution.zig");
const B = @import("../rv64_ethereum_batch.zig");
const Request = @import("../rv64_ethereum_request.zig");
const rv = A.frontend.rv64;
const R = A.R;
const a = std.testing.allocator;
const pc: u64 = 0x1000_0000_0000_0000;
const pointer: u64 = 0xffff_ffff_ffff_fe00;
const memory_program = [_]u32{ 0x0020b023, 0x0000b183, 0xff9ff06f, 0x0000000f };
const empty_program = [_]u32{ 0x00100193, 0xffdff06f };
pub const Options = struct { profile: rv.execution_profile.Profile = .ethereum_services_v2, control: A.rv.control_policy.Policy = .limbs24_v2, state: A.rv.state_policy.Policy = .cyclic_canonical_v3, steps: u32 = 2, initial_clock: u64 = (1 << 53) + 17, memory: bool = true };
pub const Fixture = struct {
    authority: A.Full.ProgramAuthority,
    policy: R.policy.Policy,
    tape: rv.compact_tape.Tape,
    finished: B.Finished,
    native: ?R.native_frontier.Prepared,
    cache: ?R.values.Cache,
    metadata: W.Metadata,
    pub fn init(allocator: std.mem.Allocator, options: Options) !Fixture {
        var memory = rv.memory.Memory.init(allocator, .{});
        defer memory.deinit();
        const words: []const u32 = if (options.memory) &memory_program else &empty_program;
        try memory.map(.{ .start = pc, .size = 16, .permissions = .{ .read = true, .execute = true } });
        try memory.map(.{ .start = pointer, .size = 512, .permissions = .{ .read = true, .write = true } });
        for (words, 0..) |word, i| {
            var raw: [4]u8 = undefined;
            std.mem.writeInt(u32, &raw, word, .little);
            try memory.initialize(pc + 4 * i, &raw);
        }
        var authority = try A.Full.ProgramAuthority.initWithControl(allocator, .{ .base = pc, .words = words }, options.profile, options.control);
        errdefer authority.deinit();
        var policy = try R.policy.Policy.fromMemory(allocator, &memory);
        errdefer policy.deinit();
        var cache = try R.values.Cache.fromMemory(allocator, .chunk512, &memory);
        errdefer cache.deinit();
        var tape = try rv.compact_tape.Tape.init(allocator, options.steps, pc, options.initial_clock, options.profile);
        errdefer tape.deinit();
        var capture = try rv.boundary_capture.Capture.init(allocator, options.initial_clock, options.steps, 1);
        defer capture.deinit();
        var cpu = rv.machine.Cpu.init(pc, 0);
        cpu.retired = options.initial_clock;
        cpu.regs[1] = pointer;
        cpu.regs[2] = std.math.maxInt(u64);
        var batch = try B.Batch.init(&authority, &tape, &capture, cpu.regs, .{ 1, 1, 1 });
        batch.state_policy = options.state;
        for (0..options.steps) |_| {
            const row = try cpu.step(&memory);
            try tape.append(row);
            try capture.append(row, &memory);
            try batch.observe(row);
        }
        var finished = try batch.finish(allocator, &cpu, &memory, &policy, .chunk512);
        errdefer finished.deinit();
        var native: ?R.native_frontier.Prepared = if (finished.openings) |*value| try R.native_frontier.Prepared.init(allocator, &cache, value) else null;
        errdefer if (native) |*value| value.deinit();
        const identity = try W.identityFor(config(options), &authority, &policy);
        return .{ .authority = authority, .policy = policy, .tape = tape, .finished = finished, .native = native, .cache = cache, .metadata = .{ .identity = identity, .index = 7, .first_step = options.initial_clock, .before = cache.root(), .after = if (native) |value| value.witness.after else cache.root() } };
    }
    pub fn view(self: *const Fixture) W.View {
        return .{ .metadata = self.metadata, .finished = &self.finished, .native = if (self.native) |*value| value else null, .tape = &self.tape };
    }
    pub fn expected(self: *const Fixture) W.Expected {
        return .{ .identity = self.metadata.identity, .authority = &self.authority, .policy = &self.policy, .state_policy = self.finished.public.state_policy };
    }
    pub fn retireCache(self: *Fixture) void {
        if (self.cache) |*value| value.deinit();
        self.cache = null;
    }
    pub fn deinit(self: *Fixture) void {
        self.retireCache();
        if (self.native) |*value| value.deinit();
        self.finished.deinit();
        self.tape.deinit();
        self.policy.deinit();
        self.authority.deinit();
    }
};
fn config(options: Options) Request.Config {
    return .{ .elf = "", .input = "", .elf_sha256 = "00" ** 32, .input_sha256 = "11" ** 32, .expected_output = "22" ** 43, .symbols = std.mem.zeroes(rv.ethereum_contract.Symbols), .output_directory = "", .terminal_pc = pc + 8, .batch_steps = options.steps, .max_steps = std.math.maxInt(u64), .control_policy = options.control, .state_policy = options.state };
}
test "portable work packet roundtrips supported ABIs and controls after native Memory and Cache death" {
    for ([_]rv.execution_profile.Profile{ .ethereum_services_v1, .ethereum_services_v2 }) |profile| for ([_]A.rv.control_policy.Policy{ .bytes_v1, .limbs24_v2 }) |control| {
        var fixture = try Fixture.init(a, .{ .profile = profile, .control = control });
        defer fixture.deinit();
        fixture.retireCache();
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const file = try temp.dir.createFile("job", .{ .read = true });
        defer file.close();
        const digest = try W.write(file, fixture.view());
        var loaded = try W.read(a, file, fixture.expected(), .{});
        defer loaded.deinit();
        try std.testing.expectEqualDeep(digest, loaded.content_digest);
        try std.testing.expectEqualDeep(fixture.metadata, loaded.metadata);
        try std.testing.expectEqualDeep(fixture.finished.cells, loaded.finished.cells);
        try std.testing.expectEqualSlices(u64, fixture.finished.openings.?.words, loaded.finished.openings.?.words);
        try std.testing.expectEqualDeep(fixture.native.?.io, loaded.native.?.io);
        try std.testing.expectEqualSlices(rv.compact_tape.Step, fixture.tape.steps(), loaded.tape.steps());
        try std.testing.expectEqualSlices(u32, fixture.authority.words, loaded.finished.public.statement.program.words);
        try std.testing.expectEqualDeep(fixture.authority.opcodes, loaded.finished.public.statement.opcodes);
        try std.testing.expectEqual(std.math.maxInt(u64), loaded.finished.cells[0].final);
        try std.testing.expectEqual(pointer, loaded.finished.cells[0].address);
        try std.testing.expectEqual(@as(u64, (1 << 53) + 17), loaded.metadata.first_step);
    };
}
test "portable work packet supports no RAM and streams Tape across buffer boundaries" {
    for ([_]bool{ false, true }) |has_memory| {
        var fixture = try Fixture.init(a, .{ .memory = has_memory, .steps = 2048 });
        defer fixture.deinit();
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const file = try temp.dir.createFile("job", .{ .read = true });
        defer file.close();
        _ = try W.write(file, fixture.view());
        var loaded = try W.read(a, file, fixture.expected(), .{});
        defer loaded.deinit();
        try std.testing.expectEqual(has_memory, loaded.native != null);
        try std.testing.expectEqual(@as(usize, 2048), loaded.tape.len);
        try std.testing.expectEqualSlices(rv.compact_tape.Step, fixture.tape.steps(), loaded.tape.steps());
    }
}
fn readAllocated(allocator: std.mem.Allocator, file: std.fs.File, expected: W.Expected) !void {
    var loaded = try W.read(allocator, file, expected, .{});
    defer loaded.deinit();
}
test "portable work packet every decode allocation failure balances narrow owners" {
    var fixture = try Fixture.init(a, .{});
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("job", .{ .read = true });
    defer file.close();
    _ = try W.write(file, fixture.view());
    try std.testing.checkAllAllocationFailures(a, readAllocated, .{ file, fixture.expected() });
}
