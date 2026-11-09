//! Explicit OP-native direct capture. The independently pinned immutable image
//! remains pristine; a separately pinned execution image produces advice only.
//! Compact tapes are retired after each ordered RAM-ledger append.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const A = front.rv64_air;
const Config = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Program = @import("../word16_execution/program.zig").Program;
const Native = @import("../word16_execution/prepared.zig").Prepared;
const Collector = @import("../word16_global_execution/services/collector.zig");
const Memory = @import("../word16_execution/memory/statement.zig");
const Coverage = @import("../word16_execution/coverage.zig");
/// Producer-only custody hook, after chronological advice owns every event and
/// raw CPU capture rows have been retired. It cannot supply public authority.
/// The current prepared shard is borrowed synchronously; failure aborts capture.
pub const Hooks = struct {
    context: ?*anyopaque = null,
    completed: ?*const fn (?*anyopaque, usize, *Native) anyerror!void = null,
};
pub const Owner = struct {
    allocator: std.mem.Allocator,
    native: []*Native,
    advice: Collector.Advice,
    steps: u64,
    final_pc: u64,
    final_registers: [32]u64,
    pub fn deinit(self: *Owner) void {
        self.advice.deinit();
        for (self.native) |n| {
            n.deinit();
            self.allocator.destroy(n);
        }
        self.allocator.free(self.native);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, config: Config.Config, image: *const Image.Owner, program: *const Program) !Owner {
        return initWithHooks(a, config, image, program, .{});
    }
    pub fn initWithHooks(a: std.mem.Allocator, config: Config.Config, image: *const Image.Owner, program: *const Program, hooks: Hooks) !Owner {
        try Config.validateBudgetForOp(config);
        if (program.profile != .ethereum_services_op_v1) return error.UnqualifiedOpSetup;
        const elf = try std.fs.cwd().readFileAlloc(a, config.elf, 64 << 20);
        defer a.free(elf);
        const input = try std.fs.cwd().readFileAlloc(a, config.input, rv.ethereum_contract.INPUT_CAPACITY_MAX - 4);
        defer a.free(input);
        try Config.pin(elf, config.elf_sha256);
        try Config.pin(input, config.input_sha256);
        var loaded = try rv.ethereum_contract.load(a, config.symbols, elf, input);
        defer loaded.deinit();
        var session = try rv.ethereum_services.Session.initWithProfile(a, rv.machine.Cpu.init(loaded.info.entry, config.symbols.stack_top), &loaded.memory, .{ .max_retirements = config.max_steps }, .ethereum_services_op_v1);
        defer session.deinit();
        var builder = Collector.Builder.init(a, Memory.fromOwner(image));
        defer builder.deinit();
        var native = std.ArrayList(*Native).empty;
        errdefer {
            for (native.items) |n| {
                n.deinit();
                a.destroy(n);
            }
            native.deinit(a);
        }
        while (session.keccak.base.cpu.pc != config.terminal_pc or native.items.len == 0) {
            if (native.items.len >= 256 or (config.max_batches != 0 and native.items.len >= config.max_batches)) return error.OpNativeCaptureShardLimit;
            const cpu = &session.keccak.base.cpu;
            var tape = try rv.compact_tape.Tape.init(a, config.batch_steps, cpu.pc, cpu.retired, .ethereum_services_op_v1);
            defer tape.deinit();
            var boundary = A.word16_execution.types.Boundary{ .steps = 0, .initial_pc = cpu.pc, .final_pc = undefined, .initial_registers = cpu.regs, .final_registers = undefined, .register_clocks = @splat(0) };
            while (boundary.steps < config.batch_steps and cpu.pc != config.terminal_pc) {
                if (cpu.retired >= config.max_steps) return error.OpNativeCaptureStepLimit;
                var event: rv.ethereum_services.Event = undefined;
                const row = if (try session.step(&event)) |retirement| block: {
                    try tape.append(retirement);
                    break :block retirement;
                } else block: {
                    try tape.appendEvent(event);
                    break :block event.retirement();
                };
                const effects = rv.execution_profile.effects(.ethereum_services_op_v1, row.opcode);
                const tick: u32 = 4 * boundary.steps;
                if (effects.reads_rs1 and row.rs1 != 0) boundary.register_clocks[row.rs1] = tick + 1;
                if (effects.reads_rs2 and row.rs2 != 0) boundary.register_clocks[row.rs2] = tick + 2;
                if (effects.writes_rd and row.rd != 0) boundary.register_clocks[row.rd] = tick + 3;
                boundary.steps += 1;
            }
            if (boundary.steps == 0) return error.InvalidOpNativeCapture;
            boundary.final_pc = cpu.pc;
            boundary.final_registers = cpu.regs;
            const n = try a.create(Native);
            errdefer a.destroy(n);
            n.* = try Native.captureForOpServices(a, program, boundary, @intCast(native.items.len + 1), try Coverage.minimalCpuLog(boundary.steps), &tape, .{ .deduplicate_shift = true });
            errdefer n.deinit();
            try builder.append(n, &tape);
            // The ordered ledger now owns chronological RAM/service advice.
            // Projection retains its independent 56-byte CPU metadata; raw
            // records are no longer needed, exactly as on the v3 capture path.
            n.cpu.?.releaseCaptureRecords();
            if (hooks.completed) |completed| try completed(hooks.context, native.items.len, n);
            try native.append(a, n);
        }
        var advice = try builder.finish();
        errdefer advice.deinit();
        const last = native.items[native.items.len - 1].cpu orelse return error.PreparedExecutionConsumed;
        _ = try @import("../word16_global_execution/ethereum/terminal.zig").require(image, last.public, advice.terminal);
        return .{ .allocator = a, .native = try native.toOwnedSlice(a), .advice = advice, .steps = session.keccak.base.cpu.retired, .final_pc = session.keccak.base.cpu.pc, .final_registers = session.keccak.base.cpu.regs };
    }
};
