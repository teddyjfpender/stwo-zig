//! Software CSP guest execution. Explicit linker ABI, no proving capability.
const std = @import("std");
const rv = @import("mod.zig");
const allocator = std.heap.smp_allocator;
const contract = @import("csp_contract.zig");
const Config = contract.Config;
const Sample = struct { setup_ns: u64, execution_ns: u64, instructions: u64, allocated_pages: usize, output: [64]u8 };

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.InvalidArguments;
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    const parsed = try std.json.parseFromSlice(Config, a, raw, .{});
    const config = parsed.value;
    if (config.samples == 0 or config.samples > 31 or config.max_steps == 0 or config.max_steps > 100000000) return error.InvalidBudget;
    if (config.expected_digest.len != 64) return error.InvalidExpectedOutput;
    const bytes = try std.fs.cwd().readFileAlloc(a, config.elf, 32 * 1024 * 1024);
    const input = try std.fs.cwd().readFileAlloc(a, config.input, 4096);
    var samples: [31]Sample = undefined;
    for (samples[0..config.samples]) |*sample| sample.* = try run(config, bytes, input);
    const encoded = try std.json.Stringify.valueAlloc(a, .{
        .profile = rv.profile.name,
        .proof_supported = false,
        .trace_retained = false,
        .cache_entries = 1024,
        .samples = samples[0..config.samples],
    }, .{});
    try std.fs.File.stdout().writeAll(encoded);
    try std.fs.File.stdout().writeAll("\n");
}

fn run(config: Config, bytes: []const u8, input: []const u8) !Sample {
    const symbols = config.symbols;
    var setup_timer = try std.time.Timer.start();
    var loaded = try contract.load(allocator, config, bytes, input);
    defer loaded.deinit();
    const image = loaded.info;
    const memory = &loaded.memory;
    var session = try rv.Session.init(allocator, rv.machine.Cpu.init(image.entry, symbols.stack_top), memory, .{ .max_retirements = config.max_steps });
    defer session.deinit();
    const setup_ns = setup_timer.read();
    var timer = try std.time.Timer.start();
    while (true) {
        const row = session.step() catch |err| {
            std.debug.print("CSP guest stopped at pc=0x{x}, retired={d}: {s}\n", .{ session.cpu.pc, session.cpu.retired, @errorName(err) });
            return err;
        };
        if (row.memory) |effect| {
            const address = effect.address.toInt();
            if (effect.write and address <= symbols.halt_flag + 3 and try rv.memory.endAddress(address, effect.width) >= symbols.halt_flag) {
                const flag = try memory.load(symbols.halt_flag, 4);
                if (flag == 1) break;
                if (flag != 0) return error.InvalidCompletion;
            }
        }
    }
    const execution_ns = timer.read();
    if (try memory.load(symbols.output_len, 4) != 32) return error.InvalidOutputLength;
    var output: [32]u8 = undefined;
    for (&output, 0..) |*byte, i| byte.* = @intCast(try memory.load(symbols.output_data + i, 1));
    const digest = std.fmt.bytesToHex(output, .lower);
    if (!std.mem.eql(u8, &digest, config.expected_digest)) return error.OutputMismatch;
    return .{ .setup_ns = setup_ns, .execution_ns = execution_ns, .instructions = session.cpu.retired, .allocated_pages = memory.pageCount(), .output = digest };
}
