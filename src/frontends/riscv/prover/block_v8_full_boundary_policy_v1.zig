//! Independent full-execution boundary authority. No execution is skipped.
//! Output admission must be coupled to the terminal Compact RAM boundary AIR;
//! matching a host snapshot alone never grants a successful proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v7_program_image_v1.zig");
pub const Ports = @import("block_v8_execution_boundary_ports_v1.zig");
pub const Trusted = struct { elf_sha256: [32]u8, input_sha256: [32]u8, total_cycles: u64, expected_output: [43]u8, config: core.pcs.PcsConfig };
pub const Limits = struct { initial: Initial.Limits = .{}, snapshot: Capture.Limits = .{} };
pub const Owned = struct {
    a: std.mem.Allocator,
    initial_snapshot: Capture.Snapshot,
    initial_policy: Ports.Initial,
    terminal_policy: Ports.Terminal,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    program_root: [32]u8,
    config: core.pcs.PcsConfig,
    digest: [32]u8,
    pub fn derive(a: std.mem.Allocator, elf: []const u8, input: []const u8, trusted: Trusted, limits: Limits) !Owned {
        if (!std.meta.eql(Capture.sha(elf), trusted.elf_sha256) or !std.meta.eql(Capture.sha(input), trusted.input_sha256) or trusted.total_cycles == 0 or input.len > limits.snapshot.max_input_bytes) return error.UntrustedFullExecutionBoundary;
        try @import("blake3_execution_protocol.zig").validateConfig(trusted.config);
        var initialized = try Initial.Owned.derive(a, elf, trusted.elf_sha256, .rv32im_zkvm_ethereum_sha_v1, limits.initial);
        defer initialized.deinit();
        var image = try Image.Owned.init(a, elf, &initialized, limits.initial);
        defer image.deinit();
        var session = try @import("../runner/mod.zig").EthereumShaExecutionSession.init(a, elf, .{ .input = input, .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
        defer session.deinit();
        var snapshot = try Capture.snapshot(a, session.cpu, &session.memory, limits.snapshot);
        errdefer snapshot.deinit(a);
        var expected: [32]u32 = @splat(0);
        expected[2] = initialized.info.stack_pointer;
        expected[3] = initialized.info.global_pointer;
        if (snapshot.cpu.pc != initialized.info.entry_point or !std.meta.eql(snapshot.cpu.regs, expected)) return error.UntrustedFullInitialCpu;
        const Terminal = @import("block_v7_terminal_protocol_v1.zig").Policy;
        const terminal = Terminal{ .final_cycle = trusted.total_cycles, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = trusted.expected_output };
        try terminal.validate();
        if (valueAt(snapshot.words, terminal.halt_address) != 0) return error.InvalidFullInitialHalt;
        var initial_ch = core.proof_suites.Blake3.Channel{};
        initial_ch.mixU32s(&.{ 0x42384649, 1, @intFromEnum(initialized.info.execution_profile) });
        initial_ch.mixRoot(trusted.elf_sha256);
        initial_ch.mixRoot(trusted.input_sha256);
        initial_ch.mixRoot(image.root.bytes);
        trusted.config.mixInto(&initial_ch);
        initial_ch.mixRoot(snapshot.identity());
        initial_ch.mixU32s(&.{snapshot.cpu.pc});
        initial_ch.mixU32s(&snapshot.cpu.regs);
        var terminal_ch = core.proof_suites.Blake3.Channel{};
        terminal_ch.mixU32s(&.{ 0x42384654, 1 });
        terminal_ch.mixRoot(trusted.elf_sha256);
        terminal_ch.mixRoot(image.root.bytes);
        trusted.config.mixInto(&terminal_ch);
        terminal_ch.mixU64(terminal.final_cycle);
        terminal_ch.mixU32s(&.{ terminal.halt_address, terminal.length_address, terminal.data_address, terminal.output_end });
        for (terminal.output) |byte| terminal_ch.mixU32s(&.{byte});
        const first = Ports.Initial{ .policy_id = initial_ch.digestBytes(), .snapshot_id = snapshot.identity(), .cpu = snapshot.cpu };
        const last = Ports.Terminal{ .policy_id = terminal_ch.digestBytes(), .policy = terminal };
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42384642, 1 });
        ch.mixRoot(first.policy_id);
        ch.mixRoot(last.policy_id);
        return .{ .a = a, .initial_snapshot = snapshot, .initial_policy = first, .terminal_policy = last, .elf_sha256 = trusted.elf_sha256, .input_sha256 = trusted.input_sha256, .program_root = image.root.bytes, .config = trusted.config, .digest = ch.digestBytes() };
    }
    pub fn deinit(self: *@This()) void {
        self.initial_snapshot.deinit(self.a);
        self.* = undefined;
    }
    pub fn windowOptions(self: *const @This(), skip: u64, cycles: u32) !Ports.Options {
        const end = try std.math.add(u64, skip, cycles);
        if (cycles == 0 or end > self.terminal_policy.policy.final_cycle) return error.InvalidFullWindowCoverage;
        return .{ .initial = if (skip == 0) self.initial_policy else null, .terminal = if (end == self.terminal_policy.policy.final_cycle) self.terminal_policy else null };
    }
    pub fn requireInitial(self: *const @This(), snapshot: Capture.Snapshot, first_cycle: u64) !void {
        if (first_cycle != 1 or !std.meta.eql(snapshot.identity(), self.initial_policy.snapshot_id) or !std.meta.eql(snapshot.cpu, self.initial_policy.cpu)) return error.UntrustedFullInitialBoundary;
    }
};
fn valueAt(words: []const Capture.Word, address: u32) u32 {
    for (words) |word| {
        if (word.address == address) return word.value;
        if (word.address > address) break;
    }
    return 0;
}
pub const production_active = false;

fn env(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingFullBoundaryBenchmarkInput;
}
fn hash(name: [:0]const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    const text = try env(name);
    if (text.len != 64) return error.InvalidFullBoundaryBenchmarkPin;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}
pub fn fromEnvironment(a: std.mem.Allocator, elf: []const u8, elf_pin: [32]u8, config: @import("stwo_core").pcs.PcsConfig) !?Owned {
    if (std.posix.getenv("STWO_B8_FULL_INPUT") == null) return null;
    const input = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_FULL_INPUT"), 4 << 20);
    defer a.free(input);
    const output = try std.fs.cwd().readFileAlloc(a, try env("STWO_B8_EXPECTED_OUTPUT"), 44);
    defer a.free(output);
    if (output.len != 43 or !std.meta.eql(Capture.sha(input), try hash("STWO_B8_FULL_INPUT_SHA256")) or !std.meta.eql(Capture.sha(output), try hash("STWO_B8_EXPECTED_OUTPUT_SHA256"))) return error.UntrustedFullBoundaryBenchmarkBytes;
    return try Owned.derive(a, elf, input, .{ .elf_sha256 = elf_pin, .input_sha256 = try hash("STWO_B8_FULL_INPUT_SHA256"), .total_cycles = try std.fmt.parseInt(u64, try env("STWO_B8_TOTAL_CYCLES"), 10), .expected_output = output[0..43].*, .config = config }, .{});
}
