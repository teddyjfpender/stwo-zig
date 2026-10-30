//! Qualification-only shared candidate. Export and runtime reconstruct exactly
//! the same admitted Program. CPU execution/first commitments (and optional
//! independent proof oracle) are fixture setup, outside the resident transaction.
//! No CPU witness columns survive this constructor or enter the device prover.
const std = @import("std");
const Program = @import("resident_native_program_v1.zig");

const Support = @import("../../frontends/riscv/prover/block_v7_execution_test_support.zig");
const Epoch = @import("../../frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
pub const Native = @import("../../frontends/riscv/prover/block_v7_native_proof_v1.zig");
const CPU = Native.For(@import("stwo_cpu_backend").CpuBackend);
pub const MAX_RETIREMENTS: u32 = 1 << 20;
pub const Security = enum {
    q8,
    q70,
    pub fn config(self: Security) @import("stwo_core").pcs.PcsConfig {
        return switch (self) {
            .q8 => @import("../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(),
            .q70 => @import("../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(),
        };
    }
};
pub const Options = struct {
    /// Total genuinely retired instructions, including setup and loop jumps.
    /// Null selects the original tiny candidate (3 for N4, 7 for N5).
    retirements: ?u32 = null,
    security: Security = .q8,
    q2: bool = false,
    cpu_reference: bool = false,
    pub fn count(self: Options, comptime N: usize) !u32 {
        comptime std.debug.assert(N == 4 or N == 5);
        const minimum: u32 = if (N == 5) 7 else 3;
        const n = self.retirements orelse minimum;
        if (n < minimum or n > MAX_RETIREMENTS) return error.InvalidResidentNativeRetirementCount;
        return n;
    }
};
pub const Selection = struct { trees: u8 = 4, options: Options = .{} };
fn environment(a: std.mem.Allocator, name: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(a, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
}
/// Shared by the offline CUDA exporter and actual proof harness. No geometry
/// knob exists here: all shape rows come from the runner's real retirements.
pub fn fromEnv(a: std.mem.Allocator) !Selection {
    var result: Selection = .{};
    if (try environment(a, "STWO_NATIVE_CANDIDATE_TREES")) |v| {
        defer a.free(v);
        if (std.mem.eql(u8, v, "4")) result.trees = 4 else if (std.mem.eql(u8, v, "5")) result.trees = 5 else return error.InvalidResidentNativeTreeSelection;
    }
    if (try environment(a, "STWO_NATIVE_CANDIDATE_RETIREMENTS")) |v| {
        defer a.free(v);
        result.options.retirements = std.fmt.parseInt(u32, v, 10) catch return error.InvalidResidentNativeRetirementCount;
    }
    if (try environment(a, "STWO_NATIVE_CANDIDATE_SECURITY")) |v| {
        defer a.free(v);
        if (std.mem.eql(u8, v, "q8")) result.options.security = .q8 else if (std.mem.eql(u8, v, "q70")) result.options.security = .q70 else return error.InvalidResidentNativeSecurity;
    }
    if (try environment(a, "STWO_NATIVE_CANDIDATE_LAYOUT")) |v| {
        defer a.free(v);
        if (std.mem.eql(u8, v, "q2")) result.options.q2 = true else if (std.mem.eql(u8, v, "q3")) result.options.q2 = false else return error.InvalidResidentNativeLayout;
    }
    _ = switch (result.trees) {
        4 => try result.options.count(4),
        5 => try result.options.count(5),
        else => unreachable,
    };
    return result;
}
fn loopJump(delta: i32) u32 {
    const value: u32 = @bitCast(delta);
    return ((value >> 20) & 1) << 31 | ((value >> 1) & 0x3ff) << 21 | ((value >> 11) & 1) << 20 | ((value >> 12) & 0xff) << 12 | 0x6f;
}

pub fn ForCommitments(comptime N: usize) type {
    return struct {
        allocator: std.mem.Allocator,
        program: *Program.ForCommitments(N).Owned,
        raw: []u32,
        retirement_count: usize,
        clock_count: usize,
        reference: ?Native.Proof,
        options: Options,
        mul_retirements: usize,
        load_retirements: usize,
        store_retirements: usize,
        const Self = @This();
        pub fn init(a: std.mem.Allocator, q2: bool, cpu_reference: bool) !Self {
            return initWithOptions(a, .{ .q2 = q2, .cpu_reference = cpu_reference });
        }
        pub fn initWithOptions(a: std.mem.Allocator, options: Options) !Self {
            const retired = try options.count(N);
            var code = if (N == 5) [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x001002b7, 0x10028293, 0x0082a023, 0x0002a483, 0x0000006f } else [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x0000006f };
            // Preserve the historical tiny ELF byte-for-byte. Larger cases
            // run a real backward JAL to MUL; no unexecuted padding is claimed.
            if (retired > code.len - 1) code[code.len - 1] = loopJump(-4 * @as(i32, @intCast(code.len - 3)));
            const elf = @import("../../frontends/riscv/runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
            var session = try @import("../../frontends/riscv/runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
            defer session.deinit();
            var executed = try session.startSegment(retired);
            defer executed.deinit();
            const rows = executed.execution_trace.rows.items;
            if (rows.len != retired) return error.IncompleteResidentNativeRetirement;
            var mul_count: usize = 0;
            var load_count: usize = 0;
            var store_count: usize = 0;
            for (rows) |row| {
                if (row.opcode == .MUL) mul_count += 1;
                if (row.is_load) load_count += 1;
                if (row.is_store) store_count += 1;
            }
            if (mul_count == 0 or (N == 5 and (load_count == 0 or store_count == 0))) return error.InvalidResidentNativeWorkload;
            const chain = &executed.state_chain_tracker;
            const clocks = try std.math.add(usize, chain.clock_updates_reg.items.len, chain.clock_updates_mem.items.len);
            const size = try std.math.add(usize, try std.math.mul(usize, rows.len, 24), try std.math.mul(usize, clocks, 5));
            const raw = try a.alloc(u32, size);
            errdefer a.free(raw);
            for (rows, 0..) |row, i| @memcpy(raw[24 * i ..][0..24], &encode(row));
            var cursor = 24 * rows.len;
            inline for (.{ chain.clock_updates_reg.items, chain.clock_updates_mem.items }) |updates| for (updates) |update| {
                @memcpy(raw[cursor..][0..5], &[_]u32{ @as(u32, update.addr_space), update.addr, update.clk, update.clk_prev, update.value });
                cursor += 5;
            };
            var counters = try @import("../../frontends/riscv/air/lookups/tables/mod.zig").counter.Set.init(a);
            defer counters.deinit(a);
            const config = options.security.config();
            var segment = try Support.Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
            defer segment.deinit();
            var pin = segment.pin;
            if (options.q2) pin.layout_mode = .degree_bounded_q2_v1;
            const entries = [_]Epoch.Entry{try pin.entry(a)};
            var counts: Epoch.Counts = @splat(0);
            counts[0] = 1;
            const epoch = try Epoch.Epoch.init(@splat(9), config, counts, &entries, 1);
            const profile = try Program.Profile.Owned.derive(a, pin, epoch, &entries, .{});
            defer profile.deinit();
            const program = try Program.ForCommitments(N).Owned.init(a, profile, .{});
            errdefer program.deinit();
            var reference: ?Native.Proof = null;
            errdefer if (reference) |*proof| proof.deinit(a);
            if (options.cpu_reference) {
                reference = try CPU.prove(a, &segment.first, segment.owner, segment.source.inputs, pin, epoch, &entries);
                _ = try CPU.verify(a, &reference.?, pin, epoch, &entries);
            }
            return .{ .allocator = a, .program = program, .raw = raw, .retirement_count = rows.len, .clock_count = clocks, .reference = reference, .options = options, .mul_retirements = mul_count, .load_retirements = load_count, .store_retirements = store_count };
        }
        pub fn deinit(self: *Self) void {
            if (self.reference) |*proof| proof.deinit(self.allocator);
            self.program.deinit();
            self.allocator.free(self.raw);
            self.* = undefined;
        }
        pub fn verify(self: *const Self, proof: *const Native.Proof) !void {
            const p = self.program.view().profile;
            _ = try CPU.verify(self.allocator, proof, p.pin, p.epoch, p.roster);
        }
    };
}

fn encode(row: @import("../../frontends/riscv/runner/trace.zig").TraceRow) [24]u32 {
    return .{ row.clk, row.pc, @intFromEnum(row.opcode), row.rd, row.rs1, row.rs2, @bitCast(row.imm), row.rs1_val, row.rs2_val, row.rs1_prev_clk, row.rs2_prev_clk, row.rd_prev_val, row.rd_prev_clk, row.rd_val, row.mem_addr, row.mem_val, row.mem_prev_word, row.mem_next_word, row.mem_prev_clk, @intFromBool(row.is_load), @intFromBool(row.is_store), @intFromBool(row.branch_taken), row.next_pc, row.inst_word };
}
