//! Durable independently expected PUBLIC job data. Storage pins are transport,
//! never verifier receipts. One input vector is shared by every window.
const std = @import("std");
const Public = @import("../air/public_data.zig");
const Profile = @import("../air/program/decode.zig").ExecutionProfile;
const Windows = @import("../prover/block_v5_register_windows_v1.zig");
const Export = @import("block_v5_global_public_export_policy_v1.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { max_windows: usize = 4096, max_input_words: usize = 16 << 20, max_output_words: usize = 16 << 20 };
/// The original data, excluding only the separately retained shared input slice.
pub const Data = struct {
    initial_pc: u32,
    final_pc: u32,
    clock: u32,
    initial_regs: [32]u32,
    final_regs: [32]u32,
    reg_last_clock: [32]u32,
    program_root: ?Public.Blake3PublicData.Root,
    initial_rw_root: ?Public.Blake3PublicData.Root,
    final_rw_root: ?Public.Blake3PublicData.Root,
    completion: ?Public.Completion,
    input_start: u32,
    input_len: u32,
    output_len: u32,
    output_len_addr: u32,
    output_data_addr: u32,
    output_words: []const Public.OutputWord,
    pub fn fromPublic(p: *const Public.Blake3PublicData) Data {
        return .{ .initial_pc = p.initial_pc, .final_pc = p.final_pc, .clock = p.clock, .initial_regs = p.initial_regs, .final_regs = p.final_regs, .reg_last_clock = p.reg_last_clock, .program_root = p.program_root, .initial_rw_root = p.initial_rw_root, .final_rw_root = p.final_rw_root, .completion = p.completion, .input_start = p.io_entries.input_start, .input_len = p.io_entries.input_len, .output_len = p.io_entries.output_len, .output_len_addr = p.io_entries.output_len_addr, .output_data_addr = p.io_entries.output_data_addr, .output_words = p.io_entries.output_words };
    }
    pub fn publicData(self: Data, input: []const u32) Public.Blake3PublicData {
        return .{ .initial_pc = self.initial_pc, .final_pc = self.final_pc, .clock = self.clock, .initial_regs = self.initial_regs, .final_regs = self.final_regs, .reg_last_clock = self.reg_last_clock, .program_root = self.program_root, .initial_rw_root = self.initial_rw_root, .final_rw_root = self.final_rw_root, .completion = self.completion, .io_entries = .{ .input_start = self.input_start, .input_len = self.input_len, .input_words = input, .output_len = self.output_len, .output_len_addr = self.output_len_addr, .output_data_addr = self.output_data_addr, .output_words = self.output_words } };
    }
    pub fn requireEqual(self: Data, other: Data) !void {
        inline for (std.meta.fields(Data)) |field| {
            if (comptime std.mem.eql(u8, field.name, "output_words")) {
                if (self.output_words.len != other.output_words.len) return error.UntrustedExpectedPublicJob;
                for (self.output_words, other.output_words) |a, b| if (!std.meta.eql(a, b)) return error.UntrustedExpectedPublicJob;
            } else if (!std.meta.eql(@field(self, field.name), @field(other, field.name))) return error.UntrustedExpectedPublicJob;
        }
    }
};
pub const Window = struct { profile: Profile, first_cycle: u64, last_cycle: u64, data: Data };
/// Borrowed independent job proposal; callers obtain this from their public job
/// authority, never from proof files. validate does not verify a proof.
pub const Expected = struct {
    coverage_digest: [32]u8,
    seal_digest: [32]u8,
    recipe: u32,
    input_words: []const u32,
    windows: []const Window,
    register_plan: Windows.Plan,
    pub const complete_block_authority = false;
    pub fn validate(self: Expected, limits: Limits) !void {
        if (self.windows.len == 0 or self.windows.len > limits.max_windows or self.input_words.len > limits.max_input_words or self.windows.len != self.register_plan.windows.len) return error.ExpectedPublicJobResourceLimit;
        try self.register_plan.validate();
        var output_count: usize = 0;
        for (self.windows, 0..) |window, index| {
            var data = window.data.publicData(self.input_words);
            try data.validate();
            if (data.clock == 0 or window.first_cycle == 0 or window.last_cycle < window.first_cycle or window.last_cycle - window.first_cycle != @as(u64, data.clock) - 1) return error.UntrustedExpectedPublicJob;
            try self.register_plan.windows[index].requirePublic(@intCast(index), window.first_cycle, &data);
            if (data.completion.?.kind != .halt_flag) _ = try @import("../air/program/decode.zig").decodeProgramWordForProfile(window.profile, data.completion.?.value);
            output_count = try std.math.add(usize, output_count, data.io_entries.output_words.len);
            if (output_count > limits.max_output_words) return error.ExpectedPublicJobResourceLimit;
        }
    }
    /// Full original fields are compared, not just their transported SHA/B5PD.
    pub fn requireEqual(self: Expected, other: Expected, limits: Limits) !void {
        try self.validate(limits);
        try other.validate(limits);
        if (!std.meta.eql(self.coverage_digest, other.coverage_digest) or !std.meta.eql(self.seal_digest, other.seal_digest) or self.recipe != other.recipe or !std.mem.eql(u32, self.input_words, other.input_words) or self.windows.len != other.windows.len or !std.meta.eql(try self.register_plan.digest(), try other.register_plan.digest())) return error.UntrustedExpectedPublicJob;
        for (self.windows, other.windows) |a, b| {
            if (a.profile != b.profile or a.first_cycle != b.first_cycle or a.last_cycle != b.last_cycle) return error.UntrustedExpectedPublicJob;
            try a.data.requireEqual(b.data);
        }
    }
    /// Original admission/coverage is independently reconstructed elsewhere.
    /// This equality cannot turn a file into native/source proof authority.
    pub fn bind(self: Expected, original: Export.Policy, limits: Limits) !Export.Policy {
        try self.validate(limits);
        try original.validate();
        if (!std.meta.eql(self.coverage_digest, original.original.plan.pinned_digest) or !std.meta.eql(self.seal_digest, original.original.plan.meta.seal_digest) or self.recipe != @intFromEnum(original.original.plan.meta.recipe) or self.windows.len != original.windows.windows.len or !std.meta.eql(try self.register_plan.digest(), try original.windows.digest())) return error.UntrustedExpectedPublicJob;
        for (self.windows, 0..) |window, index| {
            const native = (try original.native(@intCast(index))).admitted;
            if (window.profile != native.template.execution_profile or window.first_cycle != native.pin.context.first_cycle or window.last_cycle != native.pin.context.last_cycle or !std.mem.eql(u32, self.input_words, native.shape.public_data.io_entries.input_words)) return error.UntrustedExpectedPublicJob;
            try window.data.requireEqual(Data.fromPublic(&native.shape.public_data));
        }
        return .{ .original = original.original, .windows = self.register_plan };
    }
};
/// Helper owns only descriptor arrays; borrowed data/input/policy remain caller
/// owned. It is a proposal construction helper, never cryptographic acceptance.
pub const Borrowed = struct {
    allocator: std.mem.Allocator,
    expected: Expected,
    pub fn deinit(self: *Borrowed) void {
        self.allocator.free(self.expected.windows);
        self.* = undefined;
    }
};
pub fn fromPolicy(a: std.mem.Allocator, policy: Export.Policy, limits: Limits) !Borrowed {
    try policy.validate();
    if (policy.windows.windows.len > limits.max_windows) return error.ExpectedPublicJobResourceLimit;
    const windows = try a.alloc(Window, policy.windows.windows.len);
    errdefer a.free(windows);
    for (windows, 0..) |*window, index| {
        const p = (try policy.native(@intCast(index))).admitted;
        window.* = .{ .profile = p.template.execution_profile, .first_cycle = p.pin.context.first_cycle, .last_cycle = p.pin.context.last_cycle, .data = Data.fromPublic(&p.shape.public_data) };
    }
    const native = (try policy.native(0)).admitted;
    const expected = Expected{ .coverage_digest = policy.original.plan.pinned_digest, .seal_digest = policy.original.plan.meta.seal_digest, .recipe = @intFromEnum(policy.original.plan.meta.recipe), .input_words = native.shape.public_data.io_entries.input_words, .windows = windows, .register_plan = policy.windows };
    try expected.validate(limits);
    _ = try expected.bind(policy, limits);
    return .{ .allocator = a, .expected = expected };
}
