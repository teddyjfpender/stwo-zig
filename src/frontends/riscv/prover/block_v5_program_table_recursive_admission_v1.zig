//! Independently authenticated complete ROM/PCS policy, borrowed for preparation.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("block_v5_program_table_v1.zig");
const Native = @import("block_v5_program_table_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { max_capture_bytes: usize = 256 << 20, max_preparation_bytes: usize = 512 << 20 };
pub fn templateId(log: u32, config: core.pcs.PcsConfig) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x4235504b, VERSION, Source.VERSION, log, 6, 0, 4, 1, Native.Roster.Component(Native.Air).PROTOCOL_CONSTRAINT_DEGREE, 1, 2 });
    channel.mixRoot(Native.Air.SEMANTIC_DIGEST);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@embedFile("../recursion/air/universal_relation_binding.zig"));
    hash.update(@embedFile("../recursion/air/framework_interaction.zig"));
    hash.update(@embedFile("../recursion/air/universal_typed_component_component_for_manifest.zig"));
    hash.update(@embedFile("../recursion/air/universal_typed_verifier_component.zig"));
    hash.update(@embedFile("../recursion/air/universal_typed_geometry.zig"));
    channel.mixRoot(hash.finalResult());
    config.mixInto(&channel);
    return channel.digestBytes();
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    /// Independent complete ELF ROM/census storage must outlive this policy.
    plan: Source.Plan,
    index: u32,
    roots: [2][32]u8,
    sealed: Seal.Sealed,
    seal: Native.Seal,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    template_id: [32]u8,
    logs: [3][]u32,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, plan: Source.Plan, index: u32, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        var self = Prepared{ .allocator = a, .plan = plan, .index = index, .roots = sealed.program_first_roots, .sealed = sealed, .seal = sealed.programSeal(), .pins = pins, .entries = entries, .config = pins.config, .template_id = templateId(plan.log_size, pins.config), .logs = undefined, .limits = limits };
        try self.validateAuthority(self.template_id);
        var initialized: usize = 0;
        errdefer for (self.logs[0..initialized]) |logs| a.free(logs);
        for (&self.logs, [_]usize{ 6, 0, 4 }) |*logs, width| {
            logs.* = try a.alloc(u32, width);
            @memset(logs.*, plan.log_size);
            initialized += 1;
        }
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority(expected);
        for (self.logs, [_]usize{ 6, 0, 4 }) |logs, width| {
            if (logs.len != width) return error.UntrustedProgramRecursiveGeometry;
            for (logs) |log| if (log != self.plan.log_size) return error.UntrustedProgramRecursiveGeometry;
        }
    }
    fn validateAuthority(self: *const Prepared, expected: [32]u8) !void {
        try self.sealed.require(self.pins, self.entries);
        try self.plan.validate();
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        if (self.index != 0 or !std.meta.eql(self.config, self.pins.config) or !std.meta.eql(expected, self.template_id) or !std.meta.eql(expected, templateId(self.plan.log_size, self.config)) or self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0) return error.UntrustedProgramRecursiveAdmission;
        if (!std.meta.eql(self.seal, self.sealed.programSeal())) return error.UntrustedProgramRecursiveAdmission;
        try self.seal.validate(self.plan, self.roots);
        for (self.entries) |entry| if (entry.family == .program and entry.index == self.index) {
            if (!std.meta.eql(entry.roots, self.roots) or !std.meta.eql(entry.instance_id, try self.plan.digest())) return error.UntrustedProgramRecursiveAdmission;
            return;
        };
        return error.MissingProgramRecursiveProvider;
    }
};
