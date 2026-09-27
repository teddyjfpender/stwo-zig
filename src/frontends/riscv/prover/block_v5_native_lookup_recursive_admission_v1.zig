//! Independent full six-table provider policy. Plans are reconstructed from the
//! exact execution/caller/byte demand roster, never from decoded proof counters.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_native_lookup_proof_v1.zig");
const Assembly = @import("block_v5_native_lookup_assembly_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { max_capture_bytes: usize = 256 << 20, max_preparation_bytes: usize = 512 << 20 };
pub fn templateId(config: core.pcs.PcsConfig, fixed_root: [32]u8) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354c4b, VERSION, Assembly.Count }); // B5LK
    channel.mixRoot(@import("../air/lang/relation.zig").registryOrderDigest());
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@embedFile("block_v5_native_lookup_assembly_v1.zig"));
    hash.update(@embedFile("../air/lookups/tables/schema_definition.zig"));
    hash.update(@embedFile("../air/lookups/tables/equations.zig"));
    hash.update(@embedFile("../air/lookups/tables/verifier.zig"));
    hash.update(@embedFile("../air/lookups/tables/layout.zig"));
    hash.update(@embedFile("block_v5_native_lookup_proof_v1.zig"));
    hash.update(@embedFile("../air/logup_equations.zig"));
    channel.mixRoot(hash.finalResult());
    channel.mixRoot(fixed_root);
    config.mixInto(&channel);
    return channel.digestBytes();
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    plan: Native.Plan,
    index: u32,
    roots: Seal.Roots,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    template_id: [32]u8,
    logs: [3][]u32,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, plan: Native.Plan, roots: Seal.Roots, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        var self = Prepared{ .allocator = a, .plan = plan, .index = plan.index, .roots = roots, .sealed = sealed, .pins = pins, .entries = entries, .config = pins.config, .template_id = templateId(pins.config, roots[0]), .logs = undefined, .limits = limits };
        try self.validateAuthority(self.template_id);
        self.logs[0] = try Assembly.logs(a, .fixed);
        errdefer a.free(self.logs[0]);
        self.logs[1] = try Assembly.logs(a, .main);
        errdefer a.free(self.logs[1]);
        self.logs[2] = try Assembly.logs(a, .interaction);
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.validateAuthority(expected);
        const tables = @import("../air/lookups/tables/mod.zig");
        for (self.logs, [_]Assembly.Tree{ .fixed, .main, .interaction }) |logs, tree| {
            var at: usize = 0;
            for (0..Assembly.Count) |index| {
                const kind: tables.schema.Kind = @enumFromInt(index);
                const width: usize = switch (tree) {
                    .fixed => 1 + tables.schema.arity(kind),
                    .main => 1,
                    .interaction => 4,
                };
                if (logs.len < at + width) return error.UntrustedLookupRecursiveGeometry;
                for (logs[at..][0..width]) |log| if (log != tables.schema.logSize(kind)) return error.UntrustedLookupRecursiveGeometry;
                at += width;
            }
            if (logs.len != at) return error.UntrustedLookupRecursiveGeometry;
        }
    }
    fn validateAuthority(self: *const Prepared, expected: [32]u8) !void {
        try Native.admit(self.plan, self.roots, self.sealed, self.pins, self.entries);
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        if (self.index != self.plan.index or self.index >= core.fields.m31.Modulus or
            self.index >= self.pins.counts[@intFromEnum(Seal.Family.native_lookup) - 1] or
            !std.meta.eql(self.config, self.pins.config) or !std.meta.eql(self.template_id, expected) or
            !std.meta.eql(expected, templateId(self.config, self.roots[0])) or
            self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0)
            return error.UntrustedLookupRecursiveAdmission;
        for (self.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedLookupRecursiveAdmission;
    }
};
