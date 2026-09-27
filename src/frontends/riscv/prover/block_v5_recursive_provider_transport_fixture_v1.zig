//! Actual independently validated policy with literal nonproof leaf bytes.
//! No fixture here creates or qualifies a cryptographic acceptance receipt.
const std = @import("std");
const core = @import("stwo_core");
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const Range = @import("block_v5_range16_v1.zig");
const Native = @import("block_v5_range16_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Transport = @import("block_v5_recursive_provider_store_v1.zig");
pub const T = Transport.ForFamily(.range16);
pub const D = @import("block_v5_recursive_provider_definition_v1.zig").ForFamily(.range16);
pub const wires = [_]D.Bus.Wire{
    .{ .circuit = D.Bus.PUBLIC_CIRCUIT, .wire = 0, .uses = 2, .source = .sealed, .coordinate = 0 },
    .{ .circuit = D.Bus.PUBLIC_CIRCUIT, .wire = 8, .uses = 2, .source = .plan, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 1, .uses = 1, .source = .sum, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 2, .uses = 1, .source = .count, .coordinate = 0 },
    .{ .circuit = D.Bus.PUBLIC_CIRCUIT, .wire = 16, .uses = 2, .source = .shard_header, .coordinate = 3 },
    .{ .circuit = @import("../recursion/air/blake3_root_sources.zig").CIRCUIT, .wire = 8, .uses = 8, .source = .main_root, .coordinate = 0 },
};
pub const Fixture = struct {
    entries: [6]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    shard: Range.Shard,
    roots: [2][32]u8,
    plan: [32]u8,
    pub fn init() !Fixture {
        var self: Fixture = undefined;
        self.shard = .{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = 37 };
        self.plan = @splat(7);
        self.roots = .{ @splat(8), @splat(9) };
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
            .{ .family = .memory_range, .index = 0, .instance_id = Native.instanceId(self.plan, 0), .roots = self.roots },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        self.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = Parent.PCS_CONFIG, .counts = counts };
        self.sealed = try Seal.seal(self.pins, &self.entries);
        return self;
    }
    pub fn prepare(self: *const Fixture, a: std.mem.Allocator) !D.Prepared {
        return D.Prepared.init(a, self.shard, self.plan, self.roots, self.sealed, self.pins, &self.entries, .{});
    }
    pub fn template(prepared: *const D.Prepared) !T.TemplatePolicy {
        const geometry = Parent.Key{ .profile = .diagnostic_q8_pow0, .config = prepared.config, .context = .{ .child_key_id = prepared.template_id, .child_config = prepared.config, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
        const key = try D.Protocol.Key.fromGeometry(geometry, &wires);
        return .{ .key = key, .key_id = try key.identity(), .schedule = &wires };
    }
    pub fn roster(self: *const Fixture) Transport.Roster {
        return .{ .sealed = self.sealed, .pins = self.pins, .entries = &self.entries };
    }
    pub fn artifact(a: std.mem.Allocator, policy: T.Policy) !D.Stage.Artifact {
        const open = try D.proposal(policy.prepared, .{ .sum = core.fields.qm31.QM31.zero(), .count = policy.prepared.shard.request_count });
        const bytes = try a.dupe(u8, "literal not a recursive proof");
        errdefer a.free(bytes);
        const schedule = try a.dupe(D.Bus.Wire, policy.template.schedule);
        errdefer a.free(schedule);
        return .{ .bytes = bytes, .key = policy.template.key, .expected_key_id = policy.template.key_id, .schedule = schedule, .native = open, .public_values = try D.values(policy.prepared, open) };
    }
};
pub fn assemble(a: std.mem.Allocator, encoded: *const T.Codec.Encoded) ![]u8 {
    const raw = try a.alloc(u8, encoded.total_bytes);
    var offset: usize = 0;
    for (encoded.parts()) |part| {
        @memcpy(raw[offset..][0..part.len], part);
        offset += part.len;
    }
    return raw;
}
