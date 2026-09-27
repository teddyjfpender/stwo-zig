//! Reusable verifier-owned bounded transcript preprocessing, not a full PCS key.
const std = @import("std");
const core = @import("stwo_core");
const t = @import("blake3_transcript_witness.zig");
const Hash = std.crypto.hash.sha2.Sha256;
pub const Config = struct { namespace: u32, attempt_capacity: u32 };
pub const Airs = .{ t.g, t.xor, t.boundary, t.challenge, t.route, t.query_mask, t.retry_control, t.counter_step };
pub const Plan = struct {
    config: Config,
    fixed: t.Prepared,
    id: [32]u8,
    pub fn init(a: std.mem.Allocator, config: Config, operations: []const t.Operation) !Plan {
        var fixed = try t.trustedBounded(a, config.namespace, operations, config.attempt_capacity);
        errdefer fixed.deinit();
        return .{ .config = config, .fixed = fixed, .id = fingerprint(config, &fixed) };
    }
    pub fn deinit(self: *Plan) void {
        self.fixed.deinit();
        self.* = undefined;
    }
    /// Transfer allocation ownership when extending preprocessing in a parent.
    /// The plan is consumed; callers must save its id first if needed.
    pub fn intoFixed(self: *Plan) t.Prepared {
        const fixed = self.fixed;
        self.* = undefined;
        return fixed;
    }
    pub fn validate(self: *const Plan) !void {
        if (!std.mem.eql(u8, &self.id, &fingerprint(self.config, &self.fixed))) return error.CorruptBlake3TranscriptPlan;
    }
    /// No implicit capacity escalation. Caller must explicitly admit another
    /// plan/key if this one returns Blake3RetryCapacityExhausted.
    pub fn prepare(self: *const Plan, a: std.mem.Allocator, operations: []const t.Operation) !t.Prepared {
        try self.validate();
        var live = try t.prepareBounded(a, self.config.namespace, operations, self.config.attempt_capacity);
        errdefer live.deinit();
        if (!std.mem.eql(u8, &self.id, &fingerprint(self.config, &live))) return error.Blake3TranscriptPlanMismatch;
        return live;
    }
};
pub fn rows(data: *const t.Prepared) @TypeOf(.{ data.g_rows, data.xor_rows, data.boundary_rows, data.challenge_rows, data.route_rows, data.query_rows, data.control_rows, data.counter_rows }) {
    return .{ data.g_rows, data.xor_rows, data.boundary_rows, data.challenge_rows, data.route_rows, data.query_rows, data.control_rows, data.counter_rows };
}
fn integer(h: *Hash, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    h.update(&bytes);
}
fn endpoint(h: *Hash, circuit: u32, wire: u32) void {
    integer(h, u32, circuit);
    integer(h, u32, wire);
}
fn fingerprint(config: Config, data: *const t.Prepared) [32]u8 {
    var h = Hash.init(.{});
    h.update("stwo.blake3.transcript-plan.v1\x00");
    integer(&h, u32, core.channel.blake3.PROTOCOL_ID.len);
    h.update(core.channel.blake3.PROTOCOL_ID);
    integer(&h, u32, Airs.len);
    integer(&h, u32, config.namespace);
    integer(&h, u32, config.attempt_capacity);
    inline for (Airs, rows(data)) |Air, air_rows| {
        h.update(&Air.SEMANTIC_DIGEST);
        integer(&h, u32, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        integer(&h, u32, Air.PREPROCESSED_COLUMN_COUNT);
        integer(&h, u64, @intCast(air_rows.len));
        for (air_rows) |row| {
            var bytes: [Air.PREPROCESSED_COLUMN_COUNT * 4]u8 = undefined;
            for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |value, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], value.v, .little);
            h.update(&bytes);
        }
    }
    // Semantic exports and consumer receipts are part of the plan, even when
    // two roles happen to share the same physical draw schedule.
    integer(&h, u64, @intCast(data.draw_outputs.len));
    for (data.draw_outputs) |output| {
        integer(&h, u64, @intCast(output.operation));
        endpoint(&h, output.source.circuit, output.source.first_wire);
        integer(&h, u64, @intCast(output.words));
        const tag: u8 = switch (output.role) {
            .universal => 0,
            .composition => 1,
            .oods => 2,
            .deep => 3,
            .fri => 4,
            .riscv_relation => 5,
        };
        integer(&h, u8, tag);
        const index: usize = switch (output.role) {
            .universal, .fri, .riscv_relation => |i| i,
            else => 0,
        };
        integer(&h, u64, @intCast(index));
    }
    integer(&h, u64, @intCast(data.query_outputs.len));
    for (data.query_outputs) |output| {
        integer(&h, u64, @intCast(output.operation));
        integer(&h, u64, @intCast(output.query));
        endpoint(&h, output.source.circuit, output.source.wire);
    }
    integer(&h, u64, @intCast(data.payload_reads.len));
    for (data.payload_reads) |read| {
        integer(&h, u64, @intCast(read.operation));
        endpoint(&h, read.source.circuit, read.source.first_wire);
        integer(&h, u64, @intCast(read.uses.len));
        for (read.uses) |uses| integer(&h, u32, uses);
    }
    integer(&h, u64, @intCast(data.root_reads.len));
    for (data.root_reads) |read| {
        integer(&h, u64, @intCast(read.operation));
        endpoint(&h, read.source.circuit, read.source.first_wire);
        for (read.uses) |uses| integer(&h, u32, uses);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
