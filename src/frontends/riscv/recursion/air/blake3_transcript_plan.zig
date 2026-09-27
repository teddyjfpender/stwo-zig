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
        return initStorage(a, config, operations, false);
    }
    pub fn initCompact(a: std.mem.Allocator, config: Config, operations: []const t.Operation) !Plan {
        return initStorage(a, config, operations, true);
    }
    fn initStorage(a: std.mem.Allocator, config: Config, operations: []const t.Operation, compact: bool) !Plan {
        var fixed = if (compact) try t.trustedBoundedDirect(a, config.namespace, operations, config.attempt_capacity) else try t.trustedBounded(a, config.namespace, operations, config.attempt_capacity);
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
        if (self.fixed.hash_metadata != null and (self.fixed.g_rows.len != 0 or self.fixed.xor_rows.len != 0)) return error.CorruptBlake3TranscriptPlan;
        if (self.fixed.nonhash != null) return error.CorruptBlake3TranscriptPlan;
        if (self.fixed.nonhash_fixed) |*owner| {
            if (!owner.finished) return error.CorruptBlake3TranscriptPlan;
            inline for (.{ 2, 6, 7, 8, 14, 15 }) |slot| if (self.fixed.cohortRows(slot).len != 0) return error.CorruptBlake3TranscriptPlan;
        }
        if (!std.mem.eql(u8, &self.id, &fingerprint(self.config, &self.fixed))) return error.CorruptBlake3TranscriptPlan;
    }
    /// No implicit capacity escalation. Caller must explicitly admit another
    /// plan/key if this one returns Blake3RetryCapacityExhausted.
    pub fn prepare(self: *const Plan, a: std.mem.Allocator, operations: []const t.Operation) !t.Prepared {
        return self.prepareWithColumns(a, operations, null);
    }
    pub fn prepareMainColumns(self: *const Plan, a: std.mem.Allocator, operations: []const t.Operation, columns: t.MainColumns) !t.Prepared {
        return self.prepareWithColumns(a, operations, columns);
    }
    fn prepareWithColumns(self: *const Plan, a: std.mem.Allocator, operations: []const t.Operation, columns: ?t.MainColumns) !t.Prepared {
        try self.validate();
        const counts = self.fixed.hashCounts();
        if (columns) |out| try out.validate(counts.g, counts.xor);
        var live = if (self.fixed.nonhash_fixed != null) try t.prepareBoundedDirect(a, self.config.namespace, operations, self.config.attempt_capacity, &self.fixed, columns) else if (columns) |out| try t.prepareBoundedMainColumns(a, self.config.namespace, operations, self.config.attempt_capacity, out) else try t.prepareBounded(a, self.config.namespace, operations, self.config.attempt_capacity);
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
    inline for (Airs, rows(data), 0..) |Air, air_rows, cohort| {
        h.update(&Air.SEMANTIC_DIGEST);
        integer(&h, u32, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        integer(&h, u32, Air.PREPROCESSED_COLUMN_COUNT);
        if (comptime cohort < 2) {
            if (data.hash_metadata) |metadata| {
                const compact = if (comptime cohort == 0) metadata.g_rows else metadata.xor_rows;
                integer(&h, u64, @intCast(compact.len));
                for (compact) |row| fixedBytes(Air, &h, &row);
            } else {
                integer(&h, u64, @intCast(air_rows.len));
                for (air_rows) |row| fixedBytes(Air, &h, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
            }
        } else {
            const slot = comptime .{ 2, 6, 7, 8, 14, 15 }[cohort - 2];
            const index = comptime blk: {
                for (@import("blake3_nonhash_emission_v1.zig").slots, 0..) |candidate, i| if (candidate == slot) break :blk i;
                @compileError("invalid transcript source slot");
            };
            if (data.nonhash_fixed) |*owner| {
                integer(&h, u64, @intCast(owner.fixed[index].len));
                for (owner.fixed[index]) |row| fixedBytes(Air, &h, &row);
            } else if (data.nonhash) |*owner| {
                const fixed = owner.columns.owners[index].fixed;
                integer(&h, u64, @intCast(fixed.len));
                for (fixed) |row| fixedBytes(Air, &h, &row);
            } else {
                integer(&h, u64, @intCast(air_rows.len));
                for (air_rows) |row| fixedBytes(Air, &h, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
            }
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

fn fixedBytes(comptime Air: type, h: *Hash, values: []const core.fields.m31.M31) void {
    var bytes: [Air.PREPROCESSED_COLUMN_COUNT * 4]u8 = undefined;
    for (values, 0..) |value, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], value.v, .little);
    h.update(&bytes);
}
