//! Actual warm producer resource owner. Typed programs come from admitted
//! CPU Specs; sorted records/columns stay resident. No host interaction math.
const std = @import("std");
const core = @import("stwo_core");
const runtime = @import("../runtime.zig");
const shared = @import("../shared_runtime.zig");
const secure = @import("secure_polynomial_v1.zig");
const columns = @import("secure_resident_columns_v1.zig");
const external = @import("stwo_prover_engine").shared_external_memory;
pub const Role = columns.Role;
pub const MIN_ROW_LOG: u32 = 12;
pub fn requireRowLog(log: u32) !void {
    if (log < MIN_ROW_LOG or log > 24) return error.InvalidSecureResidentColumnGeometry;
}
pub const Witness = secure.WitnessResult;
pub const Buffer = runtime.ResidentBuffer;
pub const Generated = secure.InteractionResult;
pub const Program = secure.ir.Program;
pub const retainedBytes = columns.retainedBytes;
pub const Limits = struct { max_resident_bytes: usize };
extern fn stwo_zig_secure_records_upload(*anyopaque, [*]const u32, usize, *?*anyopaque, *?*anyopaque) u32;
/// Bounded permitted ingress: one sorted event shard, or one65536-count
/// immutable histogram. It is never an alternate proof authority.
pub fn upload(a: std.mem.Allocator, words: []const u32, cap: usize) !runtime.ResidentBuffer {
    const length = try std.math.mul(usize, words.len, 4);
    if (length == 0 or length > cap) return error.SecureRamIngressCap;
    var reservation = try external.reserve(a, length, .require_shared_budget);
    defer reservation.deinit();
    var lease = try shared.acquireExisting();
    defer lease.deinit();
    if (lease.identitySnapshot().identity.origin != .authenticated_core_aot) return error.SecureCompositionRequiresAuthenticatedRuntime;
    var handle: ?*anyopaque = null;
    var contents: ?*anyopaque = null;
    if (stwo_zig_secure_records_upload(lease.runtime.handle, words.ptr, length, &handle, &contents) != 0) return error.SecureRamIngressFailed;
    return .{ .handle = handle.?, .contents = contents.?, .byte_length = length, .external_reservation = reservation.take() };
}
pub const Statistics = struct { sorted_ingress_bytes: usize = 0, histogram_ingress_bytes: usize = 0, claim_readback_bytes: usize = 0, status_readback_bytes: usize = 0, device_blit_bytes: usize = 0 };
pub const Session = struct {
    a: std.mem.Allocator,
    budget_lease: external.Reservation,
    table: ?secure.RangeInverseTable,
    runtime_handle: *anyopaque,
    initialization_count: u64,
    limits: Limits,
    statistics: Statistics = .{},
    pub fn init(a: std.mem.Allocator, z: core.fields.qm31.QM31, limits: Limits) !Session {
        var budget_lease = try external.reserve(a, 0, .require_shared_budget);
        defer budget_lease.deinit();
        var lease = try shared.acquireExisting();
        defer lease.deinit();
        const identity = lease.identitySnapshot();
        if (identity.identity.origin != .authenticated_core_aot) return error.SecureCompositionRequiresAuthenticatedRuntime;
        const table = try secure.RangeInverseTable.init(lease.runtime, z, .{ .max_resident_bytes = limits.max_resident_bytes, .budget_allocator = a });
        return .{ .a = a, .budget_lease = budget_lease.take(), .table = table, .runtime_handle = lease.runtime.handle, .initialization_count = identity.initialization_count, .limits = limits };
    }
    /// Physical commitments precede B5SS and must not fabricate challenges.
    pub fn initFirstRound(a: std.mem.Allocator, limits: Limits) !Session {
        if (limits.max_resident_bytes == 0) return error.SecureRamResidentCap;
        var budget_lease = try external.reserve(a, 0, .require_shared_budget);
        defer budget_lease.deinit();
        var lease = try shared.acquireExisting();
        defer lease.deinit();
        const identity = lease.identitySnapshot();
        if (identity.identity.origin != .authenticated_core_aot) return error.SecureCompositionRequiresAuthenticatedRuntime;
        return .{ .a = a, .budget_lease = budget_lease.take(), .table = null, .runtime_handle = lease.runtime.handle, .initialization_count = identity.initialization_count, .limits = limits };
    }
    pub fn deinit(self: *Session) void {
        if (self.table) |*table| table.deinit();
        self.budget_lease.deinit();
        self.* = undefined;
    }
    pub fn noteIngress(self: *Session, bytes: usize, histogram: bool) !void {
        const field = if (histogram) &self.statistics.histogram_ingress_bytes else &self.statistics.sorted_ingress_bytes;
        field.* = try std.math.add(usize, field.*, bytes);
    }
    pub fn readClaims(self: *Session, comptime n: usize, generated: *const Generated) ![n]core.fields.qm31.QM31 {
        if (n == 0 or n > 23 or generated.claim_count != n or generated.batches != n) return error.InvalidSecureRamClaimCensus;
        var result: [n]core.fields.qm31.QM31 = undefined;
        for (&result, 0..) |*out, i| out.* = generated.claim(i);
        self.statistics.claim_readback_bytes = try std.math.add(usize, self.statistics.claim_readback_bytes, n * 16);
        return result;
    }
    fn acquire(self: *const Session) !shared.CallLease {
        var lease = try shared.acquireExisting();
        errdefer lease.deinit();
        if (self.runtime_handle != lease.runtime.handle or self.initialization_count != lease.identitySnapshot().initialization_count) return error.StaleSecureRamProducer;
        return lease;
    }
    fn remaining(self: *const Session, live: usize) !usize {
        const retained = try std.math.add(usize, live, if (self.table != null) secure.RangeInverseTable.BYTE_LENGTH else 0);
        if (retained >= self.limits.max_resident_bytes) return error.SecureRamResidentCap;
        return self.limits.max_resident_bytes - retained;
    }
    pub fn witness(self: *Session, source: anytype, metadata: *const [25]u32, log: u32) !Witness {
        if (source.budget_owner == null or source.budget_owner != self.budget_lease.owner) return error.SecureRamBudgetOwnerMismatch;
        var lease = try self.acquire();
        defer lease.deinit();
        const buffer = runtime.ResidentBuffer{ .handle = source.handle, .contents = source.contents, .byte_length = source.byte_length };
        const next_status = try std.math.add(usize, self.statistics.status_readback_bytes, 4);
        const result = try secure.generateLaneWitness(lease.runtime, &buffer, metadata, log, .{ .max_resident_bytes = try self.remaining(source.byte_length), .budget_allocator = self.a });
        self.statistics.status_readback_bytes = next_status;
        return result;
    }
    pub fn rangeWitness(self: *Session, source: *const runtime.ResidentBuffer) !Witness {
        try source.external_reservation.requireOwner(self.a, source.byte_length);
        var lease = try self.acquire();
        defer lease.deinit();
        const next_status = try std.math.add(usize, self.statistics.status_readback_bytes, 4);
        const result = try secure.generateWitness(lease.runtime, source, null, 16, .{ .max_resident_bytes = try self.remaining(source.byte_length), .budget_allocator = self.a });
        self.statistics.status_readback_bytes = next_status;
        return result;
    }
    pub fn interaction(self: *Session, a: std.mem.Allocator, program: *const Program, witness_value: *const Witness, live_pcs_bytes: usize) !Generated {
        if (a.ptr != self.a.ptr or a.vtable != self.a.vtable) return error.SecureRamBudgetOwnerMismatch;
        const table = if (self.table) |*value| value else return error.MissingSecureRangeChallenge;
        const layout = secure.ir.layout(program.kind);
        if (!secure.ir.isFraction(program.kind) or witness_value.columns != layout.fixed + layout.main or witness_value.rows < 2 or !std.math.isPowerOfTwo(witness_value.rows)) return error.InvalidSecureRamWitnessOwner;
        var lease = try self.acquire();
        defer lease.deinit();
        var plan = try secure.FractionPlan.init(a, program, .{ .max_resident_bytes = try self.remaining(try std.math.add(usize, live_pcs_bytes, witness_value.resident.byte_length)), .budget_allocator = self.a });
        defer plan.deinit();
        try plan.prepare(lease.runtime);
        var fixed: [24]u64 = undefined;
        var main: [54]u64 = undefined;
        for (fixed[0..layout.fixed], 0..) |*offset, i| offset.* = @intCast(i * witness_value.rows);
        for (main[0..layout.main], 0..) |*offset, i| offset.* = @intCast((layout.fixed + i) * witness_value.rows);
        const next_status = try std.math.add(usize, self.statistics.status_readback_bytes, 4);
        const result = try plan.generate(program, @intCast(std.math.log2_int(usize, witness_value.rows)), .{ .{ .buffer = &witness_value.resident, .column_offsets = fixed[0..layout.fixed] }, .{ .buffer = &witness_value.resident, .column_offsets = main[0..layout.main] } }, table);
        self.statistics.status_readback_bytes = next_status;
        return result;
    }
    pub fn commit(self: *Session, comptime H: type, a: std.mem.Allocator, scheme: anytype, source: *const runtime.ResidentBuffer, first_column: usize, role: Role, log: u32, other_live: usize, channel: anytype) !void {
        if (a.ptr != self.a.ptr or a.vtable != self.a.vtable) return error.SecureRamBudgetOwnerMismatch;
        try source.external_reservation.requireOwner(self.a, source.byte_length);
        // The strict precommit obtains its own short runtime lease. Do not
        // retain a read lease across it: a queued shutdown writer would make
        // recursive read-lock acquisition deadlock.
        {
            var lease = try self.acquire();
            defer lease.deinit();
        }
        const cap = try self.remaining(other_live);
        const next_blit = try std.math.add(usize, self.statistics.device_blit_bytes, try columns.bytes(role, log));
        _ = try columns.commit(H, a, self.runtime_handle, self.initialization_count, scheme, source, first_column, role, log, cap, channel);
        self.statistics.device_blit_bytes = next_blit;
    }
};
