//! Typed constructor and joined-wave ledger for synchronous sampled evaluation.
//! Numeric native payloads and private MTLBuffer bytes share the same cap.
//! ObjC/framework allocation rounding is outside this logical accounting.
const std = @import("std");
const external = @import("stwo_prover_engine").shared_external_memory;
const admission_module = @import("external_allocation_admission_v1.zig");
pub const Operation = enum(u32) { device, native_payload, borrowed_alias, release_device, release_native_payload, release_borrowed_alias };
/// Scheduling bounds, distinct from authoritative combined-cap admission.
/// One indivisible column may exceed run_bytes; it occupies its own wave.
pub const StreamPolicy = extern struct {
    run_bytes: usize = 64 * 1024 * 1024,
    wave_bytes: usize = 256 * 1024 * 1024,
    dispatches: usize = 128,

    pub fn acceptsNext(self: StreamPolicy, run_words: usize, next_words: usize) bool {
        const limit = self.run_bytes / 4;
        return next_words <= limit and run_words <= limit - next_words;
    }
    pub fn requiresJoin(self: StreamPolicy, queued: usize, dispatches: usize, source_bytes: usize, metadata_bytes: usize) !bool {
        // Numeric metadata and its device copy temporarily coexist. Aliases
        // also count toward scheduling even though ordinary aliases charge0.
        const incoming = try std.math.add(usize, source_bytes, try std.math.mul(usize, metadata_bytes, 2));
        return dispatches != 0 and (dispatches >= self.dispatches or
            incoming > self.wave_bytes or queued > self.wave_bytes - incoming);
    }
};
pub const stream_policy: StreamPolicy = .{};
pub const Receipt = extern struct {
    device_live_bytes: u64 = 0,
    native_live_bytes: u64 = 0,
    alias_live_bytes: u64 = 0,
    device_peak_bytes: u64 = 0,
    native_peak_bytes: u64 = 0,
    alias_peak_bytes: u64 = 0,
    external_peak_bytes: u64 = 0,
    owned_allocations: u64 = 0,
    alias_allocations: u64 = 0,
    submitted: u64 = 0,
    joined: u64 = 0,
};
pub const Scope = struct {
    admission: admission_module.Scope,
    receipt: Receipt = .{},
    failure: ?anyerror = null,
    finished: bool = false,
    pub fn init(a: std.mem.Allocator, policy: external.Policy) !Scope {
        return .{ .admission = try admission_module.Scope.init(a, policy) };
    }
    pub fn validateAllocator(self: *const Scope, a: std.mem.Allocator) !void {
        try self.admission.validateAllocator(a);
    }
    pub fn allowsUnownedAliases(self: *const Scope) bool {
        return self.admission.reservation.owner == null;
    }
    pub fn apply(self: *Scope, bytes: usize, operation: Operation) !void {
        if (self.finished or !self.admission.active or bytes == 0) return error.InvalidSampledBudgetOperation;
        const amount = std.math.cast(u64, bytes) orelse return error.InvalidSampledBudgetOperation;
        var next = self.receipt;
        switch (operation) {
            .device, .native_payload => {
                if (self.failure) |err| return err;
                const counter = if (operation == .device) &next.device_live_bytes else &next.native_live_bytes;
                counter.* = try std.math.add(u64, counter.*, amount);
                next.owned_allocations = try std.math.add(u64, next.owned_allocations, 1);
                try self.admission.admit(bytes);
            },
            .borrowed_alias => {
                if (self.failure) |err| return err;
                if (!self.allowsUnownedAliases()) return error.UnauthenticatedSampledAlias;
                next.alias_live_bytes = try std.math.add(u64, next.alias_live_bytes, amount);
                next.alias_allocations = try std.math.add(u64, next.alias_allocations, 1);
            },
            .release_device, .release_native_payload => {
                const counter = if (operation == .release_device) &next.device_live_bytes else &next.native_live_bytes;
                if (amount > counter.*) return error.InvalidSampledBudgetRelease;
                counter.* -= amount;
                // Trusted synchronous C boundary destroys this joined wave
                // before invoking release; no command may still borrow it.
                try self.admission.releaseJoined(bytes);
            },
            .release_borrowed_alias => {
                if (amount > next.alias_live_bytes) return error.InvalidSampledBudgetRelease;
                next.alias_live_bytes -= amount;
            },
        }
        next.device_peak_bytes = @max(next.device_peak_bytes, next.device_live_bytes);
        next.native_peak_bytes = @max(next.native_peak_bytes, next.native_live_bytes);
        next.alias_peak_bytes = @max(next.alias_peak_bytes, next.alias_live_bytes);
        next.external_peak_bytes = @max(next.external_peak_bytes, try std.math.add(u64, next.device_live_bytes, next.native_live_bytes));
        self.receipt = next;
    }
    pub fn callback(context: *anyopaque, bytes: usize, tag: u32) callconv(.c) bool {
        const self: *Scope = @ptrCast(@alignCast(context));
        const operation = std.meta.intToEnum(Operation, tag) catch {
            self.failure = error.InvalidSampledBudgetOperation;
            return false;
        };
        self.apply(bytes, operation) catch |err| {
            if (self.failure == null) self.failure = err;
            return false;
        };
        return true;
    }
    /// C has joined all submitted commands, destroyed private payloads and
    /// released their charges before returning. Retain the zero-byte owner
    /// lease until prepared/output arrays have been freed by the same allocator.
    pub fn finish(self: *Scope, success: bool, received: Receipt) !void {
        if (self.finished) return error.InvalidSampledBudgetOperation;
        self.finished = true; // A failed receipt cannot be retried into success.
        var expected = self.receipt;
        expected.submitted = received.submitted;
        expected.joined = received.joined;
        if (!std.meta.eql(expected, received) or received.submitted != received.joined or
            received.device_live_bytes != 0 or received.native_live_bytes != 0 or received.alias_live_bytes != 0)
            return error.InvalidSampledBudgetReceipt;
        if (self.failure) |err| return err;
        if (self.admission.failure) |err| return err;
        if (!success) return error.SampledDispatchFailed;
        if (received.submitted == 0) return error.InvalidSampledBudgetReceipt;
        try self.admission.releaseAfterJoin();
        self.receipt = received;
        self.finished = true;
    }
    pub fn deinit(self: *Scope) void {
        self.admission.deinit();
        self.finished = true;
    }
};

pub const CoefficientGeometry = struct {
    coefficient_words: usize,
    factor_words: usize,
    tasks: usize,
    basis_tasks: usize,
    basis_values: usize,
    outputs: usize,
};
/// Exact six persistent coefficient-evaluation buffers, including the 4-byte
/// placeholder on the streamed branch and on a zero-factor constant plan.
pub fn coefficientBaseBytes(g: CoefficientGeometry) !usize {
    if (g.coefficient_words == 0 or
        g.tasks == 0 or g.tasks > std.math.maxInt(u32) or g.basis_tasks == 0 or
        g.basis_tasks > std.math.maxInt(u32) or g.basis_values == 0 or
        g.basis_values > std.math.maxInt(u32) or g.outputs == 0 or
        g.outputs > std.math.maxInt(u32) / 4) return error.InvalidSampledBudgetGeometry;
    const coefficients = try std.math.mul(usize, g.coefficient_words, 4);
    var bytes: usize = if (@import("sampled_coefficient_geometry.zig").usesStreaming(g.coefficient_words)) 4 else coefficients;
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, @max(@as(usize, 1), g.factor_words), 4));
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, g.tasks, 20));
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, g.basis_tasks, 16));
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, g.basis_values, 16));
    return std.math.add(usize, bytes, try std.math.mul(usize, g.outputs, 16));
}

test "streamed coefficient budget accounts for bounded buffers beyond u32 source totals" {
    if (@bitSizeOf(usize) < 64) return error.SkipZigTest;
    const shape: CoefficientGeometry = .{
        .coefficient_words = @as(usize, std.math.maxInt(u32)) + 4097,
        .factor_words = 3,
        .tasks = 2,
        .basis_tasks = 1,
        .basis_values = 4,
        .outputs = 2,
    };
    try std.testing.expectEqual(@as(usize, 4 + 12 + 40 + 16 + 64 + 32), try coefficientBaseBytes(shape));
    var invalid = shape;
    invalid.coefficient_words = std.math.maxInt(usize) / 4 + 1;
    try std.testing.expectError(error.Overflow, coefficientBaseBytes(invalid));
}
