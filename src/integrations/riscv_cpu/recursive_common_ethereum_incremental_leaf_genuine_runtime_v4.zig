//! Non-semantic runtime policy for the isolated genuine role-0 gate.
//! Worker count and allocator telemetry never enter proof or artifact bytes.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const work_pool = @import("stwo_prover_engine").work_pool;
const runtime_usage =
    @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_usage_v4.zig");

pub const WORKER_COUNT_ENV = "STWO_ROLE0_GENUINE_WORKER_COUNT";
pub const HOST_BYTE_BUDGET_ENV =
    "STWO_ROLE0_GENUINE_HOST_BYTE_BUDGET";
pub const STOP_AFTER_MATERIALIZE_ENV =
    "STWO_ROLE0_GENUINE_STOP_AFTER_MATERIALIZE";
pub const MAXIMUM_WORKER_COUNT: usize = work_pool.MAX_WORKERS;
const EXECUTION_RECEIPT_DOMAIN =
    "stwo-zig/role0-genuine-stage101-execution-receipt/v4\x00";
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const RuntimePhaseV4 = runtime_usage.RuntimePhaseV4;
pub const PhaseUsageReceiptV4 = runtime_usage.PhaseUsageReceiptV4;
pub const PhaseUsageMeasurementV4 = runtime_usage.PhaseUsageMeasurementV4;

pub const WorkerPolicyV4 = struct {
    worker_count: usize,
    host_byte_budget: usize,

    pub fn hostDefault(host_byte_budget: usize) !WorkerPolicyV4 {
        const result = WorkerPolicyV4{
            .worker_count = @max(
                1,
                @min(
                    try std.Thread.getCpuCount(),
                    MAXIMUM_WORKER_COUNT,
                ),
            ),
            .host_byte_budget = host_byte_budget,
        };
        try result.validate();
        return result;
    }

    /// Worker count is host-derived by default. The host byte budget is an
    /// explicit caller policy, optionally overridden by a decimal environment
    /// value; no workstation-specific RAM total is embedded here.
    pub fn fromEnvironment(
        allocator: std.mem.Allocator,
        fallback_host_byte_budget: usize,
    ) !WorkerPolicyV4 {
        const encoded = std.process.getEnvVarOwned(
            allocator,
            WORKER_COUNT_ENV,
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (encoded) |value| allocator.free(value);
        const worker_count = if (encoded) |value|
            std.fmt.parseUnsigned(usize, value, 10) catch
                return error.InvalidRole0GenuineWorkerCount
        else
            @max(
                1,
                @min(
                    try std.Thread.getCpuCount(),
                    MAXIMUM_WORKER_COUNT,
                ),
            );
        const encoded_budget = std.process.getEnvVarOwned(
            allocator,
            HOST_BYTE_BUDGET_ENV,
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (encoded_budget) |value| allocator.free(value);
        const host_byte_budget = if (encoded_budget) |value|
            std.fmt.parseUnsigned(usize, value, 10) catch
                return error.InvalidRole0GenuineHostByteBudget
        else
            fallback_host_byte_budget;
        const result = WorkerPolicyV4{
            .worker_count = worker_count,
            .host_byte_budget = host_byte_budget,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: WorkerPolicyV4) !void {
        if (self.worker_count == 0 or
            self.worker_count > MAXIMUM_WORKER_COUNT)
        {
            return error.InvalidRole0GenuineWorkerCount;
        }
        if (self.host_byte_budget == 0 or
            self.host_byte_budget == std.math.maxInt(usize))
        {
            return error.InvalidRole0GenuineHostByteBudget;
        }
    }

    pub fn cpuRequest(
        self: WorkerPolicyV4,
    ) !prover_api.CpuCompositionExecutionRequest {
        try self.validate();
        return .{
            .worker_count = self.worker_count,
            .host_byte_budget = self.host_byte_budget,
            .contention_policy = .strict,
        };
    }
};

/// Test-transaction receipt proving both sequential Stage-101 producers were
/// handed one identical strict, non-null execution request. It is diagnostics,
/// not proof admission, and is excluded from all proof/artifact bytes.
pub const Stage101ExecutionReceiptV4 = struct {
    proof_count: u32,
    worker_count: u32,
    host_byte_budget: u64,
    contention_policy: prover_api.CpuCompositionContentionPolicy,
    identity_sha256: [32]u8,

    pub fn mint(
        request: prover_api.CpuCompositionExecutionRequest,
        proof_count: usize,
    ) !Stage101ExecutionReceiptV4 {
        const result = Stage101ExecutionReceiptV4{
            .proof_count = std.math.cast(u32, proof_count) orelse
                return error.InvalidRole0GenuineExecutionReceipt,
            .worker_count = std.math.cast(u32, request.worker_count) orelse
                return error.InvalidRole0GenuineExecutionReceipt,
            .host_byte_budget = std.math.cast(u64, request.host_byte_budget) orelse
                return error.InvalidRole0GenuineExecutionReceipt,
            .contention_policy = request.contention_policy,
            .identity_sha256 = undefined,
        };
        var sealed = result;
        sealed.identity_sha256 = executionReceiptIdentity(&sealed);
        try sealed.validate();
        return sealed;
    }

    pub fn validate(self: *const Stage101ExecutionReceiptV4) !void {
        if (self.proof_count == 0 or self.worker_count == 0 or
            @as(usize, self.worker_count) > MAXIMUM_WORKER_COUNT or
            self.host_byte_budget == 0 or
            self.contention_policy != .strict or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &executionReceiptIdentity(self),
            ))
        {
            return error.InvalidRole0GenuineExecutionReceipt;
        }
    }
};

pub fn stopAfterMaterialize(allocator: std.mem.Allocator) !bool {
    const encoded = std.process.getEnvVarOwned(
        allocator,
        STOP_AFTER_MATERIALIZE_ENV,
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer allocator.free(encoded);
    if (std.mem.eql(u8, encoded, "0")) return false;
    if (std.mem.eql(u8, encoded, "1")) return true;
    return error.InvalidRole0GenuineStopPolicy;
}

/// Thin counter around the production SMP allocator. Unlike
/// `std.testing.allocator`, large graph release does not collect stack traces.
/// Net allocations and bytes must both return to zero, including on errors.
pub const TrackedSmpAllocatorV4 = struct {
    pub const MAX_TRACKED_ALLOCATIONS: usize = 4096;

    pub const SnapshotV4 = struct {
        active_allocations: usize,
        active_bytes: usize,
        peak_active_bytes: usize,
        total_allocated_bytes: u128,
        total_freed_bytes: u128,
        untracked_active_allocations: usize,
    };

    const AllocationRecordV4 = struct {
        pointer: usize = 0,
        byte_count: usize = 0,
        return_address: usize = 0,
    };

    mutex: std.Thread.Mutex = .{},
    active_allocations: usize = 0,
    active_bytes: usize = 0,
    peak_active_bytes: usize = 0,
    total_allocated_bytes: u128 = 0,
    total_freed_bytes: u128 = 0,
    untracked_active_allocations: usize = 0,
    records: [MAX_TRACKED_ALLOCATIONS]AllocationRecordV4 =
        .{AllocationRecordV4{}} ** MAX_TRACKED_ALLOCATIONS,

    pub fn allocator(self: *TrackedSmpAllocatorV4) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn isEmpty(self: *TrackedSmpAllocatorV4) bool {
        const value = self.snapshot();
        return value.active_allocations == 0 and value.active_bytes == 0 and
            value.total_allocated_bytes == value.total_freed_bytes and
            value.untracked_active_allocations == 0;
    }

    pub fn peakBytes(self: *TrackedSmpAllocatorV4) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.peak_active_bytes;
    }

    pub fn snapshot(self: *TrackedSmpAllocatorV4) SnapshotV4 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .active_allocations = self.active_allocations,
            .active_bytes = self.active_bytes,
            .peak_active_bytes = self.peak_active_bytes,
            .total_allocated_bytes = self.total_allocated_bytes,
            .total_freed_bytes = self.total_freed_bytes,
            .untracked_active_allocations = self.untracked_active_allocations,
        };
    }

    pub fn dumpLeaks(self: *TrackedSmpAllocatorV4) void {
        // Failure-only reporting deliberately has no allocator parameter and
        // never calls through `self.allocator()`: observing a residual owner
        // must not create another tracked allocation or perturb the counters.
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.records) |record| {
            if (record.pointer != 0) std.debug.print(
                "ETHEREUM_INCREMENTAL_ROLE0_ALLOCATOR_LIVE " ++
                    "ptr=0x{x} bytes={d} caller=0x{x}\n",
                .{
                    record.pointer,
                    record.byte_count,
                    record.return_address,
                },
            );
        }
    }

    fn recordAlloc(
        self: *TrackedSmpAllocatorV4,
        pointer: [*]u8,
        byte_count: usize,
        return_address: usize,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const pointer_value = @intFromPtr(pointer);
        if (pointer_value == 0 or self.findRecordLocked(pointer_value) != null)
            self.failLocked(
                "duplicate-allocation",
                pointer_value,
                byte_count,
                byte_count,
                return_address,
            );
        const record_index = self.findEmptyRecordLocked() orelse
            self.failLocked(
                "record-capacity-exceeded",
                pointer_value,
                0,
                byte_count,
                return_address,
            );
        const active_allocations = std.math.add(
            usize,
            self.active_allocations,
            1,
        ) catch self.failLocked(
            "allocation-count-overflow",
            pointer_value,
            0,
            byte_count,
            return_address,
        );
        const active_bytes = std.math.add(
            usize,
            self.active_bytes,
            byte_count,
        ) catch self.failLocked(
            "allocation-bytes-overflow",
            pointer_value,
            0,
            byte_count,
            return_address,
        );
        const total_allocated_bytes = std.math.add(
            u128,
            self.total_allocated_bytes,
            @as(u128, byte_count),
        ) catch self.failLocked(
            "total-allocation-bytes-overflow",
            pointer_value,
            0,
            byte_count,
            return_address,
        );
        self.active_allocations = active_allocations;
        self.active_bytes = active_bytes;
        self.peak_active_bytes = @max(
            self.peak_active_bytes,
            self.active_bytes,
        );
        self.total_allocated_bytes = total_allocated_bytes;
        self.records[record_index] = .{
            .pointer = pointer_value,
            .byte_count = byte_count,
            .return_address = return_address,
        };
    }

    fn resizeLocked(
        self: *TrackedSmpAllocatorV4,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_count: usize,
        return_address: usize,
    ) bool {
        const pointer_value = @intFromPtr(memory.ptr);
        const record_index = self.requireLiveLocked(
            "resize",
            pointer_value,
            memory.len,
            new_count,
            return_address,
        );
        const updated = self.updatedByteCountersLocked(
            "resize",
            pointer_value,
            memory.len,
            new_count,
            return_address,
        );
        if (!std.heap.smp_allocator.rawResize(
            memory,
            alignment,
            new_count,
            return_address,
        )) return false;
        self.applyResizeLocked(
            record_index,
            pointer_value,
            new_count,
            updated,
        );
        return true;
    }

    fn remapLocked(
        self: *TrackedSmpAllocatorV4,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_count: usize,
        return_address: usize,
    ) ?[*]u8 {
        const old_pointer = @intFromPtr(memory.ptr);
        const record_index = self.requireLiveLocked(
            "remap",
            old_pointer,
            memory.len,
            new_count,
            return_address,
        );
        const updated = self.updatedByteCountersLocked(
            "remap",
            old_pointer,
            memory.len,
            new_count,
            return_address,
        );
        const result = std.heap.smp_allocator.rawRemap(
            memory,
            alignment,
            new_count,
            return_address,
        ) orelse return null;
        const new_pointer = @intFromPtr(result);
        if (new_pointer != old_pointer and
            self.findRecordLocked(new_pointer) != null)
        {
            self.failLocked(
                "remap-pointer-collision",
                new_pointer,
                memory.len,
                new_count,
                return_address,
            );
        }
        self.applyResizeLocked(
            record_index,
            new_pointer,
            new_count,
            updated,
        );
        return result;
    }

    const UpdatedByteCountersV4 = struct {
        active_bytes: usize,
        total_allocated_bytes: u128,
        total_freed_bytes: u128,
    };

    fn updatedByteCountersLocked(
        self: *TrackedSmpAllocatorV4,
        comptime operation: []const u8,
        pointer: usize,
        old_count: usize,
        new_count: usize,
        return_address: usize,
    ) UpdatedByteCountersV4 {
        var result = UpdatedByteCountersV4{
            .active_bytes = self.active_bytes,
            .total_allocated_bytes = self.total_allocated_bytes,
            .total_freed_bytes = self.total_freed_bytes,
        };
        if (new_count >= old_count) {
            const delta = new_count - old_count;
            result.active_bytes = std.math.add(
                usize,
                result.active_bytes,
                delta,
            ) catch self.failLocked(
                operation ++ "-active-bytes-overflow",
                pointer,
                old_count,
                new_count,
                return_address,
            );
            result.total_allocated_bytes = std.math.add(
                u128,
                result.total_allocated_bytes,
                @as(u128, delta),
            ) catch self.failLocked(
                operation ++ "-total-allocated-overflow",
                pointer,
                old_count,
                new_count,
                return_address,
            );
        } else {
            const delta = old_count - new_count;
            result.active_bytes = std.math.sub(
                usize,
                result.active_bytes,
                delta,
            ) catch self.failLocked(
                operation ++ "-active-bytes-underflow",
                pointer,
                old_count,
                new_count,
                return_address,
            );
            result.total_freed_bytes = std.math.add(
                u128,
                result.total_freed_bytes,
                @as(u128, delta),
            ) catch self.failLocked(
                operation ++ "-total-freed-overflow",
                pointer,
                old_count,
                new_count,
                return_address,
            );
        }
        return result;
    }

    fn applyResizeLocked(
        self: *TrackedSmpAllocatorV4,
        record_index: usize,
        new_pointer: usize,
        new_count: usize,
        updated: UpdatedByteCountersV4,
    ) void {
        self.active_bytes = updated.active_bytes;
        self.total_allocated_bytes = updated.total_allocated_bytes;
        self.total_freed_bytes = updated.total_freed_bytes;
        self.peak_active_bytes = @max(
            self.peak_active_bytes,
            self.active_bytes,
        );
        self.records[record_index].pointer = new_pointer;
        self.records[record_index].byte_count = new_count;
    }

    fn freeLocked(
        self: *TrackedSmpAllocatorV4,
        memory: []u8,
        return_address: usize,
    ) void {
        const pointer = @intFromPtr(memory.ptr);
        const record_index = self.requireLiveLocked(
            "free",
            pointer,
            memory.len,
            0,
            return_address,
        );
        const active_allocations = std.math.sub(
            usize,
            self.active_allocations,
            1,
        ) catch self.failLocked(
            "free-allocation-count-underflow",
            pointer,
            memory.len,
            0,
            return_address,
        );
        const active_bytes = std.math.sub(
            usize,
            self.active_bytes,
            memory.len,
        ) catch self.failLocked(
            "free-active-bytes-underflow",
            pointer,
            memory.len,
            0,
            return_address,
        );
        const total_freed_bytes = std.math.add(
            u128,
            self.total_freed_bytes,
            @as(u128, memory.len),
        ) catch self.failLocked(
            "free-total-bytes-overflow",
            pointer,
            memory.len,
            0,
            return_address,
        );
        self.records[record_index] = .{};
        self.active_allocations = active_allocations;
        self.active_bytes = active_bytes;
        self.total_freed_bytes = total_freed_bytes;
    }

    fn requireLiveLocked(
        self: *TrackedSmpAllocatorV4,
        comptime operation: []const u8,
        pointer: usize,
        old_count: usize,
        new_count: usize,
        return_address: usize,
    ) usize {
        if (self.findRecordLocked(pointer)) |index| {
            if (self.records[index].byte_count != old_count)
                self.failLocked(
                    operation ++ "-size-mismatch",
                    pointer,
                    old_count,
                    new_count,
                    return_address,
                );
            return index;
        }
        self.failLocked(
            operation ++ "-unknown-pointer",
            pointer,
            old_count,
            new_count,
            return_address,
        );
    }

    fn findRecordLocked(
        self: *TrackedSmpAllocatorV4,
        pointer: usize,
    ) ?usize {
        for (self.records, 0..) |record, index|
            if (record.pointer == pointer) return index;
        return null;
    }

    fn findEmptyRecordLocked(self: *TrackedSmpAllocatorV4) ?usize {
        for (self.records, 0..) |record, index|
            if (record.pointer == 0) return index;
        return null;
    }

    fn failLocked(
        self: *TrackedSmpAllocatorV4,
        comptime operation: []const u8,
        pointer: usize,
        old_count: usize,
        new_count: usize,
        return_address: usize,
    ) noreturn {
        // Failure reporting uses stderr directly and never the tracked
        // allocator. In particular, an unknown free fails before rawFree can
        // release/reuse the address and create an ABA bookkeeping race.
        std.debug.print(
            "ETHEREUM_INCREMENTAL_ROLE0_ALLOCATOR_INVALID " ++
                "operation={s} ptr=0x{x} old_bytes={d} new_bytes={d} " ++
                "caller=0x{x} active={d} active_bytes={d} " ++
                "untracked={d}\n",
            .{
                operation,
                pointer,
                old_count,
                new_count,
                return_address,
                self.active_allocations,
                self.active_bytes,
                self.untracked_active_allocations,
            },
        );
        for (self.records) |record| {
            if (record.pointer != 0) std.debug.print(
                "ETHEREUM_INCREMENTAL_ROLE0_ALLOCATOR_LIVE " ++
                    "ptr=0x{x} bytes={d} caller=0x{x}\n",
                .{
                    record.pointer,
                    record.byte_count,
                    record.return_address,
                },
            );
        }
        @panic("role0 genuine tracked allocator ownership mismatch");
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const result = std.heap.smp_allocator.rawAlloc(
            len,
            alignment,
            return_address,
        ) orelse return null;
        const self: *TrackedSmpAllocatorV4 = @ptrCast(@alignCast(context));
        self.recordAlloc(result, len, return_address);
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *TrackedSmpAllocatorV4 = @ptrCast(@alignCast(context));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.resizeLocked(
            memory,
            alignment,
            new_len,
            return_address,
        );
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *TrackedSmpAllocatorV4 = @ptrCast(@alignCast(context));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.remapLocked(
            memory,
            alignment,
            new_len,
            return_address,
        );
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *TrackedSmpAllocatorV4 = @ptrCast(@alignCast(context));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.freeLocked(memory, return_address);
        std.heap.smp_allocator.rawFree(memory, alignment, return_address);
    }
};

fn executionReceiptIdentity(
    value: *const Stage101ExecutionReceiptV4,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(EXECUTION_RECEIPT_DOMAIN);
    hashInt(&hash, u32, value.proof_count);
    hashInt(&hash, u32, value.worker_count);
    hashInt(&hash, u64, value.host_byte_budget);
    hashInt(&hash, u8, @intFromEnum(value.contention_policy));
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}
