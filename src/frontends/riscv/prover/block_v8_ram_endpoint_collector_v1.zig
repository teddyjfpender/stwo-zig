//! Experimental producer-only endpoint collection from the actual combined RAM
//! transition stream. This module creates witnesses, NOT proof authority.
//!
//! Native and caller records are sorted together by byte address and actual
//! execution clock. Their append order is irrelevant. These transitions omit
//! native synthetic clock-gap rows and consumed clocks: the eventual local
//! proof must restore the native RAM clock projection and close actual native
//! and caller MemoryAccess tuples against these endpoints. Reconstructing a
//! predecessor here is never evidence that the source AIR emitted that clock.
const std = @import("std");
const core = @import("stwo_core");
const K = @import("block_v8_ram_endpoint_kernel_v1.zig");
const C = @import("block_v8_ram_endpoint_component_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
pub const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const Frame = @import("../air/block/memory_event.zig").Frame;
pub const VERSION: u32 = 1;
pub const production_active = false;

pub const Limits = struct {
    max_events: usize = 1 << 24,
    max_endpoints: usize = 1 << 22,
    max_row_log: u32 = 24,
    max_scratch_bytes: usize = 1 << 30,
    max_live_bytes: usize = 8 << 30,
};
/// A new protocol schedule, independent of old per-access event-count claims.
/// `cohort_count` is the admitted total number of coarse slots, not instruction
/// count. Global WORD compatibility alone does not establish schedule binding.
pub const Request = struct {
    frame: Frame,
    cohort_ordinal: u32,
    cohort_count: u32,
    pub fn policy(self: Request) !K.Policy {
        if (self.frame.global_first_cycle == 0 or self.frame.cycle_count == 0 or
            self.cohort_count == 0 or self.cohort_count > 1 << 20 or
            self.cohort_ordinal >= self.cohort_count)
            return error.InvalidRamEndpointRequest;
        _ = try std.math.add(u64, self.frame.global_first_cycle, self.frame.cycle_count - 1);
        const local_max = try std.math.sub(u64, try std.math.mul(u64, 4, self.frame.cycle_count), 1);
        const result = K.Policy{ .source_ordinal = self.cohort_ordinal, .max_local_clock = std.math.cast(u32, local_max) orelse return error.InvalidRamEndpointRequest };
        try result.validate();
        // Explicitly pin the new coarse schedule. Do not silently reuse the
        // former experimental ordinal<<32 mapping or a per-instruction clock.
        const expected = try std.math.add(u64, try std.math.mul(u64, 4, self.cohort_ordinal), 3);
        if (try result.globalClock() != expected) return error.UnqualifiedRamEndpointClockMapping;
        const bound = try std.math.sub(u64, try std.math.mul(u64, 4, self.cohort_count), 1);
        if (expected == 0 or expected % 4 == 0 or expected > bound)
            return error.InvalidRamEndpointRequest;
        _ = try std.math.add(u64, try self.clockBase(), local_max);
        return result;
    }
    pub fn clockBase(self: Request) !u64 {
        if (self.frame.global_first_cycle == 0) return error.InvalidRamEndpointRequest;
        return std.math.mul(u64, 4, self.frame.global_first_cycle - 1);
    }
    /// Input transitions already carry projected global clocks, as in the V7
    /// combined event sink. Their frame's original encoding does not change
    /// this input contract: both leaf-local and continuous sources are projected
    /// by their source adapter before collection.
    fn localClock(self: Request, global_clock: u64, admitted: K.Policy) !u32 {
        const base = try self.clockBase();
        if (global_clock <= base) return error.RamEndpointAccessOutsideWindow;
        const local = global_clock - base;
        if (local > admitted.max_local_clock or local % 4 == 0)
            return error.RamEndpointAccessOutsideWindow;
        return @intCast(local);
    }
};

pub const Owned = struct {
    allocator: std.mem.Allocator,
    request: Request,
    policy: K.Policy,
    logical_events: usize,
    endpoints: []K.Endpoint,
    /// One net transition per address, using the NEW coarse schedule. These
    /// may enter an old WORD equation only after a new versioned source/count
    /// protocol independently binds the endpoint AIR and schedule.
    net_transitions: []Transition,
    matrix: T.Matrix,
    owned_bytes: usize,
    construction_peak_bytes: usize,
    pub fn deinit(self: *Owned) void {
        self.matrix.deinit();
        self.allocator.free(self.net_transitions);
        self.allocator.free(self.endpoints);
        self.* = undefined;
    }
};

/// Produce sorted unique endpoints while preserving the borrowed event stream.
/// Constructor errors are hygiene checks only; they must be repeated by actual
/// source/local/global proof equations before admitting any execution theorem.
pub fn collectGlobal(a: std.mem.Allocator, request: Request, events: []const Transition, limits: Limits) !Owned {
    const policy = try request.policy();
    if (limits.max_events == 0 or limits.max_endpoints == 0 or limits.max_row_log < 4 or
        limits.max_row_log > 24 or limits.max_live_bytes == 0 or events.len > limits.max_events)
        return error.RamEndpointResourceLimit;
    const scratch_bytes = try std.math.mul(usize, events.len, @sizeOf(Transition));
    if (scratch_bytes > limits.max_scratch_bytes or scratch_bytes > limits.max_live_bytes)
        return error.RamEndpointResourceLimit;
    const sorted = try a.dupe(Transition, events);
    defer a.free(sorted);
    for (sorted) |event| {
        if (event.space != 1 or event.address & 3 != 0 or event.address >= 1 << 30)
            return error.InvalidRamEndpointAccess;
        _ = try request.localClock(event.clock, policy);
    }
    std.mem.sort(Transition, sorted, {}, struct {
        fn less(_: void, left: Transition, right: Transition) bool {
            return if (left.address != right.address) left.address < right.address else left.clock < right.clock;
        }
    }.less);
    var count: usize = 0;
    for (sorted, 0..) |event, index| {
        if (index == 0 or sorted[index - 1].address != event.address) {
            count = try std.math.add(usize, count, 1);
            if (count > limits.max_endpoints) return error.RamEndpointResourceLimit;
        } else {
            const previous = sorted[index - 1];
            if (previous.clock >= event.clock) return error.DuplicateRamEndpointClock;
            if (previous.after != event.before) return error.DiscontinuousRamEndpointValue;
        }
    }
    const log = @max(@as(u32, 4), std.math.log2_int_ceil(usize, @max(@as(usize, 1), count)));
    if (log > limits.max_row_log) return error.RamEndpointResourceLimit;
    const rows = @as(usize, 1) << @intCast(log);
    const columns = C.Spec.FIXED_COUNT + C.Spec.MAIN_COUNT;
    const matrix_bytes = try std.math.add(usize, try std.math.mul(usize, try std.math.mul(usize, rows, columns), @sizeOf(core.fields.m31.M31)), try std.math.mul(usize, columns, @sizeOf(@import("block_v5_word_pcs_v1.zig").Column)));
    const endpoint_bytes = try std.math.mul(usize, count, @sizeOf(K.Endpoint));
    const transition_bytes = try std.math.mul(usize, count, @sizeOf(Transition));
    const owned_bytes = try std.math.add(usize, matrix_bytes, try std.math.add(usize, endpoint_bytes, transition_bytes));
    const peak = try std.math.add(usize, scratch_bytes, owned_bytes);
    if (peak > limits.max_live_bytes) return error.RamEndpointResourceLimit;
    const endpoints = try a.alloc(K.Endpoint, count);
    errdefer a.free(endpoints);
    const net = try a.alloc(Transition, count);
    errdefer a.free(net);
    var matrix = try T.Matrix.init(a, log, columns, limits.max_live_bytes);
    errdefer matrix.deinit();
    const coarse = try policy.globalClock();
    var begin: usize = 0;
    for (endpoints, net, 0..) |*endpoint, *transition, index| {
        var end = begin + 1;
        while (end < sorted.len and sorted[end].address == sorted[begin].address) : (end += 1) {}
        const first = sorted[begin];
        const last = sorted[end - 1];
        endpoint.* = .{ .address = first.address, .initial = first.before, .final = last.after, .last_clock = try request.localClock(last.clock, policy) };
        transition.* = .{ .space = 1, .address = endpoint.address, .clock = coarse, .before = endpoint.initial, .after = endpoint.final };
        const row = try K.constructWithPrevious(endpoint.*, if (index == 0) null else endpoints[index - 1].address, policy);
        matrix.set(0, index, core.fields.m31.M31.one());
        for (row, 0..) |value, column| matrix.set(C.Spec.FIXED_COUNT + column, index, try value.tryIntoM31());
        begin = end;
    }
    // An independently reconstructed fixed first-row selector, including an
    // empty cohort; inactive endpoint MAIN rows remain all zero.
    matrix.set(1, 0, core.fields.m31.M31.one());
    return .{ .allocator = a, .request = request, .policy = policy, .logical_events = events.len, .endpoints = endpoints, .net_transitions = net, .matrix = matrix, .owned_bytes = owned_bytes, .construction_peak_bytes = peak };
}
