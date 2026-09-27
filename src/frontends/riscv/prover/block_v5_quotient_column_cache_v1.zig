//! Proof-scoped reuse of immutable committed MAIN column evaluations. Cache
//! exhaustion falls back to the original component-local preparation. No
//! roots, AIR equations, openings, degree bounds or transcript bytes change.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Poly = engine.air.component_prover.Poly;
const Twiddles = engine.poly.twiddles.TwiddleTree([]const M);
const canonical = core.poly.circle.canonic;
const retained = @import("../air/memory_commitment/hash_component_prepared_support.zig");
const packed_support = @import("../recursion/air/universal_typed_component_contract.zig");

pub const Policy = enum { retained, packed_word, lookup };
pub const VALUE_LIMIT: usize = 256 * 1024 * 1024;
pub const ENTRY_LIMIT: usize = 4096;
const Key = struct {
    values: [*]const M,
    values_len: usize,
    coefficients: ?[*]const M,
    coefficients_len: usize,
    coefficients_log: ?u32,
    source_log: u32,
    trace_log: u32,
    eval_log: u32,
    policy: Policy,
};
const Entry = struct {
    key: Key,
    state: enum { pending, ready, failed } = .pending,
    values: []M = &.{},
    failure: ?anyerror = null,
};

pub const Cache = struct {
    a: std.mem.Allocator,
    entries: []Entry,
    count: usize = 0,
    value_limit: usize,
    reserved_bytes: usize = 0,
    recovered_columns: usize = 0,
    reused_columns: usize = 0,
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},

    pub fn init(a: std.mem.Allocator) !Cache {
        return initBounded(a, VALUE_LIMIT, ENTRY_LIMIT);
    }
    pub fn initBounded(a: std.mem.Allocator, value_limit: usize, entry_limit: usize) !Cache {
        return .{ .a = a, .value_limit = value_limit, .entries = try a.alloc(Entry, entry_limit) };
    }
    /// The owner must join all component evaluators before destroying the
    /// cache. Its sources must remain immutable and alive throughout the proof.
    pub fn deinit(self: *Cache) void {
        for (self.entries[0..self.count]) |entry| {
            std.debug.assert(entry.state != .pending);
            if (entry.state == .ready) self.a.free(entry.values);
        }
        self.a.free(self.entries);
        self.* = undefined;
    }
    /// Returned evaluations are immutable, borrowed until deinit. Null means
    /// capacity exhaustion and requires unchanged local preparation. Distinct
    /// columns can be recovered concurrently; duplicate requests wait for one
    /// producer rather than repeating FFTs or admitting an unfinished buffer.
    pub fn get(self: *Cache, policy: Policy, poly: Poly, trace_log: u32, eval_log: u32, twiddles: ?Twiddles) !?[]const M {
        try poly.validate();
        if (trace_log == 0 or trace_log >= core.circle.M31_CIRCLE_LOG_ORDER or eval_log == 0) return error.InvalidProofShape;
        if (policy == .packed_word) _ = try packed_support.sourceNeedsExtension(poly, trace_log, eval_log);
        if (policy == .retained) _ = try retained.sourceNeedsExtension(poly, trace_log, eval_log);
        if (poly.log_size == eval_log and poly.values.len != 0) return poly.values;
        if (eval_log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidProofShape;
        const eval_size = @as(usize, 1) << @intCast(eval_log);
        const byte_count = try std.math.mul(usize, eval_size, @sizeOf(M));
        const coefficients = if (poly.coefficients) |p| p.coefficients() else null;
        const key = Key{ .values = poly.values.ptr, .values_len = poly.values.len, .coefficients = if (coefficients) |p| p.ptr else null, .coefficients_len = if (coefficients) |p| p.len else 0, .coefficients_log = if (poly.coefficients) |p| p.logSize() else null, .source_log = poly.log_size, .trace_log = trace_log, .eval_log = eval_log, .policy = policy };
        self.mutex.lock();
        for (self.entries[0..self.count]) |*entry| if (std.meta.eql(entry.key, key)) {
            while (entry.state == .pending) self.changed.wait(&self.mutex);
            if (entry.failure) |failure| {
                self.mutex.unlock();
                return failure;
            }
            self.reused_columns += 1;
            const result = entry.values;
            self.mutex.unlock();
            return result;
        };
        if (self.count == self.entries.len or byte_count > self.value_limit - self.reserved_bytes) {
            self.mutex.unlock();
            return null;
        }
        const index = self.count;
        self.entries[index] = .{ .key = key };
        self.count += 1;
        self.reserved_bytes += byte_count;
        self.mutex.unlock();
        const values = recover(self.a, policy, poly, trace_log, eval_log, twiddles) catch |failure| {
            self.mutex.lock();
            self.entries[index].failure = failure;
            self.entries[index].state = .failed;
            self.reserved_bytes -= byte_count;
            self.changed.broadcast();
            self.mutex.unlock();
            return failure;
        };
        self.mutex.lock();
        self.entries[index].values = values;
        self.entries[index].state = .ready;
        self.recovered_columns += 1;
        self.changed.broadcast();
        self.mutex.unlock();
        return values;
    }
};

/// Same local recovery policies used by the existing adapters, followed by the
/// identical canonical forward transform. Lookup preserves its original full
/// recovered coefficient-tail check and permits a larger source domain.
fn recover(a: std.mem.Allocator, policy: Policy, poly: Poly, trace_log: u32, eval_log: u32, twiddles: ?Twiddles) ![]M {
    const eval_size = @as(usize, 1) << @intCast(eval_log);
    var buffers: [1][]M = undefined;
    var initialized: usize = 0;
    errdefer for (buffers[0..initialized]) |buffer| a.free(buffer);
    switch (policy) {
        .packed_word => _ = try packed_support.evaluationValues(a, poly, trace_log, eval_log, eval_size, twiddles, &buffers, &initialized),
        .retained => _ = try retained.evaluationValues(a, poly, eval_log, eval_size, &buffers, &initialized),
        .lookup => {
            if (poly.coefficients != null) {
                _ = try retained.evaluationValues(a, poly, eval_log, eval_size, &buffers, &initialized);
            } else {
                const domain = canonical.CanonicCoset.new(poly.log_size).circleDomain();
                var coefficients = try engine.poly.circle.poly.interpolateFromEvaluation(a, .{ .domain = domain, .values = poly.values });
                defer coefficients.deinit(a);
                const source = coefficients.coefficients();
                const trace_size = @as(usize, 1) << @intCast(trace_log);
                if (source.len < trace_size or trace_size > eval_size) return error.InvalidV5LookupRequestSourceDegree;
                for (source[trace_size..]) |value| if (!value.isZero()) return error.InvalidV5LookupRequestSourceDegree;
                const values = try a.alloc(M, eval_size);
                @memcpy(values[0..trace_size], source[0..trace_size]);
                @memset(values[trace_size..], M.zero());
                buffers[0] = values;
                initialized = 1;
            }
        },
    }
    if (initialized != 1) return error.InvalidProofShape;
    try engine.poly.circle.poly.evaluateBuffersWithTwiddles(&buffers, canonical.CanonicCoset.new(eval_log).circleDomain(), twiddles orelse return error.InvalidProofShape);
    return buffers[0];
}
