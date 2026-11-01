//! Optional bounded sharing of independently generated native fixed polynomials.
//! No program identity supplied by a producer is trusted here. Every hit checks
//! the actual ordered coefficient logs and values, after hashing those values.
//! Padding in backing allocations is never read. Root/column order is unchanged.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const M = @import("stwo_core").fields.m31.M31;
const T = @import("protocol.zig").T;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Coefficient = engine.poly.circle.CircleCoefficients;
const Tree = T.Scheme.CommittedTree;
const Span = struct { offset: usize, len: usize, log: u32 };
const Binding = struct { column: usize, span: Span };
const Entry = struct {
    digest: [32]u8,
    values: []M,
    alignment: std.mem.Alignment,
    spans: []Span,
    payload_allocator: std.mem.Allocator,
    payload_budget: ?*Budget = null,
    fn cost(self: *const Entry) usize {
        return @sizeOf(Entry) + self.spans.len * @sizeOf(Span) + self.values.len * @sizeOf(M);
    }
    fn matches(self: *const Entry, coefficients: []const Coefficient, bindings: []const Binding) bool {
        if (bindings.len != self.spans.len) return false;
        for (bindings, self.spans) |binding, span| {
            const actual = coefficients[binding.column];
            if (actual.log_size != span.log or actual.coeffs.len != span.len or
                !std.mem.eql(u8, std.mem.sliceAsBytes(actual.coeffs), std.mem.sliceAsBytes(self.values[span.offset..][0..span.len]))) return false;
        }
        return true;
    }
};
const State = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    references: std.atomic.Value(usize) = .init(1),
    mutex: std.Thread.Mutex = .{},
    limit: usize,
    entries: std.ArrayList(*Entry) = .empty,
    group_bytes: usize = 0,
    native_bytes: usize = 0,
    hits: u64 = 0,
    observed_individual_owners: u64 = 0,
    observed_backing_owners: u64 = 0,
    observed_spans: u64 = 0,
    duplicate_native_bytes: u64 = 0,
    fn retain(self: *State) void {
        const prior = self.references.fetchAdd(1, .monotonic);
        if (prior >= std.math.maxInt(usize) / 2) @panic("too many fixed native cache leases");
    }
    fn release(self: *State) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        const a = self.allocator;
        const budget = self.budget;
        for (self.entries.items) |entry| {
            const payload_budget = entry.payload_budget;
            entry.payload_allocator.rawFree(std.mem.sliceAsBytes(entry.values), entry.alignment, @returnAddress());
            a.free(entry.spans);
            a.destroy(entry);
            if (payload_budget) |owner| owner.destroy();
        }
        self.entries.deinit(a);
        a.destroy(self);
        if (budget) |owner| owner.destroy();
    }
    fn retainedBytes(self: *const State) usize {
        return @sizeOf(State) + self.entries.capacity * @sizeOf(*Entry) + self.group_bytes;
    }
};
pub const MINIMUM_BUDGET_BYTES = @sizeOf(State);
pub const OwnedAllocation = struct { kind: enum { native, metadata }, address: usize, bytes: usize };
pub const Snapshot = struct {
    limit_bytes: usize = 0,
    retained_bytes: usize = 0,
    native_backing_bytes: usize = 0,
    groups: usize = 0,
    hits: u64 = 0,
    duplicate_native_bytes_released: u64 = 0,
    observed_individual_owners: u64 = 0,
    observed_backing_owners: u64 = 0,
    observed_spans: u64 = 0,
    owner_leases: usize = 0,
};
pub const Result = struct { shared_groups: usize = 0, inserted_groups: usize = 0, duplicate_native_bytes_released: usize = 0 };
const Group = struct {
    values: []M,
    alignment: std.mem.Alignment,
    backing_index: ?usize = null,
    owned_column: ?usize = null,
};
const Plan = struct {
    first: usize = 0,
    count: usize = 0,
    skip: bool = false,
    candidate: ?*Entry = null,
    target: ?*Entry = null,
    adopt: bool = false,
};
pub const Cache = struct {
    state: ?*State,
    /// Zero disables the cache without allocation. Positive limits include all
    /// retained native buffers and cache/control metadata (allocator overhead is
    /// not included). No eviction or unbounded global storage is used.
    pub fn init(a: std.mem.Allocator, maximum_retained_bytes: usize) !Cache {
        if (maximum_retained_bytes == 0) return .{ .state = null };
        if (maximum_retained_bytes < @sizeOf(State)) return error.InvalidFixedNativeCacheBudget;
        const budget = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (budget) |owner| owner.destroy();
        const state = try a.create(State);
        state.* = .{ .allocator = a, .budget = budget, .limit = maximum_retained_bytes };
        return .{ .state = state };
    }
    /// The source handle must stay live while acquiring a separate handle.
    pub fn retain(self: *const Cache) Cache {
        if (self.state) |state| state.retain();
        return self.*;
    }
    pub fn deinit(self: *Cache) void {
        if (self.state) |state| state.release();
        self.* = undefined;
    }
    pub fn snapshot(self: *const Cache) Snapshot {
        const state = self.state orelse return .{};
        state.mutex.lock();
        defer state.mutex.unlock();
        return .{ .limit_bytes = state.limit, .retained_bytes = state.retainedBytes(), .native_backing_bytes = state.native_bytes, .groups = state.entries.items.len, .hits = state.hits, .duplicate_native_bytes_released = state.duplicate_native_bytes, .observed_individual_owners = state.observed_individual_owners, .observed_backing_owners = state.observed_backing_owners, .observed_spans = state.observed_spans, .owner_leases = state.references.load(.acquire) };
    }
    /// Numeric owner-range snapshot for quiescent measurement tools. No data
    /// pointer escapes the mutex. The caller frees only the descriptor array;
    /// cache capacity excludes this temporary measurement allocation.
    pub fn ownedAllocations(self: *const Cache, a: std.mem.Allocator) ![]OwnedAllocation {
        const state = self.state orelse return a.alloc(OwnedAllocation, 0);
        state.mutex.lock();
        defer state.mutex.unlock();
        const out = try a.alloc(OwnedAllocation, 2 + 3 * state.entries.items.len);
        out[0] = .{ .kind = .metadata, .address = @intFromPtr(state), .bytes = @sizeOf(State) };
        out[1] = .{ .kind = .metadata, .address = if (state.entries.capacity == 0) 0 else @intFromPtr(state.entries.items.ptr), .bytes = state.entries.capacity * @sizeOf(*Entry) };
        for (state.entries.items, 0..) |entry, i| {
            out[2 + 3 * i] = .{ .kind = .metadata, .address = @intFromPtr(entry), .bytes = @sizeOf(Entry) };
            out[3 + 3 * i] = .{ .kind = .metadata, .address = @intFromPtr(entry.spans.ptr), .bytes = entry.spans.len * @sizeOf(Span) };
            out[4 + 3 * i] = .{ .kind = .native, .address = @intFromPtr(entry.values.ptr), .bytes = entry.values.len * @sizeOf(M) };
        }
        return out;
    }
    /// Host-only concrete fixed-tree operation, before share(). All allocation,
    /// shape/alias validation and capacity decisions precede custody changes.
    /// Failure leaves tree and cache unchanged. The cache uses its own
    /// allocator for metadata; every adopted payload keeps its actual source
    /// allocator and a budget lease when supported. Stateless allocator contexts
    /// are never inspected. Other allocator contexts must outlive their owners.
    /// `a` must be the original owner allocator of this tree and its payloads,
    /// exactly as required by tree.deinit(a). A final tree lease may outlive the
    /// cache handle and its original Setup.
    pub fn internTree(self: *const Cache, a: std.mem.Allocator, tree: *Tree) !Result {
        const state = self.state orelse return .{};
        const owner_allocator = state.allocator;
        if (tree.shared_owner != null or tree.backing_teardown != null or !tree.compact_polynomials) return error.InvalidFixedNativeCachePhase;
        const buffers: [][]M = tree.coefficient_backing_buffers orelse &.{};
        const coefficients = tree.coefficients orelse return error.InvalidFixedNativeCacheShape;
        if (coefficients.len != tree.columns.len) return error.InvalidFixedNativeCacheShape;
        var owned_columns: usize = 0;
        for (coefficients, tree.columns) |coefficient, column| {
            if (coefficient.log_size >= @bitSizeOf(usize) or coefficient.coeffs.len != (@as(usize, 1) << @intCast(coefficient.log_size))) return error.InvalidFixedNativeCacheShape;
            if (coefficient.owns_coeffs) owned_columns += 1;
            if (column.coefficient_values) |view| {
                if (view.len != coefficient.coeffs.len or (view.len != 0 and view.ptr != coefficient.coeffs.ptr)) return error.InvalidFixedNativeCacheAlias;
            }
        }
        const groups = try a.alloc(Group, try std.math.add(usize, buffers.len, owned_columns));
        defer a.free(groups);
        for (buffers, 0..) |buffer, i| groups[i] = .{ .values = buffer, .alignment = tree.coefficient_backing_alignment, .backing_index = i };
        var at = buffers.len;
        for (coefficients, 0..) |coefficient, i| if (coefficient.owns_coeffs) {
            groups[at] = .{ .values = @constCast(coefficient.coeffs), .alignment = .of(M), .owned_column = i };
            at += 1;
        };
        const plans = try a.alloc(Plan, groups.len);
        defer a.free(plans);
        @memset(plans, .{});
        defer for (plans) |plan| if (plan.candidate) |entry| {
            owner_allocator.free(entry.spans);
            owner_allocator.destroy(entry);
        };
        const binding_groups = try a.alloc(?usize, coefficients.len);
        defer a.free(binding_groups);
        @memset(binding_groups, null);
        for (groups, 0..) |group, i| {
            const range = try Range.of(group.values);
            for (groups[0..i]) |other| if (range.overlaps(try Range.of(other.values))) return error.InvalidFixedNativeCacheAlias;
            for (tree.columns) |column| if (range.overlaps(try Range.of(column.values))) {
                // A retained LDE or backend alias cannot be retired by this
                // coefficient-only optimization. Leave that whole group private.
                plans[i].skip = true;
            };
        }
        for (coefficients, 0..) |coefficient, ci| {
            if (coefficient.log_size >= @bitSizeOf(usize) or coefficient.coeffs.len != (@as(usize, 1) << @intCast(coefficient.log_size))) return error.InvalidFixedNativeCacheShape;
            const range = try Range.of(coefficient.coeffs);
            for (groups, 0..) |group, bi| {
                const backing = try Range.of(group.values);
                if (!range.overlaps(backing)) continue;
                if (!backing.contains(range) or (coefficient.owns_coeffs and group.owned_column != ci)) return error.InvalidFixedNativeCacheAlias;
                binding_groups[ci] = bi;
                plans[bi].count += 1;
            }
        }
        const bindings = try a.alloc(Binding, coefficients.len);
        defer a.free(bindings);
        var total: usize = 0;
        for (plans) |*plan| {
            plan.first = total;
            total += plan.count;
            plan.count = 0;
        }
        for (coefficients, binding_groups, 0..) |coefficient, group, ci| if (group) |bi| {
            const plan = &plans[bi];
            const offset = (@intFromPtr(coefficient.coeffs.ptr) - @intFromPtr(groups[bi].values.ptr)) / @sizeOf(M);
            bindings[plan.first + plan.count] = .{ .column = ci, .span = .{ .offset = offset, .len = coefficient.coeffs.len, .log = coefficient.log_size } };
            plan.count += 1;
        };
        for (plans, groups) |*plan, group_owner| {
            const buffer = group_owner.values;
            if (plan.skip or plan.count == 0) continue;
            const entry = try owner_allocator.create(Entry);
            errdefer owner_allocator.destroy(entry);
            const spans = try owner_allocator.alloc(Span, plan.count);
            errdefer owner_allocator.free(spans);
            const group = bindings[plan.first..][0..plan.count];
            for (spans, group) |*span, binding| span.* = binding.span;
            entry.* = .{ .digest = digest(coefficients, group), .values = buffer, .alignment = group_owner.alignment, .spans = spans, .payload_allocator = a };
            _ = try std.math.add(usize, try std.math.mul(usize, buffer.len, @sizeOf(M)), try std.math.add(usize, @sizeOf(Entry), try std.math.mul(usize, spans.len, @sizeOf(Span))));
            plan.candidate = entry;
        }
        state.mutex.lock();
        defer state.mutex.unlock();
        var extra_groups: usize = 0;
        var extra_bytes: usize = 0;
        var result = Result{};
        for (plans, 0..) |*plan, pi| {
            const candidate = plan.candidate orelse continue;
            const group = bindings[plan.first..][0..plan.count];
            for (state.entries.items) |entry| if (std.mem.eql(u8, &entry.digest, &candidate.digest) and entry.matches(coefficients, group)) {
                plan.target = entry;
                break;
            };
            if (plan.target == null) for (plans[0..pi]) |prior| if (prior.target) |entry| {
                if (std.mem.eql(u8, &entry.digest, &candidate.digest) and entry.matches(coefficients, group)) {
                    plan.target = entry;
                    break;
                }
            };
            if (plan.target == null) {
                const wanted = try std.math.add(usize, state.entries.items.len, extra_groups + 1);
                const control = try std.math.add(usize, @sizeOf(State), try std.math.mul(usize, @max(state.entries.capacity, wanted), @sizeOf(*Entry)));
                const retained = try std.math.add(usize, control, try std.math.add(usize, state.group_bytes, try std.math.add(usize, extra_bytes, candidate.cost())));
                if (retained > state.limit) continue;
                plan.target = candidate;
                plan.adopt = true;
                extra_groups += 1;
                extra_bytes += candidate.cost();
            } else {
                result.duplicate_native_bytes_released = try std.math.add(usize, result.duplicate_native_bytes_released, try std.math.mul(usize, candidate.values.len, @sizeOf(M)));
            }
            result.shared_groups += 1;
        }
        const observed_individual = try std.math.add(u64, state.observed_individual_owners, owned_columns);
        const observed_backing = try std.math.add(u64, state.observed_backing_owners, buffers.len);
        const observed_spans = try std.math.add(u64, state.observed_spans, coefficients.len);
        if (result.shared_groups == 0) {
            state.observed_individual_owners = observed_individual;
            state.observed_backing_owners = observed_backing;
            state.observed_spans = observed_spans;
            return result;
        }
        _ = try std.math.add(u64, state.hits, result.shared_groups - extra_groups);
        _ = try std.math.add(u64, state.duplicate_native_bytes, result.duplicate_native_bytes_released);
        try state.entries.ensureTotalCapacityPrecise(owner_allocator, state.entries.items.len + extra_groups);
        // No fallible work follows. Each entry adopts exactly one backing;
        // duplicates are freed only after every descriptor points at its lease.
        state.retain();
        tree.backing_teardown = engine.pcs.BackingTeardownToken.init(state, 0, releaseTreeLease);
        for (plans, groups) |*plan, group_owner| {
            const entry = plan.target orelse continue;
            const original = group_owner.values;
            for (bindings[plan.first..][0..plan.count], entry.spans) |binding, span| {
                const shared = entry.values[span.offset..][0..span.len];
                coefficients[binding.column].coeffs = shared;
                coefficients[binding.column].owns_coeffs = false;
                if (tree.columns[binding.column].coefficient_values != null) tree.columns[binding.column].coefficient_values = shared;
            }
            if (plan.adopt) {
                entry.payload_budget = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                state.entries.appendAssumeCapacity(entry);
                state.group_bytes += entry.cost();
                state.native_bytes += original.len * @sizeOf(M);
                plan.candidate = null;
                result.inserted_groups += 1;
            } else {
                a.rawFree(std.mem.sliceAsBytes(original), group_owner.alignment, @returnAddress());
            }
            if (group_owner.backing_index) |index| buffers[index] = &.{};
        }
        state.observed_individual_owners = observed_individual;
        state.observed_backing_owners = observed_backing;
        state.observed_spans = observed_spans;
        state.hits += result.shared_groups - result.inserted_groups;
        state.duplicate_native_bytes += result.duplicate_native_bytes_released;
        std.debug.assert(state.retainedBytes() <= state.limit);
        return result;
    }
};
fn releaseTreeLease(context: ?*anyopaque, _: u64) void {
    const state: *State = @ptrCast(@alignCast(context.?));
    state.release();
}
const Range = struct {
    start: usize,
    end: usize,
    fn of(values: []const M) !Range {
        if (values.len == 0) return .{ .start = 0, .end = 0 };
        const start = @intFromPtr(values.ptr);
        return .{ .start = start, .end = try std.math.add(usize, start, try std.math.mul(usize, values.len, @sizeOf(M))) };
    }
    fn overlaps(a: Range, b: Range) bool {
        return a.start < a.end and b.start < b.end and a.start < b.end and b.start < a.end;
    }
    fn contains(a: Range, b: Range) bool {
        return a.start <= b.start and b.end <= a.end;
    }
};
fn digest(coefficients: []const Coefficient, bindings: []const Binding) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("RV64/fixed-native-circle-coefficient-group/v1\x00");
    var framed: [12]u8 = undefined;
    std.mem.writeInt(u64, framed[0..8], bindings.len, .little);
    hash.update(framed[0..8]);
    for (bindings) |binding| {
        const coefficient = coefficients[binding.column];
        std.mem.writeInt(u32, framed[0..4], coefficient.log_size, .little);
        std.mem.writeInt(u64, framed[4..12], coefficient.coeffs.len, .little);
        hash.update(&framed);
        hash.update(std.mem.sliceAsBytes(coefficient.coeffs));
    }
    return hash.finalResult();
}
