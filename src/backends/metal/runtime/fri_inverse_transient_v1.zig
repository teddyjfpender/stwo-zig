//! Explicit uncapped general-Metal compatibility. Buffers are per dispatch,
//! never retained in the shared budget cache or borrowed across allocators.
const std = @import("std");
const external = @import("stwo_prover_engine").shared_external_memory;
const policy = @import("fri_allocation_policy_v1.zig");
const Key = @import("fri_inverse_cache_budget_v1.zig").Key;
pub fn Transient(comptime Resource: type) type {
    return struct {
        const Self = @This();
        const Entry = struct {
            resource: Resource,
            reservation: external.Reservation,
            fn deinit(self: *Entry) void {
                self.resource.deinit();
                self.reservation.deinit();
            }
            fn take(self: *Entry) Entry {
                const moved_resource = self.resource;
                self.resource = undefined;
                return .{ .resource = moved_resource, .reservation = self.reservation.take() };
            }
        };
        entries: [2]?Entry = .{ null, null },
        completion: external.Completion = .joined,
        active: bool = true,
        pub fn init(a: std.mem.Allocator, keys: [2]?Key, factory: anytype) !Self {
            if (external.SharedBudget.fromAllocator(a) != null) return error.InvalidFriUnbudgetedPolicy;
            const binding = try policy.Binding.init(a, .explicit_unbudgeted);
            var runtime: ?usize = null;
            for (keys, 0..) |key, index| if (key) |wanted| {
                if ((wanted.kind == .circle) != (index == 0)) return error.InvalidFriInverseCacheKey;
                _ = try wanted.bytes();
                if (runtime) |id| {
                    if (id != wanted.runtime) return error.InvalidFriInverseCacheRuntime;
                } else runtime = wanted.runtime;
            };
            if (runtime == null) return error.EmptyFriInverseCacheRequest;
            var result: Self = .{};
            errdefer result.abort();
            for (keys, &result.entries) |key, *entry| if (key) |wanted| {
                var reservation = try binding.reserve(try wanted.bytes());
                defer reservation.deinit();
                // Do not let a fallible factory write through the optional's
                // result location: its tag could be visible to rollback before
                // the Resource has been initialized.
                const created_resource = try factory.create(wanted, reservation.bytes);
                entry.* = .{ .resource = created_resource, .reservation = reservation.take() };
            };
            return result.take();
        }
        pub fn take(self: *Self) Self {
            var result = Self{ .active = self.active, .completion = self.completion };
            self.active = false;
            self.completion = .joined;
            for (&self.entries, &result.entries) |*source, *destination| if (source.*) |*entry| {
                destination.* = entry.take();
                source.* = null;
            };
            return result;
        }
        pub fn resource(self: *Self, kind: Key.Kind) ?*Resource {
            if (!self.active) return null;
            return if (self.entries[if (kind == .circle) @as(usize, 0) else 1]) |*entry| &entry.resource else null;
        }
        pub fn needsGeneration(self: *const Self, kind: Key.Kind) bool {
            return self.active and self.entries[if (kind == .circle) @as(usize, 0) else 1] != null;
        }
        pub fn bindCompletion(self: *Self, completion: external.Completion) !void {
            if (!self.active or !self.completion.isCompleted()) return error.InvalidFriCompletionBinding;
            self.completion = completion;
        }
        pub fn complete(self: *Self) !void {
            if (!self.active) return;
            if (self.completion == .in_flight) {
                const pending = self.completion.in_flight;
                self.completion = .joined;
                pending.join(pending.context) catch |err| {
                    self.abort();
                    return err;
                };
            }
            self.abort();
        }
        /// Completion callbacks are terminal even when returning an error.
        pub fn abort(self: *Self) void {
            if (!self.active) return;
            if (self.completion == .in_flight) {
                const pending = self.completion.in_flight;
                self.completion = .joined;
                const join = pending.cancel_and_join orelse pending.join;
                join(pending.context) catch {};
            }
            for (&self.entries) |*entry| if (entry.*) |*value| {
                value.deinit();
                entry.* = null;
            };
            self.active = false;
        }
    };
}
