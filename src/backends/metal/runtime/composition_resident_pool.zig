//! Bounded idle/live resident scratch, keyed to runtime and allocation owner.
//! Factories return uncharged resources and are never called before admission.
const std = @import("std");
const external = @import("stwo_prover_engine").shared_external_memory;

pub fn Pool(comptime Resource: type, comptime capacity: usize, comptime cache_limit: usize) type {
    return struct {
        const Self = @This();
        const Key = struct {
            runtime: usize,
            allocator_pointer: usize,
            allocator_vtable: usize,
            fn init(a: std.mem.Allocator, runtime: usize) Key {
                return .{ .runtime = runtime, .allocator_pointer = @intFromPtr(a.ptr), .allocator_vtable = @intFromPtr(a.vtable) };
            }
        };
        const Entry = struct { key: Key, resource: Resource };
        mutex: std.Thread.Mutex = .{},
        entries: [capacity]?Entry = @splat(null),
        active: usize = 0,
        hits: u64 = 0,
        misses: u64 = 0,

        pub const Snapshot = struct { hits: u64, misses: u64, pooled: usize };
        pub fn snapshot(self: *Self) Snapshot {
            self.mutex.lock();
            defer self.mutex.unlock();
            var pooled: usize = 0;
            for (self.entries) |entry| pooled += @intFromBool(entry != null);
            return .{ .hits = self.hits, .misses = self.misses, .pooled = pooled };
        }

        pub fn acquire(self: *Self, a: std.mem.Allocator, runtime: usize, bytes: usize, factory: anytype) !Resource {
            if (runtime == 0 or bytes == 0) return error.InvalidCompositionScratchResource;
            const key = Key.init(a, runtime);
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.active >= capacity) return error.CompositionScratchCapacityExceeded;
            for (&self.entries) |*slot| if (slot.*) |entry| {
                if (std.meta.eql(entry.key, key) and entry.resource.byte_length == bytes) {
                    slot.* = null;
                    self.active += 1;
                    self.hits += 1;
                    return entry.resource;
                }
            };
            // Preserve the existing combined live+idle limit. Eviction destroys
            // the resident before its token, making released capacity usable.
            var idle: usize = 0;
            for (self.entries) |entry| idle += @intFromBool(entry != null);
            if (self.active + idle == capacity) for (&self.entries) |*slot| if (slot.*) |*entry| {
                entry.resource.deinit();
                slot.* = null;
                break;
            };
            var reservation = try external.reserve(a, bytes, .explicit_unbudgeted);
            defer reservation.deinit();
            var resource = try factory.create(bytes);
            errdefer resource.deinit();
            if (resource.byte_length != bytes or resource.external_reservation.active) return error.InvalidCompositionScratchResource;
            resource.external_reservation = reservation.take();
            self.active += 1;
            self.misses += 1;
            return resource;
        }

        /// The caller has joined every operation borrowing this resource.
        pub fn release(self: *Self, a: std.mem.Allocator, runtime: usize, resource: Resource) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            std.debug.assert(self.active > 0);
            std.debug.assert(resource.external_reservation.active);
            std.debug.assert(resource.external_reservation.owner == external.SharedBudget.fromAllocator(a));
            self.active -= 1;
            if (resource.byte_length <= cache_limit) for (&self.entries) |*slot| if (slot.* == null) {
                slot.* = .{ .key = Key.init(a, runtime), .resource = resource };
                return;
            };
            var owned = resource;
            owned.deinit();
        }

        /// Producer teardown after its borrowers joined. Keep other owners'
        /// buffers intact; their cache tokens continue charging their budgets.
        pub fn drain(self: *Self, a: std.mem.Allocator) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.active != 0) return error.RuntimeBusy;
            const key = Key.init(a, 0);
            for (&self.entries) |*slot| if (slot.*) |*entry| {
                if (entry.key.allocator_pointer == key.allocator_pointer and entry.key.allocator_vtable == key.allocator_vtable) {
                    entry.resource.deinit();
                    slot.* = null;
                }
            };
        }

        pub fn drainAll(self: *Self) !void {
            if (!self.mutex.tryLock()) return error.RuntimeBusy;
            defer self.mutex.unlock();
            if (self.active != 0) return error.RuntimeBusy;
            for (&self.entries) |*slot| if (slot.*) |*entry| {
                entry.resource.deinit();
                slot.* = null;
            };
        }
    };
}
