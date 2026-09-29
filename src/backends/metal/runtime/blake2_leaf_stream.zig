//! Proof-owned GPU leaf state. Each successful block consumes its source views
//! synchronously. Only the compact prefix remains resident between blocks.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover = @import("stwo_prover_engine");
const Runtime = @import("../runtime.zig").Runtime;
const domains = @import("../hash_domain.zig");
const Budget = prover.host_budget_allocator.SharedHostBudget;
const telemetry = @import("../telemetry.zig");

const Admit = *const fn (?*anyopaque, u64) callconv(.c) bool;
const Release = *const fn (?*anyopaque, u64) callconv(.c) bool;
const Publish = *const fn (?*anyopaque, u32, ?*const anyopaque, usize) callconv(.c) bool;
extern fn stwo_zig_metal_blake2_leaf_stream_create_v1(*anyopaque, [*]const u32, [*]const u32, u32) ?*anyopaque;
extern fn stwo_zig_metal_blake2_leaf_stream_destroy_v1(*anyopaque) void;
extern fn stwo_zig_metal_blake2_leaf_stream_push_v1(
    *anyopaque,
    [*]const [*]const u32,
    [*]const usize,
    [*]const u32,
    u32,
    bool,
    [*]const [*]const u32,
    [*]const usize,
    u32,
    ?*anyopaque,
    Admit,
    *u64,
    *u32,
    *u32,
    [*]u8,
    usize,
) bool;
extern fn stwo_zig_metal_blake2_leaf_stream_finish_v1(*anyopaque, u32, ?*anyopaque, Publish, ?*anyopaque, Admit, Release, [*]u8, usize) bool;

const Admission = struct {
    reservation: *Budget.ExternalReservation,
    failure: ?anyerror = null,
    fn release(raw: ?*anyopaque, bytes: u64) callconv(.c) bool {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (bytes > self.reservation.bytes) {
            self.failure = error.NativeBudgetUnderflow;
            return false;
        }
        self.reservation.resize(self.reservation.bytes - @as(usize, @intCast(bytes))) catch |err| {
            self.failure = err;
            return false;
        };
        return true;
    }
    fn admit(raw: ?*anyopaque, bytes: u64) callconv(.c) bool {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        const total = std.math.add(usize, self.reservation.bytes, std.math.cast(usize, bytes) orelse {
            self.failure = error.AllocationSizeOverflow;
            return false;
        }) catch {
            self.failure = error.AllocationSizeOverflow;
            return false;
        };
        self.reservation.resize(total) catch |err| {
            self.failure = err;
            return false;
        };
        return true;
    }
};

pub fn Stream(comptime H: type) type {
    const domain = domains.parameters(H) orelse @compileError("unsupported streaming hash domain");
    const b2 = @import("stwo_core").vcs_lifted.blake2_merkle;
    if (domain.family != .blake2s or (H != b2.Blake2sPlainMerkleHasher and H != b2.Blake2sMerkleHasher))
        @compileError("BLAKE2s leaf streaming requires the plain or domain-prefixed byte-digest protocol");
    return struct {
        allocator: std.mem.Allocator,
        /// Borrowed runtime; the caller must retain its session through deinit.
        handle: *anyopaque,
        reservation: Budget.ExternalReservation,
        columns: u32 = 0,
        log_size: u32 = 0,
        final_block: bool = false,
        poisoned: bool = false,
        aliases: u64 = 0,
        uploads: u64 = 0,
        const Self = @This();
        const Tree = prover.vcs_lifted.prover.MerkleProverLifted(H);

        pub fn init(a: std.mem.Allocator, runtime: *Runtime) !Self {
            var reservation = if (Budget.fromAllocator(a)) |budget| try budget.reserveExternal(0) else Budget.ExternalReservation.unbudgeted(0);
            errdefer reservation.deinit();
            const handle = stwo_zig_metal_blake2_leaf_stream_create_v1(runtime.handle, &domain.leaf_seed, &domain.node_seed, domain.domain_prefix_bytes) orelse return error.NativeLeafStreamFailed;
            return .{ .allocator = a, .handle = handle, .reservation = reservation };
        }

        pub fn deinit(self: *Self) void {
            stwo_zig_metal_blake2_leaf_stream_destroy_v1(self.handle);
            self.reservation.deinit();
            self.* = undefined;
        }

        /// Nonterminal blocks contain exactly sixteen columns. Keep the final
        /// block buffered until its terminal status is known, even if full.
        /// Explicit backing regions enable safe no-copy GPU input views.
        pub fn pushBlock(self: *Self, columns: []const []const M31, final: bool, backings: []const []const M31) !void {
            if (self.poisoned or self.final_block) return error.NativeLeafStreamClosed;
            if (columns.len == 0 or columns.len > 16 or (!final and columns.len != 16) or backings.len > std.math.maxInt(u32)) return error.InvalidColumns;
            var pointers: [16][*]const u32 = undefined;
            var lengths: [16]usize = undefined;
            var logs: [16]u32 = undefined;
            var last_log = self.log_size;
            for (columns, 0..) |column, index| {
                if (column.len < 2 or !std.math.isPowerOfTwo(column.len)) return error.InvalidColumns;
                const log: u32 = @intCast(std.math.log2_int(usize, column.len));
                if (log >= 31 or log < last_log) return error.InvalidColumns;
                last_log = log;
                if (backings.len != 0) {
                    var covered = false;
                    const begin = @intFromPtr(column.ptr);
                    const bytes = try std.math.mul(usize, column.len, @sizeOf(M31));
                    for (backings) |backing| {
                        const base = @intFromPtr(backing.ptr);
                        const size = try std.math.mul(usize, backing.len, @sizeOf(M31));
                        if (begin >= base and begin - base <= size and bytes <= size - (begin - base)) covered = true;
                    }
                    if (!covered) return error.InvalidColumns;
                }
                pointers[index] = @ptrCast(column.ptr);
                lengths[index] = column.len;
                logs[index] = log;
            }
            const count: u32 = @intCast(columns.len);
            if (self.columns > (std.math.maxInt(u32) - domain.domain_prefix_bytes) / 4 - count) return error.InvalidColumns;
            const bases = try self.allocator.alloc([*]const u32, backings.len);
            defer self.allocator.free(bases);
            const base_lengths = try self.allocator.alloc(usize, backings.len);
            defer self.allocator.free(base_lengths);
            for (backings, bases, base_lengths) |backing, *base, *length| {
                base.* = @ptrCast(backing.ptr);
                length.* = backing.len;
            }
            var admission = Admission{ .reservation = &self.reservation };
            const previous_bytes = self.reservation.bytes;
            var retained: u64 = previous_bytes;
            var aliases: u32 = 0;
            var uploads: u32 = 0;
            var message: [1024]u8 = @splat(0);
            const accepted = stwo_zig_metal_blake2_leaf_stream_push_v1(self.handle, &pointers, &lengths, &logs, count, final, bases.ptr, base_lengths.ptr, @intCast(backings.len), &admission, Admission.admit, &retained, &aliases, &uploads, &message, message.len);
            // Native temporaries and command references have drained on return.
            try self.reservation.resize(if (accepted) @intCast(retained) else previous_bytes);
            if (!accepted) {
                self.poisoned = true;
                if (admission.failure) |err| return err;
                std.log.err("native leaf stream rejected: {s}", .{std.mem.sliceTo(&message, 0)});
                return error.NativeLeafStreamFailed;
            }
            self.columns += count;
            self.log_size = last_log;
            self.final_block = final;
            self.aliases += aliases;
            self.uploads += uploads;
            telemetry.record(.metal_streaming_leaf_dispatch);
        }

        /// Publish only the requested upper layers into normal prover custody.
        /// Lower layers can subsequently be reconstructed from coefficients.
        pub fn finish(self: *Self, pruned_layers: u32) !Tree {
            if (self.poisoned or !self.final_block or pruned_layers > self.log_size) return error.NativeLeafStreamClosed;
            const layers = try self.allocator.alloc([]H.Hash, self.log_size + 1);
            @memset(layers, &.{});
            var owns_layers = true;
            defer if (owns_layers) {
                for (layers) |layer| self.allocator.free(layer);
                self.allocator.free(layers);
            };
            const Publisher = struct {
                allocator: std.mem.Allocator,
                layers: [][]H.Hash,
                failure: ?anyerror = null,
                fn publish(raw: ?*anyopaque, log: u32, values: ?*const anyopaque, bytes: usize) callconv(.c) bool {
                    const self_pub: *@This() = @ptrCast(@alignCast(raw.?));
                    if (log >= self_pub.layers.len or self_pub.layers[log].len != 0 or values == null or bytes % @sizeOf(H.Hash) != 0) {
                        self_pub.failure = error.InvalidColumns;
                        return false;
                    }
                    const layer = self_pub.allocator.alloc(H.Hash, bytes / @sizeOf(H.Hash)) catch |err| {
                        self_pub.failure = err;
                        return false;
                    };
                    @memcpy(std.mem.sliceAsBytes(layer), @as([*]const u8, @ptrCast(values.?))[0..bytes]);
                    self_pub.layers[log] = layer;
                    return true;
                }
            };
            var publisher = Publisher{ .allocator = self.allocator, .layers = layers };
            var admission = Admission{ .reservation = &self.reservation };
            var message: [1024]u8 = @splat(0);
            self.poisoned = true;
            const accepted = stwo_zig_metal_blake2_leaf_stream_finish_v1(self.handle, pruned_layers, &publisher, Publisher.publish, &admission, Admission.admit, Admission.release, &message, message.len);
            try self.reservation.resize(0);
            if (!accepted) {
                if (publisher.failure) |err| return err;
                if (admission.failure) |err| return err;
                std.log.err("native leaf tree rejected: {s}", .{std.mem.sliceTo(&message, 0)});
                return error.NativeLeafStreamFailed;
            }
            telemetry.record(.resident_merkle_commit);
            owns_layers = false;
            return .{ .layers = layers, .layer_allocator = self.allocator };
        }
    };
}
