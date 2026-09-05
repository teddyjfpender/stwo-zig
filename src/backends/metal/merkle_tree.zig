//! Metal-owned lifted Merkle tree storage.
//!
//! Small commitments retain the reference host tree. Large commitments keep
//! every hash layer device-resident and read back only queried authentication
//! nodes. The generic prover sees the same typed reader interface in both cases.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const decommit_mod = @import("stwo_prover_engine").vcs_lifted.decommit;
const host_merkle = @import("stwo_prover_engine").vcs_lifted.prover;
const hash_domain = @import("hash_domain.zig");
const runtime_mod = @import("runtime.zig");
const shared_runtime = @import("shared_runtime.zig");
const telemetry = @import("telemetry.zig");

const M31 = m31.M31;

pub fn MetalMerkleTree(comptime H: type) type {
    const HostTree = host_merkle.MerkleProverLifted(H);
    return struct {
        storage: Storage,

        const Self = @This();
        const ResidentTree = struct {
            tree: runtime_mod.Tree,
            root_hash: H.Hash,
            tracks_shared_runtime: bool,
        };
        const ResidentBatchReader = struct {
            tree: runtime_mod.Tree,

            pub fn maxLogSize(self: @This()) u32 {
                return self.tree.log_size;
            }

            pub fn readHashesBatch(
                self: @This(),
                allocator: std.mem.Allocator,
                requests: []const decommit_mod.HashReadRequest,
            ) (std.mem.Allocator.Error || error{InvalidColumnSize})!decommit_mod.HashReadBatch(H) {
                if (@sizeOf(H.Hash) != @sizeOf([32]u8)) return error.InvalidColumnSize;
                const packed_layers = self.tree.copyHashesBatch(
                    allocator,
                    requests,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.InvalidColumnSize,
                };
                defer {
                    for (packed_layers) |packed_hashes| allocator.free(packed_hashes);
                    allocator.free(packed_layers);
                }

                const layers = try allocator.alloc([]H.Hash, packed_layers.len);
                var initialized: usize = 0;
                errdefer {
                    for (layers[0..initialized]) |layer| allocator.free(layer);
                    allocator.free(layers);
                }
                for (packed_layers, layers) |packed_hashes, *layer| {
                    layer.* = try allocator.alloc(H.Hash, packed_hashes.len);
                    initialized += 1;
                    for (packed_hashes, layer.*) |hash, *destination| destination.* = @bitCast(hash);
                }
                return .{ .layers = layers };
            }

            pub fn readQueriedValuesBatch(
                self: @This(),
                allocator: std.mem.Allocator,
                query_positions: []const usize,
                columns: []const []const M31,
            ) (std.mem.Allocator.Error || error{InvalidColumnSize})!?[][]M31 {
                const word_columns = try allocator.alloc([]const u32, columns.len);
                defer allocator.free(word_columns);
                for (columns, word_columns) |column, *words| {
                    words.* = std.mem.bytesAsSlice(
                        u32,
                        std.mem.sliceAsBytes(column),
                    );
                }
                const flat = self.tree.tryCopyQueriedValuesFlat(
                    allocator,
                    word_columns,
                    query_positions,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.InvalidColumnSize,
                } orelse return null;
                defer allocator.free(flat);

                const result = try allocator.alloc([]M31, columns.len);
                var initialized: usize = 0;
                errdefer {
                    for (result[0..initialized]) |values| allocator.free(values);
                    allocator.free(result);
                }
                var canonical = true;
                for (result, 0..) |*values, column| {
                    values.* = try allocator.alloc(M31, query_positions.len);
                    initialized += 1;
                    const source = flat[column * query_positions.len .. (column + 1) * query_positions.len];
                    for (source, values.*) |raw, *value| {
                        canonical = canonical and raw < m31.Modulus;
                        value.* = M31.fromU32Unchecked(raw);
                    }
                }
                if (!canonical) return error.InvalidColumnSize;
                return result;
            }
        };
        const Storage = union(enum) {
            host: HostTree,
            resident: ResidentTree,
        };

        pub const DecommitmentResult = decommit_mod.DecommitmentResult(H);

        pub fn fromHost(tree: HostTree) Self {
            return .{ .storage = .{ .host = tree } };
        }

        pub fn fromResident(tree: runtime_mod.Tree) !Self {
            return fromResidentOwned(tree, false);
        }

        pub fn fromSharedRuntime(tree: runtime_mod.Tree) !Self {
            return fromResidentOwned(tree, true);
        }

        fn fromResidentOwned(tree: runtime_mod.Tree, tracks_shared_runtime: bool) !Self {
            errdefer {
                var owned = tree;
                owned.deinit();
            }
            const root_result = try tree.root();
            if (@sizeOf(H.Hash) != @sizeOf(@TypeOf(root_result.hash))) {
                return error.UnsupportedMetalHash;
            }
            if (tracks_shared_runtime) shared_runtime.retainResidentResource();
            const maybe_domain = comptime hash_domain.parameters(H);
            if (comptime maybe_domain != null) {
                if (comptime maybe_domain.?.family == .poseidon2_m31) {
                    telemetry.record(.metal_poseidon2_merkle_commit);
                }
            }
            return .{
                .storage = .{ .resident = .{
                    .tree = tree,
                    .root_hash = @bitCast(root_result.hash),
                    .tracks_shared_runtime = tracks_shared_runtime,
                } },
            };
        }

        pub fn commit(
            runtime: *runtime_mod.Runtime,
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) !Self {
            return commitOwned(runtime, allocator, columns, false, null);
        }

        pub fn commitShared(
            runtime: *runtime_mod.Runtime,
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) !Self {
            return commitOwned(runtime, allocator, columns, true, null);
        }

        pub fn commitSharedBacking(
            runtime: *runtime_mod.Runtime,
            allocator: std.mem.Allocator,
            columns: []const []const M31,
            backings: []const []M31,
        ) !Self {
            return commitOwned(runtime, allocator, columns, true, backings);
        }

        fn commitOwned(
            runtime: *runtime_mod.Runtime,
            allocator: std.mem.Allocator,
            columns: []const []const M31,
            tracks_shared_runtime: bool,
            backings: ?[]const []M31,
        ) !Self {
            const maybe_domain = comptime hash_domain.parameters(H);
            if (comptime maybe_domain == null) return error.UnsupportedMetalHash;
            const domain = maybe_domain.?;
            const log_sizes = try allocator.alloc(u32, columns.len);
            defer allocator.free(log_sizes);
            const word_columns = try allocator.alloc([]const u32, columns.len);
            defer allocator.free(word_columns);

            var max_log_size: u32 = 0;
            for (columns, 0..) |column, index| {
                if (column.len < 2 or !std.math.isPowerOfTwo(column.len)) {
                    return error.InvalidColumnSize;
                }
                const log_size: u32 = @intCast(std.math.log2_int(usize, column.len));
                log_sizes[index] = log_size;
                max_log_size = @max(max_log_size, log_size);
                word_columns[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column));
            }

            const tree = if (backings) |values|
                try runtime.commitColumnsWithBackingForHash(
                    allocator,
                    word_columns,
                    log_sizes,
                    max_log_size,
                    domain.leaf_seed,
                    domain.node_seed,
                    domain.domain_prefix_bytes,
                    @intFromEnum(domain.family),
                    values,
                )
            else
                try runtime.commitColumnsForHash(
                    allocator,
                    word_columns,
                    log_sizes,
                    max_log_size,
                    domain.leaf_seed,
                    domain.node_seed,
                    domain.domain_prefix_bytes,
                    @intFromEnum(domain.family),
                );

            return fromResidentOwned(tree, tracks_shared_runtime);
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            switch (self.storage) {
                .host => |tree_value| {
                    var tree = tree_value;
                    tree.deinit(allocator);
                },
                .resident => |resident_value| {
                    var resident = resident_value;
                    resident.tree.deinit();
                    if (resident.tracks_shared_runtime) shared_runtime.releaseResidentResource();
                },
            }
            self.* = undefined;
        }

        pub fn root(self: Self) H.Hash {
            return switch (self.storage) {
                .host => |tree| tree.root(),
                .resident => |resident| resident.root_hash,
            };
        }

        pub fn maxLogSize(self: Self) u32 {
            return switch (self.storage) {
                .host => |tree| tree.maxLogSize(),
                .resident => |resident| resident.tree.log_size,
            };
        }

        /// Returns a borrowed handle only when this commitment is backed by a
        /// Metal tree. Callers must scope the handle to the owning proof tree.
        pub fn quotientResidencyHandle(self: Self) ?*anyopaque {
            return switch (self.storage) {
                .host => null,
                .resident => |resident| resident.tree.handle,
            };
        }

        pub fn readHashes(
            self: Self,
            allocator: std.mem.Allocator,
            layer_log_size: u32,
            indices: []const u32,
        ) (std.mem.Allocator.Error || error{InvalidColumnSize})![]H.Hash {
            return switch (self.storage) {
                .host => |tree| tree.readHashes(allocator, layer_log_size, indices),
                .resident => |resident| blk: {
                    if (@sizeOf(H.Hash) != @sizeOf([32]u8)) {
                        return error.InvalidColumnSize;
                    }
                    const packed_hashes = resident.tree.copyHashes(
                        allocator,
                        layer_log_size,
                        indices,
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.InvalidColumnSize,
                    };
                    defer allocator.free(packed_hashes);

                    const hashes = try allocator.alloc(H.Hash, packed_hashes.len);
                    for (packed_hashes, hashes) |hash, *destination| destination.* = @bitCast(hash);
                    break :blk hashes;
                },
            };
        }

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
            columns: []const []const M31,
        ) (std.mem.Allocator.Error || error{InvalidColumnSize})!DecommitmentResult {
            return switch (self.storage) {
                .host => |tree| decommit_mod.decommit(H, tree, allocator, query_positions, columns),
                .resident => |resident| decommit_mod.decommit(
                    H,
                    ResidentBatchReader{ .tree = resident.tree },
                    allocator,
                    query_positions,
                    columns,
                ),
            };
        }
    };
}
