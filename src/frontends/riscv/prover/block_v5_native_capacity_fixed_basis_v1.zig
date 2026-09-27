//! One bounded immutable capacity fixed commitment. A lease owns a real PCS
//! reference; only main/interactions/channel/FRI are per instance. This is a
//! producer optimization and never replaces independent receiver rebuilds.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const statement = @import("../air/statement.zig");
const profile = @import("../isa/execution_profile.zig");
const suite = core.proof_suites.Blake3;
pub const Limits = struct {
    max_columns: usize = 2 * protocol.MAX_SHARDS,
    max_log: u32 = 24,
    max_retained_bytes: usize = 1 << 30,
    /// Conservative retained host payload bound: fixed LDE+coefficients,
    /// complete Merkle layers, every possible exact-log twiddle cache, and
    /// bounded descriptor slack. Scratch/backend residency remains governed
    /// by the supplied allocator; this is not a runtime RSS guarantee.
    pub fn requiredBytes(self: Limits, logs: []const u32, config: core.pcs.PcsConfig) !usize {
        try @import("blake3_execution_protocol.zig").validateConfig(config);
        if (self.max_columns > 2 * protocol.MAX_SHARDS or self.max_log > 24 or logs.len == 0 or logs.len > self.max_columns) return error.NativeCapacityFixedBasisResourceLimit;
        var fields: usize = 0;
        var largest_lde: usize = 0;
        for (logs) |log| {
            if (log == 0 or log > self.max_log) return error.NativeCapacityFixedBasisResourceLimit;
            const committed_log = try std.math.add(u32, log, config.fri_config.log_blowup_factor);
            if (committed_log > 30) return error.NativeCapacityFixedBasisResourceLimit;
            const lde = @as(usize, 1) << @intCast(committed_log);
            const trace = @as(usize, 1) << @intCast(log);
            fields = try std.math.add(usize, fields, try std.math.add(usize, lde, trace));
            largest_lde = @max(largest_lde, lde);
        }
        // A complete binary tree has fewer than 2*N nodes. Forward/inverse
        // twiddle caches across all smaller powers retain fewer than 2*N M31.
        const columns = try std.math.mul(usize, fields, @sizeOf(core.fields.m31.M31));
        const merkle = try std.math.mul(usize, largest_lde, 2 * @sizeOf(protocol.Digest));
        const twiddles = try std.math.mul(usize, largest_lde, 2 * @sizeOf(core.fields.m31.M31));
        const total = try std.math.add(usize, 64 << 10, try std.math.add(usize, columns, try std.math.add(usize, merkle, twiddles)));
        if (total > self.max_retained_bytes) return error.NativeCapacityFixedBasisResourceLimit;
        return total;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        pub const Owner = struct {
            allocator: std.mem.Allocator,
            scheme: Scheme,
            template: protocol.Template,
            template_id: protocol.Digest,
            trace_logs: []u32,
            limits: Limits,
            retained_byte_bound: usize,
            mutex: std.Thread.Mutex = .{},
            live: bool = true,
            /// Ownership is a move, never a raw struct copy after publication.
            /// Acquisition needs this object alive; acquired proof leases may
            /// outlive it. Backend payload reads and final owner allocator must
            /// support the threads performing reads/final release.
            pub fn init(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, config: core.pcs.PcsConfig, selected: profile.ExecutionProfile, limits: Limits) !Owner {
                const logs = try protocol.columnLogs(a, shape, external, .fixed);
                errdefer a.free(logs);
                const bound = try limits.requiredBytes(logs, config);
                const fixed = try protocol.fixedColumns(a, shape, external);
                defer protocol.freeColumns(a, fixed);
                var scheme = try Scheme.init(a, config);
                errdefer scheme.deinit(a);
                // Keep the original polynomial for every proof's quotient and
                // sampled evaluation, rather than re-interpolating each lease.
                scheme.setCoefficientRetentionPolicy(.always);
                var channel = suite.Channel{};
                try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
                var roots = try scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 1 or scheme.trees.items.len != 1 or scheme.pending_commit != null) return error.InvalidNativeCapacityFixedBasis;
                const template = try protocol.Template.fromShape(shape, external, config, selected, roots.items[0]);
                const id = try template.identity();
                // Sharing is complete before publication, so every later
                // copyFixed sees an already immutable refcounted tree.
                try scheme.trees.items[0].share(a);
                return .{ .allocator = a, .scheme = scheme, .template = template, .template_id = id, .trace_logs = logs, .limits = limits, .retained_byte_bound = bound };
            }
            pub fn deinit(self: *Owner) void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (!self.live) return;
                self.live = false;
                self.scheme.deinit(self.allocator);
                self.allocator.free(self.trace_logs);
                self.trace_logs = &.{};
                // Keep mutex/live valid to reject stale acquisitions safely.
            }
            pub fn require(self: *Owner, a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, config: core.pcs.PcsConfig, selected: profile.ExecutionProfile) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                return self.requireLocked(a, shape, external, config, selected);
            }
            fn requireLocked(self: *Owner, a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, config: core.pcs.PcsConfig, selected: profile.ExecutionProfile) !void {
                if (!self.live) return error.InvalidNativeCapacityFixedBasisPhase;
                if (!std.meta.eql(config, self.template.config) or !std.meta.eql(config, self.scheme.config) or selected != self.template.execution_profile) return error.UntrustedNativeCapacityFixedBasis;
                try self.template.admit(shape, external, self.template_id);
                if (self.scheme.pending_commit != null or self.scheme.trees.items.len != 1 or self.scheme.compact_polynomial_storage) return error.InvalidNativeCapacityFixedBasis;
                const tree = &self.scheme.trees.items[0];
                if (tree.shared_owner == null or tree.compact_polynomials or tree.coefficients == null or !std.meta.eql(tree.root(), self.template.fixed_root)) return error.UntrustedNativeCapacityFixedBasis;
                const logs = try protocol.columnLogs(a, shape, external, .fixed);
                defer a.free(logs);
                if (!std.mem.eql(u32, logs, self.trace_logs) or tree.columns.len != logs.len or tree.coefficients.?.len != logs.len) return error.UntrustedNativeCapacityFixedBasis;
                if (try self.limits.requiredBytes(logs, config) != self.retained_byte_bound) return error.UntrustedNativeCapacityFixedBasis;
                for (tree.columns, tree.coefficients.?, logs) |column, coefficient, log| {
                    if (column.log_size != log + config.fri_config.log_blowup_factor or coefficient.logSize() != log) return error.UntrustedNativeCapacityFixedBasis;
                    try column.validate();
                }
            }
            /// This returns a separately owning scheme with a fixed lease and
            /// a fresh twiddle provider/channel state. Main is still uncommitted.
            /// Failure releases the acquired lease through copyFixed's errdefer.
            pub fn lease(self: *Owner, a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, config: core.pcs.PcsConfig, selected: profile.ExecutionProfile, channel: *suite.Channel) !Scheme {
                self.mutex.lock();
                defer self.mutex.unlock();
                try self.requireLocked(a, shape, external, config, selected);
                return @import("block_v5_shared_first_round_v1.zig").copyFixed(Backend, a, &self.scheme, channel);
            }
        };
    };
}
