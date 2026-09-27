//! Actual original recursive children to one genuine OPEN parent STARK.
//! No source/aggregate closure or canonical producer selection is implied.
const std = @import("std");
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Frames = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
const Policy = @import("../recursion/block_v5_heterogeneous_policy_v1.zig");
const Rows = @import("../recursion/block_v5_heterogeneous_parent_preparation_v1.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_heterogeneous_parent_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_heterogeneous_parent_receiver_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const Loader = struct {
    context: *anyopaque,
    /// Trusted bounded transport returns owned original typed recursive bytes.
    take_bytes: *const fn (*anyopaque, std.mem.Allocator, u32) anyerror![]u8,
};
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    key_id: [32]u8,
    wires: []Bus.Wire,
    coverage_digest: [32]u8,
    /// Exact supplied aggregate graph was included in the freshly verified
    /// parent. Its source/public-compensation obligations still remain open.
    scoped_aggregate_equations_verified: bool,
    pub const pairing_graph_pending = false;
    pub const aggregate_joins_pending = true;
    pub const source_authorities_pending = Coverage.SOURCE_COUNT;
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.wires);
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success consumes bytes/schedule. Error leaves ownership with this stage.
    put_heterogeneous_open: *const fn (*anyopaque, *Artifact) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Options = struct { profile: Parent.protocol.Profile, transcript_capacity: u32 = 2, rows: Rows.Limits = .{}, max_child_bytes: usize = 128 << 20, max_parent_bytes: usize = 512 << 20, max_owned_bytes: usize = 4 << 30, aggregate: ?@import("../recursion/block_v5_global_join_parent_preparation_v1.zig").Aggregate = null };
        pub fn publish(backing: std.mem.Allocator, coverage: *const Coverage.Plan, expected: []const Policy.Expected, loader: Loader, options: Options, sink: Sink) !void {
            try coverage.requireExact(coverage.meta);
            if (expected.len != coverage.meta.physical.len or expected.len == 0 or expected.len > Bus.MAX_CHILDREN or options.max_child_bytes == 0 or options.max_parent_bytes == 0 or options.max_owned_bytes == 0 or !std.meta.eql(options.profile.config(), coverage.meta.security.recursive)) return error.HeterogeneousResourceLimit;
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, options.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            const fresh = try a.alloc(Frames.Fresh, expected.len);
            defer a.free(fresh);
            var initialized: usize = 0;
            defer for (fresh[0..initialized]) |*leaf| leaf.deinit();
            const children = try a.alloc(Frames.Child, expected.len);
            defer a.free(children);
            const captures = try a.alloc(*const @import("../recursion/blake3_native_parent_verifier.zig").Verified, expected.len);
            defer a.free(captures);
            var census = try Policy.Census.init(a, coverage);
            defer census.deinit();
            for (expected, 0..) |leaf, index| {
                const bytes = try loader.take_bytes(loader.context, a, @intCast(index));
                defer a.free(bytes);
                if (bytes.len == 0 or bytes.len > options.max_child_bytes) return error.HeterogeneousResourceLimit;
                fresh[index] = try leaf.verify(a, bytes, coverage, @intCast(index));
                initialized += 1;
                try census.mark(coverage, @intCast(index), &fresh[index]);
                children[index] = fresh[index].child; // Borrow only; Fresh owns the arena.
                captures[index] = &fresh[index].equation;
            }
            try census.requireComplete();
            const policy = Policy.Policy{ .plan = coverage, .children = children, .expected = expected };
            var rows = if (options.aggregate) |aggregate| try @import("../recursion/block_v5_global_join_parent_preparation_v1.zig").prepare(a, policy, captures, options.transcript_capacity, options.rows, aggregate) else try Rows.prepareVerifierRows(a, policy, captures, options.transcript_capacity, options.rows);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, options.profile);
            const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
            const id = try key.identity();
            const authority = try Protocol.Admission.init(key, id, rows.wires, rows.values);
            const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            const plan = try Plan.init(a, &rows.recursive.rows, authority);
            defer plan.deinit();
            var proof = try plan.prove(a, &rows.recursive.rows);
            defer proof.deinit();
            const bytes = try Parent.codec.encode(a, &proof, &authority);
            defer a.free(bytes);
            if (bytes.len > options.max_parent_bytes) return error.HeterogeneousResourceLimit;
            var checked = try Receiver.verify(a, bytes, key, id, rows.wires, policy);
            defer checked.deinit();
            const public_bytes = try backing.dupe(u8, bytes);
            var owns_bytes = true;
            defer if (owns_bytes) backing.free(public_bytes);
            const wires = try backing.dupe(Bus.Wire, rows.wires);
            var owns_wires = true;
            defer if (owns_wires) backing.free(wires);
            var artifact = Artifact{ .bytes = public_bytes, .key = key, .key_id = id, .wires = wires, .coverage_digest = coverage.pinned_digest, .scoped_aggregate_equations_verified = options.aggregate != null };
            try sink.put_heterogeneous_open(sink.context, &artifact);
            owns_bytes = false;
            owns_wires = false;
        }
    };
}
