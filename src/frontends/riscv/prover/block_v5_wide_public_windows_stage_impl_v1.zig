//! Original fresh children, genuine same-parent row assembly, actual producer
//! and standalone fresh new-root verification. No default driver activation.
const std = @import("std");
const O = @import("../recursion/block_v5_wide_original_child_source_v1.zig").ForSubtype(.capacity_v1);
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub fn ForModules(comptime Public: type, comptime R: type, comptime Rows: type, comptime Protocol: type, comptime Bus: type) type {
    return struct {
        pub const Limits = struct { max_owned_bytes: usize = 8 << 30, max_child_proof_bytes: usize = 512 << 20, transcript_capacity: u32 = 1 << 24, rows: Rows.Limits = .{} };
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                pub const Artifact = struct {
                    allocator: std.mem.Allocator,
                    owner: ?*Budget,
                    bytes: []u8,
                    key: Protocol.Key,
                    expected_id: [32]u8,
                    schedule: []Bus.Wire,
                    public_input: [32]u8,
                    pub const complete_source_authority = false;
                    pub fn deinit(self: *Artifact) void {
                        const lease = self.owner;
                        self.allocator.free(self.bytes);
                        self.allocator.free(self.schedule);
                        self.* = undefined;
                        if (lease) |owner| owner.destroy();
                    }
                };
                pub const Sink = struct { context: ?*anyopaque, put_open: *const fn (?*anyopaque, *Artifact) anyerror!void };
                pub fn publish(backing: std.mem.Allocator, policy: R.Policy, children: []const []const u8, limits: Limits, sink: Sink) !void {
                    try policy.public.validate();
                    if (children.len != policy.public.instances.len or children.len == 0 or limits.max_owned_bytes == 0 or limits.transcript_capacity == 0) return error.WidePublicResourceLimit;
                    for (children) |bytes| if (bytes.len == 0 or bytes.len > limits.max_child_proof_bytes) return error.WidePublicResourceLimit;
                    const budget = try Budget.create(backing, limits.max_owned_bytes);
                    defer budget.destroy();
                    const a = budget.allocator();
                    const fresh = try a.alloc(O.Fresh, children.len);
                    defer a.free(fresh);
                    var made: usize = 0;
                    defer for (fresh[0..made]) |*child| child.deinit();
                    for (fresh, children, policy.public.instances) |*child, bytes, p| {
                        child.* = try O.verify(a, p, bytes, policy.public_limits.original);
                        made += 1;
                    }
                    var public = try Public.init(a, policy.public, policy.public_limits);
                    defer public.deinit();
                    const admission = try Protocol.Admission.init(policy.key, policy.expected_id, policy.schedule, .{ .public = &public });
                    var rows = try Rows.prepare(a, &public, fresh, limits.transcript_capacity, limits.rows);
                    defer rows.deinit();
                    const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, policy.key.profile);
                    const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
                    if (!std.meta.eql(key, policy.key) or !std.meta.eql(try key.identity(), policy.expected_id) or !std.meta.eql(try Bus.scheduleDigest(rows.wires), try Bus.scheduleDigest(policy.schedule))) return error.UntrustedWidePublicGeometry;
                    const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
                    const producer = try Producer.init(a, &rows.recursive.rows, admission);
                    defer producer.deinit();
                    var proof = try producer.prove(a, &rows.recursive.rows);
                    defer proof.deinit();
                    const bytes = try Parent.codec.encode(a, &proof, &admission);
                    defer a.free(bytes);
                    const checked = try R.verify(a, policy, bytes);
                    defer checked.deinit();
                    const lease = Budget.fromAllocator(backing);
                    if (lease) |owner| _ = owner.retain();
                    errdefer if (lease) |owner| owner.destroy();
                    const output = try backing.dupe(u8, bytes);
                    errdefer backing.free(output);
                    const schedule = try backing.dupe(Bus.Wire, rows.wires);
                    errdefer backing.free(schedule);
                    var artifact = Artifact{ .allocator = backing, .owner = lease, .bytes = output, .key = key, .expected_id = policy.expected_id, .schedule = schedule, .public_input = try admission.publicInputIdentity() };
                    try sink.put_open(sink.context, &artifact);
                }
            };
        }
    };
}
