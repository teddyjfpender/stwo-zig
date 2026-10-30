//! File-only Group/late-bridge/compact-global receiver. No retained endpoint
//! trees, producer objects or status reports enter the admission boundary.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Bundle = @import("block_v8_endpoint_group_bundle_v1.zig");
const Transport = @import("block_v8_endpoint_local_transport_v1.zig");
const Bridge = @import("block_v8_endpoint_global_bridge_proof_v1.zig");
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Data = struct {
    schema: []const u8,
    elf_sha256: [64]u8,
    incoming_sha256: [64]u8,
    outgoing_sha256: [64]u8,
    window: @import("block_v7_real_window_capture_v1.zig").Window,
    config: core.pcs.PcsConfig,
    cohort_policy: @import("block_v7_real_window_policy_v2.zig").CohortPolicy,
    group_count: u32,
    bridge_batches: u32,
    endpoint_events: u32,
    selected_initial_addresses: []const u32,
    memory_roots: [4][32]u8,
    ram_log: u32,
    boundary_log: u32,
    global_epoch: [32]u8,
};
pub const Provider = struct {
    directory: std.fs.Dir,
    config: core.pcs.PcsConfig,
    group_count: u32,
    metadata_bytes: usize,
    proof_bytes: usize,
    transport: Transport.Limits,
    pub const GroupLease = struct {
        a: std.mem.Allocator,
        metadata: []u8,
        proof: []u8,
        pub fn deinit(self: *@This()) void {
            self.a.free(self.metadata);
            self.a.free(self.proof);
        }
    };
    pub const BridgeLease = @import("block_v8_endpoint_local_directory_v1.zig").Provider.BridgeLease;
    pub fn loadGroup(self: *const Provider, a: std.mem.Allocator, index: u32) !GroupLease {
        if (index >= self.group_count) return error.MissingDirectoryGroupProof;
        var name: [64]u8 = undefined;
        const metadata = try self.directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "group-{d}.json", .{index}), self.metadata_bytes);
        errdefer a.free(metadata);
        const proof = try self.directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "group-{d}.proof", .{index}), self.proof_bytes);
        return .{ .a = a, .metadata = metadata, .proof = proof };
    }
    pub fn loadBridge(self: *const Provider, a: std.mem.Allocator, index: u32, first: u32, count: u32, max_log: u32) !BridgeLease {
        if (first != try std.math.mul(u32, index, 127)) return error.InvalidGroupBridgeCoverage;
        var name: [64]u8 = undefined;
        const bytes = try self.directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "bridge-{d}.proof", .{index}), self.transport.artifact_bytes);
        defer a.free(bytes);
        const decoded = try a.create(Transport.Owned([]Q));
        errdefer a.destroy(decoded);
        decoded.* = try Transport.bridge(a, bytes, count, max_log, self.config, self.transport);
        errdefer decoded.deinit();
        const proof = try a.create(Bridge.Proof);
        proof.* = .{ .a = decoded.arena.allocator(), .stark = decoded.stark, .claims = decoded.claims };
        return .{ .a = a, .first = first, .count = count, .decoded = decoded, .proof = proof };
    }
};
pub const Limits = struct {
    max_live_bytes: usize = 16 << 30,
    metadata_bytes: usize = 128 << 20,
    metadata_decode_bytes: usize = 256 << 20,
    transport: Transport.Limits = .{},
    bundle: Bundle.Limits = .{},
};
pub fn verify(backing: std.mem.Allocator, directory: std.fs.Dir, external: Bundle.External, limits: Limits) !Bundle.Summary {
    if (limits.max_live_bytes == 0 or limits.metadata_decode_bytes == 0) return error.InvalidGroupDirectoryLimits;
    const budget = try E.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    const bytes = try directory.readFileAlloc(a, "global-public.json", limits.metadata_bytes);
    defer a.free(bytes);
    const parse_budget = try E.host_budget_allocator.SharedHostBudget.createRetainingParent(a, limits.metadata_decode_bytes);
    defer parse_budget.destroy();
    var arena = std.heap.ArenaAllocator.init(parse_budget.allocator());
    defer arena.deinit();
    const data = try std.json.parseFromSliceLeaky(Data, arena.allocator(), bytes, .{ .allocate = .alloc_always, .max_value_len = limits.metadata_bytes });
    if (!std.mem.eql(u8, data.schema, "stwo-b8-group-compact-global-memory-metadata-v1") or !std.mem.eql(u8, &data.elf_sha256, &std.fmt.bytesToHex(external.trusted.elf_sha256, .lower)) or !std.mem.eql(u8, &data.incoming_sha256, &std.fmt.bytesToHex(external.trusted.incoming_sha256, .lower)) or !std.mem.eql(u8, &data.outgoing_sha256, &std.fmt.bytesToHex(external.trusted.outgoing_sha256, .lower)) or !std.meta.eql(data.window, external.trusted.window) or !std.meta.eql(data.config, external.config) or data.group_count == 0 or data.cohort_policy.cohort_count == 0 or data.cohort_policy.cohort_count > limits.bundle.max_cohorts or data.group_count > data.cohort_policy.cohort_count or data.bridge_batches != try std.math.divCeil(u32, data.cohort_policy.cohort_count, 127) or data.endpoint_events == 0 or data.endpoint_events > limits.bundle.memory.max_events or data.ram_log != @max(@as(u32, 4), std.math.log2_int_ceil(u32, data.endpoint_events)) or data.boundary_log > limits.transport.max_row_log) return error.UntrustedGroupDirectoryMetadata;
    const proof_bytes = try directory.readFileAlloc(a, "global-memory.proof", limits.transport.artifact_bytes);
    defer a.free(proof_bytes);
    var decoded = try Transport.compact(a, proof_bytes, data.endpoint_events, data.boundary_log, external.config, limits.transport);
    defer decoded.deinit();
    const roots = decoded.stark.commitment_scheme_proof.commitments.items;
    if (roots.len != 8 or !std.meta.eql(roots[0..4].*, data.memory_roots)) return error.UntrustedGroupDirectoryRoots;
    const proof = Compact.Proof{ .a = decoded.arena.allocator(), .budget = decoded.budget, .event_count = data.endpoint_events, .roots = data.memory_roots, .claims = decoded.claims, .stark = decoded.stark };
    const provider = Provider{ .directory = directory, .config = external.config, .group_count = data.group_count, .metadata_bytes = limits.bundle.metadata.bytes, .proof_bytes = limits.bundle.group.artifact_bytes, .transport = limits.transport };
    const summary = try Bundle.verify(a, external, .{ .group_count = data.group_count, .cohort_policy = data.cohort_policy, .bridge_batches = data.bridge_batches, .selected_initial_addresses = data.selected_initial_addresses, .global_memory = &proof }, &provider, limits.bundle);
    if (!std.meta.eql(summary.epoch, data.global_epoch)) return error.UntrustedGroupDirectoryEpoch;
    return summary;
}
