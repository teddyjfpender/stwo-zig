//! Independent receiving of the durable local/bridge/global artifact directory.
//! No producer object, trace, admitted receipt or source-nominated key enters
//! verification. Full endpoint snapshots and ELF remain external trust inputs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Bundle = @import("block_v8_endpoint_local_bundle_v1.zig");
const Bridge = @import("block_v8_endpoint_global_bridge_proof_v1.zig");
const Memory = @import("block_v7_window_memory_joint_v1.zig");
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
const Transport = @import("block_v8_endpoint_local_transport_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Digest = [32]u8;
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Input = struct {
    /// Geometry nomination only, not an accepted measurement or receipt. It
    /// is checked against the sum from freshly verified local originals.
    /// Older compact artifacts omit it from metadata; callers may use their
    /// report's count without trusting any report verification/status field.
    endpoint_events_nomination: ?u32 = null,
};
pub fn Data(comptime compact: bool) type {
    return struct {
        schema: []const u8,
        authority: []const u8,
        global_argument: ?[]const u8 = null,
        elf_sha256: []const u8,
        incoming_sha256: []const u8,
        outgoing_sha256: []const u8,
        window: Capture.Window,
        cohort_policy: Window.CohortPolicy,
        cohort_count: u32,
        bridge_batches: u32,
        endpoint_events: ?u64 = null,
        config: core.pcs.PcsConfig,
        selected_initial_addresses: []const u32,
        memory_roots: if (compact) [4]Digest else [2]Digest,
        memory_interval_log: ?u32,
        compact_ram_log: ?u32 = null,
        compact_boundary_log: ?u32 = null,
        global_epoch: Digest,
    };
}
fn hashMatches(text: []const u8, digest: Digest) bool {
    if (text.len != 64) return false;
    var decoded: Digest = undefined;
    _ = std.fmt.hexToBytes(&decoded, text) catch return false;
    return std.meta.eql(decoded, digest);
}
pub const Provider = struct {
    directory: std.fs.Dir,
    config: core.pcs.PcsConfig,
    cohorts: u32,
    local_metadata_bytes: usize,
    local_proof_bytes: usize,
    transport: Transport.Limits,
    pub const LocalLease = struct {
        a: std.mem.Allocator,
        metadata: []u8,
        proof: []u8,
        pub fn deinit(self: *@This()) void {
            self.a.free(self.metadata);
            self.a.free(self.proof);
        }
    };
    pub const BridgeLease = struct {
        a: std.mem.Allocator,
        first: u32,
        count: u32,
        decoded: *Transport.Owned([]Q),
        proof: *Bridge.Proof,
        pub fn deinit(self: *@This()) void {
            // proof is a borrowed typed view of decoded's arena. Never invoke
            // proof.deinit (which would imply an independent owning allocator).
            self.a.destroy(self.proof);
            self.decoded.deinit();
            self.a.destroy(self.decoded);
        }
    };
    pub fn loadLocal(self: *const Provider, a: std.mem.Allocator, index: u32) !LocalLease {
        if (index >= self.cohorts) return error.MissingDirectoryLocalProof;
        var name: [64]u8 = undefined;
        const metadata = try self.directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "local-{d}.json", .{index}), self.local_metadata_bytes);
        errdefer a.free(metadata);
        const proof = try self.directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "local-{d}.proof", .{index}), self.local_proof_bytes);
        return .{ .a = a, .metadata = metadata, .proof = proof };
    }
    pub fn loadBridge(self: *const Provider, a: std.mem.Allocator, index: u32) !BridgeLease {
        const first = try std.math.mul(u32, index, 127);
        if (first >= self.cohorts) return error.MissingDirectoryBridgeProof;
        const count = @min(@as(u32, 127), self.cohorts - first);
        var name: [64]u8 = undefined;
        const bytes = try self.directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "bridge-{d}.proof", .{index}), self.transport.artifact_bytes);
        defer a.free(bytes);
        const decoded = try a.create(Transport.Owned([]Q));
        errdefer a.destroy(decoded);
        // Exact FRI depth is selected by the endpoint geometry, not by the
        // resource cap. These nominations bound decoding only; Bundle later
        // freshly verifies every local original and its source/root binding.
        var max_log: u32 = 4;
        for (first..first + count) |local_index| {
            const local_bytes = try self.directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "local-{d}.json", .{local_index}), self.local_metadata_bytes);
            defer a.free(local_bytes);
            const nominated = try std.json.parseFromSlice(struct { endpoint_count: u32 }, a, local_bytes, .{ .ignore_unknown_fields = true, .max_value_len = self.local_metadata_bytes });
            defer nominated.deinit();
            const events = nominated.value.endpoint_count;
            if (events == 0 or events > (1 << 24) or std.math.log2_int_ceil(u32, events) > self.transport.max_row_log) return error.InvalidDirectoryGeometry;
            max_log = @max(max_log, std.math.log2_int_ceil(u32, events));
        }
        decoded.* = try Transport.bridge(a, bytes, count, max_log, self.config, self.transport);
        errdefer decoded.deinit();
        const proof = try a.create(Bridge.Proof);
        proof.* = .{ .a = decoded.arena.allocator(), .stark = decoded.stark, .claims = decoded.claims };
        return .{ .a = a, .first = first, .count = count, .decoded = decoded, .proof = proof };
    }
};
pub fn For(comptime compact: bool) type {
    return struct {
        pub const Limits = struct {
            max_live_bytes: usize = 16 << 30,
            global_metadata_bytes: usize = 128 << 20,
            metadata_decode_bytes: usize = 256 << 20,
            transport: Transport.Limits = .{},
            bundle: if (compact) Bundle.CompactLimits else Bundle.Limits = .{},
        };
        pub fn verifyDirectory(backing: std.mem.Allocator, directory: std.fs.Dir, external: Bundle.External, input: Input, limits: @This().Limits) !Bundle.Summary {
            if (limits.max_live_bytes == 0 or limits.metadata_decode_bytes == 0) return error.InvalidDirectoryLimits;
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            const metadata = try directory.readFileAlloc(a, "global-public.json", limits.global_metadata_bytes);
            defer a.free(metadata);
            const parse_budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(a, limits.metadata_decode_bytes);
            defer parse_budget.destroy();
            var arena = std.heap.ArenaAllocator.init(parse_budget.allocator());
            defer arena.deinit();
            const data = try std.json.parseFromSliceLeaky(Data(compact), arena.allocator(), metadata, .{ .allocate = .alloc_always, .max_value_len = limits.global_metadata_bytes });
            const schema = if (compact) "stwo-b8-local-compact-global-memory-metadata-v1" else "stwo-b8-local-global-memory-metadata-v1";
            if (!std.mem.eql(u8, data.schema, schema) or !hashMatches(data.elf_sha256, external.trusted.elf_sha256) or !hashMatches(data.incoming_sha256, external.trusted.incoming_sha256) or !hashMatches(data.outgoing_sha256, external.trusted.outgoing_sha256) or !std.meta.eql(data.window, external.trusted.window) or !std.meta.eql(data.config, external.config) or data.cohort_count == 0 or data.cohort_count > limits.bundle.max_cohorts or data.cohort_count != data.cohort_policy.cohort_count or data.selected_initial_addresses.len > limits.bundle.initial.max_initialized_words or data.bridge_batches != try std.math.divCeil(u32, data.cohort_count, 127)) return error.UntrustedDirectoryMetadata;
            if (data.global_argument) |kind| if (!std.mem.eql(u8, kind, if (compact) "compact_endpoint" else "legacy_window")) return error.UntrustedDirectoryMetadata;
            try data.cohort_policy.validate(data.window.cycles);
            const bytes = try directory.readFileAlloc(a, "global-memory.proof", limits.transport.artifact_bytes);
            defer a.free(bytes);
            const provider = Provider{ .directory = directory, .config = external.config, .cohorts = data.cohort_count, .local_metadata_bytes = limits.bundle.metadata.bytes, .local_proof_bytes = limits.bundle.local.artifact_bytes, .transport = limits.transport };
            if (compact) {
                const nomination: u32 = if (data.endpoint_events) |count| std.math.cast(u32, count) orelse return error.InvalidDirectoryGeometry else input.endpoint_events_nomination orelse return error.MissingDirectoryEventNomination;
                if (input.endpoint_events_nomination) |expected| if (nomination != expected) return error.UntrustedDirectoryGeometry;
                if (nomination == 0 or nomination > limits.bundle.memory.max_events or data.memory_interval_log != null or data.compact_ram_log == null or data.compact_ram_log.? != @max(@as(u32, 4), std.math.log2_int_ceil(u32, nomination)) or data.compact_boundary_log == null) return error.UntrustedDirectoryGeometry;
                var decoded = try Transport.compact(a, bytes, nomination, data.compact_boundary_log.?, external.config, limits.transport);
                defer decoded.deinit();
                const roots = decoded.stark.commitment_scheme_proof.commitments.items;
                if (roots.len != 8 or !std.meta.eql(roots[0..4].*, data.memory_roots)) return error.UntrustedDirectoryGeometry;
                // Borrowed view only: decoded's arena/budget own all buffers.
                const proof = Compact.Proof{ .a = decoded.arena.allocator(), .budget = decoded.budget, .event_count = nomination, .roots = data.memory_roots, .claims = decoded.claims, .stark = decoded.stark };
                const result = try Bundle.verifyCompact(a, external, .{ .cohort_count = data.cohort_count, .bridge_batches = data.bridge_batches, .cohort_policy = data.cohort_policy, .selected_initial_addresses = data.selected_initial_addresses, .global_memory = &proof }, &provider, limits.bundle);
                if (!std.meta.eql(result.epoch, data.global_epoch)) return error.UntrustedDirectoryEpoch;
                return result;
            } else {
                const interval_log = data.memory_interval_log orelse return error.MissingDirectoryGeometry;
                if (data.compact_ram_log != null or data.compact_boundary_log != null) return error.UntrustedDirectoryGeometry;
                var decoded = try Transport.legacy(a, bytes, interval_log, external.config, limits.transport);
                defer decoded.deinit();
                const roots = decoded.stark.commitment_scheme_proof.commitments.items;
                if (roots.len != 4 or !std.meta.eql(roots[0..2].*, data.memory_roots)) return error.UntrustedDirectoryGeometry;
                const proof = Memory.Proof{ .allocator = decoded.arena.allocator(), .budget = decoded.budget, .ram = @constCast(decoded.claims.ram), .interval = decoded.claims.interval, .range16 = decoded.claims.range16, .terminal = decoded.claims.terminal, .interval_log = interval_log, .roots = data.memory_roots, .stark = decoded.stark };
                const result = try Bundle.verify(a, external, .{ .cohort_count = data.cohort_count, .bridge_batches = data.bridge_batches, .cohort_policy = data.cohort_policy, .selected_initial_addresses = data.selected_initial_addresses, .global_memory = &proof }, &provider, limits.bundle);
                if (!std.meta.eql(result.epoch, data.global_epoch)) return error.UntrustedDirectoryEpoch;
                return result;
            }
        }
    };
}
pub const Limits = For(false).Limits;
pub const CompactLimits = For(true).Limits;
pub const verifyDirectory = For(false).verifyDirectory;
pub const verifyDirectoryCompact = For(true).verifyDirectory;
