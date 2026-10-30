//! Original directory -> thin direct-original admission metadata. Codec decoding
//! extracts claims only; it does not verify them or create a NativeParent.
//! Returned metadata owns all wire buffers. External ELF/checkpoints are
//! immutable caller borrows and must outlive use of metadata.
const std = @import("std");
const Admission = @import("admission.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const MixedReceiver = @import("../../../frontends/riscv/recursion/block_v8_endpoint_mixed_join_receiver_v1.zig");
const Thin = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
const Directory = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_directory_v1.zig");
const Window = @import("../../../frontends/riscv/prover/block_v7_real_window_policy_v2.zig");
const LocalScope = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_scope_v1.zig");
const MixedScope = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_scope_v1.zig");
const LocalMetadata = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_statement_wire_v1.zig");
const MixedMetadata = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_statement_wire_v1.zig");
const LocalCodec = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_codec_v1.zig");
const MixedCodec = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_codec_v1.zig");
const BridgeScope = @import("../../../frontends/riscv/prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("../../../frontends/riscv/recursion/block_v8_endpoint_bridge_recursive_v1.zig");
const Global = @import("../../../frontends/riscv/recursion/block_v8_compact_ram_recursive_v1.zig");
const Transport = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_transport_v1.zig");
const ClaimsWire = @import("../../../frontends/riscv/prover/block_v7_union_claim_wire_v1.zig");
const Cursor = @import("../../../frontends/riscv/prover/guest_precompile/proof_artifact_wire.zig").Cursor;
const Writer = @import("../../../frontends/riscv/prover/bounded_artifact_writer_v1.zig").Writer;
pub const Kind = enum { native, mixed };
pub const production_active = false;

pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    metadata: Admission.Metadata,
    public_bytes: []const u8,
    pub fn deinit(v: *Owned) void {
        v.arena.deinit();
        v.* = undefined;
    }
    pub fn fromDirectory(a: std.mem.Allocator, kind: Kind, directory: std.fs.Dir, external: Upper.External) !Owned {
        if (!std.meta.eql(external.config, @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config())) return error.UnsupportedOriginalDirectoryProfile;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const owned = arena.allocator();
        const bytes = try directory.readFileAlloc(a, "global-public.json", 16 << 20);
        defer a.free(bytes);
        var parsed = try std.json.parseFromSlice(Directory.Data(true), a, bytes, .{ .max_value_len = 16 << 20 });
        defer parsed.deinit();
        const data = parsed.value;
        const n = data.cohort_count;
        if (!std.mem.eql(u8, data.schema, "stwo-b8-local-compact-global-memory-metadata-v1") or n == 0 or n > 62 or (kind == .mixed and n != 1) or data.bridge_batches != 1 or data.cohort_policy.cohort_count != n or !std.meta.eql(data.config, external.config) or !std.meta.eql(data.window, external.trusted.window) or !hashMatches(data.elf_sha256, external.trusted.elf_sha256) or !hashMatches(data.incoming_sha256, external.trusted.incoming_sha256) or !hashMatches(data.outgoing_sha256, external.trusted.outgoing_sha256)) return error.UntrustedOriginalDirectory;
        var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, external.elf, external.incoming, external.outgoing, external.trusted, data.cohort_policy, data.selected_initial_addresses, external.boundary, .{});
        defer window.deinit();
        const trusted = LocalScope.Trusted{
            .elf = external.elf,
            .elf_sha256 = external.trusted.elf_sha256,
            .profile = .rv32im_zkvm_ethereum_sha_v1,
            .config = external.config,
            .cohort_count = n,
            .terminal_cycle = if (external.boundary.terminal != null) external.trusted.window.cycles else null,
            .boundary_policy_id = if (external.boundary.terminal) |last| last.policy_id else @splat(0),
        };
        const locals = try owned.alloc([]const u8, n);
        const local_claims = try owned.alloc(std.meta.Child(@FieldType(Upper.Claims, "locals")), if (kind == .native) n else 0);
        var mixed_claims: @FieldType(MixedReceiver.Claims, "mixed") = undefined;
        const pins = try a.alloc(BridgeScope.Source, n);
        defer a.free(pins);
        var events: u32 = 0;
        var bridge_log: u32 = 4;
        var next_cycle: u64 = 1;
        for (locals, 0..) |*metadata, i| {
            var name: [64]u8 = undefined;
            metadata.* = try directory.readFileAlloc(owned, try std.fmt.bufPrint(&name, "local-{d}.json", .{i}), 16 << 20);
            const raw = try directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "local-{d}.proof", .{i}), 128 << 20);
            defer a.free(raw);
            const source = switch (kind) {
                .native => blk: {
                    const statement = try LocalMetadata.decode(a, metadata.*, trusted, .{});
                    defer statement.deinit();
                    if (statement.input.cohort_ordinal != i) return error.UntrustedOriginalCohortOrdinal;
                    const scope = try LocalScope.Owned.init(a, trusted, statement.input, .{});
                    defer scope.deinit();
                    var decoded = try LocalCodec.decode(a, raw, trusted, statement.input, .{});
                    defer decoded.deinit();
                    local_claims[i] = try cloneClaims(@TypeOf(decoded.claims), a, owned, decoded.claims);
                    break :blk scope.source();
                },
                .mixed => blk: {
                    const statement = try MixedMetadata.decode(a, metadata.*, trusted, .{});
                    defer statement.deinit();
                    if (statement.input.cohort_ordinal != i) return error.UntrustedOriginalCohortOrdinal;
                    const scope = try MixedScope.Owned.init(a, trusted, statement.input, .{});
                    defer scope.deinit();
                    var decoded = try MixedCodec.decode(a, raw, trusted, statement.input, .{});
                    defer decoded.deinit();
                    mixed_claims = try cloneClaims(@TypeOf(decoded.claims), a, owned, decoded.claims);
                    break :blk scope.source();
                },
            };
            pins[i] = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
            if (source.frame.clock_frame != .leaf_local or source.frame.global_first_cycle != next_cycle or source.frame.cycle_count == 0 or source.frame.cycle_count > data.cohort_policy.max_cohort_cycles) return error.NonContiguousOriginalDirectory;
            next_cycle = try std.math.add(u64, next_cycle, source.frame.cycle_count);
            if (source.endpoint_count == 0) return error.InvalidOriginalEndpointCount;
            events = try std.math.add(u32, events, source.endpoint_count);
            bridge_log = @max(bridge_log, std.math.log2_int_ceil(u32, source.endpoint_count));
        }
        if (next_cycle - 1 != external.trusted.window.cycles) return error.NonContiguousOriginalDirectory;
        if (data.endpoint_events) |nomination| if (nomination != events) return error.UntrustedOriginalEndpointCount;
        const policy = Global.Original.Policy{ .window = &window, .config = external.config, .event_count = events };
        if (data.memory_interval_log != null or data.compact_ram_log == null or data.compact_ram_log.? != @max(@as(u32, 4), std.math.log2_int_ceil(u32, events)) or data.compact_boundary_log == null or data.compact_boundary_log.? != policy.boundaryLog()) return error.UntrustedOriginalDirectoryGeometry;
        const bridge = try Bridge.Statement.Owned.init(a, .{ .config = external.config, .block_statement = try policy.digest() }, .{ .sources = pins, .global_memory = try policy.entry(data.memory_roots), .batch_first = 0, .batch_count = n });
        defer bridge.deinit();
        if (!std.meta.eql(data.global_epoch, bridge.scope.epoch.digest)) return error.UntrustedOriginalGlobalEpoch;
        const bridge_bytes = try directory.readFileAlloc(a, "bridge-0.proof", 128 << 20);
        defer a.free(bridge_bytes);
        var bridge_decoded = try Transport.bridge(a, bridge_bytes, n, bridge_log, external.config, .{});
        defer bridge_decoded.deinit();
        const global_bytes = try directory.readFileAlloc(a, "global-memory.proof", 128 << 20);
        defer a.free(global_bytes);
        var global_decoded = try Transport.compact(a, global_bytes, events, policy.boundaryLog(), external.config, .{});
        defer global_decoded.deinit();
        var writer = Writer.init(a, 8 << 20);
        defer writer.deinit();
        var remaining: usize = 1 << 20;
        switch (kind) {
            .native => try ClaimsWire.encode(Upper.Claims, &writer, .{ .locals = local_claims, .bridge = bridge_decoded.claims, .global = global_decoded.claims }, &remaining),
            .mixed => try ClaimsWire.encode(MixedReceiver.Claims, &writer, .{ .mixed = mixed_claims, .bridge = bridge_decoded.claims, .global = global_decoded.claims }, &remaining),
        }
        const claims = try owned.dupe(u8, writer.bytes.items);
        const addresses = try owned.dupe(u32, data.selected_initial_addresses);
        switch (kind) {
            .native => {
                const input = Upper.Leaf{ .main_root = @splat(0), .physical_claims = claims, .local_metadata = locals, .global_roots = data.memory_roots, .cohort_policy = data.cohort_policy, .selected_addresses = addresses };
                const public = try Thin.encodeNativeLeafWithLimits(owned, input, .{});
                return .{ .arena = arena, .metadata = .{ .native = .{ .external = external, .input = input } }, .public_bytes = public };
            },
            .mixed => {
                const input = MixedReceiver.Input{ .root = &.{}, .physical_claims = claims, .mixed_metadata = locals[0], .global_roots = data.memory_roots, .cohort_policy = data.cohort_policy, .selected_addresses = addresses };
                const public = try Thin.encodeMixedLeafWithLimits(owned, .{ .main_root = @splat(0), .input = input }, .{});
                return .{ .arena = arena, .metadata = .{ .mixed = .{ .external = external, .input = input } }, .public_bytes = public };
            },
        }
    }
};
fn hashMatches(text: []const u8, expected: [32]u8) bool {
    if (text.len != 64) return false;
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, text) catch return false;
    return std.meta.eql(value, expected);
}
fn cloneClaims(comptime T: type, scratch: std.mem.Allocator, owned: std.mem.Allocator, value: T) !T {
    var writer = Writer.init(scratch, 8 << 20);
    defer writer.deinit();
    var remaining: usize = 1 << 20;
    try ClaimsWire.encode(T, &writer, value, &remaining);
    var cursor = Cursor{ .bytes = writer.bytes.items };
    remaining = 1 << 20;
    const cloned = try ClaimsWire.decode(T, owned, &cursor, &remaining);
    if (cursor.position != writer.bytes.items.len) return error.NonCanonicalOriginalClaims;
    return cloned;
}
