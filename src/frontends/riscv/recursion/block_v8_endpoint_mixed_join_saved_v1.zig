//! One parent over the THREE saved originals, with no intermediate recursive
//! proofs. Loading/capture is witness preparation; receiving rebuilds all keys.
const std = @import("std");
const core = @import("stwo_core");
const Mixed = @import("block_v8_endpoint_mixed_recursive_v1.zig");
const Bridge = @import("block_v8_endpoint_bridge_recursive_v1.zig");
const Global = @import("block_v8_compact_ram_recursive_v1.zig");
const Directory = @import("../prover/block_v8_endpoint_local_directory_v1.zig");
const Metadata = @import("../prover/block_v8_endpoint_mixed_statement_wire_v1.zig");
const Codec = @import("../prover/block_v8_endpoint_mixed_codec_v1.zig");
const Transport = @import("../prover/block_v8_endpoint_local_transport_v1.zig");
const Window = @import("../prover/block_v7_real_window_policy_v2.zig");
const Scope = @import("../prover/block_v8_endpoint_mixed_scope_v1.zig");
const BridgeScope = @import("../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Source = @import("block_v8_endpoint_join_source_v1.zig");
const Pipeline = @import("block_v8_endpoint_join_pipeline_v1.zig");
const Receiver = @import("block_v8_endpoint_mixed_join_receiver_v1.zig");
pub const External = Receiver.External;
pub const Stats = struct {
    source_loading_ns: u64 = 0,
    late_source_preparation_ns: u64 = 0,
    profile_ns: u64 = 0,
    original_verification_ns: u64 = 0,
    claims_encoding_ns: u64 = 0,
    whole_ns: u64 = 0,
};
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    root: Pipeline.Artifact,
    metadata: []const u8,
    claims: []const u8,
    data: Directory.Data(true),
    stats: Stats,
    whole_ns: u64,
    pub fn deinit(self: *@This()) void {
        self.root.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn verify(self: *const @This(), a: std.mem.Allocator, external: External) !Receiver.Verified {
        return Receiver.verify(a, external, .{ .global_g_repartition = self.root.stats.global_g_repartition, .root = self.root.bytes, .physical_claims = self.claims, .mixed_metadata = self.metadata, .global_roots = self.data.memory_roots, .cohort_policy = self.data.cohort_policy, .selected_addresses = self.data.selected_initial_addresses });
    }
};
pub fn produce(a: std.mem.Allocator, directory: std.fs.Dir, external: External, options: Pipeline.Options) !Owned {
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var stats: Stats = .{};
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const t = arena.allocator();
    const public_bytes = try directory.readFileAlloc(t, "global-public.json", 16 << 20);
    const data = try std.json.parseFromSliceLeaky(Directory.Data(true), t, public_bytes, .{ .allocate = .alloc_always, .max_value_len = 16 << 20 });
    if (!std.mem.eql(u8, data.schema, "stwo-b8-local-compact-global-memory-metadata-v1") or data.cohort_count != 1 or data.bridge_batches != 1 or data.cohort_policy.cohort_count != 1 or !std.meta.eql(data.config, external.config) or !std.meta.eql(data.window, external.trusted.window) or !std.mem.eql(u8, data.elf_sha256, &std.fmt.bytesToHex(external.trusted.elf_sha256, .lower)) or !std.mem.eql(u8, data.incoming_sha256, &std.fmt.bytesToHex(external.trusted.incoming_sha256, .lower)) or !std.mem.eql(u8, data.outgoing_sha256, &std.fmt.bytesToHex(external.trusted.outgoing_sha256, .lower))) return error.UntrustedMixedJoinDirectory;
    const metadata = try directory.readFileAlloc(t, "local-0.json", 128 << 20);
    const trusted = Scope.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = data.cohort_policy.cohort_count, .terminal_cycle = if (external.boundary.terminal != null) external.trusted.window.cycles else null, .boundary_policy_id = if (external.boundary.terminal) |last| last.policy_id else @splat(0) };
    const statement = try Metadata.decode(a, metadata, trusted, .{});
    defer statement.deinit();
    const original_bytes = try directory.readFileAlloc(t, "local-0.proof", 128 << 20);
    var decoded = try Codec.decode(a, original_bytes, trusted, statement.input, .{});
    defer decoded.deinit();
    stats.source_loading_ns = phase.lap();
    const mixed = try Mixed.Profile.Owned.derive(a, statement, decoded.claims, .{});
    defer mixed.deinit();
    stats.profile_ns = phase.lap();
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, external.elf, external.incoming, external.outgoing, external.trusted, data.cohort_policy, data.selected_initial_addresses, external.boundary, .{});
    defer window.deinit();
    const source = mixed.scope.source();
    if (source.endpoint_count != (data.endpoint_events orelse return error.UntrustedMixedJoinDirectory)) return error.UntrustedMixedJoinDirectory;
    const pins = try t.alloc(BridgeScope.Source, 1);
    for (pins) |*pin| pin.* = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
    const policy = Global.Original.Policy{ .window = &window, .config = external.config, .event_count = source.endpoint_count };
    const bridge_statement = try Bridge.Statement.Owned.init(a, .{ .config = external.config, .block_statement = try policy.digest() }, .{ .sources = pins, .global_memory = try policy.entry(data.memory_roots), .batch_first = 0, .batch_count = data.cohort_policy.cohort_count });
    defer bridge_statement.deinit();
    const global_statement = try Global.Statement.Owned.init(a, .{ .config = external.config, .policy = policy }, .{ .epoch = bridge_statement.scope.epoch, .entries = bridge_statement.scope.entries, .roots = data.memory_roots });
    defer global_statement.deinit();
    if (!std.meta.eql(data.global_epoch, bridge_statement.scope.epoch.digest)) return error.UntrustedMixedJoinDirectory;
    const bridge_bytes = try directory.readFileAlloc(t, "bridge-0.proof", 128 << 20);
    var bridge_log: u32 = 4;
    {
        if (source.endpoint_count == 0) return error.UntrustedMixedJoinDirectory;
        bridge_log = @max(bridge_log, std.math.log2_int_ceil(u32, source.endpoint_count));
    }
    var bridge_decoded = try Transport.bridge(a, bridge_bytes, data.cohort_policy.cohort_count, bridge_log, external.config, .{});
    defer bridge_decoded.deinit();
    const global_bytes = try directory.readFileAlloc(t, "global-memory.proof", 128 << 20);
    var global_decoded = try Transport.compact(a, global_bytes, source.endpoint_count, policy.boundaryLog(), external.config, .{});
    defer global_decoded.deinit();
    const global_proof = Global.Original.Proof{ .a = global_decoded.arena.allocator(), .budget = global_decoded.budget, .event_count = source.endpoint_count, .roots = data.memory_roots, .claims = global_decoded.claims, .stark = global_decoded.stark };
    stats.late_source_preparation_ns = phase.lap();
    const bridge = try Bridge.Profile.Owned.derive(a, bridge_statement, bridge_decoded.claims, .{});
    defer bridge.deinit();
    const global = try Global.Profile.Owned.derive(a, global_statement, global_decoded.claims, .{});
    defer global.deinit();
    stats.profile_ns += phase.lap();
    var mixed_capture = try Mixed.Original.verifyAndCapture(a, trusted, statement.input, &decoded.stark, decoded.claims, .{});
    defer mixed_capture.deinit();
    var bridge_capture = try Bridge.Original.verifyConditionalAndCapture(a, bridge_statement.scope, &bridge_decoded.stark, bridge_decoded.claims, .{});
    defer bridge_capture.deinit();
    var global_capture = try Global.Original.verifyAndCaptureConditional(a, policy, bridge_statement.scope.epoch, bridge_statement.scope.entries, &global_proof, .{});
    defer global_capture.deinit();
    stats.original_verification_ns = phase.lap();
    const sources = [_]Source.Source{ .{ .mixed = mixed }, .{ .bridge = bridge }, .{ .global = global } };
    const captures = [_]Source.Capture{ .{ .mixed = &mixed_capture }, .{ .bridge = &bridge_capture }, .{ .global = &global_capture } };
    const claims = Receiver.Claims{ .mixed = decoded.claims, .bridge = bridge_decoded.claims, .global = global_decoded.claims };
    var writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(t, 16 << 20);
    var remaining: usize = 1 << 20;
    try @import("../prover/block_v7_union_claim_wire_v1.zig").encode(Receiver.Claims, &writer, claims, &remaining);
    const extra = @import("block_v8_endpoint_join_many_receiver_v1.zig").boundaryBytes(&window);
    stats.claims_encoding_ns = phase.lap();
    stats.whole_ns = whole.read();
    const root = try Pipeline.produceWithOptions(a, &sources, &captures, &extra, .csp_q70_pow26, options);
    return .{ .arena = arena, .root = root, .metadata = metadata, .claims = writer.bytes.items, .data = data, .stats = stats, .whole_ns = whole.read() };
}
