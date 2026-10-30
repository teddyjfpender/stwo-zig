//! Genuine adjacent windows, each with native+ROM+lookup+endpoint+global RAM
//! originals, then their exact independently admitted closed Join roots.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Run = @import("../../prover/block_v8_endpoint_local_compact_execution_v1.zig");
const Local = @import("../block_v8_endpoint_recursive_adapter_v1.zig").For(.local_open);
const Bridge = @import("../block_v8_endpoint_bridge_recursive_v1.zig");
const Global = @import("../block_v8_compact_ram_recursive_v1.zig");
const Source = @import("../block_v8_endpoint_join_source_v1.zig");
const Profile = @import("../block_v8_window_root_profile_v1.zig");
const code = [_]u32{ 0x001000b7, 0x20008093, 0x0000a103, 0x00110113, 0x0020a023, 0xff5ff06f };
const elf = blk: {
    var bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, value| std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
pub const Child = struct {
    allocator: std.mem.Allocator,
    private_live: bool = true,
    metadata_arena: *std.heap.ArenaAllocator,
    metadata: @import("../block_v8_window_root_receiver_v1.zig").Tree,
    profile: *Profile.Owned,
    proof_bytes: []u8,
    verified: @import("../blake3_native_parent_verifier.zig").Verified,
    pub fn discardPrivate(v: *Child) void {
        if (!v.private_live) return;
        v.verified.deinit();
        v.profile.deinit();
        v.allocator.free(v.proof_bytes);
        v.private_live = false;
    }
    pub fn deinit(v: *Child) void {
        v.discardPrivate();
        v.metadata_arena.deinit();
        v.allocator.destroy(v.metadata_arena);
    }
};
pub fn produce(a: std.mem.Allocator, budget: *Engine.host_budget_allocator.SharedHostBudget, pool: *Engine.work_pool.WorkPool, skip: u64) !Child {
    const config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const pin = Capture.Pins{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    const span = Capture.Window{ .skip_cycles = skip, .cycles = 4 };
    var captured = try Capture.capture(a, &elf, &.{}, pin, span, .{});
    defer captured.deinit();
    var output = std.testing.tmpDir(.{ .iterate = true });
    defer output.cleanup();
    const result = try Run.run(budget, pool, output.dir, .{ .elf = &elf, .elf_sha256 = pin.elf, .config = config, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted_window = .{ .elf_sha256 = pin.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span } }, .{ .cohort_cycles = 4, .proof_workers = 4, .program_flavor = .sparse_elf });
    defer result.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(pool);
    defer binding.deinit();
    const metadata_bytes = try output.dir.readFileAlloc(a, "local-0.json", 16 << 20);
    defer a.free(metadata_bytes);
    const proof_bytes = try output.dir.readFileAlloc(a, "local-0.proof", 128 << 20);
    defer a.free(proof_bytes);
    const trusted = @import("../../prover/block_v8_endpoint_local_scope_v1.zig").Trusted{ .elf = &elf, .elf_sha256 = pin.elf, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
    const metadata = try @import("../../prover/block_v8_endpoint_local_statement_wire_v1.zig").decode(a, metadata_bytes, trusted, .{});
    defer metadata.deinit();
    const Codec = @import("../../prover/block_v8_endpoint_local_codec_v1.zig");
    var decoded = try Codec.decode(a, proof_bytes, trusted, metadata.input, .{});
    defer decoded.deinit();
    var local_capture = try Local.Original.verifyAndCapture(a, trusted, metadata.input, &decoded.stark, decoded.claims, .{});
    defer local_capture.deinit();
    var window = try @import("../../prover/block_v7_real_window_policy_v2.zig").Owned.deriveCohortsForAddresses(a, &elf, captured.incoming, captured.outgoing, .{ .elf_sha256 = pin.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span }, result.cohort_policy, result.selected_initial_addresses, .{});
    defer window.deinit();
    const policy = Global.Original.Policy{ .window = &window, .config = config, .event_count = @intCast(result.verified.endpoint_events) };
    const local_scope = try @import("../../prover/block_v8_endpoint_local_scope_v1.zig").Owned.init(a, trusted, metadata.input, .{});
    defer local_scope.deinit();
    const src = local_scope.source();
    const pins = [_]@import("../../prover/block_v8_endpoint_global_bridge_scope_v1.zig").Source{.{ .local_identity = src.local_identity, .local_epoch = src.local_epoch, .endpoint_root = src.endpoint_root, .endpoint_count = src.endpoint_count, .policy = src.policy }};
    const bridge = try Bridge.Statement.Owned.init(a, .{ .config = config, .block_statement = try policy.digest() }, .{ .sources = &pins, .global_memory = try policy.entry(result.global_memory.roots), .batch_first = 0, .batch_count = 1 });
    defer bridge.deinit();
    var bridge_capture = try Bridge.Original.verifyConditionalAndCapture(a, bridge.scope, &result.bridges[0].stark, result.bridges[0].claims, .{});
    defer bridge_capture.deinit();
    const global = try Global.Statement.Owned.init(a, .{ .config = config, .policy = policy }, .{ .epoch = bridge.scope.epoch, .entries = bridge.scope.entries, .roots = result.global_memory.roots });
    defer global.deinit();
    var global_capture = try Global.Original.verifyAndCaptureConditional(a, policy, bridge.scope.epoch, bridge.scope.entries, &result.global_memory, .{});
    defer global_capture.deinit();
    const admissions = [_]Source.Admission{ .{ .local = .{ .statement = metadata, .claims = decoded.claims } }, .{ .bridge = .{ .statement = bridge, .claims = result.bridges[0].claims } }, .{ .global = .{ .statement = global, .claims = result.global_memory.claims } } };
    var sources: [3]Source.Source = undefined;
    var count: usize = 0;
    defer for (sources[0..count]) |s| Source.deinitProfile(s);
    for (admissions, 0..) |admission, i| {
        sources[i] = try admission.derive(a);
        count += 1;
    }
    const extra = @import("../block_v8_endpoint_join_many_receiver_v1.zig").boundaryBytes(&window);
    const Pipeline = @import("../block_v8_endpoint_join_pipeline_v1.zig");
    var root = try Pipeline.produceWithOptions(a, &sources, &.{ .{ .local = &local_capture }, .{ .bridge = &bridge_capture }, .{ .global = &global_capture } }, &extra, .csp_q70_pow26, .{ .global_g_repartition = true });
    defer root.deinit();
    var verified = try Pipeline.verifyAdmittedWithOptions(a, root.bytes, &admissions, &extra, .csp_q70_pow26, .{ .global_g_repartition = true });
    errdefer verified.deinit();
    const profile = try Profile.Owned.deriveJoin(a, &admissions, &extra, verified.capture.commitments[1], .{ .global_g_repartition = true });
    errdefer profile.deinit();
    const Receiver = @import("../block_v8_window_root_receiver_v1.zig");
    const metadata_arena = try a.create(std.heap.ArenaAllocator);
    errdefer a.destroy(metadata_arena);
    metadata_arena.* = std.heap.ArenaAllocator.init(a);
    errdefer metadata_arena.deinit();
    const public = metadata_arena.allocator();
    var writer = @import("../../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
    defer writer.deinit();
    var remaining: usize = 1 << 20;
    var local_claims = [_]Local.Ledger.Claims{decoded.claims};
    try @import("../../prover/block_v7_union_claim_wire_v1.zig").encode(Receiver.Claims, &writer, .{ .locals = &local_claims, .bridge = result.bridges[0].claims, .global = result.global_memory.claims }, &remaining);
    const metadatas = try public.alloc([]const u8, 1);
    metadatas[0] = try public.dupe(u8, metadata_bytes);
    var incoming = captured.incoming;
    incoming.words = try public.dupe(@TypeOf(incoming.words[0]), incoming.words);
    var outgoing = captured.outgoing;
    outgoing.words = try public.dupe(@TypeOf(outgoing.words[0]), outgoing.words);
    const tree = Receiver.Tree{ .leaf = .{ .external = .{ .elf = &elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = pin.elf, .incoming_sha256 = incoming.identity(), .outgoing_sha256 = outgoing.identity(), .window = span }, .config = config }, .input = .{ .main_root = verified.capture.commitments[1], .global_roots = result.global_memory.roots, .cohort_policy = result.cohort_policy, .physical_claims = try public.dupe(u8, writer.bytes.items), .local_metadata = metadatas, .selected_addresses = try public.dupe(u32, result.selected_initial_addresses), .global_g_repartition = true } } };
    return .{ .allocator = a, .metadata_arena = metadata_arena, .metadata = tree, .profile = profile, .proof_bytes = try a.dupe(u8, root.bytes), .verified = verified };
}
