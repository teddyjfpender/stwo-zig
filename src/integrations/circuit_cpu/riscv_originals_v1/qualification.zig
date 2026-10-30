//! Saved original byte qualification. This never produces/verifies a native
//! AIR receipt or an intermediate NativeParent proof.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const b = @import("stwo_circuit_frontend").builder;
const Verifier = @import("verifier.zig");
const Material = @import("material.zig");
const Sources = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_source_v1.zig");
const Q = core.fields.qm31.QM31;

test "RISC direct originals saved admission and original material q70" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_MATERIAL_Q70")) return error.SkipZigTest;
    try qualify(false, false);
}
test "RISC direct originals saved complete circuit q70 QM31 and NoValue" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_CIRCUIT_Q70")) return error.SkipZigTest;
    try qualify(true, false);
}
test "RISC direct originals combined window q70" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_JOIN_Q70")) return error.SkipZigTest;
    try qualify(false, true);
}
fn qualify(comptime render_circuits: bool, comptime joined: bool) !void {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const path = std.posix.getenv("STWO_RISCV_ORIGINALS_DIRECTORY") orelse "vectors/reports/riscv-cpu-architecture-20261029/mixed-durable-compact-bundle-q70/sha_keccak";
    var directory = try std.fs.cwd().openDir(path, .{});
    defer directory.close();
    const Capture = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
    const Directory = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_directory_v1.zig");
    const Scope = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_scope_v1.zig");
    const Bridge = Sources.Adapter(.bridge);
    const Global = Sources.Adapter(.global);
    const Transport = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_transport_v1.zig");
    const data_bytes = try directory.readFileAlloc(a, "global-public.json", 16 << 20);
    defer a.free(data_bytes);
    const data = try std.json.parseFromSlice(Directory.Data(true), a, data_bytes, .{ .ignore_unknown_fields = true });
    defer data.deinit();
    const elf = try directory.readFileAlloc(a, "guest.elf", 32 << 20);
    defer a.free(elf);
    const elf_pin = try hexDigest("d079709f439e8b303eebc08766e858495e0288d8a6c12c06bc5fbfae67cb7aa4");
    const incoming_pin = try hexDigest("f33cbcd3ad14cff75b236addc55e2b2f8ab356c2048726979649a429666f0a73");
    const outgoing_pin = try hexDigest("c3849abe8c8dd7cdd49d5e8cf75c55932e327c7e491b03da061e808a7ffe0322");
    if (!std.meta.eql(Capture.sha(elf), elf_pin)) return error.UntrustedQualificationElf;
    const incoming_bytes = try directory.readFileAlloc(a, "incoming.b7win", 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try directory.readFileAlloc(a, "outgoing.b7win", 256 << 20);
    defer a.free(outgoing_bytes);
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const trusted = @import("../../../frontends/riscv/prover/block_v7_real_window_policy_v2.zig").Trusted{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = .{ .skip_cycles = 0, .cycles = 6 } };
    if (!std.meta.eql(data.value.config, config) or data.value.cohort_count != 1 or data.value.cohort_policy.cohort_count != 1 or data.value.window.skip_cycles != 0 or data.value.window.cycles != 6) return error.UntrustedQualificationGeometry;
    var window = try @import("../../../frontends/riscv/prover/block_v7_real_window_policy_v2.zig").Owned.deriveCohortsForAddressesWithBoundary(a, elf, incoming, outgoing, trusted, data.value.cohort_policy, data.value.selected_initial_addresses, .{}, .{});
    defer window.deinit();
    const mixed_bytes = try directory.readFileAlloc(a, "local-0.json", 16 << 20);
    defer a.free(mixed_bytes);
    const mixed = try @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_statement_wire_v1.zig").decode(a, mixed_bytes, .{ .elf = elf, .elf_sha256 = elf_pin, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 }, .{});
    defer mixed.deinit();
    const local_raw = try directory.readFileAlloc(a, "local-0.proof", 128 << 20);
    defer a.free(local_raw);
    var local_decoded = try @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_codec_v1.zig").decode(a, local_raw, mixed.trusted, mixed.input, .{});
    defer local_decoded.deinit();
    const scope = try Scope.Owned.init(a, mixed.trusted, mixed.input, .{});
    defer scope.deinit();
    const source = scope.source();
    const pins = [_]@import("../../../frontends/riscv/prover/block_v8_endpoint_global_bridge_scope_v1.zig").Source{.{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy }};
    const policy = Global.Original.Policy{ .window = &window, .config = config, .event_count = source.endpoint_count };
    const bridge = try Bridge.Statement.Owned.init(a, .{ .config = config, .block_statement = try policy.digest() }, .{ .sources = &pins, .global_memory = try policy.entry(data.value.memory_roots), .batch_first = 0, .batch_count = 1 });
    defer bridge.deinit();
    const global = try Global.Statement.Owned.init(a, .{ .config = config, .policy = policy }, .{ .epoch = bridge.scope.epoch, .entries = bridge.scope.entries, .roots = data.value.memory_roots });
    defer global.deinit();
    const bridge_raw = try directory.readFileAlloc(a, "bridge-0.proof", 128 << 20);
    defer a.free(bridge_raw);
    var bridge_decoded = try Transport.bridge(a, bridge_raw, 1, try pins[0].log(), config, .{});
    defer bridge_decoded.deinit();
    const global_raw = try directory.readFileAlloc(a, "global-memory.proof", 128 << 20);
    defer a.free(global_raw);
    var global_decoded = try Transport.compact(a, global_raw, source.endpoint_count, policy.boundaryLog(), config, .{});
    defer global_decoded.deinit();
    const admissions = [_]Sources.Admission{ .{ .mixed = .{ .statement = mixed, .claims = local_decoded.claims } }, .{ .bridge = .{ .statement = bridge, .claims = bridge_decoded.claims } }, .{ .global = .{ .statement = global, .claims = global_decoded.claims } } };
    if (joined) {
        const Receiver = @import("../../../frontends/riscv/recursion/block_v8_endpoint_mixed_join_receiver_v1.zig");
        var writer = @import("../../../frontends/riscv/prover/bounded_artifact_writer_v1.zig").Writer.init(a, 16 << 20);
        defer writer.deinit();
        var remaining: usize = 1 << 20;
        try @import("../../../frontends/riscv/prover/block_v7_union_claim_wire_v1.zig").encode(Receiver.Claims, &writer, .{ .mixed = local_decoded.claims, .bridge = bridge_decoded.claims, .global = global_decoded.claims }, &remaining);
        const metadata = @import("admission.zig").Metadata{ .mixed = .{
            .external = .{ .elf = elf, .config = config, .incoming = incoming, .outgoing = outgoing, .trusted = trusted },
            .input = .{ .root = &.{}, .physical_claims = writer.bytes.items, .mixed_metadata = mixed_bytes, .global_roots = data.value.memory_roots, .cohort_policy = data.value.cohort_policy, .selected_addresses = data.value.selected_initial_addresses },
        } };
        return qualifyJoined(budget, metadata, &.{ local_raw, bridge_raw, global_raw });
    }
    var failure: ?anyerror = null;
    for (admissions, [_][]const u8{ local_raw, bridge_raw, global_raw }) |admission, bytes| {
        qualifyOriginal(render_circuits, budget, admission, bytes) catch |err| {
            std.debug.print("RISC_ORIGINAL_FAILED family={s} error={s}\n", .{ @tagName(std.meta.activeTag(admission)), @errorName(err) });
            if (failure == null) failure = err;
        };
    }
    if (failure) |err| return err;
}
fn qualifyOriginal(comptime render_circuits: bool, budget: *Engine.host_budget_allocator.SharedHostBudget, admission: Sources.Admission, bytes: []const u8) !void {
    const a = budget.allocator();
    const original = try admission.derive(a);
    defer Sources.deinitProfile(original);
    var authority = try Verifier.Authority.init(a, original);
    defer authority.deinit();
    var material = try Material.Owned.fromBytes(a, &authority, bytes, .{});
    defer material.deinit();
    if (render_circuits) {
        try render(Q, a, &authority, &material);
        var shape_arena = std.heap.ArenaAllocator.init(a);
        defer shape_arena.deinit();
        const dummy = try Material.Owned.zeroForTopologyLeaky(shape_arena.allocator(), authority.geometry);
        try render(b.NoValue, a, &authority, &dummy);
    }
    std.debug.print("RISC_ORIGINAL_QUALIFIED family={s} trees={d} samples={d} q=70 pow=26 circuits={any} nonterminal_cycles=6 native_air_receipts=0 native_parent_proofs=0 peak_bytes={d}\n", .{ @tagName(std.meta.activeTag(original)), authority.geometry.trees.len, authority.geometry.sampleCount(), render_circuits, budget.snapshot().peak_live_bytes });
}

fn hexDigest(text: []const u8) ![32]u8 {
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, text);
    return result;
}

fn render(comptime V: type, a: std.mem.Allocator, authority: *const Verifier.Authority, material: *const Material.Owned) !void {
    var ctx = try b.Context(V).init(a, 1);
    defer ctx.deinit();
    std.debug.print("RISC_ORIGINAL_CONTEXT_START family={s} value_mode={any} typed_nodes={d}\n", .{ @tagName(std.meta.activeTag(authority.source)), V == Q, authority.circuit.nodes.len });
    const result = try Verifier.build(V, &ctx, authority, material);
    // An actual statement port, also constrained through admission and original
    // transcript, anchors this standalone source qualification output.
    try ctx.setOutputs(&.{result.words[0].get()});
    try @import("../riscv_recursion/registry_v1.zig").finalizeStrict(V, &ctx);
    const common = @import("stwo_circuit_frontend").common;
    const pre_padding_vars = ctx.circuit.n_vars;
    const raw_sizes = common.finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
    const padding_targets = common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
    try common.finalize.padToTargets(V, &ctx, padding_targets);
    {
        var preprocessed = try common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
        defer preprocessed.deinit(a);
    }
    if (V == Q) {
        try std.testing.expect(try ctx.isCircuitValid());
        const targets = [_]b.Var{ result.roots[result.roots.len - 1][0].get(), result.sampled_values[0], result.felts[0] };
        for (targets) |wire| {
            const old = ctx.value_table.items[wire.idx];
            ctx.value_table.items[wire.idx] = old.add(Q.one());
            try std.testing.expect(!try ctx.isCircuitValid());
            ctx.value_table.items[wire.idx] = old;
        }
        try std.testing.expect(try ctx.isCircuitValid());
    }
    std.debug.print("RISC_ORIGINAL_GEOMETRY family={s} value_mode={any} pre_padding_vars={d} padded_vars={d} raw_eq={d} raw_qm31_ops={d} raw_triple_xor={d} raw_m31_to_u32={d} raw_blake_g_gate={d} padded_eq={d} padded_qm31_ops={d} padded_triple_xor={d} padded_m31_to_u32={d} padded_blake_g_gate={d}\n", .{ @tagName(std.meta.activeTag(authority.source)), V == Q, pre_padding_vars, ctx.circuit.n_vars, raw_sizes.eq, raw_sizes.qm31_ops, raw_sizes.triple_xor, raw_sizes.m31_to_u32, raw_sizes.blake_g_gate, padding_targets.eq, padding_targets.qm31_ops, padding_targets.triple_xor, padding_targets.m31_to_u32, padding_targets.blake_g_gate });
    std.debug.print("RISC_ORIGINAL_CONTEXT family={s} value_mode={any} variables={d} typed_nodes={d} strict_finalize=true\n", .{ @tagName(std.meta.activeTag(authority.source)), V == Q, ctx.circuit.n_vars, authority.circuit.nodes.len });
}

fn qualifyJoined(budget: *Engine.host_budget_allocator.SharedHostBudget, metadata: @import("admission.zig").Metadata, originals: []const []const u8) !void {
    const Join = @import("window_join.zig");
    const a = budget.allocator();
    {
        var authority = try Join.Authority.derive(a, metadata);
        defer authority.deinit();
        const materials = try a.alloc(Material.Owned, originals.len);
        defer a.free(materials);
        var initialized: usize = 0;
        defer for (materials[0..initialized]) |*material| material.deinit();
        for (materials, authority.sources, originals) |*material, *source, raw| {
            material.* = try Material.Owned.fromBytes(a, source, raw, .{});
            initialized += 1;
        }
        try renderJoined(Q, a, &authority, materials);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const dummy = try arena.allocator().alloc(Material.Owned, materials.len);
        for (dummy, authority.sources) |*material, *source| material.* = try Material.Owned.zeroForTopologyLeaky(arena.allocator(), source.geometry);
        try renderJoined(b.NoValue, a, &authority, dummy);
    }
    if (std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_JOIN_PROVE_Q70")) {
        const Registry = @import("../riscv_recursion/registry_v1.zig");
        const Window = @import("window_registry.zig");
        const air = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 1 << 20);
        defer a.free(air);
        const projection = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/compiled_air_constraints_v1.bin", 1 << 20);
        defer a.free(projection);
        const backend = try Registry.BackendAuthority.load(a, air, projection);
        defer backend.deinit();
        var artifact = try Window.produce(a, metadata, originals, backend, .{});
        defer artifact.deinit();
        const output_path = std.posix.getenv("STWO_RISCV_ORIGINALS_JOIN_OUTPUT") orelse "campaign/qualification/new-direct-original-window-q70-v1";
        try std.fs.cwd().makePath(output_path);
        var output = try std.fs.cwd().openDir(output_path, .{});
        defer output.close();
        // Durable bytes survive even if a later hostile control fails.
        try output.writeFile(.{ .sub_path = "root.proof", .data = artifact.bytes });
        const times = try std.json.Stringify.valueAlloc(a, artifact.times, .{ .whitespace = .indent_2 });
        defer a.free(times);
        try output.writeFile(.{ .sub_path = "producer-times.json", .data = times });
        var fresh = try std.time.Timer.start();
        try Window.verifyBytes(a, metadata, artifact.bytes, backend, .{});
        const verify_ns = fresh.read();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(artifact.bytes, &digest, .{});
        const report = try std.json.Stringify.valueAlloc(a, .{
            .schema = "stwo-riscv-direct-original-window-q70-v1",
            .scope = "nonterminal six-cycle sha-keccak fixture",
            .q = 70,
            .pow_bits = 26,
            .native_parent_proofs = 0,
            .source_count = originals.len,
            .root_bytes = artifact.bytes.len,
            .root_sha256 = std.fmt.bytesToHex(digest, .lower),
            .fresh_verify_ns = verify_ns,
            .producer_times = artifact.times,
            .charged_peak_bytes = budget.snapshot().peak_live_bytes,
            .fresh_independent_receiving = true,
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try output.writeFile(.{ .sub_path = "report.json", .data = report });
        std.debug.print("RISC_ORIGINAL_JOIN_PROVED bytes={d} fresh_verify_ns={d} native_parent_proofs=0 peak_bytes={d}\n", .{ artifact.bytes.len, verify_ns, budget.snapshot().peak_live_bytes });
    }
}
fn renderJoined(comptime V: type, a: std.mem.Allocator, authority: *const @import("window_join.zig").Authority, materials: []const Material.Owned) !void {
    const Join = @import("window_join.zig");
    const common = @import("stwo_circuit_frontend").common;
    var ctx = try b.Context(V).init(a, Join.OUTPUTS);
    defer ctx.deinit();
    const result = try Join.build(V, &ctx, authority, materials);
    try @import("../riscv_recursion/registry_v1.zig").finalizeStrict(V, &ctx);
    const raw = common.finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
    const target = common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
    try common.finalize.padToTargets(V, &ctx, target);
    var pp = try common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    if (V == Q) {
        try std.testing.expect(try ctx.isCircuitValid());
        const outputs = [_]b.Var{ result.sources[0].roots[0][0].get(), result.sources[0].sampled_values[0], result.statement.words[32].get() };
        for (outputs) |wire| {
            const old = ctx.value_table.items[wire.idx];
            ctx.value_table.items[wire.idx] = old.add(Q.one());
            try std.testing.expect(!try ctx.isCircuitValid());
            ctx.value_table.items[wire.idx] = old;
        }
        try std.testing.expect(try ctx.isCircuitValid());
    }
    std.debug.print("RISC_ORIGINAL_JOIN_GEOMETRY value_mode={any} padded_vars={d} raw_eq={d} raw_qm31_ops={d} raw_triple_xor={d} raw_m31_to_u32={d} raw_blake_g_gate={d} padded_eq={d} padded_qm31_ops={d} padded_triple_xor={d} padded_m31_to_u32={d} padded_blake_g_gate={d}\n", .{ V == Q, ctx.circuit.n_vars, raw.eq, raw.qm31_ops, raw.triple_xor, raw.m31_to_u32, raw.blake_g_gate, target.eq, target.qm31_ops, target.triple_xor, target.m31_to_u32, target.blake_g_gate });
}
