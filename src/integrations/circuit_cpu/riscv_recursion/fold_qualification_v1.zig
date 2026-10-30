//! Dormant homogeneous RISC circuit-fold gates. Nothing in this file has been
//! compiled, proved or measured during the live full-block run.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const b = @import("stwo_circuit_frontend").builder;
const Fold = @import("circuit_fold_v1.zig");
const FoldWire = @import("fold_wire_v1.zig");
const Typed = @import("fold_statement_v1.zig");
const Registry = @import("registry_v1.zig");
const Capture = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
const Wire = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Q = core.fields.qm31.QM31;

test "RISC fold metadata cycles rejected before key rendering or allocation" {
    var cycle: [2]Fold.Metadata = undefined;
    cycle = .{ .{ .pair = &cycle }, .{ .pair = &cycle } };
    try std.testing.expectError(error.RiscCircuitFoldResourceLimit, Fold.validateMetadata(.{ .pair = &cycle }));
}
test "RISC thin fold catalog rejects reused dropped reordered and unknown nodes" {
    const good = [_]FoldWire.Record{ .{ .kind = 1, .a = 0 }, .{ .kind = 1, .a = 1 }, .{ .kind = 1, .a = 2 }, .{ .kind = 2, .a = 0, .b = 1 }, .{ .kind = 2, .a = 3, .b = 2 } };
    try FoldWire.validate(.{ .records = &good, .root = 4, .sources = 3 }, 3);
    var reused = good;
    reused[4].b = 1;
    try std.testing.expectError(error.InvalidRiscCircuitFoldCatalog, FoldWire.validate(.{ .records = &reused, .root = 4, .sources = 3 }, 3));
    var duplicate = good;
    duplicate[2].a = 0;
    try std.testing.expectError(error.InvalidRiscCircuitFoldCatalog, FoldWire.validate(.{ .records = &duplicate, .root = 4, .sources = 3 }, 3));
    var cyclic = good;
    cyclic[3].a = 4;
    try std.testing.expectError(error.InvalidRiscCircuitFoldCatalog, FoldWire.validate(.{ .records = &cyclic, .root = 4, .sources = 3 }, 3));
}
test "RISC fold circuit gates enforce gap overlap CPU snapshot and interior policy" {
    inline for (.{ "gap", "overlap", "cpu", "snapshot", "terminal", "initial" }) |fault| {
        var left = span(1, 4);
        var right = span(5, 2);
        if (comptime std.mem.eql(u8, fault, "gap")) right.first_cycle = 6;
        if (comptime std.mem.eql(u8, fault, "overlap")) right.first_cycle = 4;
        if (comptime std.mem.eql(u8, fault, "cpu")) right.initial_cpu[2] = 9;
        if (comptime std.mem.eql(u8, fault, "snapshot")) right.incoming_snapshot_id[0] = 3;
        if (comptime std.mem.eql(u8, fault, "terminal")) left.terminal_policy_id = @splat(9);
        if (comptime std.mem.eql(u8, fault, "initial")) right.initial_policy_id = @splat(8);
        const parent = certificate(span(1, 6));
        var ctx = try b.Context(Q).init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = true;
        const l = try certificate(left).allocate(Q, &ctx);
        const r = try certificate(right).allocate(Q, &ctx);
        const p = try parent.allocate(Q, &ctx);
        // This is the same emitted gate law invoked by actual Fold.build;
        // host Span.merge rejection is deliberately bypassed for this test.
        try std.testing.expectError(error.EqFailedOnEval, Typed.constrainMerge(Q, &ctx, l, r, p));
    }
}
test "RISC fold role and exact security operands reject unclosed child" {
    var invalid = certificate(span(1, 6)).fold;
    invalid.children[0].role = 0; // no OPEN/PCS-only/receipt role is accepted.
    try std.testing.expectError(error.InvalidRiscFoldChildRole, invalid.validate());
    var ctx = try b.Context(Q).init(std.testing.allocator, 0);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = true;
    const source = try certificate(span(1, 4)).allocate(Q, &ctx);
    const words = try ctx.scratch().dupe(Typed.W, source.words);
    words[2] = try b.wrappers.constU32(Q, &ctx, 0);
    try std.testing.expectError(error.EqFailedOnEval, (Typed.View{ .words = words }).requireRole(Q, &ctx, Typed.ROLE_FOLD));
    words[2] = source.words[2];
    words[3] = try b.wrappers.constU32(Q, &ctx, 8);
    try std.testing.expectError(error.EqFailedOnEval, (Typed.View{ .words = words }).requireRole(Q, &ctx, Typed.ROLE_FOLD));
}

test "RISC homogeneous circuit fold actual three leaves odd carry depth two q70 fresh full receiver" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_CIRCUIT_FOLD_Q70")) return error.SkipZigTest;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    const elf = @import("qualification_v1.zig").tinyElf();
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const trusted = Full.Trusted{ .elf_sha256 = Capture.sha(&elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = output, .config = config };
    var boundary = try Full.Owned.derive(a, &elf, &.{}, trusted, .{});
    defer boundary.deinit();
    var captured: [3]Capture.Captured = undefined;
    var initialized: usize = 0;
    defer for (captured[0..initialized]) |*item| item.deinit();
    var leaves: [3]Fold.Metadata = undefined;
    var directory = try std.fs.cwd().openDir("campaign/qualification/new-full-block-depth2-driver-q70-v1", .{});
    defer directory.close();
    for (&captured, &leaves, [_]u64{ 0, 4, 6 }, [_]u32{ 4, 2, 1 }, 0..) |*item, *leaf, skip, cycles, i| {
        item.* = try Capture.capture(a, &elf, &.{}, .{ .elf = trusted.elf_sha256, .input = trusted.input_sha256 }, .{ .skip_cycles = skip, .cycles = cycles }, .{});
        initialized += 1;
        item.releaseExecution();
        var name: [64]u8 = undefined;
        const bytes = try directory.readFileAlloc(t, try std.fmt.bufPrint(&name, "node-{d}.public", .{i}), 128 << 20);
        leaf.* = .{ .leaf = .{ .leaf = .{ .input = try Wire.decodeNativeLeafLeaky(t, bytes, .{}), .external = .{ .elf = &elf, .config = config, .incoming = item.incoming, .outgoing = item.outgoing, .trusted = .{ .elf_sha256 = trusted.elf_sha256, .incoming_sha256 = item.incoming.identity(), .outgoing_sha256 = item.outgoing.identity(), .window = .{ .skip_cycles = skip, .cycles = cycles } }, .boundary = try boundary.windowOptions(skip, cycles) } } } };
    }
    const air = try std.fs.cwd().readFileAlloc(t, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 1 << 20);
    const projection = try std.fs.cwd().readFileAlloc(t, "vectors/circuit/official/compiled_air_constraints_v1.bin", 1 << 20);
    const first_pair = [_]Fold.Metadata{ leaves[0], leaves[1] };
    const first_metadata = Fold.Metadata{ .pair = &first_pair };
    const final_pair = [_]Fold.Metadata{ first_metadata, leaves[2] };
    const final_metadata = Fold.Metadata{ .pair = &final_pair };
    var root = block: {
        const backend = try Registry.BackendAuthority.load(a, air, projection);
        defer backend.deinit();
        var wrapped: [3]Registry.Artifact = undefined;
        var count: usize = 0;
        defer for (wrapped[0..count]) |*item| item.deinit();
        for (&wrapped, leaves, 0..) |*destination, leaf, i| {
            var name: [64]u8 = undefined;
            const native = try directory.readFileAlloc(a, try std.fmt.bufPrint(&name, "node-{d}.proof", .{i}), 64 << 20);
            defer a.free(native);
            destination.* = try Registry.produce(a, leaf.leaf, native, backend, .{});
            count += 1;
        }
        var first = try Fold.produce(a, first_metadata, .{ wrapped[0].bytes, wrapped[1].bytes }, backend, .{});
        defer first.deinit();
        const frontier = [_]Fold.Pending{ .{ .metadata = leaves[0], .bytes = wrapped[0].bytes }, .{ .metadata = leaves[1], .bytes = wrapped[1].bytes }, .{ .metadata = leaves[2], .bytes = wrapped[2].bytes } };
        const carried = (try Fold.oddCarry(&frontier)).?;
        try std.testing.expect(carried.bytes.ptr == wrapped[2].bytes.ptr and carried.bytes.len == wrapped[2].bytes.len);
        // Wrong independently reconstructed key for an otherwise genuine child
        // proof must fail before it can authorize a RISC fold child.
        var wrong = leaves[0].leaf;
        wrong.leaf.input.main_root[0] ^= 1;
        const accepted = check: {
            Registry.verifyBytes(a, wrong, wrapped[0].bytes, backend, .{}) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => break :check false,
            };
            break :check true;
        };
        try std.testing.expect(!accepted);
        break :block try Fold.produce(a, final_metadata, .{ first.bytes, carried.bytes }, backend, .{});
    };
    defer root.deinit();
    // All leaf/fold producer keys, decoded proofs and outer child bodies have
    // gone. Recreate canonical backend authority and FullPolicy independently.
    const records = [_]FoldWire.Record{ .{ .kind = 1, .a = 0 }, .{ .kind = 1, .a = 1 }, .{ .kind = 1, .a = 2 }, .{ .kind = 2, .a = 0, .b = 1 }, .{ .kind = 2, .a = 3, .b = 2 } };
    const public_wire = try FoldWire.encode(t, .{ .records = &records, .root = 4, .sources = 3 });
    const fresh_sources = [_]Upper.Tree{ leaves[0].leaf, leaves[1].leaf, leaves[2].leaf };
    try FoldWire.verifyFullBytes(a, public_wire, root.bytes, .{ .sources = &fresh_sources, .elf = &elf, .private_input = &.{}, .trusted = trusted, .canonical_circuit_air = air, .canonical_circuit_projection = projection }, .{});
    try std.testing.expectEqual(@as(u32, 2), root.certificate.fold.depth);
    try std.testing.expectEqual(@as(u32, 3), root.certificate.fold.leaves);
    try std.testing.expectEqual(@as(u32, 7), root.certificate.span().cycles);
    std.debug.print("RISC_CIRCUIT_FOLD q70=70 pow=26 wrapped_leaves=3 folds=2 depth=2 odd_carry=true fresh_full_receiver=true bytes={d}\n", .{root.bytes.len});
}

fn span(first: u32, cycles: u32) Typed.Span {
    return .{ .elf_sha256 = @splat(1), .first_cycle = first, .cycles = cycles, .incoming_snapshot_id = @splat(2), .outgoing_snapshot_id = @splat(2), .initial_cpu = @splat(0), .final_cpu = @splat(0), .initial_policy_id = null, .terminal_policy_id = null };
}
fn certificate(s: Typed.Span) Typed.Certificate {
    const child = Typed.Child{ .role = Typed.ROLE_FOLD, .registry_id = @splat(1), .preprocessed_root = @splat(2), .circuit_hash = @splat(3), .output_digest = @splat(4) };
    return .{ .fold = .{ .span = s, .children = .{ child, child }, .depth = 1, .leaves = 2 } };
}
