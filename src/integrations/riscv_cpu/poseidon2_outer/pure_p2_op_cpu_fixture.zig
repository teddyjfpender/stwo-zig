//! Actual OP-only Miller ECALL CPU/GKR + truth + RAM/Wire closure fixture.
//! This closed native gate is not production CLI or recursive admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Service = A.crypto.bn254_tower.execution;
const Prepared = @import("../word16_execution/prepared.zig").Prepared;
const Program = @import("../word16_execution/program.zig").Program;
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Collector = @import("../word16_global_execution/services/collector.zig");
const Pipeline = @import("../word16_global_execution/services/pipeline.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Roster = @import("../word16_global_execution/services/gkr_local/roster.zig");
const CPU = @import("pure_p2_cpu_worker.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const ClassicTruth = @import("pure_p2_tower_worker.zig");
const LocalTruth = @import("miller_local_gkr/worker.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Toy = @import("miller_local_gkr/fixture_image.zig");
const Manifest = @import("pure_p2_manifest.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const W = Protocol.W;
const ADDRESS: u64 = 0x8000000000000fe0;
const marker: u8 = 0;
fn initialWords() [Service.WORDS]u64 {
    var words: [Service.WORDS]u64 = @splat(0);
    for (0..20) |i| words[4 * i] = 1 + 2 * i;
    return words;
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < ADDRESS or address >= ADDRESS + Service.PACKET_BYTES or address & 7 != 0) return error.UntrustedOpJoinAddress;
    return initialWords()[(address - ADDRESS) / 8];
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address >= ADDRESS + Service.PACKET_BYTES) return error.UntrustedOpJoinAddress;
    return if (address < ADDRESS + Service.WRITTEN_BYTES) 3 else 1;
}
fn image() @import("../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn boundary() A.word16_execution.types.Boundary {
    var regs: [32]u64 = @splat(0);
    regs[10] = ADDRESS;
    regs[17] = Service.TAG;
    var out = A.word16_execution.types.Boundary{ .steps = 1, .initial_pc = 4096, .final_pc = 4100, .initial_registers = regs, .final_registers = regs, .register_clocks = @splat(0) };
    out.register_clocks[10] = 1;
    out.register_clocks[17] = 2;
    return out;
}
fn authority(setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, ids: [T.FAMILIES]u32, key: *const Key, instances: anytype) !Manifest.Expected {
    return .{ .kind = .cpu, .ordinal = 0, .statement = try key.statementForOp(setup, request, ids, span), .fixed = key.scope(), .fixed_identity = key.identity, .profile = key.profile, .local_instances = instances, .mass = try CPU.cpuMass(setup, request, span), .global_relations = .{ .ram = true, .kio = false, .wire = true } };
}
pub fn VerifiedJoinFor(comptime Truth: type) type {
    return struct {
        image: ?*const Image.Owner = null,
        inventory: ?*const @import("pure_p2_op_inventory.zig").Inventory = null,
        terminal: []const A.memory.closed_ram.types.Cell = &.{},
        setup: *const R.CpuSetup,
        request: P.Request,
        span: T.OpTowerSpan,
        first_ids: [T.FAMILIES]u32,
        key: *const Key,
        expected: Manifest.Expected,
        manifest: *const Manifest.Pending,
        encoded: *const CPU.Encoded,
        capture: *const core.pcs.ForField(W.O).verifier.VerifiedProofCapture(W.H),
        stage_one: Manifest.StageOne,
        truth_key: *const Truth.Key,
        truth_span: Truth.Span,
        truth_expected: Manifest.Expected,
        truth_encoded: *const Truth.Encoded,
    };
}
pub const VerifiedJoin = VerifiedJoinFor(ClassicTruth);
pub fn exercise(comptime Hook: type) !void {
    return exerciseWithLayout(Hook, false);
}
pub fn exerciseWithLayout(comptime Hook: type, comptime compact: bool) !void {
    return exerciseProvider(Hook, compact, ClassicTruth, false, false);
}
pub fn exerciseLocal(comptime Hook: type) !void {
    return exerciseProvider(Hook, true, LocalTruth, true, false);
}
fn exerciseProvider(comptime Hook: type, comptime compact: bool, comptime Truth: type, comptime toy: bool, comptime use_producer: bool) !void {
    const budget: ?*engine.host_budget_allocator.SharedHostBudget = if (use_producer) try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30) else null;
    defer if (budget) |owner| owner.destroy();
    const a = if (budget) |owner| owner.allocator() else std.testing.allocator;
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    const span = T.OpTowerSpan{ .calls = 1, .first_id = 1 };
    const profile = Protocol.Profile.op_target_b4_q72_p0_fold4_v1;
    var toy_image: Image.Owner = if (toy) try Toy.init(a) else undefined;
    defer if (toy) toy_image.deinit();
    const words: []const u32 = if (toy) &Toy.WORDS else &.{0x73};
    const expected_image = if (toy) @import("../word16_execution/driver.zig").admission(&toy_image).image else image();
    var program = if (toy) try Program.initWithAuthority(a, &toy_image.authority) else try Program.initWithProfile(a, .{ .base = 4096, .words = words }, .ethereum_services_op_v1);
    defer program.deinit();
    if (compact) try program.makeCompact();
    var tape = try front.rv64.compact_tape.Tape.init(a, 1, 4096, 0, .ethereum_services_op_v1);
    defer tape.deinit();
    const before = if (toy) Toy.beforeWords() else initialWords();
    const after = try Service.execute(&before);
    const call = front.rv64.ethereum_services.TowerCall{ .call_id = 1, .clock = 1, .pc = 4096, .pointer = ADDRESS, .before = before, .output = after[0..Service.WRITTEN_WORDS].* };
    try tape.appendTower(&call);
    var native = try Prepared.captureForOpServices(a, &program, boundary(), 1, 5, &tape, .{});
    defer native.deinit();
    var advice = try Collector.collect(a, &.{&native}, &.{&tape}, expected_image);
    defer advice.deinit();
    var geometry = try native.geometry();
    geometry.boundary_log = 7; // all 80 packet words, including readonly tail.
    var bridges = T.Logs{ .tower = 5 };
    if (compact) {
        const Plan = @import("../word16_global_execution/ethereum/plan.zig");
        const declaration = try Plan.cpuForSegment(&native, &advice, 0, 1, advice.initial.len, Plan.CpuLayout.forOpGkr());
        geometry = declaration.geometry;
        bridges = declaration.bridges;
        bridges.tower = 5;
    }
    var setup = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = words }, geometry, bridges);
    defer setup.deinit();
    var fresh = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = words }, geometry, bridges);
    defer fresh.deinit();
    if (compact) {
        try std.testing.expect(setup.materials.program.compact and fresh.materials.program.compact);
        try std.testing.expect(geometry.cpu_compact_decode and geometry.cpu_u8_pairs and geometry.cpu_fused_tail);
    }
    var key = try Key.initForOp(a, &setup, profile);
    defer key.deinit();
    var receiver_key = try Key.initForOp(a, &fresh, profile);
    defer receiver_key.deinit();
    try std.testing.expectEqualSlices(u8, &key.identity, &receiver_key.identity);
    const request = try Coordinator.requestView(&.{&native}, &advice, 0);
    const ids: [T.FAMILIES]u32 = @splat(1);
    const instances = try Roster.fromOpSetup(a, &setup);
    defer a.free(instances);
    const receiver_instances = try Roster.fromOpSetup(a, &fresh);
    defer a.free(receiver_instances);
    const cpu_expected = try authority(&setup, request, span, ids, &key, instances);
    const receiver_expected = try authority(&fresh, request, span, ids, &receiver_key, receiver_instances);
    var truth_key = try Truth.Key.init(a, profile, 8, 15);
    defer truth_key.deinit();
    var fresh_truth = try Truth.Key.init(a, profile, 8, 15);
    defer fresh_truth.deinit();
    const truth_span = Truth.Span{ .calls = span.calls, .first_id = span.first_id };
    const truth_expected = try truth_key.expected(truth_span, 1);
    const fresh_truth_expected = try fresh_truth.expected(truth_span, 1);
    var input: A.crypto.bn254_tower.narrow.trace.Input = undefined;
    for (&input, 0..) |*value, i| value.* = @as(u256, before[4 * i]) | (@as(u256, before[4 * i + 1]) << 64) | (@as(u256, before[4 * i + 2]) << 128) | (@as(u256, before[4 * i + 3]) << 192);
    var inventory: @import("pure_p2_op_inventory.zig").Inventory = undefined;
    defer if (toy) inventory.deinit();
    if (toy) {
        const exp = try @import("../word16_global_execution/ethereum/receiver.zig").expectedFromRequests(&toy_image, program.identity, &.{request}, 1, 1, true);
        inventory = try @import("pure_p2_op_inventory.zig").Inventory.initForSourceSuite(a, profile, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{.{ .key = &fresh_truth.base, .local_key = &fresh_truth, .span = truth_span }}, exp, &.{}, .{ .miller = .local_gkr });
        try std.testing.expectEqualSlices(u8, &cpu_expected.statement, &inventory.workers[0].statement);
        try std.testing.expectEqualSlices(u8, &truth_expected.statement, &inventory.workers[1].statement);
        try std.testing.expect(inventory.source_security != null);
        const Inv = @import("pure_p2_op_inventory.zig");
        const decl = Inv.MillerDeclaration{ .key = &fresh_truth.base, .local_key = &fresh_truth, .span = truth_span };
        if (Inv.Inventory.initForSourceSuite(a, profile, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{}, exp, &.{}, .{ .miller = .local_gkr })) |value| {
            var owned = value;
            owned.deinit();
            return error.MissingMillerProviderAccepted;
        } else |_| {}
        if (Inv.Inventory.initForSourceSuite(a, profile, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{ decl, decl }, exp, &.{}, .{ .miller = .local_gkr })) |value| {
            var owned = value;
            owned.deinit();
            return error.DuplicatedMillerProviderAccepted;
        } else |_| {}
        try std.testing.expectError(error.OpMillerSourceSuitePolicy, Inv.Inventory.initForSourceSuite(a, profile, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{decl}, exp, &.{}, .{}));
    }
    if (use_producer) {
        const Prod = @import("pure_p2_op_producer.zig");
        const BW = @import("pure_p2_op_bundle.zig");
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const path = try temporary.dir.realpathAlloc(a, ".");
        defer a.free(path);
        var store = try @import("pure_p2_retained_main.zig").Store.init(a, path, 1 << 30, 512 << 20);
        defer store.deinit();
        const decl = @import("pure_p2_op_inventory.zig").MillerDeclaration{ .key = &fresh_truth.base, .local_key = &fresh_truth, .span = truth_span };
        const limits = Prod.Limits{ .cpu = .{ .gkr_bytes = 512 << 20, .global_bytes = 1 << 30 }, .truth = .{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 1 << 20 }, .miller = .{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 1 << 20 }, .miller_local_gkr_bytes = 512 << 20 };
        try std.testing.expectError(error.OpSourceSuiteRequiresExplicitProducer, Prod.produce(a, &inventory, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{decl}, &.{&native}, &advice, &store, limits));
        var produced = try Prod.produceForSourceSuite(a, &inventory, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{decl}, &.{&native}, &advice, &store, limits, .{ .miller = .local_gkr });
        defer produced.deinit(a);
        var closed = try produced.verifyWithHooksForSourceSuite(a, &inventory, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{decl}, .{ .miller = .local_gkr }, .{});
        defer closed.deinit(a);
        try std.testing.expectEqualSlices(u8, &toy_image.expected_output, &try @import("../word16_global_execution/ethereum/terminal.zig").require(&toy_image, request.base.cpu, advice.terminal));
        try std.testing.expectEqual(@as(usize, 0), store.mapped);
        const encoded = try BW.encodeForSuite(a, &produced, .{ .bytes = 64 << 20, .proof_bytes = 32 << 20 }, .{ .miller = .local_gkr });
        defer a.free(encoded);
        std.debug.print("OP_SOURCE_SUITE_PRODUCER bytes={} parked_peak={} heap_peak={} full_native_receiver=true\n", .{ encoded.len, store.peak_mapped, budget.?.snapshot().peak_live_bytes });
        return;
    }
    var source = try Pipeline.buildCpuSourceForOp(a, &setup, request, span, &native, &advice, 0, ids, false, null);
    try std.testing.expectError(error.LocalGkrBudgetExceeded, CPU.Worker.initForOp(a, &setup, request, span, source, cpu_expected, ids, &key, .{ .gkr_bytes = 1, .global_bytes = 1 << 30 }));
    var worker = CPU.Worker.initForOp(a, &setup, request, span, source, cpu_expected, ids, &key, .{ .gkr_bytes = 1 << 30, .global_bytes = 1 << 30 }) catch |err| {
        source.deinit();
        return err;
    };
    defer worker.deinit();
    const truth_limits = if (Truth == LocalTruth) Truth.Limits{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 1 << 20, .gkr_bytes = 512 << 20 } else Truth.Limits{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 1 << 20 };
    var truth = try Truth.Worker.init(a, &truth_key, truth_span, truth_expected, &.{input}, truth_limits);
    defer truth.deinit();
    const stages = [_]Manifest.StageOne{ try worker.seal(a), try truth.seal() };
    const expected = [_]Manifest.Expected{ cpu_expected, truth_expected };
    const receiver_authority = [_]Manifest.Expected{ receiver_expected, fresh_truth_expected };
    const execution: [32]u8 = if (toy) inventory.execution else @splat(0x43); // receiver-selected fixture identity.
    var sender = try Manifest.verifyAndSeal(a, execution, &expected, &stages);
    defer sender.deinit(a);
    var receiver = try Manifest.verifyAndSeal(a, execution, &receiver_authority, &stages);
    defer receiver.deinit(a);
    var proof = try worker.complete(a, &sender, 0);
    defer proof.deinit(a);
    var truth_proof = try truth.complete(&sender, 1);
    defer truth_proof.deinit(a);
    var capture: core.pcs.ForField(W.O).verifier.VerifiedProofCapture(W.H) = undefined;
    const cpu_claims = try CPU.verifyForOp(a, &fresh, request, span, receiver_expected, ids, &receiver, 0, &receiver_key, &proof, &capture);
    defer capture.deinit(a);
    const truth_claims = try Truth.verify(a, &fresh_truth, truth_span, fresh_truth_expected, &receiver, 1, &truth_proof);
    try receiver.checkGlobalClosure(&.{ cpu_claims, truth_claims });
    if (toy) {
        const Suite = @import("pure_p2_source_suite.zig").Suite;
        const suite = Suite{ .miller = .local_gkr };
        const BW = @import("pure_p2_op_bundle.zig");
        const stage_bytes = try @import("pure_p2_manifest_wire.zig").encode(a, inventory.execution, inventory.workers, &stages);
        defer a.free(stage_bytes);
        const truth_envelope = try LocalTruth.encode(a, &truth_proof);
        defer a.free(truth_envelope);
        var borrowed_proofs = [_]BW.Proof{ .{ .bytes = proof.bytes, .claims = proof.claims }, .{ .bytes = truth_envelope, .claims = &truth_proof.claims } };
        const borrowed = BW.Bundle{ .source_suite = suite, .stage_one = stage_bytes, .proofs = &borrowed_proofs };
        const limits = BW.Limits{ .bytes = 64 << 20, .proof_bytes = 32 << 20 };
        const durable_bytes = try BW.encodeForSuite(a, &borrowed, limits, suite);
        defer a.free(durable_bytes);
        try std.testing.expectError(error.InvalidOpNativeBundle, BW.decode(a, durable_bytes, 2, limits));
        try std.testing.expectError(error.OpSourceSuitePolicyMismatch, BW.decodeForSuite(a, durable_bytes, 2, limits, .{}));
        try std.testing.expectError(error.InvalidOpNativeBundle, BW.decodeForSuite(a, durable_bytes, 1, limits, suite));
        var durable = try BW.decodeForSuite(a, durable_bytes, 2, limits, suite);
        defer durable.deinit(a);
        const declaration = @import("pure_p2_op_inventory.zig").MillerDeclaration{ .key = &fresh_truth.base, .local_key = &fresh_truth, .span = truth_span };
        var closed = try durable.verifyWithHooksForSourceSuite(a, &inventory, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{declaration}, suite, .{});
        defer closed.deinit(a);
        const terminal_output = try @import("../word16_global_execution/ethereum/terminal.zig").require(&toy_image, request.base.cpu, advice.terminal);
        try std.testing.expectEqualSlices(u8, &toy_image.expected_output, &terminal_output);
        const cpu_debt = durable.proofs[0].claims[durable.proofs[0].claims.len - 1];
        const truth_debt = durable.proofs[1].claims[0];
        durable.proofs[0].claims[durable.proofs[0].claims.len - 1] = cpu_debt.add(W.O.one());
        durable.proofs[1].claims[0] = truth_debt.sub(W.O.one());
        try std.testing.expect(std.meta.isError(durable.verifyWithHooksForSourceSuite(a, &inventory, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{declaration}, suite, .{})));
        durable.proofs[0].claims[durable.proofs[0].claims.len - 1] = cpu_debt;
        durable.proofs[1].claims[0] = truth_debt;
        std.mem.swap(BW.Proof, &durable.proofs[0], &durable.proofs[1]);
        try std.testing.expect(std.meta.isError(durable.verifyWithHooksForSourceSuite(a, &inventory, &.{&fresh}, &.{request}, &.{span}, &.{&receiver_key}, &.{}, &.{}, &.{declaration}, suite, .{})));
        std.mem.swap(BW.Proof, &durable.proofs[0], &durable.proofs[1]);
        const receipt = truth_proof.receipt;
        truth_proof.receipt[0] ^= 1;
        try std.testing.expect(std.meta.isError(Truth.verify(a, &fresh_truth, truth_span, fresh_truth_expected, &receiver, 1, &truth_proof)));
        truth_proof.receipt = receipt;
        if (std.process.getEnvVarOwned(a, "STWO_OP_SUITE_NATIVE_OUT")) |path| {
            defer a.free(path);
            try std.fs.cwd().makePath(path);
            var dir = try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            try dir.writeFile(.{ .sub_path = "native-op.bin", .data = durable_bytes });
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => {},
            else => return err,
        }
        std.debug.print("OP_SOURCE_SUITE_NATIVE bytes={} CPU=1 MillerLocal=1 terminal=43B full_policy=true security_qualified=false\n", .{durable_bytes.len});
    }

    try std.testing.expectError(error.GlobalGkrManifestRoster, receiver.checkGlobalClosure(&.{cpu_claims}));
    try std.testing.expectError(error.UnqualifiedOpProtocol, Key.init(a, &fresh, profile));
    try std.testing.expectError(error.UnqualifiedOpProtocol, CPU.verify(a, &fresh, request, receiver_expected, ids, &receiver, 0, &receiver_key, &proof, null));
    var wrong_span = span;
    wrong_span.first_id += 1;
    try std.testing.expectError(error.PoseidonNativeStatementMismatch, CPU.verifyForOp(a, &fresh, request, wrong_span, receiver_expected, ids, &receiver, 0, &receiver_key, &proof, null));
    wrong_span = .{};
    try std.testing.expectError(error.InvalidOpTowerPresence, CPU.verifyForOp(a, &fresh, request, wrong_span, receiver_expected, ids, &receiver, 0, &receiver_key, &proof, null));
    var missing_local = receiver_expected;
    missing_local.local_instances = receiver_instances[0 .. receiver_instances.len - 1];
    try std.testing.expectError(error.PoseidonNativeRosterMismatch, CPU.verifyForOp(a, &fresh, request, span, missing_local, ids, &receiver, 0, &receiver_key, &proof, null));
    var wrong_expected = receiver_expected;
    wrong_expected.profile = .op_control_b2_q144_p0_fold4_v1;
    try std.testing.expectError(error.PoseidonNativeFixedAuthorityMismatch, CPU.verifyForOp(a, &fresh, request, span, wrong_expected, ids, &receiver, 0, &receiver_key, &proof, null));
    const old_mass = receiver.entries[0].authority.mass;
    receiver.entries[0].authority.mass.ram += 1;
    try std.testing.expectError(error.PoseidonNativeManifestMismatch, CPU.verifyForOp(a, &fresh, request, span, receiver_expected, ids, &receiver, 0, &receiver_key, &proof, null));
    receiver.entries[0].authority.mass = old_mass;
    const claim = proof.claims[proof.claims.len - 1];
    proof.claims[proof.claims.len - 1] = claim.add(W.O.one());
    try std.testing.expect(std.meta.isError(CPU.verifyForOp(a, &fresh, request, span, receiver_expected, ids, &receiver, 0, &receiver_key, &proof, null)));
    proof.claims[proof.claims.len - 1] = claim;
    const digest = receiver.digest;
    receiver.digest[0] ^= 1;
    try std.testing.expect(std.meta.isError(CPU.verifyForOp(a, &fresh, request, span, receiver_expected, ids, &receiver, 0, &receiver_key, &proof, null)));
    receiver.digest = digest;
    if (comptime @hasDecl(Hook, "run")) try Hook.run(a, VerifiedJoinFor(Truth){ .image = if (toy) &toy_image else null, .inventory = if (toy) &inventory else null, .terminal = advice.terminal, .setup = &fresh, .request = request, .span = span, .first_ids = ids, .key = &receiver_key, .expected = receiver_expected, .manifest = &receiver, .encoded = &proof, .capture = &capture, .stage_one = stages[0], .truth_key = &fresh_truth, .truth_span = truth_span, .truth_expected = fresh_truth_expected, .truth_encoded = &truth_proof });
    std.debug.print("OP_CPU_TOWER_JOIN steps=1 compact={} profile={s} CPU_bytes={} truth_bytes={} local_OWNER=GKR RAM_Wire=closed fresh_source_receiver=true production_admitted=false\n", .{ compact, @tagName(profile), proof.bytes.len, truth_proof.bytes.len });
}

test "OP actual Miller CPU GKR physical proof freshly closes RAM Wire and manifest gates" {
    try exercise(struct {});
}
test "OP compact actual Miller CPU GKR freshly closes all packet RAM and Wire" {
    try exerciseWithLayout(struct {}, true);
}

test "OP local Miller source suite CPU GKR physically closes packet RAM Wire and terminal" {
    try exerciseLocal(struct {});
}

test "OP source suite native producer parks restores and freshly closes local Miller" {
    try exerciseProvider(struct {}, true, LocalTruth, true, true);
}
