const std = @import("std");
const core = @import("stwo_core");
const F = @import("../word16_global_execution/services/v3_fixture.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const T = @import("../word16_global_execution/services/types.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Inventory = @import("pure_p2_op_inventory.zig").Inventory;
const Key = @import("pure_p2_fixed_key.zig").Key;
const Truth = @import("pure_p2_truth_worker.zig");
const Receiver = @import("pure_p2_op_root_receiver.zig");
const Components = @import("../word16_global_execution/services/gkr_local/cpu_components.zig");
const Manifest = @import("pure_p2_manifest.zig");
const O = core.fields.om31.OM31;
const a = std.testing.allocator;
test "OP pure P2 root preparation binds complete source inventory and boundary claims" {
    const profile = @import("pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    var captured = try F.Captured.initForOp(a);
    defer captured.deinit();
    var setups: [2]R.CpuSetup = undefined;
    var keys: [2]Key = undefined;
    var made: usize = 0;
    defer for (0..made) |i| {
        keys[i].deinit();
        setups[i].deinit();
    };
    for (0..2) |i| {
        var geometry = try captured.native[i].geometry();
        geometry.boundary_log = F.BOUNDARY_LOG;
        setups[i] = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, F.BRIDGES[i]);
        keys[i] = try Key.initForOp(a, &setups[i], profile);
        made += 1;
    }
    var sha = try @import("../word16_global_execution/sha256/roster.zig").TruthSetup.init(a, F.SHA_LOG);
    defer sha.deinit();
    var arith = try @import("../word16_global_execution/arith256/roster.zig").TruthSetup.init(a, F.ARITH_LOG);
    defer arith.deinit();
    const truths = F.truthsFor(&sha, &arith);
    var tk0 = try Truth.Key.init(a, truths[0], profile);
    defer tk0.deinit();
    var tk1 = try Truth.Key.init(a, truths[1], profile);
    defer tk1.deinit();
    const Native = @import("../word16_execution/prepared.zig").Prepared;
    const natives = [_]*Native{ &captured.native[0], &captured.native[1] };
    var requests = [_]P.Request{ try Coordinator.requestView(&natives, &captured.advice, 0), try Coordinator.requestView(&natives, &captured.advice, 1) };
    try Coordinator.assignSpongeIds(&requests);
    const spans = [_]T.OpTowerSpan{ .{}, .{} };
    const expected = F.expectedFor(captured.program.identity, captured.loaded);
    var inventory = try Inventory.init(a, profile, &.{ &setups[0], &setups[1] }, &requests, &spans, &.{ &keys[0], &keys[1] }, &truths, &.{ &tk0, &tk1 }, &.{}, expected);
    defer inventory.deinit();
    const original = @import("../word16_global_execution/services/arith256_fixture.zig").initialWords();
    var output: Receiver.Output = .{ .address = F.AR_PACKET + 32, .bytes = undefined };
    for (&output.bytes, 0..) |*byte, i| byte.* = @truncate(original[(32 + i) / 8] >> @as(u6, @intCast(((32 + i) % 8) * 8)));
    const authority = Receiver.Authority{ .profile = profile, .setups = &.{ &setups[0], &setups[1] }, .requests = &requests, .spans = &spans, .cpu_keys = &.{ &keys[0], &keys[1] }, .truths = &truths, .truth_keys = &.{ &tk0, &tk1 }, .miller = &.{}, .expected = expected, .output = output };
    var plans = [_]Components.Plan{ try Components.Plan.initForOp(a, &setups[0]), try Components.Plan.initForOp(a, &setups[1]) };
    defer for (&plans) |*plan| plan.deinit();
    const values = [_][]O{ try a.alloc(O, plans[0].claim_count), try a.alloc(O, plans[1].claim_count), try a.alloc(O, 1), try a.alloc(O, 1) };
    defer for (values) |v| a.free(v);
    for (values) |v| @memset(v, O.zero());
    var leaves: [4]Receiver.Leaf = undefined;
    for (&leaves, values, 0..) |*leaf, v, i| leaf.* = .{ .ordinal = @intCast(i), .main = @splat(0), .receipt = if (i < 2) @as(Receiver.Digest, @splat(0)) else null, .claims = v };
    var metadata = Receiver.Metadata{ .execution = inventory.execution, .manifest = try Receiver.manifestFor(a, &inventory, &leaves), .leaves = &leaves };
    const shared = try Manifest.drawShared(metadata.manifest);
    var ls_offset: usize = undefined;
    var initial_offset: usize = undefined;
    var wire_offset: usize = undefined;
    for (plans, &requests, 0..) |plan, request, i| for (plan.slots) |slot| switch (slot.origin) {
        .core => |role| {
            if (role == .initial or role == .terminal) {
                values[i][slot.claim_offset] = try @import("../word16_global_execution/services/gkr_local/expected_boundary.zig").claim(if (role == .initial) request.base.memory.initial else request.base.memory.terminal, role == .initial, shared.ram);
                if (i == 0 and role == .initial) initial_offset = slot.claim_offset;
            }
            if (i == 0 and role == .ls) ls_offset = slot.claim_offset;
        },
        .bridge => |family| if (i == 0 and family == .sha256) {
            wire_offset = slot.claim_offset + 1;
        },
        else => {},
    };
    const sum = (try Components.Set.aggregate(&plans[0], values[0])).ram.add((try Components.Set.aggregate(&plans[1], values[1])).ram);
    values[0][ls_offset] = sum.neg();
    var prepared = try Receiver.prepare(a, authority, metadata);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 4), prepared.expected_outputs.len);
    try std.testing.expectEqualSlices(u8, &metadata.manifest, &prepared.manifest);
    // This is deliberately NOT execution acceptance: no root proof was supplied.
    var changed = metadata;
    changed.leaves = leaves[0..3];
    try std.testing.expectError(error.OpRootLeafCoverage, Receiver.prepare(a, authority, changed));
    const saved = leaves[1];
    leaves[1] = leaves[0];
    try std.testing.expectError(error.OpRootLeafOrder, Receiver.prepare(a, authority, metadata));
    leaves[1] = saved;
    std.mem.swap(Receiver.Leaf, &leaves[2], &leaves[3]);
    try std.testing.expectError(error.OpRootLeafOrder, Receiver.prepare(a, authority, metadata));
    std.mem.swap(Receiver.Leaf, &leaves[2], &leaves[3]);
    changed = metadata;
    changed.manifest[35] ^= 1;
    try std.testing.expectError(error.OpRootManifestAuthority, Receiver.prepare(a, authority, changed));
    changed = metadata;
    changed.execution[0] ^= 1;
    try std.testing.expectError(error.OpRootExecutionAuthority, Receiver.prepare(a, authority, changed));
    var wrong = authority;
    wrong.output.bytes[42] ^= 1;
    try std.testing.expectError(error.OpRootOutputMismatch, Receiver.prepare(a, wrong, metadata));
    wrong = authority;
    wrong.output.address = std.math.maxInt(u64) - 41;
    try std.testing.expectError(error.OpRootOutputWrap, Receiver.prepare(a, wrong, metadata));
    wrong = authority;
    wrong.output.address = 0x4000;
    try std.testing.expectError(error.OpRootOutputMissing, Receiver.prepare(a, wrong, metadata));
    wrong = authority;
    wrong.expected.admission.image_identity[0] ^= 1;
    try std.testing.expectError(error.OpRootExecutionAuthority, Receiver.prepare(a, wrong, metadata));
    wrong = authority;
    wrong.expected.final_pc += 4;
    try std.testing.expect(std.meta.isError(Receiver.prepare(a, wrong, metadata)));
    wrong = authority;
    wrong.truths = truths[0..1];
    wrong.truth_keys = &.{&tk0};
    try std.testing.expect(std.meta.isError(Receiver.prepare(a, wrong, metadata)));
    var fake_key = keys[0];
    fake_key.source_root[0] ^= 1;
    wrong = authority;
    wrong.cpu_keys = &.{ &fake_key, &keys[1] };
    try std.testing.expectError(error.PoseidonNativeFixedAuthorityMismatch, Receiver.prepare(a, wrong, metadata));
    // A forged boundary can algebraically balance LS; source public RAM
    // recomputation must reject it BEFORE treating any root as authenticated.
    values[0][initial_offset] = values[0][initial_offset].add(O.one());
    values[0][ls_offset] = values[0][ls_offset].sub(O.one());
    try std.testing.expectError(error.PoseidonNativePublicRam, Receiver.prepare(a, authority, metadata));
    values[0][initial_offset] = values[0][initial_offset].sub(O.one());
    values[0][ls_offset] = values[0][ls_offset].add(O.one());
    values[2][0] = O.one();
    try std.testing.expectError(error.UnclosedGlobalGkrWire, Receiver.prepare(a, authority, metadata));
    // Balanced service debts remain untrusted until their changed frame hashes
    // are authenticated by the root. An old proof cannot authenticate them.
    values[0][wire_offset] = O.one();
    values[2][0] = O.one().neg();
    var balanced = try Receiver.prepare(a, authority, metadata);
    defer balanced.deinit();
    try std.testing.expect(!std.mem.eql(u8, &balanced.expected_outputs[0], &prepared.expected_outputs[0]));
    try std.testing.expect(!std.mem.eql(u8, &balanced.expected_outputs[2], &prepared.expected_outputs[2]));
}
