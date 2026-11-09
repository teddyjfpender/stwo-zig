//! Test-only physical receiver attacks, reusing one persisted root. No proving
//! of the actual execution is repeated to test metadata/authority mutations.
const std = @import("std");
const Core = @import("stwo_core");
const Receiver = @import("../pure_p2_op_root_receiver.zig");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Topology = @import("topology.zig").Topology;
const O = Core.fields.om31.OM31;
fn reject(result: anytype) !void {
    if (result) |value| {
        if (comptime @TypeOf(value) == Receiver.Plan) {
            var owned = value;
            owned.deinit();
        }
        return error.OpRootAttackAccepted;
    } else |_| {}
}
fn rejectPrepareExact(expected: anyerror, result: anyerror!Receiver.Plan) !void {
    if (result) |value| {
        var owned = value;
        owned.deinit();
        return error.OpRootAttackAccepted;
    } else |err| if (err != expected) return err;
}
fn reframe(a: std.mem.Allocator, policy: Receiver.Authority, metadata: Receiver.Metadata) !Receiver.Metadata {
    const Inventory = @import("../pure_p2_op_inventory.zig").Inventory;
    var inventory = try Inventory.init(a, policy.profile, policy.setups, policy.requests, policy.spans, policy.cpu_keys, policy.truths, policy.truth_keys, policy.miller, policy.expected);
    defer inventory.deinit();
    return .{ .execution = inventory.execution, .manifest = try Receiver.manifestFor(a, &inventory, metadata.leaves), .leaves = metadata.leaves };
}
fn authority(source: Runtime.SourceDirectory) Receiver.Authority {
    return .{ .image = source.image, .output = .{ .address = source.output_address, .bytes = source.output }, .profile = source.metadata.profile, .setups = source.setups, .requests = source.requests, .spans = source.metadata.spans, .cpu_keys = source.cpu_keys, .truths = source.truths, .truth_keys = source.truth_keys, .miller = source.miller, .expected = source.expected };
}
pub fn run(a: std.mem.Allocator, source: Runtime.SourceDirectory, metadata: Receiver.Metadata, plan: *const Receiver.Plan, topology: *const Topology, root: []const u8) !void {
    if (!@import("builtin").is_test) return error.OpRootQualificationIsTestOnly;
    const bytes = try a.dupe(u8, root);
    defer a.free(bytes);
    bytes[40] ^= 1;
    try reject(@import("receiver.zig").verifyPlan(a, plan, topology, bytes));
    // Produce a VALID same-profile, nine-output algebraic proof which merely
    // guesses the expected root. Only independent source authority defeats it.
    const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
    const Authority = @import("authority.zig").Key;
    const Proof = @import("proof.zig");
    const expected = try plan.expectedRoot(a);
    var forged_context = try C.PoseidonContext.init(a, 9);
    defer forged_context.deinit();
    var ports: [9]C.Var = undefined;
    for (&ports, expected) |*port, value| port.* = try forged_context.algebra().guess(value);
    try forged_context.setOutputs(&ports);
    try forged_context.finalize();
    var forged_key = try Authority.init(a, &forged_context, source.metadata.profile);
    defer forged_key.deinit();
    const forged = try Proof.prove(a, &forged_context, &forged_key, &expected);
    defer a.free(forged);
    try Proof.verify(a, &forged_key, &expected, forged); // Positive control, not junk.
    try reject(@import("receiver.zig").verifyPlan(a, plan, topology, forged));

    const leaves = try a.dupe(Receiver.Leaf, metadata.leaves);
    defer a.free(leaves);
    var changed = metadata;
    changed.leaves = leaves;
    if (leaves.len > 1) {
        changed.leaves = leaves[0 .. leaves.len - 1];
        try reject(Receiver.prepare(a, authority(source), changed));
        changed.leaves = leaves;
        const saved = leaves[1].ordinal;
        leaves[1].ordinal = leaves[0].ordinal;
        try reject(Receiver.prepare(a, authority(source), changed));
        leaves[1].ordinal = saved;
        const first = leaves[0];
        leaves[0] = leaves[1];
        leaves[1] = first;
        try reject(Receiver.prepare(a, authority(source), changed));
        leaves[1] = leaves[0];
        leaves[0] = first;
    }
    // Balanced service debt keeps every aggregate sum closed. It must still
    // alter authenticated leaf frames and fail against the OLD valid root.
    var cpu_index: ?usize = null;
    var offset: usize = 0;
    for (source.setups, 0..) |setup, i| {
        var slots = try @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Plan.initForOp(a, setup);
        defer slots.deinit();
        for (slots.slots) |slot| {
            const kio = switch (slot.origin) {
                .sponge => true,
                .bridge => |family| family == .keccak,
                else => false,
            };
            if (kio and cpu_index == null) {
                cpu_index = i;
                offset = slot.claim_offset + 1;
            }
        }
    }
    var truth_index: ?usize = null;
    for (source.truths, 0..) |truth, j| if (truth == .keccak) {
        truth_index = source.setups.len + j;
        break;
    };
    const cpu = cpu_index orelse return error.OpRootQualificationNeedsKeccak;
    const truth = truth_index orelse return error.OpRootQualificationNeedsKeccak;
    const cclaims = try a.dupe(O, leaves[cpu].claims);
    defer a.free(cclaims);
    const tclaims = try a.dupe(O, leaves[truth].claims);
    defer a.free(tclaims);
    if (offset >= cclaims.len or tclaims.len != 5) return error.OpRootQualificationClaimShape;
    cclaims[offset] = cclaims[offset].add(O.one());
    tclaims[3] = tclaims[3].sub(O.one());
    leaves[cpu].claims = cclaims;
    leaves[truth].claims = tclaims;
    var balanced = try Receiver.prepare(a, authority(source), changed);
    defer balanced.deinit();
    try reject(@import("receiver.zig").verifyPlan(a, &balanced, topology, root));

    // Full terminal policy is independent of the claimed endpoint and digest.
    const requests = try a.dupe(@import("../../word16_global_execution/services/protocol.zig").Request, source.requests);
    defer a.free(requests);
    const Cell = @import("../../word16_execution/memory/statement.zig").Cell;
    const terminal = try a.dupe(Cell, source.terminal);
    defer a.free(terminal);
    requests[requests.len - 1].base.memory.terminal = terminal;
    var terminal_authority = authority(source);
    terminal_authority.requests = requests;
    for ([_]u64{ source.image.symbols.halt_flag, source.image.symbols.output_len }) |address| {
        var found = false;
        for (terminal) |*cell| if (cell.address == (address & ~@as(u64, 7))) {
            const saved = cell.state.value;
            cell.state.value &= ~(@as(u64, 0xffffffff) << @as(u6, @intCast((address & 7) * 8)));
            const reframed = try reframe(a, terminal_authority, metadata);
            try rejectPrepareExact(if (address == source.image.symbols.halt_flag) error.EthereumHaltNotSet else error.EthereumOutputLengthMismatch, Receiver.prepare(a, terminal_authority, reframed));
            cell.state.value = saved;
            found = true;
            break;
        };
        if (!found) return error.OpRootQualificationTerminalMissing;
    }
    requests[requests.len - 1].base.cpu.final_pc += 4;
    terminal_authority.expected.final_pc += 4;
    const pc_reframed = try reframe(a, terminal_authority, metadata);
    try rejectPrepareExact(error.EthereumTerminalPcMismatch, Receiver.prepare(a, terminal_authority, pc_reframed));
    std.debug.print("OP_P2_ROOT_ATTACKS valid_same_profile_wrong_VK=true balanced_service_debt=true missing_duplicate=true halt_length_pc=true physical_corruption=true\n", .{});
}
