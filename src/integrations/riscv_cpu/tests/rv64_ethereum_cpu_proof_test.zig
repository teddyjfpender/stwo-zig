//! One real mixed instruction stream, using each service family over shared RAM.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const Service = @import("../rv64_keccak_cpu.zig");
const SecpCtx = @import("../delegations/secp256k1/context.zig");
const S = air.crypto.secp256k1;
const Cell = @import("../rv64_full_statement.zig").Cell;
const Q = @import("stwo_core").fields.qm31.QM31;
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;
test "Ethereum v1 CPU joins Keccak secp ADD DOUBLE MUL DIV and RAM in one PCS" {
    try run(.ethereum_services_v1);
}
test "Ethereum v2 CPU joins word packets with same service and memory closure" {
    try run(.ethereum_services_v2);
}
fn run(profile: rv.execution_profile.Profile) !void {
    const Fixture = @import("rv64_ethereum_fixture.zig");
    const fixture = try Fixture.Fixture.create(a, profile);
    defer fixture.deinit();
    const pc = Fixture.pc;
    const program = Fixture.program;
    const records = &fixture.records;
    const kcalls = &fixture.kcalls;
    const scalls = &fixture.scalls;
    const public = fixture.public;
    try std.testing.expect(!std.mem.eql(u64, scalls[0].before[0..12], scalls[0].after[0..12]));
    try std.testing.expect(!std.mem.eql(u64, scalls[1].before[0..12], scalls[1].after[0..12]));
    const keccak_tag = rv.execution_profile.KECCAK_TAG;
    var setup = try Service.PreparedSetup.init(a, public);
    defer setup.deinit();
    var unused = public;
    unused.division_requests = 0;
    unused.multiplication_requests = 0;
    unused.keccak_calls = 0;
    unused.first_call_id = 37;
    unused.secp.add.calls = 0;
    unused.secp.add.first_id = 11;
    unused.secp.double.calls = 0;
    unused.secp.double.first_id = 27;
    var reused = try Service.PreparedSetup.init(a, unused);
    defer reused.deinit();
    try std.testing.expectEqualSlices(u8, &setup.root, &reused.root);
    try std.testing.expectEqualSlices(u8, &setup.cacheIdentity(), &reused.cacheIdentity());
    const Full = @import("../rv64_full.zig");
    var authority = try Full.ProgramAuthority.init(a, public.statement.program, profile);
    defer authority.deinit();
    var incompatible = public;
    incompatible.execution_profile = if (profile == .ethereum_services_v1) .ethereum_services_v2 else .ethereum_services_v1;
    try std.testing.expectError(error.InvalidRv64ServiceSetup, Service.PreparedMaterials.initWithAuthority(a, incompatible, &authority));
    var borrowed = try Service.PreparedMaterials.initWithAuthority(a, public, &authority);
    defer borrowed.deinit();
    try std.testing.expect(borrowed.base.borrows_immutable);
    const owned_fixed = try setup.materials.fixedColumns(a);
    defer a.free(owned_fixed);
    const borrowed_fixed = try borrowed.fixedColumns(a);
    defer a.free(borrowed_fixed);
    try std.testing.expectEqual(owned_fixed.len, borrowed_fixed.len);
    for (owned_fixed, borrowed_fixed) |owned, view| try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, owned.values, view.values);
    const batch = @import("../rv64_full.zig").Trace.CallBatch{ .keccak = kcalls, .secp = scalls };
    var trace = try Service.Trace.initEthereum(a, records, batch, public, &setup.materials);
    defer trace.deinit();
    try std.testing.expectEqual(@as(u32, 28), trace.cpu.secp.?.rows[1][0].previous_clocks[0]);
    var tape = try rv.compact_tape.Tape.init(a, program.len, pc, 1 << 40, profile);
    defer tape.deinit();
    var k_at: usize = 0;
    var s_at: usize = 0;
    for (records) |record| {
        if (record.opcode == .ECALL and record.rhs.toInt() == keccak_tag) {
            var call = kcalls[k_at];
            call.clock += tape.initial_clock;
            try tape.appendService(call);
            k_at += 1;
        } else if (record.opcode == .ECALL) {
            var call = scalls[s_at];
            call.clock += tape.initial_clock;
            try tape.appendSecp(call);
            s_at += 1;
        } else {
            var global = record;
            global.clock += tape.initial_clock;
            try tape.append(global);
        }
    }
    var compact = try Service.Trace.initCompact(a, &tape, public, &setup.materials);
    defer compact.deinit();
    try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, trace.cpu.main, compact.cpu.main);
    for (0..2) |kind| {
        try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, trace.secp.groups[kind].?.product.main, compact.secp.groups[kind].?.product.main);
        try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, trace.secp.groups[kind].?.bridge.main, compact.secp.groups[kind].?.bridge.main);
    }
    var bundle = try Service.proveTrace(a, &setup, public, &trace);
    defer bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    var compact_bundle = try Service.proveTrace(a, &setup, public, &compact);
    defer compact_bundle.deinit(a);
    const compact_encoded = try wire.encodeProofBytesBinary(a, compact_bundle.proof);
    defer a.free(compact_encoded);
    try std.testing.expectEqualSlices(u8, encoded, compact_encoded);
    const artifact = std.process.getEnvVarOwned(a, if (profile == .ethereum_services_v1) "STWO_RV64_ETH_CPU_V1_ARTIFACT_DIR" else "STWO_RV64_ETH_CPU_V2_ARTIFACT_DIR") catch null;
    defer if (artifact) |path| a.free(path);
    if (artifact) |path| {
        try std.fs.cwd().makePath(path);
        var directory = try std.fs.cwd().openDir(path, .{});
        defer directory.close();
        const public_json = try std.json.Stringify.valueAlloc(a, public, .{});
        defer a.free(public_json);
        const claims_json = try std.json.Stringify.valueAlloc(a, bundle.claims, .{});
        defer a.free(claims_json);
        try directory.writeFile(.{ .sub_path = "public.json", .data = public_json });
        try directory.writeFile(.{ .sub_path = "claims.json", .data = claims_json });
        try directory.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
        const cpu_main = setup.materials.base.plan.main_count;
        const secp_interaction = trace.cpu.interactionCount() + 24;
        const openings = [_]struct { name: []const u8, tree: usize, column: usize }{
            .{ .name = "bad-add-counter.bin", .tree = 1, .column = cpu_main + air.full.frame.SECP_COUNTERS },
            .{ .name = "bad-double-counter.bin", .tree = 1, .column = cpu_main + air.full.frame.SECP_COUNTERS + 1 },
            .{ .name = "bad-secp-prefix.bin", .tree = 2, .column = secp_interaction },
        };
        for (openings) |opening| {
            var bad = try wire.decodeProofBytesBinary(a, encoded);
            defer bad.deinit(a);
            const samples = bad.commitment_scheme_proof.sampled_values.items[opening.tree][opening.column];
            try std.testing.expectEqual(@as(usize, 2), samples.len);
            samples[1] = samples[1].add(Q.one());
            const corrupt = try wire.encodeProofBytesBinary(a, bad);
            defer a.free(corrupt);
            try directory.writeFile(.{ .sub_path = opening.name, .data = corrupt });
        }
    }
    var receiver = try Service.PreparedSetup.init(a, public);
    defer receiver.deinit();
    try receiver.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var wrong = bundle.claims;
    wrong.secp_header = wrong.secp_header.add(Q.one());
    wrong.secp_add.bridge = wrong.secp_add.bridge.sub(Q.one());
    try std.testing.expectError(error.OodsNotMatching, receiver.verifyOwned(a, public, wrong, try wire.decodeProofBytesBinary(a, encoded)));
}
