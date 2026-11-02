//! v3 secp256k1 `row_v1` truth qualification on the combined-services
//! fixture (Keccak-f, then secp ADD and DOUBLE on the raw Keccak output words,
//! so most coordinates are >= p and enter by residue): real CPU, bridge and
//! truth proofs, fresh receiver keys over the durable wire, and rejection by
//! RCB-profile, wrong-kind and wrong-size receivers, forged outputs and
//! nonzero unused claim slots.
const std = @import("std");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const G = @import("../protocol.zig");
const KR = @import("../keccak/shared/roster.zig");
const SR = @import("../secp/roster.zig");
const Row = @import("../secp/row_roster.zig");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const a = std.testing.allocator;
const LOG = A.crypto.curves.layout.MIN_LOG;

const Case = struct {
    setups: [2]R.CpuSetup,
    keccak: KR.TruthSetup,
    add: Row.TruthSetup,
    double: Row.TruthSetup,
    bundle: E.Bundle,
    identity: [32]u8,
    fn truths(self: *const Case) [3]R.Truth {
        return .{ .{ .keccak = .{ .setup = &self.keccak, .first_id = 1, .calls = 1 } }, .{ .secp_row = .{ .setup = &self.add, .first_id = 1, .calls = 1 } }, .{ .secp_row = .{ .setup = &self.double, .first_id = 1, .calls = 1 } } };
    }
    fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ &self.setups[0], &self.setups[1] };
    }
    fn deinit(self: *Case) void {
        self.bundle.deinit(a);
        self.keccak.deinit();
        self.add.deinit();
        self.double.deinit();
        for (&self.setups) |*s| s.deinit();
    }
};
/// `out` must not move after init (truths point into it).
fn initCase(out: *Case, wrong_output: bool) !void {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    if (wrong_output) {
        captured.advice.secp[1][1][0].after[1] ^= 1;
        captured.advice.terminal[1].state.value ^= 1;
    }
    out.setups[0] = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try captured.native[0].geometry(), .{ .keccak = 5 });
    errdefer out.setups[0].deinit();
    out.setups[1] = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try captured.native[1].geometry(), .{ .add = 5, .double = 5 });
    errdefer out.setups[1].deinit();
    out.keccak = try KR.TruthSetup.init(a, 5);
    errdefer out.keccak.deinit();
    out.add = try Row.TruthSetup.init(a, .add, LOG);
    errdefer out.add.deinit();
    out.double = try Row.TruthSetup.init(a, .double, LOG);
    errdefer out.double.deinit();
    out.identity = captured.program.identity;
    const truths = out.truths();
    out.bundle = try E.produce(a, &.{ &out.setups[0], &out.setups[1] }, &truths, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, F.expectedFor(captured.program.identity));
}

test "v3 secp row truths: ADD and DOUBLE on raw coordinates verify with fresh keys over the wire" {
    var c: Case = undefined;
    try initCase(&c, false);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.truths();
    const expected = F.expectedFor(c.identity);
    try E.verify(a, &keys, &truths, expected, &c.bundle);
    // Two CPU proofs plus three single-component truths.
    try std.testing.expectEqual(@as(usize, 5), c.bundle.manifest.roots.len);
    for (c.bundle.truths[1..]) |t| for (t.claims[1..]) |claim| try std.testing.expect(claim.isZero());

    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try W.write(a, temp.dir, &keys, &truths, &c.bundle);
    var loaded = try W.read(a, temp.dir, .{ .max_cpus = 2, .max_truths = 3, .max_total_steps = 7 });
    defer loaded.deinit(a);
    for (loaded.truth_declarations[1..], [_]@import("types.zig").Family{ .add, .double }) |d, family| {
        try std.testing.expectEqual(family, d.family);
        try std.testing.expectEqual([2]u32{ LOG, Row.PROFILE_WORD }, d.logs);
        try std.testing.expect(W.isSecpRow(d));
    }
    try std.testing.expect(!W.isSecpRow(loaded.truth_declarations[0]));
    // Fresh, independently constructed receiver keys from the declarations.
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, loaded.cpu_declarations[0].bridges);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, loaded.cpu_declarations[1].bridges);
    defer s1.deinit();
    var kt = try KR.TruthSetup.init(a, 5);
    defer kt.deinit();
    var at = try Row.TruthSetup.init(a, .add, loaded.truth_declarations[1].logs[0]);
    defer at.deinit();
    var dt = try Row.TruthSetup.init(a, .double, loaded.truth_declarations[2].logs[0]);
    defer dt.deinit();
    const fresh = [_]R.Truth{ .{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = 1 } }, .{ .secp_row = .{ .setup = &at, .first_id = 1, .calls = 1 } }, .{ .secp_row = .{ .setup = &dt, .first_id = 1, .calls = 1 } } };
    try E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle);

    // An RCB-profile receiver (product/linear/BYTE keys) rejects the row bundle.
    var rcb_add = try SR.TruthSetup.init(a, .add, .{ try S.layout.logSize(.product, &S.program.add, 1), try S.layout.logSize(.linear, &S.program.add, 1) });
    defer rcb_add.deinit();
    var rcb_double = try SR.TruthSetup.init(a, .double, .{ try S.layout.logSize(.product, &S.program.double, 1), try S.layout.logSize(.linear, &S.program.double, 1) });
    defer rcb_double.deinit();
    const rcb = [_]R.Truth{ fresh[0], .{ .secp = .{ .setup = &rcb_add, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = &rcb_double, .first_id = 1, .calls = 1 } } };
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &rcb, expected, &loaded.bundle)));
    // Swapped kinds (a DOUBLE key for the ADD span) and a larger key are other statements.
    const swapped = [_]R.Truth{ fresh[0], .{ .secp_row = .{ .setup = &dt, .first_id = 1, .calls = 1 } }, .{ .secp_row = .{ .setup = &at, .first_id = 1, .calls = 1 } } };
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &swapped, expected, &loaded.bundle)));
    var big = try Row.TruthSetup.init(a, .add, LOG + 1);
    defer big.deinit();
    const resized = [_]R.Truth{ fresh[0], .{ .secp_row = .{ .setup = &big, .first_id = 1, .calls = 1 } }, fresh[2] };
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &resized, expected, &loaded.bundle)));
    // Claim slots unused by the single row component are pinned to zero.
    loaded.bundle.truths[1].claims[2] = G.Q.one();
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle));
}

test "v3 secp row truth adversarial: a false DOUBLE output word does not close Wire35" {
    var c: Case = undefined;
    try initCase(&c, true);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.truths();
    try std.testing.expectError(error.UnclosedCombinedSecpWire, E.verify(a, &keys, &truths, F.expectedFor(c.identity), &c.bundle));
}

test "secp row wire profile: logs[1] = 0 selects the row truth, any valid RCB linear log does not" {
    const T = @import("types.zig");
    try std.testing.expect(W.isSecpRow(.{ .family = .add, .first_id = 1, .calls = 1, .logs = .{ 8, 0 } }));
    try std.testing.expect(!W.isSecpRow(.{ .family = .add, .first_id = 1, .calls = 1, .logs = .{ 8, 5 } }));
    try std.testing.expect(!W.isSecpRow(.{ .family = T.Family.sha256, .first_id = 1, .calls = 1, .logs = .{ 8, 0 } }));
    // An RCB linear log is never 0 (validate requires >= 5).
    try std.testing.expectError(error.InvalidSecpGeometry, S.layout.validate(.linear, &S.program.add, 1, 1, 0));
}
