const std = @import("std");
const F = @import("../fixture.zig");
const Coordinator = @import("coordinator.zig");
const Wire = @import("../wire.zig");
const P = @import("../protocol.zig");
const Bounds = @import("source_bounds.zig");
const Relation = @import("fractions.zig").Relation;
const a = std.testing.allocator;
fn lifecycle(allocator: std.mem.Allocator, program_log: u32, cpu: []const Wire.CpuDeclaration, truth: []const Wire.TruthDeclaration, requests: []const P.Request) !void {
    var report = try Bounds.derive(allocator, program_log, cpu, truth, requests);
    defer report.deinit();
    try std.testing.expect(!report.security_qualified and !report.transcript_round_bound_qualified);
}
test "source admission derives geometry and signed/support bounds without constructing keys" {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    const natives = [_]*@import("../../../word16_execution/prepared.zig").Prepared{ &captured.native[0], &captured.native[1] };
    var requests: [2]P.Request = undefined;
    for (&requests, 0..) |*request, i| request.* = try Coordinator.requestView(&natives, &captured.advice, i);
    const cpu = [_]Wire.CpuDeclaration{
        .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{ .keccak = 5 } },
        .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{ .add = 5, .double = 5 } },
    };
    const A = @import("stwo_riscv_frontend").rv64_air;
    const program = A.crypto.secp256k1.program;
    const layout = A.crypto.secp256k1.layout;
    const truth = [_]Wire.TruthDeclaration{
        .{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, 0 } },
        .{ .family = .add, .first_id = 1, .calls = 1, .logs = .{ try layout.logSize(.product, program.get(.add), 1), try layout.logSize(.linear, program.get(.add), 1) } },
        .{ .family = .double, .first_id = 1, .calls = 1, .logs = .{ try layout.logSize(.product, program.get(.double), 1), try layout.logSize(.linear, program.get(.double), 1) } },
    };
    var report = try Bounds.derive(a, captured.program.log_size, &cpu, &truth, &requests);
    defer report.deinit();
    try std.testing.expectEqual(@as(usize, 5), report.shape.native_proofs);
    try std.testing.expectEqual(@as(u32, 16), report.shape.max_trace_log);
    try std.testing.expectEqual(@as(u8, 5), report.shape.max_air_degree);
    try std.testing.expectEqual(@as(usize, 5), report.shape.max_samples_per_column);
    try std.testing.expectEqual(report.global_signed.ram.positive, report.global_signed.ram.negative);
    try std.testing.expectEqual(report.global_signed.kio.positive, report.global_signed.kio.negative);
    try std.testing.expectEqual(report.global_signed.wire.positive, report.global_signed.wire.negative);
    const function = report.cpu_scopes[0].relations[@intFromEnum(Relation.function)];
    try std.testing.expectEqual(Bounds.Model.unit_membership_valid_support, function.model);
    try std.testing.expect(function.unit_consumer_mass > 0 and function.valid_provider_support > 0);
    try std.testing.expectEqual(@as(u64, 0), function.unit_negative_mass);
    try std.testing.expect(report.global_denominator_slots[0] > report.global_signed.ram.positive);
    try std.testing.expect(report.conditional_degrees.poles > 0 and report.conditional_degrees.rational_identity > 0);
    try report.conditional_degrees.requireLookupOnlyBits(128);
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, report.conditional_degrees.requireLookupOnlyBits(256));
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{ captured.program.log_size, &cpu, &truth, &requests });
    var bad = cpu;
    bad[0].geometry.cpu_log = 23;
    if (Bounds.derive(a, captured.program.log_size, &bad, &truth, &requests)) |accepted| {
        var owner = accepted;
        owner.deinit();
        return error.AcceptedOversizedCandidateShape;
    } else |_| {}
    var too_padded = truth;
    too_padded[0].logs[0] = 21;
    try std.testing.expectError(error.CandidateCharacteristicBoundExceeded, Bounds.derive(a, captured.program.log_size, &cpu, &too_padded, &requests));
    var changed = requests;
    changed[0].calls[0] = 100000;
    if (Bounds.derive(a, captured.program.log_size, &cpu, &truth, &changed)) |accepted| {
        var owner = accepted;
        owner.deinit();
        return error.AcceptedOversizedCandidateCounts;
    } else |_| {}
    // No honest constructor's provider weights are used to manufacture an
    // ordinary negative-mass certificate in this source-derived admission.
    try std.testing.expect(!report.security_qualified and !report.secp_polynomial_error_budget_qualified);
}

test "weighted FUNCTION yields never weight or suppress auxiliary range AND SHIFT queries" {
    const core = @import("stwo_core");
    const A = @import("stwo_riscv_frontend").rv64_air;
    const M = core.fields.m31.M31;
    const Main = A.main_only.authority;
    const Raw = @import("fractions.zig");
    const Role = @import("role.zig");
    const Sink = struct {
        function_weight: M = M.zero(),
        functions: usize = 0,
        auxiliaries: usize = 0,
        invalid_auxiliary_weight: bool = false,
        pub fn emit(self: *@This(), relation: Raw.Relation, _: anytype, weight: M) void {
            if (relation == .function) {
                self.function_weight = weight;
                self.functions += 1;
            } else {
                self.auxiliaries += 1;
                if (!weight.eql(M.one())) self.invalid_auxiliary_weight = true;
            }
        }
    };
    for ([_]Main.Role{ .alu, .binary, .shift }) |kind| {
        const shape = Main.shape(kind);
        for ([_]u32{ 0, 1, core.fields.m31.Modulus - 1 }) |multiplicity| {
            // Zero/inactive raw polynomial inputs intentionally exercise padding
            // too. This is an emitter property, not an accepted MAIN witness.
            const fixed = [_]M{M.zero()} ** 3;
            var main = [_]M{M.zero()} ** 128;
            main[shape.main - 1] = M.fromCanonical(multiplicity);
            var sink = Sink{};
            Role.emitLocalFor(M, kind, fixed[0..shape.fixed], main[0..shape.main], M.zero(), &sink);
            try std.testing.expectEqual(@as(usize, 1), sink.functions);
            try std.testing.expect(sink.function_weight.eql(M.fromCanonical(multiplicity).neg()));
            try std.testing.expect(sink.auxiliaries > 0 and !sink.invalid_auxiliary_weight);
        }
    }
}
test "valid support handles wrapped split provider weights without inventing negative integer mass" {
    const core = @import("stwo_core");
    const O = core.fields.om31.OM31;
    const M = core.fields.m31.M31;
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const challenges = @import("challenges.zig").For(O).draw(&channel);
    var valid = [_]M{M.zero()} ** 13;
    valid[1] = M.one();
    valid[5] = M.fromCanonical(2);
    valid[9] = M.fromCanonical(3);
    var invalid = valid;
    invalid[9] = M.fromCanonical(4);
    const good = challenges.denominatorBase(.function, &valid);
    const bad = challenges.denominatorBase(.function, &invalid);
    try std.testing.expect(!good.isZero() and !bad.isZero() and !good.eql(bad));
    const first = M.fromCanonical(core.fields.m31.Modulus - 1);
    const second = M.fromCanonical(2);
    try std.testing.expect(@as(u64, first.v) + second.v >= core.fields.m31.Modulus);
    const supplied = (try O.fromBase(first).div(good)).add(try O.fromBase(second).div(good));
    try std.testing.expect((try O.one().div(good)).sub(supplied).isZero());
    try std.testing.expect(!(try O.one().div(bad)).sub(supplied).isZero());
    // This is exact rational arithmetic, not an authenticated execution proof.
    // Physical validity of support and unit-count<p are separate premises.
}
