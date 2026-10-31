//! Optional pure-function truth instances. Native partitions are transport
//! choices; only committed truth membership and the closed FUNCTION bus prove
//! execution. Physical lookup padding is never weighted by FUNCTION multiplicity.
const std = @import("std");
const core = @import("stwo_core");
const B = @import("stwo_riscv_frontend").rv64_air.word16_v1;
const G = @import("geometry.zig");
const Prepared = @import("prepared.zig").Prepared;
const P = @import("protocol.zig");
const Profile = @import("stwo_prover_api").stage_profile;
const Q = core.fields.qm31.QM31;
pub const Splits = struct { alu: G.FactCounts, binary: G.FactCounts, shift: G.FactCounts };
/// Before CPU transfer or any provider allocation, validate whole-family mass;
/// splitting must not turn one forbidden >=p mass into two apparently valid ones.
pub fn validate(g: G.Geometry, prepared: *const Prepared) !Splits {
    weights(prepared.alu.facts.len, prepared.alu.weights) catch |err| return switch (err) {
        error.InvalidProviderWeights => error.InvalidAluWeights,
        error.ProviderMultiplicityMassExceeded => error.AluMultiplicityMassExceeded,
        else => err,
    };
    weights(prepared.binary.facts.len, prepared.binary.weights) catch |err| return switch (err) {
        error.InvalidProviderWeights => error.InvalidBinaryWeights,
        error.ProviderMultiplicityMassExceeded => error.BinaryMultiplicityMassExceeded,
        else => err,
    };
    if (prepared.shift_weights.len != 0) weights(prepared.shift.len, prepared.shift_weights) catch |err| return switch (err) {
        error.InvalidProviderWeights => error.InvalidShiftWeights,
        error.ProviderMultiplicityMassExceeded => error.ShiftMultiplicityMassExceeded,
        else => err,
    };
    return .{
        .alu = try G.factCounts(prepared.alu.facts.len, g.alu_log, g.alu_tail_log),
        .binary = try G.factCounts(prepared.binary.facts.len, g.binary_log, g.binary_tail_log),
        .shift = try G.factCounts(prepared.shift.len, g.shift_log, g.shift_tail_log),
    };
}
pub fn weights(count: usize, values: []const u32) !void {
    if (values.len != count) return error.InvalidProviderWeights;
    var mass: u64 = 0;
    for (values) |value| {
        if (value >= core.fields.m31.Modulus) return error.InvalidProviderWeights;
        mass = try std.math.add(u64, mass, value);
        if (mass >= core.fields.m31.Modulus) return error.ProviderMultiplicityMassExceeded;
    }
}
pub const Tails = struct {
    alu: ?B.alu_experiment.source.Source = null,
    binary: ?B.binary_source.Source = null,
    shift: ?B.shift_word_packed_experiment.source.Source = null,
    pub fn init(a: std.mem.Allocator, g: G.Geometry, prepared: *const Prepared, splits: Splits, recorder: ?*Profile.Recorder) !Tails {
        var result = Tails{};
        errdefer result.deinit();
        if (g.alu_tail_log) |log| {
            var stage = try Profile.StageScope.begin(recorder, "source_alu_tail", "ALU tail witness");
            defer stage.end();
            result.alu = try B.alu_experiment.source.Source.initWeighted(a, prepared.alu.facts[splits.alu.head..], prepared.alu.weights[splits.alu.head..], log);
        }
        if (g.binary_tail_log) |log| {
            var stage = try Profile.StageScope.begin(recorder, "source_binary_tail", "BINARY tail witness");
            defer stage.end();
            result.binary = try B.binary_source.Source.initWeighted(a, prepared.binary.facts[splits.binary.head..], prepared.binary.weights[splits.binary.head..], log);
        }
        if (g.shift_tail_log) |log| {
            var stage = try Profile.StageScope.begin(recorder, "source_shift_tail", "SHIFT tail witness");
            defer stage.end();
            result.shift = if (prepared.shift_weights.len != 0)
                try B.shift_word_packed_experiment.source.Source.initWeighted(a, prepared.shift[splits.shift.head..], prepared.shift_weights[splits.shift.head..], log)
            else
                try B.shift_word_packed_experiment.source.Source.init(a, prepared.shift[splits.shift.head..], log);
        }
        return result;
    }
    pub fn deinit(self: *Tails) void {
        inline for (.{ "alu", "binary", "shift" }) |name| if (@field(self, name)) |*tail| tail.deinit();
        self.* = .{};
    }
    pub fn releaseMain(self: *Tails) void {
        inline for (.{ "alu", "binary", "shift" }) |name| if (@field(self, name)) |*tail| tail.releaseMain();
    }
    pub fn releaseInteraction(self: *Tails, a: std.mem.Allocator) void {
        inline for (.{ "alu", "binary", "shift" }) |name| if (@field(self, name)) |*tail| {
            a.free(tail.interaction);
            tail.interaction = &.{};
        };
    }
    pub const Claims = struct {
        alu: @FieldType(P.Claims, "alu_tail") = .{ .range16 = Q.zero(), .function = Q.zero() },
        binary: @FieldType(P.Claims, "binary_tail") = .{ .and_ = Q.zero(), .function = Q.zero() },
        shift: @FieldType(P.Claims, "shift_tail") = .{ .shift = Q.zero(), .range16 = Q.zero(), .function = Q.zero() },
    };
    pub fn generate(self: *Tails, ch: P.Draw, range: []const Q, shifts: []const Q, recorder: ?*Profile.Recorder) !Claims {
        var result = Claims{};
        const old = P.legacy(ch.cpu);
        if (self.alu) |*tail| {
            var stage = try Profile.StageScope.begin(recorder, "inter_alu_tail", "ALU tail interactions");
            defer stage.end();
            result.alu = try tail.generate(.{ .function = old.function, .range16 = old.range16 }, range);
        }
        if (self.binary) |*tail| {
            var stage = try Profile.StageScope.begin(recorder, "inter_binary_tail", "BINARY tail interactions");
            defer stage.end();
            result.binary = try tail.generate(.{ .function = old.function, .and_ = ch.and_ });
        }
        if (self.shift) |*tail| {
            var stage = try Profile.StageScope.begin(recorder, "inter_shift_tail", "SHIFT tail interactions");
            defer stage.end();
            result.shift = try tail.generate(.{ .function = old.function, .range16 = old.range16, .shift = ch.shift_ }, shifts, range);
        }
        return result;
    }
};
