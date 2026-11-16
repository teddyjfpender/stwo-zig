//! Real host acceptance authorities over host-model device memory, not CUDA execution.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const E = @import("outer_encode.zig");
const Fixture = @import("outer_encode_test.zig");
const Fault = @import("outer_fault_write.zig");
const Checks = @import("outer_checks.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;

pub const Pcs = struct {
    desc: []u32,
    image: []u32,
    pub fn init(a: std.mem.Allocator) !Pcs {
        const trees = [_]E.TreeShape{.{ .coefficient_logs = &.{2}, .sorted_to_original = &.{0}, .sample_counts = &.{1} }};
        const desc = try E.buildDescriptor(a, .{ .config = .{ .pow_bits = 20, .log_blowup = 1, .log_last_layer = 0, .n_queries = 1, .fold_step = 1, .lifting = null }, .degree_log = 2, .trees = &trees }, null, null);
        errdefer a.free(desc);
        const image = try Fixture.Synth.image(a, desc, &.{1}, 19);
        return .{ .desc = desc, .image = image };
    }
    pub fn deinit(self: *Pcs, a: std.mem.Allocator) void {
        a.free(self.image);
        a.free(self.desc);
        self.* = undefined;
    }
    fn fill(_: *anyopaque, dst: *anyopaque, byte: c_int, count: usize) callconv(.c) c_int {
        const out: [*]u8 = @ptrCast(dst);
        @memset(out[0..count], @intCast(byte));
        return 0;
    }
    /// The worker owns this arena allocation until the request is quiescent.
    pub fn run(self: *Pcs, a: std.mem.Allocator, e: *api.Enqueue, inject: bool) !u32 {
        const image = try e.alloc(self.image.len);
        defer e.free(image);
        @memcpy(image.ptr[0..image.words], self.image);
        if (inject) try Fault.pcs(e.ctx(), fill, image, E.Image.of(self.desc).terminal);
        const out = try a.alloc(u32, self.desc[E.D.max_payload_words] + 1);
        defer a.free(out);
        const verdict = try E.encodeHost(a, self.desc, image.ptr[0..image.words], .{}, out);
        if (!inject and (verdict.pcs != G.Verdict.accepted or verdict.bounds != G.Verdict.accepted)) return error.FaultFixtureBaselineRejected;
        if (inject and verdict.pcs != G.Verdict.reject(.node_pcs_status, @intFromEnum(E.PcsDetail.noncanonical))) return error.FaultFixtureWrongPcsRejection;
        return verdict.pcs;
    }
};

fn base(value: u32) O {
    return O.fromBase(M.fromCanonical(value));
}
/// Independent logarithmic-derivative tuple evaluation using Core OM31.
fn term(constants: Checks.LookupConstants, index: u32, value: [4]u32) !O {
    const tuple = [_]u32{ constants.relation, index, value[0], value[1], value[2], value[3] };
    var denominator = O.zero();
    var power = O.one();
    for (tuple) |word| {
        denominator = denominator.add(power.mul(base(word)));
        power = power.mul(base(17));
    }
    return denominator.sub(base(1009)).inv();
}

pub fn lookup(inject: bool) !u32 {
    const static = Checks.LookupStatic{ .relation = 378353459, .u_index = 2, .u_value = .{ 0, 0, 1, 0 } };
    const good = Checks.constants(static, 1, 1, 7, false);
    const actual = Checks.constants(static, 1, 1, 7, inject);
    const output = [4]u32{ 1, 2, 3, 4 };
    const output_term = try term(good, good.u_index + 1, output);
    const claim = (try term(good, good.u_index, good.u_value)).add(output_term).neg();
    const sum = claim.add(output_term).add(try term(actual, actual.u_index, actual.u_value));
    return if (sum.isZero()) G.Verdict.accepted else G.Verdict.reject(.lookup_sum, 5);
}

test "typed lookup fault violates real rational closure while baseline closes" {
    try std.testing.expectEqual(G.Verdict.accepted, try lookup(false));
    try std.testing.expectEqual(G.Verdict.reject(.lookup_sum, 5), try lookup(true));
}

test "typed PCS authority fixture construction preserves allocation ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, construct, .{});
}
fn construct(a: std.mem.Allocator) !void {
    var pcs = try Pcs.init(a);
    defer pcs.deinit(a);
}
