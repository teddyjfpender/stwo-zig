//! Explicit verifier identity for the reduced native-GKR interaction layout.
//! T_nat classes and producer statements must call this same helper before
//! constructing NativeVk; old strict/classic class hashes remain untouched.
const std = @import("std");
const Canon = @import("../native_schema/canonical.zig");
const V2 = @import("v2.zig");
const R = @import("roster.zig");
pub const DOMAIN = "rv64/native-gkr/reduced-air-class/v2";
pub fn structure(a: std.mem.Allocator, canonical_structure: [32]u8, roster: *const R.Roster) ![32]u8 {
    try V2.validate(roster);
    var h = Canon.Hasher.init(.structure_v2);
    var tag: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(DOMAIN, &tag, .{});
    h.digest(tag);
    h.digest(canonical_structure);
    h.words(&V2.identityWords());
    h.words(&.{ V2.VERSION, R.BINDING_BASE_COLUMNS, V2.LOCAL_RELATIONS, R.KINDS });
    const header = try roster.header(a);
    defer a.free(header);
    h.words(header);
    return h.final();
}

test "native GKR verifier identity binds mode and every exact query group" {
    const a = std.testing.allocator;
    const base: [32]u8 = @splat(7);
    var specs = [_]R.ComponentSpec{.{ .origin = .{ 0, 0 }, .row_log = 5, .terms = .{ 3, 2, 0, 0 } }};
    var first = try V2.derive(a, &specs);
    defer first.deinit();
    const expected = try structure(a, base, &first);
    try std.testing.expect(!std.mem.eql(u8, &base, &expected));
    specs[0].terms[0] = 4;
    var second = try V2.derive(a, &specs);
    defer second.deinit();
    try std.testing.expect(!std.mem.eql(u8, &expected, &try structure(a, base, &second)));
    // Counts 3 and4 have the same lane_log: hashing just the padded height
    // would admit a different original fraction emitter under one class key.
    try std.testing.expectEqual(first.instances[0].lane_log, second.instances[0].lane_log);
}

fn appendSpans(h: *Canon.Hasher, plan: *const @import("native_roster.zig").Plan) void {
    for (plan.spans) |span| {
        h.int64(span.fixed_offset);
        h.int64(span.main_offset);
        h.int64(span.inter_offset);
        h.int64(span.fixed);
        h.int64(span.main);
        h.int64(span.constraints);
        // Binding v1 masks: Eq at (0,+2), prefix at (0,-1);
        // each secure column has eight base coordinates.
        h.words(&.{ span.degree, span.split, span.max_main_samples, 1, 0, 2, 0, 0xFFFFFFFF, 0, 8, 8, 8 });
    }
}
/// No caller-supplied census: both helpers derive it from immutable setup.
pub fn cpuStructure(a: std.mem.Allocator, canonical_structure: [32]u8, setup: *const @import("../roster.zig").CpuSetup) ![32]u8 {
    var plan = try @import("native_roster.zig").cpu(a, setup);
    defer plan.deinit();
    var h = Canon.Hasher.init(.structure_v2);
    h.digest(try structure(a, canonical_structure, &plan.roster));
    appendSpans(&h, &plan);
    const caps = try @import("source_admission.zig").cpuClassCaps(a, setup);
    @import("source_admission.zig").emitClassCaps(&caps, &h);
    return h.final();
}
pub fn truthStructure(a: std.mem.Allocator, canonical_structure: [32]u8, d: @import("../wire.zig").TruthDeclaration) ![32]u8 {
    var plan = try @import("native_roster.zig").truth(a, d);
    defer plan.deinit();
    var h = Canon.Hasher.init(.structure_v2);
    h.digest(try structure(a, canonical_structure, &plan.roster));
    appendSpans(&h, &plan);
    const caps = try @import("source_admission.zig").truthClassCaps(a, d);
    @import("source_admission.zig").emitClassCaps(&caps, &h);
    return h.final();
}

test "native class structure public factories are fully typed" {
    try std.testing.expect(@intFromPtr(&cpuStructure) != 0);
    const actual = try truthStructure(std.testing.allocator, @splat(11), .{ .family = .sha256, .first_id = 1, .calls = 1, .logs = .{ 10, 0 } });
    try std.testing.expect(!std.mem.eql(u8, &actual, &@as([32]u8, @splat(11))));
}
