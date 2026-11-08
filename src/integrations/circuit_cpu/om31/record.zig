//! Cold native OM31 polynomial artifact for the original circuit AIR. This is
//! executable generation, not proof or key admission: callers must select the
//! component from the independently pinned/bound Authority. Roots are bounded
//! groups to keep CUDA compiler work bounded. Live parameters are never aliases.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const E = @import("program.zig");
const P = @import("protocol.zig");
const Air = @import("../air.zig");
const Comp = @import("geometry.zig").Component;
const IR = Engine.air.secure_polynomial_program_v2;
const Builder = IR.BuilderFor(P.O);
pub const MAX_ROOTS: u32 = 16;
threadlocal var active: ?*Builder = null;
const Lane = struct {
    pub const rv64_extension_degree = 8;
    id: u32,
    fn builder() *Builder {
        return active orelse @panic("outer AIR recorder outside recording");
    }
    pub fn fromM31Array(value: [8]P.M) Lane {
        return .{ .id = builder().constant(P.O.fromM31Array(value)) };
    }
    pub fn fromBase(value: P.M) Lane {
        return .{ .id = builder().constant(P.O.fromBase(value)) };
    }
    pub fn zero() Lane {
        return fromBase(P.M.zero());
    }
    pub fn one() Lane {
        return fromBase(P.M.one());
    }
    pub fn add(a: Lane, b: Lane) Lane {
        return .{ .id = builder().add(a.id, b.id) };
    }
    pub fn sub(a: Lane, b: Lane) Lane {
        return .{ .id = builder().sub(a.id, b.id) };
    }
    pub fn mul(a: Lane, b: Lane) Lane {
        return .{ .id = builder().mul(a.id, b.id) };
    }
    pub fn neg(a: Lane) Lane {
        return .{ .id = builder().neg(a.id) };
    }
    pub fn inv(_: Lane) Lane {
        if (builder().failure == null) builder().failure = error.NonPolynomialOuterInverse;
        return zero();
    }
    pub fn fromPartialEvals(values: [8]Lane) Lane {
        var result = zero();
        for (values, 0..) |value, i| {
            var basis: [8]P.M = @splat(P.M.zero());
            basis[i] = P.M.one();
            result = result.add(value.mul(fromM31Array(basis)));
        }
        return result;
    }
    fn get(_: *const anyopaque, tree: u8, column: u32, offset: i32) !Lane {
        const shift = std.math.cast(i8, offset) orelse return error.OuterMaskOffsetTooLarge;
        return .{ .id = builder().input(.{ .tree = tree, .column = column, .offset = shift }) };
    }
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    program: IR.ProgramFor(P.O),
    parameter_slots: []u32,
    original_parameter_count: usize,
    root_start: u32,
    root_count: u32,
    pub fn deinit(self: *Artifact) void {
        self.program.deinit();
        self.allocator.free(self.parameter_slots);
        self.* = undefined;
    }
    pub fn parameters(self: *const Artifact, a: std.mem.Allocator, original: []const P.O) ![]P.O {
        if (original.len != self.original_parameter_count) return error.InvalidOuterArtifactParameters;
        const values = try a.alloc(P.O, self.parameter_slots.len);
        for (values, self.parameter_slots) |*value, slot| value.* = original[slot];
        return values;
    }
};
pub fn record(a: std.mem.Allocator, component: *const Comp, part_index: usize, root_start: u32, root_count: u32) !Artifact {
    if (active != null) return error.OuterRecordingAlreadyActive;
    if (part_index >= component.parts.len or root_count == 0 or root_count > MAX_ROOTS) return error.InvalidOuterRootGroup;
    const source = component.parts[part_index].program;
    if (root_start > source.constraint_roots.len or root_count > source.constraint_roots.len - root_start) return error.InvalidOuterRootGroup;
    try E.validateLens(a, source);
    var builder = Builder.init(a);
    defer builder.deinit();
    active = &builder;
    defer active = null;
    const parameters = try a.alloc(Lane, component.ext_sources.len);
    defer a.free(parameters);
    for (parameters, 0..) |*value, i| value.* = .{ .id = builder.parameter(P.O.fromBase(P.M.fromU64(i + 1))) };
    const Eval = E.ForLane(Lane);
    const roots = try Eval.evaluate(a, source, .{ .context = &builder, .get = Lane.get }, parameters);
    defer a.free(roots);
    const ids = try a.alloc(u32, root_count);
    defer a.free(ids);
    for (ids, roots[root_start..][0..root_count]) |*id, value| id.* = value.id;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/circuit/om31/original-air-polynomial/v1\x00");
    hash.update(Air.bundle_sha256);
    var metadata: [20]u8 = undefined;
    std.mem.writeInt(u64, metadata[0..8], source.semanticHash(), .little);
    std.mem.writeInt(u32, metadata[8..12], @intCast(part_index), .little);
    std.mem.writeInt(u32, metadata[12..16], root_start, .little);
    std.mem.writeInt(u32, metadata[16..20], root_count, .little);
    hash.update(&metadata);
    var program = try builder.finish(hash.finalResult(), ids);
    errdefer program.deinit();
    const slots = try a.alloc(u32, program.parameters.len);
    errdefer a.free(slots);
    for (slots, program.parameters) |*slot, value| {
        const coordinates = value.toM31Array();
        if (coordinates[0].v == 0 or coordinates[0].v > parameters.len) return error.InvalidOuterParameterSlot;
        for (coordinates[1..]) |coordinate| if (!coordinate.isZero()) return error.InvalidOuterParameterSlot;
        slot.* = coordinates[0].v - 1;
    }
    return .{ .allocator = a, .program = program, .parameter_slots = slots, .original_parameter_count = parameters.len, .root_start = root_start, .root_count = root_count };
}
