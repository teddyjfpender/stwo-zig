//! Cold recording of a full CPU-shard role: native MAIN, authenticated local
//! terminal binding, and classic global obligations. Not a proof controller.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
pub const Authority = @import("stwo_riscv_cpu_integration").rv64_gkr_constraints;
pub const Source = Authority.Source;
const C = @import("composition_codegen.zig");
const X = @import("symbolic_external.zig");
const F = X.Lane;
pub const Parameters = @import("joined_parameters.zig");
fn authority(descriptor: Source.Descriptor) ![32]u8 {
    _ = try Authority.shape(descriptor);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/cuda/joined-native-constraints/v1");
    for (Source.Frame.originWords(descriptor.origin)) |tag| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, tag, .little);
        hash.update(&bytes);
    }
    hash.update(&.{ @intFromBool(descriptor.cpu_u8_pairs), @intFromBool(descriptor.cpu_compact_decode) });
    return hash.finalResult();
}
fn parameter(slot: u32) F {
    return F.parameter(slot);
}
fn secureInput(column: usize, offset: i8) F {
    var coordinates: [8]F = undefined;
    for (&coordinates, 0..) |*v, i| v.* = F.input(2, column + i, offset);
    return F.fromPartialEvals(coordinates);
}
pub const Artifact = struct {
    a: std.mem.Allocator,
    descriptor: Source.Descriptor,
    program: C.Program,
    /// Compacted parameter index to semantic cold slot. Runtime metadata and
    /// channel values must be gathered in exactly this map; never by value.
    parameter_slots: []u32,
    parameter_count: u32,
    /// The final ten tree-2 input columns are derived public Eq auxiliaries,
    /// explicitly uncommitted. They must never enter PCS opening obligations.
    interaction_width: usize,
    pub fn deinit(self: *@This()) void {
        self.program.deinit();
        self.a.free(self.parameter_slots);
        self.* = undefined;
    }
    pub fn identity(self: *const @This()) ![32]u8 {
        try self.validate();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/cuda/joined-executable/v1");
        h.update(&(try C.identity(&self.program)));
        h.update(@embedFile("joined_codegen.zig"));
        h.update(@embedFile("symbolic_external.zig"));
        h.update(@embedFile("joined_parameters.zig"));
        const native = @import("stwo_cuda_backend").rv64_numerical_sources;
        h.update(native.parameters);
        h.update(native.parameters_header);
        var metadata: [12]u8 = undefined;
        std.mem.writeInt(u32, metadata[0..4], self.parameter_count, .little);
        std.mem.writeInt(u64, metadata[4..12], self.interaction_width, .little);
        h.update(&metadata);
        for (self.parameter_slots) |slot| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, slot, .little);
            h.update(&bytes);
        }
        return h.finalResult();
    }
    pub fn validate(self: *const @This()) !void {
        try self.program.validate();
        if (!std.mem.eql(u8, &self.program.authority, &(try authority(self.descriptor)))) return error.InvalidJoinedArtifact;
        const shape = try Authority.shape(self.descriptor);
        const local_width: usize = if (Authority.hasLocal(self.descriptor)) 16 else 0;
        const width = local_width + Authority.Global.layout(self.descriptor.origin).width();
        if (self.parameter_count != Parameters.count or self.interaction_width != width or self.program.roots.len != shape.constraints + (if (Authority.hasLocal(self.descriptor)) @as(usize, 3) else 0) + Authority.Global.layout(self.descriptor.origin).constraints() or self.parameter_slots.len != self.program.parameters.len) return error.InvalidJoinedArtifact;
        for (self.parameter_slots) |slot| if (slot >= self.parameter_count) return error.InvalidJoinedArtifact;
        for (self.program.inputs) |input| switch (input.tree) {
            0 => if (input.column >= shape.fixed or input.offset != 0) return error.InvalidJoinedArtifact,
            1 => if (input.column >= shape.main or (input.offset != 0 and (input.offset != -1 or !Authority.previousMain(self.descriptor, input.column)))) return error.InvalidJoinedArtifact,
            2 => {
                if (input.column >= width + (if (Authority.hasLocal(self.descriptor)) @as(usize, 10) else 0)) return error.InvalidJoinedArtifact;
                const expected: i8 = if (local_width != 0 and input.column < 8) 2 else if (local_width != 0 and input.column < 16) -1 else if (input.column < width and Authority.Global.layout(self.descriptor.origin).previous(input.column - local_width)) -1 else 0;
                if (input.offset != 0 and input.offset != expected) return error.InvalidJoinedArtifact;
            },
            else => return error.InvalidJoinedArtifact,
        };
    }
};

pub fn record(a: std.mem.Allocator, descriptor: Source.Descriptor) !Artifact {
    const shape = try Authority.shape(descriptor);
    const local = Authority.hasLocal(descriptor);
    const local_width: usize = if (local) 16 else 0;
    const terms = if (local) try descriptor.terms() else 0;
    const lanes = if (local) @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms)) else 0;
    const global = Authority.Global.layout(descriptor.origin);
    const width = local_width + global.width();
    var recording = X.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    var public: Authority.PublicFor(F) = undefined;
    public.cpu.steps = parameter(Parameters.cpu_steps);
    for (&public.cpu.initial_pc, 0..) |*v, i| v.* = parameter(Parameters.initial_pc + @as(u32, @intCast(i)));
    for (&public.cpu.final_pc, 0..) |*v, i| v.* = parameter(Parameters.final_pc + @as(u32, @intCast(i)));
    public.cpu.epoch = parameter(Parameters.epoch);
    public.cpu.wide_clock = false;
    public.rows = parameter(Parameters.rows);
    public.nonempty = parameter(Parameters.nonempty);
    public.span = .{ .calls = parameter(Parameters.calls), .first_id = parameter(Parameters.first_id), .nonempty = parameter(Parameters.calls_nonempty) };
    var source_public: [Source.Public.count]F = undefined;
    for (&source_public, 0..) |*v, i| v.* = parameter(Parameters.source_public + @as(u32, @intCast(i)));
    source_public[Source.Public.epoch] = public.cpu.epoch;
    source_public[Source.Public.initial_pc] = public.cpu.initial_pc[0].add(public.cpu.initial_pc[1].mul(F.fromU32(65536)));
    const fixed = try a.alloc(F, shape.fixed);
    defer a.free(fixed);
    const main = try a.alloc(F, shape.main);
    defer a.free(main);
    const previous = try a.alloc(F, shape.main);
    defer a.free(previous);
    for (fixed, 0..) |*v, i| v.* = F.input(0, i, 0);
    for (main, previous, 0..) |*v, *p, i| {
        v.* = F.input(1, i, 0);
        p.* = if (Authority.previousMain(descriptor, i)) F.input(1, i, -1) else F.zero();
    }
    var challenges: Source.Challenges.For(F) = .{ .offsets = @splat(F.zero()), .coefficients = @splat(@splat(F.zero())) };
    for (std.enums.values(Source.Fractions.Relation)) |relation| {
        const index = @intFromEnum(relation);
        const slot: u32 = Parameters.local + @as(u32, @intCast(index)) * Parameters.local_stride;
        challenges.offsets[index] = parameter(slot);
        for (0..relation.arity()) |i| challenges.coefficients[index][i] = if (relation == .range8) F.one() else parameter(slot + 1 + @as(u32, @intCast(i)));
    }
    const lane_weights = try a.alloc(F, lanes);
    defer a.free(lane_weights);
    for (lane_weights, 0..) |*v, i| v.* = parameter(Parameters.weights + @as(u32, @intCast(i)));
    var projection = Authority.Binding.ProjectionFor(F){ .challenges = &challenges, .lane_weights = lane_weights, .terms = terms };
    if (local) {
        try descriptor.emit(F, fixed, main, previous, &source_public, &projection);
        try projection.finish();
    }
    const eta = parameter(Parameters.eta);
    const target = parameter(Parameters.target);
    const aux = Authority.Binding.AuxFor(F){ .eq0 = parameter(Parameters.eq0), .eq1 = parameter(Parameters.eq1), .first = F.input(2, width, 0), .second = F.input(2, width + 1, 0), .carry = secureInput(width + 2, 0) };
    var shared: Authority.SharedFor(F) = undefined;
    inline for (.{ "ram", "kio", "wire" }) |name| {
        const slot = @field(Parameters, name);
        @field(shared, name).offset = parameter(slot);
        for (&@field(shared, name).coefficients, 0..) |*v, i| v.* = parameter(slot + 1 + @as(u32, @intCast(i)));
    }
    const claims = Authority.Global.ClaimsFor(F){ .ram = parameter(Parameters.claims), .kio = parameter(Parameters.claims + 1), .wire = parameter(Parameters.claims + 2) };
    const current = try a.alloc(F, global.width());
    defer a.free(current);
    const prior = try a.alloc(F, global.width());
    defer a.free(prior);
    for (current, prior, 0..) |*v, *p, i| {
        v.* = F.input(2, local_width + i, 0);
        p.* = if (global.previous(i)) F.input(2, local_width + i, -1) else F.zero();
    }
    const count = shape.constraints + (if (local) @as(usize, Authority.Binding.CONSTRAINTS) else 0) + global.constraints();
    const residuals = try a.alloc(F, count);
    defer a.free(residuals);
    var sink = E.SinkFor(F){ .values = residuals };
    try Authority.emitMain(descriptor, F, public, fixed, main, previous, &sink);
    if (local) Authority.Binding.emitFor(F, .{ .eq = secureInput(0, 0), .eq_next2 = secureInput(0, 2), .prefix = secureInput(8, 0), .prefix_previous = secureInput(8, -1) }, aux, projection.combine(eta), target, &sink);
    try Authority.emitGlobal(descriptor, F, fixed, main, &source_public, shared, claims, current, prior, &sink);
    if (sink.count != count) return error.WrongJoinedConstraintCount;
    const roots = try a.alloc(u32, count);
    defer a.free(roots);
    for (roots, residuals) |*root, v| root.* = v.id;
    var program = try recording.builder.finish(try authority(descriptor), roots);
    errdefer program.deinit();
    const slots = try a.alloc(u32, program.parameters.len);
    errdefer a.free(slots);
    for (program.parameters, slots) |value, *slot| {
        const coordinates = value.toM31Array();
        for (coordinates[1..]) |v| if (!v.isZero()) return error.UnmappedJoinedParameter;
        if (coordinates[0].v == 0 or coordinates[0].v > Parameters.count) return error.UnmappedJoinedParameter;
        slot.* = coordinates[0].v - 1;
    }
    const artifact = Artifact{ .a = a, .descriptor = descriptor, .program = program, .parameter_slots = slots, .parameter_count = Parameters.count, .interaction_width = width };
    try artifact.validate();
    return artifact;
}
