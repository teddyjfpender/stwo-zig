//! Cold source-column-to-fraction codegen from the native raw tuple emitters.
//! The third input namespace is explicitly public base values, NOT PCS tree2.
//! Secure draw slots are semantic identities, never interned by live FS values.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const Source = @import("stwo_riscv_cpu_integration").rv64_gkr_source;
const C = @import("composition_codegen.zig");
const O = C.O;
const M = core.fields.m31.M31;
const F = A.evaluation.symbolic.SymbolicLane(O);
const Relation = Source.Fractions.Relation;
pub const slot_stride = 1 + Source.Fractions.MAX_ARITY;
pub const challenge_slots = std.enums.values(Relation).len * slot_stride;
comptime {
    const abi = @import("abi.zig");
    if (abi.relation_count != std.enums.values(Relation).len or abi.relation_slot_stride != slot_stride) @compileError("native projection challenge ABI is stale against tuple authority");
}
fn marker(slot: usize) O {
    return O.fromBase(M.fromCanonical(@intCast(slot + 1)));
}
fn decodeMarker(value: O) !u32 {
    const c = value.toM31Array();
    for (c[1..]) |v| if (!v.isZero()) return error.UnmappedSourceParameter;
    if (c[0].v == 0 or c[0].v > challenge_slots) return error.UnmappedSourceParameter;
    return c[0].v - 1;
}
const Collector = struct {
    roots: [2 * Source.Frame.MAX_LOCAL_TERMS]u32 = undefined,
    count: usize = 0,
    invalid: bool = false,
    pub fn emit(self: *@This(), relation: Relation, tuple: anytype, weight: F) void {
        if (self.count >= Source.Frame.MAX_LOCAL_TERMS or tuple.len != relation.arity()) {
            self.invalid = true;
            return;
        }
        const slot = @as(usize, @intFromEnum(relation)) * slot_stride;
        var d = F.fromConst(marker(slot));
        for (tuple, 0..) |value, i| {
            const coefficient = if (relation == .range8) F.one() else F.fromConst(marker(slot + 1 + i));
            d = d.sub(coefficient.mul(value));
        }
        self.roots[2 * self.count] = weight.id;
        self.roots[2 * self.count + 1] = d.id;
        self.count += 1;
    }
};
pub const Artifact = struct {
    a: std.mem.Allocator,
    descriptor: Source.Descriptor,
    program: C.Program,
    /// Compacted parameter index -> semantic challenge reservoir slot. Included
    /// in artifact identity, independently of every live challenge value.
    source_slots: []u32,
    terms: u32,
    lanes: u32,
    pub fn deinit(self: *Artifact) void {
        self.program.deinit();
        self.a.free(self.source_slots);
        self.* = undefined;
    }
    pub fn validate(self: *const Artifact) !void {
        try self.program.validate();
        const shape = try self.descriptor.shape();
        const terms = try self.descriptor.terms();
        const lanes = @as(u32, 1) << @as(u5, @intCast(std.math.log2_int_ceil(u32, terms)));
        if (self.terms != terms or self.lanes != lanes or self.program.roots.len != 2 * terms or self.source_slots.len != self.program.parameters.len or !std.mem.eql(u8, &self.program.authority, &(try sourceAuthority(self.descriptor)))) return error.InvalidSourceArtifact;
        for (self.source_slots) |slot| {
            const relation = slot / slot_stride;
            const coordinate = slot % slot_stride;
            if (relation >= std.enums.values(Relation).len) return error.InvalidSourceArtifact;
            const r: Relation = @enumFromInt(relation);
            if (coordinate > r.arity() or (r == .range8 and coordinate != 0)) return error.InvalidSourceArtifact;
        }
        for (self.program.inputs) |input| switch (input.tree) {
            0 => if (input.column >= shape.fixed or input.offset != 0) return error.InvalidSourceArtifact,
            1 => if (input.column >= shape.main or (input.offset != 0 and (input.offset != -1 or !self.descriptor.previous(input.column)))) return error.InvalidSourceArtifact,
            2 => if (input.column >= Source.Public.count or input.offset != 0) return error.InvalidSourceArtifact,
            else => return error.InvalidSourceArtifact,
        };
    }
    pub fn identity(self: *const Artifact) ![32]u8 {
        try self.validate();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/cuda/source-projection/v1\x00");
        h.update(&self.program.identity);
        h.update(@embedFile("projection_codegen.zig"));
        h.update(@embedFile("composition_codegen.zig"));
        const sources = @import("stwo_cuda_backend").rv64_numerical_sources;
        h.update(sources.projection);
        h.update(sources.composition);
        h.update(sources.om31);
        h.update(sources.quartic);
        for (self.source_slots) |slot| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, slot, .little);
            h.update(&bytes);
        }
        return h.finalResult();
    }
};
fn sourceAuthority(descriptor: Source.Descriptor) ![32]u8 {
    try descriptor.validate();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/local-source-authority/v1\x00");
    const tags = Source.Frame.originWords(descriptor.origin);
    for (tags) |tag| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, tag, .little);
        hash.update(&bytes);
    }
    hash.update(&.{ @intFromBool(descriptor.cpu_u8_pairs), @intFromBool(descriptor.cpu_compact_decode) });
    return hash.finalResult();
}
pub fn record(a: std.mem.Allocator, descriptor: Source.Descriptor) !Artifact {
    const shape = try descriptor.shape();
    const terms = try descriptor.terms();
    if (terms == 0 or terms > Source.Frame.MAX_LOCAL_TERMS) return error.InvalidSourceTermCount;
    var recording = A.evaluation.symbolic.Recording(O).init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const fixed = try a.alloc(F, shape.fixed);
    defer a.free(fixed);
    const main = try a.alloc(F, shape.main);
    defer a.free(main);
    const previous = try a.alloc(F, shape.main);
    defer a.free(previous);
    for (fixed, 0..) |*v, i| v.* = F.input(0, i, 0);
    for (main, previous, 0..) |*v, *p, i| {
        v.* = F.input(1, i, 0);
        p.* = if (descriptor.previous(i)) F.input(1, i, -1) else F.zero();
    }
    var public: [Source.Public.count]F = undefined;
    for (&public, 0..) |*v, i| v.* = F.input(2, i, 0);
    var sink = Collector{};
    try descriptor.emit(F, fixed, main, previous, &public, &sink);
    if (sink.invalid or sink.count != terms) return error.InvalidSourceTermCount;
    var program = try recording.builder.finish(try sourceAuthority(descriptor), sink.roots[0 .. 2 * sink.count]);
    errdefer program.deinit();
    const slots = try a.alloc(u32, program.parameters.len);
    errdefer a.free(slots);
    for (program.parameters, slots) |parameter, *slot| slot.* = try decodeMarker(parameter);
    const sorts = try program.sorts(a);
    defer a.free(sorts);
    for (0..terms) |i| if (sorts[program.roots[2 * i]] != .base) return error.NonbaseSourceWeight;
    for (program.inputs) |input| if (input.tree == 2 and (input.column >= Source.Public.count or input.offset != 0)) return error.InvalidPublicSource;
    return .{ .a = a, .descriptor = descriptor, .program = program, .source_slots = slots, .terms = terms, .lanes = @as(u32, 1) << @as(u5, @intCast(std.math.log2_int_ceil(u32, terms))) };
}
/// Numerical kernel only. Native invocation ownership must validate its exact
/// source layout, ranges, verdict and AOT identity before launch/publication.
pub fn emit(a: std.mem.Allocator, w: anytype, artifact: *const Artifact, name: []const u8) !void {
    if (name.len == 0 or std.ascii.isDigit(name[0])) return error.InvalidKernelName;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidKernelName;
    const p = &artifact.program;
    try artifact.validate();
    const sorts = try p.sorts(a);
    defer a.free(sorts);
    const head = try a.alloc(u32, p.nodes.len);
    defer a.free(head);
    @memset(head, std.math.maxInt(u32));
    const next = try a.alloc(u32, p.roots.len);
    defer a.free(next);
    for (p.roots, 0..) |root, j| {
        next[j] = head[root];
        head[root] = @intCast(j);
    }
    const order = try C.schedule(a, p);
    defer a.free(order);
    try w.writeAll("#include \"rv64/projection.cuh\"\nusing namespace stwo::cuda::rv64;\n");
    try w.print(
        \\extern "C" __global__ void {s}(const uint32_t *tree0,const uint32_t *tree1,const uint32_t *public_values,
        \\const uint64_t *column_offsets,const uint32_t *parameters,uint32_t *numerator,uint32_t *denominator,
        \\uint32_t trace_log,uint32_t first_row,uint32_t rows,uint32_t *status) {{
        \\ const uint32_t local=blockIdx.x*blockDim.x+threadIdx.x;
        \\ if(local>=rows) return;
        \\ const uint32_t row=first_row+local;
        \\ const uint64_t stride=(uint64_t(1)<<trace_log)*{}u;
        \\ const uint64_t first=uint64_t(row)*{}u;
        \\
    , .{ name, artifact.lanes, artifact.lanes });
    if (artifact.lanes > artifact.terms) try w.print(" for(uint32_t k={}u;k<{}u;++k) {{ numerator[first+k]=0;store(denominator,stride,first+k,one()); }}\n", .{ artifact.terms, artifact.lanes });
    for (order) |i| {
        const node = p.nodes[i];
        if (node.op == .input) {
            const input = p.inputs[node.value];
            if (input.tree == 2) try w.print(" const uint32_t v{}=public_values[{}u];\n", .{ i, input.column }) else try w.print(" const uint32_t v{}=tree{}[column_offsets[{}]+composition_mask_row(row,trace_log,trace_log,{})];\n", .{ i, input.tree, node.value, input.offset });
            try w.print(" if(v{}>=q::kPrime) {{ invalid_projection_row(numerator,denominator,row,{}u,stride,status);return; }}\n", .{ i, artifact.lanes });
        } else try C.emitValue(w, p, sorts, i);
        var root = head[i];
        while (root != std.math.maxInt(u32)) : (root = next[root]) {
            if (root % 2 == 0) {
                try w.print(" numerator[first+{}u]=v{};\n", .{ root / 2, i });
            } else {
                if (sorts[i] == .base) {
                    try w.print(" store(denominator,stride,first+{}u,base(v{}));if(!v{}) atomicOr(status,2u);\n", .{ root / 2, i, i });
                } else try w.print(" store(denominator,stride,first+{}u,v{});if(is_zero(v{})) atomicOr(status,2u);\n", .{ root / 2, i, i });
            }
        }
    }
    try w.writeAll("}\n");
}
