//! Exact precommit barrier and one-shot proof completion for the thin CPU.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const front = @import("stwo_riscv_frontend");
const W = front.rv64_air.word16_cpu;
const Mat = @import("cpu_materials.zig");
const Sources = @import("cpu_sources.zig");
const Protocol = @import("cpu_protocol.zig");
const Components = @import("cpu_components.zig").Components;
const D = @import("../rv64_distributed_v1/manifest.zig");
const T = D.T;
const Backend = @import("stwo_cpu_backend").CpuBackend;
pub const Encoded = struct {
    bytes: []u8,
    claims: Sources.Claims,
    alu_claims: front.rv64_air.word16_v1.alu_experiment.lookup.Claims = .{ .range16 = core.fields.qm31.QM31.zero(), .function = core.fields.qm31.QM31.zero() },
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};
pub const Stage1 = struct {
    allocator: std.mem.Allocator,
    materials: *const Mat.Materials,
    source: Sources.Source,
    scheme: T.Scheme,
    channel: T.P.Channel,
    receipt: T.Receipt,
    owns_scheme: bool = true,
    completed: bool = false,
    pub fn init(a: std.mem.Allocator, materials: *const Mat.Materials, context: T.Context, spec: T.Spec, public: W.public.Public, records: []const front.rv64.machine.Retirement) !Stage1 {
        if (materials.geometry.mode != .open_function) return error.ExpectedOpenThinCpuMaterials;
        try Mat.validateSpec(materials, public, spec);
        if (!std.mem.eql(u8, &context.program_key, &materials.program.identity)) return error.ThinCpuProgramMismatch;
        var source = try Sources.Source.init(a, materials, public, records);
        errdefer source.deinit();
        var scheme = try T.Scheme.init(a, T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = T.P.Channel{};
        try D.beginStage1(context, spec, &channel);
        try materials.appendFixed(a, &scheme, &channel);
        const main_columns = try source.columns(a, 1);
        defer a.free(main_columns);
        try scheme.commitBorrowedStreaming(a, main_columns, 8, &channel);
        const receipt = try T.fromCommitted(a, &scheme, spec);
        source.releaseMain();
        return .{ .allocator = a, .materials = materials, .source = source, .scheme = scheme, .channel = channel, .receipt = receipt };
    }
    pub fn deinit(self: *Stage1) void {
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.source.deinit();
        self.* = undefined;
    }
    pub fn binaryFacts(self: *const Stage1, a: std.mem.Allocator) ![]front.rv64_air.word16_v1.binary_source.Fact {
        return self.source.cpu.binaryFacts(a);
    }
    pub fn complete(self: *Stage1, manifest: *const D.Manifest, ordinal: usize) !Encoded {
        if (self.completed) return error.InvalidThinCpuStage;
        if (ordinal >= manifest.specs.len) return error.DistributedInventoryMismatch;
        try Mat.validateSpec(self.materials, self.source.cpu.public, manifest.specs[ordinal]);
        if (!std.mem.eql(u8, &manifest.context.program_key, &self.materials.program.identity)) return error.ThinCpuProgramMismatch;
        const shared = try manifest.resumeWorker(self.allocator, ordinal, &self.scheme, &self.channel);
        self.completed = true; // one-shot even on OOM/pole/proof failure.
        return finish(self.allocator, self.materials, &self.source, &self.scheme, &self.channel, &self.owns_scheme, Protocol.drawProfile(&self.channel, shared.binary, self.materials.geometry.profile), false);
    }
};
pub fn produce(a: std.mem.Allocator, materials: *const Mat.Materials, public: W.public.Public, records: []const front.rv64.machine.Retirement, scalar_reference: bool) !Encoded {
    if (materials.geometry.mode != .local_binary) return error.ExpectedClosedThinCpuMaterials;
    var source = try Sources.Source.init(a, materials, public, records);
    defer source.deinit();
    var scheme = try T.Scheme.init(a, T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = T.P.Channel{};
    try Protocol.mixLocal(&channel, materials, public);
    try materials.appendFixed(a, &scheme, &channel);
    const main_columns = try source.columns(a, 1);
    defer a.free(main_columns);
    try scheme.commitBorrowedStreaming(a, main_columns, 8, &channel);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (!std.meta.eql(roots.items[0], materials.fixed_root.value)) return error.UnexpectedThinCpuFixedRoot;
    source.releaseMain();
    const draw = Protocol.drawProfile(&channel, null, materials.geometry.profile);
    return finish(a, materials, &source, &scheme, &channel, &owns, draw, scalar_reference);
}
fn finish(a: std.mem.Allocator, materials: *const Mat.Materials, source: *Sources.Source, scheme: *T.Scheme, channel: *T.P.Channel, owns: *bool, draw: Protocol.Draw, scalar_reference: bool) !Encoded {
    const claims = try source.generate(draw.cpu, draw.and_);
    const alu_claims = source.alu_claims.?;
    Protocol.mixClaimsProfile(channel, claims, materials.geometry.profile, alu_claims);
    const columns = try source.columns(a, 2);
    defer a.free(columns);
    try scheme.commitBorrowedStreaming(a, columns, 8, channel);
    var components = try Components.initWithAlu(materials, source.cpu.public, draw, claims, alu_claims, scalar_reference);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns.* = false; // engine consumes the scheme on success AND failure.
    var proof = try engine.prove.prove(Backend, T.P.Hasher, T.P.MerkleChannel, a, handles, channel, scheme.*);
    defer proof.deinit(a);
    return .{ .bytes = try wire.encodeProofBytesBinary(a, proof), .claims = claims, .alu_claims = alu_claims };
}
