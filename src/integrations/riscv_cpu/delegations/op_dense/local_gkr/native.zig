//! Source-owned arithmetic BYTE instance and independent log8 BYTE provider.
//! Shared beta and cross-instance closure; physical MAIN binding stays mandatory.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_riscv_frontend").rv64_air.crypto.bn254_dense;
const C = D.fixture_component;
pub const Q = C.Q;
pub const M = C.M;
pub const Channel = core.channel.poseidon2_m31.Om31ChannelV2;
const GP = engine.lookups.gkr_prover.ForField(Q);
pub const GV = engine.lookups.gkr_verifier.ForField(Q);
const Base = @import("../../../poseidon2_outer/pure_p2_native.zig");
const Framing = @import("../../../poseidon2_outer/pure_p2_framing.zig");
const Closure = @import("../../../word16_global_execution/services/gkr_local/closure.zig");
const Wire = @import("../../../word16_global_execution/services/gkr_local/wire.zig");
pub const Role = enum { arithmetic, table };
pub const TABLE_LOG = 8;
pub const TERMS = 355;
pub const LANES = 512;
pub const MAGIC = "DENSELG2";
comptime {
    if (D.row.Layout(.multiply).BYTE_QUERIES + 1 != TERMS or D.row.Layout(.square).BYTE_QUERIES + 1 != TERMS) @compileError("dense BYTE source recipe changed");
}
pub const Instance = struct {
    role: Role,
    row_log: u32,
    pub fn laneLog(self: @This()) u32 {
        return if (self.role == .arithmetic) 9 else 0;
    }
    pub fn lanes(self: @This()) usize {
        return @as(usize, 1) << @intCast(self.laneLog());
    }
    pub fn rows(self: @This()) usize {
        return @as(usize, 1) << @intCast(self.row_log);
    }
    pub fn variables(self: @This()) !u32 {
        return self.row_log + self.laneLog();
    }
    pub fn facts(self: @This()) usize {
        return self.rows() * self.lanes();
    }
};
pub fn instances(log: u32) ![2]Instance {
    if (log < 8 or log > 10) return error.DenseSourceGeometry;
    return .{ .{ .role = .arithmetic, .row_log = log }, .{ .role = .table, .row_log = 8 } };
}
pub const Scope = struct { statement: [32]u8, fixed: [32]u8, main: [32]u8, arith_log: u32 };
fn raw(channel: anytype, data: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, data[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn statement(comptime kind: D.spec.Kind, log: u32, input: *const [D.spec.inputs(kind)]u256, output: [12]u256) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("closed-dense-byte-local-gkr/v2");
    h.update(&D.sourceDigest());
    h.update(&.{@intFromEnum(kind)});
    var l: [4]u8 = undefined;
    std.mem.writeInt(u32, &l, log, .little);
    h.update(&l);
    for (input) |v| {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, v, .little);
        h.update(&b);
    }
    for (output) |v| {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, v, .little);
        h.update(&b);
    }
    h.update(@embedFile("native.zig"));
    h.update(@embedFile("projection.zig"));
    h.update(@embedFile("component.zig"));
    return h.finalResult();
}
pub fn begin(scope: Scope) !Channel {
    const ii = try instances(scope.arith_log);
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x444c474b, 2, 8, 2, 355 });
    for (ii) |i| channel.mixU32s(&.{ @intFromEnum(i.role), i.row_log, i.laneLog() });
    raw(&channel, scope.statement);
    raw(&channel, scope.fixed);
    raw(&channel, scope.main);
    return channel;
}
pub fn receipt(scope: Scope, proof: *const GV.GkrBatchProof, marginals: []const []const Q) !core.crypto.poseidon2_m31_sponge.Digest {
    const ii = try instances(scope.arith_log);
    var vars: [2]u32 = undefined;
    var writer = Base.ReceiptWriter{};
    writer.tag(0x444c474b);
    writer.integer(2);
    writer.rawDigest(scope.statement);
    writer.rawDigest(scope.fixed);
    writer.rawDigest(scope.main);
    for (ii, &vars) |i, *v| {
        v.* = try i.variables();
        writer.integer(@intFromEnum(i.role));
        writer.integer(i.row_log);
        writer.integer(i.laneLog());
    }
    try Framing.emitPayload(proof, &vars, marginals, &writer);
    return writer.finish();
}
pub fn validateArtifact(log: u32, artifact: *const GV.GkrArtifact) !void {
    const ii = try instances(log);
    if (artifact.n_variables_by_instance.len != 2 or artifact.ood_point.len != try ii[0].variables() or artifact.claims_to_verify_by_instance.len != 2) return error.DenseLocalShape;
    for (ii, artifact.n_variables_by_instance, artifact.claims_to_verify_by_instance) |i, n, claim| if (n != try i.variables() or claim.len != 2) return error.DenseLocalShape;
}
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    beta: Q,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, scope: Scope, proof: *const GV.GkrBatchProof) !Pending {
    var channel = try begin(scope);
    const beta = channel.drawSecureFelt();
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp }, proof, &channel);
    errdefer artifact.deinit(a);
    try validateArtifact(scope.arith_log, &artifact);
    try Closure.close(a, proof.output_claims_by_instance);
    const digest = try receipt(scope, proof, artifact.claims_to_verify_by_instance);
    return .{ .artifact = artifact, .beta = beta, .eta = channel.drawSecureFelt(), .digest = digest };
}
pub fn encode(a: std.mem.Allocator, log: u32, proof: *const GV.GkrBatchProof) ![]u8 {
    const ii = try instances(log);
    return Wire.encodeFor(a, &ii, proof, MAGIC);
}
pub fn decode(a: std.mem.Allocator, log: u32, bytes: []const u8) !Wire.Owned {
    const ii = try instances(log);
    return Wire.decodeFor(a, &ii, bytes, MAGIC);
}
pub fn Reader(comptime kind: D.spec.Kind, comptime log: u32) type {
    return struct {
        const Self = @This();
        trace: *const D.fixture_trace.TraceForLog(kind, log),
        table: []const M,
        beta: Q,
        instance: Instance,
        const View = struct {
            trace: *const D.fixture_trace.TraceForLog(kind, log),
            physical: usize,
            pub fn fixed(v: *const @This(), c: usize) Q {
                return Q.fromBase(v.trace.fixed[c * (@as(usize, 1) << log) + v.physical]);
            }
            pub fn main(v: *const @This(), c: usize) Q {
                return Q.fromBase(v.trace.main[c * (@as(usize, 1) << log) + v.physical]);
            }
        };
        pub fn read(ctx: *const anyopaque, first: usize, n: []M, d: []Q) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            const facts = self.instance.facts();
            if (n.len != d.len or n.len > 512 or first > facts or n.len > facts - first) return error.ShapeMismatch;
            for (n, d, 0..) |*nn, *dd, j| {
                const f = first + j;
                const lane = f % self.instance.lanes();
                const p = f / self.instance.lanes();
                if (self.instance.role == .arithmetic) {
                    const v = View{ .trace = self.trace, .physical = p };
                    const pair = C.rangeFraction(kind, Q, &v, self.beta, lane);
                    const c = pair[0].toM31Array();
                    for (c[1..]) |x| if (x.v != 0) return error.InvalidLayerStructure;
                    nn.* = c[0];
                    dd.* = pair[1];
                } else {
                    if (self.table.len != 256) return error.ShapeMismatch;
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, 8), 8);
                    nn.* = self.table[p].neg();
                    dd.* = self.beta.sub(Q.fromBase(M.fromCanonical(@intCast(logical))));
                }
            }
        }
        pub fn source(self: *const Self) GP.MultiplicitiesSource {
            return .{ .variables = self.instance.variables() catch unreachable, .context = self, .wide_reads = true, .read_fn = read };
        }
    };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    beta: Q,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
pub fn prove(comptime kind: D.spec.Kind, comptime log: u32, a: std.mem.Allocator, scope: Scope, trace: *const D.fixture_trace.TraceForLog(kind, log), table: []const M) !Unbound {
    if (scope.arith_log != log or table.len != 256) return error.DenseSourceGeometry;
    const ii = try instances(log);
    var channel = try begin(scope);
    const beta = channel.drawSecureFelt();
    const readers = [_]Reader(kind, log){ .{ .trace = trace, .table = table, .beta = beta, .instance = ii[0] }, .{ .trace = trace, .table = table, .beta = beta, .instance = ii[1] } };
    const sources = [_]GP.MultiplicitiesSource{ readers[0].source(), readers[1].source() };
    var result = try GP.proveBatchSourceCheckpointedWithOptions(a, &channel, &sources, .{ .coefficient_encoding = .fixed4 });
    errdefer result.deinit(a);
    try validateArtifact(log, &result.artifact);
    try Closure.close(a, result.proof.output_claims_by_instance);
    const digest = try receipt(scope, &result.proof, result.artifact.claims_to_verify_by_instance);
    return .{ .result = result, .beta = beta, .eta = channel.drawSecureFelt(), .digest = digest };
}
