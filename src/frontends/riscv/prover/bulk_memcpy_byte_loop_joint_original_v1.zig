//! Experimental finite native + same-ROM byte-loop ORIGINAL theorem.
//! State/register/local RAM close jointly. ROM/table/global transition providers
//! remain explicit OPEN exports. No production or whole-block authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Macro = @import("bulk_memcpy_byte_loop_original_v1.zig");
const Scope = @import("bulk_memcpy_byte_loop_scope_v1.zig");
const A = @import("bulk_memcpy_byte_loop_components_v1.zig");
const Native = @import("bulk_memcpy_byte_loop_native_components_v1.zig");
const Layout = @import("bulk_memcpy_byte_loop_native_layout_v1.zig");
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
const Joined = @import("block_v6_joint_components_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_kernel_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
pub const production_active = false;
pub const whole_vm_qualified = false;
pub const maps = .{ [_]usize{ 0, 1, 8 }, [_]usize{ 0, 2, 9 }, [_]usize{ 0, 3, 10 }, [_]usize{ 0, 4, 11 }, [_]usize{ 0, 5, 12 }, [_]usize{ 0, 6, 13 }, [_]usize{ 0, 7, 14 } };
pub const Trusted = struct { macro: Macro.Trusted, shape: *const Shape };
pub const Claims = struct { native: []const Native.Claim, macro: Macro.Claims };
pub const Summary = struct {
    total_retirements: u32,
    native_retirements: u32,
    macro_retirements: u32,
    fetch_count: u64,
    program: Q,
    global_transition: Q,
    table_requests: [@import("../air/lookups/tables/schema.zig").KIND_COUNT]Q,
    state_closed: bool = true,
    registers_closed: bool = true,
    local_ram_closed: bool = true,
    whole_vm_qualified: bool = false,
};
pub const Proof = struct {
    allocator: std.mem.Allocator,
    stark: S.Proof,
    native_claims: []Native.Claim,
    macro_claims: Macro.Claims,
    pub fn claims(self: *const Proof) Claims {
        return .{ .native = self.native_claims, .macro = self.macro_claims };
    }
    pub fn deinit(self: *Proof) void {
        self.stark.deinit(self.allocator);
        self.allocator.free(self.native_claims);
        self.allocator.destroy(self);
    }
};
fn admit(a: std.mem.Allocator, t: Trusted) !*Scope.Scope {
    const scope = try Scope.Scope.create(a, t.macro);
    errdefer scope.deinit();
    const count = try t.macro.public.call.retiredInstructions();
    try t.shape.validateBlake3ExecutionWithExternal(count);
    if (count == 0 or t.shape.localZeroCustody() or t.shape.public_data.clock != t.macro.public.call.max_instruction_cycle or
        !std.meta.eql((t.shape.public_data.program_root orelse return error.InvalidJointByteLoopStatement).bytes, scope.certificate.program_root) or
        try t.macro.public.call.nextCycle() > t.shape.public_data.clock + 1) return error.InvalidJointByteLoopStatement;
    return scope;
}
fn mix(channel: anytype, t: Trusted, scope: *const Scope.Scope, digest: [32]u8) void {
    channel.mixU32s(&.{ 0x42384a4d, 1, 15, 5 * t.macro.public.call.length });
    t.shape.public_data.mixInto(channel);
    t.shape.mixShardManifest(channel);
    channel.mixRoot(digest);
    scope.mix(channel);
}
fn wholeCut(m: *Scope.Matrices, count: u32) void {
    // Cohort begins at local clock zero. Macro predecessor ports remain in
    // source/destination fixed columns and must join actual native accesses.
    for (0..count) |i| m.endpoints.set(2, i, M.zero());
}
pub fn replaceWholeEndpoints(stage: *Macro.Stage, scope: *const Scope.Scope, points: []const Endpoint.Endpoint) !void {
    if (points.len != scope.endpoint_count) return error.InvalidJointByteLoopEndpoints;
    wholeCut(&stage.matrices, scope.endpoint_count);
    var prior: ?u32 = null;
    for (points, 0..) |point, i| {
        if (point.address != (try scope.endpointAt(i)).address) return error.InvalidJointByteLoopEndpoints;
        const row = try Endpoint.constructWithPrevious(point, prior, scope.endpoint_policy);
        prior = point.address;
        for (row, 0..) |v, c| stage.matrices.endpoints.set(A.EndpointSpec.FIXED_COUNT + c, i, try v.tryIntoM31());
    }
    try stage.refreshProviders(scope);
}
const Fixed = struct {
    a: std.mem.Allocator,
    native: []Column,
    all: []Column,
    fn deinit(self: *Fixed) void {
        for (self.native) |c| self.a.free(c.values);
        self.a.free(self.native);
        self.a.free(self.all);
    }
};
fn fixed(a: std.mem.Allocator, t: Trusted, m: *const Scope.Matrices) !Fixed {
    var n: std.ArrayList(Column) = .empty;
    errdefer {
        for (n.items) |c| a.free(c.values);
        n.deinit(a);
    }
    try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(a, t.shape, try t.macro.public.call.retiredInstructions(), &n);
    const macro = try Macro.fixedColumns(a, m);
    defer a.free(macro);
    const all = try a.alloc(Column, n.items.len + macro.len);
    errdefer a.free(all);
    @memcpy(all[0..n.items.len], n.items);
    @memcpy(all[n.items.len..], macro);
    return .{ .a = a, .native = try n.toOwnedSlice(a), .all = all };
}
fn Bundle(comptime proving: bool) type {
    return struct {
        native: Joined.Combined(proving),
        placed: Placement.For(maps, 15, proving),
        fn create(a: std.mem.Allocator, n: *const Native.Owner, m: *const Macro.Owner(proving)) !@This() {
            var base = if (proving) try n.proving() else try n.verifying();
            errdefer base.deinit(a);
            const h = m.rawHandles();
            const placed = try Placement.For(maps, 15, proving).init(a, .{ base.handles, &.{h[0]}, &.{h[1]}, &.{h[2]}, &.{h[3]}, &.{h[4]}, &.{h[5]} }, .{ n.fixed.len, A.Spec(.destination).FIXED_COUNT, A.Spec(.source).FIXED_COUNT, A.Spec(.bytes).FIXED_COUNT, A.Spec(.boundary).FIXED_COUNT, A.EndpointSpec.FIXED_COUNT, A.RangeSpec.FIXED_COUNT });
            return .{ .native = base, .placed = placed };
        }
        fn deinit(self: *@This(), a: std.mem.Allocator) void {
            self.placed.deinit(a);
            self.native.deinit(a);
        }
    };
}
fn halt(scope: *const Scope.Scope) @import("block_v8_native_halt_policy_v1.zig").Policy {
    return .{ .halt_address = scope.initialized.info.halt_flag };
}
fn close(a: std.mem.Allocator, t: Trusted, scope: *const Scope.Scope, n: *const Native.Owner, drawn: A.Drawn, claims: Claims) !Summary {
    _ = try Macro.closeResources(scope, drawn, claims.macro);
    const external = try t.macro.public.call.retiredInstructions();
    const p = try Native.extract(a, t.shape, external, n.layout.slots, claims.native);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&drawn.universal);
    const Public = @import("../air/public_logup_arithmetic.zig");
    const state = (try Public.registersStateSumFor(Q, &t.shape.public_data, &shared.native)).add(p.state_sum).add(claims.macro.boundary[1]);
    const regs = (try Public.registerMemoryAccessSumFor(Q, &t.shape.public_data, &shared.native)).add(p.register_sum).add(p.register_clock_sum).add(claims.macro.boundary[2]);
    if (!state.isZero()) return error.UnclosedJointByteLoopState;
    if (!regs.isZero()) return error.UnclosedJointByteLoopRegisters;
    const ram = p.ordinary_ram_sum.add(p.ram_clock_sum).add(claims.macro.source[1]).add(claims.macro.destination[1]).add(claims.macro.endpoints[0]);
    if (!ram.isZero()) return error.UnclosedJointByteLoopRam;
    const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(t.macro.profile, &t.shape.public_data, &drawn.universal);
    return .{ .total_retirements = t.shape.total_steps, .native_retirements = t.shape.total_steps - external, .macro_retirements = external, .fetch_count = p.fetch_count + external + boundary.fetch_count, .program = p.program_sum.add(claims.macro.boundary[0]).add(boundary.sum), .global_transition = claims.macro.endpoints[1], .table_requests = p.table_requests };
}
pub fn produce(a: std.mem.Allocator, t: Trusted, main: []const Column, stage: *const Macro.Stage) !*Proof {
    const scope = try admit(a, t);
    defer scope.deinit();
    const external = try t.macro.public.call.retiredInstructions();
    var layout = try Layout.Layout.init(a, t.shape, external);
    defer layout.deinit();
    var f = try fixed(a, t, &stage.matrices);
    defer f.deinit();
    var guard = try Native.prepareMain(a, t.shape, main, halt(scope), external);
    defer guard.deinit();
    var scheme = try Scheme.init(a, t.macro.config);
    var live = true;
    defer if (live) scheme.deinit(a);
    var channel = S.Channel{};
    mix(&channel, t, scope, layout.digest);
    try scheme.commitBorrowedStreaming(a, f.all, 8, &channel);
    try scheme.commitBorrowedStreaming(a, guard.columns, 8, &channel);
    inline for (.{ "destination", "source", "bytes", "boundary", "endpoints", "range16" }) |name| {
        const fc = if (comptime std.mem.eql(u8, name, "endpoints")) A.EndpointSpec.FIXED_COUNT else if (comptime std.mem.eql(u8, name, "range16")) A.RangeSpec.FIXED_COUNT else A.Spec(@field(A.Kind, name)).FIXED_COUNT;
        try scheme.commitBorrowedStreaming(a, @field(stage.matrices, name).columns[fc..], 8, &channel);
    }
    const drawn = try A.draw(a, &channel);
    var ni = try Native.Interactions.generate(a, t.shape, guard.columns, &drawn.universal, external);
    defer ni.deinit();
    var mi = try Macro.Generated.create(a, scope, stage, drawn);
    defer mi.deinit();
    const claims = Claims{ .native = ni.claims, .macro = mi.claims() };
    try Native.recordClaims(&channel, layout.digest, claims.native);
    try Macro.recordClaims(&channel, claims.macro);
    const no = try Native.Owner.init(a, t.shape, claims.native, &drawn.universal, halt(scope), external);
    defer no.deinit();
    _ = try close(a, t, scope, no, drawn, claims);
    try scheme.commitBorrowedStreaming(a, ni.columns, 8, &channel);
    inline for (.{ "destination", "source", "bytes", "boundary", "endpoints", "range16" }) |name| try scheme.commitBorrowedStreaming(a, @field(mi, name).matrix.columns, 8, &channel);
    const mo = try Macro.Owner(true).create(a, scope, drawn, claims.macro);
    defer mo.deinit();
    var bundle = try Bundle(true).create(a, no, mo);
    defer bundle.deinit(a);
    const out = try a.create(Proof);
    errdefer a.destroy(out);
    const copied = try a.dupe(Native.Claim, claims.native);
    errdefer a.free(copied);
    live = false;
    out.* = .{ .allocator = a, .native_claims = copied, .macro_claims = claims.macro, .stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, bundle.placed.handles, &channel, scheme) };
    return out;
}
pub fn verify(a: std.mem.Allocator, t: Trusted, proof: *const S.Proof, claims: Claims) !Summary {
    const scope = try admit(a, t);
    defer scope.deinit();
    const external = try t.macro.public.call.retiredInstructions();
    var layout = try Layout.Layout.init(a, t.shape, external);
    defer layout.deinit();
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 16 or !std.meta.eql(t.macro.config, proof.commitment_scheme_proof.config)) return error.InvalidJointByteLoopGeometry;
    var matrices = try Scope.fixed(a, scope);
    defer matrices.deinit();
    wholeCut(&matrices, scope.endpoint_count);
    var f = try fixed(a, t, &matrices);
    defer f.deinit();
    var key = try Scheme.init(a, t.macro.config);
    defer key.deinit(a);
    var ignored = S.Channel{};
    try key.commitBorrowedStreaming(a, f.all, 8, &ignored);
    if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedJointByteLoopKey;
    var channel = S.Channel{};
    mix(&channel, t, scope, layout.digest);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, t.macro.config);
    defer verifier.deinit(a);
    const fl = try a.alloc(u32, f.all.len);
    defer a.free(fl);
    for (f.all, fl) |c, *l| l.* = c.log_size;
    const nl = try Native.mainLogs(a, t.shape, external);
    defer a.free(nl);
    const d: [33]u32 = @splat(scope.destination_log);
    const s: [5]u32 = @splat(scope.source_log);
    const b = [_]u32{8};
    const boundary = [_]u32{4};
    const ep: [23]u32 = @splat(scope.endpoint_log);
    const r = [_]u32{16};
    for ([_][]const u32{ fl, nl, &d, &s, &b, &boundary, &ep, &r }, 0..) |logs, i| try verifier.commit(a, roots[i], logs, &channel);
    const drawn = try A.draw(a, &channel);
    try Native.recordClaims(&channel, layout.digest, claims.native);
    try Macro.recordClaims(&channel, claims.macro);
    const no = try Native.Owner.init(a, t.shape, claims.native, &drawn.universal, halt(scope), external);
    defer no.deinit();
    const di: [24]u32 = @splat(scope.destination_log);
    const si: [20]u32 = @splat(scope.source_log);
    const bi: [8]u32 = @splat(8);
    const bdi: [12]u32 = @splat(4);
    const epi: [52]u32 = @splat(scope.endpoint_log);
    const ri: [8]u32 = @splat(16);
    for ([_][]const u32{ no.interactions, &di, &si, &bi, &bdi, &epi, &ri }, 0..) |logs, i| try verifier.commit(a, roots[8 + i], logs, &channel);
    const mo = try Macro.Owner(false).create(a, scope, drawn, claims.macro);
    defer mo.deinit();
    var bundle = try Bundle(false).create(a, no, mo);
    defer bundle.deinit(a);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, bundle.placed.handles, &channel, &verifier, proof, &capture);
    defer capture.deinit(a);
    return close(a, t, scope, no, drawn, claims);
}

const postcard = @import("interop_postcard");
fn writeQ(out: []u8, offset: *usize, q: Q) void {
    for (q.toM31Array()) |v| {
        std.mem.writeInt(u32, out[offset.*..][0..4], v.v, .little);
        offset.* += 4;
    }
}
fn readQ(raw: []const u8, offset: *usize) !Q {
    var limbs: [4]M = undefined;
    for (&limbs) |*v| {
        const n = std.mem.readInt(u32, raw[offset.*..][0..4], .little);
        if (n >= core.fields.m31.Modulus) return error.InvalidJointByteLoopEnvelope;
        v.* = M.fromCanonical(n);
        offset.* += 4;
    }
    return Q.fromM31Array(limbs);
}
pub fn encode(a: std.mem.Allocator, proof: *const Proof) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    try postcard.serializeProof(S.Hasher, bytes.writer(a), proof.stark);
    if (bytes.items.len > 16 << 20 or proof.native_claims.len > 65536) return error.InvalidJointByteLoopEnvelope;
    const header = 24 + 24 * proof.native_claims.len + 31 * 16;
    const out = try a.alloc(u8, header + bytes.items.len);
    errdefer a.free(out);
    @memcpy(out[0..8], "B8JBYTP1");
    std.mem.writeInt(u32, out[8..12], 1, .little);
    std.mem.writeInt(u32, out[12..16], @intCast(proof.native_claims.len), .little);
    std.mem.writeInt(u32, out[16..20], 31, .little);
    std.mem.writeInt(u32, out[20..24], @intCast(bytes.items.len), .little);
    var offset: usize = 24;
    for (proof.native_claims) |c| {
        writeQ(out, &offset, c.sum);
        std.mem.writeInt(u64, out[offset..][0..8], c.row_count, .little);
        offset += 8;
    }
    inline for (.{ "destination", "source", "bytes", "boundary", "endpoints", "range16" }) |name| for (@field(proof.macro_claims, name)) |c| writeQ(out, &offset, c);
    @memcpy(out[header..], bytes.items);
    return out;
}
pub fn verifyBytes(a: std.mem.Allocator, t: Trusted, raw: []const u8) !Summary {
    if (raw.len < 24 or !std.mem.eql(u8, raw[0..8], "B8JBYTP1") or std.mem.readInt(u32, raw[8..12], .little) != 1 or std.mem.readInt(u32, raw[16..20], .little) != 31) return error.InvalidJointByteLoopEnvelope;
    const scope = try admit(a, t);
    defer scope.deinit();
    const external = try t.macro.public.call.retiredInstructions();
    var layout = try Layout.Layout.init(a, t.shape, external);
    defer layout.deinit();
    const n = std.mem.readInt(u32, raw[12..16], .little);
    if (n != layout.slots.len or n > 65536) return error.InvalidJointByteLoopEnvelope;
    const header = 24 + 24 * @as(usize, n) + 31 * 16;
    if (raw.len < header or raw.len - header > 16 << 20 or std.mem.readInt(u32, raw[20..24], .little) != raw.len - header) return error.InvalidJointByteLoopEnvelope;
    const native = try a.alloc(Native.Claim, n);
    defer a.free(native);
    var offset: usize = 24;
    for (native) |*c| {
        c.sum = try readQ(raw, &offset);
        c.row_count = std.mem.readInt(u64, raw[offset..][0..8], .little);
        offset += 8;
    }
    var macro: Macro.Claims = undefined;
    inline for (.{ "destination", "source", "bytes", "boundary", "endpoints", "range16" }) |name| for (&@field(macro, name)) |*c| {
        c.* = try readQ(raw, &offset);
    };
    const nl = try Native.mainLogs(a, t.shape, external);
    defer a.free(nl);
    const fixedn = try @import("block_v5_native_template_protocol_v3.zig").columnLogs(a, t.shape, external, .fixed);
    defer a.free(fixedn);
    const counts = [_]u32{ @intCast(fixedn.len + 45), @intCast(nl.len), 33, 5, 1, 1, 23, 1, @intCast(4 * layout.slots.len), 24, 20, 8, 12, 52, 8, 16 };
    var max_log: u32 = 16;
    for (nl) |log| max_log = @max(max_log, log);
    for (fixedn) |log| max_log = @max(max_log, log);
    const empty: [16]bool = @splat(false);
    const widths: [16]u32 = @splat(6);
    const config = t.macro.config;
    try postcard.proof_preflight.validateRuntime(raw[header..], .{ .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size }, .tree_columns = &counts, .empty_tree_flags = &empty, .sample_width_limits = &widths, .allow_zero_samples = true, .max_column_log_size = max_log, .max_merkle_column_log_size = max_log, .hash_size = 32, .max_wire_bytes = 16 << 20 });
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var stream = std.io.fixedBufferStream(raw[header..]);
    const proof = try postcard.deserializeProof(S.Hasher, arena.allocator(), stream.reader());
    if (stream.pos != raw.len - header) return error.InvalidJointByteLoopEnvelope;
    return verify(a, t, &proof, .{ .native = native, .macro = macro });
}
