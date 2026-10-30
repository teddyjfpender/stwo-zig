//! Single terminal read for the original BLAKE3 execution parent. This is a
//! transport decoder, not proof authority: callers must run the independent
//! original parent verifier with its externally selected admission and claims.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const native = @import("stwo_native_cuda_integration").common;
const shared = native.proof_bundle;
const Program = @import("resident_parent_program_v1.zig");
const PCS = @import("resident_parent_pcs_v1.zig");
const Suite = @import("../../frontends/riscv/recursion/blake3_engine_protocol.zig");
const Q = core.fields.qm31.QM31;
pub const Hasher = Suite.Hasher;

pub const Layout = struct {
    sampled_values: usize,
    fri_roots: usize,
    final_coefficients: usize,
    query_count: u32,
    pow_bits: u32,
    blowup: u32,
    fold_step: u32,
    max_log_degree_bound: u32,
    pub fn derive(program: *const Program.Owned, plans: *const PCS.Plans) !Layout {
        const p = program.view();
        if (!std.mem.eql(u8, &p.identity, &plans.geometry.identity) or plans.proof_layout.sample_total == 0 or p.fri_layers.len == 0) return error.InvalidResidentParentTerminal;
        const c = p.admission.key.config;
        return .{ .sampled_values = plans.proof_layout.sample_total, .fri_roots = p.fri_layers.len, .final_coefficients = try shared.pow2(c.fri_config.log_last_layer_degree_bound), .query_count = @intCast(c.fri_config.n_queries), .pow_bits = c.pow_bits, .blowup = c.fri_config.log_blowup_factor, .fold_step = c.fri_config.fold_step, .max_log_degree_bound = p.composition_log };
    }
};
pub const Decommit = struct { capacity_words: usize };
const Descriptor = struct {
    pub fn sectionLengths(l: Layout, d: Decommit) ![shared.section_count]usize {
        if (l.sampled_values == 0 or l.fri_roots == 0 or l.final_coefficients == 0 or l.query_count == 0 or d.capacity_words == 0) return error.InvalidResidentParentTerminal;
        return .{ 4 * 8 + Program.COMPONENT_COUNT * 4, try shared.mul(l.sampled_values, 4), try shared.mul(l.fri_roots, 8), try shared.mul(l.final_coefficients, 4), 2, d.capacity_words };
    }
    pub fn fixedHeader(l: Layout, _: Decommit, count: usize) ![shared.fixed_header_words]u32 {
        return .{ shared.magic, shared.version, try shared.u32Count(count), shared.section_count, 4, Program.COMPONENT_COUNT, try shared.u32Count(try shared.mul(l.sampled_values, 4)), try shared.u32Count(l.fri_roots), try shared.u32Count(l.final_coefficients), l.query_count, l.pow_bits, 0, l.max_log_degree_bound, l.blowup, l.fold_step, std.math.maxInt(u32) };
    }
};
pub const Bundle = shared.BundleFor(Layout, Decommit, Descriptor);
pub fn init(a: std.mem.Allocator, program: *const Program.Owned, plans: *const PCS.Plans) !Bundle {
    return Bundle.init(a, try Layout.derive(program, plans), .{ .capacity_words = plans.decommit.topology.assembly_capacity_words });
}
pub const MeasuredRead = struct {
    operations: u64,
    bytes: u64,
    runtime_compile_attempts: u64,
    cpu_fallback_attempts: u64,
    pub fn validate(self: MeasuredRead, words: usize) !void {
        if (self.operations != 1 or self.bytes != try shared.mul(words, 4)) return error.InvalidTerminalRead;
        if (self.runtime_compile_attempts != 0 or self.cpu_fallback_attempts != 0) return error.NonresidentParentProof;
    }
};
pub const Proof = struct {
    stark: core.proof.StarkProof(Hasher),
    claims: [Program.COMPONENT_COUNT]Q,
    read: MeasuredRead,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
    /// Owns all decoded proof fields; input transport and device arena may be
    /// destroyed immediately after return. The independently derived plans
    /// determine every opening; no device-provided geometry is admitted.
    pub fn decode(a: std.mem.Allocator, program: *const Program.Owned, plans: *const PCS.Plans, transport: []const u32, read: MeasuredRead) !Proof {
        var bundle = try init(a, program, plans);
        defer bundle.deinit(a);
        try read.validate(bundle.total_words);
        try validateEnvelope(bundle, transport);
        const raw = try a.dupe(u32, section(bundle, transport, .decommitment));
        defer a.free(raw);
        var nested = try cuda.runtime.proof_assembly.decommit_bundle.Bundle.decodeBorrowed(a, raw);
        defer nested.deinit(a);
        const p = program.view();
        const c = p.admission.key.config;
        if (nested.rawQueries().len != c.fri_config.n_queries or nested.trees.len != 4 + p.fri_layers.len) return error.InvalidResidentParentDecommitment;
        for (raw[nested.used_words..]) |word| if (word != 0) return error.NonzeroResidentParentTail;
        var claims: [Program.COMPONENT_COUNT]Q = undefined;
        const roots_claims = section(bundle, transport, .trace_commitments);
        for (&claims, 0..) |*q, i| {
            const words = roots_claims[32 + i * 4 ..][0..4];
            for (words) |word| if (word >= core.fields.m31.Modulus) return error.InvalidFieldElement;
            q.* = Q.fromU32Unchecked(words[0], words[1], words[2], words[3]);
        }
        const view = View{ .bundle = bundle, .transport = transport, .decommitment = nested, .protocol = .{ .log_n_rows = p.fri_log, .sequence_len = 0, .pow_bits = c.pow_bits, .log_blowup_factor = c.fri_config.log_blowup_factor, .log_last_layer_degree_bound = c.fri_config.log_last_layer_degree_bound, .n_queries = @intCast(c.fri_config.n_queries), .fold_step = c.fri_config.fold_step, .lifting_log_size = c.lifting_log_size, .commitment_root_count = 4, .fri_root_count = @intCast(p.fri_layers.len), .decommit_tree_count = @intCast(4 + p.fri_layers.len) } };
        const Decoder = native.proof_decode.DecoderFor(PCS.ProofLayout.Layout, struct {});
        const stark = try Decoder.decodeProofWithLayoutFor(Hasher, a, view, &plans.proof_layout);
        return .{ .stark = stark, .claims = claims, .read = read };
    }
};
const View = struct {
    bundle: Bundle,
    transport: []const u32,
    decommitment: cuda.runtime.proof_assembly.decommit_bundle.Bundle,
    protocol: cuda.runtime.proof_assembly.stark_bundle.Protocol,
    pub fn commitmentRoots(self: View) []const u32 {
        return section(self.bundle, self.transport, .trace_commitments)[0..32];
    }
    pub fn sampledValues(self: View) []const u32 {
        return section(self.bundle, self.transport, .sampled_values);
    }
    pub fn friRoots(self: View) []const u32 {
        return section(self.bundle, self.transport, .fri_commitments);
    }
    pub fn lastLayerPolynomial(self: View) []const u32 {
        return section(self.bundle, self.transport, .fri_last_layer);
    }
    pub fn powNonce(self: View) u64 {
        const words = section(self.bundle, self.transport, .proof_of_work);
        return @as(u64, words[0]) | (@as(u64, words[1]) << 32);
    }
};
fn section(bundle: Bundle, words: []const u32, kind: shared.SectionKind) []const u32 {
    const s = bundle.section(kind);
    return words[s.offset_words..][0..s.words];
}
pub fn validateEnvelope(bundle: Bundle, words: []const u32) !void {
    if (words.len != bundle.total_words) return error.InvalidResidentParentTerminal;
    for (bundle.static_header, 0..) |expected, i| {
        if (words[i] != (if (i == 15) @as(u32, 0) else expected)) return if (i == 15) error.InvalidResidentParentVerdict else error.InvalidResidentParentTerminal;
    }
}
test "resident parent terminal has original four roots twenty-five claims and one nonce" {
    const a = std.testing.allocator;
    const program = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer program.deinit();
    var plans = try PCS.Plans.init(a, program, 96 << 30);
    defer plans.deinit();
    var bundle = try init(a, program, &plans);
    defer bundle.deinit(a);
    try bundle.validate(plans.decommit.topology.assembly_capacity_words);
    try std.testing.expectEqual(@as(usize, 132), bundle.section(.trace_commitments).words);
    try std.testing.expectEqual(@as(usize, 2), bundle.section(.proof_of_work).words);
    const words = try a.alloc(u32, bundle.total_words);
    defer a.free(words);
    @memset(words, 0);
    @memcpy(words[0..bundle.static_header.len], bundle.static_header);
    try std.testing.expectError(error.InvalidResidentParentVerdict, validateEnvelope(bundle, words));
    words[15] = 0;
    try validateEnvelope(bundle, words);
    words[5] = 11;
    try std.testing.expectError(error.InvalidResidentParentTerminal, validateEnvelope(bundle, words));
    try std.testing.expectError(error.NonresidentParentProof, (MeasuredRead{ .operations = 1, .bytes = bundle.total_words * 4, .runtime_compile_attempts = 0, .cpu_fallback_attempts = 1 }).validate(bundle.total_words));
    std.mem.doNotOptimizeAway(&Proof.decode);
}
