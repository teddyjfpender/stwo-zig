//! Finite original-native terminal transport. Decoding supplies no proof
//! authority: the independently selected original Native verifier is mandatory.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = @import("stwo_native_cuda_integration").common;
const shared = common.proof_bundle;
const Native = @import("../../frontends/riscv/prover/block_v7_native_proof_v1.zig");
const Projection = @import("../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v1.zig");
const Memory = @import("../../frontends/riscv/prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Hasher = core.proof_suites.Blake3.Hasher;
pub const MeasuredRead = @import("resident_parent_terminal_v1.zig").MeasuredRead;
pub const ACCESS_WORDS = 38;
pub fn ForCommitments(comptime N: usize) type {
    const Program = @import("resident_native_program_v1.zig").ForCommitments(N);
    const PCS = @import("resident_native_pcs_v1.zig").ForCommitments(N);
    return struct {
        const Self = @This();
        pub const Layout = struct {
            sampled_values: usize,
            fri_roots: usize,
            final_coefficients: usize,
            query_count: u32,
            pow_bits: u32,
            blowup: u32,
            fold_step: u32,
            max_log_degree_bound: u32,
            projections: usize,
            accesses: usize,
            physical_claims: usize,
            pub fn derive(program: *const Program.Owned, plans: *const PCS.Plans) !Layout {
                const p = program.view();
                if (!std.mem.eql(u8, &p.identity, &plans.geometry.identity) or plans.proof_layout.sample_total == 0 or p.fri_layers.len == 0) return error.InvalidResidentNativeTerminal;
                const c = p.profile.epoch.config;
                return .{ .sampled_values = plans.proof_layout.sample_total, .fri_roots = p.fri_layers.len, .final_coefficients = try shared.pow2(c.fri_config.log_last_layer_degree_bound), .query_count = @intCast(c.fri_config.n_queries), .pow_bits = c.pow_bits, .blowup = c.fri_config.log_blowup_factor, .fold_step = c.fri_config.fold_step, .max_log_degree_bound = p.composition_log, .projections = p.profile.projections.len, .accesses = p.profile.slots.len, .physical_claims = p.physical_claim_count };
            }
            pub fn claimWords(self: Layout) !usize {
                return std.math.add(usize, try shared.mul(self.projections, 4), try shared.mul(self.accesses, ACCESS_WORDS));
            }
        };
        pub const Decommit = struct { capacity_words: usize };
        const Descriptor = struct {
            pub fn sectionLengths(l: Layout, d: Decommit) ![shared.section_count]usize {
                if (l.sampled_values == 0 or l.fri_roots == 0 or l.final_coefficients == 0 or l.query_count == 0 or d.capacity_words == 0) return error.InvalidResidentNativeTerminal;
                return .{ try std.math.add(usize, N * 8, try l.claimWords()), try shared.mul(l.sampled_values, 4), try shared.mul(l.fri_roots, 8), try shared.mul(l.final_coefficients, 4), 2, d.capacity_words };
            }
            pub fn fixedHeader(l: Layout, _: Decommit, count: usize) ![shared.fixed_header_words]u32 {
                return .{ shared.magic, shared.version, try shared.u32Count(count), shared.section_count, N, try shared.u32Count(l.physical_claims), try shared.u32Count(try shared.mul(l.sampled_values, 4)), try shared.u32Count(l.fri_roots), try shared.u32Count(l.final_coefficients), l.query_count, l.pow_bits, 0, l.max_log_degree_bound, l.blowup, l.fold_step, std.math.maxInt(u32) };
            }
        };
        pub const Bundle = shared.BundleFor(Layout, Decommit, Descriptor);
        pub fn init(a: std.mem.Allocator, p: *const Program.Owned, pcs: *const PCS.Plans) !Bundle {
            return Bundle.init(a, try Layout.derive(p, pcs), .{ .capacity_words = pcs.decommit.topology.assembly_capacity_words });
        }
        pub const Proof = struct {
            original: Native.Proof,
            read: MeasuredRead,
            pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
                self.original.deinit(a);
                self.* = undefined;
            }
            pub fn decode(a: std.mem.Allocator, program: *const Program.Owned, plans: *const PCS.Plans, transport: []const u32, read: MeasuredRead) !Proof {
                var bundle = try Self.init(a, program, plans);
                defer bundle.deinit(a);
                try read.validate(bundle.total_words);
                try validateEnvelope(bundle, transport);
                const raw = try a.dupe(u32, section(bundle, transport, .decommitment));
                defer a.free(raw);
                var nested = try cuda.runtime.proof_assembly.decommit_bundle.Bundle.decodeBorrowed(a, raw);
                defer nested.deinit(a);
                const p = program.view();
                const c = p.profile.epoch.config;
                if (nested.rawQueries().len != c.fri_config.n_queries or nested.trees.len != N + p.fri_layers.len) return error.InvalidResidentNativeDecommitment;
                for (raw[nested.used_words..]) |word| if (word != 0) return error.NonzeroResidentNativeTail;
                const claims = try a.alloc(Projection.Claim, p.profile.projections.len);
                errdefer a.free(claims);
                const memory = try a.alloc(Memory.Claim, p.profile.slots.len);
                errdefer a.free(memory);
                try decodeClaims(program, section(bundle, transport, .trace_commitments)[N * 8 ..], claims, memory);
                const view = View{ .bundle = bundle, .transport = transport, .decommitment = nested, .protocol = .{ .log_n_rows = p.fri_log, .sequence_len = 0, .pow_bits = c.pow_bits, .log_blowup_factor = c.fri_config.log_blowup_factor, .log_last_layer_degree_bound = c.fri_config.log_last_layer_degree_bound, .n_queries = @intCast(c.fri_config.n_queries), .fold_step = c.fri_config.fold_step, .lifting_log_size = c.lifting_log_size, .commitment_root_count = N, .fri_root_count = @intCast(p.fri_layers.len), .decommit_tree_count = @intCast(N + p.fri_layers.len) } };
                const Decoder = common.proof_decode.DecoderFor(PCS.ProofLayout, struct {});
                const stark = try Decoder.decodeProofWithLayoutFor(Hasher, a, view, &plans.proof_layout);
                return .{ .original = .{ .stark = stark, .claims = claims, .memory_claims = memory }, .read = read };
            }
        };
        /// Projection row counts are selected metadata. Access counts are transported
        /// as exact u64, never truncated field elements or inferred host execution.
        pub fn decodeClaims(program: *const Program.Owned, words: []const u32, claims: []Projection.Claim, memory: []Memory.Claim) !void {
            const p = program.view();
            if (claims.len != p.profile.projections.len or memory.len != p.profile.slots.len or words.len != claims.len * 4 + memory.len * ACCESS_WORDS) return error.InvalidResidentNativeClaims;
            var cursor: usize = 0;
            for (claims, p.profile.projections) |*claim, slot| {
                claim.* = .{ .sum = try takeQ(words, &cursor), .row_count = slot.n_rows };
            }
            for (memory, p.profile.slots) |*claim, slot| {
                claim.transition_sum = try takeQ(words, &cursor);
                claim.universal_sum = try takeQ(words, &cursor);
                for (&claim.range_claims) |*q| q.* = try takeQ(words, &cursor);
                claim.active_count = @as(u64, words[cursor]) | (@as(u64, words[cursor + 1]) << 32);
                cursor += 2;
                if (claim.active_count > (@as(u64, 1) << @intCast(slot.log_size))) return error.InvalidResidentNativeActiveCount;
            }
        }
        pub fn requireBundle(program: *const Program.Owned, plans: *const PCS.Plans, bundle: *const Bundle) !void {
            const layout = try Layout.derive(program, plans);
            const decommit = Decommit{ .capacity_words = plans.decommit.topology.assembly_capacity_words };
            try bundle.validate(decommit.capacity_words);
            const lengths = try Descriptor.sectionLengths(layout, decommit);
            for (bundle.sections, lengths) |section_, length| if (section_.words != length) return error.InvalidResidentNativeTerminal;
            const expected = try Descriptor.fixedHeader(layout, decommit, bundle.total_words);
            if (!std.mem.eql(u32, &expected, bundle.static_header[0..shared.fixed_header_words])) return error.InvalidResidentNativeTerminal;
        }
        pub fn validateEnvelope(bundle: Bundle, words: []const u32) !void {
            if (words.len != bundle.total_words) return error.InvalidResidentNativeTerminal;
            for (bundle.static_header, 0..) |expected, i| if (words[i] != (if (i == 15) @as(u32, 0) else expected)) return if (i == 15) error.InvalidResidentNativeVerdict else error.InvalidResidentNativeTerminal;
        }
        const View = struct {
            bundle: Bundle,
            transport: []const u32,
            decommitment: cuda.runtime.proof_assembly.decommit_bundle.Bundle,
            protocol: cuda.runtime.proof_assembly.stark_bundle.Protocol,
            pub fn commitmentRoots(self: View) []const u32 {
                return section(self.bundle, self.transport, .trace_commitments)[0 .. N * 8];
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
                const w = section(self.bundle, self.transport, .proof_of_work);
                return @as(u64, w[0]) | (@as(u64, w[1]) << 32);
            }
        };
        fn section(bundle: Bundle, words: []const u32, kind: shared.SectionKind) []const u32 {
            const s = bundle.section(kind);
            return words[s.offset_words..][0..s.words];
        }
    };
}
fn takeQ(words: []const u32, cursor: *usize) !Q {
    const w = words[cursor.*..][0..4];
    for (w) |x| if (x >= core.fields.m31.Modulus) return error.InvalidFieldElement;
    cursor.* += 4;
    return Q.fromU32Unchecked(w[0], w[1], w[2], w[3]);
}
