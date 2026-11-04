//! Receiver-owned *candidate* construction and conditional error accountant.
//! No proof acceptance path selects this suite; no 128-bit certificate exists.
//! Values supplied by a proof bundle are not authority for Facts or reviews.
const std = @import("std");
const core = @import("stwo_core");
const Policy = @import("security_policy.zig");
pub const O = core.fields.om31.OM31;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const ID_DOMAIN = "rv64-om31-rawblake-native-localgkr-128-CANDIDATE/v2\x00";
pub const MAX_PROOFS: u64 = 256;
pub const MAX_TRACE_LOG: u32 = 22;
/// Only receiver-validated public INIT/TEARDOWN; never CPU/provider clocks.
pub const MAX_PUBLIC_BOUNDARY_LOG: u32 = 23;
pub const MAX_COLUMNS: u64 = 16384;
pub const MAX_CONSTRAINTS: u64 = 65536;
pub const MAX_SAMPLES_PER_COLUMN: u64 = 8;
pub const MAX_AIR_DEGREE: u64 = 5;
pub const MAX_LOCAL_INSTANCES: u64 = 128;
pub const MAX_TUPLE_ARITY: u64 = 128;
/// FROZEN identity input of the two admitted native profiles (`identity()`,
/// `profileIdentity()`): the stale pre-`byte_pair` roster count. Changing it
/// changes every admitted native proof byte, so it stays 9 until those profiles
/// are retired. It is NOT the roster size: see `ROSTER_LOCAL_RELATIONS`. Every
/// new native version hashes the real count (`M5_LOCAL_RELATIONS`), and the
/// ledger counts the real roster (stream profiles, M6 P4).
pub const LOCAL_RELATIONS: u64 = 9;
/// Production raw-fraction roster size (`gkr_local/fractions.zig Relation`,
/// `byte_pair` added in 63728c3f8). Pinned against the enum by a test.
pub const ROSTER_LOCAL_RELATIONS: u64 = 10;
pub const GLOBAL_RELATIONS: u64 = 3;
pub const MAX_GKR_VARIABLES: u32 = 30;
pub const MAX_ROUND_COUNT: u64 = 1 << 20;
pub const TARGET_BITS: u16 = 128;
/// Engineering target and explicit assumption scope, not certificate authority.
/// Reporting metadata only: excluded from identity()/begin() and proof framing.
pub const ASSUMPTION_TARGET = .{
    .label = "128-bit security target under documented assumptions",
    .target_bits = TARGET_BITS,
    .assumption_set = "rv64-native-om31-beta2-q256-p0-fold4-assumptions-20261102-v2-boundary23",
    .scope = "native proof bundle; recursion excluded",
    .budget_scope = "receiver-derived roster-specific bounds; changed guest or geometry requires a matching bounded review",
    .bounded_engineering_review_complete = true,
    .independent_security_audit_complete = false,
    .whole_protocol_128_certified = false,
};
/// A bounded concrete-RO audit range, not a redefinition/certificate of the
/// unrestricted target. At T=2^128 the whitepaper's conservative collision
/// term alone exceeds the literal 2^-128-per-work inequality for raw256 bits.
pub const MAX_AUDITED_LOG_WORK: u8 = 120;

/// Named PCS/security profiles of the native OM31 local-GKR route. A
/// receiver selects one from its OWN policy (CLI/request), never from proof
/// bytes; the PCS config is mixed into every worker channel, the proof's
/// config must equal the receiver's, and non-legacy profiles additionally bind
/// `profileIdentity` into the fixed-authority statement and channel.
pub const Profile = enum {
    /// Documented proven (unique-decoding) bounded model: blowup 4, 256
    /// queries, no PoW, fold-4. Historical bytes; selectable by name.
    proven_beta2_q256_p0_fold4,
    /// 128-bit CONJECTURED security (ethSTARK-style FRI accounting, owner
    /// decision 2026-11-02): blowup 2, 108 queries, 20-bit PoW, fold-4.
    /// Conjectured FRI bits = 1*108 + 20 = 128. Not a proven bound; see
    /// design/riscv-proving-stack/rv64-gkr-conjectured128-profile.md.
    conjectured128_b2_q108_p20_fold4,

    pub fn name(self: Profile) []const u8 {
        return @tagName(self);
    }
    pub fn parse(text: []const u8) !Profile {
        inline for (@typeInfo(Profile).@"enum".fields) |field| {
            if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
        }
        return error.UnknownOm31CandidateProfile;
    }
    pub fn conjectured(self: Profile) bool {
        return self == .conjectured128_b2_q108_p20_fold4;
    }
};
/// Default profile of the v3 GKR candidate route.
pub const DEFAULT_PROFILE: Profile = .conjectured128_b2_q108_p20_fold4;
pub const PROFILES = [_]Profile{ .proven_beta2_q256_p0_fold4, .conjectured128_b2_q108_p20_fold4 };
pub fn configFor(profile: Profile) core.pcs.PcsConfig {
    const log_blowup: u32, const queries: usize, const pow: u32 = switch (profile) {
        .proven_beta2_q256_p0_fold4 => .{ 2, 256, 0 },
        .conjectured128_b2_q108_p20_fold4 => .{ 1, 108, 20 },
    };
    var fri = core.fri.FriConfig.init(0, log_blowup, queries) catch unreachable;
    fri.fold_step = 4;
    return .{ .pow_bits = pow, .fri_config = fri };
}
/// Conjectured FRI security bits (ethSTARK-style: log_blowup * queries + PoW).
/// Reporting only; for the proven profile the documented bound is the
/// unique-decoding model, not this formula.
pub fn conjecturedBits(profile: Profile) u32 {
    const c = configFor(profile);
    return c.fri_config.log_blowup_factor * @as(u32, @intCast(c.fri_config.n_queries)) + c.pow_bits;
}
/// Exact-match lookup. Any config that is not one registered profile fails.
pub fn profileFor(actual: core.pcs.PcsConfig) !Profile {
    for (PROFILES) |profile| if (std.meta.eql(actual, configFor(profile))) return profile;
    return error.UnrecognizedOm31CandidateParameters;
}
/// The historical proven-model config (callers that predate named profiles).
pub fn config() core.pcs.PcsConfig {
    return configFor(.proven_beta2_q256_p0_fold4);
}
pub fn requireParameters(actual: core.pcs.PcsConfig) !void {
    if (!std.meta.eql(actual, config())) return error.UnrecognizedOm31CandidateParameters;
}
pub fn requireProfileParameters(profile: Profile, actual: core.pcs.PcsConfig) !void {
    if (!std.meta.eql(actual, configFor(profile))) return error.UnrecognizedOm31CandidateParameters;
}
pub const CONJECTURED_ID_DOMAIN = "rv64-om31-rawblake-native-localgkr-128-CONJECTURED-ethstark/v2\x00";
/// Profile identity. The proven profile keeps `identity()`; the conjectured
/// profile hashes a distinct domain, its label, every PCS parameter and the
/// same receiver caps.
pub fn profileIdentity(profile: Profile) [32]u8 {
    if (profile == .proven_beta2_q256_p0_fold4) return identity();
    const c = configFor(profile);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(CONJECTURED_ID_DOMAIN);
    h.update(profile.name());
    h.update(&Channel.profile.identity());
    for ([_]u64{ 8, c.fri_config.n_queries, c.fri_config.log_blowup_factor, c.fri_config.fold_step, c.pow_bits, c.fri_config.log_last_layer_degree_bound, conjecturedBits(profile), MAX_PROOFS, MAX_TRACE_LOG, MAX_PUBLIC_BOUNDARY_LOG, MAX_COLUMNS, MAX_CONSTRAINTS, MAX_SAMPLES_PER_COLUMN, MAX_AIR_DEGREE, MAX_LOCAL_INSTANCES, MAX_TUPLE_ARITY, LOCAL_RELATIONS, GLOBAL_RELATIONS, MAX_GKR_VARIABLES, MAX_ROUND_COUNT, TARGET_BITS }) |n| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
pub const ConjecturedTarget = struct {
    label: []const u8 = "128-bit CONJECTURED security (ethSTARK-style FRI conjecture; owner-accepted 2026-11-02)",
    target_bits: u16 = TARGET_BITS,
    profile: []const u8 = "conjectured128_b2_q108_p20_fold4",
    assumption_set: []const u8 = "rv64-native-v3-om31-conjectured128-b2-q108-p20-fold4-20261102-v2-boundary23",
    conjectured_fri_bits: u32 = 128,
    scope: []const u8 = "native proof bundle; recursion excluded",
    proven_bound: bool = false,
    independent_security_audit_complete: bool = false,
    whole_protocol_128_certified: bool = false,
};
/// Reporting metadata for a selected profile (never proof authority).
pub const Target = union(enum) {
    proven: @TypeOf(ASSUMPTION_TARGET),
    conjectured: ConjecturedTarget,
    /// Payload only: the proven profile keeps its historical report schema.
    pub fn jsonStringify(self: Target, writer: anytype) !void {
        switch (self) {
            inline else => |value| try writer.write(value),
        }
    }
};
pub fn assumptionTarget(profile: Profile) Target {
    return switch (profile) {
        .proven_beta2_q256_p0_fold4 => .{ .proven = ASSUMPTION_TARGET },
        .conjectured128_b2_q108_p20_fold4 => .{ .conjectured = .{} },
    };
}
/// Receiver hook for an explicitly selected candidate route. This admits only
/// the pinned native construction; whole-protocol promotion remains separate.
pub fn admitNative(comptime S: type, comptime Ch: type, comptime H: type, actual: core.pcs.PcsConfig, profile_id: [32]u8, facts: Facts) !void {
    if (S != O or Ch != Channel or H != Hasher) return error.UnrecognizedOm31CandidateAuthorities;
    try requireParameters(actual);
    try requireIdentity(profile_id);
    try facts.validate();
}
pub fn identity() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(ID_DOMAIN);
    h.update(&Channel.profile.identity());
    for ([_]u64{ 8, 256, 2, 4, 0, MAX_PROOFS, MAX_TRACE_LOG, MAX_PUBLIC_BOUNDARY_LOG, MAX_COLUMNS, MAX_CONSTRAINTS, MAX_SAMPLES_PER_COLUMN, MAX_AIR_DEGREE, MAX_LOCAL_INSTANCES, MAX_TUPLE_ARITY, LOCAL_RELATIONS, GLOBAL_RELATIONS, MAX_GKR_VARIABLES, MAX_ROUND_COUNT, TARGET_BITS, MAX_AUDITED_LOG_WORK }) |n| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
pub fn requireIdentity(actual: [32]u8) !void {
    if (!std.mem.eql(u8, &actual, &identity())) return error.UnrecognizedOm31CandidateIdentity;
}
pub fn begin(channel: *Channel, admitted: Facts) !void {
    try admitted.validate();
    channel.mixU32s(&.{ 0x52563634, 0x53454338, 1 });
    for (identity()) |b| channel.mixU64(b);
    config().mixInto(channel);
    for (admitted.words()) |n| channel.mixU64(n);
}

/// Derived by the RECEIVER from admitted immutable geometry, full execution
/// coverage and relation weights. These are bounds over the entire block, not
/// only one child. Do not decode these from producer self-reported metadata.
pub const Facts = struct {
    native_proofs: u64,
    max_trace_log: u32,
    max_public_boundary_log: u32 = 5,
    max_columns: u64,
    max_constraints: u64,
    max_samples_per_column: u64,
    max_air_degree: u64,
    max_local_instances: u64,
    max_tuple_arity: u64,
    max_gkr_variables: u32,
    /// Ordinary integer positive/negative mass separately, per relation and
    /// challenge group. Independent local proof groups are unioned explicitly.
    /// Source range/Boolean/weighted-fact semantics must justify these bounds.
    max_positive_mass: u64,
    max_negative_mass: u64,
    max_multiplicity: u64,
    transcript_rounds: u64,
    pub fn caps() Facts {
        return .{ .native_proofs = MAX_PROOFS, .max_trace_log = MAX_TRACE_LOG, .max_public_boundary_log = MAX_PUBLIC_BOUNDARY_LOG, .max_columns = MAX_COLUMNS, .max_constraints = MAX_CONSTRAINTS, .max_samples_per_column = MAX_SAMPLES_PER_COLUMN, .max_air_degree = MAX_AIR_DEGREE, .max_local_instances = MAX_LOCAL_INSTANCES, .max_tuple_arity = MAX_TUPLE_ARITY, .max_gkr_variables = MAX_GKR_VARIABLES, .max_positive_mass = core.fields.m31.Modulus - 1, .max_negative_mass = core.fields.m31.Modulus - 1, .max_multiplicity = core.fields.m31.Modulus - 1, .transcript_rounds = MAX_ROUND_COUNT };
    }
    pub fn validate(self: Facts) !void {
        if (self.native_proofs == 0 or self.native_proofs > MAX_PROOFS or self.max_trace_log < 5 or self.max_trace_log > MAX_TRACE_LOG or self.max_public_boundary_log < 5 or self.max_public_boundary_log > MAX_PUBLIC_BOUNDARY_LOG or self.max_columns == 0 or self.max_columns > MAX_COLUMNS or self.max_constraints == 0 or self.max_constraints > MAX_CONSTRAINTS or self.max_samples_per_column == 0 or self.max_samples_per_column > MAX_SAMPLES_PER_COLUMN or self.max_air_degree == 0 or self.max_air_degree > MAX_AIR_DEGREE or self.max_local_instances == 0 or self.max_local_instances > MAX_LOCAL_INSTANCES or self.max_tuple_arity == 0 or self.max_tuple_arity > MAX_TUPLE_ARITY or self.max_gkr_variables < 1 or self.max_gkr_variables > MAX_GKR_VARIABLES or self.transcript_rounds == 0 or self.transcript_rounds > MAX_ROUND_COUNT)
            return error.Om31CandidateScopeExceeded;
        const p = core.fields.m31.Modulus;
        if (self.max_positive_mass >= p or self.max_negative_mass >= p or self.max_multiplicity >= p)
            return error.Om31CandidateCharacteristicBoundExceeded;
    }
    fn words(self: Facts) [14]u64 {
        return .{ self.native_proofs, self.max_trace_log, self.max_public_boundary_log, self.max_columns, self.max_constraints, self.max_samples_per_column, self.max_air_degree, self.max_local_instances, self.max_tuple_arity, self.max_gkr_variables, self.max_positive_mass, self.max_negative_mass, self.max_multiplicity, self.transcript_rounds };
    }
};
pub const AlgebraicTerm = enum { tuple_compression, local_rational_identity, global_rational_identity, pole_events, gkr_sumcheck, gkr_instance_mix, gkr_late_binding, composition_mix, oods, deep_batching, fri_folding };
pub const Basis = enum { conditional_root_count, binding_theorem_required, circle_pcs_theorem_required, unreviewed_fri_envelope };
pub fn basis(term: AlgebraicTerm) Basis {
    return switch (term) {
        .gkr_late_binding => .binding_theorem_required,
        .oods, .deep_batching => .circle_pcs_theorem_required,
        .fri_folding => .unreviewed_fri_envelope,
        else => .conditional_root_count,
    };
}
pub const TERM_COUNT = @typeInfo(AlgebraicTerm).@"enum".fields.len;
pub const Ledger = struct {
    degree_weight: [TERM_COUNT]u512,
    pub fn total(self: Ledger) !u512 {
        var n: u512 = 0;
        for (self.degree_weight) |term| n = std.math.add(u512, n, term) catch return error.Om31CandidateBudgetOverflow;
        return n;
    }
    /// Conditional on nonzero polynomials, fixed prior messages, applicable
    /// list/correlated-agreement bounds and fresh ideal-RO256 challenge blocks.
    /// Raw modulo has max point probability 3^8/2^256. No PoW is credited.
    pub fn requireRawModuloBits(self: Ledger, bits: u16) !void {
        if (bits == 0 or bits > 256) return error.InvalidSecurityTarget;
        const weighted = std.math.mul(u512, try self.total(), 6561) catch return error.Om31CandidateBudgetOverflow;
        if (weighted > (@as(u512, 1) << 256) >> @intCast(bits))
            return error.Om31CandidateAlgebraicBudgetInsufficient;
    }
};
pub fn ledger(facts: Facts) !Ledger {
    try facts.validate();
    const p: u512 = facts.native_proofs;
    const n: u512 = @as(u512, 1) << @intCast(@max(facts.max_trace_log, facts.max_public_boundary_log));
    const c: u512 = facts.max_columns;
    const arity: u512 = facts.max_tuple_arity;
    const mass: u512 = @as(u512, facts.max_positive_mass) + facts.max_negative_mass;
    const v: u512 = facts.max_gkr_variables;
    const i: u512 = facts.max_local_instances;
    // Real roster count (10), not the frozen identity input (9): the ledger is
    // reporting arithmetic only and is not hashed, so this is proof-neutral.
    const local = ROSTER_LOCAL_RELATIONS;
    const global = GLOBAL_RELATIONS;
    var out: Ledger = undefined;
    // Full pairwise tuple union is intentionally conservative. It requires the
    // source-admitted integer support/mass interpretation; field residues alone
    // cannot establish the characteristic assumption.
    out.degree_weight[@intFromEnum(AlgebraicTerm.tuple_compression)] = (p * local + global) * arity * mass * mass;
    out.degree_weight[@intFromEnum(AlgebraicTerm.local_rational_identity)] = p * local * mass;
    out.degree_weight[@intFromEnum(AlgebraicTerm.global_rational_identity)] = global * mass;
    out.degree_weight[@intFromEnum(AlgebraicTerm.pole_events)] = (p * local + global) * mass;
    out.degree_weight[@intFromEnum(AlgebraicTerm.gkr_sumcheck)] = p * i * 3 * v * (v - 1) / 2;
    out.degree_weight[@intFromEnum(AlgebraicTerm.gkr_instance_mix)] = p * (i + 2) * v;
    out.degree_weight[@intFromEnum(AlgebraicTerm.gkr_late_binding)] = p * i;
    out.degree_weight[@intFromEnum(AlgebraicTerm.composition_mix)] = p * facts.max_constraints;
    // Two circle coordinates/offsets and degree≤5 constraints are overbounded by
    // 32N per sample. This term is CONDITIONAL on the applicable PCS reduction;
    // it is not a proof of list/line decoding or this quotient implementation.
    out.degree_weight[@intFromEnum(AlgebraicTerm.oods)] = p * c * facts.max_samples_per_column * 32 * n;
    out.degree_weight[@intFromEnum(AlgebraicTerm.deep_batching)] = p * c * facts.max_samples_per_column * 32 * n;
    // UNREVIEWED engineering envelope for list ≤16, fold ≤4, domain/circle
    // factors, columns and all V+1 rounds. The 65536 factor is an assumed
    // envelope, NOT an instantiated FRI theorem. Promotion requires review.
    out.degree_weight[@intFromEnum(AlgebraicTerm.fri_folding)] = p * (c + 1) * 65536 * n * (v + 1);
    return out;
}
/// Exact rational calculation: candidate Johnson agreementα=5/8, queries256,
/// union over the whole native-proof roster. This models QUERY error only.
pub fn requireQueryBits(facts: Facts, bits: u16) !void {
    try facts.validate();
    if (bits == 0 or bits > 256) return error.InvalidSecurityTarget;
    var numerator: u1024 = facts.native_proofs;
    var denominator: u1024 = 1;
    for (0..256) |_| {
        numerator *= 5;
        denominator *= 8;
    }
    if (numerator << @intCast(bits) > denominator) return error.Om31CandidateQueryBudgetInsufficient;
}
/// Necessary conditional NIROP arithmetic in a declared bounded RO-work range.
/// Tests BOTH errors, including raw256 collision term. This is NOT an
/// applicable-theorem witness, computational proof, or promotion authority.
pub fn requireConditionalRomBudget(facts: Facts, log_work: u8) !void {
    if (log_work > MAX_AUDITED_LOG_WORK) return error.Om31CandidateUnreviewedWorkRange;
    const l = try ledger(facts);
    // Reserve2 bits for union of algebraic/query/hash categories; worst case
    // (T+R)/T <=1+R<=2^21 for T>=1 under this receiver round cap.
    try l.requireRawModuloBits(TARGET_BITS + 2 + 21);
    try requireQueryBits(facts, TARGET_BITS + 2 + 21);
    // 3(T²+1)/(T*2^256) <=6*2^log_work/2^256, for T>=1.
    if (@as(u512, 6) << @intCast(@as(u16, log_work) + TARGET_BITS + 2) > @as(u512, 1) << 256)
        return error.Om31CandidateHashBudgetInsufficient;
}
pub const Reviews = struct {
    beta2_immutable_setup_qualified: bool = false,
    all_native_and_global_arguments_om31: bool = false,
    circle_fri_actual_query_layout_theorem: bool = false,
    quotient_only_degree_corrected_relation: bool = false,
    source_weight_and_characteristic_proof: bool = false,
    gkr_binding_and_late_mix_theorem: bool = false,
    adaptive_raw_mod_rom_theorem: bool = false,
    all_recursive_layers_om31_and_raw_channel: bool = false,
};
pub fn requireWholeProtocolPromotion(reviews: Reviews) !void {
    inline for (@typeInfo(Reviews).@"struct".fields) |field| {
        if (!@field(reviews, field.name)) return error.Om31CandidateReviewIncomplete;
    }
    // No caller-controlled booleans or successful necessary checks can admit
    // a certificate. A reviewed construction needs a new receiver registry ID.
    return error.NoReviewedWholeProtocol128Certificate;
}
// ---------------------------------------------------------------------------
// M7 candidate profiles (stream profiles, 2026-11-04). OFF BY DEFAULT.
//
// These are NOT members of `Profile`, `PROFILES`, `Profile.parse` or the outer
// `protocol.Profile`: no CLI flag, environment variable, proof byte or
// receiver policy can select one. They exist so the M7 arithmetic is pinned
// and tested before any circuit or prover depends on it. Promotion of an entry
// = moving it into the layer's admitted registry (native: `Profile`; outer /
// compress: `circuit_cpu/om31/protocol.zig`, owner canon-vk/compress) together
// with fresh-receiver acceptance and the reviewed note
// design/riscv-proving-stack/rv64-m7-profiles.md.
//
// `fold_step` is the LOG2 FRI folding arity per layer (core/fri: positions >>=
// fold_step). Today's "fold4" therefore already folds 16-to-1 per FRI layer;
// "FRI fold 8" is fold_step 3 and "fold 16" is fold_step 4.
// ---------------------------------------------------------------------------
pub const Layer = enum { native, outer, compress1, compress2 };
pub const CandidateProfile = enum {
    /// D2: native blowup 4, 54 queries, 20-bit PoW. 2*54 + 20 = 128.
    d2_native_b4_q54_p20_fold4,
    /// Outer leaf/fold/root (recsize 5d68d0f01 `m3_b4_q51_p26_fold4`). 2*51 + 26 = 128.
    m3_outer_b4_q51_p26_fold4,
    /// Outer alternative of recsize (protocol.zig `m3_b8_q34_p26_fold4`). 3*34 + 26 = 128.
    m3_outer_b8_q34_p26_fold4,
    /// C1 narrow compress: blowup 8, 36 queries, 20-bit PoW. 3*36 + 20 = 128.
    c1_b8_q36_p20_fold4,
    /// C2 final compress, FRI arity 8: blowup 16, 27 queries, 20-bit PoW. 4*27 + 20 = 128.
    c2_b16_q27_p20_fold3,
    /// C2 final compress, FRI arity 16 (same arity as today's fold4).
    c2_b16_q27_p20_fold4,

    pub fn name(self: CandidateProfile) []const u8 {
        return @tagName(self);
    }
};
pub const CandidateSpec = struct {
    layer: Layer,
    log_blowup: u32,
    queries: u32,
    pow_bits: u32,
    /// log2 FRI arity per layer.
    fold_step: u32,
    log_last_layer: u32 = 0,
    /// Domain string to hash into authority identity, wire header and both
    /// transcripts once promoted (outer convention of protocol.zig).
    domain: []const u8,
    /// Proof FRAMING (M7 compress, rv64-m7-compress-profiles.md). None of these
    /// changes a soundness term; each changes bytes, so each is hashed.
    /// log2 of the Merkle cap: the commitment is the 2^cap_log nodes at that
    /// level (all mixed into the transcript), paths stop below it. 0 = root.
    merkle_cap_log: u32 = 0,
    /// log2 Merkle arity (1 = binary, today's Blake2s hasher; 2 = arity 4 needs
    /// a new hasher and is not registered).
    merkle_arity_log: u32 = 1,
    /// Batched (deduplicated) decommitment: the verifier recomputes shared
    /// nodes; the wire carries exactly the canonical sibling set.
    multiproof: bool = false,
    // The pruned last FRI layer is `log_last_layer` above (core already sends
    // the last layer as 2^log_last_layer coefficients): stopping FRI 3 layers
    // early drops those layers' sibling openings from every query.
};
pub const CANDIDATE_PROFILES = [_]CandidateProfile{ .d2_native_b4_q54_p20_fold4, .m3_outer_b4_q51_p26_fold4, .m3_outer_b8_q34_p26_fold4, .c1_b8_q36_p20_fold4, .c2_b16_q27_p20_fold3, .c2_b16_q27_p20_fold4 };
pub fn candidateSpec(profile: CandidateProfile) CandidateSpec {
    return switch (profile) {
        .d2_native_b4_q54_p20_fold4 => .{ .layer = .native, .log_blowup = 2, .queries = 54, .pow_bits = 20, .fold_step = 4, .domain = "rv64-om31-native-d2-b4-q54-p20-fold4/CANDIDATE-v1" },
        .m3_outer_b4_q51_p26_fold4 => .{ .layer = .outer, .log_blowup = 2, .queries = 51, .pow_bits = 26, .fold_step = 4, .domain = "stwo/circuit/native-om31/m3-b4-q51-p26-fold4/lens-v1" },
        .m3_outer_b8_q34_p26_fold4 => .{ .layer = .outer, .log_blowup = 3, .queries = 34, .pow_bits = 26, .fold_step = 4, .domain = "stwo/circuit/native-om31/m3-b8-q34-p26-fold4/lens-v1" },
        // C1 runs on device in the request path: caps + multiproof only (cheap host
        // framing); C2 is the shipped compact proof and takes every framing lever.
        .c1_b8_q36_p20_fold4 => .{ .layer = .compress1, .log_blowup = 3, .queries = 36, .pow_bits = 20, .fold_step = 4, .domain = "stwo/circuit/native-om31/c1-b8-q36-p20-fold4/lens-v1", .merkle_cap_log = 4, .multiproof = true },
        .c2_b16_q27_p20_fold3 => .{ .layer = .compress2, .log_blowup = 4, .queries = 27, .pow_bits = 20, .fold_step = 3, .log_last_layer = 3, .domain = "stwo/circuit/native-om31/c2-b16-q27-p20-fold3/lens-v1", .merkle_cap_log = 4, .multiproof = true },
        .c2_b16_q27_p20_fold4 => .{ .layer = .compress2, .log_blowup = 4, .queries = 27, .pow_bits = 20, .fold_step = 4, .log_last_layer = 3, .domain = "stwo/circuit/native-om31/c2-b16-q27-p20-fold4/lens-v1", .merkle_cap_log = 4, .multiproof = true },
    };
}
pub fn candidateConfig(profile: CandidateProfile) core.pcs.PcsConfig {
    const s = candidateSpec(profile);
    var fri = core.fri.FriConfig.init(s.log_last_layer, s.log_blowup, s.queries) catch unreachable;
    fri.fold_step = s.fold_step;
    return .{ .pow_bits = s.pow_bits, .fri_config = fri };
}
/// ethSTARK-conjecture bits: log_blowup * queries + PoW (same formula as
/// `conjecturedBits` and `protocol.Profile.conjecturedBits`).
pub fn candidateConjecturedBits(profile: CandidateProfile) u32 {
    const c = candidateConfig(profile);
    return c.fri_config.log_blowup_factor * @as(u32, @intCast(c.fri_config.n_queries)) + c.pow_bits;
}
/// Twice the query bits under the provable Johnson regime (per-query error
/// about sqrt(rho)): 2 * (queries * log_blowup / 2 + pow). Doubled to stay integral.
pub fn candidateJohnsonBitsTimes2(profile: CandidateProfile) u32 {
    const s = candidateSpec(profile);
    return s.queries * s.log_blowup + 2 * s.pow_bits;
}
/// Johnson-regime doubled bits of the admitted native default (108 + 40 = 148).
pub fn baselineJohnsonBitsTimes2() u32 {
    const c = configFor(DEFAULT_PROFILE);
    return @as(u32, @intCast(c.fri_config.n_queries)) * c.fri_config.log_blowup_factor + 2 * c.pow_bits;
}
/// v2 (M6): framing fields hashed. No v1 candidate identity was ever consumed.
pub const CANDIDATE_ID_DOMAIN = "rv64-om31-m7-candidate-profile/v2\x00";
/// Candidate identity: distinct domain, layer, every PCS parameter and the
/// conjectured bits. Never equal to an admitted `profileIdentity`.
pub fn candidateIdentity(profile: CandidateProfile) [32]u8 {
    const s = candidateSpec(profile);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(CANDIDATE_ID_DOMAIN);
    h.update(profile.name());
    h.update(s.domain);
    h.update(&Channel.profile.identity());
    for ([_]u64{ @intFromEnum(s.layer), s.log_blowup, s.queries, s.pow_bits, s.fold_step, s.log_last_layer, candidateConjecturedBits(profile), TARGET_BITS, s.merkle_cap_log, s.merkle_arity_log, @intFromBool(s.multiproof) }) |n| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
/// A candidate config is never an admitted native profile: `profileFor`
/// must keep rejecting it until promotion.
pub fn requireCandidateNotAdmitted(profile: CandidateProfile) !void {
    if (profileFor(candidateConfig(profile))) |_| return error.Om31CandidateProfileAlreadyAdmitted else |_| {}
}

/// Outer LogUp-GKR (M7) algebraic budget, reporting only. Same conditional
/// root-count model as `ledger` (Schwartz-Zippel per challenge, raw-modulo
/// point probability 3^8/2^256, no PoW credited), applied to the outer proofs
/// of one request whose interaction columns are proven by a batched LogUp-GKR
/// instead of committed LogUp columns. See rv64-m7-profiles.md section 4.
pub const OuterGkrFacts = struct {
    /// Outer proofs in one request (leaves + folds + root + compress).
    outer_proofs: u64,
    /// Batched GKR instances per outer proof (relations x components).
    instances: u64,
    /// log2 of the largest instance (rows); = number of GKR layers.
    max_variables: u32,
    /// Max tuple arity of a LogUp relation in the outer circuit AIR.
    max_tuple_arity: u64,
    /// Sumcheck round-polynomial degree (LogUp fraction layer: 3).
    round_degree: u64 = 3,
    pub fn caps() OuterGkrFacts {
        return .{ .outer_proofs = 256, .instances = 128, .max_variables = 30, .max_tuple_arity = 128 };
    }
    pub fn validate(self: OuterGkrFacts) !void {
        if (self.outer_proofs == 0 or self.outer_proofs > 256 or self.instances == 0 or self.instances > 1024 or self.max_variables < 1 or self.max_variables > MAX_GKR_VARIABLES or self.max_tuple_arity == 0 or self.max_tuple_arity > MAX_TUPLE_ARITY or self.round_degree == 0 or self.round_degree > 8)
            return error.Om31CandidateScopeExceeded;
    }
};
pub const OuterGkrTerm = enum { sumcheck_rounds, instance_mix, layer_binding, tuple_compression, pole_events };
pub const OUTER_GKR_TERMS = @typeInfo(OuterGkrTerm).@"enum".fields.len;
pub fn outerGkrLedger(facts: OuterGkrFacts) ![OUTER_GKR_TERMS]u512 {
    try facts.validate();
    const p: u512 = facts.outer_proofs;
    const i: u512 = facts.instances;
    const v: u512 = facts.max_variables;
    const d: u512 = facts.round_degree;
    const n: u512 = @as(u512, 1) << @intCast(facts.max_variables);
    const arity: u512 = facts.max_tuple_arity;
    var out: [OUTER_GKR_TERMS]u512 = undefined;
    // Layer k has k sumcheck rounds of degree d: sum_{k<=v} k*d = d*v(v+1)/2,
    // per instance (overbound: no credit for batching instances in one sumcheck).
    out[@intFromEnum(OuterGkrTerm.sumcheck_rounds)] = p * i * d * v * (v + 1) / 2;
    // Random linear combination of instances (numerator and denominator) per layer.
    out[@intFromEnum(OuterGkrTerm.instance_mix)] = p * (2 * i + 2) * v;
    // Reducing two evaluation claims to one per layer (line restriction), degree <= 2.
    out[@intFromEnum(OuterGkrTerm.layer_binding)] = p * i * 2 * v;
    // Distinct tuples colliding under alpha-compression (degree arity), over N rows.
    out[@intFromEnum(OuterGkrTerm.tuple_compression)] = p * i * arity * n;
    // z hitting a compressed tuple (denominator pole), or the cleared rational identity in z.
    out[@intFromEnum(OuterGkrTerm.pole_events)] = p * i * 2 * n;
    return out;
}
fn outerGkrTotal(facts: OuterGkrFacts) !u512 {
    var total: u512 = 0;
    for (try outerGkrLedger(facts)) |t| total = std.math.add(u512, total, t) catch return error.Om31CandidateBudgetOverflow;
    return total;
}
/// Necessary arithmetic for OM31 challenges: union of the terms times the
/// raw-modulo point probability 3^8/2^256 is at most 2^-bits. Not a theorem.
pub fn requireOuterGkrBits(facts: OuterGkrFacts, bits: u16) !void {
    if (bits == 0 or bits > 256) return error.InvalidSecurityTarget;
    const weighted = std.math.mul(u512, try outerGkrTotal(facts), 6561) catch return error.Om31CandidateBudgetOverflow;
    if (weighted > (@as(u512, 1) << 256) >> @intCast(bits)) return error.Om31CandidateAlgebraicBudgetInsufficient;
}
/// The same ledger if the GKR challenges were QM31 (|F| = p^4, about 2^124):
/// shows why the outer GKR must draw OM31 challenges (the plan's
/// 2^-110..2^-115 estimate is this QM31 case).
pub fn requireOuterGkrBitsQm31(facts: OuterGkrFacts, bits: u16) !void {
    if (bits == 0 or bits > 124) return error.InvalidSecurityTarget;
    const p: u512 = core.fields.m31.Modulus;
    if ((try outerGkrTotal(facts)) << @intCast(bits) > p * p * p * p) return error.Om31CandidateAlgebraicBudgetInsufficient;
}
/// Characteristic bound for the outer LogUp (committed or GKR). Over M31 a
/// LogUp sum is sound only while the total multiplicity of every key stays
/// below p (the native receiver enforces the same as GlobalRamCharacteristicBound
/// / CombinedLookupMassExceeded). The Schwartz-Zippel ledger above does not
/// cover it: a multiplicity m and m + p are the same field element whatever the
/// challenge field. Conservative mass: every instance of one outer proof feeds a
/// single relation at full height, instances * 2^max_variables. Review 1
/// (rv64-m7-profiles.md section 4.2, finding 5).
pub fn outerGkrMassBound(facts: OuterGkrFacts) !u64 {
    try facts.validate();
    return std.math.mul(u64, facts.instances, @as(u64, 1) << @intCast(facts.max_variables)) catch return error.Om31CandidateBudgetOverflow;
}
/// `relation_mass`: the circuit's measured worst per-relation multiplicity
/// mass (null = use the conservative outerGkrMassBound). Must be < p.
pub fn requireOuterGkrCharacteristic(facts: OuterGkrFacts, relation_mass: ?u64) !void {
    const mass = relation_mass orelse try outerGkrMassBound(facts);
    if (mass >= core.fields.m31.Modulus) return error.Om31CandidateCharacteristicWrap;
}

// ---------------------------------------------------------------------------
// M5/M7 named FORMAT versions (stream profiles, review 2, 2026-11-04). OFF BY DEFAULT.
//
// A format version keeps the PCS parameters of a base profile and changes what
// is proven or how it is framed (canonical leaves, the chi chain, NS, an outer
// GKR section, the fused Blake2s AIR). It therefore needs its own domain string
// and identity, so no proof of one version verifies under another, but it adds
// no conjectured bits and loses none. Same promotion rule as the candidates:
// the owning stream moves the entry into its admitted registry together with
// fresh-receiver acceptance and the reviewed notes rv64-m5-binding.md (sec. 10)
// and rv64-m7-profiles.md.
// ---------------------------------------------------------------------------
pub const PcsParams = struct { log_blowup: u32, queries: u32, pow_bits: u32, fold_step: u32 };
pub const FormatVersion = enum {
    /// canon-native: native proof with the M5 chi chain (binding 3.3, lambda_k of
    /// F13), the mb family and LOCAL_RELATIONS = 10 (fixes the 9-vs-10 drift).
    m5_native_chi_chain_v1_b2_q108_p20_fold4,
    /// canon-vk: canonical leaf / k-ary fold / NS (binding 2-4) on the r1 outer PCS.
    m5_outer_canonical_r1_b2_q108_p20_fold4_v1,
    /// canon-vk: the same circuits on the recsize m3 outer PCS (M7 merge).
    m5_outer_canonical_m3_b4_q51_p26_fold4_v1,
    /// outer-gkr: canonical circuits with the interaction proven by a batched
    /// LogUp-GKR section (OM31 challenges, rv64-m7-profiles.md sec. 4).
    m7_outer_gkr_m3_b4_q51_p26_fold4_v1,
    /// blake-gadget: canonical circuits with the fused Blake2s component AIR.
    m7_outer_fused_blake_m3_b4_q51_p26_fold4_v1,
    // ---- M6 (stream profiles, M6-INTERFACES.md P1). OFF BY DEFAULT. ----
    /// native-format: chi chain v2 on the strict roster (chain vkhash == the
    /// T_nat leaf vkhash; fixes canon-native review A1), LOCAL_RELATIONS = 10.
    m6_native_v2_b2_q108_p20_fold4,
    /// native-format: v2 plus native LogUp-GKR v1 (only if it ships in M6).
    m6_native_v2_gkr_b2_q108_p20_fold4,
    /// fold-v3: in-circuit T_rec membership, NS interval chain, PCD self-VK on
    /// the canonical r1 outer PCS (root-only acceptance without --audit).
    m6_outer_fold_v3_r1_b2_q108_p20_fold4_v1,
    /// diet-wire: outer GKR + one-instance fused Blake2s + set-v2 + k-ary on r1.
    m6_outer_diet_r1_b2_q108_p20_fold4_v1,
    /// diet-wire on the recsize m3 outer PCS (only if q51 fits on the GPU).
    m6_outer_diet_m3_b4_q51_p26_fold4_v1,
    /// integrate: diet + fold v3 composed, r1.
    m6_outer_diet_fold_v3_r1_b2_q108_p20_fold4_v1,
    /// integrate: diet + fold v3 composed, m3.
    m6_outer_diet_fold_v3_m3_b4_q51_p26_fold4_v1,
    pub fn name(self: FormatVersion) []const u8 {
        return @tagName(self);
    }
};
pub const FormatSpec = struct {
    layer: Layer,
    owner: []const u8,
    pcs: PcsParams,
    domain: []const u8,
    /// Native only: local relation count hashed into the identity.
    local_relations: u64 = 0,
    /// Carries an outer LogUp-GKR section: must also pass requireOuterGkrBits
    /// and requireOuterGkrCharacteristic for the real circuit's facts.
    outer_gkr: bool = false,
    /// Owning stream's own version string of the component this format adds
    /// (outer-gkr section domain, fused Blake2s AIR id, native chain version).
    /// Hashed into the identity, so a change of the component is a new version.
    component: []const u8 = "",
    /// M6 composite versions: further component versions, in this order, hashed
    /// (length-prefixed) after the base fields ONLY when non-empty, so every M5
    /// identity is unchanged.
    extra_components: []const []const u8 = &.{},
    /// Uses the fused Blake2s gadget: must pass requireBlakeLookupMass over all
    /// consumers of each XOR table.
    fused_blake: bool = false,
    /// Fold arity is a class constant in {2,3,4} (k-ary binding, binding sec. 4).
    max_fold_arity: u32 = 2,
};
pub const FORMAT_VERSIONS = [_]FormatVersion{ .m5_native_chi_chain_v1_b2_q108_p20_fold4, .m5_outer_canonical_r1_b2_q108_p20_fold4_v1, .m5_outer_canonical_m3_b4_q51_p26_fold4_v1, .m7_outer_gkr_m3_b4_q51_p26_fold4_v1, .m7_outer_fused_blake_m3_b4_q51_p26_fold4_v1, .m6_native_v2_b2_q108_p20_fold4, .m6_native_v2_gkr_b2_q108_p20_fold4, .m6_outer_fold_v3_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_m3_b4_q51_p26_fold4_v1, .m6_outer_diet_fold_v3_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_fold_v3_m3_b4_q51_p26_fold4_v1 };
/// M6 component version strings (M6-INTERFACES.md P1). A change of any one is
/// a new FormatVersion; the owning stream posts the real string, profiles edits.
pub const M6_NATIVE_V2_COMPONENT = "rv64-m6-native-chi-chain/v2";
pub const M5_NATIVE_GKR_COMPONENT = "rv64-m5-native-gkr/v1";
pub const OUTER_GKR_COMPONENT = "stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v1";
pub const FUSED_BLAKE_ONE_INSTANCE_COMPONENT = "fused_blake2s_v1/one-instance";
pub const SET_V2_COMPONENT = "set-v2";
pub const KARY_COMPONENT = "kary-v1";
pub const FOLD_V3_COMPONENT = "rv64-m6-fold-v3/v1";
const DIET_EXTRA = [_][]const u8{ FUSED_BLAKE_ONE_INSTANCE_COMPONENT, SET_V2_COMPONENT, KARY_COMPONENT };
const DIET_FOLD_V3_EXTRA = DIET_EXTRA ++ [_][]const u8{FOLD_V3_COMPONENT};
/// Local relations of the production raw-fraction roster (fractions.zig gained
/// byte_pair in 63728c3f8). The M5 native version hashes this, not the stale 9.
pub const M5_LOCAL_RELATIONS: u64 = 10;
const R1_OUTER: PcsParams = .{ .log_blowup = 1, .queries = 108, .pow_bits = 20, .fold_step = 4 };
const M3_OUTER: PcsParams = .{ .log_blowup = 2, .queries = 51, .pow_bits = 26, .fold_step = 4 };
pub fn formatSpec(version: FormatVersion) FormatSpec {
    return switch (version) {
        .m5_native_chi_chain_v1_b2_q108_p20_fold4 => .{ .layer = .native, .owner = "canon-native", .pcs = .{ .log_blowup = 1, .queries = 108, .pow_bits = 20, .fold_step = 4 }, .domain = "rv64-m5-native-chi-chain/v1/conjectured128_b2_q108_p20_fold4\x00", .local_relations = M5_LOCAL_RELATIONS, .component = "rv64-m5-native-chi-chain/v1" },
        .m5_outer_canonical_r1_b2_q108_p20_fold4_v1 => .{ .layer = .outer, .owner = "canon-vk", .pcs = R1_OUTER, .domain = "stwo/circuit/native-om31/m5-canonical-q108-p20-fold4/lens-v1" },
        .m5_outer_canonical_m3_b4_q51_p26_fold4_v1 => .{ .layer = .outer, .owner = "canon-vk", .pcs = M3_OUTER, .domain = "stwo/circuit/native-om31/m5-canonical-m3-b4-q51-p26-fold4/lens-v1" },
        .m7_outer_gkr_m3_b4_q51_p26_fold4_v1 => .{ .layer = .outer, .owner = "outer-gkr", .pcs = M3_OUTER, .domain = "stwo/circuit/native-om31/m7-outer-gkr-m3-b4-q51-p26-fold4/lens-v1", .outer_gkr = true, .component = "stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v1" },
        .m7_outer_fused_blake_m3_b4_q51_p26_fold4_v1 => .{ .layer = .outer, .owner = "blake-gadget", .pcs = M3_OUTER, .domain = "stwo/circuit/native-om31/m7-fused-blake-m3-b4-q51-p26-fold4/lens-v1", .component = "fused_blake2s_v1", .fused_blake = true },
        .m6_native_v2_b2_q108_p20_fold4 => .{ .layer = .native, .owner = "native-format", .pcs = R1_OUTER, .domain = "rv64-m6-native-chi-chain/v2/conjectured128_b2_q108_p20_fold4\x00", .local_relations = M5_LOCAL_RELATIONS, .component = M6_NATIVE_V2_COMPONENT },
        .m6_native_v2_gkr_b2_q108_p20_fold4 => .{ .layer = .native, .owner = "native-format", .pcs = R1_OUTER, .domain = "rv64-m6-native-chi-chain/v2+native-gkr/v1/conjectured128_b2_q108_p20_fold4\x00", .local_relations = M5_LOCAL_RELATIONS, .component = M6_NATIVE_V2_COMPONENT, .extra_components = &.{M5_NATIVE_GKR_COMPONENT} },
        .m6_outer_fold_v3_r1_b2_q108_p20_fold4_v1 => .{ .layer = .outer, .owner = "fold-v3", .pcs = R1_OUTER, .domain = "stwo/circuit/native-om31/m6-fold-v3-q108-p20-fold4/lens-v1", .component = FOLD_V3_COMPONENT, .max_fold_arity = 4 },
        .m6_outer_diet_r1_b2_q108_p20_fold4_v1 => .{ .layer = .outer, .owner = "diet-wire", .pcs = R1_OUTER, .domain = "stwo/circuit/native-om31/m6-diet-q108-p20-fold4/lens-v1", .outer_gkr = true, .component = OUTER_GKR_COMPONENT, .extra_components = &DIET_EXTRA, .fused_blake = true, .max_fold_arity = 4 },
        .m6_outer_diet_m3_b4_q51_p26_fold4_v1 => .{ .layer = .outer, .owner = "diet-wire", .pcs = M3_OUTER, .domain = "stwo/circuit/native-om31/m6-diet-m3-b4-q51-p26-fold4/lens-v1", .outer_gkr = true, .component = OUTER_GKR_COMPONENT, .extra_components = &DIET_EXTRA, .fused_blake = true, .max_fold_arity = 4 },
        .m6_outer_diet_fold_v3_r1_b2_q108_p20_fold4_v1 => .{ .layer = .outer, .owner = "integrate", .pcs = R1_OUTER, .domain = "stwo/circuit/native-om31/m6-diet-fold-v3-q108-p20-fold4/lens-v1", .outer_gkr = true, .component = OUTER_GKR_COMPONENT, .extra_components = &DIET_FOLD_V3_EXTRA, .fused_blake = true, .max_fold_arity = 4 },
        .m6_outer_diet_fold_v3_m3_b4_q51_p26_fold4_v1 => .{ .layer = .outer, .owner = "integrate", .pcs = M3_OUTER, .domain = "stwo/circuit/native-om31/m6-diet-fold-v3-m3-b4-q51-p26-fold4/lens-v1", .outer_gkr = true, .component = OUTER_GKR_COMPONENT, .extra_components = &DIET_FOLD_V3_EXTRA, .fused_blake = true, .max_fold_arity = 4 },
    };
}
pub fn formatConjecturedBits(version: FormatVersion) u32 {
    const c = formatSpec(version).pcs;
    return c.log_blowup * c.queries + c.pow_bits;
}
pub fn formatJohnsonBitsTimes2(version: FormatVersion) u32 {
    const c = formatSpec(version).pcs;
    return c.queries * c.log_blowup + 2 * c.pow_bits;
}
pub const FORMAT_ID_DOMAIN = "rv64-om31-m5-format-version/v1\x00";
pub fn formatIdentity(version: FormatVersion) [32]u8 {
    const s = formatSpec(version);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(FORMAT_ID_DOMAIN);
    h.update(version.name());
    h.update(s.domain);
    var len_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_bytes, s.component.len, .little);
    h.update(&len_bytes);
    h.update(s.component);
    h.update(&Channel.profile.identity());
    for ([_]u64{ @intFromEnum(s.layer), s.pcs.log_blowup, s.pcs.queries, s.pcs.pow_bits, s.pcs.fold_step, s.local_relations, @intFromBool(s.outer_gkr), formatConjecturedBits(version), TARGET_BITS }) |n| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        h.update(&bytes);
    }
    // M6 composites only (empty list => byte-identical M5 identities).
    if (s.extra_components.len != 0 or s.max_fold_arity != 2) {
        h.update("rv64-om31-m6-format-ext/v1\x00");
        for ([_]u64{ s.extra_components.len, @intFromBool(s.fused_blake), s.max_fold_arity }) |n| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, n, .little);
            h.update(&bytes);
        }
        for (s.extra_components) |c| {
            std.mem.writeInt(u64, &len_bytes, c.len, .little);
            h.update(&len_bytes);
            h.update(c);
        }
    }
    return h.finalResult();
}

/// M5 node-summary reference models (rv64-m5-binding.md sec. 10.2). These are the
/// integer semantics the in-circuit gadgets must implement; they are not circuits.
pub const NsMassRelation = enum { ram, kio, wire };
pub const NS_MASS_RELATIONS = @typeInfo(NsMassRelation).@"enum".fields.len;
/// Fold rule for NS.mass: every child mass is a canonical integer < p, the sum is
/// an INTEGER (never an M31 sum) and must itself stay < p.
pub fn m5FoldMass(children: []const [NS_MASS_RELATIONS]u64) ![NS_MASS_RELATIONS]u64 {
    if (children.len < 2 or children.len > 4) return error.M5FoldArity;
    const p = core.fields.m31.Modulus;
    var out: [NS_MASS_RELATIONS]u64 = @splat(0);
    for (children) |child| for (child, &out) |m, *o| {
        if (m >= p) return error.M5ChildMassNoncanonical;
        o.* += m;
    };
    for (out) |o| if (o >= p) return error.M5MassCharacteristicWrap;
    return out;
}
/// What an M31 sum of the same children would give (the bug the fold must not have).
pub fn m5FieldMassForTesting(children: []const [NS_MASS_RELATIONS]u64) [NS_MASS_RELATIONS]u64 {
    var out: [NS_MASS_RELATIONS]u64 = @splat(0);
    for (children) |child| for (child, &out) |m, *o| {
        o.* = (o.* + m) % core.fields.m31.Modulus;
    };
    return out;
}
/// Leaf segment index check as the circuit evaluates it over M31: `k` is a field
/// element; a range check proves a value in [0, 2^16). One-sided = only the
/// upper check MAX_PROOFS - 1 - k; two-sided adds k itself (binding 3.2(5) [R2]).
pub fn m5LeafIndexAdmits(k: u32, two_sided: bool) bool {
    const p: u64 = core.fields.m31.Modulus;
    const upper = (MAX_PROOFS - 1 + p - @as(u64, k)) % p;
    if (upper >= 1 << 16) return false;
    return !two_sided or k < 1 << 16;
}
/// Fused Blake2s gadget lookup mass per proof (one table, e.g. byte XOR): the
/// multiplicity of a key is at most the total lookup count, which must stay < p.
pub fn requireBlakeLookupMass(compressions: u64, lookups_per_compression: u64) !void {
    const total = std.math.mul(u64, compressions, lookups_per_compression) catch return error.Om31CandidateCharacteristicWrap;
    if (total >= core.fields.m31.Modulus) return error.Om31CandidateCharacteristicWrap;
}

/// BG08 over every consumer of one lookup table (review: the fused gadget is not
/// the only user of VerifyBitwiseXor_8): the per-proof integer sum of all
/// consumers' lookup counts must stay < p.
pub fn requireBlakeTableMass(consumer_lookups: []const u64) !void {
    var total: u64 = 0;
    for (consumer_lookups) |n| total = std.math.add(u64, total, n) catch return error.Om31CandidateCharacteristicWrap;
    if (total >= core.fields.m31.Modulus) return error.Om31CandidateCharacteristicWrap;
}

pub fn requireBenchmarkControlUnchanged() !void {
    try Policy.requireClaim(Policy.benchmarkControl(), .nominal_control_only_v1, .benchmark_control_only);
}

test "public boundary log23 policy v2 separates general clocks and historical identity" {
    var facts = Facts.caps();
    try facts.validate();
    facts.max_trace_log = 23;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, facts.validate());
    facts = Facts.caps();
    facts.max_public_boundary_log = 24;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, facts.validate());
    // Reconstruct the previously admitted v1 candidate identity. This checks
    // intentional rejection of that protocol, rather than silently widening it.
    var old = std.crypto.hash.sha2.Sha256.init(.{});
    old.update("rv64-om31-rawblake-native-localgkr-128-CANDIDATE/v1\x00");
    old.update(&Channel.profile.identity());
    for ([_]u64{ 8, 256, 2, 4, 0, MAX_PROOFS, MAX_TRACE_LOG, MAX_COLUMNS, MAX_CONSTRAINTS, MAX_SAMPLES_PER_COLUMN, MAX_AIR_DEGREE, MAX_LOCAL_INSTANCES, MAX_TUPLE_ARITY, LOCAL_RELATIONS, GLOBAL_RELATIONS, MAX_GKR_VARIABLES, MAX_ROUND_COUNT, TARGET_BITS, MAX_AUDITED_LOG_WORK }) |n| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        old.update(&bytes);
    }
    try std.testing.expectError(error.UnrecognizedOm31CandidateIdentity, requireIdentity(old.finalResult()));
    try std.testing.expect(!std.mem.eql(u8, &profileIdentity(.proven_beta2_q256_p0_fold4), &profileIdentity(.conjectured128_b2_q108_p20_fold4)));
}
