//! Receiver-owned *candidate* construction and conditional error accountant.
//! No proof acceptance path selects this suite; no 128-bit certificate exists.
//! Values supplied by a proof bundle are not authority for Facts or reviews.
const std = @import("std");
const core = @import("stwo_core");
const Policy = @import("security_policy.zig");
pub const O = core.fields.om31.OM31;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const ID_DOMAIN = "rv64-om31-rawblake-native-localgkr-128-CANDIDATE/v1\x00";
pub const MAX_PROOFS: u64 = 256;
pub const MAX_TRACE_LOG: u32 = 22;
pub const MAX_COLUMNS: u64 = 16384;
pub const MAX_CONSTRAINTS: u64 = 65536;
pub const MAX_SAMPLES_PER_COLUMN: u64 = 8;
pub const MAX_AIR_DEGREE: u64 = 5;
pub const MAX_LOCAL_INSTANCES: u64 = 128;
pub const MAX_TUPLE_ARITY: u64 = 128;
pub const LOCAL_RELATIONS: u64 = 9;
pub const GLOBAL_RELATIONS: u64 = 3;
pub const MAX_GKR_VARIABLES: u32 = 30;
pub const MAX_ROUND_COUNT: u64 = 1 << 20;
pub const TARGET_BITS: u16 = 128;
/// Engineering target and explicit assumption scope, not certificate authority.
/// Reporting metadata only: excluded from identity()/begin() and proof framing.
pub const ASSUMPTION_TARGET = .{
    .label = "128-bit security target under documented assumptions",
    .target_bits = TARGET_BITS,
    .assumption_set = "rv64-native-om31-beta2-q256-p0-fold4-assumptions-20261102-v1",
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
pub const CONJECTURED_ID_DOMAIN = "rv64-om31-rawblake-native-localgkr-128-CONJECTURED-ethstark/v1\x00";
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
    for ([_]u64{ 8, c.fri_config.n_queries, c.fri_config.log_blowup_factor, c.fri_config.fold_step, c.pow_bits, c.fri_config.log_last_layer_degree_bound, conjecturedBits(profile), MAX_PROOFS, MAX_TRACE_LOG, MAX_COLUMNS, MAX_CONSTRAINTS, MAX_SAMPLES_PER_COLUMN, MAX_AIR_DEGREE, MAX_LOCAL_INSTANCES, MAX_TUPLE_ARITY, LOCAL_RELATIONS, GLOBAL_RELATIONS, MAX_GKR_VARIABLES, MAX_ROUND_COUNT, TARGET_BITS }) |n| {
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
    assumption_set: []const u8 = "rv64-native-v3-om31-conjectured128-b2-q108-p20-fold4-20261102-v1",
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
    for ([_]u64{ 8, 256, 2, 4, 0, MAX_PROOFS, MAX_TRACE_LOG, MAX_COLUMNS, MAX_CONSTRAINTS, MAX_SAMPLES_PER_COLUMN, MAX_AIR_DEGREE, MAX_LOCAL_INSTANCES, MAX_TUPLE_ARITY, LOCAL_RELATIONS, GLOBAL_RELATIONS, MAX_GKR_VARIABLES, MAX_ROUND_COUNT, TARGET_BITS, MAX_AUDITED_LOG_WORK }) |n| {
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
        return .{ .native_proofs = MAX_PROOFS, .max_trace_log = MAX_TRACE_LOG, .max_columns = MAX_COLUMNS, .max_constraints = MAX_CONSTRAINTS, .max_samples_per_column = MAX_SAMPLES_PER_COLUMN, .max_air_degree = MAX_AIR_DEGREE, .max_local_instances = MAX_LOCAL_INSTANCES, .max_tuple_arity = MAX_TUPLE_ARITY, .max_gkr_variables = MAX_GKR_VARIABLES, .max_positive_mass = core.fields.m31.Modulus - 1, .max_negative_mass = core.fields.m31.Modulus - 1, .max_multiplicity = core.fields.m31.Modulus - 1, .transcript_rounds = MAX_ROUND_COUNT };
    }
    pub fn validate(self: Facts) !void {
        if (self.native_proofs == 0 or self.native_proofs > MAX_PROOFS or self.max_trace_log < 5 or self.max_trace_log > MAX_TRACE_LOG or self.max_columns == 0 or self.max_columns > MAX_COLUMNS or self.max_constraints == 0 or self.max_constraints > MAX_CONSTRAINTS or self.max_samples_per_column == 0 or self.max_samples_per_column > MAX_SAMPLES_PER_COLUMN or self.max_air_degree == 0 or self.max_air_degree > MAX_AIR_DEGREE or self.max_local_instances == 0 or self.max_local_instances > MAX_LOCAL_INSTANCES or self.max_tuple_arity == 0 or self.max_tuple_arity > MAX_TUPLE_ARITY or self.max_gkr_variables < 1 or self.max_gkr_variables > MAX_GKR_VARIABLES or self.transcript_rounds == 0 or self.transcript_rounds > MAX_ROUND_COUNT)
            return error.Om31CandidateScopeExceeded;
        const p = core.fields.m31.Modulus;
        if (self.max_positive_mass >= p or self.max_negative_mass >= p or self.max_multiplicity >= p)
            return error.Om31CandidateCharacteristicBoundExceeded;
    }
    fn words(self: Facts) [13]u64 {
        return .{ self.native_proofs, self.max_trace_log, self.max_columns, self.max_constraints, self.max_samples_per_column, self.max_air_degree, self.max_local_instances, self.max_tuple_arity, self.max_gkr_variables, self.max_positive_mass, self.max_negative_mass, self.max_multiplicity, self.transcript_rounds };
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
    const n: u512 = @as(u512, 1) << @intCast(facts.max_trace_log);
    const c: u512 = facts.max_columns;
    const arity: u512 = facts.max_tuple_arity;
    const mass: u512 = @as(u512, facts.max_positive_mass) + facts.max_negative_mass;
    const v: u512 = facts.max_gkr_variables;
    const i: u512 = facts.max_local_instances;
    const local = LOCAL_RELATIONS;
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
pub fn requireBenchmarkControlUnchanged() !void {
    try Policy.requireClaim(Policy.benchmarkControl(), .nominal_control_only_v1, .benchmark_control_only);
}
