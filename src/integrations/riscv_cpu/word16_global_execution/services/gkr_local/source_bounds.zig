//! Receiver-derived native shape and source-support bounds. Weighted valid
//! provider support is DISTINCT from ordinary negative integer mass. This
//! engineering preflight is not a reviewed whole-protocol security certificate.
const Scope = @import("service_scope.zig");
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const Policy = @import("../../../word16_execution/om31_security_candidate.zig");
const Geometry = @import("../../../word16_execution/geometry.zig");
const Wire = @import("../wire.zig");
const P = @import("../protocol.zig");
const Types = @import("../types.zig");
const F = @import("fractions.zig");
const TF = @import("truth_fractions.zig");
const Q = @import("query_metadata.zig");
const Meta = @import("shape_metadata.zig");
const Frame = @import("frame.zig");
const Truth = @import("truth_components.zig");
const Mass = @import("mass_authority.zig");
const Global = @import("global_cpu.zig");
const Manifest = @import("manifest.zig");
const MODULUS = core.fields.m31.Modulus;
const DetachedSource = @import("../../../poseidon2_outer/sponge_local_gkr/authority.zig");
const FrontierSource = A.crypto.keccak_sponge.serialized.frontier;
/// Reporting identity for the source-derived lookup accountant, not a new
/// Fiat-Shamir/profile identifier or a whole-protocol security certificate.
pub const ACCOUNTING_PROFILE = "rv64-source-derived-services-v3-lookup/v1";
pub const LEGACY_LOCAL_NAMESPACES: u8 = @intFromEnum(F.Relation.byte_pair);
pub const V3_LOCAL_NAMESPACES: u8 = @intCast(std.meta.fields(F.Relation).len);
pub const Model = enum { unit_consistency, unit_membership_valid_support };
pub const Bound = struct {
    model: Model = .unit_membership_valid_support,
    arity: usize = 0,
    consumer_sign: enum { positive, negative } = .positive,
    unit_consumer_mass: u64 = 0,
    valid_provider_support: u64 = 0,
    unit_positive_mass: u64 = 0,
    unit_negative_mass: u64 = 0,
    /// Includes every zero-weight/padded denominator, not only semantic mass.
    denominator_slots: u64 = 0,
    pub fn validate(self: Bound) !void {
        if (self.unit_consumer_mass >= MODULUS or self.unit_positive_mass >= MODULUS or self.unit_negative_mass >= MODULUS) return error.CandidateCharacteristicBoundExceeded;
    }
};
pub const CpuScope = struct {
    namespace_count: u8 = LEGACY_LOCAL_NAMESPACES,
    relations: [std.meta.fields(F.Relation).len]Bound,
    /// Disjoint TOKEN_JD_TABLE support inside OWNER19; denominator slots remain
    /// in relations.owner so collision/pole bounds include cross-partition pairs.
    owner_table: Bound = .{ .model = .unit_membership_valid_support, .arity = 19, .consumer_sign = .negative },
};
pub const TruthScope = struct { relations: [std.meta.fields(TF.Relation).len]Bound };
pub const Shape = struct {
    native_proofs: usize = 0,
    /// General CPU/provider maximum; public boundaries have their own cap.
    max_trace_log: u32 = 0,
    max_public_boundary_log: u32 = 5,
    max_columns: usize = 0,
    max_constraints: usize = 0,
    max_samples_per_column: usize = 0,
    max_air_degree: u8 = 0,
    max_local_instances: usize = 0,
    max_tuple_arity: usize = 0,
    max_gkr_variables: u32 = 0,
    /// Source-derived M31 coefficient cells, in FIXED/MAIN/INTER order.
    /// Includes padding and repeated fixed commitments; excludes composition,
    /// GKR working planes, openings and allocations. Reporting only.
    native_trace_cells: [3]u64 = @splat(0),
    fn includeCells(self: *Shape, log: u32, widths: [3]usize) !void {
        const n = try rows(log);
        for (&self.native_trace_cells, widths) |*total, width| {
            total.* = try plus(total.*, try times(n, std.math.cast(u64, width) orelse return error.SizeOverflow));
        }
    }
    pub fn validate(self: Shape) !void {
        if (self.native_proofs == 0 or self.native_proofs > Policy.MAX_PROOFS or self.max_trace_log < 5 or self.max_trace_log > Policy.MAX_TRACE_LOG or self.max_public_boundary_log < 5 or self.max_public_boundary_log > Policy.MAX_PUBLIC_BOUNDARY_LOG or self.max_columns == 0 or self.max_columns > Policy.MAX_COLUMNS or self.max_constraints == 0 or self.max_constraints > Policy.MAX_CONSTRAINTS or self.max_samples_per_column > Policy.MAX_SAMPLES_PER_COLUMN or self.max_air_degree > Policy.MAX_AIR_DEGREE or self.max_local_instances > Policy.MAX_LOCAL_INSTANCES or self.max_tuple_arity > Policy.MAX_TUPLE_ARITY or self.max_gkr_variables > Policy.MAX_GKR_VARIABLES) return error.CandidateSourceShapeExceeded;
    }
};
pub const ConditionalDegrees = struct {
    tuple_collision: u128 = 0,
    rational_identity: u128 = 0,
    local_rational_identity: u128 = 0,
    global_rational_identity: u128 = 0,
    poles: u128 = 0,
    /// Necessary conditional algebraic source bounds only. The applicability
    /// of membership/canonicality/FS reductions remains separately reviewed.
    /// Lookup source terms ONLY. This does not include GKR, PCS, FRI,
    /// polynomial-compression, adaptive FS or recursion error terms.
    pub fn requireLookupOnlyBits(self: ConditionalDegrees, bits: u16) !void {
        var ledger = Policy.Ledger{ .degree_weight = @splat(0) };
        ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.tuple_compression)] = self.tuple_collision;
        ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.local_rational_identity)] = self.local_rational_identity;
        ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.global_rational_identity)] = self.global_rational_identity;
        ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.pole_events)] = self.poles;
        try ledger.requireRawModuloBits(bits);
    }
    pub fn add(self: *ConditionalDegrees, b: Bound) !void {
        const n: u128 = b.denominator_slots;
        const pairs = if (n == 0) 0 else try std.math.mul(u128, n, n - 1) / 2;
        self.tuple_collision = try std.math.add(u128, self.tuple_collision, try std.math.mul(u128, pairs, b.arity));
        self.rational_identity = try std.math.add(u128, self.rational_identity, n);
        self.local_rational_identity = try std.math.add(u128, self.local_rational_identity, n);
        self.poles = try std.math.add(u128, self.poles, n);
    }
    pub fn addGlobal(self: *ConditionalDegrees, bound: Bound) !void {
        try self.add(bound);
        self.local_rational_identity -= bound.denominator_slots;
        self.global_rational_identity = try std.math.add(u128, self.global_rational_identity, bound.denominator_slots);
    }
};
pub const Report = struct {
    accounting_profile: []const u8 = ACCOUNTING_PROFILE,
    allocator: std.mem.Allocator,
    shape: Shape,
    cpu_scopes: []CpuScope,
    truth_scopes: []TruthScope,
    global_signed: Mass.Globals,
    global_denominator_slots: [3]u64,
    conditional_degrees: ConditionalDegrees,
    /// No producer-controlled booleans can turn this into a certificate.
    security_qualified: bool = false,
    transcript_round_bound_qualified: bool = false,
    secp_polynomial_error_budget_qualified: bool = false,
    pub fn deinit(self: *Report) void {
        self.allocator.free(self.cpu_scopes);
        self.allocator.free(self.truth_scopes);
        self.* = undefined;
    }
};
/// Separate OP declaration/report envelope: legacy report layout is untouched.
/// Local lookup challenges are independent per physical proof. Global RAM and
/// Wire share the manifest challenge and are therefore bounded jointly.
pub const OpTowerTruthDeclaration = struct { calls: u32, first_id: u32, frontier_log: u32, arithmetic_log: u32 };
pub const OpTruthScope = struct {
    bytes: Bound,
    carries: Bound,
    ssa: Bound,
    canonical_writes: u64,
};
pub const OpReport = struct {
    base: Report,
    op_truth_scopes: []OpTruthScope,
    pub fn deinit(self: *@This()) void {
        self.base.allocator.free(self.op_truth_scopes);
        self.base.deinit();
        self.* = undefined;
    }
};
pub const DetachedRelation = enum { owner, and_, u16, u8 };
pub const DetachedScope = struct { relations: [4]Bound };
pub const DetachedOpReport = struct {
    op: OpReport,
    detached_scopes: []DetachedScope,
    pub fn deinit(self: *@This()) void {
        self.op.base.allocator.free(self.detached_scopes);
        self.op.deinit();
        self.* = undefined;
    }
};
const DetachedInventory = struct { logs: []const u32, workers: []const DetachedSource.Geometry, scopes: []DetachedScope };
const OpInventory = struct { cpu_spans: []const Types.OpTowerSpan, truths: []const OpTowerTruthDeclaration, scopes: []OpTruthScope, detached: ?DetachedInventory = null };
pub fn deriveForOp(a: std.mem.Allocator, program_log: u32, cpu: []const Wire.CpuDeclaration, truth: []const Wire.TruthDeclaration, requests: []const P.Request, cpu_spans: []const Types.OpTowerSpan, miller: []const OpTowerTruthDeclaration) !OpReport {
    return deriveForOpMode(a, program_log, cpu, truth, requests, cpu_spans, miller, null);
}
/// Explicit source equations and geometry, not a projection through fake legacy
/// Frame origins or erased request counts. Inventory admission is separate.
pub fn deriveForOpDetached(a: std.mem.Allocator, program_log: u32, cpu: []const Wire.CpuDeclaration, truth: []const Wire.TruthDeclaration, requests: []const P.Request, cpu_spans: []const Types.OpTowerSpan, miller: []const OpTowerTruthDeclaration, frontier_logs: []const u32, detached: []const DetachedSource.Geometry) !DetachedOpReport {
    if (frontier_logs.len != cpu.len) return error.InvalidDetachedSourceInventory;
    _ = try validateInventory(cpu.len, try std.math.add(usize, try std.math.add(usize, truth.len, miller.len), detached.len));
    if (requests.len != cpu.len or cpu_spans.len != cpu.len) return error.InvalidDetachedSourceInventory;
    var calls: u64 = 0;
    var permutations: u64 = 0;
    var first: u64 = 1;
    for (requests) |request| {
        calls = try plus(calls, request.sponge.calls);
        permutations = try plus(permutations, request.sponge.perms);
        first = try plus(first, request.calls[0]);
        if ((request.sponge.calls == 0) != (request.sponge.perms == 0) or request.sponge.perms < request.sponge.calls) return error.InvalidDetachedSourceInventory;
    }
    var actual_calls: u64 = 0;
    var actual_permutations: u64 = 0;
    for (detached) |geometry| {
        if (!geometry.detached or geometry.first_id != first) return error.InvalidDetachedSourceInventory;
        _ = try geometry.instances();
        actual_calls = try plus(actual_calls, geometry.calls);
        actual_permutations = try plus(actual_permutations, geometry.permutations);
        first = try plus(first, geometry.permutations);
    }
    if (actual_calls != calls or actual_permutations != permutations) return error.InvalidDetachedSourceInventory;
    const scopes = try a.alloc(DetachedScope, detached.len);
    errdefer a.free(scopes);
    return .{ .op = try deriveForOpMode(a, program_log, cpu, truth, requests, cpu_spans, miller, .{ .logs = frontier_logs, .workers = detached, .scopes = scopes }), .detached_scopes = scopes };
}
fn deriveForOpMode(a: std.mem.Allocator, program_log: u32, cpu: []const Wire.CpuDeclaration, truth: []const Wire.TruthDeclaration, requests: []const P.Request, cpu_spans: []const Types.OpTowerSpan, miller: []const OpTowerTruthDeclaration, detached: ?DetachedInventory) !OpReport {
    if (cpu_spans.len != cpu.len or requests.len != cpu.len) return error.InvalidOpTowerInventory;
    var next_cpu: u64 = 1;
    for (cpu, requests, cpu_spans) |declaration, request, span| {
        try span.validate(declaration.bridges);
        var services = try plus(request.bulk.ecalls(), request.sponge.calls);
        services = try plus(services, request.base.memory.ls_count);
        services = try plus(services, request.ls_dword);
        for (request.calls) |calls| services = try plus(services, calls);
        services = try plus(services, span.calls);
        if (services > request.base.cpu.steps) return error.InvalidCombinedServiceCount;
        if (span.calls != 0) {
            if (span.first_id != next_cpu) return error.InvalidOpTowerCoverage;
            next_cpu = try plus(next_cpu, span.calls);
        }
    }
    var next_truth: u64 = 1;
    const Tower = A.crypto.bn254_tower.narrow;
    for (miller) |declaration| {
        try Tower.equations.LayoutForField(.frontier, core.fields.om31.OM31).validateGeometry(declaration.calls, declaration.first_id, declaration.frontier_log);
        try Tower.equations.LayoutForField(.arithmetic, core.fields.om31.OM31).validateGeometry(declaration.calls, declaration.first_id, declaration.arithmetic_log);
        if (declaration.first_id != next_truth) return error.InvalidOpTowerCoverage;
        next_truth = try plus(next_truth, declaration.calls);
    }
    if (next_cpu != next_truth) return error.InvalidOpTowerCoverage;
    const scopes = try a.alloc(OpTruthScope, miller.len);
    errdefer a.free(scopes);
    return .{ .base = try deriveMode(a, program_log, cpu, truth, requests, .{ .cpu_spans = cpu_spans, .truths = miller, .scopes = scopes, .detached = detached }), .op_truth_scopes = scopes };
}
fn plus(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b);
}
fn times(a: u64, b: u64) !u64 {
    return std.math.mul(u64, a, b);
}
fn rows(log: u32) !u64 {
    if (log < 5 or log > Policy.MAX_PUBLIC_BOUNDARY_LOG) return error.CandidateSourceShapeExceeded;
    return @as(u64, 1) << @intCast(log);
}
pub fn emptyCpu() CpuScope {
    var out: CpuScope = .{ .relations = undefined };
    for (std.enums.values(F.Relation), &out.relations) |relation, *bound| bound.* = .{ .arity = relation.arity(), .model = switch (relation) {
        .register, .owner => .unit_consistency,
        .rom, .function, .range16, .range8, .and_, .shift, .selection, .byte_pair => .unit_membership_valid_support,
    } };
    return out;
}
fn addCpuRole(scope: *CpuScope, origin: Frame.Origin, log: u32) !void {
    return addCpuRoleMode(scope, origin, log, false);
}
pub fn addCpuRoleMode(scope: *CpuScope, origin: Frame.Origin, log: u32, pairs: bool) !void {
    const count = try rows(log);
    const fractions = switch (origin) {
        .bulk => |kind| Q.BULK[@intFromEnum(kind)],
        .dword => Q.DWORD,
        .sponge => |kind| Q.SPONGE[@intFromEnum(kind)],
        .core => |kind| if (pairs and kind == .cpu) Q.PAIRED_CPU else if (pairs and kind == .and_table) Q.PAIRED_AND else Q.CORE[@intFromEnum(kind)],
        .bridge => |kind| Q.BRIDGES[@intFromEnum(kind)],
        .tower => Q.TOWER,
    };
    for (std.enums.values(F.Relation), fractions, &scope.relations) |relation, queries, *bound| {
        if (queries == 0) continue;
        const slots = try times(count, queries);
        bound.denominator_slots = try plus(bound.denominator_slots, slots);
        if (relation == .register) {
            if (queries % 2 != 0) return error.CandidateSourceRelationShape;
            bound.unit_positive_mass = try plus(bound.unit_positive_mass, slots / 2);
            bound.unit_negative_mass = try plus(bound.unit_negative_mass, slots / 2);
        } else if (relation == .owner and origin == .bulk) {
            const kind = origin.bulk;
            const signs: [2]u64 = switch (kind) {
                .desc => .{ 2, 1 },
                .copy, .set, .ucopy => .{ 0, 1 },
                .cdesc => .{ 1, 2 },
                .cmp, .jdesc => .{ 1, 1 },
                .jscan => .{ 0, 1 },
                .jtab => .{ 0, 0 },
            };
            bound.unit_positive_mass = try plus(bound.unit_positive_mass, try times(count, signs[0]));
            bound.unit_negative_mass = try plus(bound.unit_negative_mass, try times(count, signs[1]));
            if (kind == .jscan) scope.owner_table.unit_consumer_mass = try plus(scope.owner_table.unit_consumer_mass, try times(count, 64));
            if (kind == .jtab) scope.owner_table.valid_provider_support = try plus(scope.owner_table.valid_provider_support, A.crypto.bulk_memory.types.TABLE_ENTRIES);
        } else if (relation == .owner and origin == .sponge) {
            if (origin.sponge == .call) bound.unit_positive_mass = try plus(bound.unit_positive_mass, count);
            bound.unit_negative_mass = try plus(bound.unit_negative_mass, count);
        } else if (relation == .owner) {
            if (origin == .core and origin.core == .cpu) bound.unit_positive_mass = try plus(bound.unit_positive_mass, slots) else bound.unit_negative_mass = try plus(bound.unit_negative_mass, slots);
        } else {
            const table = origin == .core and switch (origin.core) {
                .rom, .range16, .range8, .and_table, .shift_table, .selection => true,
                else => false,
            };
            if (table) bound.valid_provider_support = try plus(bound.valid_provider_support, slots) else if (relation == .function and !(origin == .core and origin.core == .cpu)) {
                // Each non-CPU arithmetic family emits one constrained true
                // FUNCTION yield. JALR and DIV additionally emit unit subqueries.
                bound.valid_provider_support = try plus(bound.valid_provider_support, count);
                bound.unit_consumer_mass = try plus(bound.unit_consumer_mass, try times(count, queries - 1));
            } else bound.unit_consumer_mass = try plus(bound.unit_consumer_mass, slots);
        }
    }
}
fn includeRole(shape: *Shape, origin: Frame.Origin, log: u32, descriptor: Meta.Descriptor, columns: *usize, constraints: *usize, instances: *usize) !void {
    try shape.includeCells(log, descriptor.widths);
    for (descriptor.widths) |width| columns.* = try std.math.add(usize, columns.*, width);
    constraints.* = try std.math.add(usize, constraints.*, descriptor.constraints);
    if (origin == .core and (origin.core == .initial or origin.core == .terminal)) {
        shape.max_public_boundary_log = @max(shape.max_public_boundary_log, log);
    } else {
        if (log > Policy.MAX_TRACE_LOG) return error.CandidateSourceShapeExceeded;
        shape.max_trace_log = @max(shape.max_trace_log, log);
    }
    shape.max_samples_per_column = @max(shape.max_samples_per_column, descriptor.max_samples);
    shape.max_air_degree = @max(shape.max_air_degree, descriptor.degree);
    if (descriptor.local_terms != 0) {
        const instance = Frame.Instance{ .origin = origin, .row_log = log, .terms = descriptor.local_terms, .fixed_offset = 0, .main_offset = 0 };
        shape.max_gkr_variables = @max(shape.max_gkr_variables, try instance.variables());
        instances.* = try std.math.add(usize, instances.*, 1);
    }
}
fn finishProof(shape: *Shape, columns: usize, constraints: usize, instances: usize, split: u32) !void {
    const composition = core.verifier_types.compositionColumnCount(split, A.evaluation.extensionDegree(core.fields.om31.OM31)) orelse return error.CandidateSourceShapeExceeded;
    shape.max_columns = @max(shape.max_columns, try std.math.add(usize, columns, composition));
    shape.max_constraints = @max(shape.max_constraints, constraints);
    shape.max_local_instances = @max(shape.max_local_instances, instances);
}
/// Declarations select only a validated layout; trusted program_log comes from
/// the independently loaded image. Ordinary counts come from request/call spans,
/// never decoded producer Facts or field-valued claims. Full image/coverage
/// admission remains mandatory in the accepting receiver after this preflight.
pub fn globalSlots(slots: *[3]u64, origin: Frame.Origin, log: u32) !void {
    const layout = Global.layout(origin);
    const n = try rows(log);
    slots[0] = try plus(slots[0], try times(n, layout.ram_queries));
    if (layout.other_queries != 0) {
        const index: usize = if (Global.isKio(origin)) 1 else 2;
        slots[index] = try plus(slots[index], try times(n, layout.other_queries));
    }
}
pub fn validateInventory(cpu: usize, truth: usize) !usize {
    const count = try std.math.add(usize, cpu, truth);
    if (cpu == 0 or count > Policy.MAX_PROOFS) return error.CandidateSourceShapeExceeded;
    return count;
}
pub fn derive(a: std.mem.Allocator, program_log: u32, cpu: []const Wire.CpuDeclaration, truth: []const Wire.TruthDeclaration, requests: []const P.Request) !Report {
    return deriveMode(a, program_log, cpu, truth, requests, null);
}
fn crossNamespaces(degrees: *ConditionalDegrees, relations: []const Bound) !void {
    // A joint rational sum must also charge collisions BETWEEN independently
    // domain-labeled namespaces. Their offsets are independent, so no
    // deterministic cross-namespace cancellation is assumed. Charging the sum
    // of arities is conservative even though each offset collision is linear.
    for (relations, 0..) |left, i| for (relations[i + 1 ..]) |right| {
        const pairs = try std.math.mul(u128, left.denominator_slots, right.denominator_slots);
        const weight = try std.math.mul(u128, pairs, left.arity + right.arity);
        degrees.tuple_collision = try std.math.add(u128, degrees.tuple_collision, weight);
    };
}
fn addFrontier(shape: *Shape, scope: *CpuScope, global: *Mass.Globals, global_slots: *[3]u64, columns: *usize, constraints: *usize, instances: *usize, request: P.Request, ordinal: u32, log: u32) !void {
    try FrontierSource.validatePublic(request.sponge.calls, log, request.base.epoch, ordinal);
    const count = try rows(log);
    const L = @import("../../../poseidon2_outer/sponge_cpu/equations.zig").Layout;
    try shape.includeCells(log, L.widths());
    for (L.widths()) |width| columns.* = try std.math.add(usize, columns.*, width);
    constraints.* = try std.math.add(usize, constraints.*, L.CONSTRAINTS);
    instances.* = try std.math.add(usize, instances.*, 1);
    shape.max_trace_log = @max(shape.max_trace_log, log);
    shape.max_air_degree = @max(shape.max_air_degree, 3);
    shape.max_samples_per_column = @max(shape.max_samples_per_column, 2);
    shape.max_gkr_variables = @max(shape.max_gkr_variables, log + 2);
    // Exact new local recipe: negative OWNER19 consumption plus unconditional
    // U16/U8 low/high clock queries, including zero-weight/padding denominators.
    const owner = &scope.relations[@intFromEnum(F.Relation.owner)];
    owner.unit_negative_mass = try plus(owner.unit_negative_mass, request.sponge.calls);
    owner.denominator_slots = try plus(owner.denominator_slots, count);
    inline for (.{ F.Relation.range16, F.Relation.range8 }) |relation| {
        const bound = &scope.relations[@intFromEnum(relation)];
        bound.unit_consumer_mass = try plus(bound.unit_consumer_mass, count);
        bound.denominator_slots = try plus(bound.denominator_slots, count);
    }
    global_slots[2] = try plus(global_slots[2], count);
    try global.add(.{ .wire = .{ .positive = request.sponge.calls } });
}
/// Metadata comes from the SAME concrete emitter as witness/projection code.
/// No invented Frame origin or duplicated per-role fraction-count constants.
fn detachedQueries(comptime role: DetachedSource.Role) ![4]u64 {
    const S = @import("../../../poseidon2_outer/sponge_local_gkr/source.zig");
    const K = A.crypto.keccak_sponge.equations;
    const M31 = core.fields.m31.M31;
    const Counter = struct {
        counts: [4]u64 = @splat(0),
        failure: bool = false,
        pub fn emit(self: *@This(), relation: usize, tuple: anytype, _: M31) void {
            if (tuple.len == 14 or tuple.len == 11 or tuple.len == 35) {
                const expected = if (tuple.len == 14) K.RAM else if (tuple.len == 11) K.IO else FrontierSource.WIRE;
                if (relation != expected) self.failure = true;
                return;
            }
            const i: usize = switch (tuple.len) {
                19 => if (relation == K.OWNER) @intFromEnum(DetachedRelation.owner) else {
                    self.failure = true;
                    return;
                },
                3 => if (relation == K.AND) @intFromEnum(DetachedRelation.and_) else {
                    self.failure = true;
                    return;
                },
                1 => if (relation == K.RANGE16) @intFromEnum(DetachedRelation.u16) else if (relation == K.RANGE8) @intFromEnum(DetachedRelation.u8) else {
                    self.failure = true;
                    return;
                },
                else => {
                    self.failure = true;
                    return;
                },
            };
            self.counts[i] += 1;
        }
    };
    var counter = Counter{};
    const fixed: [DetachedSource.fixedWidth(role)]M31 = @splat(M31.one());
    const main: [DetachedSource.mainWidth(role)]M31 = @splat(M31.one());
    S.emitRaw(role, M31, &fixed, &main, @as(u32, 1), &counter);
    var n: u64 = 0;
    for (counter.counts) |v| n += v;
    if (counter.failure or n != DetachedSource.localQueries(role)) return error.DetachedSourceRelationShape;
    return counter.counts;
}
fn addDetached(shape: *Shape, scope: *DetachedScope, degrees: *ConditionalDegrees, global: *Mass.Globals, global_slots: *[3]u64, geometry: DetachedSource.Geometry) !void {
    if (!geometry.detached) return error.SpongeLocalScopeFlavor;
    const Eq = @import("../../../poseidon2_outer/sponge_local_gkr/equations.zig");
    const parts = try geometry.instances();
    scope.* = .{ .relations = .{
        .{ .model = .unit_consistency, .arity = 19 },
        .{ .arity = 3 },
        .{ .arity = 1 },
        .{ .arity = 1 },
    } };
    var columns: usize = 0;
    var constraints: usize = 0;
    inline for (DetachedSource.detached_roles, 0..) |role, i| {
        const instance = parts[i];
        const n = try rows(instance.row_log);
        const query_counts = try detachedQueries(role);
        for (&scope.relations, query_counts, 0..) |*bound, queries, j| {
            const slots = try times(n, queries);
            bound.denominator_slots = try plus(bound.denominator_slots, slots);
            const provider = role == .u16 or role == .u8 or role == .and_;
            if (provider) bound.valid_provider_support = try plus(bound.valid_provider_support, slots) else if (j == @intFromEnum(DetachedRelation.owner)) {
                // Every OWNER source weight is a sum/difference of constrained
                // Boolean flags, with absolute value at most2. Conservatively
                // charge both signs; no finite-characteristic cancellation.
                bound.unit_positive_mass = try plus(bound.unit_positive_mass, try times(2, slots));
                bound.unit_negative_mass = try plus(bound.unit_negative_mass, try times(2, slots));
            } else bound.unit_consumer_mass = try plus(bound.unit_consumer_mass, slots);
        }
        const L = Eq.Layout(role);
        try shape.includeCells(instance.row_log, L.widths());
        for (L.widths()) |width| columns = try std.math.add(usize, columns, width);
        constraints = try std.math.add(usize, constraints, L.CONSTRAINTS);
        shape.max_trace_log = @max(shape.max_trace_log, instance.row_log);
        shape.max_gkr_variables = @max(shape.max_gkr_variables, try instance.variables());
        global_slots[0] = try plus(global_slots[0], try times(n, Eq.globalCount(role, false)));
        global_slots[1] = try plus(global_slots[1], try times(n, Eq.globalCount(role, true)));
        if (role == .detached_descriptor) global_slots[2] = try plus(global_slots[2], n);
    }
    for (scope.relations) |bound| {
        try bound.validate();
        try degrees.add(bound);
    }
    try crossNamespaces(degrees, &scope.relations);
    shape.max_samples_per_column = @max(shape.max_samples_per_column, 2);
    shape.max_air_degree = @max(shape.max_air_degree, 3);
    shape.max_tuple_arity = @max(shape.max_tuple_arity, 35);
    try finishProof(shape, columns, constraints, 8, 1);
    const words = try plus(try times(29, geometry.calls), try times(18, geometry.permutations));
    try global.add(.{
        .ram = .{ .positive = words, .negative = words },
        .kio = .{ .positive = try times(25, geometry.calls), .negative = try plus(try times(25, geometry.calls), try times(50, geometry.permutations)) },
        .wire = .{ .negative = geometry.calls },
    });
}
fn deriveMode(a: std.mem.Allocator, program_log: u32, cpu: []const Wire.CpuDeclaration, truth: []const Wire.TruthDeclaration, requests: []const P.Request, op: ?OpInventory) !Report {
    const truth_count = try std.math.add(usize, truth.len, if (op) |inventory| inventory.truths.len else 0);
    const detached = if (op) |inventory| inventory.detached else null;
    const count = try validateInventory(cpu.len, try std.math.add(usize, truth_count, if (detached) |d| d.workers.len else 0));
    if (requests.len != cpu.len) return error.CandidateSourceShapeExceeded;
    _ = try rows(program_log);
    const cpus = try a.alloc(CpuScope, cpu.len);
    errdefer a.free(cpus);
    const truths = try a.alloc(TruthScope, truth.len);
    errdefer a.free(truths);
    var shape = Shape{ .native_proofs = count };
    var global = Mass.Globals{};
    var global_slots: [3]u64 = @splat(0);
    var degrees = ConditionalDegrees{};
    for (cpu, requests, cpus, 0..) |declaration, request, *scope, ordinal| {
        // Explicit supported scope; unknown v3 families/layouts cannot enter these bounds.
        if (op != null) {
            var legacy = declaration;
            legacy.bridges.tower = null;
            try Scope.declaration(legacy);
        } else try Scope.declaration(declaration);
        try Scope.request(request);
        try P.bulkCounts(request.bulk);
        try declaration.geometry.validate();
        _ = try A.word16_execution.types.inputs(request.base.cpu, request.base.epoch, declaration.geometry.cpu_log);
        _ = try declaration.geometry.lsCounts(request.base.memory.ls_count);
        if (request.base.memory.initial.len >= try rows(declaration.geometry.initialLog()) or request.base.memory.terminal.len >= try rows(declaration.geometry.terminalLog())) return error.CandidateSourceCountExceeded;
        if (declaration.geometry.omit_empty_division and request.base.division_requests != 0) return error.CandidateSourceCountExceeded;
        if (request.base.division_requests >= try rows(declaration.geometry.division_log) or request.base.multiplication_requests >= try rows(declaration.geometry.multiplication_log)) return error.CandidateSourceCountExceeded;
        var columns: usize = 0;
        var constraints: usize = 0;
        var instances: usize = 0;
        scope.* = emptyCpu();
        scope.namespace_count = if (declaration.geometry.cpu_u8_pairs) V3_LOCAL_NAMESPACES else LEGACY_LOCAL_NAMESPACES;
        for (Geometry.shapesForProgramLog(program_log, declaration.geometry)) |part| {
            if (!part.present()) continue;
            const origin = Frame.Origin{ .core = part.role };
            var descriptor = try Meta.forOrigin(origin);
            if (declaration.geometry.cpu_u8_pairs) switch (part.role) {
                .cpu => {
                    descriptor.local_terms = 14;
                    if (declaration.geometry.cpu_compact_decode) {
                        // Compact decode MAIN (37 columns, compact residuals);
                        // the same 14 local terms, relations and arities.
                        const compact = A.main_only.authority.shape(.cpu_compact);
                        descriptor.widths[1] = compact.main;
                        descriptor.constraints = @import("role.zig").constraintCount(.cpu_compact, origin);
                    }
                },
                .and_table => {
                    descriptor.local_terms = 2;
                    descriptor.widths[1] = 2;
                },
                else => {},
            };
            if (descriptor.widths[0] > part.widths[0] or descriptor.widths[1] != part.widths[1]) return error.CandidateSourceRoleLayoutMismatch;
            // Source keys retain legacy fixed columns, including columns no
            // longer read by MAIN-only roles. Count their commitment cost too.
            descriptor.widths[0] = part.widths[0];
            try includeRole(&shape, origin, part.log, descriptor, &columns, &constraints, &instances);
            try addCpuRoleMode(scope, origin, part.log, declaration.geometry.cpu_u8_pairs);
            try globalSlots(&global_slots, origin, part.log);
        }
        const first = try P.firstIds(requests, ordinal);
        for (std.enums.values(Types.Family), request.calls, first) |family, calls, first_id| {
            const optional = declaration.bridges.at(family);
            if (!P.presenceAdmitted(optional != null, calls != 0)) return error.InvalidCombinedBridgePresence;
            if (optional) |log| {
                if (family == .keccak) _ = try A.crypto.keccak.word16_bridge.types.validateGeometry(calls, first_id, log) else _ = try A.crypto.secp256k1.word16_bridge.types.validateGeometry(Types.bridgeKind(family), calls, first_id, log);
                const origin = Frame.Origin{ .bridge = family };
                try includeRole(&shape, origin, log, try Meta.forOrigin(origin), &columns, &constraints, &instances);
                try addCpuRole(scope, origin, log);
                try globalSlots(&global_slots, origin, log);
            }
        }
        inline for (Types.bulk_kinds) |kind| {
            const optional = declaration.bridges.bulk.at(kind);
            const active = request.bulk.rows(kind);
            if (!P.presenceAdmitted(optional != null, active != 0)) return error.InvalidCombinedBridgePresence;
            if (optional) |log| {
                _ = try A.crypto.bulk_memory.types.validateGeometry(kind, active, log);
                const origin = Frame.Origin{ .bulk = kind };
                try includeRole(&shape, origin, log, try Meta.forOrigin(origin), &columns, &constraints, &instances);
                try addCpuRole(scope, origin, log);
                try globalSlots(&global_slots, origin, log);
            }
        }
        if (detached) |d| {
            if (declaration.bridges.sponge.any()) return error.SpongeCpuRequiresDetachedSetup;
            try addFrontier(&shape, scope, &global, &global_slots, &columns, &constraints, &instances, request, @intCast(ordinal), d.logs[ordinal]);
        } else for (Types.sponge_kinds) |kind| {
            const optional = declaration.bridges.sponge.at(kind);
            const active = request.sponge.rows(kind);
            if (!P.presenceAdmitted(optional != null, active != 0)) return error.InvalidCombinedBridgePresence;
            if (optional) |log| {
                _ = try A.crypto.keccak_sponge.types.validateGeometry(kind, active, log);
                const origin = Frame.Origin{ .sponge = kind };
                try includeRole(&shape, origin, log, try Meta.forOrigin(origin), &columns, &constraints, &instances);
                try addCpuRole(scope, origin, log);
                try globalSlots(&global_slots, origin, log);
            }
        }
        const dword_counts = try Types.dwordCounts(declaration.bridges, request.ls_dword);
        for (0..Types.DWORD_INSTANCES) |i| if (declaration.bridges.dwordLog(i)) |log| {
            if (dword_counts[i] >= try rows(log)) return error.CandidateSourceCountExceeded;
            const origin = Frame.Origin{ .dword = @intCast(i) };
            try includeRole(&shape, origin, log, try Meta.forOrigin(origin), &columns, &constraints, &instances);
            try addCpuRole(scope, origin, log);
            try globalSlots(&global_slots, origin, log);
        };
        if (op) |inventory| {
            const span = inventory.cpu_spans[ordinal];
            if (declaration.bridges.tower) |log| {
                const origin = Frame.Origin{ .tower = {} };
                try includeRole(&shape, origin, log, try Meta.forOrigin(origin), &columns, &constraints, &instances);
                try addCpuRole(scope, origin, log);
                try globalSlots(&global_slots, origin, log);
            }
            // Exact signed topology, not the field-valued residual claim.
            try global.add(.{ .ram = .{ .positive = try times(80, span.calls), .negative = try times(80, span.calls) }, .wire = .{ .positive = try times(20, span.calls), .negative = try times(12, span.calls) } });
        }
        try scope.owner_table.validate();
        if (scope.owner_table.unit_consumer_mass != 0 and scope.owner_table.valid_provider_support != A.crypto.bulk_memory.types.TABLE_ENTRIES) return error.CandidateSourceRelationShape;
        try finishProof(&shape, columns, constraints, instances, 1);
        for (scope.relations) |bound| {
            try bound.validate();
            try degrees.add(bound);
            shape.max_tuple_arity = @max(shape.max_tuple_arity, bound.arity);
        }
        if (detached != null) {
            // Only the old source event formula loses its sponge contribution;
            // requests and source geometry retain their actual call counts.
            var counts = try Mass.cpuCounts(request);
            counts.sponge = .{ 0, 0 };
            try global.add(try Mass.evaluateCpuCounts(counts));
        } else try global.add(try Mass.cpu(request));
    }
    for (truth, truths) |declaration, *scope| {
        try Scope.truthDeclaration(declaration);
        if (declaration.calls == 0) return error.InvalidCombinedTruthSpan;
        if (declaration.family != .keccak and (@intFromEnum(declaration.family) >= 3 or declaration.logs[1] == 0)) {
            const Cat = @import("truth_catalog.zig");
            const descriptor = try Cat.descriptorForDeclaration(declaration);
            const counts = try Cat.lookupCountsForDeclaration(declaration);
            try shape.includeCells(descriptor.log_size, descriptor.widths());
            for (std.enums.values(TF.Relation), &scope.relations) |relation, *bound| bound.* = .{ .arity = relation.arity(), .consumer_sign = if (relation == .byte) .positive else .negative };
            const bytes = &scope.relations[@intFromEnum(TF.Relation.byte)];
            bytes.unit_consumer_mass = counts.byte_unit_consumers;
            bytes.valid_provider_support = counts.byte_provider_support;
            bytes.denominator_slots = counts.byte_denominator_slots;
            for (scope.relations) |bound| {
                try bound.validate();
                try degrees.add(bound);
            }
            var cols: usize = 0;
            for (descriptor.widths()) |width| cols = try std.math.add(usize, cols, width);
            shape.max_trace_log = @max(shape.max_trace_log, descriptor.log_size);
            shape.max_air_degree = @max(shape.max_air_degree, descriptor.maxDegree());
            shape.max_samples_per_column = @max(shape.max_samples_per_column, descriptor.maxSamples());
            shape.max_tuple_arity = @max(shape.max_tuple_arity, 35);
            try finishProof(&shape, cols, descriptor.nConstraints(), 0, if (descriptor.maxDegree() > 3) 2 else 1);
            global_slots[2] = try plus(global_slots[2], counts.wire_denominator_slots);
            try global.add(try Mass.truth(declaration));
            continue;
        }
        const descriptors = try Truth.shapesForDeclaration(declaration);
        var columns: usize = 0;
        var constraints: usize = 0;
        for (std.enums.values(TF.Relation), &scope.relations) |relation, *bound| bound.* = .{ .arity = relation.arity(), .consumer_sign = if (relation == .byte) .positive else .negative };
        for (descriptors) |part| {
            const n = try rows(part.log_size);
            try shape.includeCells(part.log_size, part.widths());
            for (part.widths()) |width| columns = try std.math.add(usize, columns, width);
            constraints = try std.math.add(usize, constraints, part.nConstraints());
            shape.max_trace_log = @max(shape.max_trace_log, part.log_size);
            shape.max_air_degree = @max(shape.max_air_degree, part.maxDegree());
            shape.max_samples_per_column = @max(shape.max_samples_per_column, part.maxSamples());
            switch (part.kind) {
                .keccak => {
                    global_slots[1] = try plus(global_slots[1], try times(n, part.globalQueries()));
                    // Round-active is Boolean. Use the FULL physical row
                    // upper bound; do not rely on an honest active census.
                    scope.relations[@intFromEnum(TF.Relation.chi)].unit_consumer_mass = try times(n, A.crypto.keccak.layout.STATE);
                    scope.relations[@intFromEnum(TF.Relation.chi)].denominator_slots = try times(n, A.crypto.keccak.layout.STATE);
                    scope.relations[@intFromEnum(TF.Relation.xor5)].unit_consumer_mass = try times(n, A.crypto.keccak.layout.PARITY);
                    scope.relations[@intFromEnum(TF.Relation.xor5)].denominator_slots = try times(n, A.crypto.keccak.layout.PARITY);
                },
                .chi, .xor5 => {
                    const relation: TF.Relation = if (part.kind == .chi) .chi else .xor5;
                    scope.relations[@intFromEnum(relation)].valid_provider_support = n;
                    scope.relations[@intFromEnum(relation)].denominator_slots = try plus(scope.relations[@intFromEnum(relation)].denominator_slots, n);
                },
                .product, .linear => {
                    global_slots[2] = try plus(global_slots[2], try times(n, part.globalQueries()));
                    const queries = try times(n, part.instance().queries);
                    const bound = &scope.relations[@intFromEnum(TF.Relation.byte)];
                    bound.unit_consumer_mass = try plus(bound.unit_consumer_mass, queries);
                    bound.denominator_slots = try plus(bound.denominator_slots, queries);
                },
                .bytes => {
                    const bound = &scope.relations[@intFromEnum(TF.Relation.byte)];
                    bound.valid_provider_support = n;
                    bound.denominator_slots = try plus(bound.denominator_slots, n);
                },
            }
        }
        try finishProof(&shape, columns, constraints, 0, if (declaration.family == .keccak) 2 else 1);
        for (scope.relations) |bound| {
            try bound.validate();
            try degrees.add(bound);
            shape.max_tuple_arity = @max(shape.max_tuple_arity, bound.arity);
        }
        try global.add(try Mass.truth(declaration));
    }
    if (op) |inventory| {
        const Tower = A.crypto.bn254_tower.narrow;
        const FL = Tower.equations.LayoutForField(.frontier, core.fields.om31.OM31);
        const AL = Tower.equations.LayoutForField(.arithmetic, core.fields.om31.OM31);
        for (inventory.truths, inventory.scopes) |declaration, *scope| {
            const f = try rows(declaration.frontier_log);
            const arithmetic = try rows(declaration.arithmetic_log);
            const active = try times(declaration.calls, Tower.dag.STEPS);
            const ssa_mass = try times(declaration.calls, Tower.dag.READS);
            scope.* = .{
                .bytes = .{ .arity = 1, .unit_consumer_mass = try times(active, Tower.micro.BYTE_QUERIES), .valid_provider_support = 256, .denominator_slots = try times(arithmetic, Tower.micro.BYTE_QUERIES + 1) },
                .carries = .{ .arity = 1, .unit_consumer_mass = try times(active, Tower.micro.CARRY_QUERIES), .valid_provider_support = Tower.micro.CARRY_LIMIT, .denominator_slots = try times(arithmetic, Tower.micro.CARRY_QUERIES + 1) },
                // Source-owned fixed fanouts expand to this many unit writes;
                // no producer supplies a weight or an unconstrained SSA edge.
                .ssa = .{ .model = .unit_consistency, .arity = 35, .unit_positive_mass = ssa_mass, .unit_negative_mass = ssa_mass, .denominator_slots = try plus(try times(arithmetic, 8), f) },
                .canonical_writes = active,
            };
            inline for (.{ "bytes", "carries", "ssa" }) |name| {
                const bound = @field(scope, name);
                try bound.validate();
                try degrees.add(bound);
            }
            try shape.includeCells(declaration.frontier_log, FL.widths());
            try shape.includeCells(declaration.arithmetic_log, AL.widths());
            var columns: usize = 0;
            for (FL.widths()) |width| columns = try std.math.add(usize, columns, width);
            for (AL.widths()) |width| columns = try std.math.add(usize, columns, width);
            shape.max_trace_log = @max(shape.max_trace_log, @max(declaration.frontier_log, declaration.arithmetic_log));
            shape.max_air_degree = @max(shape.max_air_degree, 3);
            shape.max_samples_per_column = @max(shape.max_samples_per_column, 2);
            shape.max_tuple_arity = @max(shape.max_tuple_arity, 35);
            try finishProof(&shape, columns, FL.CONSTRAINTS + AL.CONSTRAINTS, 0, 1);
            global_slots[2] = try plus(global_slots[2], try plus(arithmetic, f));
            try global.add(.{ .wire = .{ .positive = try times(12, declaration.calls), .negative = try times(20, declaration.calls) } });
        }
    }
    if (detached) |d| for (d.workers, d.scopes) |geometry, *scope| {
        try addDetached(&shape, scope, &degrees, &global, &global_slots, geometry);
    };
    if (detached != null) {
        for (cpus) |scope| try crossNamespaces(&degrees, &scope.relations);
        for (truths) |scope| try crossNamespaces(&degrees, &scope.relations);
        if (op) |inventory| for (inventory.scopes) |scope| try crossNamespaces(&degrees, &.{ scope.bytes, scope.carries, scope.ssa });
    }
    // Global namespaces remain independently closed, with ordinary signed
    // bounds including readonly program-use multiplicity. No field residue sum.
    inline for (.{ "ram", "kio", "wire" }) |name| {
        const bound = @field(global, name);
        if (bound.positive >= MODULUS or bound.negative >= MODULUS) return error.CandidateCharacteristicBoundExceeded;
    }
    const arities = [_]usize{
        @typeInfo(@FieldType(@FieldType(Manifest.Shared, "ram"), "coefficients")).array.len,
        @typeInfo(@FieldType(@FieldType(Manifest.Shared, "kio"), "coefficients")).array.len,
        @typeInfo(@FieldType(@FieldType(Manifest.Shared, "wire"), "coefficients")).array.len,
    };
    for (arities, global_slots) |arity, slots| {
        try degrees.addGlobal(.{ .arity = arity, .denominator_slots = slots });
        if (slots != 0) shape.max_tuple_arity = @max(shape.max_tuple_arity, arity);
    }
    try shape.validate();
    // Necessary lookup-only budget; all omitted protocol terms remain explicit
    // false qualifications in Report, never a whole-protocol certificate.
    try degrees.requireLookupOnlyBits(Policy.TARGET_BITS);
    return .{ .accounting_profile = if (detached != null) "rv64-source-derived-op-detached-lookup/v1" else if (op != null) "rv64-source-derived-op-miller-lookup/v1" else ACCOUNTING_PROFILE, .allocator = a, .shape = shape, .cpu_scopes = cpus, .truth_scopes = truths, .global_signed = global, .global_denominator_slots = global_slots, .conditional_degrees = degrees };
}

test "weighted JUMPDEST OWNER support is partitioned from unit token mass and characteristic checked" {
    const t = @import("std").testing;
    var scope = emptyCpu();
    try addCpuRole(&scope, .{ .bulk = .jscan }, 5);
    try addCpuRole(&scope, .{ .bulk = .jtab }, 14);
    try t.expectEqual(@as(u64, 2048), scope.owner_table.unit_consumer_mass);
    try t.expectEqual(@as(u64, 8448), scope.owner_table.valid_provider_support);
    const owner = scope.relations[@intFromEnum(F.Relation.owner)];
    try t.expectEqual(@as(u64, 0), owner.unit_positive_mass);
    try t.expectEqual(@as(u64, 32), owner.unit_negative_mass);
    try t.expectEqual(@as(u64, 32 * 65 + 16384), owner.denominator_slots);
    try scope.owner_table.validate();
    scope.owner_table.unit_consumer_mass = MODULUS;
    try t.expectError(error.CandidateCharacteristicBoundExceeded, scope.owner_table.validate());
    const bulk = A.crypto.bulk_memory.types;
    try t.expect(bulk.TOKEN_JD_TABLE >= 256 and bulk.TOKEN_JD_TABLE < MODULUS);
    inline for (.{ bulk.TOKEN_COPY, bulk.TOKEN_SET, bulk.TOKEN_CMP, bulk.TOKEN_CMP_RESULT, bulk.TOKEN_JD }) |token| try t.expect(token != bulk.TOKEN_JD_TABLE);
}

test "public boundary log23 source summary needs typed boundary provenance" {
    var shape = Shape{ .native_proofs = 1, .max_trace_log = 23, .max_columns = 1, .max_constraints = 1 };
    try std.testing.expectError(error.CandidateSourceShapeExceeded, shape.validate());
    shape.max_public_boundary_log = 23;
    // A valid boundary must never raise the summary cap of another provider.
    try std.testing.expectError(error.CandidateSourceShapeExceeded, shape.validate());
    shape.max_trace_log = 22;
    try shape.validate();
    shape.max_public_boundary_log = 24;
    try std.testing.expectError(error.CandidateSourceShapeExceeded, shape.validate());
}

test "detached security namespace collision union includes cross relation pairs" {
    const relations = [_]Bound{ .{ .arity = 1, .denominator_slots = 3 }, .{ .arity = 19, .denominator_slots = 5 } };
    var degrees = ConditionalDegrees{};
    for (relations) |b| try degrees.add(b);
    const before = degrees.tuple_collision;
    try crossNamespaces(&degrees, &relations);
    try std.testing.expectEqual(before + 3 * 5 * (1 + 19), degrees.tuple_collision);
    try std.testing.expectEqual(@as(u128, 8), degrees.local_rational_identity);
    try std.testing.expectEqual(@as(u128, 8), degrees.poles);
}
