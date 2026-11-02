//! Receiver-derived native shape and source-support bounds. Weighted valid
//! provider support is DISTINCT from ordinary negative integer mass. This
//! engineering preflight is not a reviewed whole-protocol security certificate.
const Scope = @import("v2_scope.zig");
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
    fn validate(self: Bound) !void {
        if (self.unit_consumer_mass >= MODULUS or self.unit_positive_mass >= MODULUS or self.unit_negative_mass >= MODULUS) return error.CandidateCharacteristicBoundExceeded;
    }
};
pub const CpuScope = struct { relations: [std.meta.fields(F.Relation).len]Bound };
pub const TruthScope = struct { relations: [std.meta.fields(TF.Relation).len]Bound };
pub const Shape = struct {
    native_proofs: usize = 0,
    max_trace_log: u32 = 0,
    max_columns: usize = 0,
    max_constraints: usize = 0,
    max_samples_per_column: usize = 0,
    max_air_degree: u8 = 0,
    max_local_instances: usize = 0,
    max_tuple_arity: usize = 0,
    max_gkr_variables: u32 = 0,
    pub fn validate(self: Shape) !void {
        if (self.native_proofs == 0 or self.native_proofs > Policy.MAX_PROOFS or self.max_trace_log < 5 or self.max_trace_log > Policy.MAX_TRACE_LOG or self.max_columns == 0 or self.max_columns > Policy.MAX_COLUMNS or self.max_constraints == 0 or self.max_constraints > Policy.MAX_CONSTRAINTS or self.max_samples_per_column > Policy.MAX_SAMPLES_PER_COLUMN or self.max_air_degree > Policy.MAX_AIR_DEGREE or self.max_local_instances > Policy.MAX_LOCAL_INSTANCES or self.max_tuple_arity > Policy.MAX_TUPLE_ARITY or self.max_gkr_variables > Policy.MAX_GKR_VARIABLES) return error.CandidateSourceShapeExceeded;
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
    fn add(self: *ConditionalDegrees, b: Bound) !void {
        const n: u128 = b.denominator_slots;
        const pairs = if (n == 0) 0 else try std.math.mul(u128, n, n - 1) / 2;
        self.tuple_collision = try std.math.add(u128, self.tuple_collision, try std.math.mul(u128, pairs, b.arity));
        self.rational_identity = try std.math.add(u128, self.rational_identity, n);
        self.local_rational_identity = try std.math.add(u128, self.local_rational_identity, n);
        self.poles = try std.math.add(u128, self.poles, n);
    }
    fn addGlobal(self: *ConditionalDegrees, bound: Bound) !void {
        try self.add(bound);
        self.local_rational_identity -= bound.denominator_slots;
        self.global_rational_identity = try std.math.add(u128, self.global_rational_identity, bound.denominator_slots);
    }
};
pub const Report = struct {
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
fn plus(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b);
}
fn times(a: u64, b: u64) !u64 {
    return std.math.mul(u64, a, b);
}
fn rows(log: u32) !u64 {
    if (log < 5 or log > Policy.MAX_TRACE_LOG) return error.CandidateSourceShapeExceeded;
    return @as(u64, 1) << @intCast(log);
}
fn emptyCpu() CpuScope {
    var out: CpuScope = undefined;
    for (std.enums.values(F.Relation), &out.relations) |relation, *bound| bound.* = .{ .arity = relation.arity(), .model = switch (relation) {
        .register, .owner => .unit_consistency,
        .rom, .function, .range16, .range8, .and_, .shift, .selection => .unit_membership_valid_support,
    } };
    return out;
}
fn addCpuRole(scope: *CpuScope, origin: Frame.Origin, log: u32) !void {
    const count = try rows(log);
    const fractions = switch (origin) {
        .bulk => |kind| Q.BULK[@intFromEnum(kind)],
        .core => |kind| Q.CORE[@intFromEnum(kind)],
        .bridge => |kind| Q.BRIDGES[@intFromEnum(kind)],
    };
    for (std.enums.values(F.Relation), fractions, &scope.relations) |relation, queries, *bound| {
        if (queries == 0) continue;
        const slots = try times(count, queries);
        bound.denominator_slots = try plus(bound.denominator_slots, slots);
        if (relation == .register) {
            if (queries % 2 != 0) return error.CandidateSourceRelationShape;
            bound.unit_positive_mass = try plus(bound.unit_positive_mass, slots / 2);
            bound.unit_negative_mass = try plus(bound.unit_negative_mass, slots / 2);
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
    _ = try rows(log);
    for (descriptor.widths) |width| columns.* = try std.math.add(usize, columns.*, width);
    constraints.* = try std.math.add(usize, constraints.*, descriptor.constraints);
    shape.max_trace_log = @max(shape.max_trace_log, log);
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
fn globalSlots(slots: *[3]u64, origin: Frame.Origin, log: u32) !void {
    const layout = Global.layout(origin);
    const n = try rows(log);
    slots[0] = try plus(slots[0], try times(n, layout.ram_queries));
    if (layout.other_queries != 0) {
        const index: usize = if (origin.bridge == .keccak) 1 else 2;
        slots[index] = try plus(slots[index], try times(n, layout.other_queries));
    }
}
pub fn validateInventory(cpu: usize, truth: usize) !usize {
    const count = try std.math.add(usize, cpu, truth);
    if (cpu == 0 or count > Policy.MAX_PROOFS) return error.CandidateSourceShapeExceeded;
    return count;
}
pub fn derive(a: std.mem.Allocator, program_log: u32, cpu: []const Wire.CpuDeclaration, truth: []const Wire.TruthDeclaration, requests: []const P.Request) !Report {
    const count = try validateInventory(cpu.len, truth.len);
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
        // v2 roster only (see v2_scope.zig); v3 roles have no candidate shapes.
        try Scope.declaration(declaration);
        try Scope.request(request);
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
        for (Geometry.shapesForProgramLog(program_log, declaration.geometry)) |part| {
            if (!part.present()) continue;
            const origin = Frame.Origin{ .core = part.role };
            var descriptor = try Meta.forOrigin(origin);
            if (descriptor.widths[0] > part.widths[0] or descriptor.widths[1] != part.widths[1]) return error.CandidateSourceRoleLayoutMismatch;
            // Source keys retain legacy fixed columns, including columns no
            // longer read by MAIN-only roles. Count their commitment cost too.
            descriptor.widths[0] = part.widths[0];
            try includeRole(&shape, origin, part.log, descriptor, &columns, &constraints, &instances);
            try addCpuRole(scope, origin, part.log);
            try globalSlots(&global_slots, origin, part.log);
        }
        const first = try P.firstIds(requests, ordinal);
        for (std.enums.values(Types.Family), request.calls, first) |family, calls, first_id| {
            const optional = declaration.bridges.at(family);
            if ((optional != null) != (calls != 0)) return error.InvalidCombinedBridgePresence;
            if (optional) |log| {
                if (family == .keccak) _ = try A.crypto.keccak.word16_bridge.types.validateGeometry(calls, first_id, log) else _ = try A.crypto.secp256k1.word16_bridge.types.validateGeometry(if (family == .add) .add else .double, calls, first_id, log);
                const origin = Frame.Origin{ .bridge = family };
                try includeRole(&shape, origin, log, try Meta.forOrigin(origin), &columns, &constraints, &instances);
                try addCpuRole(scope, origin, log);
                try globalSlots(&global_slots, origin, log);
            }
        }
        try finishProof(&shape, columns, constraints, instances, 1);
        for (scope.relations) |bound| {
            try bound.validate();
            try degrees.add(bound);
            shape.max_tuple_arity = @max(shape.max_tuple_arity, bound.arity);
        }
        try global.add(try Mass.cpu(request));
    }
    for (truth, truths) |declaration, *scope| {
        try Scope.truthDeclaration(declaration);
        if (declaration.calls == 0) return error.InvalidCombinedTruthSpan;
        const descriptors = try Truth.shapesForDeclaration(declaration);
        var columns: usize = 0;
        var constraints: usize = 0;
        for (std.enums.values(TF.Relation), &scope.relations) |relation, *bound| bound.* = .{ .arity = relation.arity(), .consumer_sign = if (relation == .byte) .positive else .negative };
        for (descriptors) |part| {
            const n = try rows(part.log_size);
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
    return .{ .allocator = a, .shape = shape, .cpu_scopes = cpus, .truth_scopes = truths, .global_signed = global, .global_denominator_slots = global_slots, .conditional_degrees = degrees };
}
