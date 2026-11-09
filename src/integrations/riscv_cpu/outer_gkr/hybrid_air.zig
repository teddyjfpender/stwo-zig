//! Receiver-owned polynomial authority for the hybrid outer AIR. MAIN roots
//! are retained from the pinned original AIR; only roots depending on classic
//! INTER are replaced. Four wide components use 16 committed binding columns
//! and ten derived, uncommitted Eq auxiliaries. No proof chooses root selection.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const A = @import("stwo_riscv_frontend").rv64_air;
const P = @import("profile.zig");
const B = @import("binding_v2.zig");
const T = @import("tuples.zig");
const Legacy = @import("binding.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const IR = engine.air.secure_polynomial_program_v2;
const Builder = IR.BuilderFor(O);
const Captured = Outer.geometry.Component;
pub const PUBLIC_AUX_COLUMNS = 10;
pub fn interactionWidth(component: P.Component) u32 {
    return if (P.gkrBound(component)) 16 else P.classicInteractionBaseColumns(component);
}
pub fn interactionStart(component: P.Component) u32 {
    var n: u32 = 0;
    for (0..@intFromEnum(component)) |i| n += interactionWidth(@enumFromInt(i));
    return n;
}
pub fn interactionColumns() u32 {
    return interactionStart(.range_check_16) + interactionWidth(.range_check_16);
}
threadlocal var active: ?*Builder = null;
const F = struct {
    pub const rv64_extension_degree = 8;
    pub const rv64_external_lane = true;
    id: u32,
    fn builder() *Builder {
        return active orelse @panic("hybrid recorder inactive");
    }
    pub fn fromBase(v: M) F {
        return .{ .id = builder().constant(O.fromBase(v)) };
    }
    pub fn fromM31Array(v: [8]M) F {
        return .{ .id = builder().constant(O.fromM31Array(v)) };
    }
    pub fn zero() F {
        return fromBase(M.zero());
    }
    pub fn one() F {
        return fromBase(M.one());
    }
    pub fn add(a: F, b: F) F {
        return .{ .id = builder().add(a.id, b.id) };
    }
    pub fn sub(a: F, b: F) F {
        return .{ .id = builder().sub(a.id, b.id) };
    }
    pub fn mul(a: F, b: F) F {
        return .{ .id = builder().mul(a.id, b.id) };
    }
    pub fn neg(a: F) F {
        return .{ .id = builder().neg(a.id) };
    }
    pub fn inv(_: F) F {
        if (builder().failure == null) builder().failure = error.NonPolynomialHybridInverse;
        return zero();
    }
    pub fn fromPartialEvals(v: [8]F) F {
        var result = zero();
        for (v, 0..) |x, i| {
            var basis: [8]M = @splat(M.zero());
            basis[i] = M.one();
            result = result.add(x.mul(fromM31Array(basis)));
        }
        return result;
    }
    fn input(tree: u8, column: usize, offset: i8) F {
        return .{ .id = builder().input(.{ .tree = tree, .column = @intCast(column), .offset = offset }) };
    }
    fn parameter(slot: usize) F {
        return .{ .id = builder().parameter(O.fromBase(M.fromU64(slot + 1))) };
    }
    fn read(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !F {
        const hybrid: *const bool = @ptrCast(@alignCast(raw));
        if (tree == 2 and hybrid.*) return zero();
        return input(tree, column, std.math.cast(i8, offset) orelse return error.OuterMaskOffsetTooLarge);
    }
};
fn secure(column: usize, offset: i8) F {
    var v: [8]F = undefined;
    for (&v, 0..) |*x, i| x.* = F.input(2, column + i, offset);
    return F.fromPartialEvals(v);
}
/// Structural INTER dependency, applied only to the independently pinned source.
/// This is stronger than deleting a guessed suffix: all arithmetic roots not
/// reading INTER survive in original order, including roots in split parts.
pub fn mainRoots(a: std.mem.Allocator, p: Outer.program.Program) ![]bool {
    const base = try a.alloc(bool, p.header.max_base_regs);
    defer a.free(base);
    @memset(base, false);
    const ext = try a.alloc(bool, p.header.max_ext_regs);
    defer a.free(ext);
    @memset(ext, false);
    for (p.base_insts) |i| base[i.dst] = switch (i.op) {
        .trace_col, .preprocessed_col => i.interaction == 2,
        .param, .constant => false,
        .add, .sub, .mul => base[i.a] or base[i.b],
        .neg, .inv => base[i.a],
    };
    for (p.ext_insts) |i| ext[i.dst] = switch (i.op) {
        .secure_col => base[i.a] or base[i.b] or base[i.c] or base[i.d],
        .param, .constant => false,
        .add, .sub, .mul => ext[i.a] or ext[i.b],
        .neg => ext[i.a],
    };
    const out = try a.alloc(bool, p.constraint_roots.len);
    for (out, p.constraint_roots) |*v, r| v.* = !ext[r];
    return out;
}
pub const Artifact = struct {
    a: std.mem.Allocator,
    component: P.Component,
    program: IR.ProgramFor(O),
    parameter_slots: []u32,
    source_parameter_count: usize,
    main_constraints: usize,
    /// Same polynomial authority in native OM31 and the child-verifier lane.
    pub fn evaluateFor(self: *const @This(), comptime Lane: type, a: std.mem.Allocator, inputs: []const Lane, invocation_parameters: []const Lane) ![]Lane {
        if (inputs.len != self.program.inputs.len or invocation_parameters.len != self.program.parameters.len) return error.InvalidHybridParameters;
        const values = try a.alloc(Lane, self.program.nodes.len);
        defer a.free(values);
        for (self.program.nodes, values) |node, *value| value.* = switch (node.op) {
            .constant => Lane.fromM31Array(self.program.constantValue(node.value).toM31Array()),
            .input => inputs[node.value],
            .parameter => invocation_parameters[node.value],
            .add => values[node.lhs].add(values[node.rhs]),
            .sub => values[node.lhs].sub(values[node.rhs]),
            .mul => values[node.lhs].mul(values[node.rhs]),
            .neg => values[node.lhs].neg(),
            .fraction, .range_fraction => return error.InvalidHybridPolynomial,
        };
        const out = try a.alloc(Lane, self.program.roots.len);
        for (out, self.program.roots) |*value, root| value.* = values[root];
        return out;
    }
    pub fn deinit(self: *@This()) void {
        self.program.deinit();
        self.a.free(self.parameter_slots);
        self.* = undefined;
    }
    pub fn validate(self: *const @This()) !void {
        try self.program.validate();
        const hybrid = P.gkrBound(self.component);
        for (self.program.inputs) |input| if (input.tree == 2) {
            const width = interactionWidth(self.component);
            if (input.column >= width + (if (hybrid) @as(u32, PUBLIC_AUX_COLUMNS) else 0)) return error.InvalidHybridInteractionMask;
            if (hybrid and input.offset != 0 and !(input.column < 8 and input.offset == 2) and !(input.column >= 8 and input.column < 16 and input.offset == -1)) return error.InvalidHybridInteractionMask;
        };
        const degrees = try self.program.degrees(self.a);
        defer self.a.free(degrees);
        for (self.program.roots, 0..) |r, i| if (degrees[r] > (if (hybrid and i >= self.main_constraints) @as(u16, 2) else 3)) return error.HybridConstraintDegreeExceeded;
    }
    /// Runtime parameters are receiver-derived, including every lane weight and
    /// terminal target. Supplying arbitrary caller-chosen parameters is not proof
    /// admission: use after the section verifier and source/class checks below.
    pub fn parameters(self: *const @This(), a: std.mem.Allocator, source: *const Captured, z: O, alpha: O, class: *const P.Class, verified: *const @import("section.zig").Verified, ch: *const Legacy.Challenges, claim: O) ![]O {
        return self.parametersFor(O, a, source, z, alpha, class, verified, ch, claim);
    }
    pub fn parametersFor(self: *const @This(), comptime Lane: type, a: std.mem.Allocator, source: *const Captured, z: Lane, alpha: Lane, class: *const P.Class, verified: anytype, ch: anytype, claim: Lane) ![]Lane {
        try class.validate();
        if (class.binding_version != .cyclic_eq_v2 or source.trace_log_size != class.row_logs[@intFromEnum(self.component)] or source.ext_sources.len != self.source_parameter_count) return error.OuterGkrBindingShape;
        const original = try Outer.program.ForLane(Lane).extensionParameters(a, source, z, alpha, claim);
        defer a.free(original);
        var named: [256]Lane = undefined;
        if (self.source_parameter_count + 30 > named.len) return error.OuterGkrBindingShape;
        @memcpy(named[0..original.len], original);
        if (P.gkrBound(self.component)) {
            const point = verified.artifact.ood_point;
            const log: u32 = class.row_logs[@intFromEnum(self.component)];
            if (point.len != class.layers()) return error.OuterGkrBindingShape;
            @memset(named[original.len..][0..26], Lane.zero());
            var first: usize = 0;
            for (class.instances, 0..) |inst, g| {
                if (inst.component != self.component) continue;
                const weights = try Legacy.eqTableFor(Lane, a, point[point.len - inst.variables() .. point.len - log]);
                defer a.free(weights);
                for (weights, 0..) |weight, lane| named[original.len + first + lane] = ch.rho[g].mul(weight);
                first += inst.lanes_used;
            }
            if (first != P.FACTS[@intFromEnum(self.component)].lookups) return error.OuterGkrBindingShape;
            named[original.len + 26] = ch.gamma;
            var target = Lane.zero();
            for (class.instances, 0..) |inst, g| if (inst.component == self.component) {
                const pair = verified.artifact.claims_to_verify_by_instance[g];
                target = target.add(ch.rho[g].mul(pair[0].add(ch.gamma.mul(pair[1]))));
            };
            named[original.len + 27] = target.mul(Lane.fromBase(try M.fromU64(@as(u64, 1) << @intCast(log)).inv()));
            const mle = try @import("../logup_gkr/mle_point.zig").MleEvalPointFor(Lane).init(point[point.len - log ..]);
            named[original.len + 28] = mle.eq0;
            named[original.len + 29] = mle.eq1;
        }
        const out = try a.alloc(Lane, self.parameter_slots.len);
        errdefer a.free(out);
        for (out, self.parameter_slots) |*v, slot| {
            if (slot >= original.len + (if (P.gkrBound(self.component)) @as(usize, 30) else 0)) return error.InvalidHybridParameterSlot;
            v.* = named[slot];
        }
        return out;
    }
};
/// Source must be the matching component of Authority.bound, whose template
/// was admitted by parsePinnedAir; arbitrary external recordings are refused
/// by the caller's Authority construction, not accepted from a wire.
pub fn record(a: std.mem.Allocator, source: *const Captured, component: P.Component) !Artifact {
    if (active != null) return error.OuterRecordingAlreadyActive;
    if (!std.mem.eql(u8, source.label, @tagName(component))) return error.HybridComponentMismatch;
    var builder = Builder.init(a);
    defer builder.deinit();
    active = &builder;
    defer active = null;
    const hybrid = P.gkrBound(component);
    const count = source.ext_sources.len;
    const original = try a.alloc(F, count);
    defer a.free(original);
    for (original, 0..) |*v, i| v.* = F.parameter(i);
    var roots: std.ArrayList(u32) = .empty;
    defer roots.deinit(a);
    for (source.parts) |part| {
        try Outer.program.validateLens(a, part.program);
        const keep = try mainRoots(a, part.program);
        defer a.free(keep);
        const values = try Outer.program.ForLane(F).evaluate(a, part.program, .{ .context = &hybrid, .get = F.read }, original);
        defer a.free(values);
        for (values, keep) |value, yes| if (!hybrid or yes) {
            try roots.append(a, value.id);
        };
    }
    const main_count = roots.items.len;
    if (hybrid) {
        var c: [52]F = undefined;
        for (c[0..P.FACTS[@intFromEnum(component)].main], 0..) |*v, i| v.* = F.input(1, i, 0);
        const pp_count: usize = switch (component) {
            .triple_xor => 5,
            .blake_g_gate => 11,
            else => 3,
        };
        var pp: [11]F = undefined;
        for (pp[0..pp_count], 0..) |*v, i| {
            const index = if (component == .blake_g_gate) ([11]u8{ 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 7 })[i] else i;
            v.* = F.input(0, index, 0);
        }
        var storage: [26]T.LookupFor(F) = undefined;
        const lookups = try T.rowFor(F, component, c[0..P.FACTS[@intFromEnum(component)].main], pp[0..pp_count], &storage);
        var projection = F.zero();
        for (lookups, 0..) |lookup, i| {
            var denominator = F.zero().sub(z: {
                for (source.ext_sources, 0..) |s, j| if (s == .lookup_z) break :z original[j];
                return error.MissingHybridLookupParameter;
            });
            for (lookup.tuple[0..lookup.len], 0..) |v, j| {
                const power = if (j == 0) F.one() else x: {
                    for (source.ext_sources, 0..) |s, k| if (s == .lookup_alpha_power and s.lookup_alpha_power == j) break :x original[k];
                    return error.MissingHybridLookupParameter;
                };
                denominator = denominator.add(v.mul(power));
            }
            projection = projection.add(F.parameter(count + i).mul(lookup.numerator.add(F.parameter(count + 26).mul(denominator))));
        }
        var residuals: [3]F = undefined;
        var sink = A.evaluation.SinkFor(F){ .values = &residuals };
        B.emitFor(F, .{ .eq = secure(0, 0), .eq_next2 = secure(0, 2), .prefix = secure(8, 0), .prefix_previous = secure(8, -1) }, .{ .first = F.input(2, 16, 0), .second = F.input(2, 17, 0), .carry = secure(18, 0), .eq0 = F.parameter(count + 28), .eq1 = F.parameter(count + 29) }, projection, F.parameter(count + 27), &sink);
        for (residuals) |v| try roots.append(a, v.id);
    }
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/circuit/om31/hybrid-eq-cyclic-v2\x00");
    hash.update(CPU.air.bundle_sha256);
    hash.update(&.{@intFromEnum(component)});
    hash.update(@embedFile("hybrid_air.zig"));
    hash.update(@embedFile("tuples.zig"));
    var program = try builder.finish(hash.finalResult(), roots.items);
    errdefer program.deinit();
    const slots = try a.alloc(u32, program.parameters.len);
    errdefer a.free(slots);
    for (slots, program.parameters) |*slot, v| {
        const words = v.toM31Array();
        if (words[0].v == 0) return error.InvalidHybridParameterSlot;
        for (words[1..]) |w| if (!w.isZero()) return error.InvalidHybridParameterSlot;
        slot.* = words[0].v - 1;
    }
    const out = Artifact{ .a = a, .component = component, .program = program, .parameter_slots = slots, .source_parameter_count = count, .main_constraints = main_count };
    try out.validate();
    return out;
}
