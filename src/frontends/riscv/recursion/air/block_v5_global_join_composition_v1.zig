//! OPEN global accounting graph. Every selected claim is reconstructed from
//! original child transcript byte cells. This does not establish that the
//! selected claims cover the complete block, or authenticate endpoint sources.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const Join = @import("../../prover/block_v5_global_join_algebra_v1.zig");
const Schema = @import("../../air/lookups/tables/schema.zig");
const Frames = @import("../block_v5_heterogeneous_child_frames_v1.zig");
const Coverage = @import("../../prover/block_v5_recursive_coverage_plan_v1.zig");
const Bus = @import("../block_v5_heterogeneous_public_bus_v1.zig");
pub const VERSION: u32 = 1;
pub const CIRCUIT: u32 = 4_200_013;
pub const Source = @import("block_v5_heterogeneous_pairing_v1.zig").Source;
pub const Sum = []const u32;
pub const Ref = struct { child: u32, kind: Coverage.Kind, index: u32, frame: u32, felt: u32 };
pub const Scope = struct { index: u32, terms: Sum };
pub const Request = struct { execution: u32, claims: [Schema.KIND_COUNT]Sum, byte_part: u32 };
pub const Lookup = struct { index: u32, supply: [Schema.KIND_COUNT]Sum, requests: []const Request };
pub const Plan = struct {
    refs: []const Ref,
    states: []const Scope,
    registers: []const Scope,
    register_custody_mode: u32,
    lookup: []const Lookup,
    byte_parts: []const Sum,
    transition_requests: Sum,
    transition_provider: Sum,
    program_requests: []const Sum,
    program_provider: Sum,
    accounting: Join.Accounting(Sum),
    pub fn identity(self: Plan) ![32]u8 {
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x4235474a, VERSION, self.register_custody_mode });
        c.mixRoot(sourceIdentity());
        c.mixU64(self.refs.len);
        for (self.refs) |ref| c.mixU32s(&.{ ref.child, @intFromEnum(ref.kind), ref.index, ref.frame, ref.felt });
        inline for (.{ self.states, self.registers }) |scopes| {
            c.mixU64(scopes.len);
            for (scopes) |scope| {
                c.mixU32s(&.{scope.index});
                mixSum(&c, scope.terms);
            }
        }
        c.mixU64(self.lookup.len);
        for (self.lookup) |group| {
            c.mixU32s(&.{group.index});
            for (group.supply) |sum| mixSum(&c, sum);
            c.mixU64(group.requests.len);
            for (group.requests) |request| {
                c.mixU32s(&.{ request.execution, request.byte_part });
                for (request.claims) |sum| mixSum(&c, sum);
            }
        }
        inline for (.{ self.byte_parts, self.program_requests }) |parts| {
            c.mixU64(parts.len);
            for (parts) |sum| mixSum(&c, sum);
        }
        mixSum(&c, self.transition_requests);
        mixSum(&c, self.transition_provider);
        mixSum(&c, self.program_provider);
        inline for (std.meta.fields(@TypeOf(self.accounting))) |field| mixSum(&c, @field(self.accounting, field.name));
        return c.digestBytes();
    }
};
fn mixSum(c: anytype, sum: Sum) void {
    c.mixU64(sum.len);
    c.mixU32s(sum);
}
pub fn sourceIdentity() [32]u8 {
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x42354753, VERSION });
    inline for (.{ @embedFile("../../prover/block_v5_global_join_algebra_v1.zig"), @embedFile("block_v5_global_join_composition_v1.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        c.mixRoot(digest);
    }
    return c.digestBytes();
}
pub const Limits = struct { max_refs: usize = 65_536, max_scopes: usize = 65_536, max_terms: usize = 1_048_576, max_preparation_bytes: usize = 256 << 20 };
/// Independent pin of the coordinate mapping; never read it from proof bytes.
/// Even when valid, endpoint/source proofs and semantic completeness remain open.
pub const MappingPin = struct { plan: [32]u8, coverage: [32]u8, source_seal: [32]u8 };
pub const Prepared = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    allocator: std.mem.Allocator,
    circuit: R.Circuit,
    inputs: []Q,
    sources: []Source,
    values: []Q,
    mapping: MappingPin,
    pub const aggregate_coverage_pending = true;
    pub const endpoint_source_authority_pending = true;
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.allocator.free(self.inputs);
        self.allocator.free(self.sources);
        self.allocator.free(self.values);
        self.budget.destroy();
        self.* = undefined;
    }
    /// Used by the same parent's arithmetic input supply, not a host receipt.
    pub fn publicWires(self: *const Prepared, a: std.mem.Allocator, circuit_id: u32) ![]Bus.Wire {
        if (circuit_id == 0 or circuit_id >= core.fields.m31.Modulus) return error.InvalidGlobalJoinMapping;
        const counts = try a.alloc(u32, self.circuit.nodes.len);
        defer a.free(counts);
        const uses = try @import("verifier_arithmetic_lowering.zig").computeUseCountsInto(self.circuit.graph(), counts);
        var out: std.ArrayList(Bus.Wire) = .empty;
        errdefer out.deinit(a);
        for (self.sources, 0..) |source, node| if (uses[node] != 0) try out.append(a, .{
            .circuit = circuit_id,
            .wire = @intCast(node),
            .uses = uses[node],
            .child = source.child,
            .kind = .pairing_coordinate,
            .coordinate = source.cell,
            .part = source.part,
        });
        return out.toOwnedSlice(a);
    }
};
const Statement = struct { kind: Coverage.Kind, index: u32, source_seal: [32]u8, frames: []const Frames.Frame, cells: []const [4]M };
pub fn prepare(backing: std.mem.Allocator, children: []const Frames.Child, plan: Plan, pin: MappingPin, limits: Limits) !Prepared {
    // This scope binds mapping only. Caller must separately authenticate each
    // original child verifier in the enclosing heterogeneous parent.
    if (children.len == 0 or children.len > Bus.MAX_CHILDREN) return error.GlobalJoinResourceLimit;
    try validatePlan(plan, limits);
    const views = try backing.alloc(Statement, children.len);
    defer backing.free(views);
    for (children, views) |*child, *view| {
        try child.validate();
        view.* = .{ .kind = child.physical.kind, .index = child.physical.index, .source_seal = child.source_seal, .frames = child.frames, .cells = child.cells };
    }
    return record(backing, views, plan, pin, limits);
}
fn record(backing: std.mem.Allocator, children: []const Statement, plan: Plan, pin: MappingPin, limits: Limits) !Prepared {
    try validatePlan(plan, limits);
    if (limits.max_preparation_bytes == 0 or std.mem.allEqual(u8, &pin.coverage, 0) or std.mem.allEqual(u8, &pin.source_seal, 0) or !std.meta.eql(try plan.identity(), pin.plan)) return error.InvalidGlobalJoinMapping;
    if (children.len == 0 or children.len > Bus.MAX_CHILDREN) return error.GlobalJoinResourceLimit;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_preparation_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const count = try std.math.mul(usize, plan.refs.len, 16);
    const inputs = try a.alloc(Q, count);
    errdefer a.free(inputs);
    const sources = try a.alloc(Source, count);
    errdefer a.free(sources);
    const raw = try a.alloc(R.Scalar, count);
    defer a.free(raw);
    const claims = try a.alloc(R.Scalar, plan.refs.len);
    defer a.free(claims);
    for (plan.refs, 0..) |ref, ordinal| {
        if (ref.child >= children.len) return error.InvalidGlobalJoinMapping;
        const child = children[ref.child];
        if (child.cells.len > Frames.LIMIT) return error.GlobalJoinResourceLimit;
        if (child.kind != ref.kind or child.index != ref.index or !std.meta.eql(child.source_seal, pin.source_seal) or ref.frame >= child.frames.len) return error.InvalidGlobalJoinMapping;
        const frame = child.frames[ref.frame];
        const selected_felts = switch (frame.operation) {
            .felts => |payload| payload,
            else => return error.InvalidGlobalJoinClaimFrame,
        };
        if (ref.felt >= selected_felts.len) return error.InvalidGlobalJoinClaimFrame;
        const first = try std.math.add(usize, frame.first, try std.math.mul(usize, ref.felt, 4));
        if (first > child.cells.len or child.cells.len - first < 4) return error.InvalidGlobalJoinClaimFrame;
        for (selected_felts[ref.felt].toM31Array(), 0..) |word, component| {
            if (word.v >= core.fields.m31.Modulus) return error.NoncanonicalGlobalJoinInput;
            for (0..4) |part| {
                const value = child.cells[first + component][part];
                if (value.v != ((word.v >> @as(u5, @intCast(8 * part))) & 255)) return error.MutatedGlobalJoinStatement;
                const at = 16 * ordinal + 4 * component + part;
                inputs[at] = Q.fromBase(value);
                sources[at] = .{ .child = ref.child, .cell = @intCast(first + component), .part = @intCast(part) };
                raw[at] = (try builder.input()).value;
            }
        }
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    for (claims, 0..) |*claim, ordinal| {
        claim.* = R.Scalar.zero();
        for (0..4) |component| {
            var basis: [4]M = @splat(M.zero());
            basis[component] = M.one();
            for (0..4) |part| {
                const weight = Q.fromM31Array(basis).mul(Q.fromBase(M.fromU64(@as(u64, 1) << @as(u6, @intCast(8 * part)))));
                claim.* = claim.add(raw[16 * ordinal + 4 * component + part].mul(R.Scalar.fromSecure(weight)));
            }
        }
    }
    var sink = Sink{ .builder = &builder };
    try equations(R.Scalar, a, &sink, plan, claims);
    if (builder.failure) |err| return err;
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    errdefer a.free(values);
    try circuit.evaluateInto(inputs, values);
    return .{ .budget = budget, .allocator = a, .circuit = circuit, .inputs = inputs, .sources = sources, .values = values, .mapping = pin };
}
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        if (self.builder.failure) |err| return err;
        try self.builder.constrainZero(value);
    }
};
fn total(comptime S: type, refs: Sum, claims: []const S) S {
    var value = S.zero();
    for (refs) |ref| value = value.add(claims[ref]);
    return value;
}
pub fn equations(comptime S: type, a: std.mem.Allocator, sink: anytype, plan: Plan, claims: []const S) !void {
    if (claims.len != plan.refs.len) return error.InvalidGlobalJoinMapping;
    try validatePlan(plan, .{ .max_refs = std.math.maxInt(usize), .max_scopes = std.math.maxInt(usize), .max_terms = std.math.maxInt(usize) });
    const A = Join.Algebra(S);
    const states = try a.alloc(S, plan.states.len);
    defer a.free(states);
    for (plan.states, states) |scope, *value| value.* = total(S, scope.terms, claims);
    try A.states(sink, states);
    const registers = try a.alloc(S, plan.registers.len);
    defer a.free(registers);
    for (plan.registers, registers) |scope, *value| value.* = total(S, scope.terms, claims);
    try A.registers(sink, plan.register_custody_mode, registers);
    const Part = struct { sum: S };
    const bytes = try a.alloc(Part, plan.byte_parts.len);
    defer a.free(bytes);
    for (plan.byte_parts, bytes) |refs, *part| part.* = .{ .sum = total(S, refs, claims) };
    for (plan.lookup) |group| {
        var supply: A.TableClaims = undefined;
        for (group.supply, &supply) |refs, *value| value.* = total(S, refs, claims);
        const requests = try a.alloc(A.TableClaims, group.requests.len);
        defer a.free(requests);
        const parts = try a.alloc(Part, group.requests.len);
        defer a.free(parts);
        for (group.requests, requests, parts) |request, *values, *part| {
            for (request.claims, values) |refs, *value| value.* = total(S, refs, claims);
            part.* = bytes[request.byte_part];
        }
        _ = try A.lookupGroup(sink, supply, requests, parts);
    }
    try A.transition(sink, total(S, plan.transition_requests, claims), total(S, plan.transition_provider, claims));
    const Program = struct { claim: S };
    const programs = try a.alloc(Program, plan.program_requests.len);
    defer a.free(programs);
    for (plan.program_requests, programs) |refs, *request| request.* = .{ .claim = total(S, refs, claims) };
    try A.program(sink, total(S, plan.program_provider, claims), programs);
    var accounting: Join.Accounting(S) = undefined;
    inline for (std.meta.fields(@TypeOf(accounting))) |field| {
        @field(accounting, field.name) = total(S, @field(plan.accounting, field.name), claims);
    }
    try A.accounting(sink, accounting, bytes);
}
fn validatePlan(plan: Plan, limits: Limits) !void {
    if (plan.refs.len == 0 or plan.register_custody_mode > 1) return error.InvalidGlobalJoinMapping;
    if (plan.refs.len > limits.max_refs) return error.GlobalJoinResourceLimit;
    var scopes: usize = 0;
    var terms: usize = 0;
    inline for (.{ plan.states, plan.registers }) |groups| {
        scopes = try std.math.add(usize, scopes, groups.len);
        for (groups, 0..) |scope, index| {
            if (scope.index != index) return error.InvalidGlobalJoinScope;
            try validateSum(scope.terms, plan.refs.len, &terms);
        }
    }
    scopes = try std.math.add(usize, scopes, plan.lookup.len);
    var executions: usize = 0;
    for (plan.lookup, 0..) |group, index| {
        if (group.index != index) return error.InvalidGlobalJoinScope;
        for (group.supply) |sum| try validateSum(sum, plan.refs.len, &terms);
        for (group.requests) |request| {
            if (request.execution != executions or request.byte_part != executions or request.byte_part >= plan.byte_parts.len) return error.InvalidGlobalJoinBytePartition;
            executions += 1;
            for (request.claims) |sum| try validateSum(sum, plan.refs.len, &terms);
        }
    }
    if (executions != plan.byte_parts.len) return error.InvalidGlobalJoinBytePartition;
    inline for (.{ plan.byte_parts, plan.program_requests }) |parts| for (parts) |sum| try validateSum(sum, plan.refs.len, &terms);
    inline for (.{ plan.transition_requests, plan.transition_provider, plan.program_provider }) |sum| try validateSum(sum, plan.refs.len, &terms);
    inline for (std.meta.fields(@TypeOf(plan.accounting))) |field| try validateSum(@field(plan.accounting, field.name), plan.refs.len, &terms);
    if (scopes > limits.max_scopes or terms > limits.max_terms) return error.GlobalJoinResourceLimit;
}
fn validateSum(sum: Sum, refs: usize, terms: *usize) !void {
    terms.* = try std.math.add(usize, terms.*, sum.len);
    for (sum) |ref| if (ref >= refs) return error.InvalidGlobalJoinMapping;
}
pub const testing = if (@import("builtin").is_test) struct {
    pub const View = Statement;
    pub const recordViews = record;
    pub const validate = validatePlan;
} else struct {};
