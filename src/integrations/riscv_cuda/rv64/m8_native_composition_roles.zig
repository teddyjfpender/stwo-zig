//! Native composition roles for the M8 job producer (jobs/native_composition.zig),
//! built from the frontend authorities exactly as resident_composition.zig
//! Context.evaluateAtBlowup binds them (descriptor → case id → artifact,
//! parameter slots from real_composition.metadata, role geometry, hc
//! auxiliary columns). Lives outside rv64/jobs/ because it reads the legacy
//! composition Context's kernel metadata (owner-path imports are forbidden
//! under jobs/ by the sync lint). Pure host; no device access.
//!
//! Custody note (stated, not hidden): the parameters are host values here
//! (lookup challenges, eta, claims from the host items). Only the composition
//! coefficient and its powers are device-resident on this path.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const RC = @import("resident_composition.zig");
const Hybrid = @import("real_composition.zig");
const G = @import("joined_codegen.zig");
const NC = @import("jobs/native_composition.zig");
const Items = CPU.rv64_gkr_cpu_components;
const P = G.Parameters;
pub const TruthRoles = CPU.rv64_gkr_truth_device_composition.Roles;

pub const Roles = struct {
    a: std.mem.Allocator,
    specs: []NC.RoleSpec,
    /// Host values of every claim parameter, in ClaimSlot.claim order (the
    /// parity harness uploads them as the device claims buffer).
    claims: std.ArrayListUnmanaged(u32) = .empty,
    /// Backing storage of every spec's slices.
    words: std.ArrayListUnmanaged([]u32) = .empty,
    slots: std.ArrayListUnmanaged([]NC.ClaimSlot) = .empty,

    /// `device_claims`: claim parameters (P.claims..+2) are zeroed in the
    /// staged table and recorded as claim slots patched from device claims.
    pub fn fromItems(a: std.mem.Allocator, context: *const RC.Context, items: []const Items.Item) !Roles {
        return fromItemsWith(a, context, items, false);
    }
    pub fn fromItemsWith(a: std.mem.Allocator, context: *const RC.Context, items: []const Items.Item, device_claims: bool) !Roles {
        if (context.artifact_count != @import("joined_fixture_support.zig").count) return error.CpuCompositionNotInitialized;
        var self = Roles{ .a = a, .specs = try a.alloc(NC.RoleSpec, items.len) };
        errdefer self.deinit();
        for (items, self.specs) |*item, *spec| switch (item.*) {
            inline else => |*c| {
                const T = @TypeOf(c.*);
                const d = Hybrid.descriptor(T, c);
                const id = try Hybrid.caseId(d);
                const artifact = &context.artifacts[id];
                if (artifact.program.roots.len != c.nConstraints()) return error.WrongResidentConstraintCount;
                const metadata = Hybrid.metadata(T, c, d);
                const parameters = try self.own(artifact.parameter_slots.len * 8);
                for (artifact.parameter_slots, 0..) |slot, i| for (metadata[slot].toM31Array(), 0..) |w, j| {
                    parameters[8 * i + j] = w.v;
                };
                const masks = try self.own(artifact.program.inputs.len);
                for (artifact.program.inputs, masks) |input, *m| m.* = input.column;
                var claim_slots: []NC.ClaimSlot = &.{};
                if (device_claims) {
                    var n: usize = 0;
                    for (artifact.parameter_slots) |slot| n += @intFromBool(slot >= P.claims and slot < P.claims + 3);
                    claim_slots = try self.ownSlots(n);
                    var k: usize = 0;
                    for (artifact.parameter_slots, 0..) |slot, i| if (slot >= P.claims and slot < P.claims + 3) {
                        claim_slots[k] = .{ .parameter = @intCast(i), .claim = @intCast(self.claims.items.len / 8) };
                        try self.claims.appendSlice(a, parameters[8 * i ..][0..8]);
                        @memset(parameters[8 * i ..][0..8], 0);
                        k += 1;
                    };
                }
                const shape = c.mainShape();
                const offsets = c.columnOffsets();
                const trace_log: u32 = @intCast(G.Authority.RoleGeometry.logSize(c));
                spec.* = .{
                    .id = id,
                    .trace_log = trace_log,
                    .eval_log = @intCast(c.maxConstraintLogDegreeBound()),
                    .widths = .{ @intCast(shape.fixed), @intCast(shape.main), @intCast(G.Authority.RoleGeometry.interWidth(c)) },
                    .offsets = .{ @intCast(offsets[0]), @intCast(offsets[1]), @intCast(c.inter_offset) },
                    .parameters = parameters,
                    .mask_columns = masks,
                    .constraints = @intCast(artifact.program.roots.len),
                    .claim_slots = claim_slots,
                };
                if (comptime @hasField(T, "data")) {
                    const hc = try self.own(16 * trace_log);
                    for (0..2) |half| for (0..trace_log) |i| for ((if (half == 0) c.data.point.hc0[i] else c.data.point.hc1[i]).toM31Array(), 0..) |w, j| {
                        hc[(half * trace_log + i) * 8 + j] = w.v;
                    };
                    spec.aux = .hc;
                    spec.hc = hc;
                }
            },
        };
        return self;
    }
    /// Truth/service compositions (resident_composition.zig evaluateTruthAtBlowup
    /// + bindTruthRole): truth kernel, last-anchor auxiliary for classic roles.
    pub fn fromTruth(a: std.mem.Allocator, context: *const RC.Context, bound: TruthRoles) !Roles {
        const TC = @import("truth_codegen.zig");
        const count: usize = switch (bound) {
            .classic => |v| v.len,
            .delegated => 1,
        };
        var self = Roles{ .a = a, .specs = try a.alloc(NC.RoleSpec, count) };
        errdefer self.deinit();
        switch (bound) {
            .classic => |components| for (components, self.specs) |*c, *spec| {
                const id = try TC.classicKernelId(c.keccak_policy, c.kind);
                const w = c.widths();
                spec.* = try self.truthRole(context, id, @intCast(c.log_size), @intCast(c.maxConstraintLogDegreeBound()), .{ w[0], w[1], w[2] }, .{ c.offsets[0], c.offsets[1], c.offsets[2] }, TC.nativeMetadata(c), c.nConstraints(), true);
            },
            .delegated => |c| {
                const id: u32 = switch (c.truth.family()) {
                    .sha256 => 3,
                    .arith256_mod => 4,
                    .add => 5,
                    .double => 6,
                    .bn254_g1_add => 10,
                    .bn254_g1_double => 11,
                    .bn254_fp2_mul => 12,
                    .bls12_381_fp2_mul => 13,
                    .arith384_mont => 14,
                    else => return error.UnsupportedTruthCompositionRole,
                };
                const shape = c.mainShape();
                self.specs[0] = try self.truthRole(context, id, @intCast(c.logSize()), @intCast(c.maxConstraintLogDegreeBound()), .{ shape.fixed, shape.main, c.interWidth() }, .{ c.offsets[0], c.offsets[1], c.inter_offset }, TC.nativeMetadataV3(c), c.nConstraints(), false);
            },
        }
        return self;
    }
    fn truthRole(self: *Roles, context: *const RC.Context, id: u32, trace_log: u32, eval_log: u32, widths: [3]usize, offsets: [3]usize, metadata: anytype, constraints: usize, anchor: bool) !NC.RoleSpec {
        const artifact = &(context.truth_artifacts[id] orelse return error.TruthCompositionNotInitialized);
        if (artifact.program.roots.len != constraints) return error.WrongResidentConstraintCount;
        const parameters = try self.own(artifact.parameter_slots.len * 8);
        for (artifact.parameter_slots, 0..) |slot, i| for (metadata[slot].toM31Array(), 0..) |w, j| {
            parameters[8 * i + j] = w.v;
        };
        const masks = try self.own(artifact.program.inputs.len);
        for (artifact.program.inputs, masks) |input, *m| m.* = input.column;
        return .{
            .id = id,
            .kernel = .truth,
            .trace_log = trace_log,
            .eval_log = eval_log,
            .widths = .{ @intCast(widths[0]), @intCast(widths[1]), @intCast(widths[2]) },
            .offsets = .{ @intCast(offsets[0]), @intCast(offsets[1]), @intCast(offsets[2]) },
            .aux = if (anchor) .last else .none,
            .parameters = parameters,
            .mask_columns = masks,
            .constraints = @intCast(constraints),
        };
    }
    fn own(self: *Roles, words: usize) ![]u32 {
        const out = try self.a.alloc(u32, words);
        errdefer self.a.free(out);
        try self.words.append(self.a, out);
        return out;
    }
    fn ownSlots(self: *Roles, n: usize) ![]NC.ClaimSlot {
        const out = try self.a.alloc(NC.ClaimSlot, n);
        errdefer self.a.free(out);
        try self.slots.append(self.a, out);
        return out;
    }
    pub fn deinit(self: *Roles) void {
        for (self.words.items) |w| self.a.free(w);
        self.words.deinit(self.a);
        for (self.slots.items) |w| self.a.free(w);
        self.slots.deinit(self.a);
        self.claims.deinit(self.a);
        self.a.free(self.specs);
        self.* = undefined;
    }
};
