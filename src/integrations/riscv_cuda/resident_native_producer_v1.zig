//! Finite raw-retirement witness and physical-interaction producer. Input
//! dependent classification, row construction, counters, fractions, means and
//! prefixes remain device-side. PCS/transcript authority stays with the
//! independent original-native controller; this object is not a proof token.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Program = @import("resident_native_program_v1.zig");
const Ingress = @import("resident_native_ingress_v1.zig");
const Access = @import("resident_native_access_interaction_v1.zig");
const Projection = @import("resident_native_projection_interaction_v1.zig");
const Domain = @import("../../frontends/riscv/air/lang/relation.zig").Domain;
const Tables = @import("../../frontends/riscv/air/lookups/tables/schema.zig");
const Integer = @import("../../frontends/riscv/prover/block_execution_integer_bridge_v2.zig");
pub const FIRST_ID: u32 = (1 << 28) + 69632;
pub const ACCESS_ORIGINAL_ORDER = [_]usize{ 0, 9, 1, 2, 3, 4, 5, 6, 7, 8 };
pub const Slot = enum(u32) { main, witness, interaction, fractions, streams, terms, scan, output, parameters, claims };
pub const Limits = struct { max_extra_bytes: usize = 8 << 30, max_rows: u32 = 1 << 24 };
extern fn stwo_cuda_native_witness_v1_launch(u32, [*]const u32, [*]const u32, u32, u32, u32, [*]u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_infra_fixed_on([*]u32, [*]u32, u32, u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_infra_clock_on([*]const u32, [*]u32, u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_infra_frame_on([*]u32, u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_main_place_on([*]const u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_native_access_witness_on(u32, [*]const u32, [*]u32, u32, u64, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_access_count_on(u32, [*]const u32, [*]const u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_access_parameters_on([*]const u32, u32, u64, ?[*]const u32, u32, [*]u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_projection_parameters_on([*]const u32, u32, u32, ?[*]const u32, u32, [*]u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_projection_interactions_on([*]const u32, [*]u32, [*]u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_native_access_interactions_on([*]const u32, [*]u32, [*]u32, [*]u32, [*]u32, [*]u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_native_code_identity([*]u8) void;
extern fn stwo_native_program_on(u32, u32, ?[*]const u32, [*]const u32, ?[*]const u32, ?[*]const u32, ?[*]const u32, ?[*]const u64, ?[*]const u32, [*]u32, u32, u32, ?[*]const u32, u32, ?*anyopaque) c_int;
extern fn stwo_native_table_counts_on(u32, [*]const u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
fn table(domain: Domain) ?Tables.Kind {
    return switch (domain) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        else => null,
    };
}
fn rows(log: u32) usize {
    return @as(usize, 1) << @intCast(log);
}
pub fn ForCommitments(comptime N: usize) type {
    return struct {
        const P = Program.ForCommitments(N);
        pub const Views = struct {
            raw: common.Words,
            /// Exact original trace-tree ordinals, excluding composition.
            sources: [N - 1][]const common.Words,
            /// Device-derived original epoch106 Q outputs, not host challenge data.
            draws: common.Words,
            claims: common.Words,
            error_flag: common.Words,
            /// Canonical table-row order. Controller zeros these once per ledger.
            table_counters: [6]common.Words,
        };
        pub const Plan = struct {
            program: *const P.Owned,
            ingress: Ingress.Plan,
            limits: Limits,
            requirements: [6 + std.meta.fields(Slot).len]cuda.runtime.arena.Requirement,
            family_first: [17]usize,
            base_clock: u64,
            extra_bytes: usize,
            raw_words: usize,
            clock_rows: usize,
            pub fn init(p: *const P.Owned, limits: Limits) !Plan {
                const data = p.view();
                const shape = data.profile.pin.shape;
                if (limits.max_extra_bytes == 0 or limits.max_rows < 2 or limits.max_rows > (1 << 24)) return error.InvalidNativeProducerLimit;
                if (shape.localZeroCustody()) return error.UnsupportedNativeProducerWitness;
                var counts: [17]u32 = @splat(0);
                var max_main: usize = 1;
                var max_rows: usize = 2;
                for (shape.component_descs[0..shape.n_components]) |desc| {
                    if (rows(desc.log_size) > limits.max_rows) return error.NativeProducerResourceLimit;
                    counts[@intFromEnum(desc.family)] = try std.math.add(u32, counts[@intFromEnum(desc.family)], desc.n_rows);
                    max_rows = @max(max_rows, rows(desc.log_size));
                    max_main = @max(max_main, desc.n_columns * rows(desc.log_size));
                }
                var clock_rows: usize = 0;
                for (shape.infra_descs[0..shape.n_infra]) |desc| {
                    if (desc.kind != .clock_update or desc.n_columns != 10) return error.UnsupportedNativeProducerWitness;
                    if (rows(desc.log_size) > limits.max_rows) return error.NativeProducerResourceLimit;
                    clock_rows = try std.math.add(usize, clock_rows, desc.n_rows);
                    max_rows = @max(max_rows, rows(desc.log_size));
                    max_main = @max(max_main, 10 * rows(desc.log_size));
                }
                if (shape.n_components == 0 and shape.n_infra == 0) {
                    _ = try @import("../../frontends/riscv/prover/block_v5_native_frame_v1.zig").expected(shape, data.profile.pin.template.external_retirements);
                    max_rows = 4;
                    max_main = 16;
                }
                const ingress = try Ingress.Plan.init(counts, limits.max_extra_bytes);
                var first: [17]usize = undefined;
                var at: usize = 0;
                for (counts, &first) |n, *f| {
                    f.* = at;
                    at += n;
                }
                var sizes: [std.meta.fields(Slot).len]usize = .{ max_main, 48 * max_rows, 49 * max_rows, 72 * max_rows, 10 * (4 * max_rows + 4), 12 * max_rows, 4 * ((max_rows + 255) / 256), 49 * max_rows + 4, 164, 40 };
                var requirements: [6 + std.meta.fields(Slot).len]cuda.runtime.arena.Requirement = undefined;
                @memcpy(requirements[0..6], &ingress.requirements());
                var bytes = ingress.total_bytes;
                for (&sizes, requirements[6..], 0..) |*size, *r, i| {
                    size.* = @max(1, size.*);
                    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, size.*, 4));
                    r.* = .{ .id = FIRST_ID + @as(u32, @intCast(i)), .words = size.*, .alignment_words = 64, .live_from = .trace_generation, .live_through = .constraint_evaluation };
                }
                if (bytes > limits.max_extra_bytes) return error.NativeProducerResourceLimit;
                return .{ .program = p, .ingress = ingress, .limits = limits, .requirements = requirements, .family_first = first, .base_clock = try Integer.baseClockFromPublicFrame(data.profile.pin.frame), .extra_bytes = bytes, .clock_rows = clock_rows, .raw_words = try std.math.add(usize, 24 * @as(usize, ingress.rows), try std.math.mul(usize, 5, clock_rows)) };
            }
        };
        pub const Bound = struct {
            plan: *const Plan,
            ingress: Ingress.Bound,
            slots: [std.meta.fields(Slot).len]common.Words,
            primed: bool = false,
            witnessed: bool = false,
            interacted: bool = false,
            pub fn init(plan: *const Plan, tx: anytype) !Bound {
                var actual: [32]u8 = undefined;
                stwo_native_code_identity(&actual);
                if (!std.mem.eql(u8, &actual, &plan.program.view().code_identity)) return error.WrongNativeProgramLibrary;
                var out: Bound = .{ .plan = plan, .ingress = try Ingress.Bound.init(&plan.ingress, tx), .slots = undefined };
                for (&out.slots, plan.requirements[6..]) |*view, r| {
                    view.* = try tx.slot(r.id);
                    if (view.len != r.words) return error.InvalidNativeProducerBinding;
                }
                return out;
            }
            fn slot(self: *const Bound, which: Slot) common.Words {
                return self.slots[@intFromEnum(which)];
            }
            fn validate(self: *const Bound, v: *const Views) !void {
                const data = self.plan.program.view();
                if (v.raw.len != self.plan.raw_words or v.draws.len != 424 or v.claims.len != 4 * data.physical_claim_count or v.error_flag.len != 1) return error.InvalidNativeProducerBinding;
                for (v.sources, data.trees[0 .. N - 1]) |columns, t| {
                    if (columns.len != t.base_logs.len) return error.InvalidNativeProducerBinding;
                    for (columns, t.base_logs) |c, log| if (c.len != rows(log)) return error.InvalidNativeProducerBinding;
                }
                for (v.table_counters, 0..) |c, i| if (c.len != Tables.size(@enumFromInt(i))) return error.InvalidNativeProducerBinding;
            }
            pub fn prime(self: *Bound, session: anytype) !void {
                if (self.primed) return error.InvalidNativeProducerState;
                try self.ingress.prime(session);
                self.primed = true;
            }
            fn gather(self: *Bound, session: anytype, source: []const common.Words, target: Slot, n: usize) !void {
                if (source.len * n > self.slot(target).len) return error.InvalidNativeProducerBinding;
                for (source, 0..) |col, i| {
                    if (col.len != n) return error.InvalidNativeProducerBinding;
                    try session.context.copyDeviceSlice(u32, try self.slot(target).sub(i * n, n), col);
                }
            }
            pub fn witness(self: *Bound, session: anytype, v: *const Views) !void {
                if (!self.primed or self.witnessed) return error.InvalidNativeProducerState;
                try self.validate(v);
                try common.requireStage(session, .trace_generation);
                const indices = try self.ingress.execute(session, try v.raw.sub(0, 24 * @as(usize, self.plan.ingress.rows)), v.error_flag);
                const data = self.plan.program.view();
                var fixed_first: usize = 0;
                for (data.profile.pin.shape.component_descs[0..data.profile.pin.shape.n_components]) |desc| {
                    try common.record(session, .trace_generation, stwo_native_infra_fixed_on(try ptr(session, v.sources[0][fixed_first]), try ptr(session, v.sources[0][fixed_first + 1]), @intCast(rows(desc.log_size)), desc.n_rows, 0, try ptr(session, v.error_flag), session.context.stream));
                    fixed_first += 2;
                }
                for (data.profile.pin.shape.infra_descs[0..data.profile.pin.shape.n_infra]) |desc| {
                    try common.record(session, .trace_generation, stwo_native_infra_fixed_on(try ptr(session, v.sources[0][fixed_first]), try ptr(session, v.sources[0][fixed_first + 1]), @intCast(rows(desc.log_size)), desc.n_rows, 0, try ptr(session, v.error_flag), session.context.stream));
                    fixed_first += 2;
                }
                if (fixed_first == 0) {
                    if (v.sources[0].len != 1) return error.InvalidNativeProducerBinding;
                    try common.record(session, .trace_generation, stwo_native_infra_fixed_on(try ptr(session, v.sources[0][0]), try ptr(session, v.sources[0][0]), 4, 4, 1, try ptr(session, v.error_flag), session.context.stream));
                    fixed_first = 1;
                }
                if (fixed_first != v.sources[0].len) return error.InvalidNativeProducerBinding;
                var used: [17]usize = @splat(0);
                var main_first: usize = 0;
                for (data.profile.pin.shape.component_descs[0..data.profile.pin.shape.n_components]) |desc| {
                    const n = rows(desc.log_size);
                    const family = @intFromEnum(desc.family);
                    const selected = try indices.sub(self.plan.family_first[family] + used[family], desc.n_rows);
                    used[family] += desc.n_rows;
                    try common.record(session, .trace_generation, stwo_cuda_native_witness_v1_launch(@intCast(family), try ptr(session, v.raw), try ptr(session, selected), self.plan.ingress.rows, desc.n_rows, @intCast(n), try ptr(session, self.slot(.main)), try ptr(session, v.error_flag), session.context.stream));
                    for (v.sources[1][main_first..][0..desc.n_columns], 0..) |col, i| try common.record(session, .trace_generation, stwo_native_main_place_on(try ptr(session, try self.slot(.main).sub(i * n, n)), try ptr(session, col), @intCast(n), session.context.stream));
                    main_first += desc.n_columns;
                }
                var clock_first: usize = 0;
                for (data.profile.pin.shape.infra_descs[0..data.profile.pin.shape.n_infra]) |desc| {
                    const n = rows(desc.log_size);
                    const raw = try v.raw.sub(24 * @as(usize, self.plan.ingress.rows) + 5 * clock_first, 5 * @as(usize, desc.n_rows));
                    try common.record(session, .trace_generation, stwo_native_infra_clock_on(try ptr(session, raw), try ptr(session, self.slot(.main)), desc.n_rows, @intCast(n), try ptr(session, v.error_flag), session.context.stream));
                    for (v.sources[1][main_first..][0..10], 0..) |col, i| try session.context.copyDeviceSlice(u32, col, try self.slot(.main).sub(i * n, n));
                    clock_first += desc.n_rows;
                    main_first += 10;
                }
                for (data.components, 0..) |c, i| switch (c.kind) {
                    .projection => {
                        const domain = @import("resident_native_projection_program_v1.zig").domain(c.program.projection.fractions.slot);
                        if (table(domain)) |kind| {
                            const n = rows(c.trace_log);
                            try self.gather(session, v.sources[1][c.main_first..][0..c.main_width], .main, n);
                            try common.record(session, .trace_generation, stwo_native_table_counts_on(@intCast(i), try ptr(session, self.slot(.main)), try ptr(session, v.table_counters[@intFromEnum(kind)]), @intCast(n), try ptr(session, v.error_flag), session.context.stream));
                        }
                    },
                    .access => {
                        if (N != 5) return error.InvalidNativeProducerBinding;
                        const n = rows(c.trace_log);
                        try self.gather(session, v.sources[1][c.main_first..][0..c.main_width], .main, n);
                        try common.record(session, .trace_generation, stwo_native_access_witness_on(@intCast(c.slot.?), try ptr(session, self.slot(.main)), try ptr(session, self.slot(.witness)), @intCast(n), self.plan.base_clock, try ptr(session, v.error_flag), session.context.stream));
                        for (v.sources[2][c.witness_first.?..][0..48], 0..) |col, j| try session.context.copyDeviceSlice(u32, col, try self.slot(.witness).sub(j * n, n));
                        try common.record(session, .trace_generation, stwo_native_access_count_on(@intCast(c.slot.?), try ptr(session, self.slot(.main)), try ptr(session, self.slot(.witness)), try ptr(session, v.table_counters[@intFromEnum(Tables.Kind.range_check_8_8)]), @intCast(n), try ptr(session, v.error_flag), session.context.stream));
                    },
                    .opcode, .clock => {},
                    .frame => {
                        try common.record(session, .trace_generation, stwo_native_infra_frame_on(try ptr(session, self.slot(.main)), data.profile.pin.shape.total_steps, data.profile.pin.template.external_retirements, try ptr(session, v.error_flag), session.context.stream));
                        for (v.sources[1][c.main_first..][0..4], 0..) |col, j| try session.context.copyDeviceSlice(u32, col, try self.slot(.main).sub(j * 4, 4));
                    },
                };
                self.witnessed = true;
            }
            pub fn interactions(self: *Bound, session: anytype, v: *const Views) !void {
                if (!self.witnessed or self.interacted) return error.InvalidNativeProducerState;
                try self.validate(v);
                try common.requireStage(session, .trace_commit);
                for (self.plan.program.view().components, 0..) |c, i| {
                    if (c.kind == .frame) {
                        try session.zeroResidentSlice(u32, .trace_commit, v.sources[N - 2][c.interaction_first.?]);
                        continue;
                    }
                    if (c.kind != .projection and c.kind != .access) continue;
                    const n = rows(c.trace_log);
                    try self.gather(session, v.sources[1][c.main_first..][0..c.main_width], .main, n);
                    if (c.kind == .access) {
                        try self.gather(session, v.sources[2][c.witness_first.?..][0..48], .witness, n);
                        try common.record(session, .trace_commit, stwo_native_access_parameters_on(try ptr(session, v.draws), 416, self.plan.base_clock, null, @intCast(n), try ptr(session, self.slot(.parameters)), try ptr(session, v.error_flag), session.context.stream));
                    } else try common.record(session, .trace_commit, stwo_native_projection_parameters_on(try ptr(session, v.draws), 424, @intFromEnum(@import("resident_native_projection_program_v1.zig").domain(c.program.projection.fractions.slot)), null, @intCast(n), try ptr(session, self.slot(.parameters)), try ptr(session, v.error_flag), session.context.stream));
                    // Original phase graphs retain unused current/previous inputs;
                    // initialize their device storage instead of relying on compiler DCE.
                    try session.zeroResidentSlice(u32, .trace_commit, try self.slot(.interaction).sub(0, 49 * n));
                    try common.record(session, .trace_commit, stwo_native_program_on(@intCast(i), 0, null, try ptr(session, self.slot(.main)), try ptr(session, self.slot(.witness)), try ptr(session, self.slot(.interaction)), try ptr(session, self.slot(.parameters)), null, null, try ptr(session, self.slot(.fractions)), @intCast(n), @intCast(n), null, 1, session.context.stream));
                    if (c.kind == .projection) {
                        try common.record(session, .trace_commit, stwo_native_projection_interactions_on(try ptr(session, self.slot(.fractions)), try ptr(session, self.slot(.output)), try ptr(session, self.slot(.scan)), try ptr(session, v.error_flag), @intCast(n), session.context.stream));
                        for (v.sources[N - 2][c.interaction_first.?..][0..4], 0..) |col, j| try session.context.copyDeviceSlice(u32, col, try self.slot(.output).sub(j * n, n));
                        try session.context.copyDeviceSlice(u32, try v.claims.sub(4 * c.physical_claim_first, 4), try self.slot(.output).sub(4 * n, 4));
                    } else {
                        try common.record(session, .trace_commit, stwo_native_access_interactions_on(try ptr(session, self.slot(.fractions)), try ptr(session, self.slot(.streams)), try ptr(session, self.slot(.terms)), try ptr(session, self.slot(.scan)), try ptr(session, self.slot(.output)), try ptr(session, self.slot(.claims)), try ptr(session, v.error_flag), @intCast(n), session.context.stream));
                        for (v.sources[N - 2][c.interaction_first.?..][0..49], 0..) |col, j| try session.context.copyDeviceSlice(u32, col, try self.slot(.output).sub(j * n, n));
                        for (ACCESS_ORIGINAL_ORDER, 0..) |source, j| try session.context.copyDeviceSlice(u32, try v.claims.sub(4 * (c.physical_claim_first + j), 4), try self.slot(.claims).sub(4 * source, 4));
                    }
                }
                self.interacted = true;
            }
        };
    };
}
fn ptr(s: anytype, w: common.Words) ![*]u32 {
    return s.context.deviceSlicePointer(u32, w, w.len);
}
fn force4(b: *ForCommitments(4).Bound, s: *cuda.runtime.NativeSession, v: *const ForCommitments(4).Views) !void {
    try b.prime(s);
    try b.witness(s, v);
    try b.interactions(s, v);
}
fn force5(b: *ForCommitments(5).Bound, s: *cuda.runtime.NativeSession, v: *const ForCommitments(5).Views) !void {
    try b.prime(s);
    try b.witness(s, v);
    try b.interactions(s, v);
}
test "resident native producer original four five tree paths compile without host witness" {
    _ = &force4;
    _ = &force5;
}

fn forcePlan4(p: *const Program.ForCommitments(4).Owned) !ForCommitments(4).Plan {
    return ForCommitments(4).Plan.init(p, .{});
}
fn forcePlan5(p: *const Program.ForCommitments(5).Owned) !ForCommitments(5).Plan {
    return ForCommitments(5).Plan.init(p, .{});
}
test "resident native producer constructors are compiled" {
    _ = &forcePlan4;
    _ = &forcePlan5;
}
