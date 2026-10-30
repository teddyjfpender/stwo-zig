//! Finite original V7 native source metadata. No witness, capture, challenge
//! material or successful receipt is accepted or emitted by this cold plan.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
pub const Profile = @import("../../frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Base = @import("../../frontends/riscv/prover/block_v6_partitioned_native_components_v1.zig");
const Fused = @import("../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v2.zig");
const Frame = @import("../../frontends/riscv/prover/block_v5_native_frame_v1.zig");
const Direct = @import("resident_native_direct_codegen_v1.zig");
const Projection = @import("resident_native_projection_program_v1.zig");
const Access = @import("resident_native_access_program_v1.zig");
const R = @import("../../frontends/riscv/recursion/air/composition_graph_recorder.zig");
const Field = @import("../../frontends/riscv/recursion/air/block_v6_partitioned_composition_v1.zig").Field;
const Sample = @import("../../frontends/riscv/recursion/sample_point_layout.zig");
pub const Limits = struct { max_components: usize = 1 << 16, max_trace_log: u32 = 25, max_polynomial_bytes: usize = 96 << 30 };
pub const Kind = enum { opcode, clock, frame, projection, access };
pub const Program = union(Kind) {
    opcode: engine.air.component_prover.OwnedBasePolynomialProgram,
    clock: R.Circuit,
    frame: R.Circuit,
    projection: struct { fractions: Projection.Owned, equation: Projection.Owned },
    access: struct { denominators: Access.Owned, equations: Access.Owned },
};
/// Access wire/public order is transition, universal, count, range0..6.
/// Device access streams use transition, count, range0..6, universal.
pub const ACCESS_PUBLIC_FROM_STREAM = [10]u8{ 0, 9, 1, 2, 3, 4, 5, 6, 7, 8 };
pub const Component = struct {
    kind: Kind,
    family: ?Trace.OpcodeFamily = null,
    slot: ?usize = null,
    physical_ordinal: usize = 0,
    trace_log: u32,
    main_first: usize,
    main_width: usize,
    fixed_selector: ?usize = null,
    witness_first: ?usize = null,
    interaction_first: ?usize = null,
    physical_claim_first: usize = 0,
    physical_claim_count: usize = 0,
    first_constraint: usize = 0,
    constraints: usize,
    intrinsic_evaluation_log: u32,
    evaluation_log: u32,
    composition_split: u32,
    extension_delta: u32,
    program: Program,
};
pub const TreeKind = enum { fixed, main, access_witness, interaction, composition };
pub const Tree = struct { ordinal: u32, kind: TreeKind, base_logs: []u32, layouts: []Sample.Layout, mask_logs: []u32, lifted_log: u32 };
pub const FriLayer = struct { evaluation_log: u32, fold_step: u32, cumulative_fold: u32, leaf_log: u32 };
pub fn ForCommitments(comptime N: usize) type {
    if (N != 4 and N != 5) @compileError("native commitment inventory is four or five");
    return struct {
        pub const commitment_count = N;
        pub const interaction_tree = N - 2;
        pub const composition_tree = N - 1;
        pub const witness_tree: ?usize = if (N == 5) 2 else null;
        pub const Data = struct {
            profile: *Profile.Owned,
            trees: [N]Tree,
            components: []Component,
            fri_layers: []FriLayer,
            composition_log: u32,
            composition_split: u32,
            mask_log: u32,
            fri_log: u32,
            constraints: usize,
            physical_claim_count: usize,
            polynomial_bytes: usize,
            identity: [32]u8,
            /// Exact emitted CUDA bodies; independent of epoch-only metadata.
            code_identity: [32]u8 = @splat(0),
        };
        const Storage = struct { backing: std.mem.Allocator, arena: std.heap.ArenaAllocator, data: Data };
        pub const Owned = opaque {
            pub fn init(backing: std.mem.Allocator, input: *const Profile.Owned, limits: Limits) !*Owned {
                if (limits.max_components == 0 or limits.max_trace_log < 1 or limits.max_trace_log > 28 or limits.max_polynomial_bytes == 0) return error.InvalidResidentNativeLimit;
                // This independent original metadata reconstruction owns the
                // statement/roster. Its internal shape probes never feed GPU FS.
                try input.validate();
                const profile = try Profile.Owned.derive(backing, input.pin, input.epoch, input.roster, input.limits);
                errdefer profile.deinit();
                if (profile.trace_count + 1 != N or profile.shape.columns.len != N or !std.mem.eql(u8, &profile.seal, &input.seal)) return error.InvalidResidentNativeInventory;
                const out = try backing.create(Storage);
                errdefer backing.destroy(out);
                out.backing = backing;
                out.arena = std.heap.ArenaAllocator.init(backing);
                errdefer out.arena.deinit();
                const a = out.arena.allocator();
                const shape = profile.pin.shape;
                const split = profile.shape.split;
                const base = try Base.Owner.init(a, shape, profile.pin.template.external_retirements);
                defer base.deinit();
                const count = try std.math.add(usize, base.verifiers.len, try std.math.add(usize, profile.projections.len, profile.slots.len));
                if (count > limits.max_components) return error.ResidentNativeResourceLimit;
                const components = try a.alloc(Component, count);
                var at: usize = 0;
                var main_first: usize = 0;
                if (Frame.required(shape)) {
                    if (N != 4 or profile.projections.len != 0 or profile.slots.len != 0) return error.InvalidResidentNativeInventory;
                    components[at] = .{ .kind = .frame, .trace_log = Frame.LOG_SIZE, .main_first = 0, .main_width = Frame.MAIN_COLUMNS, .fixed_selector = 0, .interaction_first = 0, .constraints = Frame.N_CONSTRAINTS, .intrinsic_evaluation_log = base.verifiers[0].maxConstraintLogDegreeBound(), .evaluation_log = 0, .composition_split = split, .extension_delta = split - base.verifiers[0].compositionLogSplit(), .program = .{ .frame = try frameProgram(a, try Frame.expected(shape, profile.pin.template.external_retirements)) } };
                    at += 1;
                } else {
                    for (shape.component_descs[0..shape.n_components], 0..) |desc, i| {
                        const p = try Direct.program(a, desc.family, shape.localZeroCustody());
                        if (p.column_count != desc.n_columns + 1 or p.roots.len != base.verifiers[i].nConstraints()) return error.InvalidResidentNativePrograms;
                        components[at] = .{ .kind = .opcode, .family = desc.family, .trace_log = desc.log_size, .main_first = main_first, .main_width = desc.n_columns, .fixed_selector = 2 * i + 1, .constraints = p.roots.len, .intrinsic_evaluation_log = base.verifiers[i].maxConstraintLogDegreeBound(), .evaluation_log = 0, .composition_split = split, .extension_delta = split - base.verifiers[i].compositionLogSplit(), .program = .{ .opcode = p } };
                        main_first += desc.n_columns;
                        at += 1;
                    }
                    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| {
                        if (desc.kind != .clock_update) return error.UnsupportedResidentNativeInfrastructure;
                        const index = shape.n_components + i;
                        components[at] = .{ .kind = .clock, .trace_log = desc.log_size, .main_first = main_first, .main_width = desc.n_columns, .fixed_selector = 2 * index + 1, .constraints = 3, .intrinsic_evaluation_log = base.verifiers[index].maxConstraintLogDegreeBound(), .evaluation_log = 0, .composition_split = split, .extension_delta = split - base.verifiers[index].compositionLogSplit(), .program = .{ .clock = try clockProgram(a) } };
                        main_first += desc.n_columns;
                        at += 1;
                    }
                }
                const projection_split = Fused.compositionSplit(profile.projections);
                if (profile.projections.len != 0 and projection_split != split) return error.InvalidResidentNativeGeometry;
                for (profile.projections, 0..) |slot, i| {
                    components[at] = .{ .kind = .projection, .family = switch (slot.kind) {
                        .program => |f| f,
                        .lookup => |l| switch (l.source) {
                            .opcode => |f| f,
                            .clock => null,
                        },
                    }, .slot = i, .physical_ordinal = i, .trace_log = slot.log_size, .main_first = slot.main_offset, .main_width = slot.width, .interaction_first = 4 * i, .physical_claim_first = i, .physical_claim_count = 1, .constraints = 1, .intrinsic_evaluation_log = slot.log_size + projection_split, .evaluation_log = 0, .composition_split = split, .extension_delta = 0, .program = .{ .projection = .{ .fractions = try Projection.Owned.init(a, slot, .fractions), .equation = try Projection.Owned.init(a, slot, .equation) } } };
                    at += 1;
                }
                for (profile.slots, 0..) |slot, i| {
                    if (N != 5 or slot.family != .load_store or (slot.slot != 1 and slot.slot != 2) or split < 2) return error.UnsupportedResidentNativeAccess;
                    components[at] = .{ .kind = .access, .family = slot.family, .slot = slot.slot, .physical_ordinal = i, .trace_log = slot.log_size, .main_first = slot.main_offset, .main_width = Trace.nColumnsForFamily(slot.family), .witness_first = 48 * i, .interaction_first = 4 * profile.projections.len + 49 * i, .physical_claim_first = profile.projections.len + 10 * i, .physical_claim_count = 10, .constraints = 68, .intrinsic_evaluation_log = slot.log_size + 2, .evaluation_log = 0, .composition_split = split, .extension_delta = split - 2, .program = .{ .access = .{ .denominators = try Access.Owned.init(a, @intCast(slot.slot), .denominators), .equations = try Access.Owned.init(a, @intCast(slot.slot), .equations) } } };
                    at += 1;
                }
                if (at != count) return error.InvalidResidentNativePrograms;
                var constraints: usize = 0;
                var max_evaluation: u32 = 0;
                for (components) |*c| {
                    if (c.trace_log > limits.max_trace_log) return error.ResidentNativeResourceLimit;
                    c.first_constraint = constraints;
                    constraints = try std.math.add(usize, constraints, c.constraints);
                    c.evaluation_log = c.intrinsic_evaluation_log + c.extension_delta;
                    max_evaluation = @max(max_evaluation, c.evaluation_log);
                }
                if (constraints != profile.constraint_count or max_evaluation != profile.shape.composition_log) return error.InvalidResidentNativeGeometry;
                var trees: [N]Tree = undefined;
                var cursor: usize = 0;
                var bytes: usize = 0;
                const blowup = profile.epoch.config.fri_config.log_blowup_factor;
                for (profile.shape.columns, &trees, 0..) |extended, *tree, index| {
                    const logs = try a.alloc(u32, extended.len);
                    const masks = try a.dupe(Sample.Layout, profile.shape.layouts[cursor..][0..extended.len]);
                    const steps = try a.alloc(u32, extended.len);
                    var lift: u32 = 0;
                    var words: usize = 0;
                    for (extended, logs, steps, 0..) |log, *base_log, *step, j| {
                        if (log < blowup or log > 30) return error.InvalidResidentNativeGeometry;
                        base_log.* = log - blowup;
                        step.* = if (profile.shape.mask_logs.len == 0) profile.shape.mask_log else profile.shape.mask_logs[cursor + j];
                        lift = @max(lift, log);
                        words = try std.math.add(usize, words, try std.math.add(usize, try pow(base_log.*), try pow(log)));
                    }
                    if (profile.epoch.config.lifting_log_size) |requested| lift = @max(lift, requested);
                    if (lift == 0 or lift > 30) return error.InvalidResidentNativeGeometry;
                    const hash_count = try std.math.sub(usize, try std.math.mul(usize, 2, try pow(lift)), 1);
                    bytes = try std.math.add(usize, bytes, try std.math.add(usize, try std.math.mul(usize, 4, words), try std.math.mul(usize, 32, hash_count)));
                    tree.* = .{ .ordinal = @intCast(index), .kind = if (index == 0) .fixed else if (index == 1) .main else if (index == N - 1) .composition else if (index == N - 2) .interaction else .access_witness, .base_logs = logs, .layouts = masks, .mask_logs = steps, .lifted_log = lift };
                    cursor += extended.len;
                }
                if (cursor != profile.shape.layouts.len or bytes > limits.max_polynomial_bytes) return error.ResidentNativeResourceLimit;
                const layers = try a.alloc(FriLayer, profile.shape.widths.len);
                var cumulative: u32 = 0;
                for (profile.shape.widths, layers, 0..) |width, *layer, i| {
                    if (width < 2 or !std.math.isPowerOfTwo(width)) return error.InvalidResidentNativeGeometry;
                    const fold = std.math.log2_int(u32, width);
                    const eval = profile.shape.lifting_log - cumulative;
                    const pack: u32 = if ((if (i == 0) profile.epoch.config.fri_config.fold_step else fold) > 1 and eval >= core.fri.LOG_PACKED_LEAF_SIZE) core.fri.LOG_PACKED_LEAF_SIZE else 0;
                    layer.* = .{ .evaluation_log = eval, .fold_step = fold, .cumulative_fold = cumulative, .leaf_log = eval - pack };
                    cumulative += fold;
                }
                out.data = .{ .profile = profile, .trees = trees, .components = components, .fri_layers = layers, .composition_log = profile.shape.composition_log, .composition_split = split, .mask_log = profile.shape.mask_log, .fri_log = profile.shape.lifting_log, .constraints = constraints, .physical_claim_count = profile.projections.len + 10 * profile.slots.len, .polynomial_bytes = bytes, .identity = try identity(a, profile.seal, components) };
                out.data.code_identity = try @import("resident_native_kernel_bundle_v1.zig").codeIdentity(N, backing, @ptrCast(out));
                return @ptrCast(out);
            }
            pub fn view(self: *const Owned) *const Data {
                const storage: *const Storage = @ptrCast(@alignCast(self));
                return &storage.data;
            }
            pub fn deinit(self: *Owned) void {
                const storage: *Storage = @ptrCast(@alignCast(self));
                const a = storage.backing;
                storage.data.profile.deinit();
                storage.arena.deinit();
                a.destroy(storage);
            }
        };
    };
}
fn pow(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.ResidentNativeResourceLimit;
    return @as(usize, 1) << @intCast(log);
}
fn clockProgram(a: std.mem.Allocator) !R.Circuit {
    var b = R.Builder.init(a);
    defer b.deinit();
    var main: [@import("../../frontends/riscv/air/clock_update_interaction.zig").N_MAIN_COLUMNS]Field = undefined;
    for (&main) |*x| x.* = .{ .symbol = (try b.input()).value };
    const active = Field{ .symbol = (try b.input()).value };
    try b.activate();
    errdefer if (b.active) b.deactivate();
    for (try @import("../../frontends/riscv/air/clock_update_component.zig").directConstraintsGeneric(Field, &main, active)) |x| try b.constrainZero(x.symbol);
    b.deactivate();
    return b.finish();
}
fn frameProgram(a: std.mem.Allocator, expected: Frame.Expected) !R.Circuit {
    var b = R.Builder.init(a);
    defer b.deinit();
    const active = Field{ .symbol = (try b.input()).value };
    var main: [4]Field = undefined;
    for (&main) |*x| x.* = .{ .symbol = (try b.input()).value };
    const pad = Field{ .symbol = (try b.input()).value };
    try b.activate();
    errdefer if (b.active) b.deactivate();
    for (Frame.evaluateGeneric(Field, active, main, pad, Frame.symbols(Field, expected))) |x| try b.constrainZero(x.symbol);
    b.deactivate();
    return b.finish();
}

fn identity(a: std.mem.Allocator, profile: [32]u8, components: []const Component) ![32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-resident-native-program-v1");
    h.update(&profile);
    for (components) |*c| {
        const d = switch (c.program) {
            .opcode => |*p| try Direct.identity(a, p),
            .clock => |p| p.identity_digest,
            .frame => |p| p.identity_digest,
            .projection => |p| blk: {
                h.update(&p.fractions.identity);
                break :blk p.equation.identity;
            },
            .access => |p| blk: {
                h.update(&p.denominators.identity);
                break :blk p.equations.identity;
            },
        };
        h.update(&d);
    }
    return h.finalResult();
}
