//! Receiver-owned authority for the complete native-parent circuit theorem.
//! All fixed keys come from B8 metadata admission. This retains structural
//! public references before the original roster erases them into coordinates.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixed = @import("../../../frontends/riscv/recursion/blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
const Root = @import("../../../frontends/riscv/recursion/block_v8_window_root_profile_v1.zig");
const Receiver = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const RootAdmission = @import("../../../frontends/riscv/recursion/block_v8_window_root_admission_v1.zig");
const Frames = @import("../../../frontends/riscv/recursion/air/block_v5_recursive_statement_frames_v1.zig");
const Compiler = @import("../../../frontends/riscv/recursion/air/block_v5_open_parent_composition_v2.zig");
const Source = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_source_v1.zig");
const Pcs = @import("stwo_circuit_frontend").builder.blake3_pcs_reuse_v1;
pub const Statement = @import("stwo_circuit_frontend").statements.riscv_native_parent_v1;
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const TermRef = union(enum) {
    raw_word: u32,
    felt_word: struct { field: u32, coordinate: u2 },
    qm31: u32,
};

/// Deliberately has NO `pinned_public_supply` declaration. The shared typed
/// equation compiler must emit inputs for every supply tuple coordinate.
pub const DynamicAdmission = struct {
    original: *const RootAdmission.Admission,
    key: @FieldType(RootAdmission.Admission, "key"),
    source: @FieldType(RootAdmission.Admission, "source"),
    pc_clock_children: @FieldType(RootAdmission.Admission, "pc_clock_children"),
    pub fn validate(v: *const DynamicAdmission) !void {
        try v.original.validate();
        if (v.source.terms.ptr != v.original.source.terms.ptr or v.source.terms.len != v.original.source.terms.len or v.pc_clock_children.len != 0 or !std.meta.eql(try v.key.identity(), try v.original.key.identity())) return error.MutatedRiscCircuitAdmission;
    }
    pub fn config(v: *const DynamicAdmission) !core.pcs.PcsConfig {
        try v.validate();
        return v.key.config;
    }
};

pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    profile: *Root.Owned,
    composition: Compiler.Compiled,
    terms: []const TermRef,
    geometry: Pcs.Geometry,
    statement: Statement.Statement,
    seal: [32]u8,
    fixed_for_qualification: ?Fixed.Committed = null,

    pub fn derive(a: std.mem.Allocator, tree: Receiver.Tree) anyerror!Owned {
        return deriveMode(a, tree, false);
    }
    /// Qualification-only polynomial lease. No MAIN, interaction, or proof
    /// values are retained and the lease confers no verification authority.
    pub fn deriveRetainingFixedForQualification(a: std.mem.Allocator, tree: Receiver.Tree) anyerror!Owned {
        return deriveMode(a, tree, true);
    }
    fn deriveMode(a: std.mem.Allocator, tree: Receiver.Tree, retain_fixed: bool) anyerror!Owned {
        var remaining: usize = 4096;
        try requireTreeBounds(tree, 0, &remaining);
        return switch (tree) {
            .leaf => |leaf| deriveNative(a, leaf.external, leaf.input, retain_fixed),
            .mixed_leaf => |leaf| blk: {
                var metadata = try @import("../../../frontends/riscv/recursion/block_v8_endpoint_mixed_join_receiver_v1.zig").admitMetadata(a, leaf.external, leaf.input);
                defer metadata.deinit();
                break :blk deriveJoin(a, &metadata.admissions, &metadata.extra, leaf.main_root, .{ .global_g_repartition = leaf.global_g_repartition }, retain_fixed);
            },
            .branch => |branch| blk: {
                if (branch.children.len < 2 or branch.children.len > 4) return error.InvalidB8WindowFanIn;
                var profiles: [4]*Root.Owned = undefined;
                var n: usize = 0;
                defer for (profiles[0..n]) |profile| profile.deinit();
                for (branch.children, 0..) |child, i| {
                    profiles[i] = try child.derive(a);
                    n += 1;
                }
                break :blk deriveFold(a, profiles[0..n], branch.main_root, retain_fixed);
            },
        };
    }
    pub fn validate(v: *const Owned) !void {
        try v.profile.validate();
        try v.composition.circuit.validate();
        try v.geometry.validate();
        try v.statement.validate();
        const span = v.profile.span;
        var initial: [33]u32 = undefined;
        var final: [33]u32 = undefined;
        initial[0] = span.initial_cpu.pc;
        @memcpy(initial[1..], &span.initial_cpu.regs);
        final[0] = span.final_cpu.pc;
        @memcpy(final[1..], &span.final_cpu.regs);
        if (v.statement.first_cycle != span.first_cycle or v.statement.cycles != span.cycles or !std.meta.eql(v.statement.elf_sha256, span.elf_sha256) or !std.meta.eql(v.statement.initial_cpu, initial) or !std.meta.eql(v.statement.final_cpu, final) or !std.meta.eql(v.statement.incoming_snapshot_id, span.incoming_snapshot_id) or !std.meta.eql(v.statement.outgoing_snapshot_id, span.outgoing_snapshot_id) or !std.meta.eql(v.statement.initial_policy_id, span.initial_policy_id) or !std.meta.eql(v.statement.terminal_policy_id, span.terminal_policy_id) or !std.meta.eql(v.statement.native_key_id, v.profile.admission.expected_id) or !std.meta.eql(v.statement.native_public_id, v.profile.admission.public_id) or !std.meta.eql(v.statement.native_fixed_root, v.profile.fixed_root) or !std.meta.eql(v.statement.native_main_root, v.profile.main_root) or !std.meta.eql(v.statement.admission_id, v.seal)) return error.MutatedRiscCircuitStatement;
        if (v.terms.len != v.profile.admission.source.terms.len or !std.meta.eql(v.seal, try v.identity())) return error.MutatedRiscCircuitAuthority;
    }
    pub fn identity(v: *const Owned) ![32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x52384341, 1, 23, 25, 47, 4 });
        ch.mixRoot(v.profile.seal);
        ch.mixRoot(v.composition.circuit.identity_digest);
        ch.mixRoot(try v.geometry.identity());
        ch.mixU64(v.terms.len);
        for (v.terms) |term| {
            ch.mixU32s(&.{@intFromEnum(std.meta.activeTag(term))});
            switch (term) {
                .raw_word, .qm31 => |index| ch.mixU32s(&.{index}),
                .felt_word => |index| ch.mixU32s(&.{ index.field, index.coordinate }),
            }
        }
        return ch.digestBytes();
    }
    pub fn deinit(v: *Owned) void {
        if (v.fixed_for_qualification) |*fixed| fixed.deinit();
        v.composition.deinit();
        v.profile.deinit();
        v.arena.deinit();
        v.* = undefined;
    }
};

fn requireTreeBounds(tree: Receiver.Tree, depth: usize, remaining: *usize) anyerror!void {
    if (depth > 16 or remaining.* == 0) return error.RiscCircuitAuthorityResourceLimit;
    remaining.* -= 1;
    switch (tree) {
        .branch => |branch| {
            if (branch.children.len < 2 or branch.children.len > 4) return error.InvalidB8WindowFanIn;
            for (branch.children) |child| try requireTreeBounds(child, depth + 1, remaining);
        },
        .leaf, .mixed_leaf => {},
    }
}

fn finish(a: std.mem.Allocator, original: anytype, values: anytype, tag: u32, span: @import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").WindowSpan, main: [32]u8) !Owned {
    const profile = try Root.Owned.fromCompiled(a, original, values, tag, span, main);
    errdefer profile.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const own = arena.allocator();
    const terms = try resolveTerms(own, &profile.admission.prefix, original.wires, values);
    var dynamic = DynamicAdmission{ .original = &profile.admission, .key = profile.admission.key, .source = profile.admission.source, .pc_clock_children = &.{} };
    var composition = try Compiler.compileShape(a, &dynamic);
    errdefer composition.deinit();
    const geometry = try pcsGeometry(own, profile);
    var initial: [33]u32 = undefined;
    var final: [33]u32 = undefined;
    initial[0] = span.initial_cpu.pc;
    @memcpy(initial[1..], &span.initial_cpu.regs);
    final[0] = span.final_cpu.pc;
    @memcpy(final[1..], &span.final_cpu.regs);
    var out = Owned{ .allocator = a, .arena = arena, .profile = profile, .composition = composition, .terms = terms, .geometry = geometry, .seal = undefined, .statement = .{ .elf_sha256 = span.elf_sha256, .first_cycle = @intCast(span.first_cycle), .cycles = @intCast(span.cycles), .incoming_snapshot_id = span.incoming_snapshot_id, .outgoing_snapshot_id = span.outgoing_snapshot_id, .initial_cpu = initial, .final_cpu = final, .initial_policy_id = span.initial_policy_id, .terminal_policy_id = span.terminal_policy_id, .native_key_id = profile.admission.expected_id, .native_public_id = profile.admission.public_id, .native_fixed_root = profile.fixed_root, .native_main_root = profile.main_root, .admission_id = undefined } };
    out.seal = try out.identity();
    out.statement.admission_id = out.seal;
    try out.validate();
    return out;
}

fn pcsGeometry(a: std.mem.Allocator, profile: *const Root.Owned) !Pcs.Geometry {
    const shape = profile.shape.original;
    const trees = try a.alloc(Pcs.Tree, 4);
    var index: usize = 0;
    for (trees, shape.columns) |*tree, columns| {
        const out = try a.alloc(Pcs.Column, columns.len);
        for (out, columns) |*column, log| {
            const offsets = shape.layouts[index].offsets();
            const masks = try a.alloc(Pcs.Mask, offsets.len);
            for (masks, offsets) |*mask, offset| mask.* = .{ .row_log = shape.mask_log, .offset = @intCast(offset) };
            // Root.Shape stores FRI-extended logs; PCS Geometry takes original
            // polynomial logs and adds blowup exactly once at authentication.
            column.* = .{ .log_size = try std.math.sub(u32, log, shape.config.fri_config.log_blowup_factor), .masks = masks };
            index += 1;
        }
        tree.* = .{ .columns = out };
    }
    const g = Pcs.Geometry{ .config = profile.shape.config, .trees = trees };
    if (g.config.pow_bits != 26 or g.config.fri_config.n_queries != 70 or g.trees.len != 4) return error.UnsupportedRiscCircuitProfile;
    try g.validate();
    return g;
}

/// Resolve operation ORDINALS, never equal numeric values. Exact five-step
/// GenericValues framing is checked against each independently admitted child.
fn resolveTerms(a: std.mem.Allocator, frame: *const Frames.Statement, wires: anytype, values: anytype) ![]const TermRef {
    const n = values.children.len;
    if (frame.first.len != 5 * n + 5 or frame.first[0] != .words or frame.first[1] != .felts or frame.first[2] != .root or frame.first[3] != .words or frame.first[5 * n + 4] != .felts) return error.UnsupportedRiscCircuitPrefixGrammar;
    const extra = frame.first[5 * n + 4].felts;
    if (extra.len != values.extra.len) return error.UnsupportedRiscCircuitPrefixGrammar;
    for (values.children, 0..) |child, i| {
        const steps = frame.first[4 + 5 * i ..][0..5];
        if (steps[0] != .words or steps[1] != .root or steps[2] != .words or steps[3] != .felts or steps[4] != .felts or steps[0].words.len != 6 or steps[2].words.len != child.statement.words.len or steps[3].felts.len != child.statement.felts.len or steps[4].felts.len != child.public.len) return error.UnsupportedRiscCircuitPrefixGrammar;
    }
    const out = try a.alloc(TermRef, wires.len);
    for (out, wires) |*reference, wire| {
        if (wire.child == n) {
            if (wire.coordinate >= extra.len) return error.InvalidRiscCircuitPublicReference;
            reference.* = .{ .qm31 = extra.first + wire.coordinate };
            continue;
        }
        if (wire.child >= n) return error.InvalidRiscCircuitPublicReference;
        const child = values.children[wire.child];
        const steps = frame.first[4 + 5 * wire.child ..][0..5];
        reference.* = switch (wire.source) {
            .word => blk: {
                if (wire.coordinate >= child.statement.words.len) return error.InvalidRiscCircuitPublicReference;
                break :blk .{ .raw_word = steps[2].words.first + wire.coordinate };
            },
            .felt_word => blk: {
                if (wire.coordinate / 4 >= child.statement.felts.len) return error.InvalidRiscCircuitPublicReference;
                break :blk .{ .felt_word = .{ .field = steps[3].felts.first + wire.coordinate / 4, .coordinate = @intCast(wire.coordinate % 4) } };
            },
            .public_input => blk: {
                if (wire.coordinate >= child.public.len) return error.InvalidRiscCircuitPublicReference;
                break :blk .{ .qm31 = steps[4].felts.first + wire.coordinate };
            },
            .first_root => blk: {
                if (wire.coordinate / 8 >= child.roots_count or child.roots_count * 8 > child.statement.words.len) return error.InvalidRiscCircuitPublicReference;
                const offset = child.statement.words.len - 8 * child.roots_count + wire.coordinate;
                break :blk .{ .raw_word = steps[2].words.first + @as(u32, @intCast(offset)) };
            },
        };
    }
    // Equality checks an already resolved structural reference. It never
    // searches for a matching value or chooses among equal-valued wires.
    for (out, wires) |reference, wire| {
        const actual = try referenceCoordinates(frame, reference);
        if (!std.meta.eql(actual, try values.at(wire))) return error.InvalidRiscCircuitPublicReference;
    }
    return out;
}

fn referenceCoordinates(frame: *const Frames.Statement, reference: TermRef) ![4]core.fields.m31.M31 {
    const M = core.fields.m31.M31;
    const word = switch (reference) {
        .raw_word => |i| if (i < frame.words.len) frame.words[i] else return error.InvalidRiscCircuitPublicReference,
        .felt_word => |i| if (i.field < frame.felts.len) frame.felts[i.field].toM31Array()[i.coordinate].v else return error.InvalidRiscCircuitPublicReference,
        .qm31 => |i| return if (i < frame.felts.len) frame.felts[i].toM31Array() else error.InvalidRiscCircuitPublicReference,
    };
    var bytes: [4]M = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
    return bytes;
}

fn deriveJoin(a: std.mem.Allocator, admissions: []const Source.Admission, extra: []const Q, main: [32]u8, options: @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_roster_v1.zig").Options, retain_fixed: bool) !Owned {
    const sources = try a.alloc(Source.Source, admissions.len);
    defer a.free(sources);
    var count: usize = 0;
    defer for (sources[0..count]) |source| Source.deinitProfile(source);
    for (admissions, 0..) |admission, i| {
        sources[i] = try admission.derive(a);
        count += 1;
    }
    var setup = try @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_roster_v1.zig").Owned.deriveWithOptions(a, sources, extra, options);
    defer setup.deinit();
    const window = sources[sources.len - 1].global.scope.window;
    const boundary = window.boundary;
    const span = @import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").WindowSpan{ .elf_sha256 = window.initial.elf_sha256, .config = setup.context.child_config, .first_cycle = try std.math.add(u64, boundary.skip_cycles, 1), .cycles = boundary.cycles, .incoming_snapshot_id = boundary.incoming_sha256, .outgoing_snapshot_id = boundary.outgoing_sha256, .initial_cpu = boundary.initial_cpu, .final_cpu = boundary.final_cpu, .initial_policy_id = if (window.boundary_options.initial) |first| first.policy_id else null, .terminal_policy_id = if (window.boundary_options.terminal) |last| last.policy_id else null };
    return fromSetup(a, @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_protocol_v1.zig"), &setup, span, main, retain_fixed);
}
fn deriveFold(a: std.mem.Allocator, children: []const *Root.Owned, main: [32]u8, retain_fixed: bool) !Owned {
    const S = @import("../../../frontends/riscv/recursion/block_v8_window_root_source_v1.zig");
    var sources: [4]S.Source = undefined;
    var spans: [4]@import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").WindowSpan = undefined;
    for (children, 0..) |child, i| {
        sources[i] = .{ .root = child };
        spans[i] = child.span;
    }
    const span = try @import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").merge(spans[0..children.len]);
    const extra = try @import("../../../frontends/riscv/recursion/air/block_v8_window_root_composition_v1.zig").spanValues(a, span);
    defer a.free(extra);
    var setup = try @import("../../../frontends/riscv/recursion/block_v8_window_root_roster_v1.zig").Owned.deriveWithOptions(a, sources[0..children.len], extra, .{ .global_g_repartition = true });
    defer setup.deinit();
    return fromSetup(a, @import("../../../frontends/riscv/recursion/block_v8_window_root_protocol_v1.zig"), &setup, span, main, retain_fixed);
}
fn fromSetup(a: std.mem.Allocator, comptime Protocol: type, setup: anytype, span: @import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").WindowSpan, main: [32]u8, retain_fixed: bool) !Owned {
    var retained: ?Fixed.Committed = if (retain_fixed) try Fixed.deriveCommitted(a, setup.fixed, setup.context, .csp_q70_pow26) else null;
    errdefer if (retained) |*fixed| fixed.deinit();
    const key_geometry = if (retained) |fixed| fixed.key else try Fixed.derive(a, setup.fixed, setup.context, .csp_q70_pow26);
    const expected = [_]Protocol.Bus.Expected{.{ .digest = Protocol.digest(setup.values) }};
    const key = try Protocol.Key.fromGeometry(key_geometry, setup.wires, &expected);
    const admitted = try Protocol.Admission.init(key, try key.identity(), setup.wires, .{ .children = &.{setup.values} }, &expected);
    var out = try finish(a, &admitted, setup.values, Protocol.CLAIM_TAG, span, main);
    out.fixed_for_qualification = retained;
    return out;
}

// Share the canonical metadata-only factory with native receiving and the
// direct-original circuit path. This boundary allocates no NativeParent rows.
fn deriveNative(a: std.mem.Allocator, external: Receiver.External, input: Receiver.Leaf, retain_fixed: bool) !Owned {
    var metadata = try Receiver.admitLeafMetadata(a, external, input);
    defer metadata.deinit();
    return deriveJoin(a, metadata.admissions, &metadata.extra, input.main_root, .{ .global_g_repartition = input.global_g_repartition }, retain_fixed);
}
