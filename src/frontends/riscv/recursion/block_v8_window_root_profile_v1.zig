//! Receiver-owned child-root authority. Fixed keys are recompiled from original
//! source metadata, never accepted from the child proof or a host receipt.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Source = @import("block_v8_endpoint_join_source_v1.zig");
const Roster = @import("block_v8_endpoint_join_roster_v1.zig");
const Protocol = @import("block_v8_endpoint_join_protocol_v1.zig");
const RootAdmission = @import("block_v8_window_root_admission_v1.zig");
const Shape = @import("block_v5_recursive_parent_shape_v1.zig").Shape;
pub const TRACE_TREES = 3;
pub const FIRST_ROOTS = 2;
pub const RELATION_PAIRS = @import("air/universal_challenges.zig").RELATION_COUNT;
pub const Limits = struct {};
pub const Capture = struct {
    parent: *const @import("blake3_native_parent_verifier.zig").Verified,
    proof: core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher),
    final_channel: core.proof_suites.Blake3.Channel,
    pub fn borrow(parent: *const @import("blake3_native_parent_verifier.zig").Verified) Capture {
        return .{ .parent = parent, .proof = parent.capture, .final_channel = parent.channel };
    }
};
pub const Geometry = struct {
    original: *Shape,
    columns: []const []const u32,
    config: core.pcs.PcsConfig,
    widths: []const u32,
    lifting_log: u32,
    pub fn deepProfile(v: Geometry) @import("air/pcs_deep_circuit.zig").Profile {
        return v.original.deepProfile();
    }
    pub fn friProfile(v: Geometry) @import("air/fri_verifier_circuit.zig").Profile {
        return v.original.friProfile();
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    admission: RootAdmission.Admission,
    shape: Geometry,
    span: @import("block_v8_window_root_statement_v1.zig").WindowSpan,
    main_root: [32]u8,
    fixed_root: [32]u8,
    seal: [32]u8,
    pub fn deriveJoin(a: std.mem.Allocator, admissions: []const Source.Admission, extra: []const core.fields.qm31.QM31, main_root: [32]u8, options: Roster.Options) !*Owned {
        if (admissions.len < 3 or admissions.len > 64) return error.InvalidB8WindowSources;
        const sources = try a.alloc(Source.Source, admissions.len);
        defer a.free(sources);
        var count: usize = 0;
        defer for (sources[0..count]) |source| Source.deinitProfile(source);
        for (admissions, 0..) |input, i| {
            sources[i] = try input.derive(a);
            count += 1;
        }
        var setup = try Roster.Owned.deriveWithOptions(a, sources, extra, options);
        defer setup.deinit();
        const window = sources[sources.len - 1].global.scope.window;
        const boundary = window.boundary;
        const span = @import("block_v8_window_root_statement_v1.zig").WindowSpan{
            .elf_sha256 = window.initial.elf_sha256,
            .config = setup.context.child_config,
            .first_cycle = try std.math.add(u64, boundary.skip_cycles, 1),
            .cycles = boundary.cycles,
            .incoming_snapshot_id = boundary.incoming_sha256,
            .outgoing_snapshot_id = boundary.outgoing_sha256,
            .initial_cpu = boundary.initial_cpu,
            .final_cpu = boundary.final_cpu,
            .initial_policy_id = if (window.boundary_options.initial) |first| first.policy_id else null,
            .terminal_policy_id = if (window.boundary_options.terminal) |last| last.policy_id else null,
        };
        const geometry = try @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu).derive(a, setup.fixed, setup.context, .csp_q70_pow26);
        const expected = [_]Protocol.Bus.Expected{.{ .digest = Protocol.digest(setup.values) }};
        const key = try Protocol.Key.fromGeometry(geometry, setup.wires, &expected);
        const admitted = try Protocol.Admission.init(key, try key.identity(), setup.wires, .{ .children = &.{setup.values} }, &expected);
        return fromCompiled(a, &admitted, setup.values, Protocol.CLAIM_TAG, span, main_root);
    }
    /// The fold constructor replays independently compiled child profiles and
    /// closes their exact typed statements before creating any expected key.
    pub fn deriveFold(a: std.mem.Allocator, children: []const *const Owned, main_root: [32]u8) !*Owned {
        return @import("block_v8_window_root_fold_v1.zig").deriveProfile(a, children, main_root);
    }
    pub fn fromCompiled(a: std.mem.Allocator, original: anytype, values: anytype, claim_tag: u32, span: @import("block_v8_window_root_statement_v1.zig").WindowSpan, main_root: [32]u8) !*Owned {
        try span.validate();
        const out = try a.create(Owned);
        errdefer a.destroy(out);
        out.allocator = a;
        out.arena = std.heap.ArenaAllocator.init(a);
        errdefer out.arena.deinit();
        out.admission = try RootAdmission.snapshot(out.arena.allocator(), original, values, claim_tag);
        const shape = try Shape.initForAdmission(a, &out.admission, .{});
        errdefer shape.deinit();
        const columns = try out.arena.allocator().alloc([]const u32, 4);
        for (columns, shape.columns) |*dest, col| dest.* = col;
        out.shape = .{ .original = shape, .columns = columns, .config = shape.config, .widths = shape.widths, .lifting_log = shape.lifting_log };
        out.span = span;
        out.main_root = main_root;
        out.fixed_root = original.key.preprocessed_root;
        out.seal = try out.identity();
        return out;
    }
    pub fn identity(v: *const Owned) ![32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42385752, 1 });
        ch.mixRoot(v.admission.expected_id);
        ch.mixRoot(v.admission.public_id);
        ch.mixRoot(v.admission.seal);
        ch.mixRoot(v.shape.original.seal);
        ch.mixRoot(try v.span.identity());
        ch.mixRoot(v.main_root);
        return ch.digestBytes();
    }
    pub fn validate(v: *const Owned) !void {
        try v.admission.validate();
        try v.shape.original.validate();
        if (!std.meta.eql(v.seal, try v.identity())) return error.MutatedB8WindowRootProfile;
    }
    pub fn requireCapture(v: *const Owned, capture: *const Capture) !void {
        try v.validate();
        try capture.parent.validate(&v.admission, v.admission.expected_id);
        if (!std.meta.eql(capture.proof.commitments[0], v.fixed_root) or !std.meta.eql(capture.proof.commitments[1], v.main_root) or !std.meta.eql(capture.final_channel, capture.parent.channel) or !std.meta.eql(@import("../prover/proof_capture_sha256.zig").compute(&capture.proof), @import("../prover/proof_capture_sha256.zig").compute(&capture.parent.capture))) return error.UntrustedB8WindowRootCapture;
    }
    pub fn deinit(v: *Owned) void {
        const a = v.allocator;
        v.shape.original.deinit();
        v.arena.deinit();
        a.destroy(v);
    }
};
