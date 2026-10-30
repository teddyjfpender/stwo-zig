//! Genuine child -> fully device-resident original native verifier parent.
//! CPU generation of the raw child is fixture setup, explicitly outside this
//! parent-only qualification. No captured parent witness is passed to CUDA.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const ParentProfile = @import("frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("frontends/riscv/prover/block_v7_native_proof_v1.zig");
const Profile = @import("frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
const Public = @import("frontends/riscv/recursion/block_v7_native_public_v1.zig");
const Protocol = @import("frontends/riscv/recursion/block_v7_native_parent_protocol_v1.zig");
const Fixed = @import("frontends/riscv/recursion/block_v7_native_fixed_roster_v1.zig");
const Capsule = @import("frontends/riscv/recursion/block_v7_native_compiler_capsule_v1.zig").Capsule;
const Program = @import("integrations/riscv_cuda/resident_parent_program_v1.zig");
const Packet = @import("integrations/riscv_cuda/resident_parent_child_packet_v1.zig");
const Replay = @import("integrations/riscv_cuda/resident_parent_child_transcript_v1.zig");
const Frames = @import("integrations/riscv_cuda/resident_parent_child_frames_v1.zig");
const Paths = @import("integrations/riscv_cuda/resident_parent_child_paths_v1.zig");
const PathsRuntime = @import("integrations/riscv_cuda/resident_parent_child_paths_runtime_v1.zig");
const ChildRuntime = @import("integrations/riscv_cuda/resident_parent_child_runtime_v1.zig");
const Hash = @import("integrations/riscv_cuda/resident_parent_hash_plan_v1.zig");
const Arithmetic = @import("integrations/riscv_cuda/resident_parent_arithmetic_plan_v1.zig");
const Registry = @import("integrations/riscv_cuda/resident_parent_wire_registry_v1.zig");
const Readonly = @import("integrations/riscv_cuda/resident_parent_readonly_plan_v1.zig");
const Answers = @import("integrations/riscv_cuda/resident_parent_deep_answers_plan_v1.zig");
const Fri = @import("integrations/riscv_cuda/resident_parent_fri_expand_v1.zig");
const Schedule = @import("integrations/riscv_cuda/resident_parent_schedule_v1.zig");
const Seeds = @import("integrations/riscv_cuda/resident_parent_schedule_seeds_v1.zig");
const Source = @import("integrations/riscv_cuda/resident_parent_value_routes_v1.zig").Source;
const Composite = @import("integrations/riscv_cuda/resident_parent_composite_v1.zig");
const Prover = @import("integrations/riscv_cuda/resident_parent_prover_v1.zig");
const Projection = @import("frontends/riscv/recursion/air/blake3_row_columns.zig");
const Storage = @import("frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Child = struct {
    allocator: std.mem.Allocator,
    profile: *Profile.Owned,
    packet: Packet.Owned,
    claims: Public.Claims,
    fn deinit(self: *Child) void {
        self.allocator.free(self.claims.projection);
        self.allocator.free(self.claims.access);
        self.packet.deinit();
        self.profile.deinit();
    }
    fn create(a: std.mem.Allocator, config: core.pcs.PcsConfig) !Child {
        const code = [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x0000006f };
        const elf = @import("frontends/riscv/runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
        var session = try @import("frontends/riscv/runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
        defer session.deinit();
        var executed = try session.startSegment(code.len - 1);
        defer executed.deinit();
        var counters = try @import("frontends/riscv/air/lookups/tables/mod.zig").counter.Set.init(a);
        defer counters.deinit(a);
        var segment = try @import("frontends/riscv/prover/block_v7_execution_test_support.zig").Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
        defer segment.deinit();
        const Epoch = @import("frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
        const entries = [_]Epoch.Entry{try segment.pin.entry(a)};
        var counts: Epoch.Counts = @splat(0);
        counts[0] = 1;
        const epoch = try Epoch.Epoch.init(@splat(9), config, counts, &entries, 1);
        var proof = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, segment.pin, epoch, &entries);
        defer proof.deinit(a);
        const profile = try Profile.Owned.derive(a, segment.pin, epoch, &entries, .{});
        errdefer profile.deinit();
        var packet = try Packet.Owned.initNative(a, profile, &proof, .{});
        errdefer packet.deinit();
        const projection = try a.dupe(@TypeOf(proof.claims[0]), proof.claims);
        errdefer a.free(projection);
        const access = try a.dupe(@TypeOf(proof.memory_claims[0]), proof.memory_claims);
        return .{ .allocator = a, .profile = profile, .packet = packet, .claims = .{ .projection = projection, .access = access } };
    }
};
fn qualify(comptime device: bool) anyerror!void {
    const a = std.testing.allocator;
    var phase: []const u8 = "child_fixture";
    errdefer |err| std.debug.print("RESIDENT_NATIVE_FAILURE phase={s} error={s}\n", .{ phase, @errorName(err) });
    const selected_profile: ParentProfile = if (try enabledOption(std.posix.getenv("STWO_RESIDENT_NATIVE_CANONICAL"))) .csp_q70_pow26 else .diagnostic_q8_pow0;
    const retained_mode = try enabledOption(std.posix.getenv("STWO_RESIDENT_NATIVE_RETAINED"));
    const hostile_mode = try enabledOption(std.posix.getenv("STWO_RESIDENT_NATIVE_HOSTILE"));
    if (hostile_mode and (retained_mode or selected_profile != .diagnostic_q8_pow0)) return error.InvalidHostileFixtureOptions;
    var setup_clock = try std.time.Timer.start();
    var child = try Child.create(a, selected_profile.config());
    const child_setup_ns = setup_clock.lap();
    std.debug.print("RESIDENT_NATIVE_PROFILE child_queries={d} child_pow_bits={d} parent_queries={d} parent_pow_bits={d} child_cpu_fixture_ns={d}\n", .{ selected_profile.config().fri_config.n_queries, selected_profile.config().pow_bits, selected_profile.config().fri_config.n_queries, selected_profile.config().pow_bits, child_setup_ns });
    defer child.deinit();
    // The original proof and all execution witnesses are already destroyed.
    phase = "compiler";
    const capsule = try Capsule.derive(a, child.profile, .{});
    defer capsule.deinit();
    const compiler = capsule.compiler();
    phase = "fixed_roster";
    var cold = try Fixed.Owned.deriveFromCapsule(a, capsule, child.claims, 2, .{});
    defer cold.deinit();
    phase = "independent_key";
    const geometry_key = try @import("frontends/riscv/recursion/blake3_parent_fixed_key_v1.zig").ForBackend(Cpu).derive(a, cold.fixed, cold.context, selected_profile);
    const roster = [_]Protocol.Bus.Expected{Fixed.expected(child.profile)};
    const key = try Protocol.Key.fromGeometry(geometry_key, cold.wires, &roster);
    var public = try Public.reconstruct(a, child.profile, child.claims);
    defer public.deinit();
    const admission = try Protocol.Admission.init(key, try key.identity(), cold.wires, .{ .children = &.{public} }, &roster);
    phase = "native_program";
    const program = try Program.Owned.deriveNative(a, admission, .{});
    defer program.deinit();
    var arithmetic = try Arithmetic.Plan.init(a, &.{ compiler.composition.circuit.graph(), compiler.deep_graph.graph(), compiler.fri_graph.graph() }, .{});
    defer arithmetic.deinit();
    var deep = try @import("frontends/riscv/recursion/air/pcs_deep_circuit.zig").Prepared.init(a, child.profile.shape.deepProfile());
    defer deep.deinit();
    phase = "deep_answer_map";
    var answers = try Answers.Plan.init(a, &deep, &arithmetic, 1);
    defer answers.deinit();
    phase = "child_replay";
    var replay = try Replay.Owned.initNative(a, child.profile, &child.packet, 2, .{});
    defer replay.deinit();
    phase = "child_frames";
    var frames = try Frames.Owned.init(a, &replay, 1_000_000, 1 << 24);
    defer frames.deinit();
    phase = "fri_expansion";
    var fri = try Fri.Plan.init(a, &child.packet, child.profile);
    defer fri.deinit();
    const trace_first = replay.output_words;
    const answer_first = try std.math.add(u32, trace_first, replay.trace_words);
    const expanded_first = try std.math.add(u32, answer_first, answers.output_words);
    const paths_first = try std.math.add(u32, expanded_first, fri.output_words);
    const expanded = try a.alloc(Packet.Span, fri.layers.len);
    defer a.free(expanded);
    for (fri.layers, expanded) |layer, *out| out.* = .{ .first = try std.math.add(u32, expanded_first, layer.expanded.first), .count = layer.expanded.count };
    phase = "child_paths";
    var paths = try Paths.Owned.init(a, &child.packet, child.profile, expanded, .{});
    defer paths.deinit();
    const resident_used = try std.math.add(u32, paths_first, paths.output_words);
    phase = "child_bindings";
    const bindings = try Packet.Bindings.init(&child.packet, child.profile, .{ .challenges = .{ .first = 0, .count = 424 }, .composition = .{ .first = replay.composition_first, .count = 4 }, .oods = .{ .first = replay.oods_first, .count = 4 }, .deep_randomness = .{ .first = replay.deep_first, .count = 4 }, .deep_answers = .{ .first = answer_first, .count = answers.output_words }, .fri_alphas = .{ .first = replay.fri_first, .count = @intCast(fri.layers.len * 4) }, .fri_expanded = expanded });
    phase = "graph_routes";
    var routes = try Packet.Routes.init(a, bindings, &arithmetic, .{ 0, 1, 2 }, &compiler.composition, &compiler.deep_graph, &compiler.fri_graph);
    defer routes.deinit();
    var seeds: std.ArrayList(Schedule.Seed) = .empty;
    defer seeds.deinit(a);
    const frame_seeds = try Seeds.derive(a, &frames, .{ .packet_words = @intCast(child.packet.words.len), .output_first = 0, .output_words = replay.output_words, .trace_first = trace_first, .trace_words = replay.trace_words, .ready_phase = 1 }, &.{});
    defer a.free(frame_seeds);
    try seeds.appendSlice(a, frame_seeds);
    for (paths.anchors) |anchor| {
        const word = try std.math.add(u32, paths_first, anchor.output);
        var coordinates: [4]Source = undefined;
        for (&coordinates, 0..) |*out, i| out.* = Source.residentByte(word, @intCast(i), 11);
        try seeds.append(a, .{ .key = (@as(u64, anchor.circuit) << 32) | anchor.wire, .coordinates = coordinates, .word = Source.resident(word, 11) });
    }
    phase = "hash_fixed";
    const hash = try Hash.Owned.deriveFixed(a, cold.fixed, .{ .max_frames = 1 << 20 });
    defer hash.deinit();
    phase = "wire_registry";
    var registry = try Registry.Plan.init(a, program, cold.fixed, .{});
    defer registry.deinit();
    phase = "readonly_plan";
    const readonly = try Readonly.Plan.derive(a, program, cold.fixed[17], cold.fixed[16], .{});
    defer readonly.deinit();
    const tasks = [_]Composite.Types.Task{
        .{ .phase = 0, .operation = .{ .child_replay = .{ .output_first = 0, .trace_first = trace_first } } },
        .{ .phase = 1, .operation = .{ .zero_answers = .{ .destination_first = answer_first } } },
        .{ .phase = 2, .operation = .{ .child_gather = .composition } },
        .{ .phase = 3, .operation = .{ .arithmetic = .{ .first = 0, .count = 1 } } },
        .{ .phase = 4, .operation = .{ .child_gather = .deep } },
        .{ .phase = 5, .operation = .derive_answers },
        .{ .phase = 6, .operation = .{ .arithmetic = .{ .first = 1, .count = 1 } } },
        .{ .phase = 7, .operation = .{ .fri_expand = .{ .deep_first = answer_first, .alpha_first = replay.fri_first, .destination_first = expanded_first } } },
        .{ .phase = 8, .operation = .{ .child_gather = .fri } },
        .{ .phase = 9, .operation = .{ .arithmetic = .{ .first = 2, .count = 1 } } },
        .{ .phase = 10, .operation = .{ .child_paths = .{ .destination_first = paths_first } } },
    };
    phase = "schedule";
    var schedule = try Schedule.Owned.compile(a, program, cold.fixed, &registry, hash, &arithmetic, seeds.items, .{ .tasks = &tasks, .writes = &.{}, .phase = 12, .resident_used = resident_used, .graph_phase = .{ 3, 6, 9 } }, child.packet.words.len * 4, readonly.view().argument_rows, .{ .max_resident_words = 1 << 22 });
    defer schedule.deinit();
    std.debug.print("RESIDENT_NATIVE_SCHEDULE tasks={d} calls={d} hash_calls={d} resident_words={d} original_destroyed=true\n", .{ schedule.tasks.len, schedule.routes.view().calls.len, hash.view().calls.len, schedule.resident_used });
    if (!device) return;
    const child_plan = ChildRuntime.Plan{ .packet = &child.packet, .transcript = &replay, .routes = &routes };
    const path_plan = PathsRuntime.Plan{ .layout = &paths, .packet = &child.packet };
    phase = "complete_arena";
    var complete = try Composite.Cold.Plan.initFull(a, program, schedule.routes, hash, &arithmetic, schedule.tasks, schedule.writes, schedule.hash_rows, schedule.row_counts, readonly, null, child_plan, &fri, &answers, path_plan, .{});
    defer complete.deinit();
    var columns: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
    defer {
        for (columns.items) |c| a.free(c.values);
        columns.deinit(a);
    }
    inline for (Storage.Airs, 0..) |Air, i| try Projection.projectFixed(Air, a, cold.fixed[i], key.log_sizes[i], &columns);
    for ([_]@import("frontends/riscv/air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8 }) |kind| try Projection.tablePreprocessed(a, kind, &columns);
    const inputs = try a.alloc([]const core.fields.m31.M31, columns.items.len);
    defer a.free(inputs);
    for (columns.items, inputs) |column, *out| out.* = column.values;
    // Deliberately alter only one canonical opened field after every cold
    // profile, key, graph and route has been independently compiled. This is
    // not a host witness regeneration: all numeric consequences stay on GPU.
    var hostile_packet: ?[]u32 = null;
    defer if (hostile_packet) |words| a.free(words);
    if (hostile_mode) {
        const index = blk: {
            for (child.packet.queries) |tree| for (tree) |span| if (span.count != 0) break :blk span.first;
            return error.MissingHostileOpening;
        };
        const changed = try a.dupe(u32, child.packet.words);
        hostile_packet = changed;
        changed[index] = if (changed[index] == core.fields.m31.Modulus - 1) 0 else changed[index] + 1;
        child.packet.words = changed;
        std.debug.print("RESIDENT_NATIVE_HOSTILE raw_opening_index={d} cold_plan_unchanged=true\n", .{index});
    }
    const parent_cold_ns = setup_clock.read();
    var open_clock = try std.time.Timer.start();
    var runtime: ?@import("stwo_cuda_backend").runtime.NativeRuntime = if (retained_mode) try @import("stwo_cuda_backend").runtime.NativeRuntime.open(&.{90}) else null;
    defer if (runtime) |*r| r.abort() catch {};
    std.debug.print("RESIDENT_NATIVE_SETUP parent_cold_ns={d} retained_runtime_open_ns={d} retained={}\n", .{ parent_cold_ns, if (retained_mode) open_clock.read() else 0, retained_mode });
    var device_plan = Composite.Plan{ .cold = &complete };
    if (hostile_mode) {
        if (Prover.For(Composite.Plan).prove(a, .{ .program = program, .device_plan = &device_plan, .fixed = inputs, .raw_input = std.mem.sliceAsBytes(child.packet.words), .limits = .{ .max_device_bytes = 8 << 30 } })) |accepted| {
            var unexpected = accepted;
            unexpected.deinit(a);
            return error.HostileResidentProofAccepted;
        } else |err| {
            try std.testing.expectEqual(error.InvalidResidentParentVerdict, err);
            std.debug.print("RESIDENT_NATIVE_HOSTILE rejected=true device_terminal_verdict=true raw_query_field_changed=true\n", .{});
            return;
        }
    }
    for (0..@as(usize, if (retained_mode) 2 else 1)) |iteration| {
        phase = "device_prove";
        var request_clock = try std.time.Timer.start();
        var result = try Prover.For(Composite.Plan).prove(a, .{ .program = program, .device_plan = &device_plan, .fixed = inputs, .raw_input = std.mem.sliceAsBytes(child.packet.words), .limits = .{ .max_device_bytes = 8 << 30 }, .runtime = if (runtime) |*r| r else null });
        const proof_wall_ns = request_clock.read();
        std.debug.print("RESIDENT_NATIVE_NUMERICS proof_wall_ns={d} host={any} counters={any} terminal_reads={d} terminal_bytes={d}\n", .{ proof_wall_ns, result.host_timing, result.verdict.counters, result.proof.read.operations, result.proof.read.bytes });
        phase = "artifact_encode";
        var artifact = @import("frontends/riscv/recursion/blake3_native_parent_artifact.zig").Owned.init(a, result.proof.stark, program.view().proofKeyID(), result.proof.claims);
        defer artifact.deinit();
        const bytes = try @import("frontends/riscv/recursion/blake3_native_parent_codec.zig").encode(a, &artifact, &admission);
        defer a.free(bytes);
        if (std.posix.getenv("STWO_RESIDENT_NATIVE_ARTIFACT")) |path| {
            const file = if (retained_mode) try std.fmt.allocPrint(a, "{s}.{d}", .{ path, iteration }) else try a.dupe(u8, path);
            defer a.free(file);
            try std.fs.cwd().writeFile(.{ .sub_path = file, .data = bytes });
        }
        phase = "independent_native_receiver";
        var verify_clock = try std.time.Timer.start();
        var verified = try @import("frontends/riscv/recursion/block_v7_native_receiver_v1.zig").verify(a, bytes, child.profile, child.claims, key, cold.wires);
        defer verified.deinit();
        const verify_ns = verify_clock.read();
        try std.testing.expect(result.verdict.isResident());
        std.debug.print("RESIDENT_NATIVE iteration={d} retained={} queries={d} pow_bits={d} max_device_bytes=8589934592 verified=true child_receipt=true execution_closed=false raw_child_fixture_cpu=true device_bytes={d} elapsed_ns={d} proof_bytes={d} proof_wall_ns={d} verify_ns={d}\n", .{ iteration, retained_mode, selected_profile.config().fri_config.n_queries, selected_profile.config().pow_bits, result.device_arena_bytes, result.elapsed_ns, bytes.len, proof_wall_ns, verify_ns });
    }
}
test "resident genuine native complete cold schedule" {
    try qualify(false);
}
test "actual fully resident native parent fresh original receiver" {
    try qualify(true);
}

fn enabledOption(value: ?[]const u8) !bool {
    const text = value orelse return false;
    if (!std.mem.eql(u8, text, "1")) return error.InvalidResidentNativeOption;
    return true;
}
test "resident native canonical and retained options are explicit" {
    try std.testing.expect(!try enabledOption(null));
    try std.testing.expect(try enabledOption("1"));
    try std.testing.expectError(error.InvalidResidentNativeOption, enabledOption("0"));
    try std.testing.expectError(error.InvalidResidentNativeOption, enabledOption("70"));
    const c = ParentProfile.csp_q70_pow26.config();
    try std.testing.expectEqual(@as(usize, 70), c.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 26), c.pow_bits);
    try std.testing.expectEqual(@as(u32, 1), c.fri_config.fold_step);
}
