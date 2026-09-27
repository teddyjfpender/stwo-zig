//! Positive normative metadata transport. Original raw/fold premix commitments
//! are real CPU PCS commits; no STARK/FRI proof, guest or device is invoked.
//! Native/ROM/provider roots are explicitly UNVERIFIED normative proposals.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Policy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Export = @import("block_v5_memory_source_page_policy_export_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Globals = @import("block_v5_capacity_global_receiver_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
const Native = @import("block_v5_native_capacity_protocol_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Programs = @import("block_v5_program_native_capacity_batch_receiver_v1.zig");
const FusedSource = @import("block_v5_native_capacity_fused_source_v1.zig");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Program = @import("block_v5_program_table_v1.zig");
const ProgramProof = @import("block_v5_program_table_proof_v1.zig");
const Window = @import("block_v5_register_windows_v1.zig");
const LanePlan = @import("block_v5_ram_lanes_plan_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const RawStage = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const FoldStage = @import("block_v5_memory_source_fold_premix_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
const Provider = @import("block_v5_native_lookup_batch_v1.zig");
const Demand = @import("block_v5_native_lookup_plan_v1.zig");
const Fixture = struct {
    shape: @import("../air/statement.zig").Blake3ExecutionStatement,
    leaves: [8]@import("../air/memory_commitment/blake3_state_tree.zig").Leaf,
    multiplicities: [2]u64 = .{ 1, 0 },
    windows: [1]Window.Window,
    catalog: [1]Catalog.Record,
    execution: [1]Programs.InstancePin,
    provider: [1]Provider.Record,
    entries: [5]Seal.Entry,
    events: [1]u64 = .{0},
    witness: [1][32]u8,
    globals: Globals.Pins,
    context: Page.Context,
    raw_artifacts: [1]Policy.Artifact,
    fold_artifacts: [1]Policy.Artifact,
    fold_operands: [1]@import("block_v5_memory_source_fold_operand_store_v1.zig").Pin,
    limits: Policy.Limits,
    fn unverified(label: []const u8) [32]u8 {
        return Files.hash(label);
    }
    fn readEmpty(_: *anyopaque, _: Source.Stream, _: u64, out: []u8) !void {
        if (out.len != 0) return error.NonemptyPositiveSourceFixture;
    }
    fn init(self: *Fixture, a: std.mem.Allocator, dir: std.fs.Dir) !void {
        self.* = undefined;
        self.events = .{0};
        self.multiplicities = .{ 1, 0 };
        const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .n_queries = 1, .log_last_layer_degree_bound = 0, .fold_step = 1 } };
        self.limits = .{};
        self.limits.pages.raw.first.page_row_log = 3; // Five original SHA padding blocks, one eight-row source PAGE.
        self.limits.pages.protocol.raw = self.limits.pages.raw;
        self.limits.pages.protocol.page_row_log = 1; // Empty subtree and root operation.
        self.limits.pages.fold.protocol = self.limits.pages.protocol;
        self.shape = @import("block_v5_native_capacity_transport_fixture_v1.zig").shape(1);
        self.shape.x0_local_custody_version = Recipe.nativeVersion();
        self.shape.final_pc = 4;
        self.shape.public_data.final_pc = 4;
        self.shape.public_data.completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(4);
        self.shape.public_data.io_entries.input_start = 32;
        self.shape.public_data.io_entries.output_len_addr = 64;
        self.shape.public_data.io_entries.output_data_addr = 68;
        const instructions = [_]u32{ 0x00000013, 0x0000006f };
        for (instructions, 0..) |instruction, index| {
            const decoded = try @import("../air/program/decode.zig").decodeProgramWord(instruction);
            for (decoded, 0..) |value, limb| self.leaves[4 * index + limb] = .{ .index = @intCast(4 * index + limb), .value = value };
        }
        const program_root = try @import("../air/program/blake3_root_cache.zig").computeRoot(&self.leaves);
        const program = Program.Plan{ .program_root = program_root, .leaves = &self.leaves, .multiplicities = &self.multiplicities, .expected_fetches = 1, .log_size = 7 };
        self.shape.public_data.program_root = program_root;
        const empty_root = Defaults.get().defaults[0].bytes;
        self.shape.public_data.initial_rw_root = .{ .bytes = empty_root };
        self.shape.public_data.final_rw_root = .{ .bytes = empty_root };
        self.windows = .{Window.Window.fromPublic(0, 1, self.shape.public_data)};
        const registers = Window.Plan{ .version = Recipe.windowVersion(), .initial_registers = @splat(0), .final_registers = @splat(0), .windows = &self.windows };
        const memory_plan = try LanePlan.digest(a, &.{}, 0, &.{}, .{});
        const empty_sha = Initial.sha256("");
        const endpoint = Endpoints.Pins{ .initial = .{
            .layout = .{ .program_base = 0, .program_end = 8, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
            .initial_rw_root = empty_root,
            .initial_registers = @splat(0),
            .public_input_sha256 = empty_sha,
            .public_input_len = 0,
            .input_words = .{ .records = 0, .sha256 = empty_sha },
            .rw_words = .{ .records = 0, .sha256 = empty_sha },
            .first_touches = .{ .records = 0, .sha256 = empty_sha },
        }, .memory_plan_digest = memory_plan, .expected_final_rw_root = empty_root, .endpoints = .{ .records = 0, .sha256 = empty_sha } };
        const admission = try Public.Admission.init(.{ .job_id = unverified("positive-job"), .source_image_digest = Files.hash(std.mem.sliceAsBytes(&instructions)), .program_root = program_root.bytes, .program_plan_digest = try program.digest(), .memory_plan_digest = memory_plan, .initial_source_plan_digest = try endpoint.initial.digest(), .rw_endpoint_plan_digest = try endpoint.digest(), .register_custody_mode = 1, .register_endpoint_plan_digest = try registers.digest(), .execution_index = 0, .first_cycle = 1, .last_cycle = 1 }, &self.shape.public_data);
        const template = try Native.Template.fromShape(&self.shape, 0, config, .rv32im_zkvm_v1, unverified("UNVERIFIED-native-fixed"));
        self.catalog = .{try Catalog.Record.fromTemplate(0, template)};
        const catalog = Catalog.Admission{ .records = &self.catalog };
        const native_roots: Seal.Roots = .{ template.fixed_root, unverified("UNVERIFIED-native-main") };
        const native_id = try Native.instanceId(self.catalog[0].template_id, &self.shape, 0, admission, native_roots, 0);
        const native_entry = Seal.Entry{ .family = .execution, .index = 0, .instance_id = native_id, .roots = native_roots };
        const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 1 };
        const empty = try FusedSource.emptyEntry(a, &self.shape, 0, frame, native_entry, 0, 1);
        self.witness = .{empty.roots[0]};
        const slots = try FusedSource.slotsFromShapeForMode(a, &self.shape, 0, 1);
        defer a.free(slots);
        self.provider = .{.{ .plan = .{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = try Demand.nativeDemand(&self.shape, 0) }, .roots = .{ unverified("UNVERIFIED-provider-fixed"), unverified("UNVERIFIED-provider-main") } }};
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = try ProgramProof.instanceId(program), .roots = .{ unverified("UNVERIFIED-ROM-fixed"), unverified("UNVERIFIED-ROM-main") } },
            native_entry,
            empty,
            Fused.entry(self.catalog[0].template_id, native_id, native_roots, empty.roots[0], 0, frame, slots, &.{}),
            try self.provider[0].entry(),
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        const seal_pins = Seal.Pins{ .job_id = admission.context.job_id, .source_image_digest = admission.context.source_image_digest, .native_template_catalog_digest = try catalog.digest(), .program_root = program_root.bytes, .program_plan_digest = admission.context.program_plan_digest, .memory_plan_digest = memory_plan, .initial_source_plan_digest = admission.context.initial_source_plan_digest, .rw_endpoint_plan_digest = admission.context.rw_endpoint_plan_digest, .expected_final_rw_root = empty_root, .register_endpoint_plan_digest = admission.context.register_endpoint_plan_digest, .register_custody_mode = 1, .config = config, .counts = counts };
        const base = try Seal.seal(seal_pins, &self.entries);
        self.execution = .{.{ .shape = &self.shape, .external_retirements = 0, .admission = admission, .template = template, .template_id = self.catalog[0].template_id, .profile = .rv32im_zkvm_v1 }};
        self.globals = .{
            .expected_seal_digest = base.digest,
            .program = program,
            .memory = .{ .memory = .{ .lanes = .{ .seal = seal_pins, .expected_seal_digest = base.digest, .first_round = &self.entries, .pins = &.{}, .range_roots = &.{}, .expected_total_events = 0, .source = endpoint } }, .catalog = catalog, .executions = &self.execution, .opcode_witness_roots = &self.witness, .ordinary_events = &self.events, .extensions = &.{}, .register_windows = registers },
            .tables = .{ .seal = seal_pins, .roster = &self.entries, .catalog = catalog, .executions = &self.execution, .ordinary_events = &self.events, .extensions = &.{}, .providers = &self.provider, .register_windows = registers },
        };
        _ = try self.globals.validate();
        const source = try Source.admit(endpoint, seal_pins, &self.entries, base, self.limits.source);
        const admitted = try Batch.Admission.init(source, self.limits.fold);
        const raw_plan = try Schema.Protocol.init(&source, config, self.limits.pages.raw.first);
        var empty_reader: u8 = 0;
        var collector = try Schema.Round.Collector.init(source, .{ .context = &empty_reader, .read = readEmpty }, raw_plan, self.limits.pages.raw.first);
        // These are the ONLY PCS calls in the positive fixture: original 6 raw
        // and 6 fold premix trees. Fixed hash tables keep their real log16.
        const raw_pin = committed: {
            const owner = try RawStage.ForBackend(Cpu).collect(a, &collector, self.limits.pages.raw);
            defer owner.deinit() catch @panic("positive raw metadata owner lifetime");
            break :committed owner.pin.?;
        };
        try collector.requireFinished();
        const fold_plan = try Protocol.FoldPlan.init(&admitted, .{ .empty = 1, .roots = 1 }, config, self.limits.pages.protocol);
        const operations = [_]Fold.Operation{
            .{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = empty_root, .after = empty_root } },
            .{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = empty_root, .after = empty_root } },
        };
        const setup = try Blake.Setup.create(a);
        defer setup.release();
        const fold_pin = committed: {
            const owner = try FoldStage.ForBackend(Cpu).collect(a, &admitted, fold_plan, 0, &operations, 1, setup, self.limits.pages.fold);
            defer owner.deinit() catch @panic("positive fold metadata owner lifetime");
            self.fold_operands = .{try FoldStage.ForBackend(Cpu).persist(dir, "source-page-fold-0.operands", owner, &admitted, fold_plan, owner.pin.?, self.limits.pages.fold)};
            break :committed owner.pin.?;
        };
        const sealed = try Protocol.seal(&admitted, raw_plan, fold_plan, &.{raw_pin}, &.{fold_pin}, self.limits.pages.protocol);
        self.context = try Page.Context.init(a, admitted, raw_plan, fold_plan, &.{raw_pin}, &.{fold_pin}, sealed, sealed.digest, base, self.limits.pages);
        self.raw_artifacts = .{.{ .byte_len = "UNVERIFIED-RAW-ARTIFACT".len, .sha256 = Files.hash("UNVERIFIED-RAW-ARTIFACT") }};
        self.fold_artifacts = .{.{ .byte_len = "UNVERIFIED-FOLD-ARTIFACT".len, .sha256 = Files.hash("UNVERIFIED-FOLD-ARTIFACT") }};
    }
    fn deinit(self: *Fixture) void {
        self.context.deinit();
    }
    fn files(self: *const Fixture) Export.Files {
        // Explicit unverified semantic proposals for metadata-only transport,
        // matching the unverified artifact strings. No recursive fixed key or
        // successful original proof/capture is constructed by this fixture.
        const Claims = @import("block_v5_memory_source_page_semantic_columns_v1.zig").Claims;
        const unverified_claims = struct {
            const proposals = [_]Claims{Claims.zero()};
        };
        return .{ .raw = &self.raw_artifacts, .fold = &self.fold_artifacts, .fold_operands = &self.fold_operands, .raw_claims = &unverified_claims.proposals, .fold_claims = &unverified_claims.proposals };
    }
};
fn readFault(a: std.mem.Allocator, dir: std.fs.Dir, fixture: *const Fixture, pin: Policy.Pin) !void {
    const owned = try Policy.read(a, dir, pin, fixture.globals, fixture.limits);
    defer owned.deinit();
    try std.testing.expect(std.meta.eql(owned.context.epoch, fixture.context.epoch));
    try std.testing.expectEqual(@as(usize, 1), owned.context.raw.len);
    try std.testing.expectEqual(@as(usize, 1), owned.context.fold.len);
}
test "source PAGE positive metadata: genuine raw fold premix export independent reconstruct owner and OOM round trip" {
    const parent = try Budget.create(std.testing.allocator, 1 << 30);
    defer parent.destroy();
    const a = parent.allocator();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var fixture: Fixture = undefined;
    try fixture.init(a, temp.dir);
    defer fixture.deinit();
    const pin = try Export.write(a, temp.dir, fixture.globals, &fixture.context, fixture.files(), fixture.limits);
    const baseline_references = parent.references.load(.acquire);
    {
        const owned = try Policy.read(a, temp.dir, pin, fixture.globals, fixture.limits);
        defer owned.deinit();
        try std.testing.expect(parent.references.load(.acquire) > baseline_references);
        try std.testing.expect(std.meta.eql(fixture.context.epoch, owned.context.epoch));
        try std.testing.expect(std.meta.eql(fixture.context.raw[0].roots, owned.context.raw[0].roots));
        try std.testing.expect(std.meta.eql(fixture.context.fold[0].roots, owned.context.fold[0].roots));
        // Original Context rosters are independent of the first-pass owner.
        try std.testing.expect(owned.context.raw.ptr != fixture.context.raw.ptr);
        try std.testing.expect(owned.context.fold.ptr != fixture.context.fold.ptr);
        try std.testing.expect(std.meta.eql(owned.parsed.value.raw[0].pin, owned.context.raw[0]));
    }
    try std.testing.expectEqual(baseline_references, parent.references.load(.acquire));
    // The parsed owner retains its backing coordinator after that external
    // coordinator reference is released. Source/Globals here remain proposals.
    {
        const coordinator = try Budget.create(std.testing.allocator, fixture.limits.max_owned_bytes);
        var released = false;
        defer if (!released) coordinator.destroy();
        const owned = try Policy.read(coordinator.allocator(), temp.dir, pin, fixture.globals, fixture.limits);
        defer owned.deinit();
        coordinator.destroy();
        released = true;
        try owned.context.require(owned.allocator(), fixture.limits.pages);
        try std.testing.expect(std.meta.eql(owned.context.epoch, fixture.context.epoch));
    }
    // Only parsing/reconstruction is fault-swept: real commits happened ONCE.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, readFault, .{ temp.dir, &fixture, pin });
    var changed = pin;
    changed.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleFileHash, Policy.read(a, temp.dir, changed, fixture.globals, fixture.limits));
    var wrong_globals = fixture.globals;
    wrong_globals.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5GlobalPins, Policy.read(a, temp.dir, pin, wrong_globals, fixture.limits));
    const reloaded = try Policy.read(a, temp.dir, pin, fixture.globals, fixture.limits);
    defer reloaded.deinit();
    var wire = reloaded.parsed.value;
    wire.config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedSourcePagePolicyIdentity, Policy.reconstruct(a, fixture.globals, wire, fixture.limits));
    wire = reloaded.parsed.value;
    wire.raw_plan.identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePagePolicyPlan, Policy.reconstruct(a, fixture.globals, wire, fixture.limits));
    wire = reloaded.parsed.value;
    wire.sealed.digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourceUnifiedSeal, Policy.reconstruct(a, fixture.globals, wire, fixture.limits));
    std.debug.print("PAGE_POLICY_METADATA actual_raw_premix_trees=6 actual_fold_premix_trees=6 fixed_tables_log=16 sha_padding_compressions=5 fold_operations=2 STARK=false FRI=false accepted_artifacts=false\n", .{});
}
