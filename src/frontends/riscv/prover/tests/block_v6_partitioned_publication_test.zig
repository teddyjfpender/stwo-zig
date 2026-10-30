//! Genuine two-segment one-layout publication, with all first rounds retained.
//! This gate does not claim recursive/global closure: original global files
//! still exist and the next mixed-root gate must authenticate their providers.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Engine = @import("stwo_prover_engine");
const Driver = @import("../block_v5_cpu_driver_common_v1.zig").ForCapacity(false);
const Collect = @import("../block_v5_cpu_collect_v1.zig");
const Assembly = @import("../block_v5_cpu_assembly_v1.zig").ForCapacity(false);
const Store = @import("../block_v5_cpu_bundle_store_v1.zig");
const Source = @import("../block_v4_cpu_runner_source.zig");
const Guest = @import("block_v6_mixed_guest_test_support.zig");
const Protocol = @import("../block_v6_partitioned_native_proof_v1.zig");
const Codec = @import("../block_v6_partitioned_native_codec_v1.zig");
const Global = @import("../block_v5_global_receiver_v1.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Sink = struct {
    a: std.mem.Allocator,
    pins: Global.Pins,
    bytes: std.ArrayList([]u8) = .empty,
    fn expected(self: *const Sink, index: u32) !Codec.Expected {
        if (index >= self.pins.tables.executions.len) return error.InvalidPartitionedPublicationIndex;
        const pin = self.pins.tables.executions[index];
        var native: ?Seal.Entry = null;
        var request: ?Seal.Entry = null;
        for (self.pins.tables.roster) |entry| {
            if (entry.index == index and entry.family == .execution) native = entry;
            if (entry.index == index and entry.family == .program_request) request = entry;
        }
        return .{ .shape = pin.shape, .external_retirements = pin.template.external_retirements, .template_id = pin.template_id, .native_instance_id = (native orelse return error.MissingNativeEntry).instance_id, .fused_instance_id = (request orelse return error.MissingRequestEntry).instance_id, .native_roots = native.?.roots, .witness_root = self.pins.memory.opcode_witness_roots[index], .sealed_digest = self.pins.expected_seal_digest, .index = index, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = pin.shape.public_data.clock }, .register_custody_mode = self.pins.tables.seal.register_custody_mode, .config = self.pins.tables.seal.config };
    }
    fn put(raw: *anyopaque, index: u32, proof: *Protocol.Proof) !void {
        const self: *Sink = @ptrCast(@alignCast(raw));
        if (index != self.bytes.items.len) return error.InvalidPartitionedPublicationIndex;
        const bytes = try Codec.encode(self.a, proof, try self.expected(index), .{});
        errdefer self.a.free(bytes);
        try self.bytes.append(self.a, bytes);
        proof.deinit(self.a);
    }
    fn deinit(self: *Sink) void {
        for (self.bytes.items) |bytes| self.a.free(bytes);
        self.bytes.deinit(self.a);
    }
};
test "partitioned publication proves two real mixed segments without old native companion artifacts" {
    const a = std.testing.allocator;
    const selected = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0;
    const instructions = try Guest.instructions(4096);
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 256, Guest.profile);
    const oracle = [_]u8{1};
    const planned = try @import("../blake3_execution_preflight.zig").runEthereumForProfile(Guest.profile, a, &elf, &.{}, &oracle, 3 * 4096);
    const cycle_limit: u32 = @intCast(try std.math.divCeil(u64, planned.last.cycle, 2));
    const schedule = try @import("../../runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, cycle_limit, planned.required_terminal_cycles);
    try std.testing.expectEqual(@as(u32, 2), schedule.segments);
    const job = try @import("../../recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(selected.config(), planned.first, planned.last, 2, planned.first.machine.rw_memory);
    const pins = Source.Pins{ .elf_sha256 = Source.sha256(&elf), .input_sha256 = Source.sha256(&.{}), .oracle_sha256 = Source.sha256(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
    var source = try Source.Source.initFromPlan(a, &elf, &.{}, &oracle, cycle_limit, selected.config(), pins, planned);
    defer source.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var options = @import("../block_v5_cpu_product_options_v1.zig").options(selected, 2, 8);
    options.collection.native_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.access_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.globals.program_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.globals.ram_commitments = .{ .storage = .{ .max_total_file_bytes = 1 << 30 } };
    options.collection.groups.commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.caller_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.external_commitments = .{ .max_total_file_bytes = 1 << 30 };
    const policy = @import("../block_v5_cpu_driver_admission_v1.zig").InputPolicy{ .runner_pins = pins, .job_id = @splat(114), .expected_final_rw_root = planned.last.machine.rw_memory.bytes };
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const collected = try Collect.collect(a, temporary.dir, &source, policy, selected.config(), options.collection);
    defer collected.deinit();
    const assembly = try Assembly.assemblePartitioned(a, collected, policy, options.max_roster_entries);
    defer assembly.deinit();
    const provider_policies = try @import("../block_v5_cpu_bundle_policy_v1.zig").ForCapacity(false).buildProvidersForPartitioned(a, assembly.global_pins, options.store);
    defer a.free(provider_policies);
    var writer = try Store.Store.initWriter(a, temporary.dir, provider_policies, selected.config(), options.store);
    defer writer.deinit();
    var sink = Sink{ .a = a, .pins = assembly.global_pins };
    defer sink.deinit();
    _ = try Driver.publishPartitionedBase(a, temporary.dir, collected, assembly, &writer, &pool, options, .{ .context = &sink, .put_fused = Sink.put });
    try std.testing.expectEqual(@as(usize, 2), sink.bytes.items.len);
    try std.testing.expectEqual(@as(u64, 2), collected.native_commitments.reused_first_rounds);
    try std.testing.expectEqual(@as(u64, 2), collected.access_commitments.reused_access_trees);
    try std.testing.expectEqual(assembly.extensions.len, collected.caller_commitments.reused_first_rounds);
    try std.testing.expectEqual(assembly.extensions.len, collected.external_commitments.pcs.reused_first_rounds);
    try std.testing.expectEqual(collected.caller_commitments.written_bytes, collected.caller_commitments.read_bytes);
    try std.testing.expectEqual(collected.external_commitments.raw_written_bytes, collected.external_commitments.raw_read_bytes);
    const files = try writer.filePins(a);
    defer a.free(files);
    for (files) |file| try std.testing.expect(file.family != .native and file.family != .native_fused);
    // Staged wide owners have all been destroyed. Only independently pinned
    // metadata and the new wire artifact are supplied to each fresh verifier.
    for (sink.bytes.items, 0..) |bytes, i| {
        const index: u32 = @intCast(i);
        const pin = assembly.global_pins.tables.executions[index];
        const expected = try sink.expected(index);
        // Full partitioned relation identity is sealed before challenges.
        // A legacy companion roster cannot replay that same admission.
        const legacy = try @import("../block_v5_native_projection_fused_source_v1.zig").slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, expected.register_custody_mode);
        defer a.free(legacy);
        const access = try @import("../block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, pin.shape, expected.frame, expected.register_custody_mode);
        defer a.free(access);
        if (access.len != 0) try std.testing.expectError(error.UntrustedV5FullFusedProjectionEntry, @import("../block_v5_native_projection_fused_proof_v2.zig").admit(assembly.sealed, assembly.seal_pins, assembly.entries, index, expected.template_id, expected.native_instance_id, expected.native_roots, expected.witness_root, expected.frame, legacy, access, null));
        var verified = try Protocol.ForBackend(Cpu).verifyOwned(a, try Codec.decode(a, bytes, expected, .{}), index, .{ .shape = pin.shape, .admission = pin.admission, .template = pin.template, .template_id = pin.template_id, .profile = pin.profile }, .{ .frame = expected.frame, .expected_events = assembly.global_pins.memory.ordinary_events[index], .witness_root = expected.witness_root }, assembly.sealed, assembly.seal_pins, assembly.entries, assembly.global_pins.tables.catalog);
        defer verified.deinit(a);
        try std.testing.expectEqualDeep(assembly.sealed.digest, verified.native.sealed_digest);
        var wrong = expected;
        wrong.sealed_digest[0] ^= 1;
        if (Codec.decode(a, bytes, wrong, .{})) |unexpected| {
            var owned = unexpected;
            owned.deinit(a);
            return error.AcceptedChangedPartitionedPublicationPolicy;
        } else |_| {}
    }
    std.debug.print("PARTITIONED_PUBLICATION segments=2 joint_proofs=2 separate_native_proofs=0 separate_companion_proofs=0 retained_native=2 retained_access=2 fresh_verification=true global_closure=false standalone_root=false\n", .{});
}
