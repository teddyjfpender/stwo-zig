const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const Template = @import("blake3_native_prepared_template_v1.zig").ForBackend(Cpu);
const plans = @import("blake3_commitment_plan.zig");

test "native prepared template reuses invariant columns across two admitted plans" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const program = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(program.len, &program);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(4);
    defer segment.deinit();
    var owner = try Profile.Witness.initCompactSegment(a, &segment);
    defer owner.deinit();
    const native = &owner.native.statement;
    const extension = &owner.statement;
    const ranges = owner.native.compact_ranges.?.plan;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const Budget = engine.host_budget_allocator.SharedHostBudget;
    const cached_budget = try Budget.create(a, 2 * 1024 * 1024 * 1024);
    defer cached_budget.destroy();
    const canonical_budget = try Budget.create(a, 2 * 1024 * 1024 * 1024);
    defer canonical_budget.destroy();

    const original_pin = try owner.admission();
    var changed_plan = try plans.Plan.init(a, owner.plan.roots, owner.plan.memories, owner.plan.programs, owner.plan.program_leaves);
    defer changed_plan.deinit();
    changed_plan.programs[0].multiplicity += 1;
    const changed_pin = try plans.Admission.init(&changed_plan, try changed_plan.identity());
    try std.testing.expect(!std.meta.eql(original_pin.expected_id, changed_pin.expected_id));

    var timer = try std.time.Timer.start();
    const cached = try Template.init(cached_budget.allocator(), native, extension, config);
    defer cached.deinit();
    const setup_ns = timer.lap();
    const setup_memory = cached_budget.snapshot();
    const first = try cached.prepareInstance(cached_budget.allocator(), native, extension, original_pin, config, ranges);
    const first_ns = timer.lap();
    const second = try cached.prepareInstance(cached_budget.allocator(), native, extension, changed_pin, config, ranges);
    const second_ns = timer.lap();
    var changed_public = native.*;
    changed_public.public_data.initial_regs[7] ^= 1;
    const third = try cached.prepareInstance(cached_budget.allocator(), &changed_public, extension, original_pin, config, ranges);
    const third_ns = timer.lap();
    const cached_memory = cached_budget.snapshot();

    try std.testing.expectEqualDeep(first.template_id, second.template_id);
    try std.testing.expect(!std.meta.eql(first.full_fixed_root, second.full_fixed_root));
    try std.testing.expect(!std.meta.eql(first.current_key_id, second.current_key_id));
    try std.testing.expect(!std.meta.eql(first.instance_id, second.instance_id));
    try std.testing.expectEqualDeep(first.full_fixed_root, third.full_fixed_root);
    try std.testing.expect(!std.meta.eql(first.current_key_id, third.current_key_id));
    try std.testing.expect(!std.meta.eql(first.instance_id, third.instance_id));
    try std.testing.expectError(error.TemplateInstanceMismatch, first.validateExpected(second));
    try std.testing.expectError(error.TemplateInstanceMismatch, first.validateExpected(third));
    var first_channel = core.proof_suites.Blake3.Channel{};
    var second_channel = core.proof_suites.Blake3.Channel{};
    var third_channel = core.proof_suites.Blake3.Channel{};
    first.mixInto(&first_channel);
    second.mixInto(&second_channel);
    third.mixInto(&third_channel);
    try std.testing.expect(!std.meta.eql(first_channel.digestBytes(), second_channel.digestBytes()));
    try std.testing.expect(!std.meta.eql(first_channel.digestBytes(), third_channel.digestBytes()));

    {
        const canonical = try Native.PreparedVerifier.initCompact(canonical_budget.allocator(), native, extension.*, original_pin, config, ranges);
        defer canonical.deinit();
        try std.testing.expectEqualDeep(canonical.root, first.full_fixed_root);
        try std.testing.expectEqualDeep(canonical.id, first.current_key_id);
    }
    {
        const canonical = try Native.PreparedVerifier.initCompact(canonical_budget.allocator(), native, extension.*, changed_pin, config, ranges);
        defer canonical.deinit();
        try std.testing.expectEqualDeep(canonical.root, second.full_fixed_root);
        try std.testing.expectEqualDeep(canonical.id, second.current_key_id);
    }
    {
        const canonical = try Native.PreparedVerifier.initCompact(canonical_budget.allocator(), &changed_public, extension.*, original_pin, config, ranges);
        defer canonical.deinit();
        try std.testing.expectEqualDeep(canonical.root, third.full_fixed_root);
        try std.testing.expectEqualDeep(canonical.id, third.current_key_id);
    }
    const canonical_memory = canonical_budget.snapshot();

    var wrong_native = native.*;
    wrong_native.component_descs[0].n_rows += 1;
    try std.testing.expectError(error.InvalidStatement, cached.prepareInstance(cached_budget.allocator(), &wrong_native, extension, original_pin, config, ranges));
    var wrong_config = config;
    wrong_config.pow_bits = 1;
    try std.testing.expectError(error.TemplateConfigMismatch, cached.prepareInstance(cached_budget.allocator(), native, extension, original_pin, wrong_config, ranges));
    try std.testing.expectEqual(setup_memory.live_bytes, cached_memory.live_bytes);
    try std.testing.expectEqual(@as(usize, 0), canonical_memory.live_bytes);
    std.debug.print("NATIVE_TEMPLATE_PREP two_plans=true changed_public=true same_template=true distinct_full_roots=true canonical_parity=true setup_ns={d} first_instance_ns={d} second_instance_ns={d} third_instance_ns={d} setup_retained_bytes={d} setup_peak_bytes={d} cached_combined_peak_bytes={d} canonical_peak_bytes={d}\n", .{ setup_ns, first_ns, second_ns, third_ns, setup_memory.live_bytes, setup_memory.peak_live_bytes, cached_memory.peak_live_bytes, canonical_memory.peak_live_bytes });
}
