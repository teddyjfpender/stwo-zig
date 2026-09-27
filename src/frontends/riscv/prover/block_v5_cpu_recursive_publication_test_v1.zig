//! Host lifecycle/source admission only: setup fixtures are deliberately not
//! proofs. Actual complete producer/receiver bodies are retained separately.
const std = @import("std");
const T = @import("block_v5_recursive_execution_leaf_store_v1.zig").ForFamily(.caller_arithmetic);
const C = T.Codec;
const Fixture = @import("block_v5_recursive_execution_leaf_store_test_v1.zig").Fixture;
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const Callback = @import("block_v5_recursive_template_callback_v1.zig");
const wires = [_]C.Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .source = .open_sum, .coordinate = 0 }};
const Binding = Callback.ForStore(T, C.Admission.Prepared, C.Protocol.Key, C.Bus.Wire, C.index);
fn prepare(a: std.mem.Allocator, fixture: *const Fixture) !C.Admission.Prepared {
    return C.Admission.Prepared.init(a, fixture.caller.statement, fixture.caller.frame.cycle_count, fixture.caller.binding, fixture.caller.sealed, fixture.caller.pins, &fixture.entries, .{});
}
fn proposedTemplate(admitted: *const C.Admission.Prepared) !C.Template {
    const geometry = Parent.Key{ .profile = .diagnostic_q8_pow0, .config = admitted.config, .context = .{ .child_key_id = admitted.template_id, .child_config = admitted.config, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try C.Protocol.Key.fromGeometry(geometry, &wires);
    return .{ .key = key, .key_id = try key.identity(), .schedule = &wires };
}
fn lifecycle(a: std.mem.Allocator, dir: std.fs.Dir, fixture: *const Fixture) !void {
    var admitted = try prepare(a, fixture);
    defer admitted.deinit();
    const sources = [_]T.SourceAdmission{.{ .prepared = &admitted }};
    var store = try T.Store.initWriterFromSources(a, dir, fixture.roster(), &sources, .{});
    defer store.deinit();
    try std.testing.expectEqual(@as(u32, 2), C.index((try store.sourceFor(2)).prepared));
    try std.testing.expectError(error.IncompleteRecursiveExecutionFiles, store.publishedPolicies(a));
    var unpublished: C.Stage.Artifact = undefined;
    try std.testing.expectError(error.UnboundRecursiveLeafTemplate, store.put(2, &unpublished));
    var binding = Binding{ .store = &store };
    const template = try proposedTemplate(&admitted);
    try binding.callback().admit(&admitted, template.key, template.key_id, template.schedule);
    try std.testing.expect(store.owned_templates.?[0].schedule.ptr != template.schedule.ptr);
    try std.testing.expectEqualSlices(C.Bus.Wire, template.schedule, store.owned_templates.?[0].schedule);
    try std.testing.expectError(error.AlreadyBoundRecursiveLeafTemplate, binding.callback().admit(&admitted, template.key, template.key_id, template.schedule));
    try std.testing.expectError(error.IncompleteRecursiveExecutionFiles, store.filePins(a));
}
test "cpu recursive publication: genuine sparse source binds once with owned schedule but no proof authority" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try Fixture.init(std.testing.allocator);
    try lifecycle(std.testing.allocator, dir.dir, &fixture);
}
test "cpu recursive publication: every source template and schedule allocation failure unwinds" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try Fixture.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, lifecycle, .{ dir.dir, &fixture });
}
test "cpu recursive publication: equal source copy wrong key and source census cannot bind independently retained owner" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try Fixture.init(a);
    var admitted = try prepare(a, &fixture);
    defer admitted.deinit();
    const sources = [_]T.SourceAdmission{.{ .prepared = &admitted }};
    try std.testing.expectError(error.IncompleteRecursiveExecutionPolicies, T.Store.initWriterFromSources(a, dir.dir, fixture.roster(), &.{}, .{}));
    var store = try T.Store.initWriterFromSources(a, dir.dir, fixture.roster(), &sources, .{});
    defer store.deinit();
    var binding = Binding{ .store = &store };
    const template = try proposedTemplate(&admitted);
    const copy = admitted;
    try std.testing.expectError(error.UntrustedRecursiveTemplateSourceOwner, binding.callback().admit(&copy, template.key, template.key_id, template.schedule));
    var wrong = template;
    wrong.key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedRecursiveExecutionTemplate, binding.callback().admit(&admitted, wrong.key, wrong.key_id, wrong.schedule));
    try binding.callback().admit(&admitted, template.key, template.key_id, template.schedule);
    try std.testing.expectError(error.UnadmittedRecursiveExecutionIndex, store.sourceFor(0));
}
test "cpu recursive publication: schedule cap fails before ownership transfer and binding stays pending" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try Fixture.init(a);
    var admitted = try prepare(a, &fixture);
    defer admitted.deinit();
    const sources = [_]T.SourceAdmission{.{ .prepared = &admitted }};
    var store = try T.Store.initWriterFromSources(a, dir.dir, fixture.roster(), &sources, .{});
    defer store.deinit();
    // Exact allowed original allocations are already owned. New schedule
    // ownership cannot exceed the independently admitted metadata cap.
    store.limits.max_slot_bytes = store.owned_template_bytes;
    const template = try proposedTemplate(&admitted);
    try std.testing.expectError(error.RecursiveExecutionSlotResourceLimit, store.bindWriterTemplate(2, template));
    try std.testing.expectError(error.IncompleteRecursiveExecutionFiles, store.publishedPolicies(a));
}
test "cpu recursive publication: all seven original stages preserve absent callbacks and explicit option admission" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    inline for (.{ @import("block_v5_range16_recursive_stage_v1.zig"), @import("block_v5_ram_lanes_recursive_stage_v1.zig"), @import("block_v5_program_table_recursive_stage_v1.zig"), @import("block_v5_native_lookup_recursive_stage_v1.zig"), @import("block_v5_caller_arithmetic_recursive_stage_v1.zig"), @import("block_v5_caller_fused_recursive_stage_v1.zig"), @import("block_v5_native_capacity_fused_recursive_stage_v1.zig") }) |Stage| {
        const options = Stage.ForBackend(Cpu).Options{ .profile = .csp_q70_pow26 };
        try std.testing.expect(options.on_template == null);
        try options.validate(options.profile.config());
    }
    var options = @import("block_v5_cpu_recursive_publication_v1.zig").Options{};
    try options.validate();
    options.transcript_capacity = 0;
    try std.testing.expectError(error.InvalidCpuRecursivePublicationOptions, options.validate());
}
