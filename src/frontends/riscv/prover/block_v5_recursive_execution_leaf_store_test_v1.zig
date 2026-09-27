//! Real admission/durable publication with literal NONPROOF payloads. Neither
//! source fixture pins nor transport validity assert cryptographic acceptance.
const std = @import("std");
const core = @import("stwo_core");
const Files = @import("block_v5_artifact_files_v1.zig");
const Stores = @import("block_v5_recursive_execution_leaf_store_v1.zig");
const T = Stores.ForFamily(.caller_arithmetic);
const C = T.Codec;
const Seal = @import("block_v5_source_seal_v1.zig");
const Original = @import("block_v5_caller_capture_unit_test.zig").Fixture;
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const wires = [_]C.Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .source = .open_sum, .coordinate = 0 }};
pub const Fixture = struct {
    caller: Original,
    entries: [14]Seal.Entry,
    pub fn init(a: std.mem.Allocator) !Fixture {
        var out: Fixture = undefined;
        out.caller = try Original.init(a);
        out.caller.binding.execution_index = 2;
        out.caller.binding.caller_entry_index = 2;
        out.caller.binding.caller_instance_id = Protocol.instanceId(out.caller.binding.caller_key_id, out.caller.binding.execution_instance_id, 2, out.caller.binding.first_roots);
        out.entries[0] = out.caller.entries[0];
        for (0..3) |family| for (0..3) |index| {
            var entry = out.caller.entries[1 + family];
            entry.index = @intCast(index);
            out.entries[1 + 3 * family + index] = entry;
        };
        out.entries[10] = out.caller.entries[4];
        out.entries[11] = .{ .family = .precompile, .index = 2, .instance_id = out.caller.binding.caller_instance_id, .roots = out.caller.binding.first_roots };
        var schedule = try @import("block_v5_caller_fused_schedule_v1.zig").Schedule.init(a, &out.caller.statement, out.caller.frame.cycle_count, out.caller.frame, out.caller.pins.register_custody_mode);
        defer schedule.deinit();
        out.entries[12] = @import("block_v5_caller_fused_proof_v1.zig").entry(out.caller.binding, out.caller.witness, out.caller.frame, out.caller.pins.register_custody_mode, &schedule);
        out.entries[13] = @import("block_v5_external_memory_sidecar_proof_v1.zig").packedEntry(out.caller.binding.execution_instance_id, out.caller.binding.caller_instance_id, out.caller.binding.caller_key_id, out.caller.binding.first_roots, out.caller.witness, 2, schedule.memory);
        out.caller.pins.counts = @splat(0);
        for (out.entries) |entry| out.caller.pins.counts[@intFromEnum(entry.family) - 1] += 1;
        out.caller.sealed = try Seal.seal(out.caller.pins, &out.entries);
        out.caller.binding.sealed_digest = out.caller.sealed.digest;
        return out;
    }
    pub fn roster(self: *const Fixture) Stores.Roster {
        return .{ .sealed = self.caller.sealed, .pins = self.caller.pins, .entries = &self.entries };
    }
    fn prepare(self: *const Fixture, a: std.mem.Allocator) !C.Admission.Prepared {
        return C.Admission.Prepared.init(a, self.caller.statement, self.caller.frame.cycle_count, self.caller.binding, self.caller.sealed, self.caller.pins, &self.entries, .{});
    }
};
fn template(prepared: *const C.Admission.Prepared) !C.Template {
    const geometry = Parent.Key{ .profile = .diagnostic_q8_pow0, .config = prepared.config, .context = .{ .child_key_id = prepared.template_id, .child_config = prepared.config, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try C.Protocol.Key.fromGeometry(geometry, &wires);
    return .{ .key = key, .key_id = try key.identity(), .schedule = &wires };
}
fn artifact(a: std.mem.Allocator, policy: C.Policy) !C.Stage.Artifact {
    const claims = try C.Admission.Profile.ExtensionClaim.zeroForStatement(&policy.prepared.statement);
    const native = @import("block_v5_precompile_family_proof_v1.zig").OpenReceipt{ .binding = policy.prepared.binding, .open_sum = claims.componentSum() };
    const bytes = try a.dupe(u8, "literal NONPROOF sparse execution transport");
    errdefer a.free(bytes);
    const schedule = try a.dupe(C.Bus.Wire, policy.template.schedule);
    errdefer a.free(schedule);
    return .{ .bytes = bytes, .key = policy.template.key, .expected_key_id = policy.template.key_id, .schedule = schedule, .native = native, .public_values = try C.Bus.Values.fromCaller(policy.prepared, native, claims) };
}
test "execution leaf store: exact sparse source roster and publication preserve original execution index" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try Fixture.init(a);
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const key = try template(&prepared);
    const policy = C.Policy{ .prepared = &prepared, .template = &key };
    try std.testing.expectError(error.IncompleteRecursiveExecutionPolicies, T.Store.initWriter(a, dir.dir, fixture.roster(), &.{}, .{}));
    var writer = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{});
    defer writer.deinit();
    var literal = try artifact(a, policy);
    var owns = true;
    defer if (owns) literal.deinit(a);
    try std.testing.expectError(error.UnadmittedRecursiveExecutionIndex, writer.put(0, &literal));
    try std.testing.expectError(error.IncompleteRecursiveExecutionFiles, writer.filePins(a));
    const sink = writer.sink();
    try sink.put_caller_arithmetic(sink.context, 2, &literal);
    owns = false;
    const proposal = try writer.proofBytes(a, 2);
    defer a.free(proposal);
    try std.testing.expectEqualStrings("literal NONPROOF sparse execution transport", proposal);
    const pins = try writer.filePins(a);
    defer a.free(pins);
    try std.testing.expectEqual(@as(u32, 2), pins[0].index);
    var buffer: [96]u8 = undefined;
    const raw = try Files.readPinned(a, dir.dir, try T.fileName(&buffer, 2), pins[0].byte_len, pins[0].sha256, writer.limits.codec.codec.max_file_bytes);
    defer a.free(raw);
    var view = try C.decodeMetadata(a, raw, policy, .{});
    defer view.deinit();
    try std.testing.expectEqualStrings("literal NONPROOF sparse execution transport", view.proof);
    var duplicate = try artifact(a, policy);
    defer duplicate.deinit(a);
    try std.testing.expectError(error.DuplicateRecursiveExecutionLeaf, writer.put(2, &duplicate));
    try std.testing.expectEqualStrings("literal NONPROOF sparse execution transport", duplicate.bytes);
    var second = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{});
    defer second.deinit();
    try std.testing.expectError(error.ExistingV5BundleArtifact, second.put(2, &duplicate));
    try std.testing.expectError(error.IncompleteRecursiveExecutionFiles, second.filePins(a));
    var reader = try T.Store.initReader(a, dir.dir, fixture.roster(), &.{policy}, pins, .{});
    defer reader.deinit();
    try std.testing.expectError(error.IncompleteRecursiveExecutionVerification, reader.requireVerified());
    const detached = try reader.proofBytes(a, 2);
    defer a.free(detached);
    try std.testing.expectEqualStrings("literal NONPROOF sparse execution transport", detached);
    try std.testing.expectError(error.IncompleteRecursiveExecutionVerification, reader.requireVerified());
    const loader = reader.loader();
    if (loader.take_fresh(loader.context, 2)) |received| {
        var unexpected = received;
        unexpected.deinit();
        return error.AcceptedLiteralExecutionLeaf;
    } else |err| if (err == error.OutOfMemory) return err;
    try std.testing.expectError(error.IncompleteRecursiveExecutionVerification, reader.requireVerified());
    try std.testing.expectError(error.InvalidRecursiveExecutionLoadState, reader.takeFresh(2));
    try std.testing.expectError(error.InvalidRecursiveExecutionLoadState, reader.proofBytes(a, 2));
}
test "execution leaf store: independent sparse pins reject duplication reorder overflow omissions and family limits" {
    const pins = [_]Stores.FilePin{ .{ .index = 2, .byte_len = 100, .sha256 = @splat(1) }, .{ .index = 7, .byte_len = 101, .sha256 = @splat(2) } };
    try T.validatePins(&pins, .{});
    try std.testing.expectError(error.UntrustedRecursiveExecutionFilePin, T.validatePins(&.{ pins[0], pins[0] }, .{}));
    try std.testing.expectError(error.UntrustedRecursiveExecutionFilePin, T.validatePins(&.{ pins[1], pins[0] }, .{}));
    var caps: Stores.Limits = .{};
    caps.max_total_bytes = 200;
    try std.testing.expectError(error.RecursiveExecutionTotalResourceLimit, T.validatePins(&pins, caps));
    caps = .{};
    caps.max_slot_bytes = 1;
    try std.testing.expectError(error.RecursiveExecutionSlotResourceLimit, T.validatePins(&pins, caps));
    const Native = Stores.ForFamily(.native_capacity_fused);
    try std.testing.expectError(error.UntrustedRecursiveExecutionFilePin, Native.validatePins(&pins, .{}));
}
fn admissionAllocations(a: std.mem.Allocator, dir: std.fs.Dir, roster: Stores.Roster, policy: C.Policy) !void {
    var writer = try T.Store.initWriter(a, dir, roster, &.{policy}, .{});
    defer writer.deinit();
    const pins = [_]Stores.FilePin{.{ .index = 2, .byte_len = 100, .sha256 = @splat(1) }};
    var reader = try T.Store.initReader(a, dir, roster, &.{policy}, &pins, .{});
    defer reader.deinit();
}
test "execution leaf store: reader and writer admission allocations unwind without changing exact roster" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try Fixture.init(a);
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const key = try template(&prepared);
    const policy = C.Policy{ .prepared = &prepared, .template = &key };
    try admissionAllocations(a, dir.dir, fixture.roster(), policy);
    try std.testing.checkAllAllocationFailures(a, admissionAllocations, .{ dir.dir, fixture.roster(), policy });
}

fn splitRead(a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, pin: Stores.FilePin, policy: C.Policy) !void {
    var split = try @import("block_v5_recursive_leaf_envelope_parts_v1.zig").readPinned(C, a, dir, path, pin.byte_len, pin.sha256, policy, @import("block_v5_recursive_execution_leaf_files_v1.zig").Limits{});
    defer split.deinit();
}

test "execution leaf store: split input fits exact payload budget detaches proof and unwinds every I/O allocation" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try Fixture.init(a);
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const key = try template(&prepared);
    const policy = C.Policy{ .prepared = &prepared, .template = &key };
    var writer = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{});
    defer writer.deinit();
    var literal = try artifact(a, policy);
    var owns = true;
    defer if (owns) literal.deinit(a);
    try writer.put(2, &literal);
    owns = false;
    const pins = try writer.filePins(a);
    defer a.free(pins);
    var buffer: [96]u8 = undefined;
    const path = try T.fileName(&buffer, 2);
    const Parts = @import("block_v5_recursive_leaf_envelope_parts_v1.zig");
    const payload: usize = @intCast(pins[0].byte_len - Parts.HEADER_BYTES);
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(a, payload);
    defer budget.destroy();
    const bounded = budget.allocator();
    var split = try Parts.readPinned(C, bounded, dir.dir, path, pins[0].byte_len, pins[0].sha256, policy, @import("block_v5_recursive_execution_leaf_files_v1.zig").Limits{});
    var owns_split = true;
    defer if (owns_split) split.deinit();
    try std.testing.expectEqual(payload, budget.snapshot().host_live_bytes);
    var view = try C.decodeMetadataParts(a, &split.header, split.metadata, split.proof, policy, .{});
    defer view.deinit();
    try std.testing.expect(view.proof.ptr == split.proof.ptr);
    try std.testing.expectError(error.InvalidRecursiveExecutionEnvelope, C.decodeMetadataParts(a, &split.header, split.metadata[0 .. split.metadata.len - 1], split.proof, policy, .{}));
    const proof = split.detachProof();
    defer bounded.free(proof);
    split.deinit();
    owns_split = false;
    try std.testing.expectEqual(proof.len, budget.snapshot().host_live_bytes);
    try std.testing.expectEqualStrings("literal NONPROOF sparse execution transport", proof);
    try splitRead(a, dir.dir, path, pins[0], policy);
    try std.testing.checkAllAllocationFailures(a, splitRead, .{ dir.dir, path, pins[0], policy });
    var file = try dir.dir.openFile(path, .{ .mode = .read_write });
    defer file.close();
    try file.seekTo(pins[0].byte_len - 1);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try file.read(&byte));
    byte[0] ^= 1;
    try file.seekTo(pins[0].byte_len - 1);
    try file.writeAll(&byte);
    try std.testing.expectError(error.TamperedV5BundleFileHash, Parts.readPinned(C, a, dir.dir, path, pins[0].byte_len, pins[0].sha256, policy, @import("block_v5_recursive_execution_leaf_files_v1.zig").Limits{}));
}
