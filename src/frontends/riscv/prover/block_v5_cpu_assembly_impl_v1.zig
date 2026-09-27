//! Complete canonical roster and independent receiver policy from real plans.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Caller = @import("block_v5_caller_pipeline_v1.zig");
const CallerProtocol = @import("block_v5_precompile_protocol_v1.zig");
const CallerSlots = @import("block_v5_program_extension_slots_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const Collect = @import("block_v5_cpu_collect_v1.zig").ForCapacity(capacity);
        const Driver = @import("block_v5_cpu_driver_admission_v1.zig").ForCapacity(capacity);
        const Program = @import("block_v5_program_first_round_v1.zig").ForCapacity(capacity);
        const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(capacity);
        const Programs = Stack.Programs;
        const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
        const Global = @import("block_v5_global_receiver_impl_v1.zig").ForStack(Stack);
        const Receiver = Stack.FusedReceiver;
        pub const Assembly = struct {
            a: std.mem.Allocator,
            program: Program.ForBackend(Cpu),
            callers: []?Caller.Bound,
            entries: []Seal.Entry,
            executions: []Programs.InstancePin,
            extensions: []Programs.ExtensionPin,
            memory_extensions: []Memory.ExtensionPin,
            ordinary_events: []u64,
            readonly_native: []@import("block_v5_readonly_input_memory_policy_v1.zig").Native,
            readonly_caller: []@import("block_v5_readonly_input_proposal_v1.zig").Census,
            witness_roots: [][32]u8,
            seal_pins: Seal.Pins,
            sealed: Seal.Sealed,
            global_pins: Global.Pins,

            pub fn deinit(self: *Assembly) void {
                const a = self.a;
                a.free(self.witness_roots);
                a.free(self.ordinary_events);
                a.free(self.readonly_native);
                a.free(self.readonly_caller);
                a.free(self.memory_extensions);
                a.free(self.extensions);
                a.free(self.executions);
                a.free(self.entries);
                a.free(self.callers);
                self.program.deinit();
                a.destroy(self);
            }
        };
        pub fn assemble(a: std.mem.Allocator, collected: *Collect.Collected, policy: Driver.InputPolicy, max_entries: usize) !*Assembly {
            const recipe = policy.runner_pins.execution_recipe;
            try recipe.requireCompiled();
            if (collected.execution_recipe != recipe) return error.MixedV5ExecutionRecipe;
            if (collected.bound.entries.len != collected.planning.records.items.len or collected.ordinary.len != collected.bound.entries.len or collected.callers.len != collected.bound.entries.len or collected.bound.admissions.len != collected.bound.entries.len) return error.IncompleteV5CpuAssembly;
            if (!std.meta.eql(collected.globals.sources.final_rw_root, policy.expected_final_rw_root))
                return error.UntrustedV5CpuFinalRwRoot;
            const count = collected.bound.entries.len;
            var extension_count: usize = 0;
            for (collected.callers) |caller| extension_count = try std.math.add(usize, extension_count, @intFromBool(caller != null));
            const globals = try collected.globals.entries(a, max_entries);
            defer a.free(globals);
            const expected_entries = try requiredEntryCount(globals.len, count, extension_count, max_entries);
            const result = try a.create(Assembly);
            errdefer a.destroy(result);
            result.a = a;
            result.program = try Program.ForBackend(Cpu).init(a, policy.runner_pins.program_root, collected.planning.census.leaves, @intCast(count));
            errdefer result.program.deinit();
            result.callers = try a.alloc(?Caller.Bound, count);
            errdefer a.free(result.callers);
            @memset(result.callers, null);
            result.executions = try a.alloc(Programs.InstancePin, count);
            errdefer a.free(result.executions);
            result.extensions = try a.alloc(Programs.ExtensionPin, extension_count);
            errdefer a.free(result.extensions);
            result.memory_extensions = try a.alloc(Memory.ExtensionPin, extension_count);
            errdefer a.free(result.memory_extensions);
            result.readonly_native = try a.alloc(@import("block_v5_readonly_input_memory_policy_v1.zig").Native, if (collected.readonly != null) count else 0);
            errdefer a.free(result.readonly_native);
            result.readonly_caller = try a.alloc(@import("block_v5_readonly_input_proposal_v1.zig").Census, if (collected.readonly != null) extension_count else 0);
            errdefer a.free(result.readonly_caller);
            result.ordinary_events = try a.alloc(u64, count);
            errdefer a.free(result.ordinary_events);
            result.witness_roots = try a.alloc([32]u8, count);
            errdefer a.free(result.witness_roots);
            var entries: std.ArrayList(Seal.Entry) = .empty;
            defer entries.deinit(a);
            try entries.ensureTotalCapacity(a, expected_entries);
            try entries.appendSlice(a, globals);
            var next_extension: usize = 0;
            const register_mode = collected.globals.sources.register_custody_mode;
            try recipe.requireMode(register_mode);
            if (collected.register_windows) |windows| try recipe.requireWindowVersion(windows.version);
            for (collected.planning.records.items, collected.bound.entries, 0..) |*record, execution, index| {
                const native = Collect.nativeMetadata(&record.physical);
                const external = Driver.externalRetirements(&record.physical);
                try recipe.requireNative(&native.shape);
                if (collected.ordinary[index].register_custody_mode != register_mode or
                    (collected.callers[index] != null and collected.callers[index].?.register_custody_mode != register_mode)) return error.MixedV5CpuProjectionScope;
                try result.program.addLightweightFused(record.complete_fetches, &native.shape, native.template_id, execution.instance_id, execution.roots, execution.roots, external, register_mode, collected.ordinary[index].frame, collected.ordinary[index].witness_root);
                result.executions[index] = if (capacity) .{ .shape = &native.shape, .external_retirements = external, .admission = collected.bound.admissions[index], .template = native.template, .template_id = native.template_id, .profile = profile, .limits = collected.capacity_fused_limits } else .{ .shape = &native.shape, .admission = collected.bound.admissions[index], .template = native.template, .template_id = native.template_id, .profile = profile };
                result.ordinary_events[index] = Collect.ordinaryEvents(&collected.ordinary[index]);
                result.witness_roots[index] = collected.ordinary[index].witness_root;
                const access = if (capacity) try collected.ordinary[index].memoryEntry(a, native, collected.bound.admissions[index].context) else try collected.ordinary[index].bind(&record.physical, execution);
                if (capacity) {
                    // Both native and access identities must come from the actual late
                    // bound context; independently cross-check the shared ROM ledger.
                    const projection = try collected.ordinary[index].projectionEntry(a, native, collected.bound.admissions[index].context);
                    if (!std.meta.eql(projection, result.program.requestEntries()[index])) return error.ChangedCapacityCpuProjectionEntry;
                }
                try entries.append(a, access);
                if (collected.callers[index]) |*proposal| {
                    try recipe.requireCaller(&proposal.statement, proposal.total_steps);
                    result.callers[index] = try proposal.lateBind(a, execution.instance_id);
                    const bound = &result.callers[index].?;
                    try result.program.addLightweightFusedExtension(@intCast(index), record.complete_fetches, record.caller_fetches, bound);
                    try entries.append(a, bound.family11);
                    // Program.firstRound owns the one canonical family12 roster below.
                    try entries.append(a, bound.family13);
                    result.extensions[next_extension] = .{ .execution_index = @intCast(index), .statement = &bound.record.statement, .total_steps = bound.record.total_steps, .expected_key_id = bound.record.key_id };
                    result.memory_extensions[next_extension] = .{ .public = result.extensions[next_extension], .witness_root = bound.proposal.witness_root };
                    if (collected.readonly != null) {
                        const physical = bound.proposal.readonly_physical orelse return error.MissingV5CallerReadonlyAuthority;
                        result.readonly_caller[next_extension] = .{ .all_rw = physical.all_rw_events, .mutable = try std.math.sub(u64, physical.all_rw_events, physical.readonly_events), .readonly = physical.readonly_events };
                    }
                    next_extension += 1;
                } else try result.program.addLightweightExtension(@intCast(index), record.complete_fetches, record.caller_fetches, 0, null);
            }
            const program_entry = try result.program.finishCollected(collected.bound.program_plan.expected_fetches, collected.bound.config, collected.globals.program_entry orelse return error.IncompleteV5GlobalProviders);
            if (!std.meta.eql(program_entry, collected.globals.program_entry.?)) return error.ChangedV5CpuRomRoots;
            try entries.appendSlice(a, result.program.executionEntries());
            try entries.appendSlice(a, result.program.requestEntries());
            try entries.appendSlice(a, result.program.extensionEntries());
            if (entries.items.len != expected_entries) return error.IncompleteV5CpuAssembly;
            std.mem.sort(Seal.Entry, entries.items, {}, lessEntry);
            var counts: [Seal.family_count]u32 = @splat(0);
            for (entries.items) |entry| counts[@intFromEnum(entry.family) - 1] =
                try std.math.add(u32, counts[@intFromEnum(entry.family) - 1], 1);
            const digests = try collected.globals.digests();
            result.seal_pins = .{ .job_id = policy.job_id, .source_image_digest = try policy.sourceImageDigest(), .native_template_catalog_digest = try collected.bound.catalogAdmission().digest(), .program_root = policy.runner_pins.program_root.bytes, .program_plan_digest = try collected.bound.program_plan.digest(), .memory_plan_digest = digests.memory_plan_digest, .initial_source_plan_digest = digests.initial_source_plan_digest, .expected_final_rw_root = policy.expected_final_rw_root, .rw_endpoint_plan_digest = digests.rw_endpoint_plan_digest, .register_endpoint_plan_digest = digests.register_endpoint_plan_digest, .register_custody_mode = digests.register_custody_mode, .config = collected.bound.config, .counts = counts };
            if (collected.readonly) |*selected| {
                if (selected.native_count != count) return error.IncompleteReadonlyInputCollection;
                const late = selected.plan orelse return error.IncompleteReadonlyInputCollection;
                var roster = try @import("block_v5_readonly_input_roster_v1.zig").Builder.init(late.digest, selected.selection.digest, @intCast(count), @intCast(extension_count));
                for (selected.native, 0..) |proposal, index| {
                    try proposal.require(proposal.expected);
                    const expected = proposal.expected;
                    try roster.native(@intCast(index), expected.source.all_rw_events, expected.source.row_log, expected.classifier_roots, expected.census);
                }
                for (result.extensions, result.readonly_caller) |extension, census| try roster.caller(extension.execution_index, census);
                result.seal_pins.readonly_roster_digest = try roster.finish();
                try selected.bindRoster(result.seal_pins.readonly_roster_digest);
            }
            try collected.bound.requirePins(result.seal_pins);
            result.entries = try entries.toOwnedSlice(a);
            errdefer a.free(result.entries);
            result.sealed = try Seal.seal(result.seal_pins, result.entries);
            try result.sealed.requireComplete(result.seal_pins, result.entries);
            const catalog = collected.bound.catalogAdmission();
            if (capacity) for (result.executions, collected.ordinary, 0..) |pin, proposal, index| {
                _ = try Receiver.admit(a, @intCast(index), Programs.fusedPin(pin), .{ .frame = proposal.frame, .expected_events = proposal.event_count, .witness_root = proposal.witness_root }, result.sealed, result.seal_pins, result.entries, catalog);
            };
            var readonly_pins: ?@import("block_v5_readonly_input_memory_policy_v1.zig").Pins = null;
            if (collected.readonly) |*selected| {
                if (selected.native_count != count) return error.IncompleteReadonlyInputCollection;
                for (collected.bound.entries, result.readonly_native, 0..) |entry, *pin, index| {
                    const binding = try selected.nativeBinding(@intCast(index));
                    pin.* = .{ .pin = try binding.pinAfterSeal(entry.instance_id, result.sealed, result.seal_pins, result.entries), .census = binding.expected.census };
                }
                readonly_pins = .{ .authority = try selected.authority(), .native = result.readonly_native, .caller = result.readonly_caller };
            }
            result.global_pins = .{ .execution_recipe = recipe, .expected_seal_digest = result.sealed.digest, .program = collected.bound.program_plan, .memory = .{ .memory = collected.globals.receiverPins(result.seal_pins, result.entries, result.sealed), .catalog = catalog, .executions = result.executions, .opcode_witness_roots = result.witness_roots, .ordinary_events = result.ordinary_events, .extensions = result.memory_extensions, .register_windows = collected.register_windows, .readonly = readonly_pins }, .tables = .{ .seal = result.seal_pins, .roster = result.entries, .catalog = catalog, .executions = result.executions, .ordinary_events = result.ordinary_events, .extensions = result.extensions, .providers = collected.groups.records, .register_windows = collected.register_windows } };
            _ = try result.global_pins.validate();
            return result;
        }
        /// Admit the whole roster before allocating per-execution output:
        /// execution/access/request plus sparse caller arithmetic/access/request.
        pub fn requiredEntryCount(globals: usize, executions: usize, callers: usize, maximum: usize) !usize {
            if (executions == 0 or executions > std.math.maxInt(u32) or callers > executions) return error.V5CpuRosterResourceLimit;
            const total = try std.math.add(usize, globals, try std.math.mul(usize, 3, try std.math.add(usize, executions, callers)));
            if (total > maximum) return error.V5CpuRosterResourceLimit;
            return total;
        }
        fn lessEntry(_: void, left: Seal.Entry, right: Seal.Entry) bool {
            return @intFromEnum(left.family) < @intFromEnum(right.family) or
                (left.family == right.family and left.index < right.index);
        }
    };
}
