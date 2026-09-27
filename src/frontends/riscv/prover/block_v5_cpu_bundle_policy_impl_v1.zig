//! Derive transport allocation bounds exclusively from independent complete
//! receiver pins. No proof, file manifest or received claims choose geometry.
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const global = if (capacity) @import("block_v5_capacity_global_receiver_v1.zig") else @import("block_v5_global_receiver_v1.zig");
        const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(capacity);
        const Programs = Stack.Programs;
        const store = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(capacity);
        const seal = @import("block_v5_source_seal_v1.zig");
        const native = Stack.Template;
        const caller = @import("block_v5_precompile_protocol_v1.zig");
        const profile = @import("blake3_ethereum_sha_profile.zig");
        const request = @import("block_v5_program_request_proof_v1.zig");
        const extension = @import("block_v5_program_extension_proof_v1.zig");
        const native_source = @import("block_v5_native_lookup_request_source_v1.zig");
        const caller_source = @import("block_v5_precompile_lookup_source_v1.zig");
        const ordinary = @import("block_execution_sidecar_batch_v2.zig");
        const external = @import("block_execution_external_trace_v2.zig");
        const integer = @import("block_execution_integer_bridge_v2.zig");
        const sidecar_eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
        const ranges = @import("block_v5_range16_v1.zig");
        pub const Owned = struct {
            a: std.mem.Allocator,
            /// These policies borrow shape/statement pointers from independent Pins.
            /// Keep those immutable public pins alive through all Store usage.
            policies: []store.Policy,
            pub fn deinit(self: *Owned) void {
                self.a.free(self.policies);
                self.* = undefined;
            }
        };
        pub fn build(a: std.mem.Allocator, pins: global.Pins, limits: store.Limits) ![]store.Policy {
            return (try collect(a, pins, limits)).policies;
        }
        pub fn collect(a: std.mem.Allocator, pins: global.Pins, limits: store.Limits) !Owned {
            try limits.validate();
            const config = pins.tables.seal.config;
            const memory = pins.memory.memory;
            var extra_native: usize = 0;
            if (pins.memory.readonly) |selected| for (selected.native) |pin| {
                if (pin.pin != null) extra_native = try std.math.add(usize, extra_native, 1);
            };
            const ordinary_count = try std.math.add(usize, 1, try std.math.add(usize, try std.math.add(usize, try std.math.mul(usize, pins.tables.executions.len, 2), try std.math.mul(usize, pins.tables.extensions.len, 2)), try std.math.add(usize, memory.instanceCount(), try std.math.add(usize, memory.rangeRoots().len, pins.tables.providers.len))));
            const count = try std.math.add(usize, ordinary_count, extra_native);
            const metadata = try std.math.mul(usize, count, @sizeOf(store.Policy));
            if (count > limits.max_files or metadata > limits.max_metadata_bytes) return error.V5BundleMetadataResourceLimit;
            try validateStructure(pins);
            const sealed = try pins.validate();
            var policies: std.ArrayList(store.Policy) = .empty;
            errdefer policies.deinit(a);
            try policies.ensureTotalCapacityPrecise(a, count);
            for (pins.tables.executions, 0..) |pin, ordinal| {
                const index: u32 = @intCast(ordinal);
                try pin.admission.require(pins.tables.seal, &pin.shape.public_data);
                if (capacity) try pin.template.admit(pin.shape, pin.external_retirements, pin.template_id) else try pin.template.admit(pin.shape, pin.template_id);
                try pins.tables.catalog.admit(pins.tables.seal, sealed, index, pin.template, pin.template_id);
                const entry = try find(pins.tables.roster, .execution, index);
                if (!std.meta.eql(entry.roots[0], pin.template.fixed_root) or !std.meta.eql(pin.template.config, config) or
                    !std.meta.eql(try Programs.expectedInstance(pin, entry.roots, index), entry.instance_id))
                    return error.UntrustedV5BundleNativeInstance;
                const native_columns = if (capacity) blk: {
                    const plan = try native.Plan.fromShape(pin.shape, pin.external_retirements);
                    try pin.limits.native.require(&plan, pin.shape);
                    break :blk plan.fixed_count + plan.mainCount() + pin.shape.nInteractionColumns();
                } else @as(usize, pin.shape.nPreprocessedColumns()) + pin.shape.nMainColumns() + pin.shape.nInteractionColumns();
                try checkScratch(metadata, native_columns, limits);
                const fixed = try native.columnLogs(a, pin.shape, Programs.externalRetirements(pin), .fixed);
                defer a.free(fixed);
                const main = try native.columnLogs(a, pin.shape, Programs.externalRetirements(pin), .main);
                defer a.free(main);
                const interaction = try native.columnLogs(a, pin.shape, Programs.externalRetirements(pin), .interaction);
                defer a.free(interaction);
                var native_claims: u32 = 0;
                for (pin.shape.component_descs[0..pin.shape.n_components]) |desc|
                    native_claims += @intCast(@import("../air/lookups/opcode_entries.zig").batchCount(desc.family));
                for (pin.shape.infra_descs[0..pin.shape.n_infra]) |desc|
                    native_claims += @import("../air/statement.zig").nClaimedSumsForInfra(desc.kind);
                const native_expected = if (capacity) try (@import("block_v5_native_capacity_artifact_receiver_v1.zig").Policy{ .shape = pin.shape, .external_retirements = pin.external_retirements, .admission = pin.admission, .template = pin.template, .template_id = pin.template_id, .index = index, .sealed = sealed, .pins = pins.tables.seal, .entries = pins.tables.roster, .catalog = pins.tables.catalog, .native_limits = pin.limits.native }).expected(a) else @as(@import("block_v5_native_codec_v3.zig").Expected, .{ .shape = pin.shape, .external_retirements = Programs.externalRetirements(pin), .template_id = pin.template_id, .instance_id = entry.instance_id, .config = config });
                const native_log = if (capacity) try @import("block_v5_native_capacity_codec_v1.zig").maximumProofColumnLog(native_expected) else try native.maximumProofColumnLog(pin.shape, Programs.externalRetirements(pin));
                var np = make(.native, index, sealed.digest, entry.instance_id, entry.roots, native_claims, try four(fixed.len, main.len, interaction.len, core.verifier_types.COMPOSITION_LOG_SPLIT, native_log, @max(maximum(fixed), maximum(main))), config);
                np.native = native_expected;
                policies.appendAssumeCapacity(np);
                const fused_source = Stack.FusedSource;
                const fused_receiver = Stack.FusedReceiver;
                const fused_proof = Stack.Fused;
                const slots = try fused_source.slotsFromShapeForMode(a, pin.shape, Programs.externalRetirements(pin), sealed.register_custody_mode);
                defer a.free(slots);
                const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = pin.shape.public_data.clock };
                const memory_slots = if (capacity) try fused_source.memorySlots(a, pin.shape, pin.external_retirements, frame, sealed.register_custody_mode) else try ordinary.slotsFromStatementForMode(a, pin.shape, frame, sealed.register_custody_mode);
                defer a.free(memory_slots);
                const witness = pins.memory.opcode_witness_roots[index];
                _ = try fused_receiver.admit(a, index, Programs.fusedPin(pin), .{ .frame = frame, .expected_events = pins.memory.ordinary_events[index], .witness_root = witness }, sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
                if (slots.len == 0) {
                    if (memory_slots.len != 0) return error.UntrustedV5BundleEmptyProjection;
                    try @import("block_v5_empty_native_tables_v1.zig").validateShape(a, pin.shape, Programs.externalRetirements(pin));
                } else {
                    const request_entry = try find(pins.tables.roster, .program_request, index);
                    const interaction_count = try std.math.add(usize, try std.math.mul(usize, slots.len, 4), try std.math.mul(usize, memory_slots.len, sidecar_eval.INTERACTION_COUNT));
                    const split = fused_proof.compositionSplit(slots);
                    const log = @max(maxSlots(slots), maxSlots(memory_slots));
                    var geometry = try four(fixed.len, main.len, interaction_count, split, log, @max(maximum(fixed), maximum(main)));
                    if (memory_slots.len != 0) {
                        const composition = geometry.tree_columns[3];
                        geometry.tree_count = 5;
                        geometry.tree_columns = .{ @intCast(fixed.len), @intCast(main.len), @intCast(try std.math.mul(usize, memory_slots.len, integer.COLUMN_COUNT)), @intCast(interaction_count), composition };
                        geometry.sample_width_limits = .{ 2, 6, 1, 2, 1 };
                    }
                    const capacity_expected = if (capacity) try (@import("block_v5_native_capacity_fused_artifact_receiver_v1.zig").Policy{ .index = index, .native = Programs.fusedPin(pin), .memory = .{ .frame = frame, .expected_events = pins.memory.ordinary_events[index], .witness_root = witness }, .sealed = sealed, .pins = pins.tables.seal, .entries = pins.tables.roster, .catalog = pins.tables.catalog }).expected(a) else {};
                    if (capacity) {
                        const cap_codec = @import("block_v5_native_capacity_fused_codec_v1.zig");
                        var inventory = try cap_codec.Inventory.init(a, capacity_expected, .{ .max_claims = limits.max_claims, .max_claim_bytes = limits.max_metadata_bytes, .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes });
                        defer inventory.deinit();
                        const actual = try cap_codec.geometry(capacity_expected, &inventory);
                        geometry = .{ .tree_count = @intCast(actual.tree_count), .tree_columns = actual.tree_columns, .max_column_log = actual.max_log, .max_merkle_log = actual.max_merkle_log, .sample_width_limits = if (actual.tree_count == 4) .{ 1, 1, 2, 1, 1 } else .{ 1, 1, 1, 2, 1 } };
                    }
                    var policy = make(.native_fused, index, sealed.digest, request_entry.instance_id, entry.roots, @intCast(slots.len), geometry, config);
                    policy.expected.memory_claim_count = @intCast(memory_slots.len);
                    if (capacity) policy.capacity_fused = capacity_expected;
                    if (memory_slots.len != 0) {
                        policy.expected.roots[2] = witness;
                        policy.expected.root_count = 3;
                    }
                    // Bind secondary allocation grammar/access roots as well as the
                    // versioned B5FP instance identity into this independent policy.
                    var policy_channel = core.proof_suites.Blake3.Channel{};
                    policy_channel.mixU32s(&.{ if (capacity) fused_proof.TAG else 0x42354650, if (capacity) fused_proof.VERSION else 2, policy.expected.memory_claim_count, policy.expected.root_count });
                    policy_channel.mixRoot(policy.expected.policy_digest);
                    policy_channel.mixRoot(witness);
                    policy.expected.policy_digest = policy_channel.digestBytes();
                    policies.appendAssumeCapacity(policy);
                }
            }
            if (pins.memory.readonly) |selected| {
                var admitted = try selected.authority.admit(a);
                defer admitted.deinit();
                for (selected.native, 0..) |native_pin, index| if (native_pin.pin) |pin| {
                    const expected = try @import("block_v5_readonly_input_transport_policy_v1.zig").native(pin, @intCast(index), admitted.intervals.len, sealed.digest);
                    try expected.validate();
                    policies.appendAssumeCapacity(.{ .execution_recipe = pins.execution_recipe, .expected = expected, .readonly_native = pin, .readonly_seal = sealed.digest });
                };
            }
            for (pins.tables.extensions, 0..) |pin, ordinal| {
                const index = pin.execution_index;
                const entry = try find(pins.tables.roster, .precompile, index);
                const native_entry = try find(pins.tables.roster, .execution, index);
                const key = try caller.keyId(pin.statement, pin.total_steps, config, entry.roots[0]);
                if (!std.meta.eql(key, pin.expected_key_id) or !std.meta.eql(caller.instanceId(key, native_entry.instance_id, index, entry.roots), entry.instance_id))
                    return error.UntrustedV5BundleCallerInstance;
                var columns: usize = 0;
                for (profile.descriptors(pin.statement)) |desc| columns = try std.math.add(usize, columns, desc.preprocessed_columns + desc.main_columns + desc.interaction_columns);
                try checkScratch(metadata, columns, limits);
                const fixed = try caller.columnLogs(a, pin.statement, .fixed);
                defer a.free(fixed);
                const main = try caller.columnLogs(a, pin.statement, .main);
                defer a.free(main);
                const interaction = try caller.columnLogs(a, pin.statement, .interaction);
                defer a.free(interaction);
                var cp = make(.caller, index, sealed.digest, entry.instance_id, entry.roots, 1, try four(fixed.len, main.len, interaction.len, core.verifier_types.COMPOSITION_LOG_SPLIT, maximum(main), @max(maximum(fixed), maximum(main))), config);
                cp.caller_statement = pin.statement;
                cp.caller_key_id = key;
                cp.caller_instance_id = entry.instance_id;
                policies.appendAssumeCapacity(cp);
                if (ordinal >= pins.memory.extensions.len or pins.memory.extensions[ordinal].public.execution_index != index) return error.UntrustedV5BundleCallerMemory;
                const witness = pins.memory.extensions[ordinal].witness_root;
                const native_pin = pins.tables.executions[index];
                const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = native_pin.admission.context.first_cycle, .cycle_count = native_pin.shape.public_data.clock };
                const composite = @import("block_v5_caller_fused_proof_v1.zig");
                const receiver = @import("block_v5_caller_fused_receiver_v1.zig");
                var schedule = try @import("block_v5_caller_fused_schedule_v1.zig").Schedule.init(a, pin.statement, pin.total_steps, frame, sealed.register_custody_mode);
                defer schedule.deinit();
                if (pins.memory.readonly) |selected| {
                    const independent = @import("block_v5_caller_readonly_receiver_v1.zig").Pin{ .statement = pin.statement, .total_steps = pin.total_steps, .execution_instance_id = native_entry.instance_id, .expected_key_id = key, .expected_caller_instance_id = entry.instance_id, .roots = entry.roots, .witness_root = witness, .frame = frame, .expected_rw_events = schedule.rw_events, .readonly = selected.authority };
                    try @import("block_v5_caller_readonly_receiver_v1.zig").admit(a, index, independent, sealed, pins.tables.seal, pins.tables.roster);
                    const expected = try @import("block_v5_readonly_input_transport_policy_v1.zig").callerAt(a, index, independent, config, sealed.digest);
                    if (try expected.totalClaims() > limits.max_claims) return error.UntrustedV5BundleSecurity;
                    policies.appendAssumeCapacity(.{ .execution_recipe = pins.execution_recipe, .expected = expected, .readonly_caller = independent, .readonly_seal = sealed.digest });
                    continue;
                }
                try receiver.admit(a, index, .{ .statement = pin.statement, .total_steps = pin.total_steps, .execution_instance_id = native_entry.instance_id, .expected_key_id = key, .expected_caller_instance_id = entry.instance_id, .roots = entry.roots, .witness_root = witness, .frame = frame, .expected_rw_events = schedule.rw_events }, sealed, pins.tables.seal, pins.tables.roster);
                const request_entry = try find(pins.tables.roster, .program_extension_request, index);
                const column_count = try std.math.add(usize, try std.math.mul(usize, schedule.projectionCount(), 4), try std.math.mul(usize, schedule.memory.len, sidecar_eval.INTERACTION_COUNT));
                const log = @max(@max(maximum(fixed), maximum(main)), @max(maxSlots(schedule.program), @max(maxSlots(schedule.tables), maxSlots(schedule.memory))));
                const composition = core.verifier_types.compositionColumnCount(schedule.split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidV5BundleGeometry;
                const geometry = store.Geometry{ .tree_count = 5, .tree_columns = .{ @intCast(fixed.len), @intCast(main.len), @intCast(try std.math.mul(usize, schedule.memory.len, integer.COLUMN_COUNT)), @intCast(column_count), @intCast(composition) }, .max_column_log = log, .max_merkle_log = @max(log, @max(maximum(fixed), maximum(main))), .sample_width_limits = .{ 2, 6, 1, 2, 1 } };
                var policy = make(.caller_fused, index, sealed.digest, request_entry.instance_id, entry.roots, @intCast(schedule.program.len), geometry, config);
                policy.expected.state_claim_count = @intCast(schedule.program.len);
                policy.expected.table_claim_count = @intCast(schedule.tables.len);
                policy.expected.memory_claim_count = @intCast(schedule.memory.len);
                policy.expected.roots[2] = witness;
                policy.expected.root_count = 3;
                var policy_channel = core.proof_suites.Blake3.Channel{};
                policy_channel.mixU32s(&.{ composite.TAG, composite.VERSION, policy.expected.claim_count, policy.expected.state_claim_count, policy.expected.table_claim_count, policy.expected.memory_claim_count, 3 });
                policy_channel.mixRoot(policy.expected.policy_digest);
                policy_channel.mixRoot(witness);
                policy.expected.policy_digest = policy_channel.digestBytes();
                try policy.expected.validate();
                if (try policy.expected.totalClaims() > limits.max_claims) return error.UntrustedV5BundleSecurity;
                policies.appendAssumeCapacity(policy);
            }
            const rom_entry = try find(pins.tables.roster, .program, 0);
            if (!std.meta.eql(rom_entry.instance_id, try pins.program.digest())) return error.UntrustedV5BundleRom;
            var rom_geometry = try four(@import("../recursion/air/blake3_public_program.zig").PREPROCESSED_COLUMN_COUNT, 0, 4, 2, pins.program.log_size, pins.program.log_size);
            rom_geometry.allow_empty_main_tree = true;
            policies.appendAssumeCapacity(make(.rom, 0, sealed.digest, rom_entry.instance_id, rom_entry.roots, 1, rom_geometry, config));
            const assembly = @import("block_v5_native_lookup_assembly_v1.zig");
            const provider_fixed = try assembly.logs(a, .fixed);
            defer a.free(provider_fixed);
            const provider_main = try assembly.logs(a, .main);
            defer a.free(provider_main);
            const provider_interaction = try assembly.logs(a, .interaction);
            defer a.free(provider_interaction);
            for (pins.tables.providers) |record| {
                const entry = try find(pins.tables.roster, .native_lookup, record.plan.index);
                if (!std.meta.eql(try record.entry(), entry)) return error.UntrustedV5BundleProvider;
                var pp = make(.native_provider, record.plan.index, sealed.digest, entry.instance_id, entry.roots, assembly.Count, try four(provider_fixed.len, provider_main.len, provider_interaction.len, core.verifier_types.COMPOSITION_LOG_SPLIT, maximum(provider_main), maximum(provider_main)), config);
                pp.provider_plan = record.plan;
                policies.appendAssumeCapacity(pp);
            }
            var range_plan = switch (memory) {
                .word => |value| try ranges.plan(a, value.claims, value.request_counts, value.expected_total_events),
                .lanes => |value| try @import("block_v5_ram_lanes_plan_v1.zig").rangePlan(a, value.pins, value.expected_total_events, value.limits.plan),
            };
            defer range_plan.deinit(a);
            switch (memory) {
                .word => |value| {
                    const word = @import("block_v5_word_memory_component_v1.zig").Spec;
                    if (!std.meta.eql(try @import("block_v5_word_memory_receiver_v1.zig").planDigest(a, value.claims, value.memory_roots, value.range_roots, &range_plan), pins.tables.seal.memory_plan_digest)) return error.UntrustedV5BundleMemoryPlan;
                    for (value.claims, value.memory_roots, 0..) |claim, roots, ordinal| {
                        const index: u32 = @intCast(ordinal);
                        const entry = try find(pins.tables.roster, .memory, index);
                        if (!std.meta.eql(entry.roots, roots) or !std.meta.eql(entry.instance_id, @import("block_v5_word_memory_proof_v1.zig").instanceId(claim, index))) return error.UntrustedV5BundlePackedMemory;
                        policies.appendAssumeCapacity(make(.packed_memory, index, sealed.digest, entry.instance_id, roots, 1, try four(word.FIXED_COUNT, word.MAIN_COUNT, word.INTERACTION_COUNT, word.EXPANSION_BITS, claim.log_size, claim.log_size), config));
                    }
                },
                .lanes => |value| {
                    try @import("block_v5_ram_lanes_receiver_v1.zig").admit(a, value, sealed, value.limits);
                    const spec = @import("block_v5_ram_lanes_component_v1.zig").Spec;
                    for (value.pins) |pin| {
                        const entry = try pin.entry();
                        if (!std.meta.eql(entry, try find(pins.tables.roster, .memory, pin.index))) return error.UntrustedV5BundleRamLanes;
                        var policy = make(.ram_lanes, pin.index, sealed.digest, entry.instance_id, pin.roots, 1, try four(spec.FIXED_COUNT, spec.MAIN_COUNT, spec.INTERACTION_COUNT, spec.EXPANSION_BITS, pin.claim.row_log, pin.claim.row_log), config);
                        policy.lane_pin = pin;
                        policy.lane_seal_digest = sealed.digest;
                        policies.appendAssumeCapacity(policy);
                    }
                },
            }
            if (range_plan.shards.len != memory.rangeRoots().len) return error.UntrustedV5BundleRangePlan;
            const range_spec = @import("block_v5_range16_component_v1.zig").Spec;
            for (range_plan.shards, memory.rangeRoots()) |shard, roots| {
                const entry = try find(pins.tables.roster, .memory_range, shard.index);
                if (!std.meta.eql(entry.roots, roots) or !std.meta.eql(entry.instance_id, @import("block_v5_range16_proof_v1.zig").instanceId(range_plan.digest, shard.index))) return error.UntrustedV5BundleRangePlan;
                policies.appendAssumeCapacity(make(.range16, shard.index, sealed.digest, entry.instance_id, roots, 1, try four(range_spec.FIXED_COUNT, range_spec.MAIN_COUNT, range_spec.INTERACTION_COUNT, range_spec.EXPANSION_BITS, ranges.TABLE_LOG, ranges.TABLE_LOG), config));
            }
            std.sort.pdq(store.Policy, policies.items, {}, less);
            for (policies.items) |policy| try policy.expected.validate();
            return .{ .a = a, .policies = try policies.toOwnedSlice(a) };
        }
        /// Check array correspondence before receiver validators or zipped loops can
        /// touch externally decoded metadata. This confers no proof authority.
        pub fn validateStructure(pins: global.Pins) !void {
            try pins.execution_recipe.requireCompiled();
            try pins.execution_recipe.requireMode(pins.tables.seal.register_custody_mode);
            for (pins.tables.executions) |pin| try pins.execution_recipe.requireNative(pin.shape);
            for (pins.memory.executions) |pin| try pins.execution_recipe.requireNative(pin.shape);
            for (pins.tables.extensions) |pin| try pins.execution_recipe.requireCaller(pin.statement, pin.total_steps);
            if (pins.tables.register_windows) |plan| try pins.execution_recipe.requireWindowVersion(plan.version);
            if (pins.memory.register_windows) |plan| try pins.execution_recipe.requireWindowVersion(plan.version);
            const executions = pins.tables.executions.len;
            const memory = pins.memory.memory;
            if (executions == 0 or executions > std.math.maxInt(u32) or
                pins.memory.executions.len != executions or pins.tables.ordinary_events.len != executions or
                pins.memory.ordinary_events.len != executions or pins.memory.opcode_witness_roots.len != executions or
                pins.tables.catalog.records.len != executions or pins.memory.catalog.records.len != executions or
                pins.tables.extensions.len != pins.memory.extensions.len or
                (memory.instanceCount() == 0 and (pins.tables.seal.register_custody_mode != 1 or memory.totalEvents() != 0)))
                return error.InvalidV5BundlePolicyCorrespondence;
            try memory.requireStructure();
            for (pins.tables.extensions, 0..) |extension_pin, index| {
                if (extension_pin.execution_index >= executions or
                    (index != 0 and extension_pin.execution_index <= pins.tables.extensions[index - 1].execution_index) or
                    pins.memory.extensions[index].public.execution_index != extension_pin.execution_index)
                    return error.InvalidV5BundlePolicyCorrespondence;
            }
        }
        fn checkScratch(metadata: usize, columns: usize, limits: store.Limits) !void {
            if (try std.math.add(usize, metadata, try std.math.mul(usize, columns, @sizeOf(u32))) > limits.max_metadata_bytes)
                return error.V5BundleMetadataResourceLimit;
        }
        fn find(entries: []const seal.Entry, family: seal.Family, index: u32) !seal.Entry {
            for (entries) |entry| if (entry.family == family and entry.index == index) return entry;
            return error.MissingV5BundlePolicyEntry;
        }
        fn less(_: void, left: store.Policy, right: store.Policy) bool {
            return if (left.expected.family == right.expected.family) left.expected.index < right.expected.index else @intFromEnum(left.expected.family) < @intFromEnum(right.expected.family);
        }
        fn maximum(logs: []const u32) u32 {
            var result: u32 = 0;
            for (logs) |log| result = @max(result, log);
            return result;
        }
        fn maxSlots(slots: anytype) u32 {
            var result: u32 = 0;
            for (slots) |slot| result = @max(result, slot.log_size);
            return result;
        }
        fn four(fixed: usize, main: usize, interaction: usize, split: u32, log: u32, merkle_log: u32) !store.Geometry {
            const composition = core.verifier_types.compositionColumnCount(split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidV5BundleGeometry;
            return .{ .tree_count = 4, .tree_columns = .{ @intCast(fixed), @intCast(main), @intCast(interaction), @intCast(composition), 0 }, .max_column_log = log, .max_merkle_log = @max(log, merkle_log), .sample_width_limits = .{ 2, 6, 2, 1, 1 } };
        }
        fn five(fixed: usize, main: usize, slots: usize, log: u32, merkle_log: u32) !store.Geometry {
            const composition = core.verifier_types.compositionColumnCount(2, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidV5BundleGeometry;
            return .{ .tree_count = 5, .tree_columns = .{ @intCast(fixed), @intCast(main), @intCast(slots * integer.COLUMN_COUNT), @intCast(slots * sidecar_eval.INTERACTION_COUNT), @intCast(composition) }, .max_column_log = log, .max_merkle_log = @max(log, merkle_log), .sample_width_limits = .{ 2, 6, 1, 2, 1 } };
        }
        fn make(family: store.Family, index: u32, seal_digest: [32]u8, instance_id: [32]u8, roots: seal.Roots, claims: u32, geometry: store.Geometry, config: core.pcs.PcsConfig) store.Policy {
            var channel = core.proof_suites.Blake3.Channel{};
            channel.mixU32s(&.{ if (capacity) 0x42354350 else 0x42354250, 1, @intFromEnum(family), index, claims, geometry.tree_count, geometry.max_column_log, geometry.max_merkle_log });
            channel.mixRoot(seal_digest);
            channel.mixRoot(instance_id);
            for (roots) |root| channel.mixRoot(root);
            channel.mixU32s(&geometry.tree_columns);
            return .{ .expected = .{ .family = family, .index = index, .policy_digest = channel.digestBytes(), .config = config, .roots = .{ roots[0], roots[1], @splat(0) }, .geometry = geometry, .claim_count = claims } };
        }
    };
}
