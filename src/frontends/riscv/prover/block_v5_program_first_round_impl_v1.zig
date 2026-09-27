//! Bounded two-pass first-round producer for the v5 global ROM relation.
//! Pass one retains only exact ROM counters and per-segment roots/IDs. A later
//! deterministic replay must reproduce each first root before proving.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const shape = @import("../air/statement.zig");
const native = @import("blake3_commitment_plan.zig");
const census_mod = @import("block_v5_program_census_v1.zig");
const table = @import("block_v5_program_table_proof_v1.zig");
const request = @import("block_v5_program_request_proof_v1.zig");
const extension = @import("block_v5_program_extension_proof_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");

pub const ExtensionPin = struct {
    precompile_instance_id: [32]u8,
    roots: seal.Roots,
    slots: []const extension.Slot,
};

pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const Self = @This();
                const TableApi = table.ForBackend(Backend);
                const RequestApi = request.ForBackend(Backend);
                allocator: std.mem.Allocator,
                census: census_mod.Census,
                native_entries: []seal.Entry,
                request_entries: []seal.Entry,
                extension_entries: []seal.Entry,
                extension_next: u32 = 0,
                native_key_ids: [][32]u8,
                plan_ids: [][32]u8,
                legacy_request_ids: []bool,
                extension_fetches: []u64,
                extension_recorded: []bool,
                next: u32 = 0,
                expected_fetches: ?u64 = null,
                table_roots: ?seal.Roots = null,
                config: ?core.pcs.PcsConfig = null,

                pub fn init(a: std.mem.Allocator, program_root: tree.Digest, complete_rom: []const tree.Leaf, expected_instances: u32) !Self {
                    if (expected_instances == 0) return error.EmptyV5ProgramBatch;
                    var census = try census_mod.Census.init(a, program_root, complete_rom);
                    errdefer census.deinit();
                    const native_entries = try a.alloc(seal.Entry, expected_instances);
                    errdefer a.free(native_entries);
                    const request_entries = try a.alloc(seal.Entry, expected_instances);
                    errdefer a.free(request_entries);
                    const extension_entries = try a.alloc(seal.Entry, expected_instances);
                    errdefer a.free(extension_entries);
                    const native_key_ids = try a.alloc([32]u8, expected_instances);
                    errdefer a.free(native_key_ids);
                    const plan_ids = try a.alloc([32]u8, expected_instances);
                    errdefer a.free(plan_ids);
                    const legacy_request_ids = try a.alloc(bool, expected_instances);
                    errdefer a.free(legacy_request_ids);
                    const extension_fetches = try a.alloc(u64, expected_instances);
                    errdefer a.free(extension_fetches);
                    const extension_recorded = try a.alloc(bool, expected_instances);
                    @memset(extension_fetches, 0);
                    @memset(extension_recorded, false);
                    return .{ .allocator = a, .census = census, .native_entries = native_entries, .request_entries = request_entries, .extension_entries = extension_entries, .native_key_ids = native_key_ids, .plan_ids = plan_ids, .legacy_request_ids = legacy_request_ids, .extension_fetches = extension_fetches, .extension_recorded = extension_recorded };
                }

                pub fn deinit(self: *Self) void {
                    self.allocator.free(self.extension_recorded);
                    self.allocator.free(self.extension_fetches);
                    self.allocator.free(self.native_key_ids);
                    self.allocator.free(self.plan_ids);
                    self.allocator.free(self.legacy_request_ids);
                    self.allocator.free(self.request_entries);
                    self.allocator.free(self.extension_entries);
                    self.allocator.free(self.native_entries);
                    self.census.deinit();
                    self.* = undefined;
                }

                /// The caller may deinit `plan` and every PCS scheme immediately after
                /// this call. SourceSeal admission later binds these exact roots/IDs.
                pub fn add(self: *Self, plan: *const native.Plan, statement: *const shape.Blake3ExecutionStatement, native_key_id: [32]u8, native_instance_id: [32]u8, native_roots: seal.Roots, request_roots: seal.Roots) !void {
                    if (capacity) return error.CapacityProgramRequiresFusedStage;
                    return self.addImpl(plan, statement, native_key_id, native_instance_id, native_roots, request_roots, false);
                }
                /// Scoped B3SHART1 compatibility gate; never label these entries as
                /// native-v5 template admission in a complete receiver.
                pub fn addLegacy(self: *Self, plan: *const native.Plan, statement: *const shape.Blake3ExecutionStatement, native_key_id: [32]u8, native_roots: seal.Roots, request_roots: seal.Roots) !void {
                    if (capacity) return error.CapacityProgramRequiresFusedStage;
                    return self.addImpl(plan, statement, native_key_id, native_key_id, native_roots, request_roots, true);
                }
                fn addImpl(self: *Self, plan: *const native.Plan, statement: *const shape.Blake3ExecutionStatement, native_key_id: [32]u8, native_instance_id: [32]u8, native_roots: seal.Roots, request_roots: seal.Roots, legacy: bool) !void {
                    if (self.table_roots != null or self.next >= self.native_entries.len or
                        !std.meta.eql(native_roots, request_roots))
                        return error.InvalidV5ProgramFirstRound;
                    const slots = try request.slotsFromStatement(self.allocator, statement);
                    defer self.allocator.free(slots);
                    if (slots.len == 0) return error.EmptyV5OpcodeRequestUnqualified;
                    const plan_id = try plan.identity();
                    var segment_fetches: u64 = 0;
                    for (plan.programs) |word|
                        segment_fetches = try std.math.add(u64, segment_fetches, word.multiplicity);
                    const opcode_fetches = try @import("block_v5_program_request_source_v1.zig").exactOpcodeFetchCount(statement.component_descs[0..statement.n_components]);
                    const boundary_fetches: u64 = if (@import("commitment_program_witness.zig").completionFetch(statement.public_data.completion) != null) 1 else 0;
                    const covered = try std.math.add(u64, opcode_fetches, boundary_fetches);
                    if (covered > segment_fetches) return error.InvalidV5ProgramFetchPartition;
                    try self.census.add(plan);
                    const index = self.next;
                    self.native_key_ids[index] = native_key_id;
                    self.plan_ids[index] = plan_id;
                    self.legacy_request_ids[index] = legacy;
                    self.extension_fetches[index] = segment_fetches - covered;
                    self.native_entries[index] = .{ .family = .execution, .index = index, .instance_id = native_instance_id, .roots = native_roots };
                    self.request_entries[index] = .{ .family = .program_request, .index = index, .instance_id = if (legacy) request.instanceId(native_key_id, index, slots) else request.nativeV5InstanceId(native_key_id, native_instance_id, index, slots), .roots = request_roots };
                    self.next += 1;
                }

                /// Plan multiplicities already contain every opcode and precompile
                /// fetch. This records the precompile partition exactly once; it never
                /// increments the global ROM table a second time. The caller supplies
                /// canonical caller fetches from the independently replayed segment.
                pub fn addExtension(self: *Self, index: u32, plan: *const native.Plan, fetches: []const census_mod.Fetch, expected_calls: u64, request_pin: ?ExtensionPin) !void {
                    if (capacity) return error.CapacityProgramRequiresFusedStage;
                    if (self.table_roots != null or index >= self.next or
                        self.extension_recorded[index]) return error.InvalidV5ProgramExtensionCensus;
                    if (!std.meta.eql(try plan.identity(), self.plan_ids[index]))
                        return error.ChangedV5ProgramExtensionPlan;
                    const count = try self.census.validateSubset(plan, fetches);
                    try @import("block_v5_program_lightweight_first_round_v1.zig").recordExtension(self, index, count, expected_calls, request_pin);
                }

                /// Global public admission v3: no per-leaf custody Plan is built.
                pub fn addLightweight(self: *Self, fetches: []const census_mod.Fetch, statement: *const shape.Blake3ExecutionStatement, template_id: [32]u8, native_instance_id: [32]u8, roots: seal.Roots, request_roots: seal.Roots) !void {
                    if (capacity) return error.CapacityProgramRequiresFusedStage;
                    return @import("block_v5_program_lightweight_first_round_v1.zig").add(self, fetches, statement, template_id, native_instance_id, roots, request_roots);
                }
                /// Canonical production v3 identity binds the complete fused program,
                /// table/state/register/clock schedule and explicit register mode.
                pub fn addLightweightFused(self: *Self, fetches: []const census_mod.Fetch, statement: *const shape.Blake3ExecutionStatement, template_id: [32]u8, native_instance_id: [32]u8, roots: seal.Roots, request_roots: seal.Roots, external_retirements: u32, register_custody_mode: u32, frame: @import("../air/block/memory_event.zig").Frame, witness_root: [32]u8) !void {
                    return @import("block_v5_program_fused_first_round_v1.zig").ForCapacity(capacity).add(self, fetches, statement, template_id, native_instance_id, roots, request_roots, external_retirements, register_custody_mode, frame, witness_root);
                }
                pub fn addLightweightExtension(self: *Self, index: u32, complete: []const census_mod.Fetch, subset: []const census_mod.Fetch, expected_calls: u64, pin: ?ExtensionPin) !void {
                    return @import("block_v5_program_lightweight_first_round_v1.zig").addExtension(self, index, complete, subset, expected_calls, pin);
                }

                /// Canonical composite caller identity; the exact ROM census is still
                /// recorded once, using independently replayed complete/subset fetches.
                pub fn addLightweightFusedExtension(self: *Self, index: u32, complete: []const census_mod.Fetch, subset: []const census_mod.Fetch, bound: *const @import("block_v5_caller_pipeline_v1.zig").Bound) !void {
                    try bound.require(self.allocator);
                    if (bound.record.execution.index != index or index >= self.next or
                        !std.meta.eql(bound.record.execution.instance_id, self.native_entries[index].instance_id)) return error.UntrustedV5FusedCallerCensus;
                    if (self.table_roots != null or self.extension_recorded[index] or
                        !std.meta.eql(try @import("block_v5_program_lightweight_first_round_v1.zig").fetchIdentity(self.census.program_root.bytes, complete), self.plan_ids[index])) return error.ChangedV5ProgramExtensionPlan;
                    const count = try self.census.validateFetchSubset(complete, subset);
                    if (count != @import("blake3_ethereum_sha_profile.zig").externalCount(&bound.record.statement) or count != self.extension_fetches[index] or count == 0) return error.IncompleteV5ProgramExtensionCensus;
                    if (self.extension_next != 0 and index <= self.extension_entries[self.extension_next - 1].index) return error.InvalidV5ProgramExtensionCensus;
                    self.extension_entries[self.extension_next] = bound.family12;
                    self.extension_next += 1;
                    self.extension_recorded[index] = true;
                }

                /// Commit the complete ROM after all native schedules are counted, but
                /// release its PCS state before the other block families finish pass1.
                pub fn finish(self: *Self, expected_fetches: u64, config: core.pcs.PcsConfig) !seal.Entry {
                    const plan = try self.finishPlan(expected_fetches, config);
                    var first = try TableApi.commitFirstRound(self.allocator, plan, config);
                    defer first.deinit(self.allocator);
                    const result = seal.Entry{ .family = .program, .index = 0, .instance_id = try table.instanceId(plan), .roots = first.roots };
                    return self.recordFinish(plan, config, result);
                }

                /// Reuse the actual global collector's prechallenge ROM proposal.
                /// This retains plain roots only, never PCS storage or proof authority.
                /// proveTable recommits the exact census and rejects changed roots;
                /// the complete receiver independently verifies the table proof.
                pub fn finishCollected(self: *Self, expected_fetches: u64, config: core.pcs.PcsConfig, actual_program_entry: seal.Entry) !seal.Entry {
                    const plan = try self.finishPlan(expected_fetches, config);
                    return self.recordFinish(plan, config, actual_program_entry);
                }

                fn finishPlan(self: *const Self, expected_fetches: u64, config: core.pcs.PcsConfig) !@import("block_v5_program_table_v1.zig").Plan {
                    if (self.table_roots != null or self.expected_fetches != null or self.config != null or self.next != self.native_entries.len)
                        return error.IncompleteV5ProgramFirstRound;
                    try @import("blake3_execution_protocol.zig").validateConfig(config);
                    var extension_count: u32 = 0;
                    for (self.extension_recorded[0..self.next], self.extension_fetches[0..self.next]) |recorded, count| {
                        if (!recorded) return error.IncompleteV5ProgramExtensionCensus;
                        extension_count += @intFromBool(count != 0);
                    }
                    if (extension_count != self.extension_next) return error.IncompleteV5ProgramExtensionCensus;
                    return self.census.smallestTablePlan(self.next, expected_fetches);
                }

                fn recordFinish(self: *Self, plan: @import("block_v5_program_table_v1.zig").Plan, config: core.pcs.PcsConfig, entry: seal.Entry) !seal.Entry {
                    if (entry.family != .program or entry.index != 0 or
                        !std.meta.eql(entry.instance_id, try table.instanceId(plan))) return error.UntrustedV5CollectedProgramPlan;
                    for (entry.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedV5CollectedProgramRoots;
                    self.expected_fetches = plan.expected_fetches;
                    self.table_roots = entry.roots;
                    self.config = config;
                    return entry;
                }

                pub fn executionEntries(self: *const Self) []const seal.Entry {
                    return self.native_entries[0..self.next];
                }
                pub fn requestEntries(self: *const Self) []const seal.Entry {
                    return self.request_entries[0..self.next];
                }
                pub fn extensionEntries(self: *const Self) []const seal.Entry {
                    return self.extension_entries[0..self.extension_next];
                }

                /// Pass2 reconstructs the fixed/main native-root request scheme from
                /// the same source; a replay mismatch fails before challenges/proving.
                pub fn replayRequest(self: *const Self, index: u32, fixed: []const engine.pcs.ColumnEvaluation, main: []const engine.pcs.ColumnEvaluation, statement: *const shape.Blake3ExecutionStatement, native_key_id: [32]u8) !RequestApi.FirstRound {
                    if (capacity) return error.CapacityProgramRequiresFusedStage;
                    const config = self.config orelse return error.UnfinishedV5ProgramFirstRound;
                    if (index >= self.next or
                        !std.meta.eql(native_key_id, self.native_key_ids[index]))
                        return error.UntrustedV5ProgramReplay;
                    const slots = try request.slotsFromStatement(self.allocator, statement);
                    defer self.allocator.free(slots);
                    const request_id = if (self.legacy_request_ids[index])
                        request.instanceId(native_key_id, index, slots)
                    else
                        request.nativeV5InstanceId(native_key_id, self.native_entries[index].instance_id, index, slots);
                    if (!std.meta.eql(request_id, self.request_entries[index].instance_id)) return error.UntrustedV5ProgramReplay;
                    var first = try RequestApi.commitFirstRound(self.allocator, fixed, main, slots, native_key_id, index, config);
                    errdefer first.deinit(self.allocator);
                    if (!std.meta.eql(first.roots, self.request_entries[index].roots))
                        return error.UntrustedV5ProgramReplay;
                    return first;
                }

                pub fn proveTable(self: *const Self, program_seal: table.Seal) !table.Proof {
                    const config = self.config orelse return error.UnfinishedV5ProgramFirstRound;
                    const expected_roots = self.table_roots orelse return error.UnfinishedV5ProgramFirstRound;
                    const plan = try self.census.smallestTablePlan(self.next, self.expected_fetches orelse return error.UnfinishedV5ProgramFirstRound);
                    var first = try TableApi.commitFirstRound(self.allocator, plan, config);
                    defer first.deinit(self.allocator);
                    if (!std.meta.eql(first.roots, expected_roots)) return error.UntrustedV5ProgramReplay;
                    return TableApi.prove(self.allocator, &first, plan, program_seal);
                }
            };
        }
    };
}
