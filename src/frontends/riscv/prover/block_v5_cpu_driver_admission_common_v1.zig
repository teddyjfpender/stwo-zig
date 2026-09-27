//! Bounded two-pass driver planning, not proof orchestration or acceptance.
//! Real source pins and ROM census precede late native public admission. Only
//! plain owned metadata survives; pass2 must reproduce every physical root.
const std = @import("std");
const core = @import("stwo_core");
const runner = @import("block_v4_cpu_runner_source.zig"); // Runner only, no v4 proof route.
const census_mod = @import("block_v5_program_census_v1.zig");
const rom = @import("block_v5_program_table_v1.zig");
const lookup = @import("block_v5_native_lookup_plan_v1.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const public_admission = @import("block_v5_native_public_admission_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
pub const Digest = [32]u8;
pub const Fetch = census_mod.Fetch;
pub const Demand = [schema.KIND_COUNT]u64;

pub const SharedLimits = struct {
    max_executions: u32,
    max_rom_words: usize,
    max_metadata_bytes: usize,
    max_source_bytes: usize,
    lookup_request_limit: u64,
    pub fn validate(self: SharedLimits) !void {
        if (self.max_executions == 0 or self.max_rom_words == 0 or self.max_metadata_bytes == 0 or
            self.max_source_bytes == 0 or self.lookup_request_limit == 0 or
            self.lookup_request_limit >= core.fields.m31.Modulus) return error.InvalidV5DriverLimits;
    }
};
pub const SharedInputPolicy = struct {
    runner_pins: runner.Pins,
    job_id: Digest,
    /// Independently admitted final continuation image, pinned before sorting
    /// or source writing; expected_job anchors RW continuity at the input root.
    expected_final_rw_root: Digest,
    /// Borrowed immutable JSON input; retain it through Planning. Source
    /// stores parsed budgets, so raw-file SHA cannot be recovered from Source.
    schedule_json: ?[]const u8 = null,
    /// Versioned identity binds actual ELF/input/oracle/schedule hashes and
    /// the independent job ID. It is a source proposal, not ELF proof authority.
    pub fn sourceImageDigest(self: SharedInputPolicy) !Digest {
        if (std.mem.allEqual(u8, &self.job_id, 0) or std.mem.allEqual(u8, &self.expected_final_rw_root, 0) or self.runner_pins.expected_job == null)
            return error.MissingV5DriverPublicJob;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42354449, self.runner_pins.execution_recipe.callerProtocolVersion() }); // B5DI
        channel.mixRoot(self.job_id);
        channel.mixRoot(self.runner_pins.elf_sha256);
        channel.mixRoot(self.runner_pins.input_sha256);
        channel.mixRoot(self.runner_pins.oracle_sha256);
        channel.mixRoot(self.runner_pins.program_root.bytes);
        channel.mixRoot(self.expected_final_rw_root);
        channel.mixU32s(&.{@intFromBool(self.runner_pins.schedule_json_sha256 != null)});
        if (self.runner_pins.schedule_json_sha256) |hash| channel.mixRoot(hash);
        self.runner_pins.execution_recipe.mixNewSourceIdentity(&channel);
        return channel.digestBytes();
    }
    pub fn requireSource(self: SharedInputPolicy, source: *const runner.Source, limits: SharedLimits) !void {
        try limits.validate();
        if (source.execution_recipe != self.runner_pins.execution_recipe) return error.MixedV5ExecutionRecipe;
        _ = try self.sourceImageDigest();
        const bytes = try std.math.add(usize, source.elf.len, try std.math.add(usize, source.input.len, source.oracle.len));
        if (bytes > limits.max_source_bytes or source.schedule.segments > limits.max_executions)
            return error.V5DriverSourceResourceLimit;
        if ((self.runner_pins.schedule_json_sha256 != null) != (self.schedule_json != null) or
            (self.schedule_json != null) != (source.owned_budgets != null))
            return error.UntrustedV5DriverSchedule;
        if (self.schedule_json) |json| {
            if (json.len > limits.max_source_bytes or
                try std.math.mul(usize, json.len, @sizeOf(u32)) > limits.max_metadata_bytes or
                !std.meta.eql(hashBytes(json), self.runner_pins.schedule_json_sha256.?))
                return error.UntrustedV5DriverSchedule;
            var parsed = try std.json.parseFromSlice([]u32, source.allocator, json, .{});
            defer parsed.deinit();
            if (!std.mem.eql(u32, parsed.value, source.owned_budgets.?)) return error.UntrustedV5DriverSchedule;
        }
        if (!std.meta.eql(source.job, self.runner_pins.expected_job.?) or
            !std.meta.eql(source.planned.first.program, self.runner_pins.program_root) or
            !std.meta.eql(source.planned.last.program, self.runner_pins.program_root) or
            !std.meta.eql(source.planned.first.machine.rw_memory, self.runner_pins.initial_rw_root) or
            !std.meta.eql(source.planned.last.machine.rw_memory.bytes, self.expected_final_rw_root) or
            !std.meta.eql(hashBytes(source.elf), self.runner_pins.elf_sha256) or
            !std.meta.eql(hashBytes(source.input), self.runner_pins.input_sha256) or
            !std.meta.eql(hashBytes(source.oracle), self.runner_pins.oracle_sha256))
            return error.UntrustedV5DriverSource;
    }
};
fn hashBytes(bytes: []const u8) Digest {
    var result: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

pub const SharedGlobalPlans = struct {
    register_custody_mode: u32 = 0,
    memory_plan_digest: Digest,
    initial_source_plan_digest: Digest,
    rw_endpoint_plan_digest: Digest,
    register_endpoint_plan_digest: Digest,
    pub fn validate(self: SharedGlobalPlans) !void {
        if (self.register_custody_mode > 1) return error.InvalidV5RegisterCustodyMode;
        inline for (.{ "memory_plan_digest", "initial_source_plan_digest", "rw_endpoint_plan_digest", "register_endpoint_plan_digest" }) |name|
            if (std.mem.allEqual(u8, &@field(self, name), 0)) return error.IncompleteV5DriverGlobalPlans;
    }
};

pub fn ForCapacity(comptime capacity: bool) type {
    const proposal = if (capacity) @import("block_v5_cpu_capacity_root_proposal_v1.zig") else @import("block_v5_cpu_native_root_proposal_v1.zig");
    const catalog = if (capacity) @import("block_v5_native_capacity_catalog_v1.zig") else @import("block_v5_native_template_catalog_v1.zig");
    const Metadata = if (capacity) @import("block_v5_native_capacity_proof_v1.zig").Proposal else proposal.Proposal;
    return struct {
        pub const Limits = SharedLimits;
        pub const InputPolicy = SharedInputPolicy;
        pub const GlobalPlans = SharedGlobalPlans;
        /// One immutable view over the genuinely owned family metadata. It
        /// cannot move ownership or grant proof authority.
        pub fn nativeMetadata(physical: *const proposal.Proposal) *const Metadata {
            return if (capacity) &physical.physical else physical;
        }
        pub fn externalRetirements(physical: *const proposal.Proposal) u32 {
            const metadata = nativeMetadata(physical);
            return if (capacity) metadata.external_retirements else metadata.template.external_retirements;
        }
        pub fn validatePhysical(physical: *const proposal.Proposal) !void {
            const metadata = nativeMetadata(physical);
            const io = metadata.shape.public_data.io_entries;
            const expected = try std.math.add(usize, @sizeOf(proposal.Proposal), try std.math.add(usize, try std.math.mul(usize, io.input_words.len, @sizeOf(u32)), try std.math.mul(usize, io.output_words.len, @sizeOf(@import("../air/public_data.zig").OutputWord))));
            if (physical.metadata_bytes != expected or physical.first_cycle == 0 or metadata.shape.total_steps == 0 or
                physical.last_cycle != try std.math.add(u64, physical.first_cycle, metadata.shape.total_steps - 1))
                return error.InvalidV5DriverPhysicalMetadata;
            if (capacity) try physical.validate();
        }
        pub const Record = struct {
            physical: proposal.Proposal,
            complete_fetches: []Fetch,
            caller_fetches: []Fetch,
            lookup_demand: Demand,
            fn deinit(self: *Record, a: std.mem.Allocator) void {
                a.free(self.caller_fetches);
                a.free(self.complete_fetches);
                self.physical.deinit();
            }
        };
        pub const Bound = struct {
            a: std.mem.Allocator,
            config: core.pcs.PcsConfig,
            register_endpoint_plan_digest: Digest,
            /// Borrows Planning.census; Planning must outlive this plan and proving.
            program_plan: rom.Plan,
            lookup_plans: []lookup.Plan,
            admissions: []public_admission.Admission,
            entries: []seal.Entry,
            catalog_records: []catalog.Record,
            pub fn deinit(self: *Bound) void {
                self.a.free(self.catalog_records);
                self.a.free(self.entries);
                self.a.free(self.admissions);
                self.a.free(self.lookup_plans);
                self.* = undefined;
            }
            pub fn catalogAdmission(self: *const Bound) catalog.Admission {
                return .{ .records = self.catalog_records };
            }
            /// No B5SS seal is manufactured here. The complete caller supplies all
            /// families, plans and roots, then requires these exact candidates.
            pub fn requirePins(self: *const Bound, pins: seal.Pins) !void {
                if (!std.meta.eql(self.config, pins.config) or
                    !std.meta.eql(self.register_endpoint_plan_digest, pins.register_endpoint_plan_digest) or
                    !std.meta.eql(try self.program_plan.digest(), pins.program_plan_digest) or
                    !std.meta.eql(try self.catalogAdmission().digest(), pins.native_template_catalog_digest) or
                    !std.mem.allEqual(u8, &pins.native_template_id, 0) or
                    pins.counts[@intFromEnum(seal.Family.execution) - 1] != self.entries.len)
                    return error.UntrustedV5DriverBoundPlans;
                for (self.admissions) |pin| try pin.context.require(pins);
            }
        };

        pub const Planning = struct {
            a: std.mem.Allocator,
            policy: InputPolicy,
            config: core.pcs.PcsConfig,
            limits: Limits,
            census: census_mod.Census,
            records: std.ArrayList(Record) = .empty,
            metadata_bytes: usize,
            failed: bool = false,
            bound: bool = false,

            pub fn initFromSource(a: std.mem.Allocator, source: *const runner.Source, policy: InputPolicy, complete_rom: []const tree.Leaf, config: core.pcs.PcsConfig, limits: Limits) !Planning {
                try policy.requireSource(source, limits);
                try @import("blake3_execution_protocol.zig").validateConfig(config);
                if (!std.meta.eql(source.job.complete.protocol_id, @import("../recursion/blake3_block_execution_span_v3.zig").protocolIdentity(config)))
                    return error.UntrustedV5DriverConfig;
                if (complete_rom.len / 4 > limits.max_rom_words) return error.V5DriverRomResourceLimit;
                const rom_bytes = try std.math.add(usize, try std.math.mul(usize, complete_rom.len, @sizeOf(tree.Leaf)), try std.math.mul(usize, complete_rom.len / 4, @sizeOf(u64)));
                const record_bytes = try std.math.mul(usize, source.schedule.segments, @sizeOf(Record));
                const bytes = try std.math.add(usize, rom_bytes, record_bytes);
                if (bytes > limits.max_metadata_bytes) return error.V5DriverMetadataResourceLimit;
                var census = try census_mod.Census.init(a, policy.runner_pins.program_root, complete_rom);
                errdefer census.deinit();
                var records: std.ArrayList(Record) = .empty;
                try records.ensureTotalCapacityPrecise(a, source.schedule.segments);
                return .{ .a = a, .policy = policy, .config = config, .limits = limits, .census = census, .records = records, .metadata_bytes = bytes };
            }
            pub fn deinit(self: *Planning) void {
                for (self.records.items) |*record| record.deinit(self.a);
                self.records.deinit(self.a);
                self.census.deinit();
                self.* = undefined;
            }
            /// Success moves the proposal. Fetches are bounded owned multiplicity
            /// metadata, not runner rows; callers may later spool them externally.
            pub fn append(self: *Planning, physical: *proposal.Proposal, complete: []const Fetch, callers: []const Fetch, demand: Demand) !void {
                if (self.failed or self.bound) return error.InvalidV5DriverPlanningPhase;
                errdefer self.failed = true;
                const job = self.policy.runner_pins.expected_job.?;
                if (self.records.items.len >= job.segment_count or nativeMetadata(physical).index != self.records.items.len or
                    !std.meta.eql(nativeMetadata(physical).template.config, self.config) or
                    nativeMetadata(physical).shape.public_data.program_root == null or
                    !std.meta.eql(nativeMetadata(physical).shape.public_data.program_root.?.bytes, self.policy.runner_pins.program_root.bytes))
                    return error.UntrustedV5DriverProposal;
                try self.policy.runner_pins.execution_recipe.requireNative(&nativeMetadata(physical).shape);
                // The segmented public contract supplies block input only once and
                // output only on the terminal leaf. Never clone block-sized I/O into
                // every proposal merely because a caller passed unsegmented data.
                const io = nativeMetadata(physical).shape.public_data.io_entries;
                if ((nativeMetadata(physical).index != 0 and (io.input_words.len != 0 or io.input_len != 0)) or
                    (nativeMetadata(physical).index + 1 != job.segment_count and (io.output_words.len != 0 or io.output_len != 0)))
                    return error.InvalidV5DriverSegmentIo;
                const expected_first: u64 = if (self.records.items.len == 0) 1 else try std.math.add(u64, self.records.items[self.records.items.len - 1].physical.last_cycle, 1);
                const expected_pc = if (self.records.items.len == 0) job.complete.initial_state.pc else nativeMetadata(&self.records.items[self.records.items.len - 1].physical).shape.final_pc;
                if (physical.first_cycle != expected_first or nativeMetadata(physical).shape.initial_pc != expected_pc or
                    physical.last_cycle > job.complete.total_cycles) return error.V5DriverDiscontinuousSpan;
                try validatePhysical(physical);
                const fetch_bytes = try std.math.mul(usize, try std.math.add(usize, complete.len, callers.len), @sizeOf(Fetch));
                // Record storage is already counted. Count proposal-owned I/O here.
                const bytes = try std.math.add(usize, self.metadata_bytes, try std.math.add(usize, physical.metadata_bytes - @sizeOf(proposal.Proposal), fetch_bytes));
                if (bytes > self.limits.max_metadata_bytes) return error.V5DriverMetadataResourceLimit;
                _ = try self.census.validateFetchSubset(complete, callers);
                var request_total: u64 = 0;
                const native_demand = try lookup.nativeDemand(&nativeMetadata(physical).shape, externalRetirements(physical));
                for (demand, native_demand) |count, minimum| {
                    if (count < minimum) return error.UntrustedV5DriverLookupDemand;
                    request_total = try std.math.add(u64, request_total, count);
                }
                if (request_total > self.limits.lookup_request_limit) return error.BlockV5LookupGroupExceedsField;
                const owned_complete = try self.a.dupe(Fetch, complete);
                errdefer self.a.free(owned_complete);
                const owned_callers = try self.a.dupe(Fetch, callers);
                errdefer self.a.free(owned_callers);
                try self.census.addFetches(complete);
                self.records.appendAssumeCapacity(.{ .physical = physical.*, .complete_fetches = owned_complete, .caller_fetches = owned_callers, .lookup_demand = demand });
                physical.* = undefined;
                self.metadata_bytes = bytes;
            }
            /// Global digests must come from actual memory/source collection. This
            /// method binds existing plan identities; it never fabricates providers.
            pub fn bind(self: *Planning, globals: GlobalPlans) !Bound {
                if (self.failed or self.bound) return error.InvalidV5DriverPlanningPhase;
                try globals.validate();
                const job = self.policy.runner_pins.expected_job.?;
                if (self.records.items.len != job.segment_count or self.records.items.len == 0)
                    return error.IncompleteV5DriverCensus;
                const last = &self.records.items[self.records.items.len - 1].physical;
                if (last.last_cycle != job.complete.total_cycles or nativeMetadata(last).shape.final_pc != job.complete.final_state.pc)
                    return error.IncompleteV5DriverSpan;
                const program_plan = try self.census.smallestTablePlan(job.segment_count, self.census.total_fetches);
                const program_digest = try program_plan.digest();
                // Admit even the temporary demand array and worst-case one group per
                // execution before allocating any late-binding output.
                const binding_bytes = try std.math.mul(usize, self.records.items.len, @sizeOf(Demand) + @sizeOf(lookup.Plan) + @sizeOf(public_admission.Admission) + @sizeOf(seal.Entry) + @sizeOf(catalog.Record));
                if (try std.math.add(usize, self.metadata_bytes, binding_bytes) > self.limits.max_metadata_bytes)
                    return error.V5DriverMetadataResourceLimit;
                const demands = try self.a.alloc(Demand, self.records.items.len);
                defer self.a.free(demands);
                for (demands, self.records.items) |*target, record| target.* = record.lookup_demand;
                const plans = try lookup.buildRoster(self.a, demands, self.limits.lookup_request_limit);
                errdefer self.a.free(plans);
                const pins = try self.a.alloc(public_admission.Admission, self.records.items.len);
                errdefer self.a.free(pins);
                const entries = try self.a.alloc(seal.Entry, self.records.items.len);
                errdefer self.a.free(entries);
                const templates = try self.a.alloc(catalog.Record, self.records.items.len);
                errdefer self.a.free(templates);
                const image = try self.policy.sourceImageDigest();
                for (self.records.items, pins, entries, templates) |record, *pin, *entry, *template| {
                    const candidate = try record.physical.bind(.{ .job_id = self.policy.job_id, .source_image_digest = image, .program_root = self.policy.runner_pins.program_root.bytes, .program_plan_digest = program_digest, .memory_plan_digest = globals.memory_plan_digest, .initial_source_plan_digest = globals.initial_source_plan_digest, .rw_endpoint_plan_digest = globals.rw_endpoint_plan_digest, .register_custody_mode = globals.register_custody_mode, .register_endpoint_plan_digest = if (globals.register_custody_mode == 1) globals.register_endpoint_plan_digest else @splat(0), .execution_index = nativeMetadata(&record.physical).index, .first_cycle = record.physical.first_cycle, .last_cycle = record.physical.last_cycle });
                    pin.* = candidate.admission;
                    entry.* = candidate.entry;
                    template.* = candidate.catalog_record;
                }
                self.bound = true;
                return .{ .a = self.a, .config = self.config, .register_endpoint_plan_digest = globals.register_endpoint_plan_digest, .program_plan = program_plan, .lookup_plans = plans, .admissions = pins, .entries = entries, .catalog_records = templates };
            }
        };
    };
}
