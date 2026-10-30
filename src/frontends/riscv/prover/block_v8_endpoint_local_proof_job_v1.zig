//! Owned CPU cohort job. Independent jobs retain no runner/session pointers,
//! share only immutable ELF/ROM, and bind their own worker pools through TLS.
//! Joining precedes every release, including failures and cancellation paths.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Prepare = @import("block_v8_endpoint_execution_v1.zig");
const Proof = @import("block_v8_endpoint_local_proof_v1.zig");
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Collect = @import("block_v8_ram_endpoint_collector_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Program = @import("block_v8_endpoint_local_program_v1.zig");
const Native = @import("blake3_execution_trace.zig");
pub const Preparation = struct {
    execution_ns: u64,
    native_witness_ns: u64,
    endpoint_preparation_ns: u64,
    local_provider_ns: u64,
    runner_segment_release_ns: u64,
    logical_ram_events: usize,
    ram_clock_rows: usize,
    register_clock_rows: usize,
};
/// Conservative reservation BEFORE starting concurrent jobs. It includes raw
/// coefficients, full LDE columns and a complete binary Merkle tree; the real
/// retained lease remains separately checked by the existing owner.
pub fn retainedReservation(matrix: @import("block_v7_memory_trace_v1.zig").Matrix, blowup: u32) !usize {
    if (blowup > 4) return error.UnsupportedEndpointJobBlowup;
    const raw = matrix.size();
    const lde = try std.math.mul(usize, raw, @as(usize, 1) << @intCast(blowup));
    const columns = try std.math.mul(usize, 23 * 4, try std.math.add(usize, raw, lde));
    return std.math.add(usize, 64 << 10, try std.math.add(usize, columns, try std.math.mul(usize, lde, 64)));
}
pub fn For(comptime Options: type, comptime Narrow: type) type {
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        index: u32,
        count: u32,
        trusted: Scope.Trusted,
        image: *const Program.Owned,
        owner: *Native.Owner,
        endpoints: Collect.Owned,
        endpoints_live: bool = true,
        providers: Prepare.LookupPreparation,
        census: Prepare.ProgramCensus,
        program: ROM.ForBackend(Cpu).FirstRound,
        sparse_rom: ?@import("block_v8_sparse_rom_v1.zig").Owned = null,
        frame: Collect.Frame,
        preparation: Preparation,
        options: Options,
        reservation: usize,
        workers: usize,
        proof: ?*Proof.Proof = null,
        failure: ?anyerror = null,
        timing: Proof.ProveTimings = .{},
        original_ns: u64 = 0,
        thread: ?std.Thread = null,
        pub const Completed = struct { narrow: Narrow, proof_ns: u64, core_ns: u64, artifact_ns: u64, bytes: u64 };
        pub fn start(self: *Self, asynchronous: bool) !void {
            if (asynchronous) self.thread = try std.Thread.spawn(.{}, entry, .{self}) else try self.execute();
        }
        fn entry(self: *Self) void {
            self.executeThread() catch |err| {
                self.failure = err;
            };
        }
        fn executeThread(self: *Self) !void {
            var pool: E.work_pool.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = self.workers, .backing_allocator = self.a });
            defer pool.deinit();
            var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            try self.execute();
        }
        fn input(self: *const Self) Scope.Input {
            const plan = if (self.sparse_rom) |sparse| @import("block_v5_program_table_v1.zig").Plan{ .program_root = sparse.trusted.program_root, .leaves = &.{}, .multiplicities = &.{}, .expected_fetches = sparse.trusted.expected_fetches, .log_size = sparse.log_size } else self.census.plan;
            return .{ .rom_flavor = self.options.program_flavor, .native_profile = self.options.native_profile, .sparse_support = if (self.sparse_rom) |sparse| sparse.entries else &.{}, .shape = &self.owner.statement, .frame = self.frame, .cohort_ordinal = self.index, .endpoint_count = @intCast(self.endpoints.endpoints.len), .native_roots = if (self.proof) |proof| proof.native_roots else @splat(@splat(0)), .program_plan = plan, .program_roots = self.program.roots, .lookup_plan = self.providers.plan, .lookup_layout = self.providers.lookup.layout, .lookup_roots = self.providers.lookup.roots };
        }
        fn execute(self: *Self) !void {
            var timer = try std.time.Timer.start();
            self.proof = try Proof.produceWithOptions(self.a, self.trusted, self.input(), self.owner.preprocessed.items, .{ .native_main = self.owner.main.items, .endpoints = &self.endpoints, .endpoint_range = &self.providers.ranges, .program = &self.program, .program_allocator = self.a, .lookup = &self.providers.lookup }, self.options.proof, .{ .batch_native_projections = self.options.batch_native_projections, .native_batch_options = self.options.native_batch_options, .program = self.image, .timings = &self.timing, .max_retained_endpoint_bytes = self.reservation });
            self.original_ns = timer.read();
        }
        pub fn join(self: *Self) void {
            if (self.thread) |thread| {
                thread.join();
                self.thread = null;
            }
        }
        pub fn deinit(self: *Self) void {
            self.join();
            if (self.proof) |proof| proof.deinit();
            self.program.deinit(self.a);
            if (self.sparse_rom) |*plan| plan.deinit();
            self.census.deinit();
            self.providers.deinit();
            if (self.endpoints_live) self.endpoints.deinit();
            self.owner.deinit();
            self.a.destroy(self);
        }
        /// Only the coordinator serializes and publishes source artifacts, so
        /// shared directory/byte-budget accounting is never racy.
        pub fn finish(self: *Self, directory: std.fs.Dir, remaining_bytes: u64) !Completed {
            self.join();
            if (self.failure) |err| return err;
            const proof = self.proof orelse return error.MissingEndpointProofJobResult;
            var timer = try std.time.Timer.start();
            const bytes = try @import("block_v8_endpoint_local_codec_v1.zig").encode(self.a, proof, self.trusted, self.input(), self.options.codec);
            defer self.a.free(bytes);
            const metadata = try @import("block_v8_endpoint_local_statement_wire_v1.zig").encode(self.a, self.trusted, self.input(), self.options.metadata);
            defer self.a.free(metadata);
            var total = try std.math.add(u64, bytes.len, metadata.len);
            if (total > remaining_bytes) return error.EndpointLocalStagingLimit;
            var name: [64]u8 = undefined;
            try directory.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "local-{d}.proof", .{self.index}), .data = bytes });
            try directory.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "local-{d}.json", .{self.index}), .data = metadata });
            var native_cells: u64 = 0;
            for (self.owner.main.items) |column| native_cells += column.values.len;
            const report = try std.json.Stringify.valueAlloc(self.a, .{
                .schema = "stwo-b8-local-cohort-measurement-v1",
                .program_flavor = self.options.program_flavor,
                .rom_selected_pcs = if (self.sparse_rom) |plan| plan.entries.len else self.census.plan.multiplicities.len,
                .rom_log_size = if (self.sparse_rom) |plan| plan.log_size else self.census.plan.log_size,
                .cohort_ordinal = self.index,
                .cohort_count = self.count,
                .frame = self.frame,
                .security_queries = self.trusted.config.fri_config.n_queries,
                .security_pow_bits = self.trusted.config.pow_bits,
                .logical_ram_events = self.preparation.logical_ram_events,
                .endpoint_count = self.endpoints.endpoints.len,
                .ram_clock_rows = self.preparation.ram_clock_rows,
                .register_clock_rows = self.preparation.register_clock_rows,
                .native_main_cells = native_cells,
                .endpoint_cells = self.endpoints.matrix.storage.len,
                .source = proof.summary.source,
                .execution_ns = self.preparation.execution_ns,
                .native_witness_ns = self.preparation.native_witness_ns,
                .endpoint_preparation_ns = self.preparation.endpoint_preparation_ns,
                .local_provider_ns = self.preparation.local_provider_ns,
                .runner_segment_release_ns = self.preparation.runner_segment_release_ns,
                .local_original_ns = self.original_ns,
                .original = self.timing,
                .artifact_work_ns = timer.read(),
                .proof_and_metadata_bytes = total,
            }, .{ .whitespace = .indent_2 });
            defer self.a.free(report);
            total = try std.math.add(u64, total, report.len);
            if (total > remaining_bytes) return error.EndpointLocalStagingLimit;
            try directory.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "local-{d}.stats.json", .{self.index}), .data = report });
            const lease = proof.endpoint_lease orelse return error.MissingEndpointLocalRetention;
            const result = Completed{ .narrow = .{ .endpoints = self.endpoints, .lease = lease, .source = proof.summary.source }, .proof_ns = self.original_ns, .core_ns = self.timing.core_proof_ns, .artifact_ns = timer.read(), .bytes = total };
            proof.endpoint_lease = null;
            self.endpoints_live = false;
            return result;
        }
    };
}
