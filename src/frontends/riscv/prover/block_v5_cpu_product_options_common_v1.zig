//! Shared trusted policy; native proof identities remain separate typed stacks.
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
const MiB: usize = 1024 * 1024;
const GiB: usize = 1024 * MiB;
pub fn ForCapacity(comptime capacity: bool) type {
    const Driver = @import("block_v5_cpu_driver_common_v1.zig").ForCapacity(capacity);
    return struct {
        /// Explicit full requester/PAGE/RAM completion selection. Exact old
        /// collection/security policies remain independently chosen; complete
        /// recursive authority/default activation still needs qualification.
        pub fn optionsWithRecursiveCompletion(profile: Profile, max_executions: u32, workers: usize) !Driver.Options {
            if (!capacity) return error.RecursiveCompletionRequiresCapacityStack;
            var result = options(profile, max_executions, workers);
            result.recursive_families = .{};
            result.source_pages = .{};
            const globals = result.collection.globals;
            const lanes = try @import("block_v5_sorted_memory_replay_v1.zig").laneResources(globals.lane_resources, globals.maximum_memory_log, globals.max_memory_instances, globals.max_range_shards);
            result.recursive_completion = (@import("block_v5_cpu_recursive_completion_v1.zig").Options{}).withOriginalMemory(lanes.stage);
            try result.validate();
            return result;
        }
        pub fn options(profile: Profile, max_executions: u32, workers: usize) Driver.Options {
            const native_limits: @import("block_v5_native_capacity_proof_v1.zig").Limits = .{
                .max_main_cells = 1 << 29,
                .max_public_words = 32 * MiB,
                .max_metadata_bytes = 128 * MiB,
            };
            const ordinary: @import("block_v5_native_memory_stage_v1.zig").Limits = .{
                .register_custody_mode = 1,
                .max_slots = 1024,
                .max_witness_cells = 1 << 30,
                .max_metadata_bytes = 8 * MiB,
            };
            return .{
                .profile = profile,
                .workers = workers,
                .max_roster_entries = 32768,
                .collection = .{
                    .planning = .{ .max_executions = max_executions, .max_rom_words = 1 << 22, .max_metadata_bytes = 256 * MiB, .max_source_bytes = 128 * MiB, .lookup_request_limit = 500_000_000 },
                    .physical = if (capacity) .{ .native = native_limits, .max_metadata_bytes = 128 * MiB } else .{ .max_public_words = 32 * MiB, .max_metadata_bytes = 128 * MiB },
                    .ordinary = if (capacity) .{ .memory = ordinary, .fused = .{
                        .native = native_limits,
                        .max_memory_slots = ordinary.max_slots,
                        .max_witness_cells = ordinary.max_witness_cells,
                        .max_metadata_bytes = ordinary.max_metadata_bytes,
                    } } else ordinary,
                    .fixed_basis = if (capacity) .{} else {},
                    .caller = .{ .register_custody_mode = 1, .max_metadata_bytes = 8 * MiB, .max_external_slots = 1024 },
                    .groups = .{ .request_limit = 500_000_000, .max_groups = max_executions, .max_metadata_bytes = 64 * MiB, .max_counter_file_bytes = 16 * GiB },
                    .globals = .{ .minimum_memory_log = 8, .maximum_memory_log = 22, .max_memory_instances = 8192, .max_range_shards = 8192, .max_program_rows = 1 << 24 },
                    .sorter_chunk_events = 1 << 18,
                },
                .store = .{ .max_files = 65536, .max_file_bytes = 256 * MiB, .max_total_bytes = 64 * GiB, .max_metadata_bytes = 128 * MiB, .max_manifest_bytes = 8 * MiB, .max_claims = 65536, .max_proof_bytes = 128 * MiB },
                .forest = .{ .profile = profile, .lane_count = 1, .total_host_limit = 16 * GiB, .max_execution_count = max_executions, .max_proof_bytes = 128 * MiB, .pool_workers_per_lane = workers },
                .manifest = .{ .max_execution_count = max_executions, .max_manifest_bytes = 128 * MiB, .max_proof_bytes = 128 * MiB },
                .metadata = .{ .max_file_bytes = 512 * MiB, .max_owned_bytes = 4 * GiB, .max_executions = max_executions, .max_roster_entries = 32768, .max_program_words = 1 << 24, .max_schedule_wires = 1 << 22 },
                .cache = .{ .profile = profile, .aggregate_host_byte_limit = 8 * GiB, .worker_options = .{ .worker_count = workers, .host_byte_limit = 8 * GiB, .retained_scratch_limit = 64 * MiB } },
            };
        }
    };
}
