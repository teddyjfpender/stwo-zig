//! Finite semantic manifest. It does NOT expose a verification-key factory:
//! physical lowering, generated source digest, clock-provider AIR, original
//! proof adapter and recursive proof adapter have not been qualified.
const R = @import("relations.zig");
const Range = @import("range_plan.zig");
pub const TAG: u32 = 0x57313653;
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const complete_original_available = false;
pub const complete_recursive_available = false;
/// Dominant NEW kernels only. Legacy/caller adapters must inherit their actual
/// typed source degree and the complete physical profile must audit the max.
pub const maximum_dominant_kernel_degree: u32 = 4;
pub const tuple_width: u32 = 4;
pub const rom_arity: u32 = 5;
pub const legacy_signed_immediate_range16_requests = @import("legacy_adapter.zig").signed_immediate_range16_requests;
pub const signed_immediate_min: i32 = -2048;
pub const signed_immediate_max: i32 = 2047;
pub const semantic_sources = [_][]const u8{ "abi.zig", "relations.zig", "legacy_adapter.zig", "arithmetic.zig", "logic.zig", "load_store.zig", "range_plan.zig", "projection.zig" };
pub const opcode_ids = [_]u32{ 0, 1, 10, 5, 8, 9, 13, 14, 15, 21, 19, 22, 20, 23, 26, 24, 25 };
pub const operations = [_]Range.Operation{ .add, .sub, .addi, .xor, .or_, .and_, .xori, .ori, .andi, .lw, .lb, .lbu, .lh, .lhu, .sw, .sb, .sh };
pub const required_closures = [_][]const u8{
    "all17operationclasses_or_explicit_affine_legacy_adapters",
    "canonical_elf_rom_signed_immediates_and_register_indices",
    "bounded_one_based_cpu_clock_and_exact_retirement_roster",
    "all_register_accesses_x0_initial_and_final_32_registers",
    "all_previous_clock_orders_and_native_caller_interleaving",
    "all_ram_accesses_and_exact_local_endpoint_tuple_bridge",
    "initial_final_snapshot_permissions_and_first_halt",
    "native_terminal_policy_and_expected_output",
    "caller_nonterminal_halt_current_and_plus27_authentication",
    "all_range_bitwise_and_clock_provider_physical_claims",
    "complete_same_root_global_memory_and_recursive_join",
};
/// Canonical manifest framing only. The future key authority MUST additionally
/// mix the generated semantic source digest, all finite physical geometry,
/// exact positive provider tables, policy and first-root roster BEFORE draws.
/// This function alone deliberately cannot nominate or admit a proof key.
pub fn mix(channel: anytype) void {
    channel.mixU32s(&.{ TAG, VERSION, tuple_width, rom_arity, maximum_dominant_kernel_degree, operations.len, legacy_signed_immediate_range16_requests });
    inline for (.{ R.Domain.register_word, R.Domain.ram_word, R.Domain.cpu, R.Domain.rom_signed_imm, R.Domain.range16, R.Domain.range8_8, R.Domain.bitwise_byte, R.Domain.clock_order }) |domain| channel.mixU32s(&.{@intFromEnum(domain)});
    for (operations, opcode_ids) |operation, opcode| {
        const requests = Range.perActiveRow(operation);
        channel.mixU32s(&.{ @intFromEnum(operation), opcode, requests.range16, requests.byte_pairs, requests.bitwise, requests.clock_orders });
    }
    const Projection = @import("projection.zig");
    channel.mixU32s(&.{ 0x5731504c, Projection.VERSION, Projection.fixed_columns.len, 5 });
    inline for (.{ Projection.Profile.add, Projection.Profile.sub, Projection.Profile.addi, Projection.Profile.lw, Projection.Profile.sw }) |profile| {
        const physical = Projection.inventory(profile);
        channel.mixU32s(&.{ @intFromEnum(profile), physical.main, physical.fixed, physical.max_total_degree, physical.register_events, physical.ram_events, physical.clock_events, physical.range16_events, physical.rom_events, physical.cpu_events, physical.semantic_residuals });
    }
}
