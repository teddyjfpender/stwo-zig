//! Semantic metadata slots for joined kernels. Immutable layout, independent
//! of runtime field values and compacted IR parameter discovery order.
const A = @import("stwo_riscv_frontend").rv64_air;
const S = @import("stwo_riscv_cpu_integration").rv64_gkr_source;
pub const cpu_steps: u32 = 0;
pub const initial_pc: u32 = 1;
pub const final_pc: u32 = 5;
pub const epoch: u32 = 9;
pub const rows: u32 = 10;
pub const nonempty: u32 = 11;
pub const calls: u32 = 12;
pub const first_id: u32 = 13;
pub const calls_nonempty: u32 = 14;
pub const source_public: u32 = 15;
pub const local: u32 = source_public + S.Public.count;
pub const local_stride: u32 = 1 + S.Fractions.MAX_ARITY;
pub const local_count: u32 = @typeInfo(S.Fractions.Relation).@"enum".fields.len * local_stride;
pub const weights: u32 = local + local_count;
pub const max_weights: u32 = 256;
pub const eta: u32 = weights + max_weights;
pub const target: u32 = eta + 1;
pub const eq0: u32 = eta + 2;
pub const eq1: u32 = eta + 3;
pub const ram: u32 = eta + 4;
pub const ram_count: u32 = 15;
pub const kio: u32 = ram + ram_count;
pub const kio_count: u32 = 1 + A.crypto.keccak.layout.IO_ARITY;
pub const wire: u32 = kio + kio_count;
pub const wire_count: u32 = 1 + A.crypto.secp256k1.layout.WIRE_ARITY;
pub const claims: u32 = wire + wire_count;
pub const count: u32 = claims + 3;
pub const Namespace = enum(u32) { public, local, binding, shared, claims };
pub const Address = extern struct { namespace: Namespace, index: u32 };
/// Device assembly may gather from independently retained public, local draw,
/// terminal-binding, shared draw and claim reservoirs. No host field feedback.
pub fn address(slot: u32) !Address {
    if (slot >= count) return error.InvalidJoinedParameterSlot;
    if (slot < local) return .{ .namespace = .public, .index = slot };
    if (slot < weights) return .{ .namespace = .local, .index = slot - local };
    if (slot < ram) return .{ .namespace = .binding, .index = slot - weights };
    if (slot < claims) return .{ .namespace = .shared, .index = slot - ram };
    return .{ .namespace = .claims, .index = slot - claims };
}
pub const namespace_counts = [5]u32{ local, local_count, max_weights + 4, ram_count + kio_count + wire_count, 3 };
comptime {
    const abi = @import("abi.zig");
    if (count != abi.joined_parameter_count) @compileError("joined parameter count differs from native ABI");
    for (namespace_counts, abi.joined_namespace_counts) |a, b| if (a != b) @compileError("joined namespace differs from native ABI");
    if (S.Frame.MAX_LOCAL_TERMS > max_weights or count > 1024) @compileError("joined parameter geometry changed");
    if (@sizeOf(Address) != 8 or ram_count != 15) @compileError("joined parameter ABI changed");
}
