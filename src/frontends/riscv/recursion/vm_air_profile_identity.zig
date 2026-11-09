//! Canonical SegmentV2 VM AIR profile identity encoding.
//! Receives profile values structurally so protocol bytes have no dependency on
//! profile derivation, component handles, witness generation or prover code.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PROFILE_DOMAIN = "stwo-zig/riscv/recursion/vm-air-profile/v2\x00";
pub const CIRCUIT_PROFILE_DOMAIN = "stwo-zig/riscv/recursion/vm-air-profile/ethereum-circuit/v1\x00";

pub fn compute(self: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    // Preserve the frozen legacy transcript exactly. The opt-in circuit
    // has a disjoint namespace and an explicit selector/version binding.
    if (self.circuit_profile == .legacy_v4) {
        hash.update(PROFILE_DOMAIN);
    } else {
        hash.update(CIRCUIT_PROFILE_DOMAIN);
        hashInt(&hash, u16, @intFromEnum(self.circuit_profile));
    }
    hashInt(&hash, u16, self.format_version);
    hashInt(&hash, u16, self.schema_version);
    hash.update(&self.lookup_manifest_identity);
    hash.update(&self.lookup_authenticated_manifest_identity);
    hashInt(&hash, u16, self.lookup_statement_format_version);
    hash.update(&self.lookup_statement_identity);
    hash.update(&self.lookup_activation_identity);
    hashInt(&hash, u32, self.physical_component_count);
    hashInt(&hash, u32, self.preprocessed_column_count);
    hashInt(&hash, u32, self.main_column_count);
    hashInt(&hash, u32, self.interaction_column_count);
    hashInt(&hash, u32, self.air_instruction_count);
    hashInputProfile(&hash, self.input_profile);
    hashInt(&hash, u32, self.composition_log_split);
    hashInt(&hash, u32, self.composition_log_degree_bound);
    hashInt(&hash, u32, self.max_log_degree_bound);
    hashInt(&hash, u32, @as(u32, @intCast(self.entries.len)));
    for (self.entries) |entry| hashEntry(&hash, entry);
    return hash.finalResult();
}

fn hashEntry(hash: *Sha256, entry: anytype) void {
    hashInt(hash, u32, entry.physical_index);
    hashInt(hash, u32, entry.shard_ordinal);
    hashInt(hash, u8, @intFromBool(entry.active));
    hashInt(hash, u8, @intFromEnum(entry.registry));
    switch (entry.registry) {
        .opcode_semantic => |key| {
            hashInt(hash, u8, @intFromEnum(key.descriptor.family));
            hashInt(hash, u32, key.descriptor.log_size);
            hashInt(hash, u32, key.descriptor.n_rows);
            hashInt(hash, u32, key.descriptor.n_columns);
            hash.update(&key.typed_authority_identity);
        },
        .opcode_lookup => |key| {
            hashInt(hash, u8, @intFromEnum(key.family));
            hash.update(&key.typed_authority_identity);
            hash.update(&key.component_identity);
            hash.update(&key.partition_identity);
            hash.update(&key.layout_identity);
            hash.update(&key.program_identity);
        },
        .infrastructure => |key| {
            hashInt(hash, u32, @intFromEnum(key.kind));
            hashInt(hash, u8, @intFromEnum(key.adapter_kind));
        },
    }
    hashInt(hash, u32, entry.log_size);
    hashInt(hash, u32, entry.n_rows);
    hashTreeSpan(hash, entry.preprocessed);
    hashTreeSpan(hash, entry.main);
    hashTreeSpan(hash, entry.interaction);
    hashInt(hash, u32, entry.constraint_count);
    hashInt(hash, u32, entry.relation_event_count);
    hashInt(hash, u32, entry.interaction_batch_count);
    hashInt(hash, u32, entry.claimed_sum_offset);
    hashInt(hash, u32, entry.claimed_sum_count);
    hashInt(hash, u32, entry.max_constraint_log_degree_bound);
    hashInt(hash, u32, entry.composition_log_split);
}

fn hashTreeSpan(hash: *Sha256, value: anytype) void {
    hashInt(hash, u32, value.offset);
    hashInt(hash, u32, value.sampled_columns);
    hashInt(hash, u32, value.declared_columns);
}

fn hashInputProfile(hash: *Sha256, value: anytype) void {
    hashInt(hash, u32, value.sampled_value_count);
    hashInt(hash, u32, value.claimed_sum_count);
    hashInt(hash, u32, value.relation_challenge_count);
    hashInt(hash, u32, value.transcript_claimed_sum_count);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
