//! One transaction for the combined Ethereum extension witness.
//!
//! The independently retained runner tapes are cross-bound before any large
//! trace allocation. Keccak and signer rows then enter one owned extension
//! value whose deinitializer mirrors construction order exactly.

const std = @import("std");
const keccak_calls_mod = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod = @import("../../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const keccak_caller = @import("../../air/guest_precompile/keccakf_caller.zig");
const keccak_counters = @import("../../air/guest_precompile/keccakf_multiplicities.zig");
const keccak_trace = @import("../../air/guest_precompile/keccakf_trace.zig");
const recovery_caller = @import("../../air/guest_precompile/secp256k1_recovery_caller.zig");
const recovery = @import("../../air/guest_precompile/secp256k1_recovery.zig");
const secp_affine = @import("../../air/guest_precompile/secp256k1_affine.zig");
const secp_bundle = @import("../../air/guest_precompile/secp256k1_component_bundle.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");

pub const Witness = struct {
    allocator: std.mem.Allocator,
    keccak_counters: keccak_counters.Counters,
    keccak_shard: keccak_trace.Shard,
    secp_tape: secp_affine.Tape,
    secp: secp_bundle.Bundle,
    recovery_caller: secp_bundle.RecoveryCallerTrace,

    pub fn init(
        allocator: std.mem.Allocator,
        keccak_calls: []const keccak_calls_mod.Record,
        keccak_rows: []const keccak_rows_mod.ExecutionRow,
        recovery_calls: []const recovery_calls_mod.Record,
        recovery_rows: []const recovery_rows_mod.ExecutionRow,
        total_steps: u32,
    ) !Witness {
        try keccak_caller.preflight(keccak_calls, keccak_rows, total_steps);
        try recovery_caller.preflight(recovery_calls, recovery_rows, total_steps);
        try validateClockUnion(keccak_calls, recovery_calls);

        var counters = try keccak_counters.Counters.init(allocator);
        errdefer counters.deinit();
        var shard = try keccak_trace.generateShard(
            allocator,
            keccak_calls,
            0,
            &counters,
        );
        errdefer shard.deinit();
        try counters.validateTotals();

        var tape = secp_affine.Tape.init(allocator);
        errdefer tape.deinit();
        for (recovery_calls) |record| try recovery.recover(
            &tape,
            record.digest_big_endian,
            record.r_big_endian,
            record.s_big_endian,
            record.recovery_id,
            record.public_key_xy_big_endian,
        );
        if (tape.recoveries.items.len != recovery_calls.len)
            return error.RecoveryCountMismatch;
        var secp = try secp_bundle.generate(allocator, &tape);
        errdefer secp.deinit();
        var caller = try secp_bundle.generateRecoveryCaller(
            allocator,
            recovery_calls,
        );
        errdefer caller.deinit();

        return .{
            .allocator = allocator,
            .keccak_counters = counters,
            .keccak_shard = shard,
            .secp_tape = tape,
            .secp = secp,
            .recovery_caller = caller,
        };
    }

    pub fn deinit(self: *Witness) void {
        self.recovery_caller.deinit();
        self.secp.deinit();
        self.secp_tape.deinit();
        self.keccak_shard.deinit();
        self.keccak_counters.deinit();
        self.* = undefined;
    }

    pub fn shapes(self: *const Witness) statement_mod.SecpShapes {
        const signer_rows: ?u32 = if (self.secp_tape.recoveries.items.len == 0)
            0
        else
            null;
        return .{
            .product_base = shapeLogical(&self.secp.product_base, signer_rows),
            .product_scalar = shapeLogical(&self.secp.product_scalar, signer_rows),
            .linear_base = shapeLogical(&self.secp.linear_base, signer_rows),
            .linear_scalar = shapeLogical(&self.secp.linear_scalar, signer_rows),
            .point = shapeLogical(&self.secp.point, signer_rows),
            .split = shapeLogical(&self.secp.split, signer_rows),
            .scalar = shapeLogical(&self.secp.scalar, signer_rows),
            .table = shapeLogical(&self.secp.table, signer_rows),
            .recovery = shapeLogical(&self.secp.recovery, signer_rows),
            .byte = shape(&self.secp.byte),
            .recovery_caller = shapeLogical(&self.recovery_caller, signer_rows),
        };
    }
};

fn shape(trace: anytype) statement_mod.Shape {
    return .{ .log_size = trace.log_size, .n_rows = @intCast(trace.n_rows) };
}

fn shapeLogical(trace: anytype, override: ?u32) statement_mod.Shape {
    return .{
        .log_size = trace.log_size,
        .n_rows = override orelse @intCast(trace.n_rows),
    };
}

/// Both tapes are independently ordered by their caller AIRs. This merge
/// rejects duplicate or inverted clocks across families without sorting or
/// allocating, keeping the statement's external-retirement count exact.
fn validateClockUnion(
    keccak: []const keccak_calls_mod.Record,
    recovery_records: []const recovery_calls_mod.Record,
) !void {
    var keccak_index: usize = 0;
    var recovery_index: usize = 0;
    var previous: u32 = 0;
    while (keccak_index < keccak.len or recovery_index < recovery_records.len) {
        const take_keccak = recovery_index == recovery_records.len or
            (keccak_index < keccak.len and
                keccak[keccak_index].execution_clock <
                    recovery_records[recovery_index].execution_clock);
        const clock = if (take_keccak)
            keccak[keccak_index].execution_clock
        else
            recovery_records[recovery_index].execution_clock;
        if (clock <= previous) return error.ExternalClockOrderMismatch;
        previous = clock;
        if (take_keccak)
            keccak_index += 1
        else
            recovery_index += 1;
    }
}

test "Ethereum witness clock merge rejects cross-family aliasing" {
    var keccak: [2]keccak_calls_mod.Record = undefined;
    var signer: [2]recovery_calls_mod.Record = undefined;
    keccak[0].execution_clock = 2;
    keccak[1].execution_clock = 5;
    signer[0].execution_clock = 3;
    signer[1].execution_clock = 7;
    try validateClockUnion(&keccak, &signer);
    signer[0].execution_clock = 5;
    try std.testing.expectError(
        error.ExternalClockOrderMismatch,
        validateClockUnion(&keccak, &signer),
    );
}
