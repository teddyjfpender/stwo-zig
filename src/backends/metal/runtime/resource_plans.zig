//! Host-side layouts and ownership wrappers for prepared Metal resources.

const std = @import("std");

extern fn stwo_zig_metal_arena_copy_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_witness_feed_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_witness_feed_batch_destroy(batch: ?*anyopaque) void;
extern fn stwo_zig_metal_circle_lde_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_circle_ifft_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_fixed_table_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_fixed_table_batch_destroy(batch: ?*anyopaque) void;
extern fn stwo_zig_metal_merkle_parent_chain_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_merkle_leaf_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_resident_merkle_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_ec_op_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_compact_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_eval_library_destroy(library: ?*anyopaque) void;
extern fn stwo_zig_metal_eval_library_serialize(
    library: *anyopaque,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
extern fn stwo_zig_metal_eval_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_base_polynomial_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_lookup_polynomial_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_witness_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_eval_batch_destroy(batch: ?*anyopaque) void;
extern fn stwo_zig_metal_composition_finalize_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_composition_lde_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_composition_inputs_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_composition_front_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_relation_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_fri_fold_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_quotient_combine_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_fri_round_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_fri_tree_plan_destroy(plan: ?*anyopaque) void;
extern fn stwo_zig_metal_fri_final_plan_destroy(plan: ?*anyopaque) void;

/// Binds resource helpers to the runtime's public error set without creating a
/// dependency cycle between the runtime facade and its implementation module.
pub fn ResourcePlans(comptime MetalError: type) type {
    return struct {
        pub const ArenaCopyPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *ArenaCopyPlan) void {
                stwo_zig_metal_arena_copy_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const WitnessFeedPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *WitnessFeedPlan) void {
                stwo_zig_metal_witness_feed_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const WitnessFeedBatchPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *WitnessFeedBatchPlan) void {
                stwo_zig_metal_witness_feed_batch_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const CircleLdePlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *CircleLdePlan) void {
                stwo_zig_metal_circle_lde_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const CircleIfftPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *CircleIfftPlan) void {
                stwo_zig_metal_circle_ifft_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const FixedTablePlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *FixedTablePlan) void {
                stwo_zig_metal_fixed_table_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const FixedTableBatchPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *FixedTableBatchPlan) void {
                stwo_zig_metal_fixed_table_batch_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const MerkleParentChainPlan = struct {
            handle: *anyopaque,
            required_arena_bytes: usize,

            pub fn deinit(self: *MerkleParentChainPlan) void {
                stwo_zig_metal_merkle_parent_chain_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const MerkleLeafPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *MerkleLeafPlan) void {
                stwo_zig_metal_merkle_leaf_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const ResidentMerklePlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *ResidentMerklePlan) void {
                stwo_zig_metal_resident_merkle_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const EcOpPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *EcOpPlan) void {
                stwo_zig_metal_ec_op_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const CompactLayout = struct {
            tuple_words: u32,
            key_words: u32,
            total_rows: u32,
            sort_rows: u32,
            consumer_rows: u32,
            tuples_offset: u32,
            indices_a_offset: u32,
            indices_b_offset: u32,
            counts_offset: u32,
            radix_offsets_offset: u32,
            bases_offset: u32,
            heads_offset: u32,
            positions_offset: u32,
            block_sums_offset: u32,
            error_offset: u32,
            unique_offset: u32,
            enabler_slot: u32 = std.math.maxInt(u32),
            multiplicity_slot: u32,
            iota_slot: u32 = std.math.maxInt(u32),
        };

        pub const CompactPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *CompactPlan) void {
                stwo_zig_metal_compact_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const EvalLayout = struct {
            trace_offsets: u32,
            interaction_offsets: u32,
            base_params: u32,
            ext_params: u32,
            random_coeffs: u32,
            denom_inv: u32,
            coordinates: [4]u32,
            row_count: u32,
            trace_log_size: u32,
            domain_log_size: u32,
            rc_base: u32,
        };

        pub const WitnessLayout = extern struct {
            input_offsets: u32,
            table_offsets: u32,
            table_strides: u32,
            output_offsets: u32,
            multiplicity_offsets: u32,
            lookup_words: u32,
            sub_words: u32,
            row_count: u32,
            pedersen_offsets: u32,
            pedersen_rows: u32,
            poseidon_keys: u32,
        };

        comptime {
            if (@sizeOf(WitnessLayout) != 11 * @sizeOf(u32)) @compileError("Metal witness ABI drift");
        }

        pub fn evalArguments(layout: EvalLayout) MetalError![14]u32 {
            if (layout.row_count < 2 or !std.math.isPowerOfTwo(layout.row_count) or layout.trace_log_size >= 32 or
                layout.domain_log_size >= @ctz(layout.row_count)) return MetalError.PolynomialEvaluationFailed;
            return .{
                layout.trace_offsets,   layout.interaction_offsets, layout.base_params,    layout.ext_params,
                layout.random_coeffs,   layout.denom_inv,           layout.coordinates[0], layout.coordinates[1],
                layout.coordinates[2],  layout.coordinates[3],      layout.row_count,      layout.trace_log_size,
                layout.domain_log_size, layout.rc_base,
            };
        }

        pub const EvalLibrary = struct {
            handle: *anyopaque,

            pub fn deinit(self: *EvalLibrary) void {
                stwo_zig_metal_eval_library_destroy(self.handle);
                self.* = undefined;
            }

            pub fn serialize(self: EvalLibrary) MetalError!void {
                var message: [4096]u8 = [_]u8{0} ** 4096;
                if (!stwo_zig_metal_eval_library_serialize(self.handle, &message, message.len)) {
                    std.log.err("Metal evaluation archive serialization failed: {s}", .{std.mem.sliceTo(&message, 0)});
                    return MetalError.PolynomialEvaluationFailed;
                }
            }
        };

        pub const EvalPlan = extern struct {
            handle: *anyopaque,

            pub fn deinit(self: *EvalPlan) void {
                stwo_zig_metal_eval_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const BasePolynomialPlan = extern struct {
            handle: *anyopaque,

            pub fn deinit(self: *BasePolynomialPlan) void {
                stwo_zig_metal_base_polynomial_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const BasePolynomialDispatch = extern struct {
            plan: *anyopaque,
            selector: [*]const u32,
            main_column_offset: u32,
            main_column_count: u32,
            row_count: u32,
            power_word_offset: u32,
            power_word_count: u32,
            output_index: u32,
            denominator_inverses: [2]u32,
        };

        pub const BasePolynomialOutput = extern struct {
            columns: [4][*]u32,
            row_count: u32,
        };

        pub const LookupPolynomialPlan = extern struct {
            handle: *anyopaque,

            pub fn deinit(self: *LookupPolynomialPlan) void {
                stwo_zig_metal_lookup_polynomial_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const LookupPolynomialDispatch = extern struct {
            plan: *anyopaque,
            selector: [*]const u32,
            main_column_offset: u32,
            main_column_count: u32,
            interaction_column_offset: u32,
            interaction_column_count: u32,
            row_count: u32,
            power_word_offset: u32,
            power_word_count: u32,
            parameter_word_offset: u32,
            parameter_word_count: u32,
            output_index: u32,
            denominator_inverses: [2]u32,
        };

        pub const WitnessPlan = extern struct {
            handle: *anyopaque,

            pub fn deinit(self: *WitnessPlan) void {
                stwo_zig_metal_witness_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const EvalBatchPlan = extern struct {
            handle: *anyopaque,

            pub fn deinit(self: *EvalBatchPlan) void {
                stwo_zig_metal_eval_batch_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const CompositionFinalizePlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *CompositionFinalizePlan) void {
                stwo_zig_metal_composition_finalize_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const CompositionLdeOptions = struct {
            radix4: bool = true,
        };

        pub fn compositionLdeOptionsFromEnvironment() MetalError!CompositionLdeOptions {
            return compositionLdeOptions(std.posix.getenv("STWO_ZIG_METAL_RADIX4_RFFT"));
        }

        fn compositionLdeOptions(value: ?[]const u8) MetalError!CompositionLdeOptions {
            const encoded = value orelse return .{};
            if (std.mem.eql(u8, encoded, "1")) return .{};
            if (std.mem.eql(u8, encoded, "0")) return .{ .radix4 = false };
            return MetalError.PolynomialEvaluationFailed;
        }

        pub const CompositionLdePlan = extern struct {
            handle: *anyopaque,

            pub fn deinit(self: *CompositionLdePlan) void {
                stwo_zig_metal_composition_lde_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const CompositionExtParamDescriptor = extern struct {
            destination: u32,
            kind: u32,
            source: u32,
            scale: u32,
            constant: [4]u32,
        };

        pub const CompositionInputPlan = extern struct {
            handle: *anyopaque,

            pub fn deinit(self: *CompositionInputPlan) void {
                stwo_zig_metal_composition_inputs_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const CompositionFrontPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *CompositionFrontPlan) void {
                stwo_zig_metal_composition_front_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const RelationPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *RelationPlan) void {
                stwo_zig_metal_relation_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const FriFoldPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *FriFoldPlan) void {
                stwo_zig_metal_fri_fold_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const QuotientCombinePlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *QuotientCombinePlan) void {
                stwo_zig_metal_quotient_combine_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const FriRoundPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *FriRoundPlan) void {
                stwo_zig_metal_fri_round_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const FriTreePlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *FriTreePlan) void {
                stwo_zig_metal_fri_tree_plan_destroy(self.handle);
                self.* = undefined;
            }
        };

        pub const FriFinalPlan = struct {
            handle: *anyopaque,

            pub fn deinit(self: *FriFinalPlan) void {
                stwo_zig_metal_fri_final_plan_destroy(self.handle);
                self.* = undefined;
            }
        };
    };
}

const TestResources = ResourcePlans(error{PolynomialEvaluationFailed});

test "evaluation arguments retain ABI order and validation" {
    const arguments = try TestResources.evalArguments(.{
        .trace_offsets = 1,
        .interaction_offsets = 2,
        .base_params = 3,
        .ext_params = 4,
        .random_coeffs = 5,
        .denom_inv = 6,
        .coordinates = .{ 7, 8, 9, 10 },
        .row_count = 16,
        .trace_log_size = 4,
        .domain_log_size = 3,
        .rc_base = 11,
    });
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 4, 3, 11 }, &arguments);

    var invalid = std.mem.zeroes(TestResources.EvalLayout);
    invalid.row_count = 3;
    try std.testing.expectError(error.PolynomialEvaluationFailed, TestResources.evalArguments(invalid));
}

test "composition LDE radix-4 policy is default-on with explicit rollback" {
    try std.testing.expect((try TestResources.compositionLdeOptions(null)).radix4);
    try std.testing.expect((try TestResources.compositionLdeOptions("1")).radix4);
    try std.testing.expect(!(try TestResources.compositionLdeOptions("0")).radix4);
    try std.testing.expectError(error.PolynomialEvaluationFailed, TestResources.compositionLdeOptions("false"));
}

test "resource layouts retain host ABI invariants" {
    try std.testing.expectEqual(11 * @sizeOf(u32), @sizeOf(TestResources.WitnessLayout));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(TestResources.WitnessLayout, "input_offsets"));
    try std.testing.expectEqual(10 * @sizeOf(u32), @offsetOf(TestResources.WitnessLayout, "poseidon_keys"));
    try std.testing.expectEqual(@as(usize, 2 * @sizeOf(usize)), @sizeOf(TestResources.MerkleParentChainPlan));
}
