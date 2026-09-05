//! Verifier-bound universal rows 10--11 for a schema-3 role-0 wrapper.
//!
//! Both rows consume the exact 412 field words reconstructed by the stage-101
//! cold verifier. Row 11 evaluates the canonical statement-semantics graph as
//! a segment leaf; the child-public owner must expose the identical statement
//! identity before either owner can join a universal cohort.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const child_public =
    @import("recursive_common_ethereum_incremental_leaf_child_public_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const statement_circuit = recursion.statement_semantics_circuit;
const statement_input = recursion.air.statement_input_witness;
const statement_semantics = recursion.air.statement_semantics_input_witness;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 10;
pub const LAST_ROW: usize = 11;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const STATEMENT_CIRCUIT_ID: u32 = recursion.segment_statement_outer_source
    .STATEMENT_CIRCUIT_ID;
pub const ROWS_10_THROUGH_11_AVAILABLE = true;
pub const CALLER_STATEMENT_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-child-statement/v4-schema3\x00";

pub const Error = error{
    EthereumIncrementalChildStatementMismatchV4,
};

pub const LogSizesV4 = [ROW_COUNT]u32;

pub fn OwnerV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const ChildPublic = child_public.OwnerV4(Engine);

    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
        ) !*Self {
            try materialized.validate();
            try child.validate();
            const child_binding = try child.binding();
            const statement_identity = statementWordsIdentity(
                materialized.base.input.statement_words,
            );
            if (!std.mem.eql(
                u8,
                &child_binding.statement_words_identity_sha256,
                &statement_identity,
            )) return error.EthereumIncrementalChildStatementMismatchV4;

            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            var statement_words: recursion.span_statement.StatementWords =
                undefined;
            for (
                &statement_words,
                materialized.base.input.statement_words,
            ) |*destination, word| destination.* = M31.fromCanonical(word);

            var row10_preprocessing = try statement_input.Preprocessed.init(
                allocator,
            );
            var row10_owned = true;
            errdefer if (row10_owned) row10_preprocessing.deinit();
            var circuit = try statement_circuit.build(allocator);
            var circuit_owned = true;
            errdefer if (circuit_owned) circuit.deinit();
            var row11_preprocessing = try statement_semantics.Preprocessed.init(
                allocator,
                STATEMENT_CIRCUIT_ID,
                circuit.inputBindings(),
            );
            var row11_owned = true;
            errdefer if (row11_owned) row11_preprocessing.deinit();
            var evaluation = try circuit.evaluate(
                allocator,
                statement_circuit.Witness.forSegment(&statement_words),
            );
            var evaluation_owned = true;
            errdefer if (evaluation_owned) evaluation.deinit();
            const row11_values = try allocator.alloc(
                M31,
                evaluation.inputs().len,
            );
            errdefer allocator.free(row11_values);
            try baseInputs(evaluation.inputs(), row11_values);

            backing.* = .{
                .allocator = allocator,
                .materialized = materialized,
                .child = child,
                .child_binding = child_binding,
                .statement_words = statement_words,
                .row10_preprocessing = row10_preprocessing,
                .circuit = circuit,
                .row11_preprocessing = row11_preprocessing,
                .evaluation = evaluation,
                .row11_values = row11_values,
                .statement_words_identity_sha256 = statement_identity,
                .identity_sha256 = undefined,
            };
            row10_owned = false;
            circuit_owned = false;
            row11_owned = false;
            evaluation_owned = false;
            errdefer backing.destroy();
            backing.identity_sha256 = backing.computeIdentity();
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn logSizes(self: *const Self) !LogSizesV4 {
            try self.validate();
            const value = storageConst(self);
            return .{
                value.row10_preprocessing.log_size,
                value.row11_preprocessing.log_size,
            };
        }

        pub fn statementWords(
            self: *const Self,
        ) !*const recursion.span_statement.StatementWords {
            try self.validate();
            return &storageConst(self).statement_words;
        }

        pub fn statementInputPreprocessing(
            self: *const Self,
        ) !*const statement_input.Preprocessed {
            try self.validate();
            return &storageConst(self).row10_preprocessing;
        }

        pub fn statementSemanticsPreprocessing(
            self: *const Self,
        ) !*const statement_semantics.Preprocessed {
            try self.validate();
            return &storageConst(self).row11_preprocessing;
        }

        pub fn statementSemanticsValues(
            self: *const Self,
        ) ![]const M31 {
            try self.validate();
            return storageConst(self).row11_values;
        }

        pub fn loweringCircuit(
            self: *const Self,
        ) !*const statement_circuit.Circuit {
            try self.validate();
            return &storageConst(self).circuit;
        }

        pub fn loweringEvaluation(
            self: *const Self,
        ) !*const statement_circuit.Evaluation {
            try self.validate();
            return &storageConst(self).evaluation;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            try self.validate();
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
            child_binding: child_public.ChildPublicBindingV4,
            statement_words: recursion.span_statement.StatementWords,
            row10_preprocessing: statement_input.Preprocessed,
            circuit: statement_circuit.Circuit,
            row11_preprocessing: statement_semantics.Preprocessed,
            evaluation: statement_circuit.Evaluation,
            row11_values: []M31,
            statement_words_identity_sha256: [32]u8,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.materialized.validate();
                try self.child.validate();
                const expected_child_binding = try self.child.binding();
                try self.row10_preprocessing.validate();
                try self.circuit.validate();
                try self.row11_preprocessing.validate();
                if (!try self.circuit.graph().outputsAreZero(
                    self.evaluation.values(),
                )) return error.EthereumIncrementalChildStatementMismatchV4;
                if (self.evaluation.inputs().len != self.row11_values.len)
                    return error.EthereumIncrementalChildStatementMismatchV4;
                for (
                    self.evaluation.inputs(),
                    self.row11_values,
                ) |secure, base| {
                    const limbs = secure.toM31Array();
                    if (!limbs[0].eql(base) or !limbs[1].isZero() or
                        !limbs[2].isZero() or !limbs[3].isZero())
                    {
                        return error.EthereumIncrementalChildStatementMismatchV4;
                    }
                }
                for (
                    self.statement_words,
                    self.materialized.base.input.statement_words,
                ) |felt, word| if (felt.toU32() != word)
                    return error.EthereumIncrementalChildStatementMismatchV4;
                const expected_statement_identity = statementWordsIdentity(
                    self.materialized.base.input.statement_words,
                );
                if (!std.meta.eql(self.child_binding, expected_child_binding) or
                    !std.mem.eql(
                        u8,
                        &self.statement_words_identity_sha256,
                        &expected_statement_identity,
                    ) or !std.mem.eql(
                    u8,
                    &self.child_binding.statement_words_identity_sha256,
                    &expected_statement_identity,
                ) or !std.mem.eql(
                    u8,
                    &self.evaluation.circuit_identity,
                    &self.circuit.identity_digest,
                ) or !std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &self.computeIdentity(),
                )) return error.EthereumIncrementalChildStatementMismatchV4;
            }

            fn computeIdentity(self: *const Storage) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hash.update(&self.materialized.identity_sha256);
                hash.update(&self.child_binding.identity_sha256);
                hash.update(&self.statement_words_identity_sha256);
                hash.update(&self.row10_preprocessing.authority_digest);
                hash.update(&self.circuit.identity_digest);
                hash.update(&self.row11_preprocessing.authority_digest);
                for (self.evaluation.inputs()) |value| hashQm31(&hash, value);
                for (self.evaluation.values()) |value| hashQm31(&hash, value);
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                allocator.free(self.row11_values);
                self.evaluation.deinit();
                self.row11_preprocessing.deinit();
                self.circuit.deinit();
                self.row10_preprocessing.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        fn handle(value: *Storage) *Self {
            return @ptrCast(value);
        }

        fn storage(value: *Self) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn storageConst(value: *const Self) *const Storage {
            return @ptrCast(@alignCast(value));
        }
    };
}

fn baseInputs(source: []const QM31, destination: []M31) Error!void {
    if (source.len != destination.len)
        return error.EthereumIncrementalChildStatementMismatchV4;
    for (source, destination) |secure, *base| {
        const limbs = secure.toM31Array();
        if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero())
            return error.EthereumIncrementalChildStatementMismatchV4;
        base.* = limbs[0];
    }
}

fn statementWordsIdentity(words: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/common-ethereum-incremental-child-statement/v4\x00");
    for (words) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 10 or
        LAST_ROW != 11 or ROW_COUNT != 2 or STATEMENT_CIRCUIT_ID != 11 or
        !ROWS_10_THROUGH_11_AVAILABLE or CALLER_STATEMENT_ADMITTED or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental child-statement V4 drifted");
    }
}
