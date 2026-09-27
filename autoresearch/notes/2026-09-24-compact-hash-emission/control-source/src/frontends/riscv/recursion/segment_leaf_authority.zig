//! Single production authority for recursive segment rows 10 and 12--14.
//!
//! One admitted `PublicData` value produces the canonical VM claim, canonical
//! span statement, claim-input witness, claim hash, public-I/O hashes, and all
//! shared Poseidon requests.  Every retained snapshot validates back to that
//! same source; no row accepts an independently supplied digest.

const std = @import("std");
const public_data_mod = @import("../air/public_data.zig");
const protocol = @import("protocol.zig");
const span_statement = @import("span_statement.zig");
const vm_claim = @import("vm_public_claim.zig");
const statement_input = @import("air/statement_input_witness.zig");
const claim_input = @import("air/vm_public_claim_input_witness.zig");
const claim_hash = @import("air/vm_public_claim_hash_witness.zig");
const io_hash = @import("air/vm_public_io_hash_witness.zig");

pub const FORMAT_VERSION: u16 = 1;

pub const Error = vm_claim.Error || span_statement.Error ||
    statement_input.Error || claim_input.Error || claim_hash.Error ||
    io_hash.Error || std.mem.Allocator.Error || error{
    AuthorityMismatch,
};

pub const Preprocessing = struct {
    statement_input: statement_input.Preprocessed,
    claim_input: claim_input.Preprocessed,
    claim_hash: claim_hash.Preprocessed,
    io_hash: io_hash.Preprocessed,

    pub fn init(
        allocator: std.mem.Allocator,
        shape: vm_claim.Shape,
    ) Error!Preprocessing {
        var statement_input_value = try statement_input.Preprocessed.init(allocator);
        errdefer statement_input_value.deinit();
        var claim_input_value = try claim_input.Preprocessed.init(allocator, shape);
        errdefer claim_input_value.deinit();
        var claim_hash_value = try claim_hash.Preprocessed.init(
            allocator,
            &claim_input_value,
        );
        errdefer claim_hash_value.deinit();
        var io_hash_value = try io_hash.Preprocessed.init(
            allocator,
            &claim_input_value,
        );
        errdefer io_hash_value.deinit();
        const result = Preprocessing{
            .statement_input = statement_input_value,
            .claim_input = claim_input_value,
            .claim_hash = claim_hash_value,
            .io_hash = io_hash_value,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *Preprocessing) void {
        self.io_hash.deinit();
        self.claim_hash.deinit();
        self.claim_input.deinit();
        self.statement_input.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Preprocessing) Error!void {
        try self.statement_input.validate();
        try self.claim_input.validate();
        try self.claim_hash.validateAgainst(&self.claim_input);
        try self.io_hash.validateAgainst(&self.claim_input);
    }
};

pub const Prepared = struct {
    claim: vm_claim.Encoded,
    statement: span_statement.SegmentLeaf,
    claim_input: claim_input.MainWitness,
    claim_hash: claim_hash.MainWitness,
    io_hash: io_hash.MainWitness,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessing,
        data: *const public_data_mod.PublicData,
    ) Error!Prepared {
        try preprocessing.validate();
        var claim_value = try vm_claim.encode(
            allocator,
            data,
            preprocessing.claim_input.shape,
        );
        errdefer claim_value.deinit();
        const statement_value = try span_statement.SegmentLeaf.init(
            data,
            &claim_value,
            protocol.protocolId(),
        );
        var claim_input_value = try claim_input.MainWitness.init(
            allocator,
            &preprocessing.claim_input,
            .{ .segment_leaf = claim_value.words },
        );
        errdefer claim_input_value.deinit();
        var claim_hash_value = try claim_hash.MainWitness.init(
            allocator,
            &preprocessing.claim_hash,
            .{ .segment_leaf = claim_value.words },
        );
        errdefer claim_hash_value.deinit();
        var io_hash_value = try io_hash.MainWitness.init(
            allocator,
            &preprocessing.io_hash,
            .{ .segment_leaf = claim_value.words },
        );
        errdefer io_hash_value.deinit();
        const result = Prepared{
            .claim = claim_value,
            .statement = statement_value,
            .claim_input = claim_input_value,
            .claim_hash = claim_hash_value,
            .io_hash = io_hash_value,
        };
        try result.validateAgainst(preprocessing, data);
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.io_hash.deinit();
        self.claim_hash.deinit();
        self.claim_input.deinit();
        self.claim.deinit();
        self.* = undefined;
    }

    /// Allocation-free revalidation of every row snapshot and cross-row hash.
    pub fn validateAgainst(
        self: *const Prepared,
        preprocessing: *const Preprocessing,
        data: *const public_data_mod.PublicData,
    ) Error!void {
        try preprocessing.validate();
        try self.claim.validateAgainst(data);
        try self.statement.validateAgainst(data, &self.claim);
        try self.claim_input.validateAgainst(
            &preprocessing.claim_input,
        );
        try self.claim_hash.validateAgainstSource(
            &preprocessing.claim_hash,
            .{ .segment_leaf = self.claim.words },
        );
        try self.claim_hash.validateDigest(
            &preprocessing.claim_hash,
            self.claim.digest,
        );
        try self.io_hash.validateAgainstSource(
            &preprocessing.io_hash,
            .{ .segment_leaf = self.claim.words },
        );
        try self.io_hash.validateDigest(
            &preprocessing.io_hash,
            .{ self.claim.public_input_digest, self.claim.public_output_digest },
        );
        const row10_witness = statement_input.StatementWitness{
            .segment_leaf = &self.statement.words,
        };
        for (preprocessing.statement_input.rows[0..span_statement.SPAN_STATEMENT_CANONICAL_WORDS], 0..) |
            metadata,
            index,
        | {
            const main = try statement_input.mainRow(metadata, row10_witness);
            if (!main[1].eql(self.statement.words[index]))
                return error.AuthorityMismatch;
        }
    }

    pub fn poseidonCallCount(self: *const Prepared) usize {
        return self.claim_hash.poseidon_calls.len + self.io_hash.poseidon_calls.len;
    }
};
