//! Internal transcript binding witness authority shard; use transcript_binding_witness.zig publicly.

const dependency_0 = @import("transcript_binding_witness_contract.zig");
const dependency_1 = @import("transcript_binding_witness_preprocessed.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const MainRow = dependency_1.MainRow;
const MainWitness = dependency_1.MainWitness;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const Preprocessed = dependency_1.Preprocessed;
const PreprocessedRow = dependency_0.PreprocessedRow;
const ProofKind = dependency_0.ProofKind;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const protectHeader = dependency_1.protectHeader;
const std = dependency_0.std;
const validateMainRowDirect = dependency_1.validateMainRowDirect;
const validatePreprocessedRowDirect = dependency_1.validatePreprocessedRowDirect;
const writeMainRow = dependency_1.writeMainRow;
const writePreprocessedRow = dependency_1.writePreprocessedRow;

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) Error!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.BindingMismatch;
        const actual = supplied.identityDigest();
        if (!std.mem.eql(u8, &actual, &BINDING_DIGEST))
            return error.BindingMismatch;
        return .{ .binding = supplied.*, .binding_digest = actual };
    }

    pub fn validate(self: *const Executor) Error!void {
        const actual = self.binding.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest) or
            !std.mem.eql(u8, &actual, &BINDING_DIGEST) or
            !std.mem.eql(u8, &self.binding.source_authority_digest, &component.SOURCE_AUTHORITY_DIGEST))
        {
            return error.BindingMismatch;
        }
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try preprocessing.validate();
        try protectHeader(columns, preprocessing);
        return direct.generateMainInto(
            M31,
            PreprocessedRow,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            preprocessing.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validatePreprocessedRowDirect,
            writePreprocessedRow,
        );
    }

    pub fn generateMainInto(
        self: *const Executor,
        witness: *const MainWitness,
        preprocessing: *const Preprocessed,
        columns: *[MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try witness.validateAgainst(preprocessing);
        try protectHeader(columns, witness);
        try protectHeader(columns, preprocessing);
        return direct.generateMainInto(
            M31,
            MainRow,
            MAIN_COLUMN_COUNT,
            columns,
            witness.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validateMainRowDirect,
            writeMainRow,
        );
    }
};

pub fn logicalInputs(
    main: MainRow,
    preprocessing: PreprocessedRow,
    proof_kind: ProofKind,
) [component.LOGICAL_INPUT_COUNT]M31 {
    const selectors = proof_kind.selectors();
    return main.values() ++ preprocessing.values() ++ .{
        selectors[0],
        selectors[1],
    };
}
