//! Format-specific statement input admission over the shared typed AIR.
const profile = @import("statement_semantics_input_witness_profile.zig").Profile(true);

pub const MIN_LOG_SIZE = profile.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = profile.MAX_LOG_SIZE;
pub const MAIN_COLUMN_COUNT = profile.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = profile.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = profile.ProofKind;
pub const BINDING_FORMAT_VERSION = profile.BINDING_FORMAT_VERSION;
pub const BINDING_DOMAIN = profile.BINDING_DOMAIN;
pub const BINDING_DIGEST_HEX = profile.BINDING_DIGEST_HEX;
pub const BINDING_DIGEST = profile.BINDING_DIGEST;
pub const Error = profile.Error;
pub const MainSource = profile.MainSource;
pub const PreprocessedSource = profile.PreprocessedSource;
pub const Slot = profile.Slot;
pub const Binding = profile.Binding;
pub const Executor = profile.Executor;
pub const ProofKindSet = profile.ProofKindSet;
pub const InputSource = profile.InputSource;
pub const Source = profile.Source;
pub const InputBinding = profile.InputBinding;
pub const Row = profile.Row;
pub const Preprocessed = profile.Preprocessed;
pub const mainRow = profile.mainRow;
pub const logicalRow = profile.logicalRow;
pub const logicalRowForEthereum = profile.logicalRowForEthereum;
pub const isIntegerWord = profile.isIntegerWord;
