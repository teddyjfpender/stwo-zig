//! Repository-owned official Stwo-Cairo witness source rewriter.
//!
//! The implementation is split by compiler phase but included into one
//! private module. This keeps the migration-proven lowering semantics in a
//! single Rust namespace without widening internal APIs solely for file
//! decomposition.

mod compiler {
    include!("compiler/model.rs");
    include!("compiler/cli.rs");
    include!("compiler/source_analysis.rs");
    include!("compiler/relation_analysis.rs");
    include!("compiler/shape_analysis.rs");
    include!("compiler/deduce_analysis.rs");
    include!("compiler/lowerer.rs");
    include!("compiler/lowerer_bindings.rs");
    include!("compiler/lowerer_expressions.rs");
    include!("compiler/lowerer_calls.rs");
    include!("compiler/lowerer_operators.rs");
    include!("compiler/emission.rs");
    include!("compiler/emission_differential.rs");
    include!("compiler/source_helpers.rs");
    include!("compiler/commands.rs");
    include!("compiler/tests.rs");
}

fn main() -> std::process::ExitCode {
    compiler::run()
}
