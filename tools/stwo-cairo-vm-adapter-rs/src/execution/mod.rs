//! Typed execution boundary for admitted Cairo program artifacts.

mod executable;
mod legacy_json;

use anyhow::Result;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use stwo_cairo_adapter::PublicSegmentContext;

pub const CAIRO_LANGUAGE_VERSION: &str = "2.20.0";
pub const PROGRAM_TYPE_NAMES: [&str; 2] = ["json", "executable"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramType {
    Json,
    Executable,
}

impl ProgramType {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "json" => Ok(Self::Json),
            "executable" => Ok(Self::Executable),
            _ => anyhow::bail!("unsupported program type {value:?}; expected json or executable"),
        }
    }
}

pub struct CompletedExecution {
    pub runner: CairoRunner,
    pub public_segment_context: Option<PublicSegmentContext>,
}

pub fn run(
    program_type: ProgramType,
    program_bytes: &[u8],
    argument_bytes: Option<&[u8]>,
) -> anyhow::Result<CompletedExecution> {
    let config = CairoRunConfig {
        trace_enabled: true,
        relocate_trace: false,
        layout: LayoutName::all_cairo_stwo,
        fill_holes: true,
        proof_mode: true,
        disable_trace_padding: true,
        ..Default::default()
    };
    match program_type {
        ProgramType::Json => Ok(CompletedExecution {
            runner: legacy_json::run(program_bytes, argument_bytes, &config)?,
            public_segment_context: None,
        }),
        ProgramType::Executable => executable::run(program_bytes, argument_bytes, &config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_type_names_are_stable_and_strict() {
        assert_eq!(ProgramType::parse("json").unwrap(), ProgramType::Json);
        assert_eq!(
            ProgramType::parse("executable").unwrap(),
            ProgramType::Executable
        );
        assert!(ProgramType::parse("sierra").is_err());
        assert_eq!(PROGRAM_TYPE_NAMES, ["json", "executable"]);
    }
}
