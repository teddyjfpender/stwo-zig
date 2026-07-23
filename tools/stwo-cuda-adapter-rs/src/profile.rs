use crate::model::{StageNode, StageProfile};
use anyhow::{Context, Result};
use std::fs;

pub(crate) fn time_stage<T, F>(id: &str, label: &str, f: F) -> Result<(T, StageNode)>
where
    F: FnOnce() -> Result<T>,
{
    let start = std::time::Instant::now();
    let value = f()?;
    Ok((
        value,
        StageNode {
            id: id.to_string(),
            label: label.to_string(),
            seconds: start.elapsed().as_secs_f64(),
            children: None,
        },
    ))
}

pub(crate) fn write_stage_profile(path: &str, stages: Vec<StageNode>) -> Result<()> {
    let profile = StageProfile {
        schema_version: 1,
        runtime: "rust".to_string(),
        example: "wide_fibonacci".to_string(),
        stages,
    };
    fs::write(path, serde_json::to_string_pretty(&profile)?)
        .with_context(|| format!("failed writing stage profile {path}"))?;
    Ok(())
}
