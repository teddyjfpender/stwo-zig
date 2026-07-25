use crate::model::{Cli, Example, FriConfigWire, Mode, PcsConfigWire, ProveMode, ProverBackend};
use anyhow::{anyhow, bail, Result};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;

pub(crate) fn parse_cli(args: Vec<String>) -> Result<Cli> {
    let mut mode: Option<Mode> = None;
    let mut example: Option<Example> = None;
    let mut artifact: Option<String> = None;
    let mut stage_profile_out: Option<String> = None;
    let mut prove_mode = ProveMode::Prove;
    let mut include_all_preprocessed_columns = false;
    let mut backend = ProverBackend::Scalar;

    let mut pow_bits = 0u32;
    let mut fri_log_blowup = 1u32;
    let mut fri_log_last_layer = 0u32;
    let mut fri_n_queries = 3usize;

    let mut sm_log_n_rows = 5u32;
    let mut sm_initial_0 = 9u32;
    let mut sm_initial_1 = 3u32;

    let mut blake_log_n_rows = 5u32;
    let mut blake_n_rounds = 10u32;

    let mut plonk_log_n_rows = 5u32;

    let mut poseidon_log_n_instances = 8u32;

    let mut wf_log_n_rows = 5u32;
    let mut wf_sequence_len = 16u32;

    let mut xor_log_size = 5u32;
    let mut xor_log_step = 2u32;
    let mut xor_offset = 3usize;

    let mut bench_warmups = 1usize;
    let mut bench_repeats = 5usize;

    let mut i = 1usize;
    while i < args.len() {
        let flag = &args[i];
        if !flag.starts_with("--") {
            bail!("invalid argument {flag}");
        }
        if i + 1 >= args.len() {
            bail!("missing value for {flag}");
        }
        let value = &args[i + 1];
        i += 2;

        match flag.as_str() {
            "--mode" => {
                mode = match value.as_str() {
                    "capabilities" => Some(Mode::Capabilities),
                    "generate" => Some(Mode::Generate),
                    "verify" => Some(Mode::Verify),
                    "bench" => Some(Mode::Bench),
                    _ => bail!("invalid mode {value}"),
                }
            }
            "--example" => {
                example = match value.as_str() {
                    "blake" => Some(Example::Blake),
                    "plonk" => Some(Example::Plonk),
                    "poseidon" => Some(Example::Poseidon),
                    "state_machine" => Some(Example::StateMachine),
                    "wide_fibonacci" => Some(Example::WideFibonacci),
                    "xor" => Some(Example::Xor),
                    _ => bail!("invalid example {value}"),
                }
            }
            "--artifact" => artifact = Some(value.clone()),
            "--stage-profile-out" => stage_profile_out = Some(value.clone()),
            "--prove-mode" => {
                prove_mode = prove_mode_from_str(value)
                    .ok_or_else(|| anyhow!("invalid prove mode {value}"))?
            }
            "--include-all-preprocessed-columns" => {
                include_all_preprocessed_columns = match value.as_str() {
                    "0" | "false" => false,
                    "1" | "true" => true,
                    _ => bail!(
                        "invalid boolean value for --include-all-preprocessed-columns: {value}"
                    ),
                };
            }
            "--backend" => {
                backend = match value.as_str() {
                    "scalar" | "cpu-scalar" => ProverBackend::Scalar,
                    "simd" => ProverBackend::Simd,
                    _ => bail!("invalid backend {value}"),
                }
            }
            "--pow-bits" => pow_bits = value.parse()?,
            "--fri-log-blowup" => fri_log_blowup = value.parse()?,
            "--fri-log-last-layer" => fri_log_last_layer = value.parse()?,
            "--fri-n-queries" => fri_n_queries = value.parse()?,
            "--sm-log-n-rows" => sm_log_n_rows = value.parse()?,
            "--sm-initial-0" => sm_initial_0 = value.parse()?,
            "--sm-initial-1" => sm_initial_1 = value.parse()?,
            "--blake-log-n-rows" => blake_log_n_rows = value.parse()?,
            "--blake-n-rounds" => blake_n_rounds = value.parse()?,
            "--plonk-log-n-rows" => plonk_log_n_rows = value.parse()?,
            "--poseidon-log-n-instances" => poseidon_log_n_instances = value.parse()?,
            "--wf-log-n-rows" => wf_log_n_rows = value.parse()?,
            "--wf-sequence-len" => wf_sequence_len = value.parse()?,
            "--xor-log-size" => xor_log_size = value.parse()?,
            "--xor-log-step" => xor_log_step = value.parse()?,
            "--xor-offset" => xor_offset = value.parse()?,
            "--bench-warmups" => bench_warmups = value.parse()?,
            "--bench-repeats" => bench_repeats = value.parse()?,
            _ => bail!("unknown flag {flag}"),
        }
    }

    let mode = mode.ok_or_else(|| anyhow!("--mode is required"))?;
    let artifact = match (mode, artifact) {
        (Mode::Capabilities, None) => String::new(),
        (_, Some(value)) => value,
        _ => bail!("--artifact is required"),
    };
    Ok(Cli {
        mode,
        example,
        artifact,
        stage_profile_out,
        prove_mode,
        include_all_preprocessed_columns,
        backend,
        pow_bits,
        fri_log_blowup,
        fri_log_last_layer,
        fri_n_queries,
        sm_log_n_rows,
        sm_initial_0,
        sm_initial_1,
        blake_log_n_rows,
        blake_n_rounds,
        plonk_log_n_rows,
        poseidon_log_n_instances,
        wf_log_n_rows,
        wf_sequence_len,
        xor_log_size,
        xor_log_step,
        xor_offset,
        bench_warmups,
        bench_repeats,
    })
}

pub(crate) fn prove_mode_to_str(mode: ProveMode) -> &'static str {
    match mode {
        ProveMode::Prove => "prove",
        ProveMode::ProveEx => "prove_ex",
    }
}

pub(crate) fn prove_mode_from_str(value: &str) -> Option<ProveMode> {
    match value {
        "prove" => Some(ProveMode::Prove),
        "prove_ex" => Some(ProveMode::ProveEx),
        _ => None,
    }
}

pub(crate) fn pcs_config_from_cli(cli: &Cli) -> Result<PcsConfig> {
    Ok(PcsConfig {
        pow_bits: cli.pow_bits,
        fri_config: FriConfig::new(
            cli.fri_log_last_layer,
            cli.fri_log_blowup,
            cli.fri_n_queries,
        ),
    })
}

pub(crate) fn pcs_config_to_wire(config: PcsConfig) -> PcsConfigWire {
    PcsConfigWire {
        pow_bits: config.pow_bits,
        fri_config: FriConfigWire {
            log_blowup_factor: config.fri_config.log_blowup_factor,
            log_last_layer_degree_bound: config.fri_config.log_last_layer_degree_bound,
            n_queries: config.fri_config.n_queries as u64,
            fold_step: 1,
        },
        lifting_log_size: None,
    }
}

pub(crate) fn pcs_config_from_wire(wire: &PcsConfigWire) -> Result<PcsConfig> {
    if wire.fri_config.fold_step != 1 {
        bail!("unsupported PCS fold_step {}", wire.fri_config.fold_step);
    }
    if let Some(value) = wire.lifting_log_size {
        bail!("unsupported PCS lifting_log_size {value}");
    }
    let n_queries: usize = wire
        .fri_config
        .n_queries
        .try_into()
        .map_err(|_| anyhow!("fri n_queries out of range"))?;
    Ok(PcsConfig {
        pow_bits: wire.pow_bits,
        fri_config: FriConfig::new(
            wire.fri_config.log_last_layer_degree_bound,
            wire.fri_config.log_blowup_factor,
            n_queries,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_cli, pcs_config_from_wire};
    use crate::model::{FriConfigWire, Mode, PcsConfigWire, ProverBackend};

    fn config_wire() -> PcsConfigWire {
        PcsConfigWire {
            pow_bits: 0,
            fri_config: FriConfigWire {
                log_blowup_factor: 1,
                log_last_layer_degree_bound: 0,
                n_queries: 3,
                fold_step: 1,
            },
            lifting_log_size: None,
        }
    }

    #[test]
    fn rejects_unsupported_outer_pcs_fields() {
        let mut fold_step = config_wire();
        fold_step.fri_config.fold_step = 2;
        assert!(pcs_config_from_wire(&fold_step)
            .unwrap_err()
            .to_string()
            .contains("fold_step"));

        let mut lifting = config_wire();
        lifting.lifting_log_size = Some(4);
        assert!(pcs_config_from_wire(&lifting)
            .unwrap_err()
            .to_string()
            .contains("lifting_log_size"));
    }

    #[test]
    fn backend_selection_is_explicit_and_scalar_by_default() {
        let scalar = parse_cli(vec![
            "tool".into(),
            "--mode".into(),
            "bench".into(),
            "--artifact".into(),
            "unused.json".into(),
        ])
        .unwrap();
        assert_eq!(scalar.backend, ProverBackend::Scalar);

        let simd = parse_cli(vec![
            "tool".into(),
            "--mode".into(),
            "bench".into(),
            "--artifact".into(),
            "unused.json".into(),
            "--backend".into(),
            "simd".into(),
        ])
        .unwrap();
        assert_eq!(simd.backend, ProverBackend::Simd);
    }

    #[test]
    fn capabilities_is_the_only_artifact_free_mode() {
        let capabilities =
            parse_cli(vec!["tool".into(), "--mode".into(), "capabilities".into()]).unwrap();
        assert_eq!(capabilities.mode, Mode::Capabilities);
        assert!(capabilities.artifact.is_empty());

        let verify = parse_cli(vec!["tool".into(), "--mode".into(), "verify".into()]);
        assert!(verify
            .unwrap_err()
            .to_string()
            .contains("--artifact is required"));
    }
}
