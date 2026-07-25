use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use serde::Serialize;
use stwo_cairo_official_verifier::{
    ADAPTER_VERSION, Channel, ProofFormat, STWO_CAIRO_REVISION, STWO_REVISION, identity,
    proof_sha256, verify_proof, write_json_new,
};

enum Command {
    Identity,
    Verify {
        proof: PathBuf,
        channel: Channel,
        format: ProofFormat,
        result: PathBuf,
    },
}

#[derive(Serialize)]
struct VerifyReport {
    schema_version: u32,
    adapter_version: &'static str,
    stwo_cairo_revision: &'static str,
    stwo_revision: &'static str,
    proof_sha256: Option<String>,
    channel: Channel,
    proof_format: ProofFormat,
    verified: bool,
    wall_time_ns: u64,
    error: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("stwo-cairo-official-verifier: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    match parse_args(std::env::args_os().skip(1))? {
        Command::Identity => {
            serde_json::to_writer(
                std::io::stdout().lock(),
                &identity(std::env::current_exe().ok().as_deref())?,
            )?;
            println!();
            Ok(ExitCode::SUCCESS)
        }
        Command::Verify {
            proof,
            channel,
            format,
            result,
        } => verify(&proof, channel, format, &result),
    }
}

fn verify(
    proof: &std::path::Path,
    channel: Channel,
    format: ProofFormat,
    result: &std::path::Path,
) -> anyhow::Result<ExitCode> {
    let started = Instant::now();
    let digest = proof_sha256(proof);
    let verdict = digest
        .as_ref()
        .map(|_| verify_proof(proof, channel, format));
    let verified = matches!(verdict, Ok(Ok(())));
    let error = match (&digest, &verdict) {
        (Err(error), _) => Some(format!("{error:#}")),
        (_, Ok(Err(error))) => Some(format!("{error:#}")),
        _ => None,
    };
    write_json_new(
        result,
        &VerifyReport {
            schema_version: 1,
            adapter_version: ADAPTER_VERSION,
            stwo_cairo_revision: STWO_CAIRO_REVISION,
            stwo_revision: STWO_REVISION,
            proof_sha256: digest.ok(),
            channel,
            proof_format: format,
            verified,
            wall_time_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
            error,
        },
    )?;
    Ok(if verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    })
}

fn parse_args<I>(mut args: I) -> anyhow::Result<Command>
where
    I: Iterator<Item = OsString>,
{
    let command = utf8(args.next(), "missing command")?;
    match command.as_str() {
        "identity" => {
            anyhow::ensure!(args.next().is_none(), "identity accepts no arguments");
            Ok(Command::Identity)
        }
        "verify" => {
            let mut proof = None;
            let mut channel = None;
            let mut format = None;
            let mut result = None;
            while let Some(flag) = args.next() {
                let flag = flag
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("option is not valid UTF-8"))?;
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
                match flag.as_str() {
                    "--proof" if proof.is_none() => proof = Some(PathBuf::from(value)),
                    "--channel" if channel.is_none() => {
                        channel = Some(Channel::parse(&utf8(Some(value), "missing channel")?)?)
                    }
                    "--proof-format" if format.is_none() => {
                        format = Some(ProofFormat::parse(&utf8(Some(value), "missing format")?)?)
                    }
                    "--result" if result.is_none() => result = Some(PathBuf::from(value)),
                    "--proof" | "--channel" | "--proof-format" | "--result" => {
                        anyhow::bail!("duplicate option {flag}")
                    }
                    _ => anyhow::bail!("unknown option {flag}"),
                }
            }
            Ok(Command::Verify {
                proof: proof.ok_or_else(|| anyhow::anyhow!("missing --proof"))?,
                channel: channel.unwrap_or(Channel::Blake2s),
                format: format.unwrap_or(ProofFormat::Json),
                result: result.ok_or_else(|| anyhow::anyhow!("missing --result"))?,
            })
        }
        _ => anyhow::bail!("unknown command {command}"),
    }
}

fn utf8(value: Option<OsString>, error: &str) -> anyhow::Result<String> {
    value
        .ok_or_else(|| anyhow::anyhow!("{error}"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("argument is not valid UTF-8"))
}
