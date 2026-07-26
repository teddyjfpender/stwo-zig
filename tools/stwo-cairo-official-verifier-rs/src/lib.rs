//! Isolated adapter around the pinned official Rust `verify_cairo`.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use cairo_air::CairoProofForRustVerifier;
use cairo_air::utils::{ProofFormat as UpstreamProofFormat, deserialize_proof_from_file};
use cairo_air::verifier::verify_cairo;
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sM31MerkleChannel, Blake2sMerkleChannel, Blake2sMerkleHasher,
};
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};

pub mod claim;
pub mod input;

pub const ADAPTER_VERSION: &str = "stwo-cairo-official-verifier/1";
pub const STWO_CAIRO_REPOSITORY: &str = "https://github.com/starkware-libs/stwo-cairo";
pub const STWO_CAIRO_REVISION: &str = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78";
pub const STWO_REPOSITORY: &str = "https://github.com/starkware-libs/stwo";
pub const STWO_REVISION: &str = "7b211edde786775016ef3eecb837a6240d8fe792";
pub const MAX_PROOF_BYTES: u64 = 2 << 30;

const CARGO_LOCK: &[u8] = include_bytes!("../Cargo.lock");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Blake2s,
    Blake2sM31,
    Poseidon252,
}

impl Channel {
    pub const ALL: [Self; 3] = [Self::Blake2s, Self::Blake2sM31, Self::Poseidon252];

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "blake2s" => Ok(Self::Blake2s),
            "blake2s_m31" => Ok(Self::Blake2sM31),
            "poseidon252" => Ok(Self::Poseidon252),
            _ => bail!(
                "unsupported channel {value:?}; expected blake2s, blake2s_m31, or poseidon252"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFormat {
    Json,
    Binary,
    ExtendedBinary,
}

impl ProofFormat {
    pub const ALL: [Self; 3] = [Self::Json, Self::Binary, Self::ExtendedBinary];

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "json" => Ok(Self::Json),
            "binary" => Ok(Self::Binary),
            "extended_binary" => Ok(Self::ExtendedBinary),
            _ => bail!(
                "unsupported proof format {value:?}; expected json, binary, or extended_binary"
            ),
        }
    }

    fn upstream(self) -> UpstreamProofFormat {
        match self {
            Self::Json => UpstreamProofFormat::Json,
            Self::Binary => UpstreamProofFormat::Binary,
            Self::ExtendedBinary => UpstreamProofFormat::ExtendedBinary,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SourceIdentity {
    pub repository: &'static str,
    pub revision: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Identity {
    pub schema_version: u32,
    pub adapter_version: &'static str,
    pub stwo_cairo: SourceIdentity,
    pub stwo: SourceIdentity,
    pub cargo_lock_sha256: String,
    pub executable_sha256: Option<String>,
    pub channels: [Channel; 3],
    pub proof_formats: [ProofFormat; 3],
    pub max_proof_bytes: u64,
    pub prover_input_schema: &'static str,
    pub claim_summary_schema: &'static str,
    pub max_input_bytes: u64,
}

pub fn identity(executable: Option<&Path>) -> Result<Identity> {
    Ok(Identity {
        schema_version: 1,
        adapter_version: ADAPTER_VERSION,
        stwo_cairo: SourceIdentity {
            repository: STWO_CAIRO_REPOSITORY,
            revision: STWO_CAIRO_REVISION,
        },
        stwo: SourceIdentity {
            repository: STWO_REPOSITORY,
            revision: STWO_REVISION,
        },
        cargo_lock_sha256: sha256_hex(CARGO_LOCK),
        executable_sha256: executable.map(sha256_file).transpose()?,
        channels: Channel::ALL,
        proof_formats: ProofFormat::ALL,
        max_proof_bytes: MAX_PROOF_BYTES,
        prover_input_schema: "stwo_cairo_adapter::ProverInput@1.2.2",
        claim_summary_schema: claim::SUMMARY_SCHEMA,
        max_input_bytes: input::MAX_INPUT_BYTES,
    })
}

pub fn proof_sha256(path: &Path) -> Result<String> {
    validate_proof_file(path)?;
    sha256_file(path)
}

pub fn verify_proof(path: &Path, channel: Channel, format: ProofFormat) -> Result<()> {
    validate_proof_file(path)?;
    match channel {
        Channel::Blake2s => {
            let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
                deserialize_proof_from_file(path, format.upstream())
                    .context("failed to deserialize Blake2s Cairo proof")?;
            verify_cairo::<Blake2sMerkleChannel>(proof)
                .context("official Blake2s verify_cairo rejected the proof")
        }
        Channel::Blake2sM31 => {
            let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
                deserialize_proof_from_file(path, format.upstream())
                    .context("failed to deserialize Blake2s-M31 Cairo proof")?;
            verify_cairo::<Blake2sM31MerkleChannel>(proof)
                .context("official Blake2s-M31 verify_cairo rejected the proof")
        }
        Channel::Poseidon252 => {
            let proof: CairoProofForRustVerifier<Poseidon252MerkleHasher> =
                deserialize_proof_from_file(path, format.upstream())
                    .context("failed to deserialize Poseidon252 Cairo proof")?;
            verify_cairo::<Poseidon252MerkleChannel>(proof)
                .context("official Poseidon252 verify_cairo rejected the proof")
        }
    }
}

pub fn inspect_blake2s_proof_public_statement(
    path: &Path,
    format: ProofFormat,
) -> Result<input::public_statement::PublicStatementSummary> {
    validate_proof_file(path)?;
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(path, format.upstream())
            .context("failed to deserialize Blake2s Cairo proof")?;
    Ok(input::public_statement::summarize(&proof.claim.public_data))
}

pub fn inspect_blake2s_proof_claim(
    path: &Path,
    format: ProofFormat,
) -> Result<claim::ProofClaimSummary> {
    validate_proof_file(path)?;
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(path, format.upstream())
            .context("failed to deserialize Blake2s Cairo proof")?;
    Ok(claim::summarize(
        &proof.claim,
        proof.interaction_pow,
        &proof.interaction_claim,
        proof.preprocessed_trace_variant,
    ))
}

pub fn write_json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().context("result path has no file name")?;
    for sequence in 0..1_000_u32 {
        let temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        let mut file = match File::options()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create result temporary file"),
        };
        let publish = (|| -> Result<()> {
            serde_json::to_writer(&mut file, value).context("failed to serialize result")?;
            file.write_all(b"\n")
                .context("failed to terminate result")?;
            file.sync_all().context("failed to sync result")?;
            std::fs::hard_link(&temporary, path)
                .with_context(|| format!("refusing to replace {}", path.display()))
        })();
        drop(file);
        std::fs::remove_file(&temporary).ok();
        return publish;
    }
    bail!("unable to allocate a unique result temporary file")
}

fn validate_proof_file(path: &Path) -> Result<()> {
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?;
    ensure!(metadata.is_file(), "proof path is not a regular file");
    ensure!(metadata.len() > 0, "proof file is empty");
    ensure!(
        metadata.len() <= MAX_PROOF_BYTES,
        "proof exceeds the {MAX_PROOF_BYTES}-byte limit"
    );
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 256 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .context("failed while hashing file")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_and_format_parsers_fail_closed() {
        assert_eq!(Channel::parse("blake2s").unwrap(), Channel::Blake2s);
        assert_eq!(ProofFormat::parse("binary").unwrap(), ProofFormat::Binary);
        assert!(Channel::parse("other").is_err());
        assert!(ProofFormat::parse("cairo_serde").is_err());
    }

    #[test]
    fn identity_is_bound_to_official_sources() {
        let value = identity(None).unwrap();
        assert_eq!(value.stwo_cairo.revision, STWO_CAIRO_REVISION);
        assert_eq!(value.stwo.revision, STWO_REVISION);
        assert_eq!(value.cargo_lock_sha256.len(), 64);
        assert!(value.executable_sha256.is_none());
    }
}
