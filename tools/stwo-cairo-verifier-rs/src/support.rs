pub const STWO_CAIRO_REPOSITORY: &str = "https://github.com/teddyjfpender/stwo-cairo";
pub const STWO_CAIRO_REVISION: &str = "dcd5834565b7a26a27a614e353c9c60109ebc1d9";
pub const STWO_REPOSITORY: &str = "https://github.com/teddyjfpender/stwo";
pub const STWO_REVISION: &str = "9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2";
pub const JSON_PROOF_PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const EXTENDED_JSON_PROOF_ENCODING: &str = "cairo_proof_extended_json_v1";
pub const RUST_VERIFIER_JSON_PROOF_ENCODING: &str = "cairo_proof_rust_verifier_json_v1";
pub const EMBEDDED_STATEMENT_ENCODING: &str = "embedded_in_cairo_proof_json_v1";
pub const JSON_BRIDGE_PROVENANCE_SOURCE: &str = "gpu_bench_json_bridge_v1";
pub const COMPACT_PROOF_PROVENANCE_SOURCE: &str = "metal_prover_service_v1";
pub const COMPACT_PROOF_SERIALIZATION: &str = "resident_sn2_bundle_v1";

const CARGO_LOCK: &[u8] = include_bytes!("../Cargo.lock");

#[derive(Debug, Serialize)]
pub struct SourcePin {
    pub repository: &'static str,
    pub revision: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AdapterIdentity {
    pub schema_version: u32,
    pub adapter_version: &'static str,
    pub envelope_abi: &'static str,
    pub cargo_lock_sha256: String,
    pub executable_sha256: Option<String>,
    pub stwo_cairo: SourcePin,
    pub stwo: SourcePin,
    pub proof_reconstruction_implemented: bool,
    pub canonical_verification_implemented: bool,
    pub json_proof_verification_implemented: bool,
    pub compact_claim_reconstruction_implemented: bool,
    pub compact_stark_proof_reconstruction_implemented: bool,
    pub compact_proof_reconstruction_implemented: bool,
    pub compact_proof_verification_implemented: bool,
}

#[derive(Debug, Serialize)]
pub struct SectionLimits {
    pub protocol_bytes: u64,
    pub statement_bytes: u64,
    pub proof_bytes: u64,
    pub provenance_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct VerifierConfig {
    pub schema_version: u32,
    pub adapter_version: &'static str,
    pub envelope_abi: &'static str,
    pub result_schema_version: u32,
    pub argv_template: [&'static str; 5],
    pub timeout_ms: u64,
    pub max_envelope_bytes: u64,
    pub max_result_bytes: u64,
    pub max_address_space_bytes: u64,
    pub section_limits: SectionLimits,
    pub stwo_cairo: SourcePin,
    pub stwo: SourcePin,
}

pub fn adapter_identity(executable: Option<&Path>) -> io::Result<AdapterIdentity> {
    Ok(AdapterIdentity {
        schema_version: 1,
        adapter_version: env!("CARGO_PKG_VERSION"),
        envelope_abi: ENVELOPE_ABI,
        cargo_lock_sha256: hex_digest(sha256(CARGO_LOCK)),
        executable_sha256: executable.map(sha256_file).transpose()?.map(hex_digest),
        stwo_cairo: SourcePin {
            repository: STWO_CAIRO_REPOSITORY,
            revision: STWO_CAIRO_REVISION,
        },
        stwo: SourcePin {
            repository: STWO_REPOSITORY,
            revision: STWO_REVISION,
        },
        proof_reconstruction_implemented: true,
        canonical_verification_implemented: true,
        json_proof_verification_implemented: true,
        compact_claim_reconstruction_implemented: true,
        compact_stark_proof_reconstruction_implemented: true,
        compact_proof_reconstruction_implemented: true,
        compact_proof_verification_implemented: true,
    })
}

pub fn verifier_config() -> VerifierConfig {
    VerifierConfig {
        schema_version: 1,
        adapter_version: env!("CARGO_PKG_VERSION"),
        envelope_abi: ENVELOPE_ABI,
        result_schema_version: 1,
        argv_template: [
            "verify",
            "--envelope",
            "{exclusive_envelope_path}",
            "--result",
            "{exclusive_result_path}",
        ],
        timeout_ms: DEFAULT_TIMEOUT_MS,
        max_envelope_bytes: MAX_ENVELOPE_LEN,
        max_result_bytes: MAX_RESULT_LEN,
        max_address_space_bytes: MAX_ADDRESS_SPACE_LEN,
        section_limits: SectionLimits {
            protocol_bytes: SectionKind::Protocol.max_payload_len(),
            statement_bytes: SectionKind::Statement.max_payload_len(),
            proof_bytes: SectionKind::Proof.max_payload_len(),
            provenance_bytes: SectionKind::Provenance.max_payload_len(),
        },
        stwo_cairo: SourcePin {
            repository: STWO_CAIRO_REPOSITORY,
            revision: STWO_CAIRO_REVISION,
        },
        stwo: SourcePin {
            repository: STWO_REPOSITORY,
            revision: STWO_REVISION,
        },
    }
}

pub fn read_envelope_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "envelope path is not a regular file",
        ));
    }
    if metadata.len() > MAX_ENVELOPE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "envelope length {} exceeds {MAX_ENVELOPE_LEN}-byte limit",
                metadata.len()
            ),
        ));
    }

    let capacity = usize::try_from(metadata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "envelope length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::take(&mut file, MAX_ENVELOPE_LEN + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ENVELOPE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "envelope grew beyond the allocation limit while reading",
        ));
    }
    Ok(bytes)
}

pub fn write_json_atomically<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "result path has no file name")
    })?;
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "result path already exists",
        ));
    }

    let encoded = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "result length overflow"))?;
    if encoded_len.saturating_add(1) > MAX_RESULT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encoded result length {} exceeds {MAX_RESULT_LEN}-byte limit",
                encoded_len.saturating_add(1)
            ),
        ));
    }

    let mut reserved = None;
    for attempt in 0..32_u32 {
        let name = format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            attempt
        );
        let candidate = parent.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                reserved = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temporary, mut file) = reserved.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve an atomic result temporary file",
        )
    })?;

    let write_result = (|| {
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    let publish = fs::hard_link(&temporary, path);
    let cleanup = fs::remove_file(&temporary);
    publish?;
    cleanup?;
    if let Ok(directory) = File::open(parent) {
        directory.sync_all()?;
    }
    Ok(())
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

pub fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
use crate::framing::{
    SectionKind, DEFAULT_TIMEOUT_MS, ENVELOPE_ABI, MAX_ADDRESS_SPACE_LEN, MAX_ENVELOPE_LEN,
    MAX_RESULT_LEN,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
