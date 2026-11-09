//! Host-only independent standard EIP-4844 sidecar check, no guest/prover.
use c_kzg::{Blob, Bytes48, KzgSettings};
use sha2::{Digest, Sha256};
use std::{env, error::Error, fs, path::Path};
const WIDTH: usize = 48 + 48 + 131_072;
const SETUP: [u8; 32] = [0xd3,0x9b,0x9f,0x2d,0x04,0x7c,0xc9,0xdc,0xa2,0xde,0x58,0xf2,0x64,0xb6,0xa0,0x94,0x48,0xcc,0xd3,0x4d,0xb9,0x67,0x88,0x1a,0x67,0x13,0xea,0xca,0xcf,0x0f,0x26,0xb7];
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 3 { return Err("SETUP_FILE BOUNDED_SIDECAR_BUNDLE required".into()); }
    let setup = Path::new(&args[1]);
    if fs::metadata(setup)?.len() > 1 << 20 { return Err("setup byte cap".into()); }
    let setup_bytes = fs::read(setup)?;
    if Sha256::digest(&setup_bytes).as_slice() != SETUP { return Err("trusted setup SHA mismatch".into()); }
    let input = Path::new(&args[2]);
    if fs::metadata(input)?.len() > 64 << 20 { return Err("sidecar bundle byte cap".into()); }
    let bytes = fs::read(input)?;
    if bytes.len() < 4 { return Err("truncated bundle".into()); }
    let count = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
    if count > 256 || bytes.len() != 4 + count * WIDTH { return Err("noncanonical bundle count/length".into()); }
    let settings = KzgSettings::parse_kzg_trusted_setup(std::str::from_utf8(&setup_bytes)?, 0)?;
    let mut previous: Option<[u8; 48]> = None;
    for data in bytes[4..].chunks_exact(WIDTH) {
        let commitment = Bytes48::from_bytes(&data[..48])?;
        let proof = Bytes48::from_bytes(&data[48..96])?;
        let blob = Blob::from_bytes(&data[96..])?;
        let current: [u8; 48] = data[..48].try_into()?;
        if previous.is_some_and(|p| p >= current) { return Err("sidecar order/duplicate".into()); }
        previous = Some(current);
        if settings.blob_to_kzg_commitment(&blob)?.to_bytes().as_ref() != commitment.as_ref() {
            return Err("blob commitment mismatch".into());
        }
        if !settings.verify_blob_kzg_proof(&blob, &commitment, &proof)? {
            return Err("standard blob KZG proof rejected".into());
        }
    }
    println!("{{\"verified_standard_sidecars\":{count},\"trusted_setup_sha256\":\"d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7\",\"kzg_verified\":true}}");
    Ok(())
}
