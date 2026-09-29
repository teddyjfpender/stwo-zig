//! Diagnostic format conversion only. The official verifier must still accept
//! the emitted JSON before it is called an official Cairo proof.
use std::{env, fs, io::Write};
use stwo_cairo_verifier_adapter::compact_codec::{
    reconstruct_cairo_proof_v1, CompactProtocolV1, CompactStatementV1,
};
use stwo_cairo_verifier_adapter::{Envelope, SectionKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let input = args.next().ok_or("expected compact envelope")?;
    let output = args.next().ok_or("expected output JSON path")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let bytes = fs::read(input)?;
    let envelope = Envelope::parse(&bytes)?;
    let protocol = CompactProtocolV1::decode(envelope.section(SectionKind::Protocol).payload)?;
    let statement = CompactStatementV1::decode(envelope.section(SectionKind::Statement).payload)?;
    let proof = reconstruct_cairo_proof_v1(
        envelope.section(SectionKind::Proof).payload,
        &protocol,
        &statement,
    )?;
    let json = serde_json::to_vec(&proof)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&json)?;
    file.sync_all()?;
    Ok(())
}
