//! Failure localization only: checks the transcript through Cairo OODS.
//! Never verifies or emits a full proof. The failed FRI suffix is outside scope.
use cairo_air::{
    cairo_components::CairoComponents, claims::lookup_sum, relations::CommonLookupElements,
};
use serde_json::json;
use std::{error::Error, fs, io::Write};
use stwo::core::{
    air::Components,
    channel::{Blake2sChannel, Channel},
    circle::CirclePoint,
    fields::qm31::QM31,
    pcs::CommitmentSchemeVerifier,
    vcs_lifted::blake2_merkle::Blake2sMerkleChannel,
};
use stwo_cairo_verifier_adapter::compact_codec::{
    derive_sample_shape_v1, reconstruct_claims_prefix_for_diagnostics_v1, CompactProtocolV1,
    CompactStatementV1,
};

fn word(bytes: &[u8], index: usize) -> Result<u32, Box<dyn Error>> {
    Ok(u32::from_le_bytes(
        bytes
            .get(index * 4..index * 4 + 4)
            .ok_or("truncated transport")?
            .try_into()?,
    ))
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: cuda_prefix_oracle <transport> <protocol> <statement> <exclusive-result.json>"
                .into(),
        );
    }
    let transport = fs::read(&args[0])?;
    let protocol = CompactProtocolV1::decode(&fs::read(&args[1])?)?;
    let statement = CompactStatementV1::decode(&fs::read(&args[2])?)?;
    if word(&transport, 0)? != 0x43505753
        || word(&transport, 1)? != 1
        || word(&transport, 2)? as usize * 4 != transport.len()
        || word(&transport, 3)? != 6
    {
        return Err("invalid SWPC framing".into());
    }
    let degree_verdict = word(&transport, 15)?;
    let mut sections = Vec::new();
    let mut cursor = 34;
    for i in 0..6 {
        if word(&transport, 16 + 3 * i)? != (i + 1) as u32
            || word(&transport, 17 + 3 * i)? as usize != cursor
        {
            return Err("noncanonical SWPC sections".into());
        }
        let count = word(&transport, 18 + 3 * i)? as usize;
        sections.push(
            transport
                .get(cursor * 4..(cursor + count) * 4)
                .ok_or("invalid section extent")?
                .to_vec(),
        );
        cursor += count;
    }
    if cursor * 4 != transport.len() {
        return Err("SWPC tail".into());
    }
    // Decode only the byte-exact prefix. Failed suffixes remain untouched.
    let mut payload = sections[0].clone();
    if sections[4].len() != 16 {
        return Err("invalid PoW extent".into());
    }
    payload.extend_from_slice(&sections[4][..8]);
    let proof = reconstruct_claims_prefix_for_diagnostics_v1(&payload, &protocol, &statement)?;
    let shape = derive_sample_shape_v1(
        &protocol,
        &proof.cairo_claim,
        &proof.interaction_claim,
        protocol.preprocessed_trace_variant,
    )?;
    let mut sample_index = 0;
    let mut sampled = Vec::new();
    for tree in shape {
        let mut columns = Vec::new();
        for count in tree {
            let mut values = Vec::new();
            for _ in 0..count {
                let mut coords = [0; 4];
                for c in &mut coords {
                    *c = word(&sections[1], sample_index)?;
                    sample_index += 1;
                    if *c >= 0x7fffffff {
                        return Err("noncanonical OODS sample".into());
                    }
                }
                values.push(QM31::from_u32_unchecked(
                    coords[0], coords[1], coords[2], coords[3],
                ));
            }
            columns.push(values);
        }
        sampled.push(columns);
    }
    if sample_index * 4 != sections[1].len() {
        return Err("OODS sample extent mismatch".into());
    }
    let sampled = stwo::core::pcs::TreeVec::new(sampled);
    let roots: Vec<_> = sections[0][..protocol.commitment_count as usize * 32]
        .chunks_exact(32)
        .map(|b| stwo::core::vcs::blake2_hash::Blake2sHash(b.try_into().unwrap()))
        .collect();
    let config = stwo::core::pcs::PcsConfig {
        pow_bits: protocol.query_pow_bits,
        fri_config: stwo::core::fri::FriConfig::new(
            protocol.log_last_layer_degree_bound,
            protocol.log_blowup_factor,
            protocol.query_count as usize,
            protocol.fri_fold_step,
        ),
        lifting_log_size: protocol.fri_lifting_log_size,
    };
    let mut channel = Blake2sChannel::default();
    channel.mix_felts(&[protocol.channel_salt.into()]);
    config.mix_into(&mut channel);
    let mut scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let mut logs = proof.cairo_claim.log_sizes();
    let preprocessed = protocol.preprocessed_trace_variant.to_preprocessed_trace();
    logs.insert(0, preprocessed.log_sizes());
    scheme.commit(roots[0], &logs[0], &mut channel);
    proof
        .cairo_claim
        .mix_into::<Blake2sMerkleChannel>(&mut channel);
    scheme.commit(roots[1], &logs[1], &mut channel);
    let interaction_pow_ok =
        channel.verify_pow_nonce(protocol.interaction_pow_bits, proof.interaction_pow);
    channel.mix_u64(proof.interaction_pow);
    let lookup_channel_digest = channel.digest().0;
    let lookups = CommonLookupElements::draw(&mut channel);
    let sum = lookup_sum(&proof.cairo_claim, &lookups, &proof.interaction_claim);
    let lookup_ok = sum == QM31::default();
    proof.interaction_claim.mix_into(&mut channel);
    scheme.commit(roots[2], &logs[2], &mut channel);
    let alpha = channel.draw_secure_felt();
    scheme.commit(roots[3], &[protocol.max_log_degree_bound; 8], &mut channel);
    let point = CirclePoint::<QM31>::get_random_point(&mut channel);
    let cairo_components = CairoComponents::new(
        &proof.cairo_claim,
        &lookups,
        &proof.interaction_claim,
        &preprocessed.ids(),
    );
    let components = Components {
        components: cairo_components.components(),
        n_preprocessed_columns: logs[0].len(),
    };
    let expected = components.eval_composition_polynomial_at_point(
        point,
        &sampled,
        alpha,
        protocol.max_log_degree_bound,
    );
    let samples = &sampled[3];
    let left =
        QM31::from_partial_evals([samples[0][0], samples[1][0], samples[2][0], samples[3][0]]);
    let right =
        QM31::from_partial_evals([samples[4][0], samples[5][0], samples[6][0], samples[7][0]]);
    let observed = left + point.repeated_double(protocol.max_log_degree_bound - 1).x * right;
    let report = json!({"schema":"stwo-cairo-cuda-prefix-oracle-v1","full_proof_verified":false,"scope":"byte-exact prefix through OODS; FRI/queries/openings not verified; final polynomial omitted", "cuda_degree_verdict":degree_verdict,"interaction_pow_ok":interaction_pow_ok,"lookup_sum_ok":lookup_ok,"lookup_sum":sum,"lookup_channel_digest_hex":lookup_channel_digest.iter().map(|x|format!("{x:02x}")).collect::<String>(),"composition_oods_ok":expected==observed,"expected_oods":expected,"observed_oods":observed,"composition_alpha":alpha,"oods_point":{"x":point.x,"y":point.y}});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[3])?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!("{report}");
    Ok(())
}
