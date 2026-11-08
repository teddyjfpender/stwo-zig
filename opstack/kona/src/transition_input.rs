//! Bounded input to the OP Mainnet anchored transition program.
use crate::{
    anchored_blobs::BlobSidecar,
    transition::{
        Transition, TransitionError, VerifiedTransition, verify_blob_transition_statement,
    },
    witness::{HEADER as WITNESS_HEADER, MAX_INPUT, MAX_TRANSITION_WITNESS, Validation, Witness},
};
use alloc::{borrow::Cow, boxed::Box, sync::Arc, vec, vec::Vec};
use alloy_eips::{BlockNumHash, eip4844::BYTES_PER_BLOB};
use alloy_primitives::B256;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};

const MAGIC: &[u8; 8] = b"STWOPD01";
const MAGIC_ZLIB: &[u8; 8] = b"STWOPDZ1";
const HEADER: usize = 8 + 4 * 40 + 8;
const SIDECAR_BYTES: usize = 2 * 48 + BYTES_PER_BLOB;
const MAX_SIDECARS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("invalid anchored transition input length")]
    Length,
    #[error("invalid anchored transition input magic")]
    Version,
    #[error("invalid bounded zlib transition input")]
    Compression,
    #[error("sidecar commitments are not strictly ordered")]
    SidecarOrder,
    #[error("anchored transition preimages must have empty metadata")]
    Metadata,
    #[error(transparent)]
    Witness(#[from] crate::witness::Error),
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error("pinned mainnet chain configuration is missing")]
    Config,
    #[error("in-memory derivation provider returned pending")]
    Pending,
}

pub struct TransitionInput<'a> {
    pub claim: Transition,
    body: Cow<'a, [u8]>,
    witness_len: usize,
}

impl<'a> TransitionInput<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, InputError> {
        if !(HEADER..=MAX_INPUT).contains(&input.len()) {
            return Err(InputError::Length);
        }
        let compressed = match &input[..8] {
            bytes if bytes == MAGIC => false,
            bytes if bytes == MAGIC_ZLIB => true,
            _ => return Err(InputError::Version),
        };
        let field = |index: usize| {
            let bytes = &input[8 + 40 * index..8 + 40 * (index + 1)];
            BlockNumHash {
                number: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                hash: B256::from_slice(&bytes[8..]),
            }
        };
        let (anchor, previous, next, next_origin) = (field(0), field(1), field(2), field(3));
        let claim = Transition {
            anchor,
            previous_number: previous.number,
            previous_root: previous.hash,
            next_number: next.number,
            next_root: next.hash,
            next_origin,
        };
        let u32_at =
            |offset| u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap()) as usize;
        let witness_len = u32_at(HEADER - 8);
        let count = u32_at(HEADER - 4);
        if witness_len < WITNESS_HEADER || count > MAX_SIDECARS {
            return Err(InputError::Length);
        }
        let size = witness_len
            .checked_add(count * SIDECAR_BYTES)
            .ok_or(InputError::Length)?;
        if size > MAX_TRANSITION_WITNESS {
            return Err(InputError::Length);
        }
        let body = if compressed {
            Cow::Owned(inflate_exact(&input[HEADER..], size)?)
        } else {
            if input.len() - HEADER != size {
                return Err(InputError::Length);
            }
            Cow::Borrowed(&input[HEADER..])
        };
        let (witness, sidecars) = body.split_at(witness_len);
        if !Witness::parse_transition(witness, Validation::Lazy)?
            .metadata()
            .is_empty()
        {
            return Err(InputError::Metadata);
        }
        let mut previous = None;
        for bytes in sidecars.chunks_exact(SIDECAR_BYTES) {
            let commitment = &bytes[..48];
            if previous.is_some_and(|old| old >= commitment) {
                return Err(InputError::SidecarOrder);
            }
            previous = Some(commitment);
        }
        Ok(Self {
            claim,
            body,
            witness_len,
        })
    }

    /// The receiver must independently pin the expected OD public output.
    /// Chain rules are fixed by this program.
    pub fn verify(&self) -> Result<VerifiedTransition, InputError> {
        let config = kona_registry::ROLLUP_CONFIGS
            .get(&10)
            .ok_or(InputError::Config)?;
        let l1_config = kona_registry::L1_CONFIGS
            .get(&1)
            .ok_or(InputError::Config)?;
        let sidecars: Vec<_> = self.body[self.witness_len..]
            .chunks_exact(SIDECAR_BYTES)
            .map(|bytes| BlobSidecar {
                blob: bytes[96..].try_into().unwrap(),
                commitment: bytes[..48].try_into().unwrap(),
                proof: bytes[48..96].try_into().unwrap(),
            })
            .collect();
        let future = verify_blob_transition_statement(
            &self.body[..self.witness_len],
            self.claim,
            Arc::new(config.clone()),
            Arc::new(l1_config.clone()),
            &sidecars,
        );
        match core::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => Ok(value?),
            Poll::Pending => Err(InputError::Pending),
        }
    }
}

fn inflate_exact(input: &[u8], len: usize) -> Result<Vec<u8>, InputError> {
    use miniz_oxide::inflate::{
        TINFLStatus,
        core::{DecompressorOxide, decompress, inflate_flags},
    };
    let mut output = vec![0; len];
    let mut decoder = Box::<DecompressorOxide>::default();
    let (status, consumed, produced) = decompress(
        &mut decoder,
        input,
        &mut output,
        0,
        inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    if (status, consumed, produced) != (TINFLStatus::Done, input.len(), len) {
        return Err(InputError::Compression);
    }
    Ok(output)
}

/// Encode a witness with sidecars already sorted by commitment.
pub fn encode(
    claim: Transition,
    witness: &[u8],
    sidecars: &[BlobSidecar<'_>],
) -> Result<Vec<u8>, InputError> {
    if witness.len() > MAX_TRANSITION_WITNESS || sidecars.len() > MAX_SIDECARS {
        return Err(InputError::Length);
    }
    let size = witness.len() + sidecars.len() * SIDECAR_BYTES;
    if size > MAX_TRANSITION_WITNESS {
        return Err(InputError::Length);
    }
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(witness);
    for sidecar in sidecars {
        body.extend_from_slice(&sidecar.commitment);
        body.extend_from_slice(&sidecar.proof);
        body.extend_from_slice(sidecar.blob.as_slice());
    }
    let compressed = if HEADER + size > MAX_INPUT {
        Some(miniz_oxide::deflate::compress_to_vec_zlib(&body, 6))
    } else {
        None
    };
    let (magic, body) = match &compressed {
        Some(compressed) => (MAGIC_ZLIB, compressed.as_slice()),
        None => (MAGIC, body.as_slice()),
    };
    if HEADER + body.len() > MAX_INPUT {
        return Err(InputError::Length);
    }
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(magic);
    for (number, hash) in [
        (claim.anchor.number, claim.anchor.hash),
        (claim.previous_number, claim.previous_root),
        (claim.next_number, claim.next_root),
        (claim.next_origin.number, claim.next_origin.hash),
    ] {
        out.extend_from_slice(&number.to_le_bytes());
        out.extend_from_slice(hash.as_slice());
    }
    out.extend_from_slice(&(witness.len() as u32).to_le_bytes());
    out.extend_from_slice(&(sidecars.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    TransitionInput::parse(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloy_eips::eip4844::Blob;

    #[test]
    fn compressed_body_has_exact_input_and_output_boundaries() {
        let data = [7; 8192];
        let mut compressed = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
        assert_eq!(inflate_exact(&compressed, data.len()).unwrap(), data);
        assert!(matches!(
            inflate_exact(&compressed, data.len() - 1),
            Err(InputError::Compression)
        ));
        assert!(matches!(
            inflate_exact(&compressed, data.len() + 1),
            Err(InputError::Compression)
        ));
        compressed.push(0);
        assert!(matches!(
            inflate_exact(&compressed, data.len()),
            Err(InputError::Compression)
        ));
    }

    #[test]
    fn exact_framing_and_sidecar_order() {
        let claim = Transition {
            anchor: BlockNumHash {
                number: 77,
                hash: B256::repeat_byte(1),
            },
            previous_number: 10,
            previous_root: B256::repeat_byte(2),
            next_number: 11,
            next_root: B256::repeat_byte(3),
            next_origin: BlockNumHash {
                number: 76,
                hash: B256::repeat_byte(4),
            },
        };
        let witness = crate::witness::encode(&[], &[]).unwrap();
        let blob = Box::<Blob>::default();
        let low = BlobSidecar {
            blob: &blob,
            commitment: [1; 48],
            proof: [9; 48],
        };
        let high = BlobSidecar {
            blob: &blob,
            commitment: [2; 48],
            proof: [8; 48],
        };
        let input = encode(claim, &witness, &[low, high]).unwrap();
        let parsed = TransitionInput::parse(&input).unwrap();
        assert_eq!(parsed.claim.anchor, claim.anchor);
        assert_eq!(parsed.claim.previous_number, claim.previous_number);
        assert_eq!(parsed.claim.previous_root, claim.previous_root);
        assert_eq!(parsed.claim.next_number, claim.next_number);
        assert_eq!(parsed.claim.next_root, claim.next_root);
        assert_eq!(parsed.claim.next_origin, claim.next_origin);
        assert_eq!(parsed.body.len() - parsed.witness_len, 2 * SIDECAR_BYTES);
        assert!(matches!(
            TransitionInput::parse(&input[..input.len() - 1]),
            Err(InputError::Length)
        ));
        let mut trailing = input;
        trailing.push(0);
        assert!(matches!(
            TransitionInput::parse(&trailing),
            Err(InputError::Length)
        ));
        trailing.pop();
        trailing[HEADER - 4..HEADER].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            TransitionInput::parse(&trailing),
            Err(InputError::Length)
        ));
        assert!(matches!(
            encode(claim, &witness, &[high, low]),
            Err(InputError::SidecarOrder)
        ));
        assert!(matches!(
            encode(claim, &witness, &[low, low]),
            Err(InputError::SidecarOrder)
        ));
        let hidden = crate::witness::encode(b"hidden metadata", &[]).unwrap();
        assert!(matches!(
            encode(claim, &hidden, &[]),
            Err(InputError::Metadata)
        ));
    }
}
