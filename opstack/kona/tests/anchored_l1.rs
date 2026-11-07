#![cfg(feature = "derivation")]

use alloy_consensus::{
    EMPTY_ROOT_HASH, Header, Receipt, ReceiptEnvelope, SignableTransaction, TxEnvelope, TxLegacy,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{B256, Signature, U256, keccak256};
use kona_derive::ChainProvider;
use kona_mpt::ordered_trie_with_encoder;
use std::{
    collections::BTreeMap,
    future::Future,
    task::{Context, Poll, Waker},
};
use stwo_kona_execution::{
    anchored_l1::{AnchorError, AnchoredL1},
    witness::{Validation, Witness, encode},
};

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("in-memory derivation provider blocked"),
    }
}

fn add_header(records: &mut BTreeMap<B256, Vec<u8>>, header: &Header) -> B256 {
    let encoded = alloy_rlp::encode(header);
    let hash = keccak256(&encoded);
    records.insert(hash, encoded);
    hash
}

#[test]
fn authenticates_ordered_data_from_the_anchor_and_rejects_other_forks() {
    let receipts = [
        ReceiptEnvelope::Eip1559(
            Receipt {
                status: true.into(),
                cumulative_gas_used: 21_000,
                logs: vec![],
            }
            .into(),
        ),
        ReceiptEnvelope::Legacy(
            Receipt {
                status: false.into(),
                cumulative_gas_used: 42_000,
                logs: vec![],
            }
            .into(),
        ),
    ];
    let mut trie = ordered_trie_with_encoder(&receipts, Encodable2718::encode_2718);
    let receipts_root = trie.root();
    let mut records: BTreeMap<_, _> = trie
        .take_proof_nodes()
        .into_inner()
        .into_values()
        .map(|data| (keccak256(&data), data.to_vec()))
        .collect();
    let transaction = TxEnvelope::from(
        TxLegacy {
            nonce: 1,
            ..Default::default()
        }
        .into_signed(Signature::new(U256::from(1), U256::from(2), false)),
    );
    let mut trie = ordered_trie_with_encoder(
        core::slice::from_ref(&transaction),
        Encodable2718::encode_2718,
    );
    let transactions_root = trie.root();
    records.extend(
        trie.take_proof_nodes()
            .into_inner()
            .into_values()
            .map(|data| (keccak256(&data), data.to_vec())),
    );
    let parent = Header {
        number: 10,
        timestamp: 1000,
        receipts_root,
        transactions_root,
        ..Default::default()
    };
    let parent_hash = add_header(&mut records, &parent);
    let anchor = Header {
        number: 11,
        parent_hash,
        transactions_root: EMPTY_ROOT_HASH,
        ..Default::default()
    };
    let anchor_hash = add_header(&mut records, &anchor);
    let fork_hash = add_header(
        &mut records,
        &Header {
            timestamp: 1001,
            ..parent.clone()
        },
    );
    let input = encode(b"", &records.clone().into_iter().collect::<Vec<_>>()).unwrap();
    let witness = || Witness::parse(&input, Validation::Lazy).unwrap();
    assert!(matches!(
        AnchoredL1::new(witness(), 10, anchor_hash),
        Err(AnchorError::Ancestry)
    ));
    let mut provider = AnchoredL1::new(witness(), 11, anchor_hash).unwrap();
    assert!(matches!(
        ready(provider.header_by_hash(fork_hash)),
        Err(AnchorError::Ancestry)
    ));
    assert!(matches!(
        ready(provider.block_info_by_number(12)),
        Err(AnchorError::Ancestry)
    ));
    assert_eq!(
        ready(provider.block_info_by_number(10)).unwrap().hash,
        parent_hash
    );
    assert_eq!(
        ready(provider.receipts_by_hash(parent_hash)).unwrap(),
        receipts.map(|receipt| receipt.as_receipt().unwrap().clone())
    );
    let (info, txs): (_, Vec<TxEnvelope>) =
        ready(provider.block_info_and_transactions_by_hash(parent_hash)).unwrap();
    assert_eq!(info.hash, parent_hash);
    assert_eq!(txs, vec![transaction]);
    assert!(
        ready(provider.block_info_and_transactions_by_hash(anchor_hash))
            .unwrap()
            .1
            .is_empty()
    );

    records.get_mut(&receipts_root).unwrap()[0] ^= 1;
    let input = encode(b"", &records.into_iter().collect::<Vec<_>>()).unwrap();
    let mut provider = AnchoredL1::new(
        Witness::parse(&input, Validation::Lazy).unwrap(),
        11,
        anchor_hash,
    )
    .unwrap();
    assert!(matches!(
        ready(provider.receipts_by_hash(parent_hash)),
        Err(AnchorError::Trie(_))
    ));
}
