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

#[cfg(feature = "host")]
#[test]
fn opens_mainnet_safe_head_and_its_system_config_from_the_checkpoint() {
    use alloy_consensus::proofs::calculate_transaction_root;
    use alloy_eips::{BlockNumHash, eip2718::Decodable2718};
    use alloy_rlp::Decodable;
    use kona_derive::L2ChainProvider;
    use kona_protocol::{BatchValidationProvider, OutputRoot};
    use op_alloy_consensus::OpTxEnvelope;
    use std::sync::Arc;
    use stwo_kona_execution::{
        anchored_l2::AnchoredL2,
        transition::{Transition, TransitionError, verify_calldata_transition},
    };

    // Header and body imported from the pinned Kona replay corpus, block 121057303.
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("op-mainnet-121057303-body.json")).unwrap();
    let header_rlp =
        alloy_primitives::hex::decode(fixture["expected_rlp"].as_str().unwrap()).unwrap();
    let header = Header::decode(&mut header_rlp.as_slice()).unwrap();
    let hash: B256 = fixture["expected_block_hash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(hash, keccak256(&header_rlp));
    assert_eq!(header.number, 121057303);
    let txs: Vec<_> = fixture["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tx| {
            let bytes = alloy_primitives::hex::decode(tx.as_str().unwrap()).unwrap();
            OpTxEnvelope::decode_2718_exact(&bytes).unwrap()
        })
        .collect();
    assert_eq!(header.transactions_root, calculate_transaction_root(&txs));
    let mut trie = ordered_trie_with_encoder(&txs, Encodable2718::encode_2718);
    assert_eq!(trie.root(), header.transactions_root);
    let mut records: BTreeMap<_, _> = trie
        .take_proof_nodes()
        .into_inner()
        .into_values()
        .map(|data| (keccak256(&data), data.to_vec()))
        .collect();
    records.insert(hash, header_rlp);
    // This test checkpoint uses a synthetic withdrawal root. The actual header,
    // state commitment, and every transaction are pinned to the mainnet hash.
    let checkpoint = OutputRoot::from_parts(header.state_root, B256::ZERO, hash);
    records.insert(checkpoint.hash(), checkpoint.encode().to_vec());
    let wrong = OutputRoot::from_parts(B256::ZERO, B256::ZERO, hash);
    records.insert(wrong.hash(), wrong.encode().to_vec());
    let headers: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("eth-mainnet-20035800-anchor.json")).unwrap();
    for header in &headers {
        records.insert(
            header["hash"].as_str().unwrap().parse().unwrap(),
            alloy_primitives::hex::decode(header["rlp"].as_str().unwrap()).unwrap(),
        );
    }
    let input = encode(b"", &records.into_iter().collect::<Vec<_>>()).unwrap();
    let witness = || Witness::parse(&input, Validation::Lazy).unwrap();
    let config = Arc::new(kona_registry::ROLLUP_CONFIGS.get(&10).unwrap().clone());
    assert!(matches!(
        AnchoredL2::new(witness(), header.number, wrong.hash(), config.clone()),
        Err(AnchorError::OutputRoot)
    ));
    let mut provider =
        AnchoredL2::new(witness(), header.number, checkpoint.hash(), config.clone()).unwrap();
    let info = ready(provider.l2_block_info_by_number(header.number)).unwrap();
    assert_eq!(info.hash(), hash);
    let payload: stwo_kona_execution::execution::Fixture =
        serde_json::from_str(include_str!("fixture.json")).unwrap();
    let mut other_parent = info;
    other_parent.block_info.hash = B256::ZERO;
    let prepared = kona_protocol::OpAttributesWithParent::new(
        payload.executing_payload,
        other_parent,
        None,
        false,
    );
    assert!(matches!(
        provider.execute_prepared(prepared, header.number + 1, B256::ZERO),
        Err(AnchorError::Ancestry)
    ));

    assert_eq!(
        info.l1_origin.hash,
        "0xc10a3bb5847ad354f9a70b56f253baaea1c3841647851c4c62e10b22fe4e8694"
            .parse::<B256>()
            .unwrap()
    );
    let claim = Transition {
        anchor: BlockNumHash {
            number: 20_035_800,
            hash: headers[1]["hash"].as_str().unwrap().parse().unwrap(),
        },
        previous_number: header.number,
        previous_root: checkpoint.hash(),
        next_number: header.number + 1,
        next_root: B256::ZERO,
        next_origin: info.l1_origin,
    };
    let l1_config = Arc::new(kona_registry::L1_CONFIGS.get(&1).unwrap().clone());
    let verify = |claim| {
        ready(verify_calldata_transition(
            &input,
            claim,
            config.clone(),
            l1_config.clone(),
        ))
    };
    assert!(matches!(
        verify(Transition {
            next_origin: BlockNumHash {
                hash: B256::ZERO,
                ..claim.next_origin
            },
            ..claim
        }),
        Err(TransitionError::Origin)
    ));
    // The mainnet fixture opens the safe head and canonical L1 origin, but
    // lacks the parent block required by Kona's reset walkback.
    assert!(matches!(
        verify(claim),
        Err(TransitionError::Pipeline(kona_derive::PipelineErrorKind::Critical(
            kona_derive::PipelineError::Provider(message)
        ))) if message.contains(&format!("{:?}", header.parent_hash))
    ));
    assert_eq!(
        ready(provider.block_by_number(header.number))
            .unwrap()
            .body
            .transactions,
        txs
    );
    assert_eq!(
        ready(provider.system_config_by_l2_hash(hash, config))
            .unwrap()
            .gas_limit,
        header.gas_limit
    );
}

#[test]
fn authenticates_the_mainnet_l1_origin_from_its_successor() {
    // Canonical execution headers from Ethereum Mainnet JSON-RPC. The origin
    // hash is also committed by the first deposit in the OP Mainnet fixture.
    let headers: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("eth-mainnet-20035800-anchor.json")).unwrap();
    let mut records = BTreeMap::new();
    for header in &headers {
        let hash: B256 = header["hash"].as_str().unwrap().parse().unwrap();
        let rlp = alloy_primitives::hex::decode(header["rlp"].as_str().unwrap()).unwrap();
        assert_eq!(keccak256(&rlp), hash);
        records.insert(hash, rlp);
    }
    let input = encode(b"", &records.into_iter().collect::<Vec<_>>()).unwrap();
    let anchor = headers[1]["hash"].as_str().unwrap().parse().unwrap();
    let origin = headers[0]["hash"]
        .as_str()
        .unwrap()
        .parse::<B256>()
        .unwrap();
    let witness = Witness::parse(&input, Validation::Lazy).unwrap();
    let mut provider = AnchoredL1::new(witness, 20_035_800, anchor).unwrap();
    assert_eq!(
        ready(provider.block_info_by_number(20_035_799))
            .unwrap()
            .hash,
        origin
    );
    assert_eq!(
        ready(provider.header_by_hash(origin)).unwrap().number,
        20_035_799
    );
}
