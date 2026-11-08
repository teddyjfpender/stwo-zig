//! L1 execution data for Kona derivation, authenticated from one trusted head.
use crate::{
    anchored_chain::{AnchoredChain, block_info},
    witness::Witness,
};
use alloc::{boxed::Box, vec::Vec};
use alloy_consensus::{Header, Receipt, ReceiptEnvelope, TxEnvelope};
use alloy_primitives::{Address, B256, BloomInput};
use async_trait::async_trait;
use kona_derive::ChainProvider;
use kona_genesis::{CONFIG_UPDATE_TOPIC, RollupConfig};
use kona_protocol::{BlockInfo, DEPOSIT_EVENT_ABI_HASH};

pub use crate::anchored_chain::AnchorError;

#[derive(Debug, Clone)]
pub struct AnchoredL1<'a> {
    chain: AnchoredChain<'a>,
    receipt_topics: Option<[(Address, B256); 2]>,
}

fn might_have_log(header: &Header, address: Address, topic: B256) -> bool {
    header
        .logs_bloom
        .contains_input(BloomInput::Raw(address.as_slice()))
        && header
            .logs_bloom
            .contains_input(BloomInput::Raw(topic.as_slice()))
}

impl<'a> AnchoredL1<'a> {
    /// `hash` and `number` must come from the public transition statement.
    pub fn new(witness: Witness<'a>, number: u64, hash: B256) -> Result<Self, AnchorError> {
        Ok(Self {
            chain: AnchoredChain::new(witness, number, hash)?,
            receipt_topics: None,
        })
    }

    /// Restrict the receipt query to the two log kinds consumed by the pinned
    /// Kona derivation stages. This mode is never returned to general callers.
    pub(crate) fn for_derivation(mut self, config: &RollupConfig) -> Self {
        self.receipt_topics = Some([
            (config.l1_system_config_address, CONFIG_UPDATE_TOPIC),
            (config.deposit_contract_address, DEPOSIT_EVENT_ABI_HASH),
        ]);
        self
    }
}

#[async_trait]
impl ChainProvider for AnchoredL1<'_> {
    type Error = AnchorError;

    async fn header_by_hash(&mut self, hash: B256) -> Result<Header, Self::Error> {
        self.chain.authenticated_header(hash)
    }

    async fn block_info_by_number(&mut self, number: u64) -> Result<BlockInfo, Self::Error> {
        let (hash, header) = self.chain.ancestor(number)?;
        Ok(block_info(*hash, header))
    }

    async fn receipts_by_hash(&mut self, hash: B256) -> Result<Vec<Receipt>, Self::Error> {
        let header = self.chain.authenticated_header(hash)?;
        // A consensus-valid Ethereum header's bloom cannot have false
        // negatives. If either log could occur, keep the complete list so
        // deposits retain their canonical global log index.
        if self.receipt_topics.is_some_and(|topics| {
            !topics
                .into_iter()
                .any(|(address, topic)| might_have_log(&header, address, topic))
        }) {
            return Ok(Vec::new());
        }
        self.chain
            .ordered_list::<ReceiptEnvelope>(header.receipts_root)?
            .into_iter()
            .map(|receipt| receipt.as_receipt().cloned().ok_or(AnchorError::Envelope))
            .collect()
    }

    async fn block_info_and_transactions_by_hash(
        &mut self,
        hash: B256,
    ) -> Result<(BlockInfo, Vec<TxEnvelope>), Self::Error> {
        let header = self.chain.authenticated_header(hash)?;
        Ok((
            block_info(hash, &header),
            self.chain.ordered_list(header.transactions_root)?,
        ))
    }
}
