//! L1 execution data for Kona derivation, authenticated from one trusted head.
use crate::{
    anchored_chain::{AnchoredChain, block_info},
    witness::Witness,
};
use alloc::{boxed::Box, vec::Vec};
use alloy_consensus::{Header, Receipt, ReceiptEnvelope, TxEnvelope};
use alloy_primitives::B256;
use async_trait::async_trait;
use kona_derive::ChainProvider;
use kona_protocol::BlockInfo;

pub use crate::anchored_chain::AnchorError;

#[derive(Debug, Clone)]
pub struct AnchoredL1<'a>(AnchoredChain<'a>);

impl<'a> AnchoredL1<'a> {
    /// `hash` and `number` must come from the public transition statement.
    pub fn new(witness: Witness<'a>, number: u64, hash: B256) -> Result<Self, AnchorError> {
        Ok(Self(AnchoredChain::new(witness, number, hash)?))
    }
}

#[async_trait]
impl ChainProvider for AnchoredL1<'_> {
    type Error = AnchorError;

    async fn header_by_hash(&mut self, hash: B256) -> Result<Header, Self::Error> {
        self.0.authenticated_header(hash)
    }

    async fn block_info_by_number(&mut self, number: u64) -> Result<BlockInfo, Self::Error> {
        let (hash, header) = self.0.ancestor(number)?;
        Ok(block_info(*hash, header))
    }

    async fn receipts_by_hash(&mut self, hash: B256) -> Result<Vec<Receipt>, Self::Error> {
        let header = self.0.authenticated_header(hash)?;
        self.0
            .ordered_list::<ReceiptEnvelope>(header.receipts_root)?
            .into_iter()
            .map(|receipt| receipt.as_receipt().cloned().ok_or(AnchorError::Envelope))
            .collect()
    }

    async fn block_info_and_transactions_by_hash(
        &mut self,
        hash: B256,
    ) -> Result<(BlockInfo, Vec<TxEnvelope>), Self::Error> {
        let header = self.0.authenticated_header(hash)?;
        Ok((
            block_info(hash, &header),
            self.0.ordered_list(header.transactions_root)?,
        ))
    }
}
