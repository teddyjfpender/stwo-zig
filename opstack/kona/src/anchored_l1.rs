//! L1 execution data for Kona derivation, authenticated from one trusted head.
use crate::{execution::decode_exact, witness::Witness};
use alloc::{boxed::Box, collections::BTreeMap, string::ToString, vec::Vec};
use alloy_consensus::{Header, Receipt, ReceiptEnvelope, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::B256;
use async_trait::async_trait;
use kona_derive::{ChainProvider, PipelineError, PipelineErrorKind};
use kona_mpt::{OrderedListWalker, TrieNode, TrieProvider};
use kona_protocol::BlockInfo;

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("{0}")]
    Witness(#[from] crate::witness::Error),
    #[error("L1 header number or ancestry does not match the anchor")]
    Ancestry,
    #[error("L1 ordered trie: {0}")]
    Trie(kona_mpt::OrderedListWalkerError),
    #[error("invalid EIP-2718 L1 list entry")]
    Envelope,
}

impl From<AnchorError> for PipelineErrorKind {
    fn from(error: AnchorError) -> Self {
        PipelineError::Provider(error.to_string()).crit()
    }
}

#[derive(Debug)]
pub struct AnchoredL1<'a> {
    witness: Witness<'a>,
    oldest: BlockInfo,
    head_number: u64,
    headers: BTreeMap<u64, (B256, Header)>,
}

impl<'a> AnchoredL1<'a> {
    /// `hash` and `number` must come from the public transition statement.
    pub fn new(witness: Witness<'a>, number: u64, hash: B256) -> Result<Self, AnchorError> {
        let header: Header = decode_exact(witness.get(hash)?)?;
        if header.number != number {
            return Err(AnchorError::Ancestry);
        }
        let oldest = block_info(hash, &header);
        Ok(Self {
            witness,
            oldest,
            head_number: number,
            headers: BTreeMap::from([(number, (hash, header))]),
        })
    }

    fn ancestor(&mut self, number: u64) -> Result<&(B256, Header), AnchorError> {
        if number > self.head_number {
            return Err(AnchorError::Ancestry);
        }
        while self.oldest.number > number {
            let hash = self.oldest.parent_hash;
            let header: Header = decode_exact(self.witness.get(hash)?)?;
            if header.number != self.oldest.number - 1 {
                return Err(AnchorError::Ancestry);
            }
            self.oldest = block_info(hash, &header);
            self.headers.insert(header.number, (hash, header));
        }
        self.headers.get(&number).ok_or(AnchorError::Ancestry)
    }

    fn authenticated_header(&mut self, hash: B256) -> Result<Header, AnchorError> {
        // A hash-addressed preimage can be from a competing fork. Its height
        // is only a lookup hint until the anchored chain agrees with its hash.
        let candidate: Header = decode_exact(self.witness.get(hash)?)?;
        let (canonical_hash, header) = self.ancestor(candidate.number)?;
        if *canonical_hash != hash {
            return Err(AnchorError::Ancestry);
        }
        Ok(header.clone())
    }

    fn ordered_list<T: Decodable2718>(&self, root: B256) -> Result<Vec<T>, AnchorError> {
        if root == alloy_consensus::EMPTY_ROOT_HASH {
            return Ok(Vec::new());
        }
        OrderedListWalker::try_new_hydrated(root, self)
            .map_err(AnchorError::Trie)?
            .map(|(_, encoded)| {
                let mut bytes = encoded.as_ref();
                let item = T::decode_2718(&mut bytes).map_err(|_| AnchorError::Envelope)?;
                if !bytes.is_empty() {
                    return Err(AnchorError::Envelope);
                }
                Ok(item)
            })
            .collect()
    }
}

fn block_info(hash: B256, header: &Header) -> BlockInfo {
    BlockInfo {
        hash,
        number: header.number,
        parent_hash: header.parent_hash,
        timestamp: header.timestamp,
    }
}

impl TrieProvider for AnchoredL1<'_> {
    type Error = AnchorError;

    fn trie_node_by_hash(&self, hash: B256) -> Result<TrieNode, Self::Error> {
        Ok(decode_exact(self.witness.get(hash)?)?)
    }
}

#[async_trait]
impl ChainProvider for AnchoredL1<'_> {
    type Error = AnchorError;

    async fn header_by_hash(&mut self, hash: B256) -> Result<Header, Self::Error> {
        self.authenticated_header(hash)
    }

    async fn block_info_by_number(&mut self, number: u64) -> Result<BlockInfo, Self::Error> {
        let (hash, header) = self.ancestor(number)?;
        Ok(block_info(*hash, header))
    }

    async fn receipts_by_hash(&mut self, hash: B256) -> Result<Vec<Receipt>, Self::Error> {
        let header = self.authenticated_header(hash)?;
        self.ordered_list::<ReceiptEnvelope>(header.receipts_root)?
            .into_iter()
            .map(|receipt| receipt.as_receipt().cloned().ok_or(AnchorError::Envelope))
            .collect()
    }

    async fn block_info_and_transactions_by_hash(
        &mut self,
        hash: B256,
    ) -> Result<(BlockInfo, Vec<TxEnvelope>), Self::Error> {
        let header = self.authenticated_header(hash)?;
        Ok((
            block_info(hash, &header),
            self.ordered_list(header.transactions_root)?,
        ))
    }
}
