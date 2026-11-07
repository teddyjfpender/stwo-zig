//! Hash-addressed headers and ordered tries rooted at a fixed trusted head.
use crate::{execution::decode_exact, witness::Witness};
use alloc::{collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use alloy_consensus::Header;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::B256;
use kona_derive::{PipelineError, PipelineErrorKind};
use kona_mpt::{OrderedListWalker, TrieNode, TrieProvider};
use kona_protocol::BlockInfo;
use spin::{Mutex, MutexGuard};

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("{0}")]
    Witness(#[from] crate::witness::Error),
    #[error("header number or ancestry does not match the anchor")]
    Ancestry,
    #[error("ordered trie: {0}")]
    Trie(kona_mpt::OrderedListWalkerError),
    #[error("invalid EIP-2718 list entry")]
    Envelope,
    #[error("invalid OP checkpoint output preimage or state root")]
    OutputRoot,
    #[error("invalid OP block info: {0}")]
    L2Info(#[from] kona_protocol::FromBlockError),
    #[error("invalid OP system config: {0}")]
    SystemConfig(#[from] kona_protocol::OpBlockConversionError),
    #[error("rollup config differs from the pinned configuration")]
    RollupConfig,
    #[error("Kona execution: {0}")]
    Execution(alloc::string::String),
    #[error("Kona output-root computation: {0}")]
    OutputRootComputation(alloc::string::String),
}

impl From<AnchorError> for PipelineErrorKind {
    fn from(error: AnchorError) -> Self {
        PipelineError::Provider(error.to_string()).crit()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AnchoredChain<'a> {
    witness: Arc<Mutex<Witness<'a>>>,
    oldest: BlockInfo,
    head_number: u64,
    headers: BTreeMap<u64, (B256, Header)>,
}

impl<'a> AnchoredChain<'a> {
    /// `hash` and `number` must come from the public transition statement.
    pub(crate) fn new(witness: Witness<'a>, number: u64, hash: B256) -> Result<Self, AnchorError> {
        let header: Header = decode_exact(witness.get(hash)?)?;
        if header.number != number {
            return Err(AnchorError::Ancestry);
        }
        let oldest = block_info(hash, &header);
        Ok(Self {
            witness: Arc::new(Mutex::new(witness)),
            oldest,
            head_number: number,
            headers: BTreeMap::from([(number, (hash, header))]),
        })
    }

    pub(crate) fn head(&self) -> &(B256, Header) {
        &self.headers[&self.head_number]
    }

    pub(crate) fn witness(&self) -> MutexGuard<'_, Witness<'a>> {
        self.witness.lock()
    }

    pub(crate) fn ancestor(&mut self, number: u64) -> Result<&(B256, Header), AnchorError> {
        if number > self.head_number {
            return Err(AnchorError::Ancestry);
        }
        while self.oldest.number > number {
            let hash = self.oldest.parent_hash;
            let header: Header = decode_exact(self.witness.lock().get(hash)?)?;
            if header.number != self.oldest.number - 1 {
                return Err(AnchorError::Ancestry);
            }
            self.oldest = block_info(hash, &header);
            self.headers.insert(header.number, (hash, header));
        }
        self.headers.get(&number).ok_or(AnchorError::Ancestry)
    }

    pub(crate) fn authenticated_header(&mut self, hash: B256) -> Result<Header, AnchorError> {
        // A hash-addressed preimage can be from a competing fork. Its height
        // is only a lookup hint until the anchored chain agrees with its hash.
        let candidate: Header = decode_exact(self.witness.lock().get(hash)?)?;
        let (canonical_hash, header) = self.ancestor(candidate.number)?;
        if *canonical_hash != hash {
            return Err(AnchorError::Ancestry);
        }
        Ok(header.clone())
    }

    pub(crate) fn ordered_list<T: Decodable2718>(&self, root: B256) -> Result<Vec<T>, AnchorError> {
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

pub(crate) fn block_info(hash: B256, header: &Header) -> BlockInfo {
    BlockInfo {
        hash,
        number: header.number,
        parent_hash: header.parent_hash,
        timestamp: header.timestamp,
    }
}

impl TrieProvider for AnchoredChain<'_> {
    type Error = AnchorError;

    fn trie_node_by_hash(&self, hash: B256) -> Result<TrieNode, Self::Error> {
        Ok(decode_exact(self.witness.lock().get(hash)?)?)
    }
}
