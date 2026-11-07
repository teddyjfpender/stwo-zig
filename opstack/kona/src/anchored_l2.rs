//! Safe L2 history from the previous OP output commitment.
use crate::{
    anchored_chain::{AnchoredChain, block_info},
    execution::Provider,
    witness::Witness,
};
use alloc::{boxed::Box, string::ToString, sync::Arc};
use alloy_consensus::{BlockBody, Header, Sealed};
use alloy_op_evm::{OpEvmFactory, OpTx, block::OpAlloyReceiptBuilder};
use alloy_primitives::B256;
use async_trait::async_trait;
use kona_derive::L2ChainProvider;
use kona_executor::StatelessL2Builder;
use kona_genesis::{RollupConfig, SystemConfig};
use kona_mpt::NoopTrieHinter;
use kona_protocol::{
    BatchValidationProvider, L2BlockInfo, OpAttributesWithParent, OutputRoot, to_system_config,
};
use op_alloy_consensus::OpBlock;

pub use crate::anchored_chain::AnchorError;

#[derive(Debug, Clone)]
pub struct AnchoredL2<'a> {
    chain: AnchoredChain<'a>,
    config: Arc<RollupConfig>,
}

impl<'a> AnchoredL2<'a> {
    /// Open the checkpoint's V0 output root and verify its header number and state root.
    pub fn new(
        witness: Witness<'a>,
        number: u64,
        root: B256,
        config: Arc<RollupConfig>,
    ) -> Result<Self, AnchorError> {
        let bytes = witness.get(root)?;
        if bytes.len() != OutputRoot::ENCODED_LENGTH || bytes[..32] != [0; 32] {
            return Err(AnchorError::OutputRoot);
        }
        let hash = B256::from_slice(&bytes[96..128]);
        let mut chain = AnchoredChain::new(witness, number, hash)?;
        if chain.ancestor(number)?.1.state_root.as_slice() != &bytes[32..64] {
            return Err(AnchorError::OutputRoot);
        }
        Ok(Self { chain, config })
    }

    /// Execute the exact attributes returned by the authenticated derivation pipeline.
    /// The caller must obtain `prepared` from that pipeline, then bind the
    /// resulting L1 origin to the public anchor and transition statement.
    pub fn execute_prepared(
        &self,
        prepared: OpAttributesWithParent,
        next_number: u64,
        next_root: B256,
    ) -> Result<L2BlockInfo, AnchorError> {
        let (parent_hash, parent) = self.chain.head();
        if prepared.parent.block_info != block_info(*parent_hash, parent)
            || parent.number.checked_add(1) != Some(next_number)
        {
            return Err(AnchorError::Ancestry);
        }
        let attributes = prepared.take_inner();
        let first_tx = attributes
            .transactions
            .as_ref()
            .and_then(|txs| txs.first())
            .cloned();
        let witness = self.chain.witness();
        let mut builder = StatelessL2Builder::new(
            &self.config,
            OpEvmFactory::<OpTx>::default(),
            OpAlloyReceiptBuilder::default(),
            Provider(&witness),
            NoopTrieHinter,
            Sealed::new_unchecked(parent.clone(), *parent_hash),
        );
        let outcome = builder
            .build_block(attributes)
            .map_err(|error| AnchorError::Execution(error.to_string()))?;
        if outcome.header.number != next_number || outcome.header.parent_hash != *parent_hash {
            return Err(AnchorError::Ancestry);
        }
        let output = builder
            .compute_output_root()
            .map_err(|error| AnchorError::OutputRootComputation(error.to_string()))?;
        if output != next_root {
            return Err(AnchorError::OutputRoot);
        }
        Ok(L2BlockInfo::from_header_and_first_tx(
            &outcome.header,
            first_tx.as_ref(),
            &self.config.genesis,
        )?)
    }

    fn block(&self, header: Header) -> Result<OpBlock, AnchorError> {
        let transactions = self.chain.ordered_list(header.transactions_root)?;
        let withdrawals = self
            .config
            .is_canyon_active(header.timestamp)
            .then(Default::default);
        Ok(OpBlock {
            header,
            body: BlockBody {
                transactions,
                ommers: Default::default(),
                withdrawals,
            },
        })
    }

    fn block_by_hash(&mut self, hash: B256) -> Result<OpBlock, AnchorError> {
        let header = self.chain.authenticated_header(hash)?;
        self.block(header)
    }
}

#[async_trait]
impl BatchValidationProvider for AnchoredL2<'_> {
    type Error = AnchorError;

    async fn block_by_number(&mut self, number: u64) -> Result<Arc<OpBlock>, Self::Error> {
        let header = self.chain.ancestor(number)?.1.clone();
        Ok(Arc::new(self.block(header)?))
    }

    async fn l2_block_info_by_number(&mut self, number: u64) -> Result<L2BlockInfo, Self::Error> {
        let block = self.block_by_number(number).await?;
        Ok(L2BlockInfo::from_block_and_genesis(
            &block,
            &self.config.genesis,
        )?)
    }

    async fn l2_block_info_by_hash(&mut self, hash: B256) -> Result<L2BlockInfo, Self::Error> {
        let block = self.block_by_hash(hash)?;
        Ok(L2BlockInfo::from_block_and_genesis(
            &block,
            &self.config.genesis,
        )?)
    }
}

#[async_trait]
impl L2ChainProvider for AnchoredL2<'_> {
    type Error = AnchorError;

    async fn system_config_by_l2_hash(
        &mut self,
        hash: B256,
        config: Arc<RollupConfig>,
    ) -> Result<SystemConfig, AnchorError> {
        if !Arc::ptr_eq(&config, &self.config) && config != self.config {
            return Err(AnchorError::RollupConfig);
        }
        let block = self.block_by_hash(hash)?;
        Ok(to_system_config(&block, &self.config)?)
    }
}
