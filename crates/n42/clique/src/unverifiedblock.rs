// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::{B256, U256};
use n42_primitives::{AttestationData, CommitteeIndex};
// reth-primitives (deleted in reth 2.4.1) supplied this default type argument.
type SealedBlock<B = n42_tx_types::Block> = reth_primitives_traits::SealedBlock<B>;
use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize, Debug)]
pub struct BlockVerifyResult {
    pub pubkey: String,
    pub signature: String,
    pub attestation_data: AttestationData,
    pub block_hash: B256,
}

#[derive(Clone, Default, Deserialize, Serialize, Debug)]
pub struct UnverifiedBlock {
    pub blockbody: SealedBlock,
    pub db: CachedReads,
    pub td: U256,
    pub committee_index: CommitteeIndex,
}
impl UnverifiedBlock {
    pub fn new(
        blockbody: SealedBlock,
        db: CachedReads,
        td: U256,
        committee_index: CommitteeIndex,
    ) -> Self {
        Self {
            blockbody,
            db,
            td,
            committee_index,
        }
    }
}
