// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`NodePrimitives`] built on [`N42TxEnvelope`].

use crate::envelope::{N42TxEnvelope, N42TxType};
use reth_primitives_traits::NodePrimitives;
use serde::{Deserialize, Serialize};

/// A block of N42 transactions.
pub type Block = alloy_consensus::Block<N42TxEnvelope>;

/// A block body of N42 transactions.
pub type BlockBody = alloy_consensus::BlockBody<N42TxEnvelope>;

/// A receipt that can name a 0x50 transaction.
pub type Receipt = reth_ethereum_primitives::Receipt<N42TxType>;

/// The node's primitive types: Ethereum's, with [`N42TxEnvelope`] as the
/// transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct N42Primitives;

impl NodePrimitives for N42Primitives {
    type Block = Block;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = BlockBody;
    type SignedTx = N42TxEnvelope;
    type Receipt = Receipt;
}
