// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::Address;
use alloy_primitives::{Sealable, B256};
use alloy_rpc_types::BlockId;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{
    core::{RpcResult, SubscriptionResult},
    proc_macros::rpc,
    types::{
        error::{INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
        ErrorObject,
    },
    PendingSubscriptionSink, SubscriptionMessage,
};
use n42_clique::{BlockVerifyResult, UnverifiedBlock};
use n42_primitives::{
    beacon_chain_spec, epoch_to_block_number, AttestationData, BLSPubkey, BeaconBlock, BeaconState,
    Snapshot, ValidatorInfo,
};
use pubsub_mem::{subscribe, RouterMsg};
use reth_consensus::{ConsensusError, FullConsensus};
use n42_tx_types::N42Primitives as EthPrimitives;
use reth_node_core::primitives::AlloyBlockHeader;
use reth_provider::{BeaconProvider, BlockIdReader, BlockReader, HeaderProvider};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::debug;

/// trait interface for a custom rpc namespace: `consensus`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "consensusExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "consensusExt"))]
pub trait ConsensusExtApi {
    /// Propose in the clique consensus.
    #[method(name = "propose")]
    fn propose(&self, address: Address, auth: bool) -> RpcResult<()>;

    /// Discard in the clique consensus.
    #[method(name = "discard")]
    fn discard(&self, address: Address) -> RpcResult<()>;

    /// GetSnapshot in the clique consensus.
    #[method(name = "get_snapshot")]
    fn get_snapshot(&self, number: u64) -> RpcResult<Snapshot>;

    /// Proposals in the clique consensus.
    #[method(name = "proposals")]
    fn proposals(&self) -> RpcResult<HashMap<Address, bool>>;
}

/// The type that implements the `consensus` rpc namespace trait
pub struct ConsensusExt<Cons, Provider> {
    pub consensus: Cons,
    pub provider: Provider,
}

impl<Cons, Provider> ConsensusExtApiServer for ConsensusExt<Cons, Provider>
where
    Cons: FullConsensus<EthPrimitives> + Clone + Unpin + 'static,
    Provider: HeaderProvider + Clone + Send + Sync + 'static,
{
    fn propose(&self, address: Address, auth: bool) -> RpcResult<()> {
        Ok(self.consensus.propose(address, auth).unwrap_or_default())
    }

    fn discard(&self, address: Address) -> RpcResult<()> {
        Ok(self.consensus.discard(address).unwrap_or_default())
    }

    fn get_snapshot(&self, number: u64) -> RpcResult<Snapshot> {
        let hash = self
            .provider
            .header_by_number(number)
            .unwrap_or_default()
            .unwrap_or_default()
            .hash_slow();
        self.consensus.snapshot(number, hash, None).map_err(|err| {
            ErrorObject::owned(INVALID_PARAMS_CODE, err.to_string(), Option::<()>::None)
        })
    }

    fn proposals(&self) -> RpcResult<HashMap<Address, bool>> {
        Ok(self.consensus.proposals().unwrap_or_default())
    }
}

/// trait interface for a custom rpc namespace: `consensusBeaconExt`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "consensusBeaconExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "consensusBeaconExt"))]
pub trait ConsensusBeaconExtApi {
    #[subscription(name = "subscribeToVerificationRequest", item = String)]
    fn subscribe_to_verification_request(&self, pubkey: BLSPubkey) -> SubscriptionResult;

    #[method(name = "submitVerification")]
    fn submit_verification(
        &self,
        pubkey: String,
        signature: String,
        attestation_data: AttestationData,
        block_hash: B256,
    ) -> RpcResult<()>;

    /// get_beacon_block_hash_by_eth1_hash
    #[method(name = "get_beacon_block_hash_by_eth1_hash")]
    fn get_beacon_block_hash_by_eth1_hash(&self, eth1_hash: B256) -> RpcResult<Option<B256>>;

    /// get_beacon_block_by_hash
    #[method(name = "get_beacon_block_by_hash")]
    fn get_beacon_block_by_hash(&self, beacon_block_hash: B256) -> RpcResult<Option<BeaconBlock>>;

    /// get_beacon_block_by_number
    #[method(name = "get_beacon_block_by_number")]
    fn get_beacon_block_by_number(&self, block_id: BlockId) -> RpcResult<Option<BeaconBlock>>;

    /// get_beacon_state_by_beacon_block_hash
    #[method(name = "get_beacon_state_by_beacon_block_hash")]
    fn get_beacon_state_by_beacon_block_hash(
        &self,
        beacon_block_hash: B256,
    ) -> RpcResult<Option<BeaconState>>;

    /// get_beacon_state_by_number
    #[method(name = "get_beacon_state_by_number")]
    fn get_beacon_state_by_number(&self, state_id: BlockId) -> RpcResult<Option<BeaconState>>;

    /// get_beacon_validator_by_pubkey
    #[method(name = "get_beacon_validator_by_pubkey")]
    fn get_beacon_validator_by_pubkey(&self, pubkey: BLSPubkey)
        -> RpcResult<Option<ValidatorInfo>>;

    /// get_total_effective_balance
    #[method(name = "get_total_effective_balance")]
    fn get_total_effective_balance(&self) -> RpcResult<u64>;
}

/// The type that implements the `consensusBeaconRpc` rpc namespace trait
pub struct ConsensusBeaconExt<Cons, Provider> {
    pub consensus: Cons,
    pub provider: Provider,
    pub verification_tx: mpsc::Sender<BlockVerifyResult>,
    pub router_tx: mpsc::Sender<RouterMsg<UnverifiedBlock>>,
}

impl<Cons, Provider> ConsensusBeaconExtApiServer for ConsensusBeaconExt<Cons, Provider>
where
    Cons: FullConsensus<EthPrimitives> + Clone + Unpin + 'static,
    Provider: HeaderProvider + BeaconProvider + BlockIdReader + BlockReader + Clone + 'static,
{
    fn subscribe_to_verification_request(
        &self,
        pending: PendingSubscriptionSink,
        pubkey: BLSPubkey,
    ) -> SubscriptionResult {
        let router_tx_clone = self.router_tx.clone();

        tokio::spawn(async move {
            let (_id, mut rx) = match subscribe(router_tx_clone, hex::encode(&pubkey)).await {
                Ok(v) => v,
                Err(err) => {
                    debug!(target: "reth::cli", ?pubkey, ?err, "subscribe_to_verification_request failed");
                    return;
                }
            };
            debug!(target: "reth::cli", ?pubkey, "subscribe_to_verification_request New client subscribed");
            if let Ok(sink) = pending.accept().await {
                let subscription_id = sink.subscription_id();
                while let Some(event) = rx.recv().await {
                    let data_to_be_verified = event.payload;
                    debug!(target: "reth::cli", ?pubkey, "start broadcasting, block number {:?}", data_to_be_verified.blockbody.header().number());
                    if sink.is_closed() {
                        debug!(target: "reth::cli", ?subscription_id, "subscribe_to_verification_request client disconnected");
                        break;
                    }
                    let message = SubscriptionMessage::new(
                        "subscribeToVerificationRequest",
                        subscription_id.clone(),
                        &data_to_be_verified,
                    )
                    .unwrap();
                    if let Err(e) = sink.send(message).await {
                        debug!(target: "reth::cli", ?subscription_id, ?e, "subscribe_to_verification_request Error sending to client");
                        break;
                    }
                    debug!(target: "reth::cli", ?pubkey, "finish broadcasting, block number {:?}", data_to_be_verified.blockbody.header().number());
                }
            }
        });
        Ok(())
    }

    fn submit_verification(
        &self,
        pubkey: String,
        signature: String,
        attestation_data: AttestationData,
        block_hash: B256,
    ) -> RpcResult<()> {
        debug!(target: "reth::cli", ?pubkey, "received verification from rpc, slot={:?}", attestation_data.slot);
        let v = BlockVerifyResult {
            pubkey,
            signature,
            attestation_data,
            block_hash,
        };
        let _ = self.verification_tx.try_send(v);
        Ok(())
    }

    fn get_beacon_block_hash_by_eth1_hash(&self, eth1_hash: B256) -> RpcResult<Option<B256>> {
        self.provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_block_by_hash(&self, beacon_block_hash: B256) -> RpcResult<Option<BeaconBlock>> {
        self.provider
            .get_beacon_block_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_block_by_number(&self, block_id: BlockId) -> RpcResult<Option<BeaconBlock>> {
        let eth1_hash = match self.provider.block_hash_for_id(block_id).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        let beacon_block_hash = match self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_hash)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        self.provider
            .get_beacon_block_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_state_by_beacon_block_hash(
        &self,
        beacon_block_hash: B256,
    ) -> RpcResult<Option<BeaconState>> {
        self.provider
            .get_beacon_state_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_state_by_number(&self, block_id: BlockId) -> RpcResult<Option<BeaconState>> {
        let eth1_hash = match self.provider.block_hash_for_id(block_id).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        let beacon_block_hash = match self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_hash)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        self.provider
            .get_beacon_state_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_validator_by_pubkey(
        &self,
        pubkey: BLSPubkey,
    ) -> RpcResult<Option<ValidatorInfo>> {
        let beacon_state = match self.get_beacon_state_by_number(BlockId::latest())? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };
        let validator_index = match beacon_state.get_validator_index_from_pubkey(&pubkey) {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };
        let validator = beacon_state.get_validator(validator_index).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })?;
        let balance_in_beacon = beacon_state.get_balance(validator_index).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })?;
        let effective_balance = beacon_state
            .get_effective_balance(validator_index)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })?;
        let inactivity_score = beacon_state
            .get_inactivity_score(validator_index)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })?;
        let activation_block_number = epoch_to_block_number(validator.activation_epoch);
        let activation_timestamp = match self
            .provider
            .header_by_number(activation_block_number)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })? {
            Some(v) => v.timestamp(),
            None => 0,
        };
        let exit_block_number = epoch_to_block_number(validator.exit_epoch);
        let exit_timestamp =
            match self
                .provider
                .header_by_number(exit_block_number)
                .map_err(|e| {
                    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
                })? {
                Some(v) => v.timestamp(),
                None => 0,
            };

        let validator_info = ValidatorInfo {
            activation_timestamp,
            exit_timestamp,
            balance_in_beacon,
            effective_balance,
            inactivity_score,
        };
        Ok(Some(validator_info))
    }

    fn get_total_effective_balance(&self) -> RpcResult<u64> {
        let beacon_state = match self.get_beacon_state_by_number(BlockId::latest())? {
            Some(v) => v,
            None => {
                return Err(ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    format!("beacon state not found"),
                    None::<()>,
                ));
            }
        };
        let spec = beacon_chain_spec();
        let total_active_balance = beacon_state.get_total_active_balance(&spec).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })?;

        Ok(total_active_balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::server::ServerBuilder;
    use reth_consensus::noop::NoopConsensus;
    use reth_provider::test_utils::NoopProvider;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_propose_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::propose(&client, Address::random(), true)
            .await
            .unwrap();
        assert_eq!(result, ());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_discard_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::discard(&client, Address::random())
            .await
            .unwrap();
        assert_eq!(result, ());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_get_snapshot_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::get_snapshot(&client, 0)
            .await
            .unwrap();
        assert_eq!(result, Snapshot::default());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_proposals_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::proposals(&client).await.unwrap();
        assert_eq!(result, HashMap::default());
    }

    async fn start_server() -> std::net::SocketAddr {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let consensus = NoopConsensus::default();
        let provider = NoopProvider::default();
        let api = ConsensusExt {
            consensus,
            provider,
        };
        let server_handle = server.start(api.into_rpc());

        tokio::spawn(server_handle.stopped());

        addr
    }
}
